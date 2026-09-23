package acme

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/miekg/dns"
)

// DNSSolver adds one step on top of lego's DNS providers: "wait until every
// authoritative NS for the zone returns this TXT".
//
// Why it cannot be skipped: Let's Encrypt validates from several vantage points and
// demands that all of them agree. Querying only the local recursive resolver is fooled
// by its cache, so locally everything looks ready while LE's validation fails. And a
// failed validation is rate limited per identifier (5 per hour) -- a very real cost.
//
// The step holds for CNAME delegation too: GetChallengeInfo follows the CNAME and
// reports the EffectiveFQDN, so what we query is the zone that really carries the TXT
// after delegation.
type DNSSolver struct {
	// newProvider fetches a fresh provider instance on every use. The tencentcloud path
	// goes through CAM temporary credentials that expire, so it must not be held long
	// term.
	newProvider func(ctx context.Context) (challenge.Provider, error)

	timeout              time.Duration
	interval             time.Duration
	log                  *slog.Logger
	recursiveNameservers []string
	exchange             func(ctx context.Context, msg *dns.Msg, server string) (*dns.Msg, error)
}

// NewDNSSolver picks an implementation from dns.provider.
//
// The two implementations use completely different credential systems:
//   - dnspod       uses a DNSPod-native API token (never expires, build once, reuse)
//   - tencentcloud uses Tencent Cloud CAM credentials, shared with certificate
//     deployment (supports temporary credentials from a CVM role)
const dnsAPITimeout = 60 * time.Second

// tencentDNSConfig builds the tencentcloud provider's config, timeout included.
//
// Split out so a test can assert the timeout is there: it cannot be read back from the constructed
// provider (lego keeps its config unexported), and that is exactly the field whose absence is
// invisible until a connection stalls.
type DNSRecord struct {
	FQDN  string
	Value string
}

// Present writes the TXT into DNS but **does not wait for propagation**.
//
// Splitting "write" from "wait" is deliberate, for two reasons:
//
//  1. Correctness: a wildcard + its apex write to the same _acme-challenge name, so
//     both records must exist at the same time. "Write, wait, then write the second"
//     works too, but hoisting every write up front is harder to get wrong.
//  2. Performance: waiting for propagation is the slowest step in the whole chain --
//     DNSPod's free tier has a 600s TTL floor and 9 authoritative NS, so one
//     propagation round takes over 2 minutes. Waiting per record makes records on the
//     same name wait twice for nothing.
const maxProbeConcurrency = 8

// recordProbe is the probe result for one record.
type recordProbe struct {
	record  DNSRecord
	ready   bool
	summary string
}

// probeRecords probes several records concurrently; results keep the input order.
//
// Concurrency is mandatory: one round for a single record asks every authoritative NS
// in its zone (9 for DNSPod), so handling 100 domains serially is 100 polling rounds at
// up to 3 seconds each -- one round then runs far past the 5-second polling interval.
// Propagation waiting would degrade into "advance a little every 5 seconds", and a
// 5-minute budget would not survive even a few rounds.
type zoneBudget struct {
	passStart time.Time // when the whole propagation wait began
	zoneStart time.Time // when this zone was entered
	deadline  time.Time // shared across every zone
}

// waitZone polls one zone until its records are confirmed, within the shared deadline.
// delegated is the number of NS names in the zone's delegation (see authoritativeNS): servers
// holds only the names that resolved, and the propagation rule needs the full count.
type nsProbe struct {
	ns            string
	server        string
	hasValue      bool
	authoritative bool
	err           error // non-nil means this address is unreachable from here, or did not answer
}

// probeTXT probes every authoritative NS concurrently.
//
// Concurrency is necessary here: 9 servers in series with a 5-second timeout each makes
// a worst-case round of 45 seconds.
type recursiveVerdict struct {
	confirmed bool // at least one resolver returned the value
	denied    bool // at least one resolver answered definitively without it
	reachable int  // resolvers that gave one of those two answers
	summary   string
}

// probeRecursive asks every configured recursive resolver for the TXT value.
//
// The three-way split mirrors the authoritative probe, and for the same reason: "denied" and
// "could not tell" are different answers and must not be collapsed.
//
//   - NOERROR with the value          -> confirmed
//   - NXDOMAIN, or NOERROR without it -> denied (this includes a negatively cached answer,
//     which is exactly what the CA would be handed, so waiting is the correct response)
//   - anything else (timeout, SERVFAIL, REFUSED, truncation) -> inconclusive
//
// Callers block on a denial and require a confirmation, unless every resolver was
// inconclusive: a host with no usable public DNS must still be able to issue certificates, so
// "nobody answered" degrades to a warning rather than a refusal.
var challengeLeases = newTXTLeases()

// txtLease is one challenge name's slot: the mutex that orders the provider calls at
// the name, the values currently live there, and a count of goroutines that hold (or
// are about to lock) the mutex.
type txtLease struct {
	mu     sync.Mutex
	refs   int
	values map[string]bool
}

type txtLeases struct {
	// guards entries; the per-name mutexes inside order the provider calls
	mu      sync.Mutex
	entries map[string]*txtLease
}

func (l *txtLeases) add(fqdn, value string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[fqdn]
	if e == nil {
		e = &txtLease{values: map[string]bool{}}
		l.entries[fqdn] = e
	}
	e.values[value] = true
}

// addUnderLock records a lease while holding the name's mutex.
//
// The plain add() only takes the registry lock, which is enough for the `values` map but NOT
// enough for the check-then-act that CleanUp performs: CleanUp holds the per-name mutex across
// "is any other value live?" and the provider's delete-EVERY-TXT call. An add that lands
// between those two steps is invisible to the check and the value it registered is then
// deleted -- so the CA is asked to validate a record that no longer exists, which books a
// billed authorization failure against the 5-per-hour-per-identifier limit and leaves an
// entry in the identifier ledger that arms the failure fallback.
//
// Present() was already safe because it adds while holding the same mutex. The two paths that
// did NOT were WaitAll (re-registering the records of a resumed order, whose TXT a previous
// process wrote) and registerRecoveredLeases. Taking the mutex here makes all four paths
// equivalent.
func (l *txtLeases) addUnderLock(fqdn, value string) {
	mu, release := l.lock(fqdn)
	defer release()
	mu.Lock()
	defer mu.Unlock()
	l.add(fqdn, value)
}

// remove drops one lease and reports whether any other value is still live at the name.
//
// It deliberately does **not** drop the entry itself, even when the last value goes:
// the caller still holds the per-name mutex across its provider call, and dropping the
// entry here would let a concurrent Present re-create the name under a different mutex
// and sneak its write in between this CleanUp's "no live values" check and its
// delete-all. Pruning is the release function's job (see lock).
func (l *txtLeases) remove(fqdn, value string) (othersLive bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[fqdn]
	if e == nil {
		return false
	}
	delete(e.values, value)
	return len(e.values) > 0
}

// CleanUp deletes the TXT record this call wrote -- or defers doing so.
//
// lego's provider deletes **every** TXT record at the challenge name, so this wrapper
// only calls it once no other value is live at the name (see challengeLeases); while
// another certificate (or this one's wildcard sibling) still needs its record there, the
// deletion is skipped and left to the last leaver.
//
// A skipped record is not leaked: the last CleanUp at the name removes all records in
// one call, and anything stranded by a crash is reclaimed later by the manager's
// cleanupOrphanTXT.
func exchangeDNS(ctx context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
	client := &dns.Client{Timeout: 3 * time.Second}
	resp, _, err := client.ExchangeContext(ctx, msg, server)
	if err != nil || resp == nil || !resp.Truncated {
		return resp, err
	}

	tcp := &dns.Client{Net: "tcp", Timeout: 3 * time.Second}
	tcpResp, _, tcpErr := tcp.ExchangeContext(ctx, msg, server)
	if tcpErr != nil || tcpResp == nil {
		// Keep the UDP answer. It is incomplete, and Truncated says so.
		return resp, nil
	}
	return tcpResp, nil
}

func domainSequence(fqdn string) []string {
	labels := dns.SplitDomainName(dns.Fqdn(fqdn))
	out := make([]string, 0, len(labels))
	for i := range labels {
		out = append(out, strings.Join(labels[i:], ".")+".")
	}
	return out
}

func responseHasTXT(resp *dns.Msg, want string) bool {
	for _, rr := range resp.Answer {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		// A TXT record can be split into several string segments; join them, then compare.
		if strings.Join(txt.Txt, "") == want {
			return true
		}
	}
	return false
}
