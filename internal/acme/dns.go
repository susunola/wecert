package acme

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/providers/dns/dnspod"
	"github.com/go-acme/lego/v4/providers/dns/tencentcloud"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
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
func NewDNSSolver(dnsCfg config.DNS, tencentCfg config.Tencent, log *slog.Logger) (*DNSSolver, error) {
	var newProvider func(ctx context.Context) (challenge.Provider, error)

	switch dnsCfg.Provider {
	case config.DNSProviderDNSPod:
		// Hazard: lego wraps this provider's HTTP client in its debug dumper, which is
		// enabled by LEGO_DEBUG_DNS_API_HTTP_CLIENT. It redacts Authorization/Token/
		// Api-Key *headers*, but dnspod-go puts the credential in the POST *body* as
		// `login_token=...`, which no redaction rule matches -- so setting that variable
		// on the service writes a never-expiring DNSPod token (record write over every
		// zone in the account) into stdout, which under systemd means the journal.
		//
		// Keep it out of the unit and out of any drop-in; debug DNS locally instead.
		p, err := dnspod.NewDNSProviderConfig(dnspodConfig(dnsCfg))
		if err != nil {
			return nil, fmt.Errorf("initialise the dnspod provider: %w", err)
		}
		// A DNSPod-native token never expires, so one reused instance is enough.
		newProvider = func(context.Context) (challenge.Provider, error) { return p, nil }

	case config.DNSProviderTencentCloud:
		creds, err := deploy.NewCredentialSource(tencentCfg)
		if err != nil {
			return nil, err
		}
		// Fetch and build on the spot every time, so the API is never called with credentials
		// that have expired since they were fetched -- the CVM instance role hands out temporary
		// ones.
		//
		// The cost is not quite negligible, and it is worth writing down because it is invisible
		// here: the SDK builds each client's HTTP client around a CLONE of http.DefaultTransport
		// (common.Client.Init, unless common.DefaultHttpClient is set, which this program does not
		// set), so every provider instance has its own connection pool. One Present or CleanUp is
		// therefore one fresh TLS handshake, plus one connection left idle for the SDK's 30s
		// IdleConnTimeout. That is the price of not reusing a client; sharing one is not free
		// either, because the SDK applies ReqTimeout by mutating the client it was given, so a
		// shared client would couple unrelated timeouts.
		newProvider = func(ctx context.Context) (challenge.Provider, error) {
			cred, err := creds(ctx)
			if err != nil {
				return nil, err
			}
			return tencentcloud.NewDNSProviderConfig(tencentDNSConfig(
				cred.GetSecretId(), cred.GetSecretKey(), cred.GetToken(), dnsCfg))
		}

	case config.DNSProviderLego:
		// Any provider from lego's registry, by name, with its credentials taken from the
		// environment in lego's own variable names. See the build-tag files for why this is
		// opt-in rather than always compiled in.
		newProvider = newLegoProvider(dnsCfg.LegoProvider)

	default:
		return nil, fmt.Errorf("unknown dns.provider %q", dnsCfg.Provider)
	}

	resolvers, err := recursiveNameservers(dnsCfg.RecursiveNameservers)
	if err != nil {
		return nil, err
	}
	if err := dns01.AddRecursiveNameservers(resolvers)(&dns01.Challenge{}); err != nil {
		return nil, fmt.Errorf("configure lego recursive nameservers: %w", err)
	}
	return &DNSSolver{newProvider: newProvider, timeout: dnsCfg.Propagation, interval: dnsCfg.Polling, log: log, recursiveNameservers: resolvers, exchange: exchangeDNS}, nil
}

// dnsAPITimeout bounds one call to the DNS provider's API.
//
// It has to be set explicitly, because a provider built from a struct literal does NOT get lego's
// NewDefaultConfig defaults: the tencentcloud provider would leave the SDK's ReqTimeout at 0, and
// the SDK then builds an http.Client with Timeout 0 -- no timeout at all. Present and CleanUp hold
// the per-name TXT lease mutex across that call (see challengeLeases), so one stalled connection
// would wedge every certificate sharing the challenge FQDN for as long as the TCP connection
// lives, with the pass never finishing and the TXT records left in DNS. Sixty seconds matches the
// other Tencent Cloud client in this program (internal/deploy).
const dnsAPITimeout = 60 * time.Second

// tencentDNSConfig builds the tencentcloud provider's config, timeout included.
//
// Split out so a test can assert the timeout is there: it cannot be read back from the constructed
// provider (lego keeps its config unexported), and that is exactly the field whose absence is
// invisible until a connection stalls.
func tencentDNSConfig(secretID, secretKey, sessionToken string, dnsCfg config.DNS) *tencentcloud.Config {
	return &tencentcloud.Config{
		SecretID:           secretID,
		SecretKey:          secretKey,
		SessionToken:       sessionToken,
		TTL:                dnsCfg.TTL,
		PropagationTimeout: dnsCfg.Propagation,
		PollingInterval:    dnsCfg.Polling,
		HTTPTimeout:        dnsAPITimeout,
	}
}

// dnspodConfig builds the DNSPod provider's config, with a bounded HTTP client for the same reason
// as tencentDNSConfig: a nil client falls back to http.DefaultClient, which has no timeout either.
func dnspodConfig(dnsCfg config.DNS) *dnspod.Config {
	return &dnspod.Config{
		LoginToken:         dnsCfg.LoginToken,
		TTL:                dnsCfg.TTL,
		PropagationTimeout: dnsCfg.Propagation,
		PollingInterval:    dnsCfg.Polling,
		HTTPClient:         &http.Client{Timeout: dnsAPITimeout},
	}
}

// PropagationTimeout reports the budget WaitAll waits for a record to appear.
func (s *DNSSolver) PropagationTimeout() time.Duration { return s.timeout }

// DNSRecord is one _acme-challenge TXT record that is to be written or verified.
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
func (s *DNSSolver) Present(ctx context.Context, domain, token, keyAuth string) (DNSRecord, error) {
	provider, err := s.newProvider(ctx)
	if err != nil {
		return DNSRecord{}, fmt.Errorf("get the DNS provider: %w", err)
	}

	info := dns01.GetChallengeInfo(domain, keyAuth)
	rec := DNSRecord{
		FQDN:  dns.Fqdn(info.EffectiveFQDN),
		Value: info.Value,
	}

	// Register the lease under the same per-name lock that CleanUp holds across its
	// delete call, so a cleanup can never slip a delete-all in between "this name has no
	// live values" and the write landing. See challengeLeases.
	mu, release := challengeLeases.lock(rec.FQDN)
	defer release()
	mu.Lock()
	defer mu.Unlock()

	// Resolve the zone before handing the write to the provider, so its answer is ours to
	// report. lego does the same SOA walk internally but has no guard against the walk
	// climbing to the public suffix: when the resolver answers for `com.` but not for the
	// domain, lego concludes the zone is `com.` and the write fails with "zone com. not found
	// in dnspod for domain ...", which reads like a DNSPod account problem and is not. This
	// costs one short SOA walk (findZone already refuses to return a public suffix) and only
	// runs when a record is about to be written.
	if _, err := s.findZone(ctx, rec.FQDN); err != nil {
		return DNSRecord{}, fmt.Errorf("present TXT: %w", err)
	}

	if err := provider.Present(domain, token, keyAuth); err != nil {
		return DNSRecord{}, fmt.Errorf("present TXT: %w", err)
	}
	challengeLeases.add(rec.FQDN, rec.Value)
	return rec, nil
}

// WaitAll waits until every record is visible on all authoritative NS of its zone.
//
// It deduplicates by (FQDN, Value), and resolves each zone's authoritative NS list once.
func (s *DNSSolver) WaitAll(ctx context.Context, records []DNSRecord) error {
	byZone := map[string][]DNSRecord{}
	seen := map[string]bool{}

	for _, r := range records {
		key := r.FQDN + "|" + r.Value
		if seen[key] {
			continue
		}
		seen[key] = true

		// A resumed order reuses records a previous process wrote, so Present never runs
		// for them in this process and the lease registry would not know they are live.
		// WaitAll sees every record a round depends on, so this is where those leases get
		// re-registered -- otherwise a concurrent certificate's cleanup could delete-all
		// the name right out from under this one (see challengeLeases).
		//
		// Under the name's mutex, not just the registry lock: CleanUp checks "is any other
		// value live?" and then deletes while holding that mutex, so an add outside it can
		// land in the window and have its value deleted (see addUnderLock).
		challengeLeases.addUnderLock(r.FQDN, r.Value)

		zone, err := s.findZone(ctx, r.FQDN)
		if err != nil {
			return fmt.Errorf("find the zone for %s: %w", r.FQDN, err)
		}
		byZone[zone] = append(byZone[zone], r)
	}

	if len(byZone) == 0 {
		return nil
	}

	// The budget is global: every zone shares one deadline, so the overall wait does not inflate
	// linearly as zones are added. That is deliberate (the contract test pins it), but it means a
	// zone reached after the deadline has already passed must not be entered at all -- it would get
	// one probe round and then fail with a message blaming it for a wait that was not its own.
	start := time.Now()
	deadline := start.Add(s.timeout)

	// byZone is a map, so the order is random: without this, which zone is starved changes from
	// pass to pass, which is worse than a fixed order because it looks intermittent.
	for zone, recs := range byZone {
		waitStart := time.Now()
		if !waitStart.Before(deadline) {
			return fmt.Errorf("TXT propagation was not confirmed before the %s budget ran out "+
				"(zone %s was not reached; %s was spent on the zones before it)",
				s.timeout, zone, waitStart.Sub(start).Round(time.Second))
		}
		servers, err := s.authoritativeNS(ctx, zone)
		if err != nil {
			return err
		}
		if err := s.waitZone(ctx, zone, servers, recs, zoneBudget{
			passStart: start, zoneStart: waitStart, deadline: deadline,
		}); err != nil {
			return err
		}
	}
	return nil
}

// maxProbeConcurrency caps how many record probes are in flight at once.
//
// Each record then probes all the authoritative NS of its zone concurrently, so real
// concurrency is this number x the NS count. Set it too high and we fire off thousands
// of DNS queries in an instant, which is exactly how you get rate limited or dropped.
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
func probeRecordsWithExchange(servers []nsServer, recs []DNSRecord, exchange func(*dns.Msg, string) (*dns.Msg, error)) []recordProbe {
	out := make([]recordProbe, len(recs))
	if len(recs) == 0 {
		return out
	}

	limit := maxProbeConcurrency
	if len(recs) < limit {
		limit = len(recs)
	}

	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup

	for i, r := range recs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, r DNSRecord) {
			defer wg.Done()
			defer func() { <-sem }()

			ready, summary := probeReadyWithExchange(servers, r.FQDN, r.Value, exchange)
			// Each goroutine writes only its own index; no overlap, so no lock is needed.
			out[i] = recordProbe{record: r, ready: ready, summary: summary}
		}(i, r)
	}
	wg.Wait()

	return out
}

func probeRecords(servers []nsServer, recs []DNSRecord) []recordProbe {
	return probeRecordsWithExchange(servers, recs, func(msg *dns.Msg, server string) (*dns.Msg, error) {
		client := &dns.Client{Timeout: 3 * time.Second}
		resp, _, err := client.Exchange(msg, server)
		return resp, err
	})
}

// waitZone polls the zone's authoritative NS until the records are confirmed propagated.
// zoneBudget is the propagation budget as it applies to one zone.
//
// Two timestamps rather than one because the message has to be honest about both: how long THIS zone
// waited, and how much of the shared budget was already gone when it was entered. Reporting the pass
// elapsed as if it were the zone's own wait is what the old message did, and it points the operator
// at the wrong zone -- the one that happens to sort last in a map iteration.
type zoneBudget struct {
	passStart time.Time // when the whole propagation wait began
	zoneStart time.Time // when this zone was entered
	deadline  time.Time // shared across every zone
}

// waitZone polls one zone until its records are confirmed, within the shared deadline.
func (s *DNSSolver) waitZone(
	ctx context.Context, zone string, servers []nsServer, recs []DNSRecord, b zoneBudget,
) error {
	for {
		results := s.probeRecords(servers, recs)

		// Summarise only the records that are **not ready yet**.
		//
		// This used to unconditionally reuse the last record's summary, so with the two
		// same-name TXT records of wildcard + apex, as soon as the second one was ready
		// the timeout error printed "confirmed 9 / denied 0 / unreachable 0" -- a summary
		// that looks perfectly healthy, and is the most baffling kind of log there is.
		var pending []string
		for _, res := range results {
			if res.ready {
				continue
			}
			pending = append(pending,
				fmt.Sprintf("%s = %s (%s)", res.record.FQDN, res.record.Value, res.summary))
		}

		if len(pending) == 0 {
			// The authoritative servers agree. That is necessary but not sufficient: the CA
			// validates through a recursive resolver, so ask that path too before telling the CA
			// to look (see probeRecursive for why the two views can disagree).
			if ready, why := s.recursiveReady(ctx, recs); !ready {
				pending = why
			}
		}

		if len(pending) == 0 {
			// The evidence goes into the success line too, not just into the timeout error.
			//
			// This verdict is a lower bound on global propagation and it is derived from this
			// host's view: a lagging authority that happens to be unreachable from here
			// contributes nothing, while the CA's own resolver may reach it and be told the
			// record does not exist. That asymmetry is exactly what turned a "propagated" verdict
			// into an NXDOMAIN at the CA in production, and with only a server count in the log
			// there was no way to see afterwards how thin the evidence had been. Every round
			// re-probes every address, so the summary printed here is the state of the round that
			// decided it.
			readiness := make([]string, 0, len(results))
			for _, res := range results {
				readiness = append(readiness, fmt.Sprintf("%s = %s (%s)",
					res.record.FQDN, res.record.Value, res.summary))
			}
			s.log.Info("TXT propagated",
				"zone", zone, "nameservers", len(servers), "records", len(recs),
				"evidence", strings.Join(readiness, " | "))
			return nil
		}

		// The context is checked BEFORE the budget.
		//
		// With the budget first, a cancellation that landed during the final probe round was
		// reported as a propagation timeout -- and upstream a timeout is a business failure:
		// solveChallenges calls markResumedUnpresented and recordFailure books a
		// consecutive_failures increment and a backoff for what was actually a shutdown. Both of
		// those rules ("a stop signal is not a failure", "a cancelled wait says nothing about DNS")
		// depend on the cancellation being visible here.
		if err := ctx.Err(); err != nil {
			return err
		}
		if !time.Now().Before(b.deadline) {
			return fmt.Errorf(
				"TXT propagation not confirmed: this zone waited %s, entering it %s into the %s "+
					"budget; zone=%s, ns=%d, %d/%d records still not ready: %s",
				time.Since(b.zoneStart).Round(time.Second),
				b.zoneStart.Sub(b.passStart).Round(time.Second), s.timeout,
				zone, len(servers), len(pending), len(recs),
				strings.Join(pending, " | "))
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.interval):
		}
	}
}

// nsProbe is the probe result for one address of one authoritative NS.
//
// ns is the nameserver NAME this address belongs to, and it is not decoration: a name with both an
// A and an AAAA record is one server, and the propagation rule requires two *servers* to agree. See
// probeReadyWithExchange.
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
func probeTXTWithExchange(servers []nsServer, fqdn, want string, exchange func(*dns.Msg, string) (*dns.Msg, error)) []nsProbe {
	results := make([]nsProbe, len(servers))

	var wg sync.WaitGroup
	for i, server := range servers {
		wg.Add(1)
		go func(i int, server nsServer) {
			defer wg.Done()
			results[i] = nsProbe{ns: server.ns, server: server.addr}

			m := new(dns.Msg)
			m.SetQuestion(fqdn, dns.TypeTXT)
			m.RecursionDesired = false
			// Without EDNS0 the answer is capped at 512 bytes (miekg falls back to
			// MinMsgSize), and a challenge name shared by a wildcard and its apex plus a
			// leftover value from the previous round gets close to that. Asking for a bigger
			// buffer is what keeps the answer whole rather than truncated.
			m.SetEdns0(4096, false)

			resp, err := exchange(m, server.addr)
			if err != nil {
				results[i].err = err
				return
			}
			if resp == nil {
				results[i].err = errors.New("no response")
				return
			}
			// Rcode decides what kind of answer this is, and the three kinds are not
			// interchangeable:
			//
			//   NOERROR   -- answered; look for the value.
			//   NXDOMAIN  -- answered definitively: the name does not exist, so the value is not
			//                there. A denial, which is a real answer.
			//   anything  -- SERVFAIL, REFUSED, ... The server has not answered the question.
			//     else       Treating that as "the record is not there" is a false denial, and in
			//                LookupTXT's branch a false denial is what licenses deleting the
			//                authorization row of a name that is still being validated. It is not
			//                a confirmation either, so it counts as unreachable: inconclusive.
			switch resp.Rcode {
			case dns.RcodeSuccess:
			case dns.RcodeNameError:
				results[i].authoritative = resp.Authoritative
				results[i].hasValue = false
				return
			default:
				results[i].err = fmt.Errorf("server answered %s", dns.RcodeToString[resp.Rcode])
				return
			}
			// A truncated answer may be missing the very record being looked for, so it can
			// neither confirm nor deny. exchangeDNS retries over TCP; this is the case where
			// that failed too.
			if resp.Truncated {
				results[i].err = errors.New("truncated answer (TCP retry failed)")
				return
			}
			results[i].authoritative = resp.Authoritative
			results[i].hasValue = results[i].authoritative && responseHasTXT(resp, want)
		}(i, server)
	}
	wg.Wait()

	return results
}

// probeReady decides whether a record can count as propagated, and returns a
// plain-language summary.
//
// The rule: **no reachable NS denies the value**, and at least one confirms it. When the
// zone has multiple authorities, at least 2 must confirm independently, so "only one
// server was reachable" cannot slip through.
//
// Not requiring all 9 to be reachable is deliberate: any single NS being unreachable
// from here would make "everything agrees" permanently unsatisfiable -- and that has
// nothing to do with whether the record propagated. LE validates from several of its own
// locations, so an NS we cannot reach may be reachable for LE.
//
// Conversely, if even one reachable NS plainly says "no such value", we must never let it
// through -- that really is propagation incomplete, and letting it through burns a
// failed-validation quota slot (5 per hour) for nothing.
//
// A single-authority zone has to be able to pass: requiring 2 confirmations would leave
// such a zone waiting for propagation forever.
func probeReadyWithExchange(servers []nsServer, fqdn, want string, exchange func(*dns.Msg, string) (*dns.Msg, error)) (bool, string) {
	results := probeTXTWithExchange(servers, fqdn, want, exchange)

	var confirmed, missing, nonAuthoritative, unreachable int
	// Counted per NS NAME, not per address: one server answering on both its A and its AAAA
	// record is one server, and the rule below is about how many independent servers agree.
	//
	// This cuts both ways, and both were wrong before. Counting addresses let a single
	// multi-homed authority satisfy "two independent confirmations" -- the guard the comment
	// promises is exactly what it lost. It also made a single-authority zone whose name has an
	// unreachable second address permanently unconfirmable, because the "one authority is exempt"
	// branch was keyed on the address count.
	confirmingNS := map[string]bool{}
	authorities := map[string]bool{}
	for _, r := range results {
		authorities[r.ns] = true
		switch {
		case r.err != nil:
			unreachable++
		case !r.authoritative:
			nonAuthoritative++
		case r.hasValue:
			confirmed++
			confirmingNS[r.ns] = true
		default:
			missing++
		}
	}

	summary := fmt.Sprintf("confirmed %d/%d server(s) / denied %d / non-authoritative %d / unreachable %d (of %d addresses)",
		len(confirmingNS), len(authorities), missing, nonAuthoritative, unreachable, len(results))

	// Any reachable server that answers "no such value" -> not propagated yet. Checked per
	// address on purpose: one address of one authority denying the value is enough to hold the
	// whole thing back.
	if missing > 0 {
		return false, summary
	}
	// Not a single confirmation (everything unreachable) -> must not let it through.
	if confirmed == 0 {
		return false, summary
	}
	// With more than one authority, require two of them to confirm, so "only one server was
	// reachable" cannot slip through. A zone with a single authority is exempt, whoever many
	// addresses that authority has.
	if len(authorities) >= 2 && len(confirmingNS) < 2 {
		return false, summary
	}
	return true, summary
}

func probeReady(servers []nsServer, fqdn, want string) (bool, string) {
	return probeReadyWithExchange(servers, fqdn, want, func(msg *dns.Msg, server string) (*dns.Msg, error) {
		client := &dns.Client{Timeout: 3 * time.Second}
		resp, _, err := client.Exchange(msg, server)
		return resp, err
	})
}

// recursiveVerdict is what the CA-shaped view says about one record.
//
// A validator resolves through a recursive resolver, not by asking authoritative servers
// directly, so this is the closest thing wecert has to the CA's own view -- and the two views
// can disagree. Observed on a real account: the authoritative probe saw every reachable server
// confirm the value while the CA was told NXDOMAIN for the same name, because a lagging
// authority was unreachable from wecert's host and reachable from the CA's resolver. The cost
// of that disagreement is a failed-validation quota slot (5 per hour per identifier), spent on
// a round that could simply have waited.
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
func (s *DNSSolver) probeRecursive(ctx context.Context, fqdn, want string) recursiveVerdict {
	v := recursiveVerdict{}
	notes := make([]string, 0, len(s.recursiveNameservers))
	for _, resolver := range s.recursiveNameservers {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(fqdn), dns.TypeTXT)
		msg.RecursionDesired = true
		msg.SetEdns0(4096, false)

		resp, err := s.exchange(ctx, msg, resolver)
		switch {
		case err != nil:
			notes = append(notes, resolver+" unreachable")
		case resp == nil:
			notes = append(notes, resolver+" no response")
		case resp.Truncated:
			notes = append(notes, resolver+" truncated answer (TCP retry failed)")
		case resp.Rcode == dns.RcodeSuccess:
			v.reachable++
			if responseHasTXT(resp, want) {
				v.confirmed = true
				notes = append(notes, resolver+" has the value")
			} else {
				v.denied = true
				notes = append(notes, resolver+" answered NOERROR without the value")
			}
		case resp.Rcode == dns.RcodeNameError:
			v.reachable++
			v.denied = true
			notes = append(notes, resolver+" answered NXDOMAIN")
		default:
			notes = append(notes, resolver+" answered "+dns.RcodeToString[resp.Rcode])
		}
	}
	v.summary = fmt.Sprintf("recursive: confirmed=%t denied=%t reachable=%d/%d (%s)",
		v.confirmed, v.denied, v.reachable, len(s.recursiveNameservers), strings.Join(notes, "; "))
	return v
}

// recursiveReady reports whether the CA-shaped view permits the verdict, and why not.
func (s *DNSSolver) recursiveReady(ctx context.Context, recs []DNSRecord) (bool, []string) {
	var pending []string
	for _, r := range recs {
		v := s.probeRecursive(ctx, r.FQDN, r.Value)
		if v.denied {
			pending = append(pending, fmt.Sprintf(
				"%s = %s (a recursive resolver, which is what the CA talks to, answered without the value: %s)",
				r.FQDN, r.Value, v.summary))
			continue
		}
		if !v.confirmed && v.reachable == 0 && len(s.recursiveNameservers) > 0 {
			// Not one resolver could answer. Refusing here would make issuance impossible on a
			// host without public DNS egress -- a configuration wecert supports -- and the
			// authoritative verdict above already passed, so this is a warning, not a blocker.
			s.log.Warn("no recursive resolver could answer; falling back to the authoritative verdict alone",
				"name", r.FQDN)
			continue
		}
		if !v.confirmed {
			pending = append(pending, fmt.Sprintf(
				"%s = %s (no recursive resolver returned the value yet: %s)", r.FQDN, r.Value, v.summary))
		}
	}
	return len(pending) == 0, pending
}

// challengeLeases tracks, per effective challenge FQDN, the TXT values this process
// currently relies on.
//
// It exists because the comment that used to sit on CleanUp was a lie: lego's
// dnspod/tencentcloud CleanUp does **not** locate one record by the (domain, token,
// keyAuth) triple -- it deletes **every** TXT record at the challenge name. Config
// dedups certificate names, not domains, so two certificates can legitimately share
// _acme-challenge.example.com; reconciled concurrently (a webhook trigger overlapping a
// scheduled pass), certificate A's cleanup would then kill certificate B's still-pending
// challenge record.
//
// True value-scoped deletion is not reachable at this layer: lego hands out only the
// challenge.Provider interface, and the record-level API client behind it is unexported.
// What this layer can guarantee is that the delete-all call never fires while any value
// at the name is still live: the last leaver's cleanup removes every record in one call,
// including the records earlier leavers had to skip. That suffices because the state
// store's exclusive lock (internal/state) already guarantees a single wecert process per
// state directory, so every writer of these records passes through this registry.
//
// The per-name mutex must be held across the provider call on both sides (Present and
// CleanUp): without that, a Present could land between CleanUp's "no live values" check
// and its delete-all, and the fresh record would die with the rest.
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

func newTXTLeases() *txtLeases {
	return &txtLeases{entries: map[string]*txtLease{}}
}

// lock returns the per-name mutex plus a release function; every caller must hold the
// mutex across its provider call and run release afterwards.
//
// The reference count is taken under l.mu **before** the caller locks the per-name
// mutex, and that is what makes pruning safe: an entry is dropped (in release) only once
// no goroutine references it, so nobody can be between "got the mutex pointer" and
// "locked it" when the entry disappears. Pruning without the count would open exactly
// that window -- the name gets re-created under a **different** mutex while the old one
// is still in use, and two goroutines then run their provider calls concurrently at the
// same name, which is the race the mutex exists to prevent.
func (l *txtLeases) lock(fqdn string) (*sync.Mutex, func()) {
	l.mu.Lock()
	e := l.entries[fqdn]
	if e == nil {
		e = &txtLease{values: map[string]bool{}}
		l.entries[fqdn] = e
	}
	e.refs++
	l.mu.Unlock()

	var once sync.Once
	return &e.mu, func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			e.refs--
			if e.refs == 0 && len(e.values) == 0 {
				// Nothing live at the name and nobody using the mutex: drop the entry,
				// so a long-running process does not accumulate one mutex per FQDN
				// forever.
				delete(l.entries, fqdn)
			}
		})
	}
}

// add records that this process relies on the value staying in DNS. Set semantics: a
// re-registration (a resumed order re-presenting nothing) must not inflate a count that
// CleanUp then never balances.
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
func (s *DNSSolver) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	fqdn := dns.Fqdn(info.EffectiveFQDN)

	mu, release := challengeLeases.lock(fqdn)
	defer release()
	mu.Lock()
	defer mu.Unlock()

	if challengeLeases.remove(fqdn, info.Value) {
		s.log.Info("another challenge is still live at the TXT name; leaving its cleanup to the last leaver",
			"name", fqdn)
		return nil
	}

	provider, err := s.newProvider(ctx)
	if err != nil {
		return fmt.Errorf("get the DNS provider: %w", err)
	}
	return provider.CleanUp(domain, token, keyAuth)
}

// LookupTXT asks the zone's **authoritative** nameservers whether this challenge's TXT
// record is currently in DNS, returning the record's identity either way so callers can
// persist it.
//
// It backs the two crash-recovery probes: a pass that died between the DNS write and the
// state persist left the record up while the authorization row denies it -- re-Present
// would duplicate the record, and deleting the row would orphan it.
//
// The answer is deliberately not taken from the recursive resolvers, even though they are
// cheaper. "found == false" is what licenses deleting the only row that records a value,
// and a recursive resolver's "no such record" is not evidence of absence:
//   - a negative answer can come from its cache, and DNSPod's 600s TTL floor applies to
//     the negative entry too, so a record written minutes ago can still be hidden;
//   - one name can carry several TXT values (two certificates, or a wildcard and its
//     apex, share one challenge name), and the cached answer may hold only some of them.
//
// The rules mirror probeReady's:
//   - confirmed by at least one authoritative server -> found, no error;
//   - denied by at least one and confirmed by none   -> absent (found=false, no error);
//   - nothing authoritative answered                 -> error, meaning "cannot tell".
//
// The last case must not be folded into "absent": the caller keeps the authorization row,
// which is the only record of the value, and retries next round.
func (s *DNSSolver) LookupTXT(ctx context.Context, domain, keyAuth string) (DNSRecord, bool, error) {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	rec := DNSRecord{
		FQDN:  dns.Fqdn(info.EffectiveFQDN),
		Value: info.Value,
	}

	zone, err := s.findZone(ctx, rec.FQDN)
	if err != nil {
		return rec, false, fmt.Errorf("find the zone of %s: %w", rec.FQDN, err)
	}
	servers, err := s.authoritativeNS(ctx, zone)
	if err != nil {
		return rec, false, fmt.Errorf("list the authoritative nameservers of %s: %w", zone, err)
	}

	results := probeTXTWithExchange(servers, rec.FQDN, rec.Value, s.authoritativeExchange())
	var confirmed, denied, unanswered int
	for _, r := range results {
		switch {
		case r.err != nil, !r.authoritative:
			unanswered++
		case r.hasValue:
			confirmed++
		default:
			denied++
		}
	}

	switch {
	case confirmed > 0:
		return rec, true, nil
	case denied > 0:
		return rec, false, nil
	default:
		return rec, false, fmt.Errorf(
			"cannot tell whether %s still carries the record: none of its %d authoritative nameservers answered",
			rec.FQDN, len(results))
	}
}

// authoritativeExchange is the exchange used for the authoritative probes: a short
// per-server deadline, and it ignores the caller's context on purpose.
//
// It must not inherit a cancelled context: the probes run during cleanup, and a shutdown
// racing them would turn a knowable answer into "cannot tell", which keeps rows around.
// The deadline is what bounds them instead.
func (s *DNSSolver) authoritativeExchange() func(*dns.Msg, string) (*dns.Msg, error) {
	return func(msg *dns.Msg, server string) (*dns.Msg, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return s.exchange(ctx, msg, server)
	}
}

func (s *DNSSolver) findZone(ctx context.Context, fqdn string) (string, error) {
	for _, domain := range domainSequence(fqdn) {
		msg := new(dns.Msg)
		msg.SetQuestion(domain, dns.TypeSOA)
		msg.RecursionDesired = true
		resp, err := s.queryRecursive(ctx, msg)
		if err != nil || resp == nil || resp.Rcode == dns.RcodeNameError {
			continue
		}
		if resp.Rcode != dns.RcodeSuccess {
			return "", fmt.Errorf("SOA lookup for %s returned %s", domain, dns.RcodeToString[resp.Rcode])
		}
		for _, rr := range resp.Answer {
			if soa, ok := rr.(*dns.SOA); ok {
				zone := dns.Fqdn(soa.Hdr.Name)
				if suffix, _ := publicsuffix.PublicSuffix(strings.TrimSuffix(zone, ".")); suffix != "" &&
					zone == dns.Fqdn(suffix) {
					// The SOA walk climbed all the way to the public suffix itself (a
					// typo'd exmaple.com ends up at the com. SOA). That "zone" can never
					// hold the TXT record, so treating it as found burns the whole
					// propagation budget querying TLD nameservers for nothing. Fail fast
					// with the likely cause instead.
					return "", fmt.Errorf(
						"%s has no hosted zone: the SOA walk stopped at the public suffix %s; check the domain for typos",
						fqdn, zone)
				}
				return zone, nil
			}
		}
	}
	return "", fmt.Errorf("could not find an SOA for %s via recursive resolvers %s", fqdn, strings.Join(s.recursiveNameservers, ","))
}

// nsServer is one address of one authoritative nameserver.
//
// The name is carried alongside the address because the propagation rule counts SERVERS, and one
// server commonly owns several addresses: DNSPod's pools publish three A records per NS name, and a
// dual-stack name publishes an A and an AAAA. Counting addresses instead made a single multi-homed
// authority look like two independent servers.
type nsServer struct {
	ns   string
	addr string
}

// authoritativeNS resolves the public NS delegation through the configured recursive resolver set.
func (s *DNSSolver) authoritativeNS(ctx context.Context, zone string) ([]nsServer, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(zone, dns.TypeNS)
	msg.RecursionDesired = true
	resp, err := s.queryRecursive(ctx, msg)
	if err != nil {
		return nil, fmt.Errorf("lookup NS for %s: %w", zone, err)
	}
	var names []string
	for _, rr := range resp.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			names = append(names, dns.Fqdn(ns.Ns))
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("%s has no NS records", zone)
	}

	var servers []nsServer
	seen := make(map[string]bool)
	for _, ns := range names {
		ips, err := s.lookupHost(ctx, ns)
		if err != nil {
			s.log.Warn("could not resolve an authoritative nameserver; skipping it", "ns", ns, "err", err)
			continue
		}
		for _, ip := range ips {
			addr := net.JoinHostPort(ip, "53")
			if !seen[addr] {
				seen[addr] = true
				servers = append(servers, nsServer{ns: ns, addr: addr})
			}
		}
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("none of %s's nameservers resolve to an address", zone)
	}
	return servers, nil
}

func (s *DNSSolver) probeRecords(servers []nsServer, recs []DNSRecord) []recordProbe {
	return probeRecordsWithExchange(servers, recs, s.authoritativeExchange())
}

func (s *DNSSolver) queryRecursive(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	var errs []error
	for _, resolver := range s.recursiveNameservers {
		resp, err := s.exchange(ctx, msg.Copy(), resolver)
		if err == nil && resp != nil && resp.Truncated {
			// exchangeDNS hands back the UDP answer when its TCP retry fails, with Truncated still
			// set so the caller can decide -- the probe paths do decide. Callers of this one read
			// the answer structurally (authoritativeNS builds the server list out of resp.Answer),
			// so accepting it would silently shrink the authority set, and a reduced set is how the
			// "two independent servers must agree" rule degrades into the single-authority
			// exemption it exists to avoid. Ask the next resolver instead.
			errs = append(errs, fmt.Errorf("%s: truncated answer (TCP retry failed)", resolver))
			continue
		}
		if err == nil && resp != nil && (resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError) {
			return resp, nil
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", resolver, err))
		} else if resp == nil {
			errs = append(errs, fmt.Errorf("%s: empty response", resolver))
		} else {
			errs = append(errs, fmt.Errorf("%s: DNS response %s", resolver, dns.RcodeToString[resp.Rcode]))
		}
	}
	return nil, fmt.Errorf("all configured recursive resolvers failed: %w", errors.Join(errs...))
}

func (s *DNSSolver) lookupHost(ctx context.Context, host string) ([]string, error) {
	var ips []string
	var errs []error
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		msg := new(dns.Msg)
		msg.SetQuestion(host, qtype)
		msg.RecursionDesired = true
		resp, err := s.queryRecursive(ctx, msg)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, rr := range resp.Answer {
			switch r := rr.(type) {
			case *dns.A:
				ips = append(ips, r.A.String())
			case *dns.AAAA:
				ips = append(ips, r.AAAA.String())
			}
		}
	}
	if len(ips) == 0 {
		if len(errs) == 0 {
			return nil, errors.New("no A or AAAA records")
		}
		return nil, fmt.Errorf("no A or AAAA records: %w", errors.Join(errs...))
	}
	return ips, nil
}

func recursiveNameservers(configured []string) ([]string, error) {
	if len(configured) > 0 {
		return append([]string(nil), configured...), nil
	}
	resolv, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("read recursive nameservers from /etc/resolv.conf: %w", err)
	}
	if len(resolv.Servers) == 0 {
		return nil, errors.New("/etc/resolv.conf contains no nameservers")
	}
	servers := make([]string, 0, len(resolv.Servers))
	for _, server := range resolv.Servers {
		servers = append(servers, net.JoinHostPort(server, resolv.Port))
	}
	return servers, nil
}

// exchangeDNS asks one server, retrying over TCP when the UDP answer was truncated.
//
// The TCP attempt does not replace the UDP answer on failure. The two share the caller's 3-second
// context, and a server that is slow to accept TCP is exactly the case this retry exists for, so
// overwriting `resp` there meant discarding a truncated-but-real answer -- including one whose
// answer section already carried the value being looked for -- and reporting the server as
// unreachable. The truncated answer is returned instead, with Truncated still set, and the caller
// decides: probeTXT classifies it as unreachable (an incomplete answer is not a denial) rather than
// reading the missing record as "not propagated".
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
