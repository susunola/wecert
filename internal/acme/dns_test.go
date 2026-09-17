package acme

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/miekg/dns"
)

func dnsReply(question *dns.Msg, answers ...dns.RR) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(question)
	resp.Answer = append(resp.Answer, answers...)
	return resp
}

func TestConfiguredDiscoveryUsesOneResolverViewAndAuthoritativeTXT(t *testing.T) {
	resolver, authority := "192.0.2.53:53", "198.51.100.53:53"
	solver := &DNSSolver{recursiveNameservers: []string{resolver}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	var seen []string
	solver.exchange = func(_ context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
		seen = append(seen, server+"|"+dns.TypeToString[msg.Question[0].Qtype])
		name := msg.Question[0].Name
		switch server {
		case resolver:
			switch msg.Question[0].Qtype {
			case dns.TypeSOA:
				return dnsReply(msg, &dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET}, Ns: "ns1.example.net."}), nil
			case dns.TypeNS:
				return dnsReply(msg, &dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ns1.example.net."}), nil
			case dns.TypeA:
				if name == "ns1.example.net." {
					return dnsReply(msg, &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: []byte{198, 51, 100, 53}}), nil
				}
			case dns.TypeAAAA:
				return dnsReply(msg), nil
			}
		case authority:
			resp := dnsReply(msg, &dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{"wanted"}})
			resp.Authoritative = true
			return resp, nil
		}
		return nil, fmt.Errorf("unexpected query %s to %s", name, server)
	}
	zone, err := solver.findZone(context.Background(), "_acme-challenge.example.com.")
	if err != nil || zone != "example.com." {
		t.Fatalf("findZone = %q, %v", zone, err)
	}
	servers, err := solver.authoritativeNS(context.Background(), zone)
	if err != nil || len(servers) != 1 || servers[0].addr != authority {
		t.Fatalf("authoritativeNS = %v, %v", servers, err)
	}
	results := solver.probeRecords(servers, []DNSRecord{{FQDN: "_acme-challenge.example.com.", Value: "wanted"}})
	if len(results) != 1 || !results[0].ready {
		t.Fatalf("authoritative TXT should pass, got %+v", results)
	}
	for _, call := range seen {
		if call != authority+"|TXT" && !strings.HasPrefix(call, resolver) {
			t.Errorf("discovery queried an unexpected server: %s", call)
		}
	}
}

func TestNonAuthoritativeTXTResponseDoesNotPassPropagation(t *testing.T) {
	ready, summary := probeReadyWithExchange(oneAuthority("192.0.2.53:53"), "_acme-challenge.example.com.", "wanted", func(msg *dns.Msg, _ string) (*dns.Msg, error) {
		return dnsReply(msg, &dns.TXT{Hdr: dns.RR_Header{Name: "_acme-challenge.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{"wanted"}}), nil
	})
	if ready {
		t.Fatalf("a recursive/non-authoritative TXT response must not pass: %s", summary)
	}
}

func TestRecursiveDiscoveryFallsBackToNextConfiguredResolver(t *testing.T) {
	solver := &DNSSolver{recursiveNameservers: []string{"192.0.2.1:53", "192.0.2.2:53"}}
	solver.exchange = func(_ context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
		if server == "192.0.2.1:53" {
			return nil, errors.New("unreachable")
		}
		return dnsReply(msg, &dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET}, Ns: "ns1.example.net."}), nil
	}
	zone, err := solver.findZone(context.Background(), "_acme-challenge.example.com.")
	if err != nil || zone != "example.com." {
		t.Fatalf("fallback resolver did not find the zone: %q, %v", zone, err)
	}
}

// txtResponse builds a response containing the given TXT records.
func txtResponse(values ...string) *dns.Msg {
	m := new(dns.Msg)
	for _, v := range values {
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   "_acme-challenge.example.com.",
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
			},
			Txt: []string{v},
		})
	}
	return m
}

// probeRecords must put each result back at its own index.
//
// This is the one place the concurrent rewrite can easily go wrong: each goroutine
// writes only its own slot, so a crossed index shows up as "propagation waiting never
// passes for a few names while the rest are fine" -- hell to diagnose, worse with more SANs.
//
// Driven by an empty NS list: no network requests, but the whole concurrent path runs.
func TestProbeRecordsPreservesOrder(t *testing.T) {
	const n = 20 // deliberately above maxProbeConcurrency to force queueing

	recs := make([]DNSRecord, 0, n)
	for i := 0; i < n; i++ {
		recs = append(recs, DNSRecord{
			FQDN:  fmt.Sprintf("_acme-challenge.host%02d.example.com.", i),
			Value: fmt.Sprintf("value-%02d", i),
		})
	}

	got := probeRecords(nil, recs)

	if len(got) != n {
		t.Fatalf("got %d results, want %d", len(got), n)
	}
	for i, res := range got {
		if res.record.FQDN != recs[i].FQDN || res.record.Value != recs[i].Value {
			t.Errorf("index %d crossed: got %s=%s, want %s=%s",
				i, res.record.FQDN, res.record.Value, recs[i].FQDN, recs[i].Value)
		}
		if res.ready {
			t.Errorf("index %d must not be reported ready when there are no authoritative NS", i)
		}
		if res.summary == "" {
			t.Errorf("index %d is missing a diagnostic summary", i)
		}
	}
}

func TestProbeRecordsEmpty(t *testing.T) {
	if got := probeRecords(nil, nil); len(got) != 0 {
		t.Errorf("empty input should yield an empty result, got %d", len(got))
	}
}

// A single record must not break on the concurrency pool's edge handling.
func TestProbeRecordsSingle(t *testing.T) {
	got := probeRecords(nil, []DNSRecord{{FQDN: "_acme-challenge.a.example.com.", Value: "v"}})
	if len(got) != 1 {
		t.Fatalf("got %d results", len(got))
	}
	if got[0].record.Value != "v" {
		t.Errorf("record mismatch: %+v", got[0].record)
	}
}

// probeReady's rule: no reachable NS denies the value, and at least one confirms it --
// two when the zone has several authorities.
// This exercises the rule itself, with no real DNS involved.
func TestProbeReadyJudgement(t *testing.T) {
	// No reachable NS: neither confirmed nor allowed through.
	ready, summary := probeReady(nil, "_acme-challenge.example.com.", "v")
	if ready {
		t.Error("letting it through with zero NS probed makes CA validation fail and burns quota")
	}
	if summary == "" {
		t.Error("a human-readable summary should be returned")
	}
}

// responseHasTXT must handle a TXT value split into several string segments,
// and pick the matching one out of several TXT records (as when wildcard + apex coexist).
func TestResponseHasTXT(t *testing.T) {
	// Two TXT records on the same name is the normal wildcard + apex case.
	if !responseHasTXT(txtResponse("other-value", "wanted-value"), "wanted-value") {
		t.Error("the matching value should be found among several TXT records")
	}
	if responseHasTXT(txtResponse("other-value"), "wanted-value") {
		t.Error("a value that is not present must not count as a hit")
	}

	// A TXT record over 255 bytes is split into segments; join them first, then compare.
	// Skip it and a long key authorization reads as "not propagated", then waits out the timeout for nothing.
	segmented := &dns.Msg{}
	segmented.Answer = append(segmented.Answer, &dns.TXT{
		Hdr: dns.RR_Header{Name: "_acme-challenge.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET},
		Txt: []string{"wanted-", "value"},
	})
	if !responseHasTXT(segmented, "wanted-value") {
		t.Error("a segmented TXT must be joined before comparison")
	}

	if responseHasTXT(txtResponse(), "anything") {
		t.Error("an empty response must not count as a hit")
	}
}

// recordingProvider is a challenge.Provider that records which operations actually reached
// the DNS API -- the lease registry's whole job is deciding when the delete-all call may fire.
type recordingProvider struct {
	presents []string
	cleanups []string
}

func (p *recordingProvider) Present(domain, _, _ string) error {
	p.presents = append(p.presents, domain)
	return nil
}

func (p *recordingProvider) CleanUp(domain, _, _ string) error {
	p.cleanups = append(p.cleanups, domain)
	return nil
}

// lego's provider CleanUp deletes **every** TXT record at the challenge name, so it must
// never run while another value is still live there: two certificates can share one domain
// (config dedups certificate names, not domains), and cert A's cleanup would otherwise kill
// cert B's pending challenge. The deletion is deferred to the last leaver, whose single
// delete-all call removes every record at the name.
func TestCleanUpDefersDeleteAllWhileAnotherValueIsLive(t *testing.T) {
	// No network CNAME chase inside GetChallengeInfo; the registry is package state, so
	// give this test a private one to keep the assertion independent of other tests.
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")
	saved := challengeLeases
	challengeLeases = newTXTLeases()
	t.Cleanup(func() { challengeLeases = saved })

	p := &recordingProvider{}
	solver := &DNSSolver{
		newProvider: func(context.Context) (challenge.Provider, error) { return p, nil },
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	ctx := context.Background()

	// Two certificates (or a wildcard and its apex) share one challenge name; the two key
	// authorizations hash to two different TXT values.
	if _, err := solver.Present(ctx, "shared.example.com", "tok-a", "keyauth-a"); err != nil {
		t.Fatalf("Present A: %v", err)
	}
	if _, err := solver.Present(ctx, "shared.example.com", "tok-b", "keyauth-b"); err != nil {
		t.Fatalf("Present B: %v", err)
	}

	// A finishes first: the delete-all must NOT fire, B's record would die with it.
	if err := solver.CleanUp(ctx, "shared.example.com", "tok-a", "keyauth-a"); err != nil {
		t.Fatalf("CleanUp A: %v", err)
	}
	if len(p.cleanups) != 0 {
		t.Fatalf("cleanup while another value is live must not call the provider, got %v", p.cleanups)
	}

	// B is the last leaver: one delete-all call removes every record at the name,
	// including the one A had to skip.
	if err := solver.CleanUp(ctx, "shared.example.com", "tok-b", "keyauth-b"); err != nil {
		t.Fatalf("CleanUp B: %v", err)
	}
	if len(p.cleanups) != 1 {
		t.Fatalf("the last leaver must run the delete-all exactly once, got %v", p.cleanups)
	}
}

// A typo'd domain (exmaple.com) has no SOA of its own, so the walk climbs to the TLD's SOA.
// Accepting "com." as the zone burns the whole propagation budget querying TLD nameservers
// for a record that can never exist -- findZone must fail fast instead.
func TestFindZoneFailsFastOnPublicSuffix(t *testing.T) {
	resolver := "192.0.2.53:53"
	solver := &DNSSolver{
		recursiveNameservers: []string{resolver},
		log:                  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	var queries []string
	solver.exchange = func(_ context.Context, msg *dns.Msg, _ string) (*dns.Msg, error) {
		name := msg.Question[0].Name
		queries = append(queries, name)
		if name == "com." {
			return dnsReply(msg, &dns.SOA{Hdr: dns.RR_Header{Name: "com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET}, Ns: "a.gtld-servers.net."}), nil
		}
		resp := dnsReply(msg)
		resp.Rcode = dns.RcodeNameError
		return resp, nil
	}

	zone, err := solver.findZone(context.Background(), "_acme-challenge.exmaple.com.")
	if err == nil {
		t.Fatalf("a zone equal to the public suffix must be treated as not found, got zone %q", zone)
	}
	if !strings.Contains(err.Error(), "public suffix") {
		t.Errorf("the error must say why this is almost certainly a typo, got: %v", err)
	}
	// The walk stops at the TLD's SOA; it must never go probing beyond it.
	if len(queries) > 3 {
		t.Errorf("the walk should have stopped at the public suffix, but kept querying: %v", queries)
	}
}

// ---------- LookupTXT: the reclaim probe must be authoritative ----------

// cachedNXDOMAINHarness scripts the failure mode that forced the reclaim probe to become
// authoritative: the recursive resolver serves a **negatively cached** NXDOMAIN for the
// TXT (the record was written after the negative answer got cached, and DNSPod's SOA
// negative TTL is ~600s), while the zone's authoritative nameserver answers per
// authorityReply.
func cachedNXDOMAINHarness(
	t *testing.T,
	authorityReply func(msg *dns.Msg, name, value string) (*dns.Msg, error),
) (*DNSSolver, DNSRecord, *int) {
	t.Helper()
	// No network CNAME chase inside GetChallengeInfo.
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")

	info := dns01.GetChallengeInfo("example.com", "keyauth-1")
	rec := DNSRecord{FQDN: dns.Fqdn(info.EffectiveFQDN), Value: info.Value}

	resolver, authority := "192.0.2.53:53", "198.51.100.53:53"
	solver := &DNSSolver{
		recursiveNameservers: []string{resolver},
		log:                  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	authorityQueries := 0
	solver.exchange = func(_ context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
		name := msg.Question[0].Name
		switch server {
		case resolver:
			switch msg.Question[0].Qtype {
			case dns.TypeSOA:
				if name == "example.com." {
					return dnsReply(msg, &dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET}, Ns: "ns1.example.net."}), nil
				}
				resp := dnsReply(msg)
				resp.Rcode = dns.RcodeNameError
				return resp, nil
			case dns.TypeNS:
				return dnsReply(msg, &dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET}, Ns: "ns1.example.net."}), nil
			case dns.TypeA:
				if name == "ns1.example.net." {
					return dnsReply(msg, &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: []byte{198, 51, 100, 53}}), nil
				}
			case dns.TypeAAAA:
				return dnsReply(msg), nil
			case dns.TypeTXT:
				// The negatively cached answer: NXDOMAIN even though the record may
				// already exist at the authority.
				resp := dnsReply(msg)
				resp.Rcode = dns.RcodeNameError
				return resp, nil
			}
		case authority:
			authorityQueries++
			return authorityReply(msg, name, rec.Value)
		}
		return nil, fmt.Errorf("unexpected query %s type %d to %s", name, msg.Question[0].Qtype, server)
	}
	return solver, rec, &authorityQueries
}

// The reclaim probe used to trust the recursive resolver's first answer, so a negatively
// cached NXDOMAIN read as "the record is gone" -- the state row got deleted while the
// TXT lived on in DNSPod forever. The negative answer must be confirmed against the
// authority, which here says the record is up.
func TestLookupTXTDistrustsACachedNXDOMAIN(t *testing.T) {
	solver, rec, authorityQueries := cachedNXDOMAINHarness(t,
		func(msg *dns.Msg, name, value string) (*dns.Msg, error) {
			resp := dnsReply(msg, &dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{value}})
			resp.Authoritative = true
			return resp, nil
		})

	got, found, err := solver.LookupTXT(context.Background(), "example.com", "keyauth-1")
	if err != nil {
		t.Fatalf("LookupTXT: %v", err)
	}
	if !found {
		t.Error("the authority holds the record; the cached NXDOMAIN must not win")
	}
	if got != rec {
		t.Errorf("record identity = %+v, want %+v", got, rec)
	}
	if *authorityQueries == 0 {
		t.Error("a negative recursive answer must be confirmed against the authority")
	}
}

// Only an authoritative denial may count as "truly absent" -- that is the answer the
// reclaim path may delete the state row on.
func TestLookupTXTAuthoritativeNXDOMAINIsTrulyAbsent(t *testing.T) {
	solver, _, _ := cachedNXDOMAINHarness(t,
		func(msg *dns.Msg, _, _ string) (*dns.Msg, error) {
			resp := dnsReply(msg)
			resp.Rcode = dns.RcodeNameError
			resp.Authoritative = true
			return resp, nil
		})

	_, found, err := solver.LookupTXT(context.Background(), "example.com", "keyauth-1")
	if err != nil {
		t.Fatalf("an authoritative NXDOMAIN is a definitive answer, not an error: %v", err)
	}
	if found {
		t.Error("every reachable authority denies the record; it is truly absent")
	}
}

// No authoritative answer at all (the NS is unreachable): the record's fate is unknown,
// and an error is what makes the callers keep the state row.
func TestLookupTXTWithNoAuthoritativeAnswerKeepsTheFateUnknown(t *testing.T) {
	solver, _, _ := cachedNXDOMAINHarness(t,
		func(_ *dns.Msg, _, _ string) (*dns.Msg, error) {
			return nil, errors.New("unreachable")
		})

	_, found, err := solver.LookupTXT(context.Background(), "example.com", "keyauth-1")
	if err == nil {
		t.Error("with no authoritative answer the fate is unknown; that must be an error so the row is kept")
	}
	if found {
		t.Error("a failed probe must never report the record as present")
	}
}

// ---------- txtLeases: pruning must never split the per-name mutex ----------

// The lease registry must not accumulate one mutex per challenge FQDN forever: an entry
// is pruned once no value is live at the name and no goroutine can still be using the
// per-name mutex.
func TestTXTLeasesPrunesEmptyEntries(t *testing.T) {
	l := newTXTLeases()
	const fqdn = "_acme-challenge.example.com."

	mu, release := l.lock(fqdn)
	mu.Lock()
	l.add(fqdn, "v")
	if others := l.remove(fqdn, "v"); others {
		t.Fatal("no other value is live at the name")
	}
	mu.Unlock()
	release()

	l.mu.Lock()
	_, kept := l.entries[fqdn]
	l.mu.Unlock()
	if kept {
		t.Error("an entry with no live values and no users must be pruned")
	}

	// A name that still has live values must survive: the last leaver's delete-all
	// depends on finding it.
	l.add(fqdn, "still-live")
	l.mu.Lock()
	_, kept = l.entries[fqdn]
	l.mu.Unlock()
	if !kept {
		t.Error("an entry with live values must not be pruned")
	}
}

// The pruning hazard: a goroutine that already fetched the per-name mutex but has not
// locked it yet must never end up excluded by a **different** mutex than a goroutine
// that arrives after a prune -- then two provider calls run concurrently at the same
// name, which is the race the registry exists to prevent. The reference count taken in
// lock (before the mutex is touched) is what keeps that impossible; this hammers the
// window and lets the inside-counter (and -race) catch a regression.
func TestTXTLeasesPruneNeverSplitsTheMutex(t *testing.T) {
	l := newTXTLeases()
	const fqdn = "_acme-challenge.race.example."

	var guard sync.Mutex
	inside := 0
	split := false

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				mu, release := l.lock(fqdn)
				mu.Lock()

				guard.Lock()
				inside++
				if inside > 1 {
					split = true
				}
				guard.Unlock()

				l.add(fqdn, "v")
				_ = l.remove(fqdn, "v")

				guard.Lock()
				inside--
				guard.Unlock()

				mu.Unlock()
				release()
			}
		}()
	}
	wg.Wait()

	if split {
		t.Error("two goroutines were inside the per-name critical section at once: the prune split the mutex")
	}
}

// Registering a lease must serialize with CleanUp's check-then-delete.
//
// CleanUp holds the name's mutex across "is any other value live at this name?" and the
// provider's delete-EVERY-TXT call. A lease registered OUTSIDE that mutex can land between
// the two: the check does not see it, the delete-all fires, and the value that was just
// registered is gone -- so the CA is asked to validate a record that no longer exists, which
// books a billed authorization failure against the 5-per-hour-per-identifier limit and adds
// an identifier-ledger entry that arms the failure fallback.
//
// The two unsafe paths were WaitAll (re-registering the records of a resumed order, whose TXT
// a previous process wrote) and registerRecoveredLeases. Present was already safe because it
// adds while holding the mutex.
//
// The property is directly observable: while a test holds the name's mutex, an add that takes
// it must block, and an add that does not take it completes immediately.
func TestLeaseRegistrationHoldsTheNameLock(t *testing.T) {
	const fqdn = "_acme-challenge.lock-probe.example.com."

	mu, release := challengeLeases.lock(fqdn)
	defer release()
	mu.Lock()

	done := make(chan struct{})
	go func() {
		challengeLeases.addUnderLock(fqdn, "value-must-wait")
		close(done)
	}()

	select {
	case <-done:
		mu.Unlock()
		t.Fatal("addUnderLock completed while the name's mutex was held: it does not serialize " +
			"with CleanUp's check-then-delete, so a concurrent cleanup can delete the value it registers")
	case <-time.After(150 * time.Millisecond):
		// Blocked, as it must be.
	}

	// The contrast that shows the test can tell the two apart: the plain add does NOT block,
	// which is exactly why the two call sites had to change.
	plain := make(chan struct{})
	go func() {
		challengeLeases.add(fqdn, "value-without-lock")
		close(plain)
	}()
	select {
	case <-plain:
	case <-time.After(2 * time.Second):
		mu.Unlock()
		t.Fatal("the plain add should not take the name mutex; this test's premise is wrong")
	}

	mu.Unlock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("addUnderLock never completed after the mutex was released")
	}
}

// oneAuthority builds a single NS name whose addresses are the given ones.
//
// The confirmation rule counts NS names, so a test that wants "two independent servers" has to say
// whether its addresses belong to one name or two -- which is exactly the distinction the rule is
// about.
func oneAuthority(addrs ...string) []nsServer {
	out := make([]nsServer, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, nsServer{ns: "ns1.example.net.", addr: a})
	}
	return out
}

// The success verdict must carry the evidence it rests on, not just a server count.
//
// "TXT propagated" is a lower bound on global propagation derived from this host's view: an
// authority that is unreachable from here contributes nothing, while the CA's resolver may
// reach it and be told the record does not exist. That asymmetry is what turned a
// "propagated" verdict into an NXDOMAIN at the CA in production, and with only
// `nameservers=10 records=1` in the log there was no way to see afterwards how thin the
// evidence had been.
func TestPropagatedVerdictLogsItsEvidenceIncludingUnreachableAuthorities(t *testing.T) {
	var logs bytes.Buffer
	solver := &DNSSolver{
		recursiveNameservers: []string{"192.0.2.53:53"},
		log:                  slog.New(slog.NewTextHandler(&logs, nil)),
		interval:             time.Millisecond,
		timeout:              5 * time.Second,
		exchange: func(_ context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
			switch server {
			case "198.51.100.1:53", "198.51.100.2:53":
				resp := dnsReply(msg, &dns.TXT{
					Hdr: dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET},
					Txt: []string{"wanted"},
				})
				resp.Authoritative = true
				return resp, nil
			}
			// One authority is unreachable from here -- exactly the case that used to be
			// invisible in the success line.
			return nil, errors.New("network unreachable")
		},
	}
	servers := []nsServer{
		{ns: "ns1.example.net.", addr: "198.51.100.1:53"},
		{ns: "ns2.example.net.", addr: "198.51.100.2:53"},
		{ns: "ns3.example.net.", addr: "198.51.100.3:53"},
	}
	recs := []DNSRecord{{FQDN: "_acme-challenge.example.com.", Value: "wanted"}}
	now := time.Now()
	budget := zoneBudget{passStart: now, zoneStart: now, deadline: now.Add(5 * time.Second)}

	if err := solver.waitZone(context.Background(), "example.com.", servers, recs, budget); err != nil {
		t.Fatalf("two authorities confirmed and none denied, so this is propagated: %v", err)
	}
	out := logs.String()
	for _, want := range []string{"TXT propagated", "confirmed 2/3 server(s)", "unreachable 1 (of 3 addresses)"} {
		if !strings.Contains(out, want) {
			t.Errorf("the success line must carry the evidence it rests on; %q is missing from:\n%s", want, out)
		}
	}
}

// recursiveTestSolver builds a solver whose authoritative servers always confirm the value and
// whose single configured recursive resolver answers however the test says.
func recursiveTestSolver(t *testing.T, logs *bytes.Buffer, resolver func(*dns.Msg) (*dns.Msg, error)) *DNSSolver {
	t.Helper()
	const resolverAddr = "192.0.2.53:53"
	return &DNSSolver{
		recursiveNameservers: []string{resolverAddr},
		log:                  slog.New(slog.NewTextHandler(logs, nil)),
		interval:             time.Millisecond,
		timeout:              2 * time.Second,
		exchange: func(_ context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
			if server == resolverAddr {
				return resolver(msg)
			}
			resp := dnsReply(msg, &dns.TXT{
				Hdr: dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET},
				Txt: []string{"wanted"},
			})
			resp.Authoritative = true
			return resp, nil
		},
	}
}

func recursiveTestServers() []nsServer {
	return []nsServer{
		{ns: "ns1.example.net.", addr: "198.51.100.1:53"},
		{ns: "ns2.example.net.", addr: "198.51.100.2:53"},
	}
}

func recursiveTestBudget(d time.Duration) zoneBudget {
	now := time.Now()
	return zoneBudget{passStart: now, zoneStart: now, deadline: now.Add(d)}
}

// The verdict must not be handed to the CA while the path the CA actually uses says no.
//
// This is the production failure this check exists for: every authoritative server wecert
// could reach confirmed the value, so the old rule said "propagated", and the CA -- resolving
// through a recursive resolver that reached a lagging authority -- was told NXDOMAIN. The
// failed validation then cost a quota slot (5 per hour per identifier) for a round that could
// simply have waited.
func TestRecursiveDenialBlocksAnOtherwiseConfirmedVerdict(t *testing.T) {
	var logs bytes.Buffer
	solver := recursiveTestSolver(t, &logs, func(msg *dns.Msg) (*dns.Msg, error) {
		resp := new(dns.Msg)
		resp.SetRcode(msg, dns.RcodeNameError)
		return resp, nil
	})
	recs := []DNSRecord{{FQDN: "_acme-challenge.example.com.", Value: "wanted"}}

	err := solver.waitZone(context.Background(), "example.com.", recursiveTestServers(), recs,
		recursiveTestBudget(60*time.Millisecond))
	if err == nil {
		t.Fatal("every recursive resolver answered NXDOMAIN, which is exactly what the CA would be " +
			"handed; reporting this as propagated spends a failed-validation quota slot for nothing")
	}
	if !strings.Contains(err.Error(), "recursive") {
		t.Errorf("the timeout must say the recursive view is what held it back, got: %v", err)
	}
}

// A recursive resolver that has the value is the happy path, and it must still pass.
func TestRecursiveConfirmationAllowsTheVerdict(t *testing.T) {
	var logs bytes.Buffer
	solver := recursiveTestSolver(t, &logs, func(msg *dns.Msg) (*dns.Msg, error) {
		return dnsReply(msg, &dns.TXT{
			Hdr: dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET},
			Txt: []string{"wanted"},
		}), nil
	})
	recs := []DNSRecord{{FQDN: "_acme-challenge.example.com.", Value: "wanted"}}

	if err := solver.waitZone(context.Background(), "example.com.", recursiveTestServers(), recs,
		recursiveTestBudget(2*time.Second)); err != nil {
		t.Fatalf("both views have the value, so this is propagated: %v", err)
	}
}

// "Nobody answered" must not become "refuse to issue": a host with no usable public DNS still
// has to be able to get certificates, and the authoritative verdict already passed.
func TestUnreachableRecursiveResolversDegradeToAWarning(t *testing.T) {
	var logs bytes.Buffer
	solver := recursiveTestSolver(t, &logs, func(*dns.Msg) (*dns.Msg, error) {
		return nil, errors.New("network unreachable")
	})
	recs := []DNSRecord{{FQDN: "_acme-challenge.example.com.", Value: "wanted"}}

	if err := solver.waitZone(context.Background(), "example.com.", recursiveTestServers(), recs,
		recursiveTestBudget(2*time.Second)); err != nil {
		t.Fatalf("no recursive resolver was reachable, so the authoritative verdict stands: %v", err)
	}
	if !strings.Contains(logs.String(), "no recursive resolver could answer") {
		t.Errorf("degrading must be visible in the log, got:\n%s", logs.String())
	}
}
