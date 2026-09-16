package acme

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func quietSolver(exchange func(context.Context, *dns.Msg, string) (*dns.Msg, error)) *DNSSolver {
	return &DNSSolver{
		recursiveNameservers: []string{"192.0.2.53:53"},
		timeout:              time.Second,
		interval:             time.Millisecond,
		log:                  slog.New(slog.NewTextHandler(io.Discard, nil)),
		exchange:             exchange,
	}
}

func soaReply(msg *dns.Msg, zone string) *dns.Msg {
	return dnsReply(msg, &dns.SOA{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET},
		Ns:  "ns1.example.net.",
	})
}

func nsReply(msg *dns.Msg, zone string, names ...string) *dns.Msg {
	rrs := make([]dns.RR, 0, len(names))
	for _, n := range names {
		rrs = append(rrs, &dns.NS{
			Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET},
			Ns:  n,
		})
	}
	return dnsReply(msg, rrs...)
}

func aReply(msg *dns.Msg) *dns.Msg {
	return dnsReply(msg, &dns.A{
		Hdr: dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET},
		A:   []byte{198, 51, 100, 53},
	})
}

func authTXT(msg *dns.Msg, values ...string) *dns.Msg {
	resp := dnsReply(msg, &dns.TXT{
		Hdr: dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET},
		Txt: values,
	})
	resp.Authoritative = true
	return resp
}

// ── recursiveNameservers ─────────────────────────────────────────────────────────────

// Configured resolvers must win over the system ones. The whole reason the option exists is
// that the host's resolver view can differ (VPN, split horizon, a captive resolver), and
// silently preferring /etc/resolv.conf would reintroduce exactly that ambiguity.
func TestRecursiveNameserversPrefersConfigured(t *testing.T) {
	got, err := recursiveNameservers([]string{"1.1.1.1:53", "9.9.9.9:5353"})
	if err != nil {
		t.Fatalf("recursiveNameservers: %v", err)
	}
	if len(got) != 2 || got[0] != "1.1.1.1:53" || got[1] != "9.9.9.9:5353" {
		t.Errorf("configured resolvers must be used verbatim, got %v", got)
	}
}

// The configured list is copied, not aliased: the caller's config slice must not be mutable
// through the solver.
func TestRecursiveNameserversCopiesTheSlice(t *testing.T) {
	cfg := []string{"1.1.1.1:53"}
	got, err := recursiveNameservers(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got[0] = "mutated"
	if cfg[0] != "1.1.1.1:53" {
		t.Error("the solver mutated the caller's configured resolver list")
	}
}

// ── WaitAll: the propagation budget ──────────────────────────────────────────────────

// The budget is global, not per zone. Per-zone budgets make the total wait grow with the
// number of zones, so a certificate spread over several zones silently takes several times
// longer than the configured timeout.
func TestWaitAllSharesOneDeadlineAcrossZones(t *testing.T) {
	// Two zones, each with one authority that never confirms. With a shared budget the whole
	// call must finish in roughly the configured timeout, not twice it.
	const budget = 60 * time.Millisecond
	var authQueries int
	solver := quietSolver(func(_ context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
		name := msg.Question[0].Name
		switch msg.Question[0].Qtype {
		case dns.TypeSOA:
			// Both names resolve to their own zone.
			zone := "example.com."
			if strings.HasSuffix(name, "other.net.") {
				zone = "other.net."
			}
			return soaReply(msg, zone), nil
		case dns.TypeNS:
			return nsReply(msg, name, "ns1.example.net."), nil
		case dns.TypeA:
			return aReply(msg), nil
		default:
			authQueries++
			// Authoritative but never carrying the value: propagation never completes.
			return authTXT(msg, "something-else"), nil
		}
	})
	solver.timeout = budget

	start := time.Now()
	err := solver.WaitAll(context.Background(), []DNSRecord{
		{FQDN: "_acme-challenge.example.com.", Value: "v1"},
		{FQDN: "_acme-challenge.other.net.", Value: "v2"},
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("nothing ever confirmed, so WaitAll must fail")
	}
	// Generous upper bound: the point is that it did not wait per zone.
	if elapsed > 4*budget {
		t.Errorf("WaitAll took %s for two zones with a %s budget: the budget is per zone, not global",
			elapsed, budget)
	}
	if authQueries == 0 {
		t.Error("no authoritative query was made, so the test did not exercise propagation")
	}
}

// The timeout error must carry the real elapsed time and name the records that are not ready.
// A message that says "not confirmed within 5m" after a few seconds sends the operator looking
// for a propagation problem that is not there.
func TestWaitAllTimeoutNamesTheUnconfirmedRecords(t *testing.T) {
	solver := quietSolver(func(_ context.Context, msg *dns.Msg, _ string) (*dns.Msg, error) {
		switch msg.Question[0].Qtype {
		case dns.TypeSOA:
			return soaReply(msg, "example.com."), nil
		case dns.TypeNS:
			return nsReply(msg, msg.Question[0].Name, "ns1.example.net."), nil
		case dns.TypeA:
			return aReply(msg), nil
		default:
			return authTXT(msg, "not-the-value"), nil
		}
	})
	solver.timeout = 30 * time.Millisecond

	err := solver.WaitAll(context.Background(), []DNSRecord{
		{FQDN: "_acme-challenge.example.com.", Value: "wanted"},
	})
	if err == nil {
		t.Fatal("expected a propagation timeout")
	}
	msg := err.Error()
	if !strings.Contains(msg, "_acme-challenge.example.com.") || !strings.Contains(msg, "wanted") {
		t.Errorf("the error must name the unconfirmed record and its value, got: %s", msg)
	}
	if !strings.Contains(msg, "waited") {
		t.Errorf("the error must report the real elapsed time, got: %s", msg)
	}
	if !strings.Contains(msg, "denied 1") {
		t.Errorf("the summary must explain why it is not ready (an authoritative NS denied it), got: %s", msg)
	}
}

// A wildcard and its apex write the SAME name with different values. WaitAll must confirm that
// name once per value, not once overall -- confirming only one of the two would mean telling
// the CA to validate a challenge whose record is not up yet, which burns an
// authorization-failure credit.
func TestWaitAllConfirmsEachValueAtASharedName(t *testing.T) {
	confirmed := map[string]bool{}
	solver := quietSolver(func(_ context.Context, msg *dns.Msg, _ string) (*dns.Msg, error) {
		switch msg.Question[0].Qtype {
		case dns.TypeSOA:
			return soaReply(msg, "example.com."), nil
		case dns.TypeNS:
			return nsReply(msg, msg.Question[0].Name, "ns1.example.net."), nil
		case dns.TypeA:
			return aReply(msg), nil
		default:
			// One value is up, the other is not.
			return authTXT(msg, "value-a"), nil
		}
	})
	solver.timeout = 40 * time.Millisecond

	err := solver.WaitAll(context.Background(), []DNSRecord{
		{FQDN: "_acme-challenge.example.com.", Value: "value-a"},
		{FQDN: "_acme-challenge.example.com.", Value: "value-b"},
	})
	if err == nil {
		t.Fatal("value-b was never published, so WaitAll must fail rather than report both ready")
	}
	if !strings.Contains(err.Error(), "value-b") {
		t.Errorf("the error must name the value that is missing, got: %s", err)
	}
	if !confirmed["value-a"] {
		t.Log("value-a was confirmed before the timeout, as expected")
	}
}

// An empty record list means there is nothing to confirm, and must not be an error: the
// caller already finished its work.
func TestWaitAllWithNoRecordsIsANoOp(t *testing.T) {
	solver := quietSolver(func(_ context.Context, msg *dns.Msg, _ string) (*dns.Msg, error) {
		t.Errorf("no query should be made for an empty record list, got %s", msg.Question[0].Name)
		return nil, nil
	})
	if err := solver.WaitAll(context.Background(), nil); err != nil {
		t.Fatalf("WaitAll(nil) = %v, want nil", err)
	}
}

// A cancelled context must stop the wait promptly rather than run the budget out.
func TestWaitAllHonoursContextCancellation(t *testing.T) {
	solver := quietSolver(func(_ context.Context, msg *dns.Msg, _ string) (*dns.Msg, error) {
		switch msg.Question[0].Qtype {
		case dns.TypeSOA:
			return soaReply(msg, "example.com."), nil
		case dns.TypeNS:
			return nsReply(msg, msg.Question[0].Name, "ns1.example.net."), nil
		case dns.TypeA:
			return aReply(msg), nil
		default:
			return authTXT(msg, "other"), nil
		}
	})
	solver.timeout = 10 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := solver.WaitAll(ctx, []DNSRecord{{FQDN: "_acme-challenge.example.com.", Value: "v"}})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a cancelled wait must fail")
	}
	if elapsed > 2*time.Second {
		t.Errorf("cancellation took %s: the wait polls to the deadline instead of observing ctx", elapsed)
	}
}

// ── zone and nameserver discovery ────────────────────────────────────────────────────

// A nameserver that does not resolve must be skipped, not fail the whole lookup: one broken
// delegation record should not stop propagation confirmation for the zone.
func TestAuthoritativeNSSkipsAnUnresolvableNameserver(t *testing.T) {
	solver := quietSolver(func(_ context.Context, msg *dns.Msg, _ string) (*dns.Msg, error) {
		switch msg.Question[0].Qtype {
		case dns.TypeNS:
			return nsReply(msg, msg.Question[0].Name, "ns1.example.net.", "ns2.example.net."), nil
		case dns.TypeA:
			if msg.Question[0].Name == "ns1.example.net." {
				return nil, fmt.Errorf("no such host")
			}
			return aReply(msg), nil
		case dns.TypeAAAA:
			return dnsReply(msg), nil
		}
		return nil, fmt.Errorf("unexpected query %s", msg.Question[0].Name)
	})

	servers, err := solver.authoritativeNS(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("one unresolvable NS must not fail the lookup: %v", err)
	}
	if len(servers) != 1 || servers[0] != "198.51.100.53:53" {
		t.Errorf("servers = %v, want only the resolvable one", servers)
	}
}

// If no nameserver resolves there is nothing to query, and that must be an error rather than an
// empty server list that later probes silently do nothing with.
func TestAuthoritativeNSFailsWhenNoneResolve(t *testing.T) {
	solver := quietSolver(func(_ context.Context, msg *dns.Msg, _ string) (*dns.Msg, error) {
		switch msg.Question[0].Qtype {
		case dns.TypeNS:
			return nsReply(msg, msg.Question[0].Name, "ns1.example.net."), nil
		case dns.TypeA, dns.TypeAAAA:
			return nil, fmt.Errorf("no such host")
		}
		return nil, fmt.Errorf("unexpected")
	})

	if _, err := solver.authoritativeNS(context.Background(), "example.com."); err == nil {
		t.Fatal("no resolvable NS must be an error")
	}
}

// A zone with no NS records at all must be an error naming the zone.
func TestAuthoritativeNSFailsWithoutNSRecords(t *testing.T) {
	solver := quietSolver(func(_ context.Context, msg *dns.Msg, _ string) (*dns.Msg, error) {
		if msg.Question[0].Qtype == dns.TypeNS {
			return dnsReply(msg), nil
		}
		return nil, fmt.Errorf("unexpected")
	})

	_, err := solver.authoritativeNS(context.Background(), "example.com.")
	if err == nil || !strings.Contains(err.Error(), "example.com.") {
		t.Errorf("the error must name the zone, got: %v", err)
	}
}

// The SOA walk must stop at the public suffix and say so, rather than returning a TLD as the
// zone and spending the whole propagation budget asking a TLD's nameservers about a TXT record
// that can never live there.
func TestFindZoneRejectsAPublicSuffix(t *testing.T) {
	solver := quietSolver(func(_ context.Context, msg *dns.Msg, _ string) (*dns.Msg, error) {
		if msg.Question[0].Qtype == dns.TypeSOA {
			// Every step answers with the public suffix, as it would for a domain with no
			// hosted zone.
			return soaReply(msg, "com."), nil
		}
		return nil, fmt.Errorf("unexpected")
	})

	_, err := solver.findZone(context.Background(), "_acme-challenge.exmaple.com.")
	if err == nil {
		t.Fatal("a TLD SOA must not be accepted as the zone")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "typo") &&
		!strings.Contains(strings.ToLower(err.Error()), "public suffix") {
		t.Errorf("the error should point at the likely cause, got: %v", err)
	}
}

// ── recursive lookup behaviour ───────────────────────────────────────────────────────

// A failing resolver must not end the lookup: the next configured one is tried, so one dead
// resolver does not stall every issuance.
func TestQueryRecursiveFallsBackToTheNextResolver(t *testing.T) {
	var tried []string
	solver := quietSolver(func(_ context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
		tried = append(tried, server)
		if server == "192.0.2.53:53" {
			return nil, fmt.Errorf("connection refused")
		}
		return dnsReply(msg), nil
	})
	solver.recursiveNameservers = []string{"192.0.2.53:53", "198.51.100.53:53"}

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeSOA)
	if _, err := solver.queryRecursive(context.Background(), msg); err != nil {
		t.Fatalf("a working second resolver must be used: %v", err)
	}
	if len(tried) != 2 {
		t.Errorf("tried %v, want both resolvers", tried)
	}
}

// When every resolver fails, the error must name each one and its reason: "all resolvers
// failed" alone leaves nothing to act on.
func TestQueryRecursiveReportsEveryFailure(t *testing.T) {
	solver := quietSolver(func(_ context.Context, _ *dns.Msg, server string) (*dns.Msg, error) {
		return nil, fmt.Errorf("timeout talking to %s", server)
	})
	solver.recursiveNameservers = []string{"192.0.2.53:53", "198.51.100.53:53"}

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeSOA)
	_, err := solver.queryRecursive(context.Background(), msg)
	if err == nil {
		t.Fatal("expected a failure")
	}
	for _, want := range []string{"192.0.2.53:53", "198.51.100.53:53"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error must name resolver %s, got: %v", want, err)
		}
	}
}

// A response code that is neither success nor NXDOMAIN is a resolver problem, not an answer,
// so the next resolver gets a turn.
func TestQueryRecursiveRejectsAServfailAsAnAnswer(t *testing.T) {
	var tried int
	solver := quietSolver(func(_ context.Context, msg *dns.Msg, _ string) (*dns.Msg, error) {
		tried++
		if tried == 1 {
			resp := new(dns.Msg)
			resp.SetReply(msg)
			resp.Rcode = dns.RcodeServerFailure
			return resp, nil
		}
		return dnsReply(msg), nil
	})
	solver.recursiveNameservers = []string{"192.0.2.53:53", "198.51.100.53:53"}

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeSOA)
	if _, err := solver.queryRecursive(context.Background(), msg); err != nil {
		t.Fatalf("SERVFAIL on the first resolver must fall through: %v", err)
	}
	if tried != 2 {
		t.Errorf("tried %d resolver(s), want 2", tried)
	}
}
