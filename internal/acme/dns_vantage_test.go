package acme

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The propagation verdict is a statement about THIS HOST's reach, and two vantage points can
// therefore disagree while both are "ready".
//
// The recorded gap (docs/e2e-run-2026-09-17-credentialed.md section 6) is that the criterion's
// optimism was sampled for exactly one domain from exactly one network position. What makes the
// optimism structural rather than incidental is this pair: the rule is "no reachable authority
// denies the value, and at least two confirm", where "reachable" is decided by whichever host is
// asking. A host that can reach only two of a zone's three authorities passes on those two alone;
// a host that can also reach the third -- the lagging one, which is still serving the OLD record --
// is denied by it and waits. Nothing in the verdict says which of the two it was.
func TestThePropagationVerdictDependsOnTheVantagePoint(t *testing.T) {
	const (
		fqdn  = "_acme-challenge.example.com."
		value = "wanted"
	)
	servers := []nsServer{
		{ns: "ns1.example.net.", addr: "198.51.100.1:53"},
		{ns: "ns2.example.net.", addr: "198.51.100.2:53"},
		{ns: "ns3.example.net.", addr: "198.51.100.3:53"},
	}
	confirm := func(msg *dns.Msg) (*dns.Msg, error) {
		resp := dnsReply(msg, &dns.TXT{
			Hdr: dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET},
			Txt: []string{value},
		})
		resp.Authoritative = true
		return resp, nil
	}
	lagging := func(msg *dns.Msg) (*dns.Msg, error) {
		// Reachable, authoritative, and still serving the pre-write state: an authoritative "no
		// such value", which is a denial.
		resp := dnsReply(msg)
		resp.Authoritative = true
		return resp, nil
	}

	// Vantage point A: the third authority is unreachable from here.
	readyA, summaryA := probeReadyWithDelegation(servers, 3, fqdn, value,
		func(msg *dns.Msg, server string) (*dns.Msg, error) {
			if server == servers[2].addr {
				return nil, errors.New("network unreachable")
			}
			return confirm(msg)
		})

	// Vantage point B: the same three authorities, all reachable -- and the third denies.
	readyB, summaryB := probeReadyWithDelegation(servers, 3, fqdn, value,
		func(msg *dns.Msg, server string) (*dns.Msg, error) {
			if server == servers[2].addr {
				return lagging(msg)
			}
			return confirm(msg)
		})

	if !readyA {
		t.Fatalf("vantage point A reached two confirming authorities and no denial, so it must "+
			"report ready; summary=%s", summaryA)
	}
	if readyB {
		t.Fatalf("vantage point B was denied by an authoritative server, so it must wait; summary=%s", summaryB)
	}
	t.Logf("same record, same instant, different host:\n  A: %s\n  B: %s", summaryA, summaryB)

	// And the success line for A does carry the shape of its evidence -- which is what an operator
	// has to read to know the verdict was thin.
	if !strings.Contains(summaryA, "unreachable 1") {
		t.Errorf("A's evidence must show that one authority was never asked, got %s", summaryA)
	}
}

// "Ready" is decided once, and is never re-checked before the call that spends the quota slot.
//
// This is the other half of the optimism: probeReadyWithDelegation answers about one snapshot, and
// waitZone returns on the first snapshot that passes. So a record that appeared on exactly the two
// authorities this host can reach passes -- even if the third (unreachable, and reachable by the
// CA's resolver) has not got it, and even if the change that made the first two answer is about to
// be undone. The round-7 note calls the optional tightening "N consecutive agreeing rounds"; this
// case shows what today's single snapshot accepts, so the difference a tightening would make is
// visible rather than asserted.
func TestASingleAgreeingSnapshotIsEnoughToDeclarePropagation(t *testing.T) {
	var logs bytes.Buffer
	const (
		authorityA = "198.51.100.1:53"
		authorityB = "198.51.100.2:53"
		fqdn       = "_acme-challenge.example.com."
		value      = "wanted"
	)

	// The two reachable authorities confirm on their FIRST query and deny afterwards -- a transient
	// state, which is exactly what a second agreeing round would catch and one snapshot cannot.
	// Per-address counting, because both addresses are probed concurrently.
	var queries [2]atomic.Int64
	solver := &DNSSolver{
		recursiveNameservers: []string{"192.0.2.53:53"},
		log:                  slog.New(slog.NewTextHandler(&logs, nil)),
		interval:             time.Millisecond,
		timeout:              2 * time.Second,
		exchange: func(_ context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
			if server == "192.0.2.53:53" {
				return dnsReply(msg, &dns.TXT{
					Hdr: dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET},
					Txt: []string{value},
				}), nil
			}
			idx := 0
			if server == authorityB {
				idx = 1
			}
			n := queries[idx].Add(1)
			resp := dnsReply(msg)
			resp.Authoritative = true
			if n == 1 {
				resp.Answer = append(resp.Answer, &dns.TXT{
					Hdr: dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET},
					Txt: []string{value},
				})
			}
			return resp, nil
		},
	}

	servers := []nsServer{
		{ns: "ns1.example.net.", addr: authorityA},
		{ns: "ns2.example.net.", addr: authorityB},
	}
	recs := []DNSRecord{{FQDN: fqdn, Value: value}}
	now := time.Now()
	budget := zoneBudget{passStart: now, zoneStart: now, deadline: now.Add(2 * time.Second)}

	start := time.Now()
	if err := solver.waitZone(context.Background(), "example.com.", servers, 2, recs, budget); err != nil {
		t.Fatalf("the first snapshot agrees, and that is the whole criterion today: %v", err)
	}
	total := queries[0].Load() + queries[1].Load()
	t.Logf("declared propagated after %s and %d authority queries", time.Since(start).Round(time.Millisecond), total)
	if total != 2 {
		t.Errorf("waitZone must return on the first agreeing snapshot; it queried the authorities %d "+
			"times, so a second round is being required somewhere", total)
	}
	if !strings.Contains(logs.String(), "TXT propagated") {
		t.Error("the verdict has to be logged with its evidence")
	}
}

// A deep negative cache delays the verdict for as long as the cache lives, and the budget is what
// decides whether that is "wait" or "fail the round".
//
// The recorded gap (docs/e2e-run-2026-09-17-credentialed.md section 6, last row) is that this was
// never constructed. It is a timing question, and the two numbers that answer it both come from the
// code: the propagation budget (dns.propagationTimeout, 5m by default, and the config refuses below
// 30s) and the poll interval (dns.pollingInterval, 5s). A resolver whose negative cache outlives
// the budget cannot be waited out at all: the round ends in a propagation timeout, books the
// certificate's backoff, and the next pass starts the same clock again. The behaviour is correct --
// refusing to hand a negatively-cached name to the CA is the whole point of the criterion -- but
// the cost is a full budget per pass, and that is the part that was never measured.
func TestADeepNegativeCacheCostsTheWholePropagationBudget(t *testing.T) {
	var logs bytes.Buffer
	var txtQueries int
	solver := recursiveTestSolver(t, &logs, func(msg *dns.Msg) (*dns.Msg, error) {
		// The recursive resolver's negative cache: the answer is NXDOMAIN for as long as the SOA
		// minimum in the cached negative response says, regardless of what the authority now holds.
		txtQueries++
		resp := new(dns.Msg)
		resp.SetRcode(msg, dns.RcodeNameError)
		return resp, nil
	})
	solver.timeout = 300 * time.Millisecond // stand-in for the 5m default
	solver.interval = 20 * time.Millisecond

	recs := []DNSRecord{{FQDN: "_acme-challenge.example.com.", Value: "wanted"}}
	// The authoritative side confirms immediately: this is exactly the production shape -- the
	// record IS in DNS, and only the resolver's cache says otherwise.
	start := time.Now()
	err := solver.waitZone(context.Background(), "example.com.", recursiveTestServers(), 2, recs,
		zoneBudget{passStart: start, zoneStart: start, deadline: start.Add(solver.timeout)})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a negatively cached resolver is what the CA's own resolver would be, so this must " +
			"not be reported as propagated")
	}
	if !strings.Contains(err.Error(), "recursive") {
		t.Errorf("the timeout has to name the recursive view as the blocker, got: %v", err)
	}
	if elapsed < solver.timeout {
		t.Errorf("the wait must consume the whole budget before giving up (waited %s of %s): a "+
			"shortcut here would tell the CA to validate a name the resolver still denies",
			elapsed.Round(time.Millisecond), solver.timeout)
	}
	t.Logf("negative cache outliving the budget: %d TXT queries over %s, then a propagation timeout",
		txtQueries, elapsed.Round(time.Millisecond))
	if txtQueries < 2 {
		t.Errorf("the wait must poll, not give up after one answer; got %d queries", txtQueries)
	}
	// And with the budget below the poll interval the config layer already refuses to start
	// (dns.pollingInterval >= dns.propagationTimeout), so this cannot degrade into "probe once".
	if solver.interval >= solver.timeout {
		t.Error("fixture: the poll interval must be shorter than the budget for the wait to be a wait")
	}
}
