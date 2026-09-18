package acme

import (
	"context"
	"fmt"
	"testing"

	"github.com/miekg/dns"
)

// A delegated NS that does not resolve still counts as an authority.
//
// The propagation rule exempts single-authority zones from the "two servers must confirm"
// requirement. Keying that exemption on the names that RESOLVED turned a two-NS zone with one
// broken A record into a "single-authority" zone: one confirmation from the surviving server
// passed, while the unresolvable server may be exactly the one the CA reaches -- and be told
// the record does not exist.
func TestAnUnresolvableDelegatedNSStillCountsAsAnAuthority(t *testing.T) {
	solver := quietSolver(func(_ context.Context, msg *dns.Msg, _ string) (*dns.Msg, error) {
		switch msg.Question[0].Qtype {
		case dns.TypeNS:
			return nsReply(msg, msg.Question[0].Name, "ns1.example.net.", "ns2.example.net."), nil
		case dns.TypeA:
			if msg.Question[0].Name == "ns2.example.net." {
				return nil, fmt.Errorf("no such host")
			}
			return aReply(msg), nil
		case dns.TypeAAAA:
			return dnsReply(msg), nil
		}
		return nil, fmt.Errorf("unexpected query %s", msg.Question[0].Name)
	})

	servers, delegated, err := solver.authoritativeNS(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("one unresolvable NS must not fail the lookup: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("servers = %v, want only the resolvable one", servers)
	}
	if delegated != 2 {
		t.Fatalf("delegated = %d, want 2: the unresolvable name is still part of the delegation", delegated)
	}

	// The surviving authority confirms, on every address it has. With the exemption keyed on the
	// delegation this must NOT pass: only one of the two delegated servers has spoken.
	ready, summary := probeReadyWithDelegation(servers, delegated, "_acme-challenge.example.com.", "wanted",
		func(msg *dns.Msg, _ string) (*dns.Msg, error) {
			return authoritativeTXT(msg, "wanted"), nil
		})
	if ready {
		t.Errorf("one of two delegated authorities confirmed and the other could not even be "+
			"resolved; the single-authority exemption must not open: %s", summary)
	}

	// The inferred count must never shrink the delegation a caller reported.
	if got := delegatedCount(servers); got != 1 {
		t.Errorf("delegatedCount(%v) = %d, want 1: it is the fallback for callers that never went "+
			"through authoritativeNS, for which the server list IS the delegation", servers, got)
	}
}
