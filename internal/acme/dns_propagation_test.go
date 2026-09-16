package acme

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Two addresses of ONE nameserver are one server.
//
// The rule this pins is stated in probeReadyWithExchange: with more than one authority, two of them
// must confirm independently, "so 'only one server was reachable' cannot slip through". Counting
// addresses let a single multi-homed authority satisfy it -- three A records per name is normal for
// DNSPod's own pools -- so the guard was not there.
func TestOneMultiHomedAuthorityIsNotTwoConfirmations(t *testing.T) {
	single := oneAuthority("192.0.2.1:53", "192.0.2.2:53")
	if len(single) != 2 {
		t.Fatalf("setup: want one authority with two addresses, got %d entries", len(single))
	}

	// Both addresses of the single authority confirm; a second authority is unreachable. There is
	// still exactly one independent server behind this answer.
	servers := append(append([]nsServer{}, single...), nsServer{ns: "ns2.example.net.", addr: "192.0.2.3:53"})
	ready, summary := probeReadyWithExchange(servers, "_acme-challenge.example.com.", "wanted",
		func(msg *dns.Msg, server string) (*dns.Msg, error) {
			if server == "192.0.2.3:53" {
				return nil, errors.New("unreachable")
			}
			return authoritativeTXT(msg, "wanted"), nil
		})
	if ready {
		t.Errorf("one authority answered on two of its own addresses and the second authority was "+
			"unreachable, so only ONE server confirmed; the rule must not pass: %s", summary)
	}

	// With both authorities answering, it must pass -- otherwise the fix could be "never ready".
	ready, summary = probeReadyWithExchange(servers, "_acme-challenge.example.com.", "wanted",
		func(msg *dns.Msg, _ string) (*dns.Msg, error) {
			return authoritativeTXT(msg, "wanted"), nil
		})
	if !ready {
		t.Errorf("two authorities both confirmed and nothing denied, so this must pass: %s", summary)
	}
}

// The mirror image, which the same root cause produced: a single-authority zone whose name has an
// address this host cannot reach must still be able to confirm. Keying the "single authority is
// exempt" branch on the address count made such a zone wait out its whole budget on every pass.
func TestOneMultiHomedAuthorityCanStillConfirm(t *testing.T) {
	servers := oneAuthority("192.0.2.1:53", "2001:db8::1:53") // the second is unreachable from here
	ready, summary := probeReadyWithExchange(servers, "_acme-challenge.example.com.", "wanted",
		func(msg *dns.Msg, server string) (*dns.Msg, error) {
			if server == "2001:db8::1:53" {
				return nil, errors.New("no route to host")
			}
			return authoritativeTXT(msg, "wanted"), nil
		})
	if !ready {
		t.Errorf("a zone with a single authority must be able to pass on one of its addresses: %s", summary)
	}
}

// A server that answers SERVFAIL has not answered the question.
//
// The classification is what the fix is about, and it matters in two places. Treating a SERVFAIL as
// a denial holds propagation back for a record that may be perfectly propagated; and in LookupTXT's
// branch a denial is what licenses deleting the authorization row of a name that is still being
// validated. NXDOMAIN is the opposite and must stay a denial: it is a definitive answer.
func TestServerFailureIsNotADenial(t *testing.T) {
	servers := oneAuthority("192.0.2.1:53")

	_, summary := probeReadyWithExchange(servers, "_acme-challenge.example.com.", "wanted",
		func(msg *dns.Msg, _ string) (*dns.Msg, error) {
			return servfail(msg), nil
		})
	if !strings.Contains(summary, "unreachable 1") || strings.Contains(summary, "denied 1") {
		t.Errorf("a SERVFAIL must be counted as an inconclusive answer, not as a denial: %s", summary)
	}

	_, summary = probeReadyWithExchange(servers, "_acme-challenge.example.com.", "wanted",
		func(msg *dns.Msg, _ string) (*dns.Msg, error) {
			return nxdomain(msg), nil
		})
	if !strings.Contains(summary, "denied 1") {
		t.Errorf("an authoritative NXDOMAIN says the name does not exist, which is a denial and must "+
			"keep counting as one: %s", summary)
	}

	// REFUSED, the other way an authority declines to answer, is inconclusive too.
	_, summary = probeReadyWithExchange(servers, "_acme-challenge.example.com.", "wanted",
		func(msg *dns.Msg, _ string) (*dns.Msg, error) {
			resp := new(dns.Msg)
			resp.SetReply(msg)
			resp.Rcode = dns.RcodeRefused
			return resp, nil
		})
	if !strings.Contains(summary, "unreachable 1") || strings.Contains(summary, "denied 1") {
		t.Errorf("a REFUSED must be inconclusive, not a denial: %s", summary)
	}
}

// A truncated answer is inconclusive, not a denial.
//
// This is the case exchangeDNS' TCP retry failed in: the UDP answer was cut off, so the missing
// record may simply not have fitted. Reading it as "not propagated" burns the whole propagation
// budget on a record that is already there.
func TestTruncatedAnswerIsInconclusive(t *testing.T) {
	servers := oneAuthority("192.0.2.1:53")
	ready, summary := probeReadyWithExchange(servers, "_acme-challenge.example.com.", "wanted",
		func(msg *dns.Msg, _ string) (*dns.Msg, error) {
			return truncated(msg), nil
		})
	if ready {
		t.Fatalf("a truncated answer cannot confirm anything: %s", summary)
	}
	if !strings.Contains(summary, "unreachable 1") || strings.Contains(summary, "denied 1") {
		t.Errorf("a truncated answer must be inconclusive, not a denial: %s", summary)
	}
}

// exchangeDNS must not discard the UDP answer when the TCP retry fails.
//
// The two attempts share the caller's context, so a server that answers UDP quickly with TC=1 and
// then stalls on TCP -- the case the retry exists for -- used to end with resp == nil, throwing away
// an answer whose answer section may already have carried the value, and reporting the server as
// unreachable.
func TestExchangeDNSKeepsTheUDPAnswerWhenTCPFails(t *testing.T) {
	addr := startTruncatingThenStalling(t)

	msg := new(dns.Msg)
	msg.SetQuestion("_acme-challenge.example.com.", dns.TypeTXT)

	// Short context: it bounds both attempts, so the test does not sit for the production 3s.
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	resp, err := exchangeDNS(ctx, msg, addr)
	if err != nil {
		t.Fatalf("the UDP answer was usable and the TCP retry failed, so the answer must come back "+
			"rather than the failure: %v", err)
	}
	if resp == nil {
		t.Fatal("resp is nil: the truncated UDP answer was thrown away when the TCP retry failed")
	}
	if !resp.Truncated {
		t.Error("the answer must still be marked truncated, so the caller can treat it as inconclusive")
	}
	if !responseHasTXT(resp, "wanted") {
		t.Error("the value the UDP answer already carried must survive: dropping it is what made the " +
			"server look unreachable for a record that had propagated")
	}
}

// startTruncatingThenStalling runs a server that answers UDP with a truncated answer and never
// answers over TCP. Returns its address.
func startTruncatingThenStalling(t *testing.T) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	addr := pc.LocalAddr().String()

	udpSrv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Truncated = true
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET},
			Txt: []string{"wanted"},
		})
		_ = w.WriteMsg(m)
	})}
	go func() { _ = udpSrv.ActivateAndServe() }()
	t.Cleanup(func() { _ = udpSrv.Shutdown() })

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen tcp on the same address: %v", err)
	}
	// Never answer, but do not hold the test open either: cleanup closes released first.
	released := make(chan struct{})
	tcpSrv := &dns.Server{Listener: ln, Handler: dns.HandlerFunc(func(_ dns.ResponseWriter, _ *dns.Msg) {
		<-released
	})}
	go func() { _ = tcpSrv.ActivateAndServe() }()
	t.Cleanup(func() {
		close(released)
		_ = tcpSrv.Shutdown()
	})

	return addr
}

// ── helpers ────────────────────────────────────────────────────────────────

func authoritativeTXT(query *dns.Msg, value string) *dns.Msg {
	resp := &dns.Msg{}
	resp.SetReply(query)
	resp.Authoritative = true
	resp.Rcode = dns.RcodeSuccess
	resp.Answer = append(resp.Answer, &dns.TXT{
		Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET},
		Txt: []string{value},
	})
	return resp
}

func servfail(query *dns.Msg) *dns.Msg {
	resp := &dns.Msg{}
	resp.SetReply(query)
	resp.Rcode = dns.RcodeServerFailure
	return resp
}

func nxdomain(query *dns.Msg) *dns.Msg {
	resp := &dns.Msg{}
	resp.SetReply(query)
	resp.Authoritative = true
	resp.Rcode = dns.RcodeNameError
	return resp
}

func truncated(query *dns.Msg) *dns.Msg {
	resp := &dns.Msg{}
	resp.SetReply(query)
	resp.Authoritative = true
	resp.Truncated = true
	return resp
}

// The zone deadline must be checked before entering a zone, and the message must not blame the zone
// that was reached too late for time spent on the ones before it.
func TestWaitAllDoesNotBlameAZoneItNeverHadTimeFor(t *testing.T) {
	queried := map[string]int{}

	// findZone runs before the budget starts, and it must succeed or WaitAll never reaches the zone
	// loop this test is about. Only TXT queries to an authority count as "a zone was entered".
	solver := &DNSSolver{
		recursiveNameservers: []string{"192.0.2.53:53"}, // findZone needs a resolver to ask
		log:                  slog.New(slog.NewTextHandler(io.Discard, nil)),
		timeout:              0, // already spent when the loop starts: no zone may be entered
		interval:             time.Millisecond,
	}
	solver.exchange = func(_ context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
		if msg.Question[0].Qtype == dns.TypeSOA {
			// findZone walks the name from the left and takes the first SOA whose owner is a hosted
			// zone. The owners here must sit under a real public suffix: "example." would be read as
			// the public suffix itself and rejected as a typo.
			name := msg.Question[0].Name
			for _, zone := range []string{"example.com.", "example.net."} {
				if strings.HasSuffix(name, "."+zone) {
					return dnsReply(msg, &dns.SOA{
						Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET},
						Ns:  "ns1." + zone,
					}), nil
				}
			}
			return dnsReply(msg), nil // no SOA: keep climbing
		}
		queried[server]++
		return nil, errors.New("unreachable")
	}

	err := solver.WaitAll(context.Background(), []DNSRecord{
		{FQDN: "_acme-challenge.a.example.com.", Value: "v"},
		{FQDN: "_acme-challenge.b.example.net.", Value: "v"},
	})
	if err == nil {
		t.Fatal("with the budget already spent this must fail")
	}
	if len(queried) != 0 {
		t.Errorf("no zone should have been probed once the budget was gone, but %d server(s) were "+
			"asked: a zone reached too late gets one doomed round and the log blames it for time "+
			"spent on the zones before it", len(queried))
	}
	if !strings.Contains(err.Error(), "budget") || !strings.Contains(err.Error(), "not reached") {
		t.Errorf("the message must say the budget ran out and that the zone was not reached, rather "+
			"than implying the zone was polled and failed: %v", err)
	}
}
