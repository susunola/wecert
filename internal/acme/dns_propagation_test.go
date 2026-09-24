package acme

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
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
	// An inconclusive ANSWER, in its own bucket: "failed" says a response came back that was
	// neither a confirmation nor a denial, which is not the same as a server that never
	// answered. Folding the two together is what made an intercepting middlebox look like a
	// broken zone.
	if !strings.Contains(summary, "failed 1") || strings.Contains(summary, "denied 1") {
		t.Errorf("a SERVFAIL must be counted as an inconclusive answer, not as a denial: %s", summary)
	}
	if strings.Contains(summary, "unreachable 1") {
		t.Errorf("a server that answered SERVFAIL is reachable and must not be counted as "+
			"unreachable: %s", summary)
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
	// REFUSED gets its own bucket because of what it usually means in the field: a network
	// that intercepts port 53 answers REFUSED on the authority's behalf, so every address of a
	// perfectly healthy zone comes back refused at once. Reported as "unreachable" -- which is
	// what this did before -- the operator is sent to look at the zone.
	if !strings.Contains(summary, "refused 1") || strings.Contains(summary, "denied 1") {
		t.Errorf("a REFUSED must be inconclusive, not a denial: %s", summary)
	}
	if strings.Contains(summary, "unreachable 1") {
		t.Errorf("a server that answered REFUSED is reachable and must not be counted as "+
			"unreachable, or an intercepted port 53 reads as a broken zone: %s", summary)
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

// ── dropped packets: a round is not decided by one lost exchange ───────────

// One dropped packet used to cost an address the whole round, and with a small delegation a lost
// round is a lost verdict.
//
// Measured on the machine this was written for (Route 53 + Cloudflare, Let's Encrypt staging, four
// runs of the same zone): the same zone confirmed 2/4 or 3/4 servers and issued in some runs, and
// ended the five-minute budget with a single independent nameserver confirming in others -- which
// fails the verdict, since it needs two independent servers to agree. The addresses that answered
// in one run were reported unreachable in the next, so the path is lossy rather than the zone slow.
// An address gets one exchange per round, so the retry inside the round is what keeps one dropped
// packet from throwing the whole round away.
func TestProbeRetriesADroppedExchangeWithinTheRoundAndConfirms(t *testing.T) {
	servers := []nsServer{
		{ns: "ns1.example.net.", addr: "192.0.2.1:53"},
		{ns: "ns2.example.net.", addr: "192.0.2.2:53"},
	}

	// The first exchange to the first address is dropped, exactly as an intermittent path drops it:
	// no response and no error. Every later exchange answers.
	var flaky, asked []*dns.Msg
	exchange := func(msg *dns.Msg, server string) (*dns.Msg, error) {
		if server == "192.0.2.1:53" {
			flaky = append(flaky, msg)
			if len(flaky) == 1 {
				return nil, errors.New("i/o timeout")
			}
		} else {
			asked = append(asked, msg)
		}
		return authoritativeTXT(msg, "wanted"), nil
	}

	ready, summary := probeReadyWithExchange(servers, "_acme-challenge.example.com.", "wanted", exchange)

	// The lost exchange must not decide the record: both authorities eventually answer with the
	// value, so the verdict has to pass.
	if !ready {
		t.Errorf("both authorities answered authoritatively and neither denied the value, so the "+
			"retry inside the round must let this pass: %s", summary)
	}
	// This is the part the old behaviour cannot satisfy: one attempt per round means this address
	// was asked once and recorded unreachable.
	if len(flaky) < 2 {
		t.Fatalf("the first address was asked %d time(s): a single dropped exchange still ends the "+
			"round for that address, which is what makes the verdict depend on the packet", len(flaky))
	}
	if !strings.Contains(summary, "unreachable 0") {
		t.Errorf("the address answered on the second attempt, so it is reachable and must be "+
			"counted unreachable 0: %s", summary)
	}
	assertAllTXTQuestions(t, flaky, "_acme-challenge.example.com.")
	assertAllTXTQuestions(t, asked, "_acme-challenge.example.com.")
}

// The retries are bounded, and an address that never answers is still what it always was:
// unreachable. This guards the unchanged path -- what a retry adds is attempts, not leniency.
func TestProbeStillCountsAnAlwaysTimingOutAddressUnreachable(t *testing.T) {
	servers := []nsServer{
		{ns: "ns1.example.net.", addr: "192.0.2.1:53"},
		{ns: "ns2.example.net.", addr: "192.0.2.2:53"},
	}
	var dead []*dns.Msg
	exchange := func(msg *dns.Msg, server string) (*dns.Msg, error) {
		if server == "192.0.2.1:53" {
			dead = append(dead, msg)
			return nil, errors.New("i/o timeout")
		}
		return authoritativeTXT(msg, "wanted"), nil
	}

	ready, summary := probeReadyWithExchange(servers, "_acme-challenge.example.com.", "wanted", exchange)

	if ready {
		t.Errorf("only one authority confirmed; a zone with two authorities needs two independent "+
			"confirmations and must not pass here: %s", summary)
	}
	if !strings.Contains(summary, "unreachable 1") {
		t.Errorf("an address that answered on neither transport must still be counted unreachable "+
			"after its attempts are spent: %s", summary)
	}
	// The retries are actually spent here -- one exchange per round is the old behaviour this test
	// exists to pin -- and they stay bounded, so an address that never answers cannot hold a round
	// open indefinitely. The literal 2 is deliberate: dnsProbeAttempts is what sets the bound, but
	// "at least two attempts" is the shipped behaviour a probe must show to a timeout address, so
	// the test states the behaviour rather than restating the constant.
	if len(dead) < 2 {
		t.Errorf("the address was asked %d time(s) within one probe, want at least 2: without the "+
			"retry a single dropped exchange ends the round for that address", len(dead))
	}
	if len(dead) > dnsProbeAttempts {
		t.Errorf("the address was asked %d time(s), want the bounded %d: an address that never "+
			"answers must not be retried without limit", len(dead), dnsProbeAttempts)
	}
	assertAllTXTQuestions(t, dead, "_acme-challenge.example.com.")
}

// REFUSED is an ANSWER, not a dropped packet.
//
// A network that intercepts port 53 refuses on the authority's behalf, so every address comes back
// REFUSED at once -- re-asking them would multiply that traffic by the attempt count and blur the
// refused bucket, which is exactly the signal that says "look at your egress, not at the zone". The
// retry loop must therefore not fire once a response came back, whatever its rcode.
//
// One address, so "asked once per round" is the strongest form of that: had the retry fired on an
// answer, the count would be the attempt count instead of one.
func TestProbeDoesNotRetryWhenTheServerAnswersRefused(t *testing.T) {
	const addr = "192.0.2.1:53"
	servers := oneAuthority(addr)

	var mu sync.Mutex
	var asked []*dns.Msg
	exchange := func(msg *dns.Msg, _ string) (*dns.Msg, error) {
		mu.Lock()
		asked = append(asked, msg)
		mu.Unlock()
		resp := new(dns.Msg)
		resp.SetReply(msg)
		resp.Rcode = dns.RcodeRefused
		return resp, nil
	}

	// Two rounds, so the count per round is what is being pinned rather than a single total.
	const rounds = 2
	for round := 0; round < rounds; round++ {
		results := probeTXTWithExchange(servers, "_acme-challenge.example.com.", "wanted", exchange)
		if len(results) != len(servers) {
			t.Fatalf("round %d produced %d result(s), want %d", round+1, len(results), len(servers))
		}
		for i, res := range results {
			// The classification is untouched: a REFUSED is neither a confirmation nor a denial,
			// and it is emphatically not a transport failure.
			if res.hasValue || res.err != nil {
				t.Errorf("round %d: a server that answered REFUSED has not confirmed anything and is "+
					"not unreachable, got %+v", round+1, res)
			}
			if res.rcode != "REFUSED" {
				t.Errorf("round %d address %d: rcode = %q, want REFUSED", round+1, i, res.rcode)
			}
		}
		// Checked per round: an ANSWER is never retried, whatever its rcode, so one server must
		// have been asked exactly once -- not once per attempt.
		if len(asked) != round+1 {
			t.Fatalf("after round %d the server had been asked %d time(s), want exactly %d: a server "+
				"that answered REFUSED answered, and re-asking it is a retry storm that burns the "+
				"budget and blurs the refused bucket", round+1, len(asked), round+1)
		}
	}
	assertAllTXTQuestions(t, asked, "_acme-challenge.example.com.")
}

// assertAllTXTQuestions pins what every recorded attempt was: a fresh TXT question for the
// challenge name. An attempt that asked something else would not be a retry of the same question.
func assertAllTXTQuestions(t *testing.T, msgs []*dns.Msg, fqdn string) {
	t.Helper()
	if len(msgs) == 0 {
		t.Fatal("no query was recorded")
	}
	for i, m := range msgs {
		if len(m.Question) != 1 {
			t.Fatalf("attempt %d carried %d question(s), want exactly 1", i+1, len(m.Question))
		}
		if m.Question[0].Qtype != dns.TypeTXT || m.Question[0].Name != fqdn {
			t.Errorf("attempt %d asked %s %s, want TXT %s", i+1, m.Question[0].Name,
				dns.TypeToString[m.Question[0].Qtype], fqdn)
		}
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

// A network that drops outbound UDP/53 must not make a whole zone look unreachable.
//
// Measured on a machine whose egress policy blocks UDP/53 and allows TCP/53: every one of
// the zone's eight authoritative addresses timed out, the propagation wait burned its full
// five-minute budget and reported "unreachable 8 (of 8 addresses)", and the issuance never
// reached the CA -- which would have validated the record fine from its own network. TCP is
// an equally authoritative transport (RFC 7766), so a server that answers over it has
// answered.
func TestExchangeDNSFallsBackToTCPWhenUDPIsSilent(t *testing.T) {
	addr := startTCPOnlyAnswering(t, "wanted")

	msg := new(dns.Msg)
	msg.SetQuestion("_acme-challenge.example.com.", dns.TypeTXT)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	resp, err := exchangeDNS(ctx, msg, addr)
	if err != nil {
		t.Fatalf("the server answers over TCP, so the UDP failure must not be returned: %v", err)
	}
	if resp == nil || !responseHasTXT(resp, "wanted") {
		t.Fatalf("the TCP answer must come back, got %v", resp)
	}
	if !resp.Authoritative {
		t.Error("the answer must stay authoritative: the caller uses that to decide whether the " +
			"server is speaking for the zone at all")
	}
}

// startTCPOnlyAnswering listens on TCP only, so the UDP attempt fails on the spot and the
// fallback is what makes the query succeed. Returns the address to dial.
func startTCPOnlyAnswering(t *testing.T, value string) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	srv := &dns.Server{Listener: ln, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		_ = w.WriteMsg(authoritativeTXT(r, value))
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	return ln.Addr().String()
}
