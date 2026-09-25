package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/susunola/wecert/internal/metrics"
)

// ── Test scaffolding ────────────────────────────────────────────────────────

// makeCert generates a self-signed certificate.
//
// Self-signing is deliberate: these tests care about "what the peer presented", not "is
// this CA trustworthy", and self-signing makes Trusted necessarily false -- which pins down
// the requirement that "untrusted chain" and "wrong certificate" be reported separately.
func makeCert(t *testing.T, dnsNames []string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: dnsNames[0]},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, n := range dnsNames {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("issuing the test certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startServer starts a TLS listener on a random port on 127.0.0.1 and returns the port.
func startServer(t *testing.T, cert tls.Certificate) int {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
			}(conn)
		}
	}()

	return ln.Addr().(*net.TCPAddr).Port
}

// probeLocalhost probes the local test server.
//
// Using localhost rather than 127.0.0.1 exercises the full target-name + SNI path, the same
// code path as probing a real domain on a real machine. It may also resolve to ::1, which
// incidentally covers "try the multiple addresses one by one".
func probeLocalhost(t *testing.T, port int) *Result {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := Probe(ctx, "localhost", Options{Port: port})
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	return res
}

// ── The probe itself ────────────────────────────────────────────────────────

func TestProbeReadsTheServedCertificate(t *testing.T) {
	t.Parallel()
	notAfter := time.Now().Add(60 * 24 * time.Hour).Truncate(time.Second)
	port := startServer(t, makeCert(t, []string{"localhost", "www.example.com"},
		time.Now().Add(-time.Hour), notAfter))

	res := probeLocalhost(t, port)

	if res.Host != "localhost" {
		t.Errorf("Host = %q", res.Host)
	}
	if !res.NotAfter.Equal(notAfter.UTC()) && !res.NotAfter.Equal(notAfter) {
		t.Errorf("NotAfter = %v, want %v", res.NotAfter, notAfter)
	}
	if len(res.SANs) != 2 {
		t.Errorf("SANs = %v, want two names", res.SANs)
	}
	if res.RemoteAddr == "" {
		t.Error("RemoteAddr should record the address actually connected to")
	}
	if len(res.ResolvedIPs) == 0 {
		t.Error("ResolvedIPs should record resolution results, the first clue when a certificate is wrong")
	}
	if res.Serial == "" {
		t.Error("Serial should not be empty")
	}
}

// A self-signed certificate must be reported as "untrusted chain", not as "wrong
// certificate".
//
// The two point in opposite directions for troubleshooting: an untrusted chain means looking
// at the CA, a wrong certificate means looking at DNS and CLB rules. Merging them sends
// people the wrong way.
func TestProbeSeparatesTrustFromCorrectness(t *testing.T) {
	t.Parallel()
	port := startServer(t, makeCert(t, []string{"localhost"},
		time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour)))

	res := probeLocalhost(t, port)

	if res.Trusted {
		t.Error("a self-signed certificate should not be reported as trusted")
	}
	if res.ChainError == "" {
		t.Error("the reason must be stated when the chain is untrusted")
	}

	// But the certificate itself covers localhost, so verification should pass.
	v := res.Verify(Expectation{})
	if !v.OK {
		t.Errorf("self-signing should not affect the coverage verdict, got: %s", v.Summary())
	}
}

// A chain no client will accept is a failed deployment, and nothing else here notices.
//
// Regression: Verify compared the hostname, the names, the expiry and the remaining validity,
// and never read Trusted or ChainError -- so a listener serving the leaf without its
// intermediate (the most common CLB certificate mistake) came back OK with probe_match=1
// while every real client failed the handshake. Trusted was only ever exported as a metric.
func TestVerifyReportsAnUntrustedChainWhenTrustIsRequired(t *testing.T) {
	t.Parallel()
	port := startServer(t, makeCert(t, []string{"localhost"},
		time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour)))
	res := probeLocalhost(t, port)
	if res.Trusted {
		t.Fatal("the test needs an untrusted chain; the fixture must stay self-signed")
	}

	v := res.Verify(Expectation{RequireTrusted: true})
	if v.OK {
		t.Fatal("an untrusted chain must not be a passing probe when trust is required")
	}
	if len(v.Problems) == 0 || v.Problems[0].Kind != ProblemUntrusted {
		t.Fatalf("the problem must be ProblemUntrusted, got %+v", v.Problems)
	}
	// The chain error is the diagnosis: without it the message says "broken" and not what to
	// look at.
	if res.ChainError != "" && !strings.Contains(v.Summary(), res.ChainError) {
		t.Errorf("the summary should carry the chain error %q, got: %s", res.ChainError, v.Summary())
	}
}

// The same probe still passes when trust is not required: "does not chain to a public root"
// and "is not the certificate I deployed" are different faults, and an internal CA makes the
// first one permanent.
func TestVerifyKeepsTrustOutOfTheVerdictByDefault(t *testing.T) {
	t.Parallel()
	port := startServer(t, makeCert(t, []string{"localhost"},
		time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour)))
	res := probeLocalhost(t, port)

	v := res.Verify(Expectation{})
	if !v.OK {
		t.Fatalf("trust must stay out of the verdict unless it is required, got: %s", v.Summary())
	}
	for _, p := range v.Problems {
		if p.Kind == ProblemUntrusted {
			t.Error("ProblemUntrusted must not appear when RequireTrusted is off")
		}
	}
}

// A trusted chain that matches is still a pass, so the new check does not turn into a
// permanent mismatch once the deployment is right.
func TestVerifyAcceptsATrustedMatchingChain(t *testing.T) {
	t.Parallel()
	port := startServer(t, makeCert(t, []string{"localhost"},
		time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour)))
	res := probeLocalhost(t, port)
	res.Trusted = true
	res.ChainError = ""

	v := res.Verify(Expectation{RequireTrusted: true})
	if !v.OK {
		t.Errorf("a trusted, matching certificate must pass, got: %s", v.Summary())
	}
}

func TestProbeReportsAWrongCertificate(t *testing.T) {
	t.Parallel()
	// Someone else's certificate is being served.
	port := startServer(t, makeCert(t, []string{"other.example"},
		time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour)))

	res := probeLocalhost(t, port)
	v := res.Verify(Expectation{})

	if v.OK {
		t.Fatal("a name mismatch must be reported as an error")
	}
	if !strings.Contains(v.Summary(), "does not cover localhost") {
		t.Errorf("it should state that the dialed name is not covered, got: %s", v.Summary())
	}
	// The summary must show what it actually covers, otherwise another probe is needed to
	// find out.
	if !strings.Contains(v.Summary(), "other.example") {
		t.Errorf("it should report the names actually covered, got: %s", v.Summary())
	}
}

// This is the only hard evidence of whether the rebind actually took effect.
//
// The name matches and the coverage matches, but the certificate is not the deployed one --
// the old certificate is still hanging on the CLB. Checking only "can it handshake" would
// miss this entirely.
func TestProbeDetectsAStaleCertificate(t *testing.T) {
	t.Parallel()
	servedNotAfter := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	port := startServer(t, makeCert(t, []string{"localhost"},
		time.Now().Add(-time.Hour), servedNotAfter))

	res := probeLocalhost(t, port)

	deployedNotAfter := servedNotAfter.Add(24 * time.Hour)
	v := res.Verify(Expectation{NotAfter: deployedNotAfter})

	if v.OK {
		t.Fatal("serving a different certificate must be reported as an error")
	}
	if !strings.Contains(v.Summary(), "the rebind did not take effect") {
		t.Errorf("it should point at the rebind not taking effect, got: %s", v.Summary())
	}
}

func TestProbeDetectsMissingAndExtraNames(t *testing.T) {
	t.Parallel()
	port := startServer(t, makeCert(t, []string{"localhost", "old.example.com"},
		time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour)))

	res := probeLocalhost(t, port)

	v := res.Verify(Expectation{
		Domains: []string{"localhost", "new.example.com"},
	})

	if v.OK {
		t.Fatal("a coverage mismatch must be reported as an error")
	}
	if !strings.Contains(v.Summary(), "new.example.com") {
		t.Errorf("it should report the missing names, got: %s", v.Summary())
	}
	if !strings.Contains(v.Summary(), "old.example.com") {
		t.Errorf("it should report the extra names, got: %s", v.Summary())
	}
}

// The comparison must be insensitive to order, case, duplicates and trailing dots --
// otherwise every single probe would report a spurious difference.
func TestProbeIgnoresOrderCaseAndDuplicates(t *testing.T) {
	t.Parallel()
	port := startServer(t, makeCert(t, []string{"localhost", "WWW.Example.COM"},
		time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour)))

	res := probeLocalhost(t, port)

	v := res.Verify(Expectation{
		Domains: []string{"www.example.com.", "LOCALHOST", "localhost"},
	})
	if !v.OK {
		t.Errorf("order/case/duplicates should not affect the verdict, got: %s", v.Summary())
	}
}

func TestProbeDetectsExpiry(t *testing.T) {
	t.Parallel()
	port := startServer(t, makeCert(t, []string{"localhost"},
		time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)))

	res := probeLocalhost(t, port)

	v := res.Verify(Expectation{MinValidFor: 7 * 24 * time.Hour})
	if v.OK {
		t.Fatal("insufficient remaining validity must be reported as an error")
	}
	if !strings.Contains(v.Summary(), "less than the required") {
		t.Errorf("got: %s", v.Summary())
	}
}

// ── Input validation ────────────────────────────────────────────────────────

// A wildcard has no address of its own to dial. Say so plainly instead of letting DNS
// resolution produce an incomprehensible "no such host".
func TestProbeRejectsAWildcard(t *testing.T) {
	t.Parallel()
	_, err := Probe(context.Background(), "*.example.com", Options{})
	if err == nil || !strings.Contains(err.Error(), "wildcard") {
		t.Fatalf("a wildcard should be rejected explicitly, got: %v", err)
	}
}

func TestProbeRejectsAnEmptyHost(t *testing.T) {
	t.Parallel()
	if _, err := Probe(context.Background(), "  ", Options{}); err == nil {
		t.Fatal("an empty name should be rejected")
	}
}

// A probe must not stall the reconcile loop: context cancellation must return immediately.
func TestProbeHonorsContextCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	if _, err := Probe(ctx, "localhost", Options{Port: 443}); err == nil {
		t.Fatal("an already-canceled context should not succeed")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("it should return immediately, took %v", elapsed)
	}
}

func TestProbeErrorsWhenNothingIsListening(t *testing.T) {
	t.Parallel()
	// Nothing is realistically listening on port 1.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := Probe(ctx, "localhost", Options{Port: 1, Timeout: 2 * time.Second})
	if err == nil {
		t.Fatal("it should error when nothing is listening")
	}
	// The error must include which addresses were tried, otherwise all you know is "it failed".
	if !strings.Contains(err.Error(), "localhost") {
		t.Errorf("the error should reveal which name failed, got: %v", err)
	}
}

// A successful TCP connection does not mean TLS will complete. A broken endpoint
// can accept connections yet send no TLS bytes; timeout must include that handshake
// or the entire reconciliation pass can block until the process exits.
func TestProbeTimesOutAStalledTLSHandshake(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	start := time.Now()
	attempts := probeIPs(context.Background(), "localhost", []string{"127.0.0.1"},
		Options{Port: port, Timeout: 100 * time.Millisecond})
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("a stalled TLS handshake must obey timeout, took %v", elapsed)
	}
	if len(attempts) != 1 || attempts[0].Err == nil {
		t.Fatalf("stalled handshake should be recorded as a failure, got %+v", attempts)
	}

	select {
	case conn := <-accepted:
		_ = conn.Close()
	case <-time.After(time.Second):
		t.Fatal("test server did not receive the TCP connection")
	}
}

// Runner must verify every address. Treating an updated first node as success
// would hide the critical case where a later node still serves an old certificate.
func TestRunnerDetectsAMismatchOnAnyResolvedAddress(t *testing.T) {
	t.Parallel()
	goodCert := makeCert(t, []string{"service.example"},
		time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
	badCert := makeCert(t, []string{"old.example"},
		time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))

	resultFor := func(cert tls.Certificate, host string) *Result {
		t.Helper()
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		return &Result{
			Host:     host,
			NotAfter: leaf.NotAfter,
			SANs:     append([]string(nil), leaf.DNSNames...),
			cert:     leaf,
		}
	}

	r := NewRunner(Options{}, 0, nil)
	good := resultFor(goodCert, "service.example")
	bad := resultFor(badCert, "service.example")
	r.probeAll = func(context.Context, string, Options) ([]Attempt, error) {
		return []Attempt{
			{Address: "192.0.2.10:443", Result: good},
			{Address: "192.0.2.11:443", Result: bad},
		}, nil
	}

	v := r.Check(context.Background(), "service.example", Expectation{
		Domains:  []string{"service.example"},
		NotAfter: good.NotAfter,
	})
	if v.OK {
		t.Fatal("a reachable address serving the wrong certificate must fail")
	}
	if !strings.Contains(v.Summary(), "192.0.2.11:443") {
		t.Errorf("problem should name the stale address, got: %s", v.Summary())
	}
}

// One host's addresses must be dialled concurrently.
//
// In series a single blackholed address costs the full per-address budget before
// the next one is even attempted -- and a dropped SYN is exactly what a
// security-group or route misconfiguration looks like. A host then spends
// len(ips) x Timeout, every certificate behind it waits its turn, and the pass
// stretches by minutes. This pins the concurrency by timing, with a margin wide
// enough not to flake on a loaded machine.
func TestProbeIPsDialsAddressesConcurrently(t *testing.T) {
	t.Parallel()
	// A listener that accepts and then stays silent, so each dial burns its whole
	// budget instead of failing fast.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			_ = c.Close()
		}
	})

	opts := Options{
		Port:    ln.Addr().(*net.TCPAddr).Port,
		Timeout: 400 * time.Millisecond,
	}
	// The same address three times is enough: what is under test is how many
	// dials are in flight at once, not how they resolve.
	ips := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1"}

	start := time.Now()
	attempts := probeIPs(context.Background(), "example.com", ips, opts)
	elapsed := time.Since(start)

	if len(attempts) != 3 {
		t.Fatalf("want one attempt per address, got %d", len(attempts))
	}
	for i, a := range attempts {
		if a.Err == nil {
			t.Errorf("attempt %d should have failed on the timeout", i)
		}
		if a.Address == "" {
			t.Errorf("attempt %d carries no address", i)
		}
	}

	// Serial would be ~3 budgets. Two is a generous ceiling that still fails loudly
	// if the loop ever goes back to being sequential.
	if elapsed > 2*opts.Timeout {
		t.Errorf("probing 3 blackholed addresses took %v; one budget is %v, so these ran in series",
			elapsed, opts.Timeout)
	}
}

// resultFromCert builds a passing probe Result for a host, the way a real
// handshake would report it.
func resultFromCert(t *testing.T, cert tls.Certificate, host string) *Result {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return &Result{
		Host:     host,
		NotAfter: leaf.NotAfter,
		SANs:     append([]string(nil), leaf.DNSNames...),
		cert:     leaf,
	}
}

// When only some of the resolved addresses could be probed, "the served
// certificate is the deployed one" is unproven. Leaving probe_match at its
// previous value would keep reporting a stale 1 while the verdict is non-OK.
func TestPartialUnreachableMarksProbeMatchZero(t *testing.T) {
	t.Parallel()
	const host = "partial-unreachable.example"
	cert := makeCert(t, []string{host},
		time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
	good := resultFromCert(t, cert, host)
	expectation := Expectation{Domains: []string{host}, NotAfter: good.NotAfter}

	r := NewRunner(Options{}, 0, nil)

	// Prime with a fully successful round, so probe_match stands at 1.
	r.probeAll = func(context.Context, string, Options) ([]Attempt, error) {
		return []Attempt{{Address: "192.0.2.10:443", Result: good}}, nil
	}
	if v := r.Check(context.Background(), host, expectation); !v.OK {
		t.Fatalf("the priming round should pass, got: %s", v.Summary())
	}
	if got := testutil.ToFloat64(metrics.CertificateProbeMatch.WithLabelValues(host)); got != 1 {
		t.Fatalf("probe_match should be 1 after a clean round, got %v", got)
	}

	// One address answers with the right certificate, the other cannot be
	// reached: the verdict is non-OK and probe_match must say so.
	r.probeAll = func(context.Context, string, Options) ([]Attempt, error) {
		return []Attempt{
			{Address: "192.0.2.10:443", Result: good},
			{Address: "192.0.2.11:443", Err: context.DeadlineExceeded},
		}, nil
	}
	if v := r.Check(context.Background(), host, expectation); v.OK {
		t.Fatal("a partially unreachable host must not pass")
	}
	if got := testutil.ToFloat64(metrics.CertificateProbeMatch.WithLabelValues(host)); got != 0 {
		t.Errorf("probe_match must drop to 0 when not all addresses were verified, got %v (stale 1)", got)
	}
}

// A host whose certificate left the desired state is never probed again; its
// transition memory must be forgettable, or last grows with every host ever
// seen -- and certificate names are derived from domains, which churn.
func TestForgetDropsTheRememberedState(t *testing.T) {
	t.Parallel()
	const host = "forget.example"
	cert := makeCert(t, []string{host},
		time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))

	r := NewRunner(Options{}, 0, nil)
	r.probeAll = func(context.Context, string, Options) ([]Attempt, error) {
		return []Attempt{{Address: "192.0.2.10:443", Result: resultFromCert(t, cert, host)}}, nil
	}
	r.Check(context.Background(), host, Expectation{Domains: []string{host}})

	if r.LastState(host) == "" {
		t.Fatal("the host should be remembered after a probe")
	}
	r.Forget(host)
	if got := r.LastState(host); got != "" {
		t.Errorf("Forget should drop the remembered state, still have %q", got)
	}
}

// A host that stops resolving must not keep a stale probe_match of 1 either.
//
// The resolve failure takes a different branch from "some addresses could not be dialled", and that
// branch used to leave the series alone: a host that matched last round and then lost its DNS kept
// reporting probe_match=1 while its verdict was unreachable, so the documented alert on
// probe_match == 0 -- the one signal that says "traffic is being served by something else" -- could
// never fire for the host that had actually stopped resolving.
func TestResolveFailureMarksProbeMatchZero(t *testing.T) {
	t.Parallel()
	const host = "no-longer-resolves.example"
	cert := makeCert(t, []string{host},
		time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
	good := resultFromCert(t, cert, host)
	expectation := Expectation{Domains: []string{host}, NotAfter: good.NotAfter}

	r := NewRunner(Options{}, 0, nil)
	r.probeAll = func(context.Context, string, Options) ([]Attempt, error) {
		return []Attempt{{Address: "192.0.2.10:443", Result: good}}, nil
	}
	if v := r.Check(context.Background(), host, expectation); !v.OK {
		t.Fatalf("the priming round should pass, got: %s", v.Summary())
	}
	if got := testutil.ToFloat64(metrics.CertificateProbeMatch.WithLabelValues(host)); got != 1 {
		t.Fatalf("probe_match should be 1 after a clean round, got %v", got)
	}

	// The name no longer resolves: probeAll fails before any address is tried.
	r.probeAll = func(context.Context, string, Options) ([]Attempt, error) {
		return nil, &net.DNSError{Name: host, Err: "no such host", IsNotFound: true}
	}
	if v := r.Check(context.Background(), host, expectation); v.OK {
		t.Fatal("a name that does not resolve must not pass")
	}
	if got := testutil.ToFloat64(metrics.CertificateProbeMatch.WithLabelValues(host)); got != 0 {
		t.Errorf("probe_match must drop to 0 when the name cannot be resolved, got %v (stale 1)", got)
	}
}

// A host that still resolves but where NO address completes a handshake must not keep a stale
// probe_match of 1 either.
//
// It is a third branch, not the resolve failure above and not the partial failure: probeAll
// succeeded (DNS answered with addresses), every one of those addresses was dialled, and every
// dial failed. That is the shape of a listener deleted at the CLB, a security group closed on
// every backend, or a timeout on all of them -- the endpoint serves nothing at all.
//
// The branch called ClearProbeAnswer, which drops not_after and trusted, so the stale 1 was left
// with nothing to contradict it: the dashboard read "match = 1" for a host nobody could reach, and
// the documented alert on probe_match == 0 never fired.
func TestNoAddressCompletedAHandshakeMarksProbeMatchZero(t *testing.T) {
	const host = "nothing-answers.example"
	cert := makeCert(t, []string{host},
		time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
	good := resultFromCert(t, cert, host)
	expectation := Expectation{Domains: []string{host}, NotAfter: good.NotAfter}

	r := NewRunner(Options{}, 0, nil)
	r.probeAll = func(context.Context, string, Options) ([]Attempt, error) {
		return []Attempt{{Address: "192.0.2.10:443", Result: good}}, nil
	}
	if v := r.Check(context.Background(), host, expectation); !v.OK {
		t.Fatalf("the priming round should pass, got: %s", v.Summary())
	}
	if got := testutil.ToFloat64(metrics.CertificateProbeMatch.WithLabelValues(host)); got != 1 {
		t.Fatalf("probe_match should be 1 after a clean round, got %v", got)
	}

	// The name still resolves -- so this is not the resolve-failure branch -- but every address
	// fails the handshake. Two addresses, so it is not the single-address case either.
	r.probeAll = func(context.Context, string, Options) ([]Attempt, error) {
		return []Attempt{
			{Address: "192.0.2.10:443", Err: context.DeadlineExceeded},
			{Address: "192.0.2.11:443", Err: context.DeadlineExceeded},
		}, nil
	}
	if v := r.Check(context.Background(), host, expectation); v.OK {
		t.Fatal("a host where no address completed a handshake must not pass")
	}
	if got := testutil.ToFloat64(metrics.CertificateProbeMatch.WithLabelValues(host)); got != 0 {
		t.Errorf("probe_match must drop to 0 when no address completed a handshake, got %v (stale 1)", got)
	}
	// And no series is left behind claiming to describe a certificate that was never read.
	if got := testutil.ToFloat64(metrics.CertificateProbeNotAfter.WithLabelValues(host)); got != 0 {
		t.Errorf("probe_not_after must not survive a round that read no certificate, got %v", got)
	}
}

// A name with more addresses than the cap is reported as unverified, never sampled.
//
// Every resolved address has to be checked -- a rebind takes effect per backend -- so "here are the
// first N" would be a claim the probe cannot support, and it would be indistinguishable from a
// clean verdict. The cap exists so one name cannot spend an unbounded slice of a pass: the cost of
// probing is len(addresses) dials of up to Timeout each, inside that certificate's own pass claim.
func TestTooManyAddressesIsRefusedRatherThanSampled(t *testing.T) {
	t.Parallel()
	ips := make([]string, 0, maxProbeAddresses+1)
	for i := 0; i <= maxProbeAddresses; i++ {
		ips = append(ips, fmt.Sprintf("192.0.2.%d", i%256))
	}

	// The resolver is not injectable, so the decision is tested where it is made: the cap is a
	// comparison against maxProbeAddresses, and this asserts the documented boundary.
	if maxProbeAddresses < 8 {
		t.Fatalf("the cap must be comfortably above any real deployment, got %d", maxProbeAddresses)
	}
	if len(ips) <= maxProbeAddresses {
		t.Fatalf("the fixture must exceed the cap, got %d addresses", len(ips))
	}
	err := capCheck("example.com", len(ips))
	if err == nil {
		t.Fatal("a name past the cap must produce an error, not a silent sample")
	}
	if !strings.Contains(err.Error(), "unverified") {
		t.Errorf("the message has to say the name is unverified rather than probed, got %v", err)
	}
	if err := capCheck("example.com", maxProbeAddresses); err != nil {
		t.Errorf("the cap itself must be allowed, got %v", err)
	}
}

// A misspelled -expect-san must not be reported as both missing and extra.
//
// normalizeSet trimmed the spaces BEFORE stripping the dot, so it was not idempotent: a name written
// "www.example.com.." kept one dot after the first pass and lost it on the second. Verify compares
// two normalized sets, so the same name landed in both "missing names that were deployed" and "has
// names that were not deployed" -- one typo, a self-contradictory verdict and exit code 2.
func TestExpectSANNormalisationIsIdempotent(t *testing.T) {
	t.Parallel()
	for _, spelling := range []string{"www.example.com", "WWW.Example.com ", "www.example.com.", "www.example.com..", " www.example.com ."} {
		first := normalizeSet([]string{spelling})
		for name := range first {
			second := normalizeSet([]string{name})
			if len(second) != 1 || !second[name] {
				t.Errorf("normalizeSet is not idempotent for %q: first pass %q, second pass %v",
					spelling, name, second)
			}
			if name != "www.example.com" {
				t.Errorf("%q normalised to %q, want www.example.com", spelling, name)
			}
		}
	}
}

// ── The remembered answer ───────────────────────────────────────────────────

// An inventory page reads the last conclusion instead of the last metric, so a matching round
// has to leave the evidence behind: what was found, whether the chain was trusted, when the
// served certificate expires, and no problem kind at all.
func TestAnswerRemembersAMatchingHost(t *testing.T) {
	t.Parallel()
	const host = "answer-match.example"
	cert := makeCert(t, []string{host},
		time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
	served := resultFromCert(t, cert, host)
	// The probe's own verdict about the chain is what gets remembered, and a self-signed fixture
	// is never trusted on its own -- so this value can only come from the copy.
	served.Trusted = true

	r := NewRunner(Options{}, 0, nil)
	r.probeAll = func(context.Context, string, Options) ([]Attempt, error) {
		return []Attempt{{Address: "192.0.2.10:443", Result: served}}, nil
	}

	if a, ok := r.Answer(host); ok {
		t.Fatalf("a host that was never probed must have no answer, got %+v", a)
	}
	if v := r.Check(context.Background(), host,
		Expectation{Domains: []string{host}, NotAfter: served.NotAfter}); !v.OK {
		t.Fatalf("the round should pass, got: %s", v.Summary())
	}

	a, ok := r.Answer(host)
	if !ok {
		t.Fatal("a matching round must leave an answer")
	}
	if a.Host != host {
		t.Errorf("answer names host %q, want %q", a.Host, host)
	}
	if !a.Match {
		t.Error("a matching round must record Match=true")
	}
	if !a.Trusted {
		t.Error("Trusted must be copied from the served result")
	}
	if !a.NotAfter.Equal(served.NotAfter) {
		t.Errorf("answer NotAfter is %v, want the served %v", a.NotAfter, served.NotAfter)
	}
	if a.ProblemKind != "" {
		t.Errorf("a match has no problem kind, got %q", a.ProblemKind)
	}
}

// A mismatch has to name the problem kind, because "did not match" alone sends the reader to
// the wrong place: a missing name is a deploy/SNI question, not an expiry one.
func TestAnswerNamesTheProblemKindOnAMismatch(t *testing.T) {
	t.Parallel()
	const host = "answer-missing.example"
	cert := makeCert(t, []string{host},
		time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
	served := resultFromCert(t, cert, host)
	served.Trusted = true

	r := NewRunner(Options{}, 0, nil)
	r.probeAll = func(context.Context, string, Options) ([]Attempt, error) {
		return []Attempt{{Address: "192.0.2.10:443", Result: served}}, nil
	}

	// The served certificate covers the dialled name but is missing one that was deployed, and
	// its expiry matches -- so names_missing is the only problem and must be the one reported.
	v := r.Check(context.Background(), host, Expectation{
		Domains:  []string{host, "also-deployed.example"},
		NotAfter: served.NotAfter,
	})
	if v.OK {
		t.Fatal("a certificate missing a deployed name must not pass")
	}

	a, ok := r.Answer(host)
	if !ok {
		t.Fatal("a mismatching round must still leave an answer")
	}
	if a.Match {
		t.Error("a mismatch must record Match=false")
	}
	if a.ProblemKind != string(ProblemNamesMissing) {
		t.Errorf("problem kind is %q, want %q", a.ProblemKind, ProblemNamesMissing)
	}
	// The certificate WAS read, so the evidence it carries is real and has to survive.
	if !a.NotAfter.Equal(served.NotAfter) {
		t.Errorf("answer NotAfter is %v, want the served %v", a.NotAfter, served.NotAfter)
	}
	if !a.Trusted {
		t.Error("a served certificate's Trusted must be copied even when the verdict is a mismatch")
	}
}

// Every path where the probe could not answer must overwrite the previous answer.
//
// The failure this pins is the one the whole change exists to remove: a host that matched and
// then lost its DNS, its listener or one of its addresses kept Match=true with its old NotAfter,
// so the page showed a healthy unexpired certificate for an endpoint nobody can dial.
func TestAnswerGoesUnreachableOnEveryUnreachablePath(t *testing.T) {
	t.Parallel()
	const host = "answer-unreachable.example"
	cert := makeCert(t, []string{host},
		time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
	served := resultFromCert(t, cert, host)
	expectation := Expectation{Domains: []string{host}, NotAfter: served.NotAfter}

	cases := []struct {
		name  string
		probe func(context.Context, string, Options) ([]Attempt, error)
	}{
		{"probeAll fails", func(context.Context, string, Options) ([]Attempt, error) {
			return nil, &net.DNSError{Name: host, Err: "no such host", IsNotFound: true}
		}},
		{"no address completed a handshake", func(context.Context, string, Options) ([]Attempt, error) {
			return []Attempt{{Address: "192.0.2.11:443", Err: context.DeadlineExceeded}}, nil
		}},
		{"only some addresses were probed", func(context.Context, string, Options) ([]Attempt, error) {
			return []Attempt{
				{Address: "192.0.2.10:443", Result: served},
				{Address: "192.0.2.11:443", Err: context.DeadlineExceeded},
			}, nil
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRunner(Options{}, 0, nil)

			// Prime with a clean round, so a surviving stale answer is visible as Match=true.
			r.probeAll = func(context.Context, string, Options) ([]Attempt, error) {
				return []Attempt{{Address: "192.0.2.10:443", Result: served}}, nil
			}
			if v := r.Check(context.Background(), host, expectation); !v.OK {
				t.Fatalf("the priming round should pass, got: %s", v.Summary())
			}
			if a, ok := r.Answer(host); !ok || !a.Match {
				t.Fatalf("the priming round should leave a match, got %+v (ok=%v)", a, ok)
			}

			r.probeAll = tc.probe
			if v := r.Check(context.Background(), host, expectation); v.OK {
				t.Fatal("an unreachable host must not pass")
			}

			a, ok := r.Answer(host)
			if !ok {
				t.Fatal("an unreachable round must still leave an answer")
			}
			if a.Match {
				t.Error("the previous match survived an unreachable round (stale answer)")
			}
			if a.ProblemKind != string(ProblemUnreachable) {
				t.Errorf("problem kind is %q, want %q", a.ProblemKind, ProblemUnreachable)
			}
			// No handshake happened, so there is no certificate to report -- the same reason the
			// notAfter and trusted metrics are cleared on these paths.
			if a.Trusted {
				t.Error("Trusted must be false when nothing was read")
			}
			if !a.NotAfter.IsZero() {
				t.Errorf("NotAfter must be zero when nothing was read, got %v", a.NotAfter)
			}
		})
	}
}

// Forget exists so per-host memory stops growing with every name ever seen; the answer is part
// of that memory, so it has to go with the transition state.
func TestForgetDropsTheRememberedAnswer(t *testing.T) {
	t.Parallel()
	const host = "answer-forget.example"
	cert := makeCert(t, []string{host},
		time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))

	r := NewRunner(Options{}, 0, nil)
	r.probeAll = func(context.Context, string, Options) ([]Attempt, error) {
		return []Attempt{{Address: "192.0.2.10:443", Result: resultFromCert(t, cert, host)}}, nil
	}
	r.Check(context.Background(), host, Expectation{Domains: []string{host}})
	if _, ok := r.Answer(host); !ok {
		t.Fatal("the host should have an answer after a probe")
	}

	r.Forget(host)
	if a, ok := r.Answer(host); ok {
		t.Errorf("Forget should drop the remembered answer, still have %+v", a)
	}
}

// Check runs one goroutine per host and an inventory page reads answers while rounds are still
// landing, so both maps live behind the same mutex. Run with -race, this is what proves it.
func TestAnswerIsRaceFreeUnderConcurrentChecks(t *testing.T) {
	t.Parallel()
	const hostCount = 8

	served := make(map[string]*Result, hostCount)
	expectations := make(map[string]Expectation, hostCount)
	for i := 0; i < hostCount; i++ {
		host := fmt.Sprintf("answer-race-%d.example", i)
		cert := makeCert(t, []string{host},
			time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
		res := resultFromCert(t, cert, host)
		served[host] = res
		expectations[host] = Expectation{Domains: []string{host}, NotAfter: res.NotAfter}
	}

	r := NewRunner(Options{}, 0, nil)
	r.probeAll = func(_ context.Context, host string, _ Options) ([]Attempt, error) {
		res, ok := served[host]
		if !ok {
			return nil, fmt.Errorf("no fixture for %s", host)
		}
		return []Attempt{{Address: "192.0.2.10:443", Result: res}}, nil
	}

	var wg sync.WaitGroup
	for host := range served {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				r.Check(context.Background(), host, expectations[host])
			}
		}(host)
	}
	// Reads deliberately overlap the writes above: Answer must be safe at any moment, not only
	// once the round has settled.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			for host := range served {
				r.Answer(host)
				r.ProbedHosts()
			}
		}
	}()
	wg.Wait()

	for host, want := range served {
		a, ok := r.Answer(host)
		if !ok {
			t.Fatalf("no answer for %s after concurrent checks", host)
		}
		if !a.Match {
			t.Errorf("%s: want a matching answer, got %+v", host, a)
		}
		if !a.NotAfter.Equal(want.NotAfter) {
			t.Errorf("%s: NotAfter is %v, want %v", host, a.NotAfter, want.NotAfter)
		}
	}
}

// ── The transition line must name the actual problem class ─────────────────────────

// The transition line is what the CRITICAL alert's annotation repeats, so it must name
// what Verify actually found: "not the one that was deployed" sends the operator to CLB
// bindings, SNI and the deploy path -- the wrong direction entirely when the served
// certificate IS the deployed one and the problem is a broken chain or an expired leaf.
func TestMismatchMessageNamesTheActualProblemClass(t *testing.T) {
	for _, tc := range []struct {
		name     string
		problems []Problem
		want     string
	}{
		{"untrusted only", []Problem{{Kind: ProblemUntrusted}},
			"the certificate being served does not verify against the system roots"},
		{"outside validity window only", []Problem{{Kind: ProblemValidityWindow}},
			"the certificate being served is expired or not yet valid"},
		{"validity floor only", []Problem{{Kind: ProblemMinValidFor}},
			"the certificate being served has less validity left than required"},
		{"not covered only", []Problem{{Kind: ProblemNotCovered}},
			"the certificate being served does not cover this name"},
		// The mix that used to fall into the default: the deployed certificate IS
		// being served, expiring AND with a chain no client accepts.
		{"validity floor and untrusted", []Problem{{Kind: ProblemMinValidFor}, {Kind: ProblemUntrusted}},
			"the certificate being served is the deployed one, but it is currently not usable"},
		{"a different certificate", []Problem{{Kind: ProblemNotAfter}},
			"the certificate being served is not the one that was deployed"},
		{"name problems stay wrong-certificate", []Problem{{Kind: ProblemNotCovered}, {Kind: ProblemNotAfter}},
			"the certificate being served is not the one that was deployed"},
	} {
		if got := mismatchMessage(tc.problems); got != tc.want {
			t.Errorf("%s: mismatchMessage = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// ── The validity window is not opt-in ───────────────────────────────────────────────

// An expired certificate must fail even when nothing asked about validity.
//
// Verify's only clock checks used to be opt-in: RequireTrusted covers the chain and
// MinValidFor a remaining-validity floor. With both off -- the default for a plain probe
// -- a certificate whose names and notAfter matched the expectation came back OK while
// every client rejected it as expired: exactly the false green this package exists to
// rule out.
func TestVerifyRejectsAnExpiredCertificateWithoutBeingAsked(t *testing.T) {
	port := startServer(t, makeCert(t, []string{"localhost"},
		time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)))
	res := probeLocalhost(t, port)

	v := res.Verify(Expectation{})
	if v.OK {
		t.Fatal("an expired certificate must not pass with every policy check off")
	}
	found := false
	for _, p := range v.Problems {
		if p.Kind == ProblemValidityWindow {
			found = true
		}
	}
	if !found {
		t.Errorf("the problem must be ProblemValidityWindow, got %+v", v.Problems)
	}
}

// The other direction of the window: a certificate whose validity has not started yet.
func TestVerifyRejectsANotYetValidCertificate(t *testing.T) {
	port := startServer(t, makeCert(t, []string{"localhost"},
		time.Now().Add(time.Hour), time.Now().Add(60*24*time.Hour)))
	res := probeLocalhost(t, port)

	v := res.Verify(Expectation{})
	if v.OK {
		t.Fatal("a not-yet-valid certificate must not pass")
	}
	if !strings.Contains(v.Summary(), "not valid until") {
		t.Errorf("it should say when validity starts, got: %s", v.Summary())
	}
}

// With no certificate captured, Verify must report exactly that -- and not pile on
// "different notAfter", "too little validity left" and "outside the validity window" for
// the zero times a missing leaf leaves behind. Checks 2 and 5 already guarded on r.cert;
// 3 and 4 did not.
func TestVerifyWithoutACertificateReportsOnlyThat(t *testing.T) {
	res := &Result{Host: "example.com"} // no leaf: the zero times must not double-report
	v := res.Verify(Expectation{
		Domains:        []string{"example.com"},
		NotAfter:       time.Now().Add(24 * time.Hour),
		MinValidFor:    time.Hour,
		RequireTrusted: true,
	})
	if v.OK {
		t.Fatal("no certificate cannot be OK")
	}
	if len(v.Problems) != 1 || v.Problems[0].Kind != ProblemNoCertificate {
		t.Errorf("want exactly ProblemNoCertificate, got %+v", v.Problems)
	}
}

// ── Shutdown is not an environment failure ──────────────────────────────────────────

// A cancelled context is the daemon shutting down, not a host that became unreachable.
//
// The error branch used to treat it as one: probe_errors incremented, probe_match forced
// to 0, ClearProbeAnswer deleting the notAfter/trusted series and an ERROR-level
// transition logged -- a full "environment is broken" record for a process that was
// simply stopping, which then pages whoever is on call for the wrong reason.
func TestCancelledContextWritesNoMetricsOrState(t *testing.T) {
	const host = "cancelled-shutdown.example"
	r := NewRunner(Options{}, 0, nil)
	r.probeAll = func(context.Context, string, Options) ([]Attempt, error) {
		return nil, context.Canceled
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	v := r.Check(ctx, host, Expectation{Domains: []string{host}})
	if v.OK {
		t.Fatal("a cancelled probe cannot be OK")
	}
	if got := r.LastState(host); got != "" {
		t.Errorf("a cancelled probe must not record a state transition, got %q", got)
	}
	// The error counter is the discriminating series: it only ever increases, so 0 here
	// means the cancelled round truly wrote nothing. (probe_match cannot tell "never
	// written" from "written 0" -- reading the gauge creates the child either way.)
	if got := testutil.ToFloat64(metrics.CertificateProbeErrors.WithLabelValues(host)); got != 0 {
		t.Errorf("a cancelled probe must not count as a probe error, got %v", got)
	}
}

// The same rule when the resolution succeeded and the context died during the dials:
// every cancelled dial would otherwise count as a probe error, and the whole-addresses-
// failed branch would record an unreachable transition.
func TestCancelledDuringDialsWritesNoMetricsOrState(t *testing.T) {
	const host = "cancelled-mid-probe.example"
	ctx, cancel := context.WithCancel(context.Background())
	r := NewRunner(Options{}, 0, nil)
	r.probeAll = func(context.Context, string, Options) ([]Attempt, error) {
		cancel() // the context dies while the answers are coming back
		return []Attempt{{Address: "192.0.2.10:443", Err: context.Canceled}}, nil
	}

	v := r.Check(ctx, host, Expectation{Domains: []string{host}})
	if v.OK {
		t.Fatal("a cancelled probe cannot be OK")
	}
	if got := r.LastState(host); got != "" {
		t.Errorf("a cancelled probe must not record a state transition, got %q", got)
	}
	if got := testutil.ToFloat64(metrics.CertificateProbeErrors.WithLabelValues(host)); got != 0 {
		t.Errorf("cancelled dials must not count as probe errors, got %v", got)
	}
}

// ── Per-host serialization ──────────────────────────────────────────────────────────

// Two Checks for the SAME host must never overlap.
//
// Two certificates can cover one name, and the reconciler dials a certificate's names
// concurrently, so the same host can legitimately be checked twice at once. Unserialized,
// the two interleave their metric writes and their state transitions: transition() then
// never sees the same state twice in a row for that host, the dedup never fires, and a
// persistent mismatch re-alerts every single round.
func TestCheckSerializesOneHost(t *testing.T) {
	r := NewRunner(Options{}, 0, nil)
	var inFlight, maxSeen atomic.Int32
	r.probeAll = func(context.Context, string, Options) ([]Attempt, error) {
		n := inFlight.Add(1)
		for {
			if m := maxSeen.Load(); n <= m || maxSeen.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		inFlight.Add(-1)
		return nil, errors.New("no such host")
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Check(context.Background(), "shared.example", Expectation{Domains: []string{"shared.example"}})
		}()
	}
	wg.Wait()

	if got := maxSeen.Load(); got != 1 {
		t.Errorf("checks of one host overlapped: %d were in flight at once, so the "+
			"transition dedup never fires and every round re-alerts", got)
	}
}

// The serialization is PER HOST: different hosts must still probe in parallel, or one
// slow host would stall every other certificate's probe behind it.
func TestCheckSerializesPerHostOnly(t *testing.T) {
	r := NewRunner(Options{}, 0, nil)
	entered := make(chan string, 2)
	release := make(chan struct{})
	r.probeAll = func(_ context.Context, host string, _ Options) ([]Attempt, error) {
		entered <- host
		<-release
		return nil, errors.New("no such host")
	}

	var wg sync.WaitGroup
	for _, host := range []string{"a.example", "b.example"} {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			r.Check(context.Background(), h, Expectation{Domains: []string{h}})
		}(host)
	}

	// Both must be inside probeAll before either is released: if the lock were global,
	// the second receive would never happen and the first Check would wait forever.
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("the second host never entered probeAll: the serialization is global, not per-host")
		}
	}
	close(release)
	wg.Wait()
}

// ── Options validation and address deduplication ────────────────────────────────────

// Options are validated before any DNS lookup: an invalid port or an absurd timeout is a
// caller/configuration error, and reporting it as "could not resolve" sends the diagnosis
// to DNS for a mistake that is in the arguments. (The config layer floors probe.timeout
// at 1s; the maximum here is the other end -- the timeout is the per-address budget, so
// past it a probe is stalled, not patient.)
func TestProbeRejectsAnOutOfRangePort(t *testing.T) {
	for _, port := range []int{-1, 70000} {
		_, err := Probe(context.Background(), "example.com", Options{Port: port})
		if err == nil || !strings.Contains(err.Error(), "port") {
			t.Errorf("port %d: want a port validation error before any lookup, got %v", port, err)
		}
	}
}

func TestProbeRejectsAnAbsurdTimeout(t *testing.T) {
	_, err := Probe(context.Background(), "example.com", Options{Timeout: maxProbeTimeout + time.Second})
	if err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("a timeout past the maximum must be rejected before any lookup, got %v", err)
	}
}

// The same resolved address twice is dialled twice for no extra evidence -- and counted
// twice against the address cap. A hosts-file line next to the DNS answer is enough to
// produce the duplicate.
func TestDedupeAddrs(t *testing.T) {
	got := dedupeAddrs([]string{"10.0.0.2", "10.0.0.1", "10.0.0.2", "2001:db8::1", "10.0.0.1"})
	want := []string{"10.0.0.2", "10.0.0.1", "2001:db8::1"}
	if len(got) != len(want) {
		t.Fatalf("dedupeAddrs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("dedupeAddrs = %v, want %v (order must be preserved)", got, want)
		}
	}
}
