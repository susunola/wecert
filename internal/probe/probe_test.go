package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
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

func TestProbeReportsAWrongCertificate(t *testing.T) {
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
	_, err := Probe(context.Background(), "*.example.com", Options{})
	if err == nil || !strings.Contains(err.Error(), "wildcard") {
		t.Fatalf("a wildcard should be rejected explicitly, got: %v", err)
	}
}

func TestProbeRejectsAnEmptyHost(t *testing.T) {
	if _, err := Probe(context.Background(), "  ", Options{}); err == nil {
		t.Fatal("an empty name should be rejected")
	}
}

// A probe must not stall the reconcile loop: context cancellation must return immediately.
func TestProbeHonorsContextCancellation(t *testing.T) {
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

// A name with more addresses than the cap is reported as unverified, never sampled.
//
// Every resolved address has to be checked -- a rebind takes effect per backend -- so "here are the
// first N" would be a claim the probe cannot support, and it would be indistinguishable from a
// clean verdict. The cap exists so one name cannot spend an unbounded slice of a pass: the cost of
// probing is len(addresses) dials of up to Timeout each, inside that certificate's own pass claim.
func TestTooManyAddressesIsRefusedRatherThanSampled(t *testing.T) {
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
