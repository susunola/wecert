package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
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
