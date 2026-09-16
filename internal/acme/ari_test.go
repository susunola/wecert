package acme

import (
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"testing"
	"time"
)

// Determinism in RenewalTime is a hard requirement: if every call re-rolled the dice,
// each process restart would push the renewal a little further out until it slid past
// the expiry. This test pins that property down.
func TestRenewalTimeIsDeterministic(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(48 * time.Hour)

	first := RenewalTime("example-com", start, end)
	for i := 0; i < 100; i++ {
		if got := RenewalTime("example-com", start, end); !got.Equal(first) {
			t.Fatalf("call %d returned a different instant: %s != %s", i, got, first)
		}
	}
}

func TestRenewalTimeStaysInsideWindow(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(48 * time.Hour)

	// Jitter can push it outside the window; it must be clamped back.
	for _, name := range []string{"a", "b", "example-com", "api-example-com", "x.y.z"} {
		got := RenewalTime(name, start, end)
		if got.Before(start) || got.After(end) {
			t.Errorf("%s: %s falls outside the window [%s, %s]", name, got, start, end)
		}
	}
}

// Different certificates should spread across the window, or hundreds will hit the CA in the same second.
func TestRenewalTimeSpreadsAcrossNames(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(48 * time.Hour)

	seen := map[time.Time]bool{}
	distinct := 0
	const n = 50
	for i := 0; i < n; i++ {
		name := "cert-" + string(rune('a'+i%26)) + string(rune('0'+i/26))
		at := RenewalTime(name, start, end)
		if !seen[at] {
			seen[at] = true
			distinct++
		}
	}
	if distinct < n/2 {
		t.Errorf("50 certificates spread into only %d distinct instants; not enough jitter", distinct)
	}
}

func TestRenewalTimeDegenerateWindow(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	// When end is not after start it must return start as-is, not panic (divide by zero).
	if got := RenewalTime("x", start, start); !got.Equal(start) {
		t.Errorf("a zero-width window should return start, got %s", got)
	}
	if got := RenewalTime("x", start, start.Add(-time.Hour)); !got.Equal(start) {
		t.Errorf("an invalid window should return start, got %s", got)
	}
}

func TestDeterministicTimeWithinSpread(t *testing.T) {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	spread := 6 * time.Hour

	for _, name := range []string{"a", "b", "example-com"} {
		at := DeterministicTime(name, base, spread)
		if at.Before(base) || at.After(base.Add(spread)) {
			t.Errorf("%s: %s falls outside [%s, %s]", name, at, base, base.Add(spread))
		}
		if again := DeterministicTime(name, base, spread); !again.Equal(at) {
			t.Errorf("%s: not deterministic, %s != %s", name, again, at)
		}
	}

	// A spread of 0 should fall back to base.
	if got := DeterministicTime("a", base, 0); !got.Equal(base) {
		t.Errorf("spread=0 should return base, got %s", got)
	}
}

// CertID must follow RFC 9773 exactly; otherwise the ARI lookup misses
// and we never get the "exempt from every rate limit" treatment.
func TestCertIDFormat(t *testing.T) {
	aki := []byte{0x01, 0x02, 0x03, 0xff}
	serial := big.NewInt(0xdeadbeef)

	leaf := &x509.Certificate{AuthorityKeyId: aki, SerialNumber: serial}

	got, err := CertID(leaf)
	if err != nil {
		t.Fatalf("CertID returned an error: %v", err)
	}

	want := base64.RawURLEncoding.EncodeToString(aki) + "." +
		base64.RawURLEncoding.EncodeToString(serial.Bytes())
	if got != want {
		t.Errorf("CertID = %q, want %q", got, want)
	}
}

func TestCertIDRequiresAKI(t *testing.T) {
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1)}
	if _, err := CertID(leaf); err == nil {
		t.Error("a missing AKI must be an error, not a certID that can never be looked up")
	}
}

// The last gate before deploy: the issued certificate must cover every requested name.
func TestVerifyCoverage(t *testing.T) {
	leaf := &x509.Certificate{DNSNames: []string{"example.com", "*.example.com"}}

	if err := VerifyCoverage(leaf, []string{"example.com", "*.example.com"}); err != nil {
		t.Errorf("full coverage must not be an error: %v", err)
	}
	// Case must not affect the decision.
	if err := VerifyCoverage(leaf, []string{"EXAMPLE.COM"}); err != nil {
		t.Errorf("differing case must not be an error: %v", err)
	}
	if err := VerifyCoverage(leaf, []string{"example.com", "other.com"}); err == nil {
		t.Error("a missing other.com must be an error")
	}
}
