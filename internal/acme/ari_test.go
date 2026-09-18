package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/acme/api"
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

	cases := []struct {
		name    string
		serial  *big.Int
		wantDER []byte
	}{
		// 0xde has the top bit set: DER must carry a leading 0x00 or the INTEGER reads
		// as negative. big.Int.Bytes() drops that byte, and pinning the dropped form
		// here is what let the wrong encoding through review in the first place.
		{"high-bit serial gets the DER leading zero", big.NewInt(0xdeadbeef), []byte{0x00, 0xde, 0xad, 0xbe, 0xef}},
		{"low-bit serial stays untouched", big.NewInt(0x1eaf), []byte{0x1e, 0xaf}},
	}

	for _, tc := range cases {
		leaf := &x509.Certificate{AuthorityKeyId: aki, SerialNumber: tc.serial}

		got, err := CertID(leaf)
		if err != nil {
			t.Fatalf("%s: CertID returned an error: %v", tc.name, err)
		}

		want := base64.RawURLEncoding.EncodeToString(aki) + "." +
			base64.RawURLEncoding.EncodeToString(tc.wantDER)
		if got != want {
			t.Errorf("%s: CertID = %q, want %q", tc.name, got, want)
		}
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

// The CA's Retry-After for a PROCESSING ORDER cannot reach wecert at all.
//
// The recorded limitation (rounds 7-10, section 2.4) says order/authorization polling ignores the
// CA's Retry-After because lego's ExtendedOrder does not expose it. This pins that against lego
// v4.35.2 with a real api.Core talking to a test server that DOES send the header:
//
//   - lego's OrderService.Get (acme/api/order.go:105) throws the *http.Response away --
//     `_, err := o.core.postAsGet(orderURL, &order)` -- so the header is unreachable even though
//     the response carrying it was in lego's hands;
//   - ExtendedOrder (acme/commons.go:132) is `Order` plus `Location`, and `Order` has no
//     Retry-After field (the only struct that carries one is ExtendedChallenge, filled in for
//     challenge URLs).
//
// wecert is therefore left with one fixed interval for order/authorization polling
// (pollInterval = 3s), which is what the claim records. This is the confirmed blocker, not a bug
// to fix here: honouring a processing order's Retry-After needs a lego change, or a hand-rolled
// poller that reads the header instead of lego's api.Core.
//
// One Retry-After DOES reach wecert: lego attaches the header to its typed RateLimitedError
// (acme/errors.go:88, sender.go:157), and wecert books that deadline in noteNewOrderRefusal. That
// is a REFUSED order, not a processing one.
func TestLegoDropsTheRetryAfterHeaderOnOrderPolling(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var srv *httptest.Server
	// TLS, because lego refuses a plaintext directory ("HTTPS is required").
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dir":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"newNonce":   srv.URL + "/nonce",
				"newAccount": srv.URL + "/acct",
				"newOrder":   srv.URL + "/order",
			})
		case "/nonce":
			// Every POST needs a fresh nonce; lego's nonce manager fetches them here.
			w.Header().Set("Replay-Nonce", "nonce-1")
			w.WriteHeader(http.StatusOK)
		case "/order/1":
			// The CA telling the client how long to wait before asking again -- exactly the header
			// that RFC 8555 section 7.4 attaches to a processing order.
			w.Header().Set("Retry-After", "7")
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"status":"processing"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	core, err := api.New(srv.Client(), "wecert-test", srv.URL+"/dir", "", key)
	if err != nil {
		t.Fatalf("build a lego api.Core against the test directory: %v", err)
	}
	order, err := core.Orders.Get(srv.URL + "/order/1")
	if err != nil {
		t.Fatalf("Orders.Get: %v", err)
	}
	if order.Status != "processing" {
		t.Fatalf("fixture: got status %q", order.Status)
	}

	// ExtendedOrder carries no Retry-After -- neither as a field nor as a method -- so nothing
	// downstream of this call can honour the 7 seconds the CA asked for.
	if strings.Contains(fmt.Sprintf("%#v", order), "7") {
		t.Errorf("ExtendedOrder unexpectedly carries the Retry-After value: %#v", order)
	}
	if _, ok := any(order).(interface{ GetRetryAfter() time.Duration }); ok {
		t.Error("ExtendedOrder grew a Retry-After accessor: wecert could act on a processing order's " +
			"Retry-After now, and the recorded limitation is stale")
	}
	if pollInterval != 3*time.Second {
		t.Errorf("pollInterval = %s; the recorded fallback is one fixed 3s interval", pollInterval)
	}
}
