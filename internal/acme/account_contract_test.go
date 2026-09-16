package acme

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/acme/api"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/state"
)

// accountFixture starts the fake directory plus a state store, and points the config at the
// fake. The HTTP client comes from the test server, so its CA is trusted.
func accountFixture(t *testing.T) (*fakeACME, *state.Store, *config.Config) {
	t.Helper()

	fake := newFakeACME(t)
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := &config.Config{}
	cfg.ACME.Directory = fake.srv.URL + "/directory"
	cfg.ACME.Email = "ops@example.com"
	return fake, store, cfg
}

// A first run registers an account and persists both the key and the kid.
//
// The kid is what later requests authenticate with; the key is the account's identity. Losing
// either means a brand-new account, and accounts are a limited resource (10 per IP per 3 hours).
func TestEnsureAccountRegistersAndPersists(t *testing.T) {
	fake, store, cfg := accountFixture(t)

	core, err := EnsureAccount(cfg, store, fake.srv.Client())
	if err != nil {
		t.Fatalf("EnsureAccount: %v", err)
	}
	if core == nil {
		t.Fatal("EnsureAccount returned no core")
	}

	stored, err := store.GetAccount(cfg.ACME.Directory)
	if err != nil {
		t.Fatalf("GetAccount: %v", err)
	}
	if stored == nil {
		t.Fatal("the account must be persisted, or every restart registers a new one")
	}
	if stored.KID == "" {
		t.Error("the kid must be persisted: without it the stored key cannot be used")
	}
	if !strings.Contains(string(stored.PrivateKeyPEM), "PRIVATE KEY") {
		t.Errorf("the account key must be stored as PEM, got %q", stored.PrivateKeyPEM)
	}
	if stored.Directory != cfg.ACME.Directory {
		t.Errorf("the row is keyed on the directory, got %q", stored.Directory)
	}
}

// The stored key must be the one the account was registered with, i.e. parseable back into a
// usable signer. A key that only round-trips as bytes would fail at the next request.
func TestEnsureAccountStoresAUsableKey(t *testing.T) {
	fake, store, cfg := accountFixture(t)

	if _, err := EnsureAccount(cfg, store, fake.srv.Client()); err != nil {
		t.Fatalf("EnsureAccount: %v", err)
	}
	stored, err := store.GetAccount(cfg.ACME.Directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePrivateKeyPEM(stored.PrivateKeyPEM); err != nil {
		t.Errorf("the persisted account key does not parse back: %v", err)
	}
}

// A stored account must be reused rather than re-registered: a new account squanders one of the
// 10-per-IP-per-3-hours registrations and orphans every order placed under the old one.
func TestEnsureAccountReusesAStoredAccount(t *testing.T) {
	fake, store, cfg := accountFixture(t)

	if _, err := EnsureAccount(cfg, store, fake.srv.Client()); err != nil {
		t.Fatalf("first: %v", err)
	}
	first, err := store.GetAccount(cfg.ACME.Directory)
	if err != nil {
		t.Fatal(err)
	}

	// The fake would hand back the same account URL on a second registration, so compare the
	// key: a re-registration means a new key.
	fake.omitAccountLocation.Store(true)
	if _, err := EnsureAccount(cfg, store, fake.srv.Client()); err != nil {
		t.Fatalf("second: %v", err)
	}
	second, err := store.GetAccount(cfg.ACME.Directory)
	if err != nil {
		t.Fatal(err)
	}
	if second.KID != first.KID {
		t.Errorf("the account was re-registered: kid %q -> %q", first.KID, second.KID)
	}
	if string(second.PrivateKeyPEM) != string(first.PrivateKeyPEM) {
		t.Fatal("the account key changed, so a second registration happened despite a stored account")
	}
}

// A stored key that cannot be parsed must be a hard error, never a silent re-registration.
//
// Re-registering looks like success while costing a scarce registration, and the operator
// believes they are running on the key they restored.
func TestEnsureAccountRefusesAnUnparseableStoredKey(t *testing.T) {
	fake, store, cfg := accountFixture(t)

	if err := store.PutAccount(&state.Account{
		Directory:     cfg.ACME.Directory,
		KID:           "https://acme.test/acct/1",
		PrivateKeyPEM: []byte("this is not a PEM block"),
	}); err != nil {
		t.Fatal(err)
	}

	_, err := EnsureAccount(cfg, store, fake.srv.Client())
	if err == nil {
		t.Fatal("an unparseable stored key must fail rather than register a new account")
	}
	if !strings.Contains(err.Error(), "account key") {
		t.Errorf("the error should name what is wrong, got: %v", err)
	}

	// The row must be left alone, so the operator can recover it by hand.
	after, err := store.GetAccount(cfg.ACME.Directory)
	if err != nil {
		t.Fatal(err)
	}
	if after == nil || after.KID != "https://acme.test/acct/1" {
		t.Error("the stored account was modified by a failed load")
	}
}

// A stored row with no key cannot authenticate anything, so it is treated as no account and
// replaced by a real registration rather than failing forever.
//
// PutAccount cannot produce this shape -- private_key_pem is NOT NULL, which this test found --
// so the row is written the way an older database could hold it: straight SQL with a NULL key.
func TestEnsureAccountTreatsAnEmptyKeyAsNoAccount(t *testing.T) {
	fake, store, cfg := accountFixture(t)

	if err := store.PutAccountWithoutKey(cfg.ACME.Directory, "https://acme.test/acct/1"); err != nil {
		t.Fatalf("build a legacy account row: %v", err)
	}
	if _, err := EnsureAccount(cfg, store, fake.srv.Client()); err != nil {
		t.Fatalf("an account row with no key must be replaced by a real registration: %v", err)
	}
	stored, err := store.GetAccount(cfg.ACME.Directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.PrivateKeyPEM) == 0 {
		t.Error("no key was stored")
	}
}

// A registration response without a Location header carries no kid, so the account can be
// neither used nor usefully persisted. It must be reported, not written with an empty kid.
func TestEnsureAccountRequiresAKid(t *testing.T) {
	fake, store, cfg := accountFixture(t)
	fake.omitAccountLocation.Store(true)

	if _, err := EnsureAccount(cfg, store, fake.srv.Client()); err == nil {
		t.Fatal("a registration without a Location header must fail")
	}
	stored, err := store.GetAccount(cfg.ACME.Directory)
	if err != nil {
		t.Fatal(err)
	}
	if stored != nil {
		t.Errorf("nothing usable should be persisted, got %+v", stored)
	}
}

// ── User-Agent ───────────────────────────────────────────────────────────────────────

// The User-Agent must name the running version, so a CA-side log lines up with the binary that
// sent the request instead of naming a release superseded months ago.
func TestUserAgentCarriesTheRunningVersion(t *testing.T) {
	saved := userAgentVersion
	t.Cleanup(func() { userAgentVersion = saved })

	SetUserAgentVersion("9.9.9")
	if got := userAgent(); !strings.HasPrefix(got, "wecert/9.9.9 ") {
		t.Errorf("userAgent = %q, want it to start with wecert/9.9.9", got)
	}

	// An empty version must be ignored: the value comes from -ldflags and may be unset when a
	// binary is built by hand, and blanking it would yield "wecert/ ".
	SetUserAgentVersion("")
	if got := userAgent(); !strings.HasPrefix(got, "wecert/9.9.9 ") {
		t.Errorf("an empty version must not blank the field, got %q", got)
	}
}

// ── ARI ──────────────────────────────────────────────────────────────────────────────
//
// These drive lego's real renewalInfo request against a canned response, because what matters is
// lego's parsing wiring: whether Retry-After survives, and whether a non-200 or a bad body is
// distinguishable from a usable window.

// ariServer answers /directory and /renewal-info. lego forces https for sender requests
// (sender.newHTTPSOnly), so the fake must speak TLS.
func ariServer(t *testing.T, status int, body string, headers map[string]string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		base := "https://" + r.Host
		writeJSON(w, map[string]any{
			"newNonce":    base + "/new-nonce",
			"newAccount":  base + "/new-account",
			"newOrder":    base + "/new-order",
			"revokeCert":  base + "/revoke-cert",
			"keyChange":   base + "/key-change",
			"renewalInfo": base + "/renewal-info",
		})
	})
	mux.HandleFunc("/new-nonce", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.WriteHeader(http.StatusOK)
	})
	// lego requests {renewalInfo}/{certID}, so this must match the subtree, not one path.
	mux.HandleFunc("/renewal-info/", func(w http.ResponseWriter, _ *http.Request) {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func ariCore(t *testing.T, srv *httptest.Server) API {
	t.Helper()
	key, err := GenerateKey(config.KeyTypeECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	core, err := api.New(srv.Client(), "wecert/test", srv.URL+"/directory", "", key)
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}
	return NewAPI(core)
}

// FetchRenewalInfo must surface the server's Retry-After: that header is part of the
// conclusion, deciding how long to wait before asking again. Dropping it means hammering the
// endpoint on every pass.
func TestFetchRenewalInfoReturnsRetryAfter(t *testing.T) {
	srv := ariServer(t, http.StatusOK,
		`{"suggestedWindow":{"start":"2026-09-20T00:00:00Z","end":"2026-09-25T00:00:00Z"}}`,
		map[string]string{"Retry-After": "3600"})

	info, retryAfter, err := FetchRenewalInfo(ariCore(t, srv), "aki.serial")
	if err != nil {
		t.Fatalf("FetchRenewalInfo: %v", err)
	}
	if info.SuggestedWindow.Start.IsZero() || info.SuggestedWindow.End.IsZero() {
		t.Errorf("the window was not parsed: %+v", info)
	}
	if retryAfter != time.Hour {
		t.Errorf("Retry-After = %s, want 1h", retryAfter)
	}
}

// A non-200 still carries information: the status, and Retry-After when present. Both must come
// back, or a throttled caller either retries immediately or loses the server's guidance.
func TestFetchRenewalInfoReportsStatusAndRetryAfterOnFailure(t *testing.T) {
	srv := ariServer(t, http.StatusTooManyRequests, `{}`, map[string]string{"Retry-After": "60"})

	_, retryAfter, err := FetchRenewalInfo(ariCore(t, srv), "aki.serial")
	if err == nil {
		t.Fatal("a 429 must be reported as an error")
	}
	if !strings.Contains(err.Error(), "429") {
		t.Errorf("the error must name the status, got: %v", err)
	}
	if retryAfter != time.Minute {
		t.Errorf("Retry-After = %s, want 1m even on failure", retryAfter)
	}
}

// An inverted window is not a usable interval and must be rejected rather than producing a
// renewal time from a negative span.
func TestFetchRenewalInfoRejectsAnInvertedWindow(t *testing.T) {
	srv := ariServer(t, http.StatusOK,
		`{"suggestedWindow":{"start":"2026-09-25T00:00:00Z","end":"2026-09-20T00:00:00Z"}}`, nil)

	if _, _, err := FetchRenewalInfo(ariCore(t, srv), "aki.serial"); err == nil {
		t.Fatal("an inverted suggestedWindow must be rejected")
	}
}

// A malformed body must be an error, not a zero window -- which reads as "renew now".
func TestFetchRenewalInfoRejectsGarbage(t *testing.T) {
	srv := ariServer(t, http.StatusOK, `not json at all`, nil)

	if _, _, err := FetchRenewalInfo(ariCore(t, srv), "aki.serial"); err == nil {
		t.Fatal("a body that is not JSON must be rejected")
	}
}

// ── renewal time selection ───────────────────────────────────────────────────────────

// The renewal instant must be deterministic: re-rolling it every pass would walk the renewal
// later with each restart until it slid past expiry.
func TestRenewalTimeIsDeterministicAndInsideTheWindow(t *testing.T) {
	start := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	end := start.Add(96 * time.Hour)

	first := RenewalTime("example-com", start, end)
	for i := 0; i < 5; i++ {
		if got := RenewalTime("example-com", start, end); !got.Equal(first) {
			t.Fatalf("RenewalTime is not deterministic: %s then %s", first, got)
		}
	}
	if first.Before(start) || first.After(end) {
		t.Errorf("the renewal instant %s is outside %s..%s", first, start, end)
	}
	if other := RenewalTime("other-com", start, end); other.Equal(first) {
		t.Error("two certificates chose the identical instant, so the jitter does nothing")
	}
}

// A degenerate window must fall back to the start rather than producing a time outside it.
func TestRenewalTimeHandlesADegenerateWindow(t *testing.T) {
	start := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	if got := RenewalTime("x", start, start); !got.Equal(start) {
		t.Errorf("RenewalTime with an empty window = %s, want %s", got, start)
	}
}

// The fallback instant must be spread deterministically across the range and never before the
// base: renewing early costs quota.
func TestDeterministicTimeStaysInRange(t *testing.T) {
	base := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	spread := 48 * time.Hour

	first := DeterministicTime("example-com", base, spread)
	if first.Before(base) || !first.Before(base.Add(spread)) {
		t.Errorf("instant %s is outside %s..%s", first, base, base.Add(spread))
	}
	if got := DeterministicTime("example-com", base, spread); !got.Equal(first) {
		t.Errorf("not deterministic: %s then %s", first, got)
	}
	if got := DeterministicTime("x", base, 0); !got.Equal(base) {
		t.Errorf("spread 0 = %s, want the base %s", got, base)
	}
}

var _ = context.Background
