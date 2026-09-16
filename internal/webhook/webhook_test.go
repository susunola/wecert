package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/reconcile"
	"github.com/susunola/wecert/internal/state"
)

const testToken = "0123456789abcdef0123456789abcdef"

// fakeReconciler records what was triggered and returns preset errors.
type fakeReconciler struct {
	names   []string
	started []string
	failFor map[string]error

	// startAllErr simulates "the desired state is unreadable": nothing started.
	startAllErr error
}

func (f *fakeReconciler) CertNames() []string { return f.names }

func (f *fakeReconciler) StartCert(_ context.Context, name string) error {
	f.started = append(f.started, name)
	return f.failFor[name]
}

func (f *fakeReconciler) StartAll(ctx context.Context) (accepted, skipped []string, err error) {
	if f.startAllErr != nil {
		return nil, nil, f.startAllErr
	}
	for _, n := range f.names {
		if err := f.StartCert(ctx, n); err != nil {
			skipped = append(skipped, n)
		} else {
			accepted = append(accepted, n)
		}
	}
	return accepted, skipped, nil
}

func newTestServer(t *testing.T, rec Reconciler) (*Server, *state.Store) {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("failed to open the state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := New(rec, store, testToken, context.Background(), log)
	if err != nil {
		t.Fatalf("failed to build the webhook server: %v", err)
	}
	return srv, store
}

func do(t *testing.T, s *Server, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func bearer() map[string]string {
	return map[string]string{"Authorization": "Bearer " + testToken}
}

// ── Authentication ────────────────────────────────────────────────────────────────────

// This endpoint triggers real issuance and burns rate-limit quota; running it
// unauthenticated is unacceptable.
func TestAuthIsRequired(t *testing.T) {
	rec := &fakeReconciler{names: []string{"a"}}
	s, _ := newTestServer(t, rec)

	for _, tc := range []struct {
		name    string
		headers map[string]string
	}{
		{"no headers at all", nil},
		{"empty token", map[string]string{"Authorization": "Bearer "}},
		{"wrong token", map[string]string{"Authorization": "Bearer wrongwrongwrong"}},
		{"correct prefix, wrong value", map[string]string{"Authorization": "Bearer " + testToken[:len(testToken)-1] + "X"}},
		{"wrong X-Wecert-Token", map[string]string{"X-Wecert-Token": "nope"}},
	} {
		w := do(t, s, http.MethodPost, "/hook/reconcile", "", tc.headers)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: should return 401, got %d", tc.name, w.Code)
		}
	}
	if len(rec.started) != 0 {
		t.Errorf("auth failure should trigger nothing, got %v", rec.started)
	}
}

// An empty configured token must be rejected at construction: "Bearer " would
// otherwise compare equal to it.
func TestNewRejectsEmptyToken(t *testing.T) {
	rec := &fakeReconciler{names: []string{"a"}}
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("failed to open the state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := New(rec, store, "", context.Background(), nil); err == nil {
		t.Fatal("New with an empty token should fail")
	}
}

func TestAuthAcceptsBothHeaderForms(t *testing.T) {
	for name, headers := range map[string]map[string]string{
		"Bearer": bearer(),
		"X-Wecert-Token": {
			"X-Wecert-Token": testToken,
		},
	} {
		rec := &fakeReconciler{names: []string{"a"}}
		s, _ := newTestServer(t, rec)

		w := do(t, s, http.MethodPost, "/hook/reconcile", `{"cert":"a"}`, headers)
		if w.Code != http.StatusAccepted {
			t.Errorf("%s: should return 202, got %d", name, w.Code)
		}
	}
}

// Health checks must not require auth, or liveness probes cannot work.
func TestHealthzNeedsNoAuth(t *testing.T) {
	s, _ := newTestServer(t, &fakeReconciler{})

	w := do(t, s, http.MethodGet, "/healthz", "", nil)
	if w.Code != http.StatusOK {
		t.Errorf("healthz should return 200, got %d", w.Code)
	}
}

// ── Rate limiting ────────────────────────────────────────────────────────────────────

// Repeated token failures from one address must end in a lockout, or the
// endpoint can be brute-forced at wire speed.
func TestAuthLockoutAfterFailures(t *testing.T) {
	rec := &fakeReconciler{names: []string{"a"}}
	s, _ := newTestServer(t, rec)

	bad := map[string]string{"Authorization": "Bearer wrong"}
	for i := 0; i < authMaxFailures; i++ {
		w := do(t, s, http.MethodPost, "/hook/reconcile", "", bad)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: should return 401, got %d", i+1, w.Code)
		}
	}

	// Once locked out, even the *correct* token gets a 429: the block is on the
	// address, not on the credentials presented.
	w := do(t, s, http.MethodPost, "/hook/reconcile", `{"cert":"a"}`, bearer())
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("a locked-out address should return 429, got %d", w.Code)
	}
	if ra := w.Header().Get("Retry-After"); ra == "" {
		t.Error("a 429 should carry a Retry-After header")
	}
	if len(rec.started) != 0 {
		t.Errorf("a locked-out address should trigger nothing, got %v", rec.started)
	}
}

// A good token decays the failure counter (see recordSuccess): one success
// after a few failures must keep the address well clear of the lockout.
func TestAuthSuccessForgivesFailures(t *testing.T) {
	rec := &fakeReconciler{names: []string{"a"}}
	s, _ := newTestServer(t, rec)

	bad := map[string]string{"Authorization": "Bearer wrong"}
	for i := 0; i < authMaxFailures-1; i++ {
		do(t, s, http.MethodPost, "/hook/reconcile", "", bad)
	}
	if w := do(t, s, http.MethodPost, "/hook/reconcile", `{"cert":"a"}`, bearer()); w.Code != http.StatusAccepted {
		t.Fatalf("a good token should still work before the limit, got %d", w.Code)
	}

	// Had the earlier failures not been forgiven, this one would hit the limit.
	w := do(t, s, http.MethodPost, "/hook/reconcile", "", bad)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("one failure after a success should be a plain 401, got %d", w.Code)
	}
}

// ── Triggering ────────────────────────────────────────────────────────────────────

func TestTriggerAllWhenBodyEmpty(t *testing.T) {
	rec := &fakeReconciler{names: []string{"a", "b"}}
	s, _ := newTestServer(t, rec)

	w := do(t, s, http.MethodPost, "/hook/reconcile", "", bearer())
	if w.Code != http.StatusAccepted {
		t.Fatalf("should return 202, got %d", w.Code)
	}

	var resp reconcileResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse the response: %v", err)
	}
	if len(resp.Accepted) != 2 {
		t.Errorf("should accept two certificates, got %v", resp.Accepted)
	}
}

func TestTriggerSingleCert(t *testing.T) {
	rec := &fakeReconciler{names: []string{"a", "b", "c"}}
	s, _ := newTestServer(t, rec)

	w := do(t, s, http.MethodPost, "/hook/reconcile", `{"cert":"b"}`, bearer())
	if w.Code != http.StatusAccepted {
		t.Fatalf("should return 202, got %d", w.Code)
	}
	if len(rec.started) != 1 || rec.started[0] != "b" {
		t.Errorf("only b should be triggered, got %v", rec.started)
	}
}

func TestTriggerMultipleCerts(t *testing.T) {
	rec := &fakeReconciler{names: []string{"a", "b", "c"}}
	s, _ := newTestServer(t, rec)

	do(t, s, http.MethodPost, "/hook/reconcile", `{"certs":["a","c"]}`, bearer())

	if len(rec.started) != 2 {
		t.Fatalf("should trigger two, got %v", rec.started)
	}
}

func TestTriggerUnknownCertIsReportedNotFatal(t *testing.T) {
	rec := &fakeReconciler{names: []string{"a"}}
	s, _ := newTestServer(t, rec)

	w := do(t, s, http.MethodPost, "/hook/reconcile", `{"cert":"nope"}`, bearer())
	if w.Code != http.StatusAccepted {
		t.Fatalf("an unknown name should not fail the whole request, got %d", w.Code)
	}

	var resp reconcileResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Unknown) != 1 || resp.Unknown[0] != "nope" {
		t.Errorf("the unknown name should be reported in unknown, got %+v", resp)
	}
}

// A certificate already being processed must be reported as skipped, not
// dishonestly as accepted — the caller uses that to judge whether the trigger
// actually did anything.
func TestTriggerBusyCertIsSkipped(t *testing.T) {
	rec := &fakeReconciler{
		names:   []string{"busy"},
		failFor: map[string]error{"busy": reconcile.ErrAlreadyRunning},
	}
	s, _ := newTestServer(t, rec)

	w := do(t, s, http.MethodPost, "/hook/reconcile", `{"cert":"busy"}`, bearer())

	var resp reconcileResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Skipped) != 1 || resp.Skipped[0] != "busy" {
		t.Errorf("should be reported as skipped, got %+v", resp)
	}
	if len(resp.Accepted) != 0 {
		t.Errorf("should not be reported as accepted, got %+v", resp)
	}
}

func TestTriggerRejectsBothForms(t *testing.T) {
	s, _ := newTestServer(t, &fakeReconciler{names: []string{"a"}})

	w := do(t, s, http.MethodPost, "/hook/reconcile", `{"cert":"a","certs":["a"]}`, bearer())
	if w.Code != http.StatusBadRequest {
		t.Errorf("sending both cert and certs should return 400, got %d", w.Code)
	}
}

func TestTriggerRejectsBadJSON(t *testing.T) {
	s, _ := newTestServer(t, &fakeReconciler{names: []string{"a"}})

	w := do(t, s, http.MethodPost, "/hook/reconcile", `{not json`, bearer())
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad JSON should return 400, got %d", w.Code)
	}
}

// An explicit "certs": [] asks for nothing; silently widening it into a full
// convergence would burn issuance quota the caller never asked for.
func TestTriggerRejectsEmptyCerts(t *testing.T) {
	rec := &fakeReconciler{names: []string{"a"}}
	s, _ := newTestServer(t, rec)

	w := do(t, s, http.MethodPost, "/hook/reconcile", `{"certs":[]}`, bearer())
	if w.Code != http.StatusBadRequest {
		t.Errorf("an explicit empty certs list should return 400, got %d", w.Code)
	}
	if len(rec.started) != 0 {
		t.Errorf("nothing should be triggered, got %v", rec.started)
	}
}

// "certs": null is what a Go caller marshalling a nil []string emits. It names no
// certificates just like an empty list, so it must not be read as an absent body —
// that reading turns a targeted trigger into a full-fleet convergence.
func TestTriggerRejectsNullCerts(t *testing.T) {
	rec := &fakeReconciler{names: []string{"a"}}
	s, _ := newTestServer(t, rec)

	w := do(t, s, http.MethodPost, "/hook/reconcile", `{"certs":null}`, bearer())
	if w.Code != http.StatusBadRequest {
		t.Errorf(`{"certs":null} should return 400, got %d`, w.Code)
	}
	if len(rec.started) != 0 {
		t.Errorf("nothing should be triggered, got %v", rec.started)
	}
}

func TestTriggerRejectsGET(t *testing.T) {
	s, _ := newTestServer(t, &fakeReconciler{names: []string{"a"}})

	w := do(t, s, http.MethodGet, "/hook/reconcile", "", bearer())
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET should return 405, got %d", w.Code)
	}
	if allow := w.Header().Get("Allow"); allow != "POST" {
		t.Errorf("should carry Allow: POST, got %q", allow)
	}
}

// ── Status ────────────────────────────────────────────────────────────────────

func TestStatusReportsCertificates(t *testing.T) {
	rec := &fakeReconciler{names: []string{"cert-a", "cert-b"}}
	s, store := newTestServer(t, rec)

	notAfter := time.Now().Add(60 * 24 * time.Hour).Truncate(time.Second)
	if err := store.PutCert(&state.CertState{
		Name: "cert-a", NotAfter: notAfter,
		DeployedCertID: "ap123", DeployConfirmed: true,
	}); err != nil {
		t.Fatal(err)
	}

	w := do(t, s, http.MethodGet, "/hook/status", "", bearer())
	if w.Code != http.StatusOK {
		t.Fatalf("should return 200, got %d", w.Code)
	}

	var out struct {
		Certificates []certStatus `json:"certificates"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if len(out.Certificates) != 2 {
		t.Fatalf("should return two certificates, got %d", len(out.Certificates))
	}

	a := out.Certificates[0]
	if a.Name != "cert-a" || !a.Uploaded || !a.DeployConfirmed {
		t.Errorf("cert-a state is wrong: %+v", a)
	}
	if a.DaysLeft == nil || *a.DaysLeft < 58 || *a.DaysLeft > 60 {
		t.Errorf("DaysLeft is not plausible: %v", a.DaysLeft)
	}

	// A certificate missing from the state store must still appear, just without
	// timing info.
	if out.Certificates[1].Name != "cert-b" || out.Certificates[1].NotAfter != "" {
		t.Errorf("cert-b should be listed but without notAfter: %+v", out.Certificates[1])
	}
}

func TestStatusRequiresAuth(t *testing.T) {
	s, _ := newTestServer(t, &fakeReconciler{names: []string{"a"}})

	w := do(t, s, http.MethodGet, "/hook/status", "", nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("the status endpoint should require auth too, got %d", w.Code)
	}
}

// ── Outbound notification ────────────────────────────────────────────────────────────────

func TestNotifierPostsEvent(t *testing.T) {
	got := make(chan RenewalEvent, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev RenewalEvent
		_ = json.NewDecoder(r.Body).Decode(&ev)
		got <- ev
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewNotifier(srv.URL, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	n.Renewal(context.Background(), "my-cert", nil)

	select {
	case ev := <-got:
		if ev.Event != "renewal" || ev.Cert != "my-cert" || ev.Result != "ok" {
			t.Errorf("wrong event content: %+v", ev)
		}
		if ev.Timestamp == "" {
			t.Error("the event should carry a timestamp")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no notification received")
	}
}

func TestNotifierReportsErrorResult(t *testing.T) {
	got := make(chan RenewalEvent, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev RenewalEvent
		_ = json.NewDecoder(r.Body).Decode(&ev)
		got <- ev
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewNotifier(srv.URL, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	n.Renewal(context.Background(), "c", errors.New("boom"))

	select {
	case ev := <-got:
		if ev.Result != "error" || !strings.Contains(ev.Error, "boom") {
			t.Errorf("wrong failure event content: %+v", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no notification received")
	}
}

// A dead notification target must not affect convergence: Renewal must return
// immediately (it is asynchronous).
func TestNotifierDoesNotBlockOnDeadEndpoint(t *testing.T) {
	n := NewNotifier("http://127.0.0.1:1/nowhere", "", slog.New(slog.NewTextHandler(io.Discard, nil)))

	start := time.Now()
	n.Renewal(context.Background(), "c", nil)
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("Renewal should return immediately, took %v", elapsed)
	}
}

func TestNewNotifierDisabledWhenURLEmpty(t *testing.T) {
	if n := NewNotifier("", "", slog.New(slog.NewTextHandler(io.Discard, nil))); n != nil {
		t.Error("an empty url should return nil")
	}
}

// When the desired state is unreadable a full trigger starts nothing, so the
// answer must be 503 -- never 202 with every certificate "accepted" (from the
// last good cache) for a convergence that will never happen.
func TestTriggerAllDesiredStateUnavailable(t *testing.T) {
	rec := &fakeReconciler{
		names:       []string{"a", "b"},
		startAllErr: reconcile.ErrDesiredStateUnavailable,
	}
	s, _ := newTestServer(t, rec)

	w := do(t, s, http.MethodPost, "/hook/reconcile", "", bearer())
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("an unreadable desired state should return 503, got %d", w.Code)
	}
	if len(rec.started) != 0 {
		t.Errorf("nothing should be started, got %v", rec.started)
	}
}

// An explicit "cert": "" is indistinguishable from an absent field as a plain
// string and would silently widen into a full trigger -- the same problem as
// "certs": [], so it gets the same answer.
func TestTriggerRejectsEmptyCertString(t *testing.T) {
	rec := &fakeReconciler{names: []string{"a"}}
	s, _ := newTestServer(t, rec)

	w := do(t, s, http.MethodPost, "/hook/reconcile", `{"cert":""}`, bearer())
	if w.Code != http.StatusBadRequest {
		t.Errorf("an explicit empty cert should return 400, got %d", w.Code)
	}
	if len(rec.started) != 0 {
		t.Errorf("nothing should be triggered, got %v", rec.started)
	}
}

// A desired-state read failure behind a single-certificate trigger is a
// transient internal problem, not "not managed": reporting it in unknown tells
// the caller to give up on a certificate that may well exist.
func TestTriggerCertResolveFailureIs503(t *testing.T) {
	rec := &fakeReconciler{
		names:   []string{"a"},
		failFor: map[string]error{"a": reconcile.ErrDesiredStateUnavailable},
	}
	s, _ := newTestServer(t, rec)

	w := do(t, s, http.MethodPost, "/hook/reconcile", `{"cert":"a"}`, bearer())
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("a resolve failure should return 503, got %d", w.Code)
	}
}

// A true not-found still lands in the unknown bucket with a 202 -- that is the
// one case where "we do not manage this name" is the honest answer.
func TestTriggerUnknownCertSentinelIsReportedUnknown(t *testing.T) {
	rec := &fakeReconciler{
		names:   []string{"a"},
		failFor: map[string]error{"a": reconcile.ErrUnknownCert},
	}
	s, _ := newTestServer(t, rec)

	w := do(t, s, http.MethodPost, "/hook/reconcile", `{"cert":"a"}`, bearer())
	if w.Code != http.StatusAccepted {
		t.Fatalf("a genuine not-found should still return 202, got %d", w.Code)
	}

	var resp reconcileResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Unknown) != 1 || resp.Unknown[0] != "a" {
		t.Errorf("the name should be reported in unknown, got %+v", resp)
	}
}

// A duplicated name would otherwise be started twice: the second start reports
// "already running", and one certificate shows up as both accepted and skipped.
func TestTriggerDeduplicatesRepeatedNames(t *testing.T) {
	rec := &fakeReconciler{names: []string{"a", "b"}}
	s, _ := newTestServer(t, rec)

	w := do(t, s, http.MethodPost, "/hook/reconcile", `{"certs":["a","a"]}`, bearer())
	if w.Code != http.StatusAccepted {
		t.Fatalf("should return 202, got %d", w.Code)
	}
	if len(rec.started) != 1 || rec.started[0] != "a" {
		t.Errorf("a should be started exactly once, got %v", rec.started)
	}

	var resp reconcileResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Accepted) != 1 || len(resp.Skipped) != 0 {
		t.Errorf("a should be accepted once and never skipped, got %+v", resp)
	}
}

// An empty certificate list must serialize as [], not null -- clients that
// iterate the field read null as "no answer".
func TestStatusEmptyCertificatesSerializesAsEmptyArray(t *testing.T) {
	s, _ := newTestServer(t, &fakeReconciler{})

	w := do(t, s, http.MethodGet, "/hook/status", "", bearer())
	if w.Code != http.StatusOK {
		t.Fatalf("should return 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"certificates": []`) {
		t.Errorf("an empty list must serialize as [], got %s", w.Body.String())
	}
}

// The notify target is often a public endpoint, so the receiver needs a way to tell a
// genuine renewal event from anything else that can reach its URL. The signature covers
// the raw body, so it must be computed over the bytes actually sent.
func TestNotifierSignsTheBodyWhenASecretIsSet(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"

	body := make(chan []byte, 1)
	sig := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body <- raw
		sig <- r.Header.Get("X-Wecert-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewNotifier(srv.URL, secret, slog.New(slog.NewTextHandler(io.Discard, nil)))
	n.Renewal(context.Background(), "my-cert", nil)

	select {
	case raw := <-body:
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write(raw)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if got := <-sig; got != want {
			t.Errorf("signature mismatch\n got %q\nwant %q", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no notification received")
	}
}

// Without a secret the header must be absent, not an empty or truncated value: a receiver
// that only checks "is the header present" would otherwise accept unsigned traffic.
func TestNotifierOmitsSignatureWithoutASecret(t *testing.T) {
	sig := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sig <- r.Header.Get("X-Wecert-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewNotifier(srv.URL, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	n.Renewal(context.Background(), "my-cert", nil)

	select {
	case got := <-sig:
		if got != "" {
			t.Errorf("no secret means no signature header, got %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no notification received")
	}
}
