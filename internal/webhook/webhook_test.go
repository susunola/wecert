package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/spec"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/reconcile"
	"github.com/susunola/wecert/internal/state"
)

const testToken = "0123456789abcdef0123456789abcdef"

// fakeReconciler records what was triggered and returns preset errors.
type fakeReconciler struct {
	names    []string
	started  []string
	failFor  map[string]error
	resolves int

	// startAllErr simulates "the desired state is unreadable": nothing started.
	startAllErr error

	// fresh is what the reconciler's own resolve finds. When it is set it differs from names,
	// which stands for the cache CertNames() reads -- the situation a named trigger meets when a
	// certificate was onboarded after the last pass.
	fresh []string
}

func (f *fakeReconciler) CertNames() []string { return f.names }

func (f *fakeReconciler) StartCert(_ context.Context, name string) error {
	f.started = append(f.started, name)
	return f.failFor[name]
}

// StartNamed mirrors the real reconciler's batch entry point: resolve once, then start
// each name. The fake counts resolutions so a test can assert the webhook does not pay
// one per name, and it keeps the same error buckets as the real implementation: an
// "already running" or "not managed" answer lands in its bucket, while anything else
// means the desired state could not be read and nothing may be reported as started.
func (f *fakeReconciler) StartNamed(_ context.Context, names []string) (started, running, unknown []string, err error) {
	f.resolves++
	for _, n := range names {
		if !f.known(n) {
			unknown = append(unknown, n)
			continue
		}
		switch e := f.StartCert(context.Background(), n); {
		case e == nil:
			started = append(started, n)
		case errors.Is(e, reconcile.ErrAlreadyRunning):
			running = append(running, n)
		case errors.Is(e, reconcile.ErrUnknownCert):
			unknown = append(unknown, n)
		default:
			return nil, nil, nil, e
		}
	}
	return started, running, unknown, nil
}

func (f *fakeReconciler) known(name string) bool {
	if f.fresh != nil {
		for _, n := range f.fresh {
			if n == name {
				return true
			}
		}
		return false
	}
	for _, n := range f.names {
		if n == name {
			return true
		}
	}
	return false
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

// An explicit "cert": "" (or "cert": null) names no certificate, exactly like an
// empty certs list. It must be rejected rather than read as an absent body.
//
// This is the shape a CI job produces when it templates an unset $CERT into the
// documented `-d '{"cert":"<name>"}'` call, so widening it into a full-fleet
// convergence is not a theoretical concern: it burns issuance quota on every
// certificate the caller never asked about.
func TestTriggerRejectsEmptyCert(t *testing.T) {
	for _, body := range []string{`{"cert":""}`, `{"cert":null}`} {
		t.Run(body, func(t *testing.T) {
			rec := &fakeReconciler{names: []string{"a", "b"}}
			s, _ := newTestServer(t, rec)

			w := do(t, s, http.MethodPost, "/hook/reconcile", body, bearer())
			if w.Code != http.StatusBadRequest {
				t.Errorf("%s should return 400, got %d", body, w.Code)
			}
			if len(rec.started) != 0 {
				t.Errorf("%s triggered %v; it asks for nothing and must not widen to a full convergence",
					body, rec.started)
			}
		})
	}
}

// Control for the two tests above: an absent body still means "everything", so the
// rejection cannot be implemented by simply refusing all empty-looking requests.
func TestTriggerWithNoBodyStillProcessesEverything(t *testing.T) {
	rec := &fakeReconciler{names: []string{"a", "b"}}
	s, _ := newTestServer(t, rec)

	w := do(t, s, http.MethodPost, "/hook/reconcile", "", bearer())
	if w.Code != http.StatusAccepted {
		t.Fatalf("an empty body should be accepted as a full trigger, got %d", w.Code)
	}
	if len(rec.started) != 2 {
		t.Errorf("an empty body should process everything, started=%v", rec.started)
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

// A multi-name trigger must resolve the desired state once, not once per name.
//
// StartCert resolves internally -- a file read, a YAML decode, a full validation and a
// document hash -- and the webhook's loop used to call it per name, synchronously inside
// a request with a 15s write timeout. The full-trigger path already had this fixed.
func TestMultiCertTriggerResolvesTheDesiredStateOnce(t *testing.T) {
	rec := &fakeReconciler{names: []string{"a", "b", "c", "d", "e"}}
	s, _ := newTestServer(t, rec)

	w := do(t, s, http.MethodPost, "/hook/reconcile", `{"certs":["a","b","c","d","e"]}`, bearer())
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", w.Code)
	}
	if rec.resolves != 1 {
		t.Errorf("the desired state was resolved %d times for a 5-name trigger, want 1", rec.resolves)
	}
	if len(rec.started) != 5 {
		t.Errorf("started = %v, want all five", rec.started)
	}
}

// ── /hook/desired ────────────────────────────────────────────────────────────────────
//
// The diagnostic endpoint is the one that answers "why isn't my domain being issued?", and the
// distinction it has to keep is "no desired state has been read" versus "the desired state is
// empty" -- the second would be read as "nothing should be issued".

// desiredReader is a reconciler that also serves the last resolved desired state.
type desiredReader struct {
	*fakeReconciler
	last *spec.Result
}

func (d *desiredReader) LastResult() *spec.Result { return d.last }

func newDesiredServer(t *testing.T, last *spec.Result) *Server {
	t.Helper()
	rec := &desiredReader{fakeReconciler: &fakeReconciler{names: []string{"a"}}, last: last}
	s, _ := newTestServer(t, rec)
	return s
}

// With no desired state ever read, the endpoint must answer 503 with an explanation rather than
// an empty certificate list: an empty list means "nothing should be issued", which is a
// completely different message.
func TestDesiredWithoutAReadStateIs503(t *testing.T) {
	s := newDesiredServer(t, nil)

	w := do(t, s, http.MethodGet, "/hook/desired", "", bearer())
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 when no desired state has been read", w.Code)
	}
	if !strings.Contains(w.Body.String(), "not the same as an empty desired state") {
		t.Errorf("the body must explain the distinction, got: %s", w.Body.String())
	}
}

// The endpoint must be authenticated like the others: it exposes certificate names, domains and
// error text.
func TestDesiredRequiresAuth(t *testing.T) {
	s := newDesiredServer(t, &spec.Result{})

	w := do(t, s, http.MethodGet, "/hook/desired", "", nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 without a token", w.Code)
	}
}

func TestDesiredRejectsNonGET(t *testing.T) {
	s := newDesiredServer(t, &spec.Result{})

	w := do(t, s, http.MethodPost, "/hook/desired", "", bearer())
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
	if allow := w.Header().Get("Allow"); allow != "GET" {
		t.Errorf("Allow = %q, want GET", allow)
	}
}

// The payload must put what is desired next to whether it exists, and mark issued certificates
// with their expiry -- that pairing is what makes the endpoint answer "is my domain live?".
func TestDesiredReportsIssuedStateAndDaysLeft(t *testing.T) {
	last := &spec.Result{
		Revision:    "sha256:abc",
		GeneratedAt: time.Now().Add(-time.Hour),
		Certificates: []config.Certificate{{
			Name: "example-com", Domains: []string{"example.com"}, Profile: "classic",
		}},
		Decisions: []spec.Decision{{Hostname: "example.com", Included: true, Reason: "declared"}},
	}
	s := newDesiredServer(t, last)

	// No certificate row yet: the certificate is desired but not issued.
	w := do(t, s, http.MethodGet, "/hook/desired", "", bearer())
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var view struct {
		Revision     string `json:"revision"`
		Certificates []struct {
			Name     string `json:"name"`
			Issued   bool   `json:"issued"`
			NotAfter string `json:"notAfter"`
			DaysLeft *int   `json:"daysLeft"`
		} `json:"certificates"`
		Decisions []spec.Decision `json:"decisions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view.Revision != "sha256:abc" {
		t.Errorf("revision = %q, want the desired state's", view.Revision)
	}
	if len(view.Certificates) != 1 {
		t.Fatalf("certificates = %+v", view.Certificates)
	}
	if view.Certificates[0].Issued {
		t.Error("no certificate row exists, so issued must be false")
	}
	if view.Certificates[0].DaysLeft != nil {
		t.Error("daysLeft must be absent while nothing is issued")
	}
	if len(view.Decisions) != 1 {
		t.Errorf("decisions must be passed through, got %+v", view.Decisions)
	}
}

// An issued certificate must report its expiry and remaining days, rounded up: a caller that
// treats 0 as expired would read a healthy certificate as down.
func TestDesiredReportsDaysLeftForAnIssuedCertificate(t *testing.T) {
	notAfter := time.Now().Add(36 * time.Hour)
	last := &spec.Result{
		Certificates: []config.Certificate{{Name: "example-com", Domains: []string{"example.com"}}},
	}
	s := newDesiredServer(t, last)

	// Seed a certificate row through the store the server holds.
	store := s.store
	if err := store.PutCert(&state.CertState{Name: "example-com", NotAfter: notAfter}); err != nil {
		t.Fatal(err)
	}

	w := do(t, s, http.MethodGet, "/hook/desired", "", bearer())
	var view struct {
		Certificates []struct {
			Issued   bool   `json:"issued"`
			DaysLeft *int   `json:"daysLeft"`
			NotAfter string `json:"notAfter"`
		} `json:"certificates"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	c := view.Certificates[0]
	if !c.Issued {
		t.Fatal("a certificate row exists, so issued must be true")
	}
	if c.DaysLeft == nil {
		t.Fatal("daysLeft must be present for an issued certificate")
	}
	if *c.DaysLeft < 1 || *c.DaysLeft > 3 {
		t.Errorf("daysLeft = %d for a certificate expiring in 36h; it must round up and not read as 0", *c.DaysLeft)
	}
}

// A frozen desired state must be visible in the payload: it means the source is unreadable and
// nothing new will be picked up, which is exactly what an operator needs to see.
func TestDesiredSurfacesAFrozenState(t *testing.T) {
	last := &spec.Result{
		Revision:     "sha256:abc",
		Frozen:       true,
		FreezeReason: "the document is unreadable",
		Certificates: []config.Certificate{{Name: "example-com", Domains: []string{"example.com"}}},
	}
	s := newDesiredServer(t, last)

	w := do(t, s, http.MethodGet, "/hook/desired", "", bearer())
	var view struct {
		Frozen       bool   `json:"frozen"`
		FreezeReason string `json:"freezeReason"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !view.Frozen || view.FreezeReason == "" {
		t.Errorf("a frozen state must be reported with its reason, got %+v", view)
	}
}

// ── clientIP ─────────────────────────────────────────────────────────────────────────

// The lockout is keyed by client IP, so a RemoteAddr that does not split must fall back to the
// raw value rather than an empty string -- which would put every such caller in one bucket.
func TestClientIPFallsBackToRemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "not-a-host-port"
	if got := clientIP(req); got != "not-a-host-port" {
		t.Errorf("clientIP = %q, want the raw RemoteAddr", got)
	}

	req.RemoteAddr = "192.0.2.7:54321"
	if got := clientIP(req); got != "192.0.2.7" {
		t.Errorf("clientIP = %q, want the host without the port", got)
	}

	// An IPv6 literal must keep its brackets stripped correctly, or the bucket key changes
	// shape and a blocked address can walk back in under the other spelling.
	req.RemoteAddr = "[2001:db8::1]:443"
	if got := clientIP(req); got != "2001:db8::1" {
		t.Errorf("clientIP = %q, want the bare IPv6 address", got)
	}
}

// ── full-trigger accounting ──────────────────────────────────────────────────────────

// The full-trigger response is split by the reconciler itself (accepted vs skipped)
// rather than derived here by subtracting the skipped names from CertNames. Deriving it
// was wrong whenever the two reads disagreed: a certificate could be reported accepted
// even though it was never processed.
func TestFullTriggerReportsWhatTheReconcilerStarted(t *testing.T) {
	rec := &fakeReconciler{names: []string{"a", "b", "c"}}
	srv, _ := newTestServer(t, rec)

	w := do(t, srv, http.MethodPost, "/hook/reconcile", "", bearer())
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", w.Code, w.Body.String())
	}
	var resp reconcileResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Accepted) != 3 {
		t.Errorf("accepted = %v, want all three names", resp.Accepted)
	}
	if len(resp.Skipped) != 0 {
		t.Errorf("skipped = %v, want none", resp.Skipped)
	}

	// The reported set must come from the reconciler's own answer, not from a second
	// look at CertNames: dropping a name from the resolver must drop it from accepted.
	rec.names = []string{"a", "b"}
	w = do(t, srv, http.MethodPost, "/hook/reconcile", "", bearer())
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Accepted) != 2 {
		t.Errorf("accepted = %v, want only the resolver's answer", resp.Accepted)
	}
}

// ── Drain ────────────────────────────────────────────────────────────────────────────

// Drain must wait for a notification that is already in flight.
//
// Delivery is fire-and-forget: Renewal hands the POST to a goroutine and returns. That is
// right while the daemon keeps running, but a one-shot run or a shutdown would otherwise
// exit with the POST in flight and lose it -- including the "result":"error" one, which is
// the notification an operator most needs. Drain is what the daemon calls before returning.
func TestDrainWaitsForAnInFlightNotification(t *testing.T) {
	received := make(chan struct{})
	release := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Block until the test says so: this is the "still in flight" window.
		<-release
		close(received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	n := NewNotifier(srv.URL, "shhh", log)
	if n == nil {
		t.Fatal("NewNotifier returned nil for a configured URL")
	}

	n.Renewal(context.Background(), "example-com", errors.New("issuance failed"))

	drained := make(chan struct{})
	go func() {
		n.Drain(context.Background())
		close(drained)
	}()

	// The send is blocked in the handler, so Drain must still be waiting.
	select {
	case <-drained:
		t.Fatal("Drain returned while a notification was still in flight")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)

	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("Drain did not return after the in-flight notification completed")
	}
	select {
	case <-received:
	default:
		t.Error("the notification was never delivered to the endpoint")
	}
}

// A notification offered after Drain must be refused rather than accepted: nothing is left
// to wait for it, so taking it is the same as dropping it later, only less visibly.
func TestDrainRefusesNewNotifications(t *testing.T) {
	var got int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&got, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	n := NewNotifier(srv.URL, "", log)
	n.Drain(context.Background())

	n.Renewal(context.Background(), "example-com", nil)
	time.Sleep(100 * time.Millisecond)

	if atomic.LoadInt32(&got) != 0 {
		t.Error("a notification accepted after Drain can never be waited for; it must be refused")
	}
}

// A certificate onboarded after the last pass must be STARTED by a named trigger, not reported as
// unknown.
//
// The classification used to run against CertNames(), the cache a pass refreshes, while StartNamed
// resolves the document itself -- so the flow this endpoint exists for (README: CI triggers
// convergence right after a domain is added) put the new name in "unknown" and, because the
// pre-filter had already emptied the target list, handed StartNamed nothing to resolve. The caller
// was told the certificate is not in the configuration, and issuance waited for the next pass.
func TestTriggerStartsACertificateTheCacheHasNotSeen(t *testing.T) {
	rec := &fakeReconciler{names: []string{"a"}, fresh: []string{"a", "new-one"}}
	s, _ := newTestServer(t, rec)

	w := do(t, s, http.MethodPost, "/hook/reconcile", `{"cert":"new-one"}`, bearer())
	if w.Code != http.StatusAccepted {
		t.Fatalf("accepted convergence should answer 202, got %d", w.Code)
	}

	var resp reconcileResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Accepted) != 1 || resp.Accepted[0] != "new-one" {
		t.Errorf("the fresh desired state has this certificate, so it must be started, got %+v", resp)
	}
	if len(resp.Unknown) != 0 {
		t.Errorf("reporting it unknown tells the caller to give up on a certificate that exists: %+v", resp)
	}
}
