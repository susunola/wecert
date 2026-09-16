package webhook

import (
	"context"
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
}

func (f *fakeReconciler) CertNames() []string { return f.names }

func (f *fakeReconciler) StartCert(_ context.Context, name string) error {
	f.started = append(f.started, name)
	return f.failFor[name]
}

func (f *fakeReconciler) StartAll(_ context.Context) []string {
	var skipped []string
	for _, n := range f.names {
		if err := f.StartCert(context.Background(), n); err != nil {
			skipped = append(skipped, n)
		}
	}
	return skipped
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
	if a.Name != "cert-a" || !a.Deployed || !a.DeployConfirmed {
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

	n := NewNotifier(srv.URL, slog.New(slog.NewTextHandler(io.Discard, nil)))
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

	n := NewNotifier(srv.URL, slog.New(slog.NewTextHandler(io.Discard, nil)))
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
	n := NewNotifier("http://127.0.0.1:1/nowhere", slog.New(slog.NewTextHandler(io.Discard, nil)))

	start := time.Now()
	n.Renewal(context.Background(), "c", nil)
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("Renewal should return immediately, took %v", elapsed)
	}
}

func TestNewNotifierDisabledWhenURLEmpty(t *testing.T) {
	if n := NewNotifier("", slog.New(slog.NewTextHandler(io.Discard, nil))); n != nil {
		t.Error("an empty url should return nil")
	}
}
