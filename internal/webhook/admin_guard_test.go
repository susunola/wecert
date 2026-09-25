package webhook

// The guarded /admin surface holds a second secret with a different blast radius from the
// read-only hook token: it can replace state.db. These tests pin the guard itself rather than
// the operations behind it -- who is let in, what a surface with no token answers, and what a
// locked-out address does to the legitimate caller that shares it.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
)

// adminReq builds a request to drive the handler a test holds directly, which is what a
// running process holds for its whole life.
func adminReq(method, path string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// TestAdminSurfaceClosesWhenTheTokenIsRotatedToEmpty pins what happens to the handlers a
// running process has already registered when SIGHUP removes webhook.adminToken.
//
// The mux is built once, at construction, and SetAdminToken only rotates the secret: the
// listener keeps the /admin routes for the rest of its life. So the guard has to refuse them
// itself, and the refusal must look exactly like the answer a process that never had an admin
// surface gives -- a deployment that removes the admin token must not keep answering
// /admin/restore just because it started with one, and the 404 must not reveal that the route
// exists but is disabled.
func TestAdminSurfaceClosesWhenTheTokenIsRotatedToEmpty(t *testing.T) {
	t.Parallel()
	s := adminServer(t, AdminOps{
		BackupHealth: func(context.Context) (any, error) { return map[string]any{"ok": true}, nil },
	})
	auth := map[string]string{"Authorization": "Bearer " + adminTok}

	// The handler the listener holds. It is deliberately NOT rebuilt between the two calls:
	// rebuilding it would re-run the mount check and hide the case this test is about.
	h := s.Handler()

	w := httptest.NewRecorder()
	h.ServeHTTP(w, adminReq(http.MethodGet, "/admin/backup-health", auth))
	if w.Code != http.StatusOK {
		t.Fatalf("admin surface while its token is set = %d, want 200 (body %s)", w.Code, w.Body.String())
	}

	s.SetAdminToken("")

	w = httptest.NewRecorder()
	h.ServeHTTP(w, adminReq(http.MethodGet, "/admin/backup-health", auth))
	if w.Code != http.StatusNotFound {
		t.Fatalf("after the admin token was cleared = %d, want 404 (body %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "admin surface is not configured") {
		t.Errorf("the refusal must say the surface is not configured, got %s", w.Body.String())
	}

	// A request to a surface that is not configured is not a failed authentication: nothing
	// was guessed, so the audit trail (and the per-address lockout budget) must stay clean.
	b, err := os.ReadFile(s.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "admin_auth_failed") {
		t.Errorf("a disabled surface must not be recorded as a failed authentication:\n%s", b)
	}
}

// TestAdminTokenIsAcceptedFromTheDedicatedHeader covers the second way the admin secret may be
// presented. It exists so a client that already spends Authorization on something else (an
// internal proxy, a Basic-auth sidecar) can still reach the admin surface; the guard therefore
// has to read it, and it must not be shadowed by an Authorization header it cannot use.
func TestAdminTokenIsAcceptedFromTheDedicatedHeader(t *testing.T) {
	t.Parallel()
	s := adminServer(t, AdminOps{
		BackupHealth: func(context.Context) (any, error) { return map[string]any{"ok": true}, nil },
	})

	if w := do(t, s, http.MethodGet, "/admin/backup-health", "",
		map[string]string{"X-Wecert-Admin-Token": adminTok}); w.Code != http.StatusOK {
		t.Fatalf("dedicated header = %d, want 200 (body %s)", w.Code, w.Body.String())
	}

	// A wrong value in it is refused exactly like a wrong bearer token.
	if w := do(t, s, http.MethodGet, "/admin/backup-health", "",
		map[string]string{"X-Wecert-Admin-Token": adminTok + "x"}); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong dedicated header = %d, want 401", w.Code)
	}

	// An Authorization header carrying a scheme this guard does not understand must not
	// shadow the dedicated one: the request carries the right secret, in the right place.
	if w := do(t, s, http.MethodGet, "/admin/backup-health", "", map[string]string{
		"Authorization":        "Basic dXNlcjpwYXNz",
		"X-Wecert-Admin-Token": adminTok,
	}); w.Code != http.StatusOK {
		t.Fatalf("dedicated header behind an unrelated Authorization scheme = %d, want 200", w.Code)
	}

	// The refused attempt is on the record with the path it was aimed at.
	b, err := os.ReadFile(s.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, `"action":"admin_auth_failed"`) {
		t.Errorf("a refused authentication must be audited:\n%s", text)
	}
	if !strings.Contains(text, `"path":"/admin/backup-health"`) {
		t.Errorf("the audit line must carry the targeted path:\n%s", text)
	}
}

// TestAdminLockoutStillAnswersTheCorrectToken pins the ordering the admin guard shares with
// /hook/*: the token is compared first, and only a failed comparison spends the address's
// budget.
//
// The documented deployment puts a TLS terminator in front of this listener, so every client
// collapses onto one address. If the lockout were consulted first, one misconfigured CI job --
// or one attacker -- would take the admin surface away from the operator for the whole block
// window, which is the failure mode this ordering exists to prevent.
func TestAdminLockoutStillAnswersTheCorrectToken(t *testing.T) {
	t.Parallel()
	s := adminServer(t, AdminOps{
		BackupHealth: func(context.Context) (any, error) { return map[string]any{"ok": true}, nil },
	})
	wrong := map[string]string{"Authorization": "Bearer wrong"}

	// Every failure inside the budget is still answered as a failed authentication.
	for i := 0; i < authMaxFailures; i++ {
		if w := do(t, s, http.MethodGet, "/admin/backup-health", "", wrong); w.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d of %d = %d, want 401", i+1, authMaxFailures, w.Code)
		}
	}

	// The next one finds the address blocked, and says for how long.
	w := do(t, s, http.MethodGet, "/admin/backup-health", "", wrong)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("after %d failures = %d, want 429", authMaxFailures, w.Code)
	}
	retryAfter, err := strconv.Atoi(w.Header().Get("Retry-After"))
	if err != nil || retryAfter <= 0 {
		t.Errorf("Retry-After = %q, want a positive number of seconds", w.Header().Get("Retry-After"))
	}

	// The legitimate caller sharing that address is still answered.
	if w := do(t, s, http.MethodGet, "/admin/backup-health", "",
		map[string]string{"Authorization": "Bearer " + adminTok}); w.Code != http.StatusOK {
		t.Fatalf("correct token under lockout = %d, want 200 (body %s)", w.Code, w.Body.String())
	}

	// Answering the good token does not hand the address back to the attacker: the block
	// outlives the success that decayed the failure count.
	if w := do(t, s, http.MethodGet, "/admin/backup-health", "", wrong); w.Code != http.StatusTooManyRequests {
		t.Errorf("a wrong token after a good one = %d, want it still blocked", w.Code)
	}

	// The block itself is audited: the journal is the only place an operator can see that
	// the admin surface was under a guessing attempt.
	b, err := os.ReadFile(s.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"action":"admin_auth_blocked"`) {
		t.Errorf("engaging the lockout must be audited:\n%s", b)
	}
}
