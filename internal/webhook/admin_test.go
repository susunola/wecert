package webhook

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/susunola/wecert/internal/state"
)

const adminTok = "admin-token-min-32-characters-long!!"

func adminServer(t *testing.T, ops AdminOps) *Server {
	t.Helper()
	rec := &fakeReconciler{names: []string{"a"}}
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s, err := NewWithAdmin(rec, store, testToken,
		AdminOptions{Token: adminTok, AuditPath: t.TempDir() + "/audit.jsonl", Ops: ops},
		context.Background(), log)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Read-only token cannot reach /admin; admin token can. Without admin token the
// routes are not mounted at all.
func TestAdminSurfaceRequiresTheAdminToken(t *testing.T) {
	ops := AdminOps{
		BackupHealth: func(context.Context) (any, error) {
			return map[string]any{"ok": true}, nil
		},
	}
	s := adminServer(t, ops)

	// Read-only token is not enough.
	w := do(t, s, http.MethodGet, "/admin/backup-health", "", bearer())
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("read-only token = %d, want 401", w.Code)
	}
	// Admin token works.
	w = do(t, s, http.MethodGet, "/admin/backup-health", "",
		map[string]string{"Authorization": "Bearer " + adminTok})
	if w.Code != http.StatusOK {
		t.Fatalf("admin token = %d body %s", w.Code, w.Body.String())
	}

	// No admin token configured: 404, not 401 (the routes are not there).
	s2, _ := newTestServer(t, &fakeReconciler{names: []string{"a"}})
	if w := do(t, s2, http.MethodGet, "/admin/backup-health", "", map[string]string{"Authorization": "Bearer " + adminTok}); w.Code != http.StatusNotFound {
		t.Errorf("unset admin = %d, want 404", w.Code)
	}
}

// Restore needs a one-shot confirm token from /admin/challenge, bound to one source.
func TestAdminRestoreRequiresAConfirmChallenge(t *testing.T) {
	restored := 0
	s := adminServer(t, AdminOps{
		Restore: func(_ context.Context, src string) (any, error) {
			restored++
			return map[string]any{"source": src}, nil
		},
	})
	auth := map[string]string{"Authorization": "Bearer " + adminTok}

	// No confirm token.
	w := do(t, s, http.MethodPost, "/admin/restore", `{"source":"latest"}`, auth)
	if w.Code != http.StatusForbidden || restored != 0 {
		t.Fatalf("restore without challenge = %d restored=%d", w.Code, restored)
	}

	// Challenge without source is refused: the token is bound to one restore source.
	w = do(t, s, http.MethodPost, "/admin/challenge", `{}`, auth)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("challenge without source = %d, want 400", w.Code)
	}

	// Issue a challenge for "latest", then restore that source.
	w = do(t, s, http.MethodPost, "/admin/challenge", `{"source":"latest"}`, auth)
	if w.Code != http.StatusOK {
		t.Fatalf("challenge = %d %s", w.Code, w.Body.String())
	}
	var ch struct {
		ConfirmToken string `json:"confirmToken"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &ch); err != nil || ch.ConfirmToken == "" {
		t.Fatalf("challenge body %s (%v)", w.Body.String(), err)
	}
	body := `{"source":"latest","confirmToken":"` + ch.ConfirmToken + `"}`
	w = do(t, s, http.MethodPost, "/admin/restore", body, auth)
	if w.Code != http.StatusOK || restored != 1 {
		t.Fatalf("restore = %d restored=%d body %s", w.Code, restored, w.Body.String())
	}

	// The token is one-shot.
	w = do(t, s, http.MethodPost, "/admin/restore", body, auth)
	if w.Code != http.StatusForbidden || restored != 1 {
		t.Fatalf("second restore with the same token = %d restored=%d", w.Code, restored)
	}
}

// A confirm token minted for one source must not restore another.
func TestAdminConfirmTokenIsBoundToItsSource(t *testing.T) {
	restored := 0
	s := adminServer(t, AdminOps{
		Restore: func(_ context.Context, src string) (any, error) {
			restored++
			return map[string]any{"source": src}, nil
		},
	})
	auth := map[string]string{"Authorization": "Bearer " + adminTok}
	w := do(t, s, http.MethodPost, "/admin/challenge", `{"source":"latest"}`, auth)
	if w.Code != http.StatusOK {
		t.Fatalf("challenge = %d %s", w.Code, w.Body.String())
	}
	var ch struct {
		ConfirmToken string `json:"confirmToken"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &ch); err != nil {
		t.Fatal(err)
	}
	// Same token, different source: refused, and the token is already burned.
	w = do(t, s, http.MethodPost, "/admin/restore",
		`{"source":"other.db.backup-20260101T000000.000Z.db","confirmToken":"`+ch.ConfirmToken+`"}`, auth)
	if w.Code != http.StatusForbidden || restored != 0 {
		t.Fatalf("source mismatch = %d restored=%d body %s", w.Code, restored, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "bound to another restore source") {
		t.Errorf("403 must name source_mismatch, got %s", w.Body.String())
	}
	// Even the matching source is now refused (one-shot).
	w = do(t, s, http.MethodPost, "/admin/restore",
		`{"source":"latest","confirmToken":"`+ch.ConfirmToken+`"}`, auth)
	if w.Code != http.StatusForbidden || restored != 0 {
		t.Fatalf("burned token accepted = %d restored=%d", w.Code, restored)
	}
}

// Every admin action is audited (path + action + remote).
func TestAdminActionsAreAudited(t *testing.T) {
	path := t.TempDir() + "/audit.jsonl"
	s := adminServer(t, AdminOps{BackupHealth: func(context.Context) (any, error) { return nil, nil }})
	s.auditPath = path
	auth := map[string]string{"Authorization": "Bearer " + adminTok}
	_ = do(t, s, http.MethodGet, "/admin/backup-health", "", auth)
	_ = do(t, s, http.MethodGet, "/admin/backup-health", "", map[string]string{"Authorization": "Bearer wrong"})
	// wrong auth still audits the failed attempt
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, "admin_backup_health") || !strings.Contains(text, "admin_auth_failed") {
		t.Errorf("audit log must record both outcomes, got:\n%s", text)
	}
	if !strings.Contains(text, `"action":"admin_backup_health"`) {
		t.Error("audit line must carry the action")
	}
}
