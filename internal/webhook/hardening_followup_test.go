package webhook

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/state"
)

func hardenTestServer(t *testing.T, ops AdminOps) *Server {
	t.Helper()
	rec := &fakeReconciler{names: []string{"a"}}
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	s, err := NewWithAdmin(rec, store, testToken,
		AdminOptions{Token: adminTok, Ops: ops},
		context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPagerDutyResolvesOnSuccess(t *testing.T) {
	n := formatNotifier(config.NotifyFormatPagerDuty, "R0-key")
	b, err := n.pagerdutyPayload(RenewalEvent{Cert: "www", Result: "ok"})
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatal(err)
	}
	if env["event_action"] != "resolve" || env["dedup_key"] != "wecert/www" {
		t.Fatalf("success must resolve the incident, got %s", b)
	}
}

func TestAdminAuthIsRateLimited(t *testing.T) {
	s := hardenTestServer(t, AdminOps{})
	var last int
	for i := 0; i < authMaxFailures+2; i++ {
		w := do(t, s, http.MethodGet, "/admin/backup-health", "",
			map[string]string{"Authorization": "Bearer wrong"})
		last = w.Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("admin auth must lock out like /hook, last=%d", last)
	}
}

func TestSetAdminTokenRotates(t *testing.T) {
	s := hardenTestServer(t, AdminOps{
		BackupHealth: func(context.Context) (any, error) { return map[string]any{"ok": true}, nil },
	})
	const rotated = "rotated-admin-token-32-characters-long!"
	s.SetAdminToken(rotated)
	if w := do(t, s, http.MethodGet, "/admin/backup-health", "",
		map[string]string{"Authorization": "Bearer " + adminTok}); w.Code != http.StatusUnauthorized {
		t.Fatalf("old token still accepted: %d", w.Code)
	}
	if w := do(t, s, http.MethodGet, "/admin/backup-health", "",
		map[string]string{"Authorization": "Bearer " + rotated}); w.Code != http.StatusOK {
		t.Fatalf("new token rejected: %d %s", w.Code, w.Body.String())
	}
}

func TestRedactSecretsStripsURLCredentials(t *testing.T) {
	got := redactSecrets("boom https://user:pass@host.example/path?token=abc")
	if strings.Contains(got, "pass") || strings.Contains(got, "token=abc") {
		t.Errorf("secret-bearing URL must be redacted, got %q", got)
	}
}

func TestRedactSecretsStripsBearerAKIDAndPEM(t *testing.T) {
	got := redactSecrets("auth Bearer AbcDef1234567890 key AKIA0123456789ABCDEF " +
		"block -----BEGIN PRIVATE KEY-----\nMII...\n-----END PRIVATE KEY----- token=supersecret99")
	for _, leak := range []string{"AbcDef1234567890", "AKIA0123456789ABCDEF", "MII...", "supersecret99"} {
		if strings.Contains(got, leak) {
			t.Errorf("redactSecrets leaked %q in %q", leak, got)
		}
	}
	if !strings.Contains(got, "Bearer") {
		t.Errorf("the scheme should stay so the operator sees a token was there, got %q", got)
	}
}
