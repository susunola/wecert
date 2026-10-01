package webhook

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadRegistryRefusesToWipeCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cloud-accounts.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCloudAccounts(filepath.Join(dir, "state.db")); err == nil {
		t.Fatal("corrupt registry must be an error")
	}
	if _, err := readRegistry[CloudAccount](path); err == nil {
		t.Fatal("corrupt registry must be an error")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "{not json" {
		t.Fatalf("corrupt registry was modified: %q", data)
	}
}

func TestReadRegistryMissingIsEmpty(t *testing.T) {
	list, err := readRegistry[CloudAccount](filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Errorf("want empty, got %d", len(list))
	}
}

func TestWriteRegistryEmitsArrayNotNull(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cloud-accounts.json")
	if err := writeRegistry[CloudAccount](path, nil); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if string(b) != "[]" {
		t.Fatalf("empty registry must marshal as [], got %q", b)
	}
}

func TestConsoleCertificateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state.db")
	want := []ConsoleCertificate{{
		Name: "c", Domains: []string{"a.example.com"}, Profile: "classic",
		KeyType: "ecdsa-p256", UIN: "1000",
		DNS: &DNSCredential{Provider: "cloudflare", Cred: "reused"},
	}}
	if err := WriteConsoleCertificates(state, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadConsoleCertificates(state)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "c" || got[0].DNS.Provider != "cloudflare" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestStatusForErrorSplitsClientAndServer(t *testing.T) {
	if got := statusForError(InvalidRequestf("bad field")); got != http.StatusBadRequest {
		t.Errorf("client error must be 400, got %d", got)
	}
	if got := statusForError(fmt.Errorf("cloud unavailable")); got != http.StatusServiceUnavailable {
		t.Errorf("server error must be 503, got %d", got)
	}
	// wrapped client error still maps to 400
	wrapped := fmt.Errorf("stage: %w", InvalidRequestf("nope"))
	if got := statusForError(wrapped); got != http.StatusBadRequest {
		t.Errorf("wrapped client error must be 400, got %d", got)
	}
}

// The session endpoint is a token oracle; it must consume the same lockout
// budget as /hook/* and /admin/*, or those can be walked around from here.
func TestSessionEndpointCountsFailedGuesses(t *testing.T) {
	s := newTestSessionServer(t)
	for i := 0; i < 12; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/session",
			strings.NewReader(`{"token":"wrong","adminToken":"wrong"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		s.handleSession()(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			if i < 10 {
				t.Fatalf("lockout fired too early at attempt %d", i+1)
			}
			return
		}
	}
	t.Fatal("repeated wrong tokens on /api/session must lock out")
}

// An unconfigured admin surface must not report a match for a missing token:
// ConstantTimeCompare of two empty strings is a match.
func TestEmptyTokensNeverAuthenticate(t *testing.T) {
	s := &Server{now: time.Now, limiter: newAuthLimiter()}
	if s.tokenMatches(httptest.NewRequest(http.MethodGet, "/x", nil)) {
		t.Error("empty read token must not authenticate")
	}
	if s.adminTokenMatches(httptest.NewRequest(http.MethodGet, "/x", nil)) {
		t.Error("empty admin token must not authenticate")
	}
	req := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	rec := httptest.NewRecorder()
	s.handleSession()(rec, req)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["read"] == true || body["admin"] == true {
		t.Errorf("empty-token server must report no credentials, got %v", body)
	}
}

func TestSetTokenRejectsEmpty(t *testing.T) {
	s := &Server{token: "keep-me", now: time.Now, limiter: newAuthLimiter()}
	s.SetToken("")
	if s.token != "keep-me" {
		t.Error("SetToken must refuse to clear the secret")
	}
}

func newTestSessionServer(t *testing.T) *Server {
	t.Helper()
	return &Server{
		token:      "read-token-value",
		adminToken: "admin-token-value-long-enough",
		now:        time.Now,
		limiter:    newAuthLimiter(),
	}
}

// The DNS token already lives in a 0600 file; the registry must not carry a
// second plain-text copy beside the state database.
func TestConsoleRegistryDoesNotStoreTheDNSToken(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state.db")
	dns := &DNSCredential{Provider: "cloudflare", Cred: "token", Token: "super-secret", File: "/etc/wecert/x"}
	rec := ConsoleCertificate{Name: "c", Domains: []string{"a.example.com"}}
	san := dns.Sanitized()
	rec.DNS = &san
	if err := WriteConsoleCertificates(state, [][]ConsoleCertificate{{rec}}[0]); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "console-certificates.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "super-secret") {
		t.Fatalf("registry leaked the DNS token:\n%s", raw)
	}
	if strings.Contains(string(raw), "/etc/wecert/x") {
		t.Fatalf("registry leaked the credential path:\n%s", raw)
	}
	if !strings.Contains(string(raw), "cloudflare") {
		t.Fatalf("registry should keep the provider name:\n%s", raw)
	}
}
