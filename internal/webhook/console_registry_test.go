package webhook

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
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
