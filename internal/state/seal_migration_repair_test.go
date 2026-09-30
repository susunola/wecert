package state

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// A row sealed twice -- the shape a buggy migration stored as v2(v1(plain)) --
// must be repaired on open, not skipped forever because the prefix looks current.
func TestMigrationRepairsDoubleSealedRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := OpenSealed(path, []byte("master"))
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("accounts/private_key_pem/https://acme.example/d")
	inner, err := s.sealer.seal([]byte("PRIVATE KEY"), aad)
	if err != nil {
		t.Fatal(err)
	}
	// Two layers: open peels one and hands back another sealed blob.
	double, err := s.sealer.seal(inner, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(double, sealedPrefixV2) {
		t.Fatal("expected a v2-prefixed double-wrapped blob")
	}
	if err := s.PutAccount(&Account{Directory: "https://acme.example/d", KID: "kid", PrivateKeyPEM: []byte("PRIVATE KEY")}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE accounts SET private_key_pem = ? WHERE directory = ?`,
		double, "https://acme.example/d"); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	// Re-open: the migration must detect and repair the double wrap.
	fixed, err := OpenSealed(path, []byte("master"))
	if err != nil {
		t.Fatalf("re-open with a double-sealed row must not fail: %v", err)
	}
	defer fixed.Close()
	account, err := fixed.GetAccount("https://acme.example/d")
	if err != nil {
		t.Fatalf("after repair the account must read: %v", err)
	}
	if string(account.PrivateKeyPEM) != "PRIVATE KEY" {
		t.Fatalf("want PRIVATE KEY, got %q", account.PrivateKeyPEM)
	}
	var blob []byte
	if err := fixed.db.QueryRow(`SELECT private_key_pem FROM accounts WHERE directory = ?`,
		"https://acme.example/d").Scan(&blob); err != nil {
		t.Fatal(err)
	}
	opened, err := fixed.sealer.open(blob, aad)
	if err != nil {
		t.Fatal(err)
	}
	if isSealed(opened) {
		t.Fatal("row is still double-sealed after migration")
	}
}

// A double-wrapped row must fail snapshot payload validation: peeling one layer
// and getting ciphertext back is not proof the material is usable.
func TestCheckSnapshotPayloadRejectsDoubleSealed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := OpenSealed(path, []byte("master"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	aad := []byte("accounts/private_key_pem/https://acme.example/d")
	inner, err := s.sealer.seal([]byte("PRIVATE KEY"), aad)
	if err != nil {
		t.Fatal(err)
	}
	double, err := s.sealer.seal(inner, aad)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutAccount(&Account{Directory: "https://acme.example/d", KID: "kid", PrivateKeyPEM: []byte("PRIVATE KEY")}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE accounts SET private_key_pem = ? WHERE directory = ?`,
		double, "https://acme.example/d"); err != nil {
		t.Fatal(err)
	}
	_, err = checkSnapshotPayload(s.db, path, s.sealer)
	if err == nil {
		t.Fatal("double-sealed payload must fail validation")
	}
	if !strings.Contains(err.Error(), "sealed twice") {
		t.Fatalf("error should name the double seal, got %v", err)
	}
}
