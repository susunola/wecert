package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A snapshot of a sealed database is a valid recovery point, and saying so is the whole point of the
// payload check.
//
// checkSnapshotPayload decodes PEM to prove a snapshot's material is readable rather than merely
// well-framed. Sealing arrived later and stores ciphertext there, so every snapshot a sealed
// deployment wrote was rejected -- by -restore, by the admin recovery endpoints and by backup-drill
// -- with "its payload is damaged ... use an older snapshot", which fails identically. The upload
// side kept working, so the first sign of trouble would have been an operator trying to recover.
//
// This is the cross-feature chain the two halves never had: seal, snapshot, inspect, restore, and
// read the restored database back with the same key.
func TestASealedSnapshotInspectsAndRestores(t *testing.T) {
	dir := t.TempDir()
	master := []byte("a-long-random-master-key-for-the-test")
	statePath := filepath.Join(dir, "state.db")

	store, err := OpenSealed(statePath, master)
	if err != nil {
		t.Fatalf("OpenSealed: %v", err)
	}
	if err := store.PutAccount(&Account{
		Directory: "https://acme.example/d", KID: "kid-1", PrivateKeyPEM: []byte(testAccountKeyPEM),
	}); err != nil {
		t.Fatalf("PutAccount: %v", err)
	}
	if err := store.PutCert(&CertState{
		Name: "example-com", NotAfter: time.Now().Add(60 * 24 * time.Hour),
		CertPEM: []byte("-----BEGIN CERTIFICATE-----\nBAUG\n-----END CERTIFICATE-----\n"),
		KeyPEM:  testCertKeyPEM,
	}); err != nil {
		t.Fatalf("PutCert: %v", err)
	}
	snapshot, err := store.Snapshot(dir, 3)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	info, err := InspectSnapshot(snapshot)
	if err != nil {
		t.Fatalf("a sealed snapshot must inspect cleanly: %v\nSealing and the restore payload check "+
			"were added independently; treating ciphertext as damaged PEM rejects every snapshot this "+
			"deployment writes.", err)
	}
	if info.Certificates != 1 || !info.Account {
		t.Errorf("info = %+v, want one certificate and an account", info)
	}
	if !info.Sealed {
		t.Error("info.Sealed = false for a snapshot of a sealed database: the operator has to be told " +
			"the restored deployment needs the same key")
	}

	// Restore it somewhere else and open it the way the daemon would.
	restored := filepath.Join(dir, "restored.db")
	if _, err := Restore(restored, snapshot); err != nil {
		t.Fatalf("Restore of a sealed snapshot: %v", err)
	}
	back, err := OpenSealed(restored, master)
	if err != nil {
		t.Fatalf("OpenSealed on the restored database: %v", err)
	}
	defer back.Close()
	cert, err := back.GetCert("example-com")
	if err != nil || cert == nil {
		t.Fatalf("GetCert after the restore: %v, %+v", err, cert)
	}
	if string(cert.KeyPEM) != string(testCertKeyPEM) {
		t.Errorf("certificate key did not survive the sealed round trip: %q", cert.KeyPEM)
	}
	acct, err := back.GetAccount("https://acme.example/d")
	if err != nil || acct == nil {
		t.Fatalf("GetAccount after the restore: %v, %+v", err, acct)
	}
	if string(acct.PrivateKeyPEM) != string(testAccountKeyPEM) {
		t.Errorf("account key did not survive the sealed round trip: %q", acct.PrivateKeyPEM)
	}

	// A plaintext snapshot stays valid, and must not be reported as sealed.
	plainPath := filepath.Join(dir, "plain.db")
	plain, err := Open(plainPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.PutCert(&CertState{Name: "plain-com", NotAfter: time.Now().Add(time.Hour), KeyPEM: testCertKeyPEM}); err != nil {
		t.Fatal(err)
	}
	plainSnapshot, err := plain.Snapshot(dir, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.Close(); err != nil {
		t.Fatal(err)
	}
	plainInfo, err := InspectSnapshot(plainSnapshot)
	if err != nil {
		t.Fatalf("a plaintext snapshot must inspect cleanly: %v", err)
	}
	if plainInfo.Sealed {
		t.Error("a plaintext snapshot must not be reported as sealed")
	}

	// And genuinely damaged material is still refused: this is a check, not a formality.
	damaged := filepath.Join(dir, "damaged.db")
	raw, err := os.ReadFile(plainSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(damaged, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	store2, err := Open(damaged)
	if err != nil {
		t.Fatalf("open the copy: %v", err)
	}
	if err := store2.PutCert(&CertState{Name: "broken", NotAfter: time.Now().Add(time.Hour), KeyPEM: []byte("not key material at all")}); err != nil {
		t.Fatal(err)
	}
	if err := store2.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectSnapshot(damaged); err == nil {
		t.Error("a database whose key material is neither PEM nor sealed must still be refused")
	}
}
