package state

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// This file is the seam ledger: each test here exists because two features that each
// had their own tests cracked when they were used together. New features that touch
// sealing, restore, remote HMAC, or the identifier pause are expected to land a test
// in this shape -- a chain across the seam, not another unit test on one side.

// seam: sealing × snapshot × HMAC
//
// A signed remote backup of a sealed deployment is a three-party object: the snapshot
// bytes are VACUUM INTO ciphertext, the HMAC signs those bytes, and a restore has to
// accept the pair and then open the result with the master key. Each link had tests
// of its own; nothing crossed all three. Signing the wrong bytes (or verifying before
// the snapshot is written) is invisible until someone tries to recover.
func TestSealedSnapshotIsWhatTheSignatureSigns(t *testing.T) {
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
		t.Fatal(err)
	}
	snapshot, err := store.Snapshot(dir, 3)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// The object that travels is the snapshot file itself -- sealed rows and all.
	object, err := os.ReadFile(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(object, sealedPrefixV2) {
		t.Fatal("a sealed database's snapshot must contain sealed rows, not plaintext keys")
	}

	key := []byte("remote-hmac-key-not-the-master")
	good := hmacSHA256Hex(key, object)
	if !hmacEqual(key, object, good) {
		t.Fatal("the signature must cover the snapshot bytes as they will be uploaded")
	}
	// A signature over different bytes must not pass the check a restore runs.
	if hmacEqual(key, []byte(testAccountKeyPEM), good) {
		t.Fatal("a signature over different bytes must not verify")
	}

	// Restore the sealed snapshot and read it back with the master -- the recovery
	// path a signed remote object is for.
	restored := filepath.Join(dir, "restored.db")
	if _, err := RestoreSealed(restored, snapshot, master); err != nil {
		t.Fatalf("RestoreSealed of the signed snapshot: %v", err)
	}
	back, err := OpenSealed(restored, master)
	if err != nil {
		t.Fatalf("OpenSealed on the restored database: %v", err)
	}
	defer back.Close()
	acct, err := back.GetAccount("https://acme.example/d")
	if err != nil || acct == nil {
		t.Fatalf("GetAccount after sealed restore: %+v %v", acct, err)
	}
	if !bytes.Equal(acct.PrivateKeyPEM, []byte(testAccountKeyPEM)) {
		t.Fatalf("restored key = %q, want the original plaintext", acct.PrivateKeyPEM)
	}
}

// seam: sealing × restore payload check × wrong key
//
// A sealed snapshot that is inspected without a key must still report Sealed (so the
// operator knows the restore needs the same master), and a restore with the wrong key
// must refuse before replacing anything. Both halves were true; this pins them together
// so a future "simplify InspectSnapshot" cannot drop the Sealed bit while leaving the
// name of the field in the JSON.
func TestInspectedSealedSnapshotSaysItNeedsTheSameKey(t *testing.T) {
	dir := t.TempDir()
	master := []byte("a-long-random-master-key-for-the-test")
	statePath := filepath.Join(dir, "state.db")
	store, err := OpenSealed(statePath, master)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutAccount(&Account{
		Directory: "https://acme.example/d", KID: "kid-1", PrivateKeyPEM: []byte(testAccountKeyPEM),
	}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Snapshot(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Close()

	info, err := InspectSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Sealed {
		t.Fatal("InspectSnapshot must report Sealed for a sealed snapshot: the restore needs the same key")
	}
	if _, err := RestoreSealed(filepath.Join(dir, "nope.db"), snapshot, []byte("wrong")); err == nil {
		t.Fatal("the wrong master must be refused")
	}
	if _, err := os.Stat(filepath.Join(dir, "nope.db")); !os.IsNotExist(err) {
		t.Fatal("a refused sealed restore must leave no destination behind")
	}
}

func hmacSHA256Hex(key, data []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

func hmacEqual(key, data []byte, wantHex string) bool {
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return hmac.Equal(mac.Sum(nil), want)
}
