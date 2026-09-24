package state

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestSealerBindsCiphertextToItsField(t *testing.T) {
	s, err := newSealer([]byte("master"))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := s.seal([]byte("private-key"), []byte("accounts/key"))
	if err != nil {
		t.Fatal(err)
	}
	if string(ciphertext) == "private-key" {
		t.Fatal("plaintext leaked")
	}
	if _, err := s.open(ciphertext, []byte("orders/key")); err == nil {
		t.Fatal("wrong field must not decrypt")
	}
	plain, err := s.open(ciphertext, []byte("accounts/key"))
	if err != nil || string(plain) != "private-key" {
		t.Fatalf("open = %q, %v", plain, err)
	}
}

// A blob sealed with the v1 (SHA-256) KDF must open under the current sealer and
// migrate to v2. This is the upgrade path for every deployment that already used
// stateEncryption before the Argon2id switch -- without it the comment "v1 still
// decrypts" is a lie and the upgrade bricks the private keys.
func TestSealerOpensV1BlobsAndMigrationReseals(t *testing.T) {
	master := []byte("test-master-key-not-a-password")
	v1sum := sha256.Sum256(master)
	block, err := aes.NewCipher(v1sum[:])
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	// Hand-build a v1 blob the way the old newSealer did.
	plain := []byte("legacy-key-material")
	aad := []byte("accounts/private_key_pem/dir")
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	blob := append(append([]byte{}, sealedPrefixV1...), nonce...)
	blob = aead.Seal(blob, nonce, plain, aad)

	s, err := newSealer(master)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.open(blob, aad)
	if err != nil {
		t.Fatalf("v1 blob must open under the new sealer: %v", err)
	}
	if string(got) != string(plain) {
		t.Fatalf("open = %q, want %q", got, plain)
	}

	// seal() always emits v2; a re-seal of the same plaintext must open too.
	v2, err := s.seal(plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(v2, sealedPrefixV2) {
		t.Error("new writes must carry the v2 prefix")
	}
	got2, err := s.open(v2, aad)
	if err != nil || string(got2) != string(plain) {
		t.Fatalf("v2 round-trip: %q %v", got2, err)
	}
}

// Wrong master must fail to open, for both versions.
func TestSealerRejectsWrongMaster(t *testing.T) {
	s1, _ := newSealer([]byte("master-one"))
	s2, _ := newSealer([]byte("master-two"))
	aad := []byte("x")
	blob, err := s1.seal([]byte("secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.open(blob, aad); err == nil {
		t.Fatal("wrong master must not decrypt")
	}
}

// migrateSealedMaterial must OPEN a v1 blob and re-seal the plaintext. Sealing
// the ciphertext instead stores v2(v1(plain)), and the next open peels only v2 --
// handing the caller a second AEAD blob instead of the key. Self-seal/self-open
// unit tests cannot see that brick; this one puts a real v1 row in the database.
func TestMigrateSealedMaterialOpensV1ThenReseals(t *testing.T) {
	master := []byte("migration-master-key-not-a-password")
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	// Build the store unsealed first so we can plant a v1 row the way an old
	// binary would have written it.
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(
		`INSERT INTO accounts (directory, kid, private_key_pem, updated_at) VALUES (?, ?, ?, ?)`,
		"dir", "kid-dir", []byte("plaintext-key-material"), time.Now().Unix(),
	); err != nil {
		_ = st.Close()
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// Hand-build a v1 blob for that row.
	v1sum := sha256.Sum256(master)
	block, err := aes.NewCipher(v1sum[:])
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("legacy-private-key-pem")
	aad := []byte("accounts/private_key_pem/dir")
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	blob := append(append([]byte{}, sealedPrefixV1...), nonce...)
	blob = aead.Seal(blob, nonce, plain, aad)

	// Rewrite the row as a v1-sealed blob, then open sealed (which migrates).
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE accounts SET private_key_pem = ? WHERE directory = ?`, blob, "dir"); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	_ = db.Close()

	st2, err := OpenSealed(path, master)
	if err != nil {
		t.Fatalf("OpenSealed on a v1 row must succeed: %v", err)
	}
	defer st2.Close()

	// The row must now be v2, and open() must yield the ORIGINAL plaintext --
	// not v1 ciphertext, which is what sealing the blob without opening it stored.
	var got []byte
	if err := st2.db.QueryRow(`SELECT private_key_pem FROM accounts WHERE directory = ?`, "dir").Scan(&got); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(got, sealedPrefixV2) {
		t.Fatalf("migration must emit a v2 blob, got prefix %q", got[:min(16, len(got))])
	}
	if bytes.HasPrefix(got, sealedPrefixV1) {
		t.Fatal("v1 prefix must be gone after migration")
	}
	opened, err := st2.sealer.open(got, aad)
	if err != nil {
		t.Fatalf("migrated blob must open: %v", err)
	}
	if string(opened) != string(plain) {
		t.Fatalf("migrated open = %q, want the v1 plaintext %q (double-seal would yield the v1 ciphertext)", opened, plain)
	}

	// And the store's own account read path must see the same plaintext.
	acct, err := st2.GetAccount("dir")
	if err != nil {
		t.Fatalf("GetAccount after migration: %v", err)
	}
	if acct == nil {
		t.Fatal("GetAccount after migration: row disappeared")
	}
	if string(acct.PrivateKeyPEM) != string(plain) {
		t.Fatalf("GetAccount = %q, want %q", acct.PrivateKeyPEM, plain)
	}
}
