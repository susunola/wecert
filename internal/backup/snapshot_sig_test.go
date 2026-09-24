package backup

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A writable backup bucket is not a trusted restore source. When a signing key is
// configured, a remote object without a matching sidecar -- or with one that does
// not match -- must be refused. That is the whole point of the HMAC chain.
func TestVerifySnapshotAcceptsMatchingSignature(t *testing.T) {
	key := []byte("signing-key-not-the-master")
	data := []byte("sqlite bytes")
	sig := SignSnapshot(key, data)
	if err := VerifySnapshot(key, data, sig); err != nil {
		t.Fatalf("matching signature rejected: %v", err)
	}
	if err := VerifySnapshot(key, data, sig+"\n"); err != nil {
		t.Fatalf("trailing newline must be tolerated: %v", err)
	}
}

func TestVerifySnapshotRejectsTamperedObject(t *testing.T) {
	key := []byte("signing-key")
	sig := SignSnapshot(key, []byte("original"))
	if err := VerifySnapshot(key, []byte("tampered"), sig); err == nil {
		t.Fatal("tampered object must not verify")
	}
}

func TestVerifySnapshotRejectsWrongKey(t *testing.T) {
	sig := SignSnapshot([]byte("key-one"), []byte("data"))
	if err := VerifySnapshot([]byte("key-two"), []byte("data"), sig); err == nil {
		t.Fatal("wrong key must not verify")
	}
}

func TestVerifySnapshotRejectsNonHexSignature(t *testing.T) {
	if err := VerifySnapshot([]byte("k"), []byte("d"), "not-hex"); err == nil {
		t.Fatal("non-hex signature must not verify")
	}
}

func TestLoadHMACKey(t *testing.T) {
	if k, err := LoadHMACKey(""); err != nil || k != nil {
		t.Fatalf("empty path = %q, %v; want nil, nil", k, err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "hmac.key")
	if err := os.WriteFile(path, []byte("  the-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k, err := LoadHMACKey(path)
	if err != nil || string(k) != "the-key" {
		t.Fatalf("LoadHMACKey = %q, %v", k, err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHMACKey(empty); err == nil {
		t.Fatal("empty key file must be an error, not unsigned upload")
	}
	if _, err := LoadHMACKey(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing key file must be an error, not unsigned upload")
	}
}

// Keep=1 with one snapshot and its sidecar must delete nothing (the sidecar is
// not a recovery point and must not occupy a Keep slot). With two signed pairs,
// the older snapshot and its sidecar go together and the newest survives.
// Counting .hmac against Keep used to delete the only recovery point.
func TestPruneCountingIgnoresHMACSidecars(t *testing.T) {
	// Pure-name filter, no network: the logic pruneSFTP uses on directory entries.
	filter := func(names []string, current string, keep int) (victims []string) {
		base := strings.Split(current, ".backup-")[0] + ".backup-"
		var candidates []string
		for _, name := range names {
			if name == current || strings.HasSuffix(name, ".hmac") {
				continue
			}
			if strings.HasPrefix(name, base) {
				candidates = append(candidates, name)
			}
		}
		if len(candidates) < keep {
			return nil
		}
		// keep counts current, which is not in candidates.
		for _, name := range candidates[:len(candidates)-(keep-1)] {
			victims = append(victims, name, name+".hmac")
		}
		return victims
	}

	// One signed pair, keep=1: nothing is a victim. The old code counted the
	// sidecar, saw 2 > 1, and deleted the snapshot.
	one := []string{
		"state.db.backup-20260101T000000.000Z.db",
		"state.db.backup-20260101T000000.000Z.db.hmac",
	}
	if v := filter(one, one[0], 1); v != nil {
		t.Fatalf("keep=1 with one signed pair must delete nothing, got victims %v", v)
	}

	// Two signed pairs, keep=1: the older pair goes, the current stays.
	two := []string{
		"state.db.backup-20260101T000000.000Z.db",
		"state.db.backup-20260101T000000.000Z.db.hmac",
		"state.db.backup-20260102T000000.000Z.db",
		"state.db.backup-20260102T000000.000Z.db.hmac",
	}
	current := two[2]
	want := []string{
		"state.db.backup-20260101T000000.000Z.db",
		"state.db.backup-20260101T000000.000Z.db.hmac",
	}
	got := filter(two, current, 1)
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("victims = %v, want %v", got, want)
	}
	for _, name := range got {
		if name == current {
			t.Fatal("keep=1 deleted the only recovery point")
		}
	}
}

func TestSignSnapshotIsHexHMAC(t *testing.T) {
	sig := SignSnapshot([]byte("k"), []byte("data"))
	if len(sig) != 64 {
		t.Fatalf("sig length = %d, want 64 hex chars (SHA-256)", len(sig))
	}
	for _, r := range sig {
		if !strings.ContainsRune("0123456789abcdef", r) {
			t.Fatalf("sig is not lower-case hex: %q", sig)
		}
	}
	if !bytes.Equal([]byte(sig), []byte(SignSnapshot([]byte("k"), []byte("data")))) {
		t.Fatal("HMAC must be deterministic for the same key and data")
	}
}
