package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A hand copy that takes only state.db is already caught by the generation sidecar.
// The remaining silent path is a copy that takes the sidecar along (file and database
// agree), or a copy onto a machine that has no sidecar at all. install-id is a host
// file that a `state.db*` glob does not match; when the database's install_id does not
// match this host's file, the next start says so before it trusts the ledger.
func TestCopiedDatabaseWithoutItsInstallIDIsCalledOut(t *testing.T) {
	srcDir := t.TempDir()
	src, err := Open(filepath.Join(srcDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := src.Close(); err != nil {
		t.Fatal(err)
	}
	srcDB := filepath.Join(srcDir, "state.db")
	srcGen := srcDB + generationSuffix
	if _, err := os.Stat(installIDPath(srcDB)); err != nil {
		t.Fatalf("a first open must mint install-id: %v", err)
	}

	// The usual "back up the database" copy: state.db and its generation sidecar,
	// nothing else. On a fresh directory that pair is self-consistent -- the sidecar
	// check stays quiet -- and the install-id hole is what has to speak.
	dstDir := t.TempDir()
	dstDB := filepath.Join(dstDir, "state.db")
	copyFileForTest(t, srcDB, dstDB)
	copyFileForTest(t, srcGen, dstDB+generationSuffix)

	out := captureStderr(t, func() {
		s, err := Open(dstDB)
		if err != nil {
			t.Fatal(err)
		}
		_ = s.Close()
	})
	if !strings.Contains(out, "install-id") || !strings.Contains(out, "copied") {
		t.Fatalf("a database+sidecar copy onto a host with no install-id must be called out, got:\n%s", out)
	}
	// After the warning the host adopts a fresh identity, so a *second* ordinary
	// restart of this copy is quiet -- the alarm is about the arrival, not forever.
	out = captureStderr(t, func() {
		s, err := Open(dstDB)
		if err != nil {
			t.Fatal(err)
		}
		_ = s.Close()
	})
	if strings.Contains(out, "install-id") {
		t.Fatalf("a second start of the same copy must be quiet, got:\n%s", out)
	}
}

// Two installations' states pasted over each other keep two different install-ids.
// The host file wins as the truth and the database is stamped to match.
func TestDatabaseFromAnotherInstallationIsCalledOut(t *testing.T) {
	a := t.TempDir()
	b := t.TempDir()
	for _, dir := range []string{a, b} {
		s, err := Open(filepath.Join(dir, "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		_ = s.Close()
	}

	// Copy A's database over B's, leaving B's install-id file in place.
	copyFileForTest(t, filepath.Join(a, "state.db"), filepath.Join(b, "state.db"))
	copyFileForTest(t, filepath.Join(a, "state.db")+generationSuffix,
		filepath.Join(b, "state.db")+generationSuffix)

	out := captureStderr(t, func() {
		s, err := Open(filepath.Join(b, "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		dbID, err := s.readInstallID()
		if err != nil {
			t.Fatal(err)
		}
		hostID, err := loadInstallIDFile(installIDPath(filepath.Join(b, "state.db")))
		if err != nil {
			t.Fatal(err)
		}
		if dbID != hostID {
			t.Fatalf("after the warning the host file must win: db=%q host=%q", dbID, hostID)
		}
	})
	if !strings.Contains(out, "install id") && !strings.Contains(out, "install-id") {
		t.Fatalf("a database from another installation must be called out, got:\n%s", out)
	}
}

// A supported wecert -restore leaves its marker and adopts the host identity, so a
// legitimate restore is not a false alarm -- the same contract the generation sidecar
// has.
func TestSupportedRestoreAdoptsTheHostIdentityWithoutAlarming(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	s, err := OpenSealed(filepath.Join(src, "state.db"), []byte("a-long-random-master-key-for-the-test"))
	if err != nil {
		// Unsealed is enough for this seam.
		s, err = Open(filepath.Join(src, "state.db"))
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := s.PutAccount(&Account{
		Directory: "https://acme.example/d", KID: "kid", PrivateKeyPEM: testAccountKeyPEM,
	}); err != nil {
		t.Fatal(err)
	}
	snap, err := s.Snapshot(src, 3)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	dstDB := filepath.Join(dst, "state.db")
	// Host already has an identity (it ran once).
	host, err := Open(dstDB)
	if err != nil {
		t.Fatal(err)
	}
	_ = host.Close()

	out := captureStderr(t, func() {
		if _, err := Restore(dstDB, snap); err != nil {
			t.Fatal(err)
		}
		s2, err := Open(dstDB)
		if err != nil {
			t.Fatal(err)
		}
		defer s2.Close()
		dbID, _ := s2.readInstallID()
		hostID, _ := loadInstallIDFile(installIDPath(dstDB))
		if dbID != hostID || dbID == "" {
			t.Fatalf("a supported restore must adopt the host identity: db=%q host=%q", dbID, hostID)
		}
	})
	if strings.Contains(out, "install") {
		t.Fatalf("wecert -restore must not alarm about install-id, got:\n%s", out)
	}
}

func copyFileForTest(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
