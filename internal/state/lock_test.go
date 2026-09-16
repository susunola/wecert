//go:build unix

package state

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMain doubles as the entry point for the "crashing child process".
//
// What is verified here is the single most important property flock has over a PID
// file: the kernel releases the lock automatically when the process dies. That cannot
// be tested inside this process -- it takes a child process that grabs the lock and
// then calls os.Exit directly, without Close.
func TestMain(m *testing.M) {
	if os.Getenv("WECERT_LOCK_HELPER") == "1" {
		s, err := Open(os.Getenv("WECERT_LOCK_PATH"))
		if err != nil {
			os.Stderr.WriteString("helper: " + err.Error() + "\n")
			os.Exit(3)
		}
		_ = s // deliberately no Close: simulating kill -9
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func lockTestPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "state.db")
}

// Why this gate exists: with daemon and timer both enabled, each process holds its own
// local view of "at most one in-flight order per certificate", so they order
// concurrently -- and what they hit is the exact-set limit, unrecoverable for 7 days.
func TestOpenTakesAnExclusiveLock(t *testing.T) {
	path := lockTestPath(t)

	first, err := Open(path)
	if err != nil {
		t.Fatalf("first open failed: %v", err)
	}
	defer first.Close()

	_, err = Open(path)
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("second open should get ErrLocked, got: %v", err)
	}
	// The error must make clear which file is taken, otherwise diagnosing multiple
	// instances is painful.
	if !strings.Contains(err.Error(), "state.db.lock") {
		t.Errorf("error should carry the lock file path, got: %v", err)
	}
}

func TestCloseReleasesTheLock(t *testing.T) {
	path := lockTestPath(t)

	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := Open(path)
	if err != nil {
		t.Fatalf("should reopen after release, got: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

// The unlocked path must work while the daemon is running.
//
// The tools that use it are not read-only -- `-revoke` records a revocation request, `-dry-run`
// registers the ACME account on a first run -- so what makes skipping the lock safe is that none of
// those writes need serialising against a pass. What does NOT belong on this path is the migration,
// and that is what the test below this one pins.
func TestOpenUnlockedIgnoresTheLock(t *testing.T) {
	path := lockTestPath(t)

	held, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	unlocked, err := OpenUnlocked(path)
	if err != nil {
		t.Fatalf("the unlocked path should not be blocked, got: %v", err)
	}
	if err := unlocked.Close(); err != nil {
		t.Fatal(err)
	}

	// And it must not release someone else's lock.
	if _, err := Open(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("Close without the lock should not release someone else's lock, got: %v", err)
	}
}

// This is why flock was chosen over a PID file: no stale lock survives a crash.
//
// With a PID file, a kill -9 leaves behind a lock that can never be removed, and sooner
// or later someone rm's it by hand -- at which point this protection is purely nominal.
func TestLockIsReleasedWhenTheProcessDiesWithoutClosing(t *testing.T) {
	path := lockTestPath(t)

	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(),
		"WECERT_LOCK_HELPER=1",
		"WECERT_LOCK_PATH="+path,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child process failed: %v\n%s", err, out)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("no stale lock should survive process death, got: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

// LockFile exposes the same flock for sibling state files (wecert-onboard's state
// file): a second acquisition must fail fast with ErrLocked, and releasing must make
// the path lockable again.
func TestLockFileFailsFastAndReleases(t *testing.T) {
	path := lockTestPath(t) + ".onboard-state.lock"

	unlock, err := LockFile(path)
	if err != nil {
		t.Fatalf("first LockFile failed: %v", err)
	}

	if _, err := LockFile(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("a held lock must fail fast with ErrLocked, got: %v", err)
	}

	if err := unlock(); err != nil {
		t.Fatalf("release failed: %v", err)
	}
	unlock2, err := LockFile(path)
	if err != nil {
		t.Fatalf("the path should be lockable again after release, got: %v", err)
	}
	if err := unlock2(); err != nil {
		t.Fatal(err)
	}
}

// The lock must be taken before the db file is created: two processes initializing an
// empty db at once is harder to diagnose than two writing an existing one, because they
// each end up with a different table schema.
func TestLockFileIsCreatedNextToTheDatabase(t *testing.T) {
	path := lockTestPath(t)

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, err := os.Stat(path + ".lock"); err != nil {
		t.Fatalf("a lock file should be created: %v", err)
	}
}

// An unlocked open must never migrate, and must say what to do instead.
//
// `migrate` is CREATE TABLE plus a check-then-act `ALTER TABLE ... ADD COLUMN`, so two unlocked
// openers racing on an older database can both pass the "does this column exist?" check and the
// loser aborts the whole open with `duplicate column name: ...` -- reproduced by hand with four
// concurrent OpenUnlocked calls against a legacy-shaped database. Refusing is the fix: the daemon
// owns the schema, and this path is not allowed to change it.
func TestOpenUnlockedRefusesToMigrate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	// A database that needs work: nothing exists yet, so every table is pending.
	if _, err := OpenUnlocked(path); err == nil {
		t.Fatal("an unlocked open created a schema; the migration must belong to the exclusive path")
	} else if !strings.Contains(err.Error(), "schema update") {
		t.Errorf("the refusal must name the problem, got: %v", err)
	}

	// The exclusive path does the work, and then the unlocked one is happy.
	s, err := Open(path)
	if err != nil {
		t.Fatalf("the exclusive open must migrate: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	unlocked, err := OpenUnlocked(path)
	if err != nil {
		t.Fatalf("with the schema current the unlocked path must work: %v", err)
	}
	if err := unlocked.Close(); err != nil {
		t.Fatal(err)
	}
}

// The archived rollback material must survive whichever order the two writers arrive in.
//
// The orphan path records a certificate it merely uploaded, with no material; the retirement path
// records the one that was serving, with the fullchain and key. `ON CONFLICT ... DO NOTHING` let
// whichever arrived first win, so a row could keep two NULLs and the documented manual rollback in
// docs/recovery.md had nothing to restore.
func TestRetiredCertificateMaterialSurvivesEitherWriteOrder(t *testing.T) {
	cases := []struct {
		name     string
		first    [2][]byte
		second   [2][]byte
		wantCert []byte
		wantKey  []byte
	}{
		{"empty first, real second", [2][]byte{nil, nil}, [2][]byte{[]byte("cert-pem"), []byte("key-pem")},
			[]byte("cert-pem"), []byte("key-pem")},
		{"real first, empty second", [2][]byte{[]byte("cert-pem"), []byte("key-pem")}, [2][]byte{nil, nil},
			[]byte("cert-pem"), []byte("key-pem")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.db")
			s, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			if err := s.AddRetiredCert("cert-1", "name", tc.first[0], tc.first[1]); err != nil {
				t.Fatal(err)
			}
			if err := s.AddRetiredCert("cert-1", "name", tc.second[0], tc.second[1]); err != nil {
				t.Fatal(err)
			}

			rows, err := s.ListRetiredCertsBefore(time.Now().Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 1 {
				t.Fatalf("want one row, got %d", len(rows))
			}
			if string(rows[0].CertPEM) != string(tc.wantCert) || string(rows[0].KeyPEM) != string(tc.wantKey) {
				t.Errorf("archived material = (%q, %q), want (%q, %q): the row the documented manual "+
					"rollback reads must keep the real material",
					rows[0].CertPEM, rows[0].KeyPEM, tc.wantCert, tc.wantKey)
			}
		})
	}
}

// A one-shot tool must be able to run on a machine where the daemon has never started.
//
// This is the documented install flow: install, edit the config, `wecert -dry-run`. Opening the
// store unlocked unconditionally -- which is what OpenUnlocked does -- made that fail on a fresh
// state directory, because a brand-new database needs a schema and the unlocked path refuses to
// create one. The dry run exists to check the config BEFORE the daemon is started, so it cannot
// require the daemon to have run first.
func TestOpenForToolMigratesWhenNobodyHoldsTheLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")

	store, err := OpenForTool(path)
	if err != nil {
		t.Fatalf("a fresh state directory must be usable by a one-shot command: %v", err)
	}
	defer store.Close()

	// The schema really is there, not just "open succeeded".
	if err := store.PutCert(&CertState{Name: "c", CertPEM: []byte("x")}); err != nil {
		t.Fatalf("the freshly created schema is not usable: %v", err)
	}
}

// With the daemon running, the same call must fall back to reading without the lock instead of
// failing: that is the whole reason the unlocked path exists.
func TestOpenForToolFallsBackToTheUnlockedPath(t *testing.T) {
	path := lockTestPath(t)

	held, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	tool, err := OpenForTool(path)
	if err != nil {
		t.Fatalf("a running daemon must not stop a one-shot command: %v", err)
	}
	defer tool.Close()

	// And it must not have taken over the lock: the daemon still holds it.
	if _, err := Open(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("the tool released the daemon's lock, got: %v", err)
	}
}
