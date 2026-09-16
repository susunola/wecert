//go:build unix

package state

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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

// The -dry-run path must work while the daemon is running.
//
// It only reads the existing ACME account and initiates no issuance, so skipping the
// lock is safe; and "you cannot even validate the config because the daemon is running"
// pushes people into editing the config blindly.
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
