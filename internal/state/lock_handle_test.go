//go:build unix

package state

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// The handle form of the sibling-file lock: a second acquisition must fail fast with
// ErrLocked, and Unlock must make the path lockable again.
func TestAcquireFileLockFailsFastAndReleases(t *testing.T) {
	path := lockTestPath(t) + ".onboard-state.lock"

	lock, err := AcquireFileLock(path)
	if err != nil {
		t.Fatalf("first AcquireFileLock failed: %v", err)
	}

	if _, err := AcquireFileLock(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("a held lock must fail fast with ErrLocked, got: %v", err)
	}

	if err := lock.Unlock(); err != nil {
		t.Fatalf("release failed: %v", err)
	}
	lock2, err := AcquireFileLock(path)
	if err != nil {
		t.Fatalf("the path should be lockable again after release, got: %v", err)
	}
	if err := lock2.Unlock(); err != nil {
		t.Fatal(err)
	}
}

// flock is bound to the inode, not the name: once the lock file is removed, the next
// process locks a NEW inode while this one keeps holding the old one, and the mutual
// exclusion is silently gone. VerifyHeld is how a lock holder notices before it
// publishes anything.
func TestFileLockVerifyHeldNoticesRemovalAndReplacement(t *testing.T) {
	path := lockTestPath(t) + ".onboard-state.lock"

	lock, err := AcquireFileLock(path)
	if err != nil {
		t.Fatalf("AcquireFileLock failed: %v", err)
	}
	defer func() { _ = lock.Unlock() }()

	if err := lock.VerifyHeld(); err != nil {
		t.Fatalf("the lock was just taken and the file is there: %v", err)
	}

	// The "clear the stale lock" habit: the file is gone, so a second process can now
	// lock a new file at the same path and run concurrently with this one.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	err = lock.VerifyHeld()
	if err == nil {
		t.Fatal("a removed lock file must fail VerifyHeld: another process can lock a new " +
			"file at the same path right now")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the error must name the lock file, got: %v", err)
	}

	// A new file at the path -- another process may already be holding ITS lock.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err = lock.VerifyHeld()
	if err == nil {
		t.Fatal("a replaced lock file must fail VerifyHeld: this process holds the old inode")
	}
	if !strings.Contains(err.Error(), "replaced") {
		t.Errorf("the error must say the file was replaced, got: %v", err)
	}
}
