//go:build unix

package state

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// fileLock is a cross-process exclusive lock built on flock.
//
// Why flock instead of a PID file: the kernel releases it automatically when the
// process exits -- including the kill -9 case. A PID file leaves behind a stale lock
// that can never be removed after a crash, and that lock inevitably gets rm'd by hand
// sooner or later, at which point this protection is purely nominal.
type fileLock struct {
	f    *os.File
	path string
}

func acquireLock(path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create lock file %s: %w", path, err)
	}

	// LOCK_NB: fail immediately when it cannot be taken, never wait here.
	//
	// Waiting would mean a mistakenly started process quietly queues up behind the
	// first one and suddenly starts issuing after that one exits -- far more dangerous
	// than an outright error: the mistake would only surface hours later, by which time
	// nobody remembers starting a second process.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		// EWOULDBLOCK and EAGAIN are the same value on Linux/macOS, but the syscall
		// package does not expose identical names across platforms, so accept both.
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("%w (lock file: %s)", ErrLocked, path)
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}

	return &fileLock{f: f, path: path}, nil
}

// VerifyHeld reports whether this process still holds the lock FILE that sits at the path.
//
// flock is bound to the inode, so `rm state.db.lock` -- the very "clear the stale lock" habit the
// comment above uses to justify flock over a PID file -- hands the next process a brand new inode
// to lock while this one keeps "holding" the old one. Both then run against the same database,
// which is precisely the duplicate-order path the lock exists to prevent (two orders for one
// identifier set run into the 5-per-7-days limit). Nothing can prevent the removal; what can be
// done is to notice it. The caller reports this, and the operator has a process to stop.
func (l *fileLock) VerifyHeld() error {
	if l == nil {
		return nil
	}
	held, err := l.f.Stat()
	if err != nil {
		return fmt.Errorf("cannot stat the held lock file %s: %w", l.path, err)
	}
	onDisk, err := os.Stat(l.path)
	if err != nil {
		return fmt.Errorf("the lock file %s that this process holds is gone (%v); another process can "+
			"now open the same state database, and two writers are one duplicate order away from the "+
			"exact-identifier-set rate limit", l.path, err)
	}
	if !os.SameFile(held, onDisk) {
		return fmt.Errorf("the lock file %s has been replaced since this process locked it; another "+
			"process can hold a lock on the new file while this one keeps writing", l.path)
	}
	return nil
}

func (l *fileLock) release() error {
	if l == nil || l.f == nil {
		return nil
	}
	// Unlock explicitly, then close. Closing releases the lock on its own, but doing it
	// explicitly makes "when the lock was dropped" readable in the code instead of
	// relying on the reader knowing a close side effect.
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	return l.f.Close()
}
