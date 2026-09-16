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
