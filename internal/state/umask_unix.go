//go:build unix

package state

import "syscall"

// setUmask sets the process umask temporarily and returns the previous value so it
// can be restored.
//
// Tests rely on this too: proving that file permissions are set explicitly by the
// code requires verifying under a umask that masks nothing -- a 0600 produced by
// running under umask 077 is the umask's doing, not the code's.
func setUmask(mask int) int { return syscall.Umask(mask) }

// restrictiveUmask sets the process umask to 077 and returns a function that
// restores the previous value.
//
// Files born while it is in effect are never group/other-accessible, no matter
// what mode bits the creating call passes or derives. It exists for the state
// database's create/migrate window: SQLite derives -wal/-shm permissions from the
// process umask, and those files are copies of the private keys.
func restrictiveUmask() (restore func()) {
	prev := setUmask(0o077)
	return func() { setUmask(prev) }
}
