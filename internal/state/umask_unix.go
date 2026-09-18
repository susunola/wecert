//go:build unix

package state

import (
	"sync"
	"syscall"
)

// setUmask sets the process umask temporarily and returns the previous value so it
// can be restored.
//
// Tests rely on this too: proving that file permissions are set explicitly by the
// code requires verifying under a umask that masks nothing -- a 0600 produced by
// running under umask 077 is the umask's doing, not the code's.
func setUmask(mask int) int { return syscall.Umask(mask) }

// umaskMu serialises every restrictive-umask window in the process.
//
// umask(2) is process-global, not goroutine-local, so two windows running at once
// interleave their set/restore pairs -- and one window's "previous value" is then
// the OTHER window's 077: when both restore, the process umask is stuck at 077 for
// the rest of its life, and every later file anywhere in the process is born
// private. Open (its create/migrate window) and Snapshot both use this mutex, so
// their windows are strictly sequential and each restores the value it actually
// saw.
var umaskMu sync.Mutex

// restrictiveUmask sets the process umask to 077 and returns a function that
// restores the previous value.
//
// Files born while it is in effect are never group/other-accessible, no matter
// what mode bits the creating call passes or derives. It exists for the state
// database's create/migrate window: SQLite derives -wal/-shm permissions from the
// process umask, and those files are copies of the private keys.
//
// The contract the mutex above cannot enforce: NOTHING else in the process may
// create a file while a window is open. The window covers the whole of openFiles
// and a Snapshot's VACUUM INTO, and an unrelated goroutine creating a file in that
// time gets its mode masked by 077 -- permissions it did not ask for and nothing
// repairs. Both windows are short and bounded by the store's own work; the daemon
// must not run unrelated file-writing goroutines that could overlap them. The
// returned restore must be called exactly once (defer it): skipping it leaves the
// umask at 077 AND the mutex locked, which is worse than either failure alone.
func restrictiveUmask() (restore func()) {
	umaskMu.Lock()
	prev := setUmask(0o077)
	return func() {
		setUmask(prev)
		umaskMu.Unlock()
	}
}
