package state

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
)

// Concurrent restrictive-umask windows must restore the umask each one actually saw.
//
// umask(2) is process-global, so without serialisation two windows interleave their set/restore
// pairs: one window's "previous value" is the other window's 077, and when both restore the
// process umask is stuck at 077 forever -- every later file anywhere in the process is born
// private. Open's create/migrate window and Snapshot share one mutex so this cannot happen.
func TestConcurrentRestrictiveUmaskWindowsRestoreTheOriginal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no umask semantics on Windows")
	}

	// Pin a known starting value so "restored correctly" is checkable rather than assumed.
	orig := setUmask(0o022)
	defer setUmask(orig)

	const goroutines = 8
	const windowsPerGoroutine = 50
	errs := make(chan error, goroutines*windowsPerGoroutine)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < windowsPerGoroutine; j++ {
				restore := restrictiveUmask()
				// Inside a serialised window the umask is 077, full stop. Reading it as anything
				// else means another window interleaved with this one.
				if cur := setUmask(0o077); cur != 0o077 {
					errs <- fmt.Errorf("inside a restrictive window the umask is %04o, not 077: "+
						"another window interleaved with this one", cur)
				}
				restore()
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	// The failure the mutex exists for: after every window has restored, the process umask is
	// back where it started -- not stuck at the last window's 077.
	if got := setUmask(orig); got != 0o022 {
		t.Errorf("after %d concurrent windows the process umask is %04o, want 022: a restore "+
			"pair interleaved and the umask is stuck restrictive for the rest of the process",
			goroutines*windowsPerGoroutine, got)
	}
}
