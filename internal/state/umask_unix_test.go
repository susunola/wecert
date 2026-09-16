//go:build unix

package state

import "syscall"

// setUmask sets the process umask temporarily and returns the previous value so it can
// be restored.
//
// Test-only: proving that file permissions are set explicitly by the code requires
// verifying under a umask that masks nothing -- a 0600 produced by running under
// umask 077 is the umask's doing, not the code's.
func setUmask(mask int) int { return syscall.Umask(mask) }
