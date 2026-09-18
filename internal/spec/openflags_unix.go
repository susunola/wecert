//go:build unix

package spec

import (
	"errors"
	"os"
	"syscall"
)

// documentOpenFlags are the flags openDocumentFile opens the desired-state document with.
//
// O_NOFOLLOW makes the symlink refusal a property of the open call rather than of a
// separate Lstat that a concurrent writer can invalidate between the two.
//
// O_NONBLOCK is what makes the regular-file check in LoadDocument reachable. open(2) on a
// FIFO with no writer BLOCKS until one appears, so a FIFO planted at desiredState.path hung
// the daemon inside newProvider -- before metrics, the webhook and the snapshots start --
// and a Type=simple unit never notices. With O_NONBLOCK the open returns immediately, the
// stat then sees a non-regular file, and the reader refuses it. On a regular file the flag
// is a no-op.
const documentOpenFlags = os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK

// isSymlinkRefusal reports whether err is how open(2) answers O_NOFOLLOW on a symlink.
func isSymlinkRefusal(err error) bool {
	return errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK)
}
