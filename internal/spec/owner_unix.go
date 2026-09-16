//go:build unix

package spec

import (
	"os"
	"syscall"
)

// fileOwnerUID reports the uid that owns fi, when the platform exposes one.
//
// Used to require that the desired-state document is owned by the account running
// wecert: the mode bits say nothing about who the writer is, so a 0644 document owned by
// someone else is still theirs to rewrite.
func fileOwnerUID(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}
