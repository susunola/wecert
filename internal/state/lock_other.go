//go:build !unix

package state

import (
	"fmt"
	"runtime"
)

// fileLock has no implementation on non-Unix platforms.
//
// wecert only targets linux and darwin, so the sole purpose of this branch is to let it
// compile on other platforms too -- it is not meant to run the daemon there. The whole
// "at most one wecert process touches this state database" invariant every rate-limit
// safety decision in this program depends on (see Store.lock and ErrLocked) rests on
// this lock actually locking. A version of this file used to return success without
// doing anything, which is far more dangerous than failing outright: a platform that
// silently gets no protection looks, from every caller's point of view, exactly like a
// platform that is safely locked, right up until two processes place two orders for the
// same certificate at once and burn the account's "5 certificates per exact identifier
// set / 7 days" quota for a week.
//
// So acquireLock refuses instead of pretending. Before this can genuinely run on
// Windows, this needs to become LockFileEx, at which point it can start returning
// success again.
type fileLock struct{}

func acquireLock(path string) (*fileLock, error) {
	return nil, fmt.Errorf(
		"cross-process locking is not implemented on %s; refusing to open the state store "+
			"exclusively rather than risk two wecert processes issuing against %s at once",
		runtime.GOOS, path)
}

func (l *fileLock) release() error { return nil }

// VerifyHeld is a no-op where there is no cross-process lock to verify (see the build tag above).
func (l *fileLock) VerifyHeld() error { return nil }
