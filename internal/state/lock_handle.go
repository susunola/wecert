package state

// FileLock is a held cross-process exclusive lock on an arbitrary file.
//
// It is the handle form of LockFile: same flock underneath (see fileLock), but the
// caller also gets VerifyHeld. That check matters because flock is bound to the inode,
// not to the name -- `rm state.json.lock`, the classic "clear the stale lock" habit,
// hands the next process a brand new inode to lock while this one keeps "holding" the
// old one, and both then run against the same state file. The removal cannot be
// prevented; it can be noticed, before this process publishes anything.
type FileLock struct {
	inner *fileLock
}

// AcquireFileLock takes the cross-process exclusive lock described in Store.lock on an
// arbitrary file.
//
// The store locks "<db>.lock" itself inside Open; this is for sibling state files that
// need the same "at most one process" gate -- wecert-onboard's state file, where two
// overlapping cron runs would each load the same baseline and then last-writer-wins the
// save, losing Changes entries and regressing AbsentSince. Like the store's lock it
// fails fast rather than queueing: a second run that waited would apply its stale
// baseline the moment the first one exits, which is worse than an outright error.
func AcquireFileLock(path string) (*FileLock, error) {
	lock, err := acquireLock(path)
	if err != nil {
		return nil, err
	}
	return &FileLock{inner: lock}, nil
}

// VerifyHeld reports whether this process still holds the lock FILE that sits at the
// path. See fileLock.VerifyHeld for why the check exists.
func (l *FileLock) VerifyHeld() error {
	if l == nil {
		return nil
	}
	return l.inner.VerifyHeld()
}

// Unlock releases the lock. Safe to call once at the end of the critical section; the
// kernel would release it at process exit anyway, but an explicit release makes "when
// the lock was dropped" readable.
func (l *FileLock) Unlock() error {
	if l == nil {
		return nil
	}
	return l.inner.release()
}
