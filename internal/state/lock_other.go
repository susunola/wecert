//go:build !unix

package state

// fileLock is a no-op on non-Unix platforms.
//
// wecert only targets linux and darwin, so the sole purpose of this branch is to let it
// compile on other platforms too. It provides **no cross-process protection**, and that
// must be said plainly -- quietly pretending to succeed is far more dangerous than
// failing outright.
//
// Before this can genuinely run on Windows, this needs to become LockFileEx.
type fileLock struct{}

func acquireLock(string) (*fileLock, error) { return &fileLock{}, nil }

func (l *fileLock) release() error { return nil }
