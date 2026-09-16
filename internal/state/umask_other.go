//go:build !unix

package state

// Windows has no umask semantics, so both helpers are no-ops here. wecert only
// targets linux and darwin; this branch exists so the package compiles elsewhere,
// not so the daemon can run there.
func setUmask(int) int { return 0 }

func restrictiveUmask() (restore func()) { return func() {} }
