//go:build !unix

package state

// setUmask is a no-op on non-Unix platforms (Windows has no umask semantics).
func setUmask(int) int { return 0 }
