//go:build !unix

package state

// setUmask 在非 Unix 平台上是个空操作（Windows 没有 umask 语义）。
func setUmask(int) int { return 0 }
