//go:build !linux

package state

// Linux is the supported production target and exposes the filesystem magic
// value needed for a reliable mount-type check.  Keep other release targets
// buildable; their local-development state paths remain protected by the file
// permission and lock checks in Open.
func unsafeFilesystemForPath(string) (string, error) { return "", nil }
