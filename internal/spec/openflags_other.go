//go:build !unix

package spec

import "os"

// documentOpenFlags on platforms without POSIX open flags is a plain read-only open:
// O_NOFOLLOW and O_NONBLOCK do not exist there, so neither the symlink refusal nor the
// FIFO non-block applies. The mode-bit checks in LoadDocument still do.
const documentOpenFlags = os.O_RDONLY

// isSymlinkRefusal is never true where O_NOFOLLOW does not exist.
func isSymlinkRefusal(error) bool { return false }
