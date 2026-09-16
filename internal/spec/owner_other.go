//go:build !unix

package spec

import "os"

// fileOwnerUID has no answer on platforms without POSIX ownership, so the ownership
// check is skipped there rather than failing closed on a property the platform does not
// express. The mode-bit checks in LoadDocument still apply.
func fileOwnerUID(os.FileInfo) (uint32, bool) { return 0, false }
