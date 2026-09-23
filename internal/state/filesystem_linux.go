//go:build linux

package state

import (
	"fmt"
	"syscall"
)

// Linux filesystem magic values from linux/magic.h.  FUSE includes sshfs and
// many cloud-mounted filesystems; it is refused along with the conventional
// network filesystems because neither SQLite nor flock can provide the single
// writer guarantee there.
const (
	nfsSuperMagic  = 0x6969
	cifsSuperMagic = 0xff534d42
	smb2SuperMagic = 0xfe534d42
	fuseSuperMagic = 0x65735546
)

func unsafeFilesystemForPath(path string) (string, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return "", fmt.Errorf("stat filesystem for %s: %w", path, err)
	}
	switch uint64(stat.Type) {
	case nfsSuperMagic:
		return "NFS", nil
	case cifsSuperMagic, smb2SuperMagic:
		return "CIFS/SMB", nil
	case fuseSuperMagic:
		return "FUSE", nil
	default:
		return "", nil
	}
}
