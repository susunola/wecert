//go:build unix

package spec

import (
	"io/fs"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// uidFileInfo fakes os.FileInfo with a chosen owner uid: chown-ing a real directory
// needs root, and the decision under test is pure given the stat result.
type uidFileInfo struct{ uid uint32 }

func (uidFileInfo) Name() string       { return "dir" }
func (uidFileInfo) Size() int64        { return 0 }
func (uidFileInfo) Mode() fs.FileMode  { return fs.ModeDir | 0o755 }
func (uidFileInfo) ModTime() time.Time { return time.Time{} }
func (uidFileInfo) IsDir() bool        { return true }
func (u uidFileInfo) Sys() any         { return &syscall.Stat_t{Uid: u.uid} }

// The mode bits of a directory say nothing about WHO owns it: a 0755 directory owned by
// another user passes the writability check while its owner can still replace the
// document by rename. The directory must be owned by the account running wecert, with
// uid 0 exempt -- a root-owned /etc/wecert with the daemon running as its own user is a
// normal arrangement, and root can replace anything on the machine anyway.
func TestDocumentDirectoryMustBeOwnedByUsOrRoot(t *testing.T) {
	euid := uint32(os.Geteuid())

	if err := checkDocumentDirOwner("/etc/wecert", uidFileInfo{uid: euid}); err != nil {
		t.Errorf("a directory owned by the daemon's own uid must be accepted, got %v", err)
	}
	if err := checkDocumentDirOwner("/etc/wecert", uidFileInfo{uid: 0}); err != nil {
		t.Errorf("a root-owned directory must be accepted, got %v", err)
	}

	other := euid + 1
	if other == 0 { // euid at the uint32 ceiling; pick any value that is not us or root
		other = 2
	}
	err := checkDocumentDirOwner("/etc/wecert", uidFileInfo{uid: other})
	if err == nil {
		t.Fatal("a directory owned by another user must be refused: its owner can replace the document by rename")
	}
	if !strings.Contains(err.Error(), "owned by uid") {
		t.Errorf("the refusal must name the ownership problem, got %v", err)
	}
}
