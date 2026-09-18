package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Open must refuse a state file it cannot stat, rather than opening with the identity check
// silently disabled.
//
// VerifyOnDisk's "is this still the same inode" comparison is the only tripwire for a database
// unlinked or replaced under a running daemon, and it needs the FileInfo sampled at open time.
// Continuing past a failed stat opened the store with openedAs=nil, which disabled that check
// for the life of the process -- with no error and no log anywhere. The file was pre-created by
// openFiles itself, so a stat failure means the filesystem is in a state nothing downstream can
// reason about; refusing is the only honest answer.
func TestOpenRefusesAStateFileItCannotStat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	saved := statOpenedFile
	statOpenedFile = func(p string) (os.FileInfo, error) {
		if p == path {
			return nil, os.ErrPermission
		}
		return os.Stat(p)
	}
	defer func() { statOpenedFile = saved }()

	s, err := Open(path)
	if err == nil {
		if s != nil {
			_ = s.Close()
		}
		t.Fatal("open must refuse when the state file it just created cannot be stat'd: " +
			"continuing would leave VerifyOnDisk's identity check silently disabled for the " +
			"life of the process")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the error must name the state file, got: %v", err)
	}
}

// A store that opened normally always has the identity check armed: openedAs is set, and a
// replaced database is reported. This is the control that keeps the test above from being
// satisfied by disabling VerifyOnDisk outright.
func TestASuccessfulOpenArmsTheIdentityCheck(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if s.openedAs == nil {
		t.Fatal("a successful open must record the opened file's identity: without it VerifyOnDisk " +
			"can never notice the database being unlinked or replaced under a running daemon")
	}
}
