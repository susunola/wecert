// Package atomicfile replaces a file so that a reader sees either the old contents or the new ones,
// and so that the new contents survive a power loss.
//
// The protocol is always the same three steps: write a temporary file in the same directory, fsync
// it, rename it over the target. rename(2) is atomic within one filesystem, so a concurrent reader
// -- and wecert's daemon reads the desired-state document on every pass -- never sees a half-written
// file, which for a document that lists the domains is the most dangerous input there is.
//
// It lives in one place because it existed in three, and they had already drifted: the onboarding
// report writer was missing the fsync for several rounds, so a crash could leave a renamed,
// truncated report behind a round that otherwise completed. Three copies also meant three chances
// to get the ordering wrong the next time someone needs a durable write.
package atomicfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Write replaces path with data, creating it with perm.
//
// perm is applied to the temporary file BEFORE the rename rather than to the target afterwards.
// Chmod-after-rename leaves a window in which the file has whatever the process umask allows, and
// these files carry private keys or the names that will be issued as certificates; the window is
// short but it is a window (the same reasoning as internal/state's restrictiveUmask).
//
// The parent directory is synced after the rename. Without that the rename itself can be lost by a
// power cut even though the file's contents reached the disk: the new name lives in the directory's
// own block, and "the file is on disk but nothing points at it" is indistinguishable from a lost
// write. Filesystems that cannot sync a directory report EINVAL or ENOTSUP; those are tolerated
// (the file IS installed), everything else is reported, because silently skipping the step would
// make the durability claim above false.
func Write(path string, data []byte, perm os.FileMode) error {
	// Refuse a symlinked target rather than silently replacing the link.
	//
	// rename(2) replaces the NAME, so writing through a symlink destroys the link and leaves the
	// file it pointed at frozen at its old contents -- an operator who keeps desired-state.yaml as a
	// link into their configuration repository would find the link gone and their repository copy
	// stale after one round. The desired-state reader refuses symlinks for the same reason, so this
	// keeps the two halves consistent instead of letting the writer quietly undo the reader's rule.
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing to replace it -- point the path at the real "+
			"file, because writing here would destroy the link and leave its target stale", path)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, TempPrefix+"*.tmp")
	if err != nil {
		// Named after the TARGET, not the temporary file: the caller logs this against the
		// document or the report it was trying to write, and a random temp name in the message
		// sends the reader looking for a file that does not exist.
		return fmt.Errorf("write %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer func() {
		// Every failure path removes the temp file, or the directory slowly fills with junk that
		// looks like a usable copy of something.
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	return Install(tmpName, path, perm, dir)
}

// Install moves an already-written temporary file into place and makes the rename durable.
//
// For callers whose temporary file is produced by something else -- internal/state's snapshots are
// written by SQLite's VACUUM INTO, which refuses to write into an existing file -- but who want the
// same permissions-before-rename and directory-sync guarantees.
//
// It takes ownership of tmpPath: on success the caller must not touch it again, and on failure it is
// left in place for the caller's own cleanup (the caller knows which cleanup its writer needs).
func Install(tmpPath, path string, perm os.FileMode, dir string) error {
	// chmod(2) follows symlinks, and both callers hand this function a name they created -- but
	// "a name we created a moment ago" is not a property chmod can check, and the failure mode is
	// ugly: the mode of an unrelated file changes, and the symlink itself is installed under the
	// target's name. A regular-file check closes it for the price of one lstat.
	if fi, err := os.Lstat(tmpPath); err != nil {
		return fmt.Errorf("install %s: %w", path, err)
	} else if !fi.Mode().IsRegular() {
		return fmt.Errorf("install %s: the temporary file %s is not a regular file (%s)",
			path, tmpPath, fi.Mode().Type())
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return fmt.Errorf("set the permissions of %s: %w", path, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	if err := SyncDir(dir); err != nil {
		return fmt.Errorf("%s is in place, but making its name durable failed: %w", path, err)
	}
	return nil
}

// SyncDir makes a directory's entries durable.
//
// A failure here means the RENAME may not survive a power cut, not that the write failed: the file
// is in place and readable. Callers report it as an error because silence would make the durability
// claim above false, and the wording says which of the two happened so an operator reading the log
// knows whether to retry or to copy the file elsewhere.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open %s to sync its entries: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		var errno syscall.Errno
		if errors.As(err, &errno) && (errno == syscall.EINVAL || errno == syscall.ENOTSUP || errno == syscall.ENOSYS) {
			// The filesystem has no notion of syncing a directory. The rename happened; there is
			// nothing else this call can do, and reporting it would fail a write that succeeded.
			return nil
		}
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	return nil
}

// TempPrefix is the prefix every temporary file this package creates uses.
//
// Exported so a test (or an operator cleaning up after a crash) can recognise the leftovers: a
// process killed between CreateTemp and the rename leaves one behind, and nothing revisits it.
const TempPrefix = ".atomic-"

// IsTemp reports whether a directory entry is one of this package's temporary files.
func IsTemp(name string) bool {
	ok, err := filepath.Match(TempPrefix+"*.tmp", name)
	return err == nil && ok
}
