package atomicfile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Write replaces the contents in one step and reports the permissions it promises.
func TestWriteReplacesAndSetsPerm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target")

	if err := Write(path, []byte("first\n"), 0o600); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "first\n" {
		t.Errorf("contents = %q", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("perm = %04o, want 0600: the permissions are set on the temporary file before the "+
			"rename so the target is never readable by anyone the umask allows", perm)
	}

	if err := Write(path, []byte("second\n"), 0o600); err != nil {
		t.Fatalf("Write over an existing file: %v", err)
	}
	got, _ = os.ReadFile(path)
	if string(got) != "second\n" {
		t.Errorf("after replace, contents = %q", got)
	}
}

// No temporary file survives a successful write.
func TestWriteLeavesNoTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	if err := Write(filepath.Join(dir, "target"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if IsTemp(e.Name()) {
			t.Errorf("left a temporary file behind: %s", e.Name())
		}
	}
	if len(entries) != 1 {
		t.Errorf("expected exactly the target, got %v", entries)
	}
}

// A write that cannot even create its temporary file reports the target, not the temp name.
func TestWriteReportsTheTargetWhenTheDirectoryIsMissing(t *testing.T) {
	err := Write(filepath.Join(t.TempDir(), "nope", "target"), []byte("x"), 0o600)
	if err == nil {
		t.Fatal("writing into a missing directory must fail")
	}
	if !strings.Contains(err.Error(), "target") {
		t.Errorf("the error has to name the file the caller asked for, got %v", err)
	}
}

// Install takes a file written elsewhere, sets its permissions, and moves it into place.
func TestInstallMovesAndSetsPerm(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, ".atomic-123.tmp")
	if err := os.WriteFile(tmp, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "final")

	if err := Install(tmp, target, 0o600, dir); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Errorf("the temporary file must be gone after the rename, stat err %v", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("perm = %04o, want 0600", info.Mode().Perm())
	}
	body, _ := os.ReadFile(target)
	if string(body) != "payload" {
		t.Errorf("contents = %q", body)
	}
}

// Write must refuse a symlinked target rather than silently replacing the link.
//
// rename(2) replaces the NAME: the link is destroyed and the file it pointed at stays frozen at its
// old contents. The desired-state reader refuses a symlinked document, so a writer that quietly
// undid that rule would leave the operator with a link gone, a stale target, and no error.
func TestWriteRefusesASymlinkedTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.yaml")
	if err := os.WriteFile(target, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "desired-state.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	err := Write(link, []byte("new\n"), 0o644)
	if err == nil {
		t.Fatal("writing over a symlink must be refused")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("the refusal must say what it saw, got %v", err)
	}
	if fi, lerr := os.Lstat(link); lerr != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Error("the link must still be there; the write must not have replaced it")
	}
	got, _ := os.ReadFile(target)
	if string(got) != "old\n" {
		t.Errorf("the target must be untouched, got %q", got)
	}
}

// Install must refuse a temporary path that is not a regular file, because chmod(2) follows links.
func TestInstallRefusesANonRegularTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, []byte("unrelated"), 0o644); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, ".atomic-link.tmp")
	if err := os.Symlink(target, tmp); err != nil {
		t.Fatal(err)
	}

	if err := Install(tmp, filepath.Join(dir, "final"), 0o600, dir); err == nil {
		t.Fatal("a symlinked temporary path must be refused: chmod follows the link and would change " +
			"the mode of an unrelated file before installing the link under the target's name")
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("the unrelated file's mode changed to %04o", info.Mode().Perm())
	}
}

// The fsync has to happen on the TEMPORARY file, before the rename.
//
// This is the round-4 change that was recorded as having no behavioural test ("a crash cannot be
// manufactured in a test"): the onboarding report writer used to rename without syncing, so a
// crash -- or just a lost page cache -- could leave a renamed, truncated (or zero-byte) report
// behind a round that otherwise completed. Whether the bytes reached the platter is not observable
// from inside the process, but the two things the fix actually changed are: which file is synced,
// and that it is synced before the rename. Both are pinned here through the syncFile seam.
//
// Write now syncs twice: once before closing the temporary file, and once inside Install (which
// makes the same promise for callers whose writer is not Write). What is pinned is not the count
// but that every sync is on the temporary file and precedes the rename.
func TestWriteSyncsTheTemporaryFileBeforeTheRename(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "onboarding-report.json")

	var mu sync.Mutex
	var synced []string
	orig := syncFile

	syncFile = func(f *os.File) error {
		mu.Lock()
		defer mu.Unlock()
		synced = append(synced, f.Name())
		// At the moment of the sync the target must NOT exist yet: a sync after the rename would
		// be syncing the wrong name, and the durability claim is about the temp file's contents.
		if _, err := os.Stat(target); err == nil {
			t.Errorf("the target already exists when Sync runs (%s): the sync must precede the rename", f.Name())
		} else if !os.IsNotExist(err) {
			t.Errorf("stat %s: %v", target, err)
		}
		// And the file being synced must be this package's temporary file in the target directory.
		if filepath.Dir(f.Name()) != dir {
			t.Errorf("the sync must be on a temporary file in the target's directory, got %s", f.Name())
		}
		if !IsTemp(filepath.Base(f.Name())) {
			t.Errorf("the synced file %s is not one of this package's temporaries", f.Name())
		}
		return f.Sync()
	}
	t.Cleanup(func() { syncFile = orig })

	if err := Write(target, []byte(`{"round":"ok"}`), 0o644); err != nil {
		t.Fatalf("Write: %v", err)
	}
	mu.Lock()
	n := len(synced)
	mu.Unlock()
	if n == 0 {
		t.Fatal("no fsync happened on the temporary file: the durability claim is empty")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"round":"ok"}` {
		t.Errorf("the target holds %q", got)
	}
}

// A failed sync must fail the write and leave the previous contents alone.
//
// The whole point of syncing before the rename is that a crash between the two is the only window
// left; a sync that is attempted and ignored would put the truncated-report window back without
// changing the code's shape. The rename must therefore not have happened when the sync fails.
func TestAFailedSyncLeavesTheOldContentsInPlace(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "onboarding-report.json")
	if err := os.WriteFile(target, []byte("previous"), 0o644); err != nil {
		t.Fatal(err)
	}

	orig := syncFile
	syncFile = func(*os.File) error { return errors.New("EIO") }
	t.Cleanup(func() { syncFile = orig })

	if err := Write(target, []byte("new"), 0o644); err == nil {
		t.Fatal("a sync failure must be reported: the caller has to know the write is not durable")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "previous" {
		t.Errorf("a failed sync must not install the new contents, target holds %q", got)
	}
	// And the temporary file must not be left behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if IsTemp(e.Name()) {
			t.Errorf("a failed write left %s behind", e.Name())
		}
	}
}

// Install must fsync the temporary file itself, before the rename.
//
// The package promises the new contents survive a power loss; callers whose writer is not Write
// (internal/state's snapshots come from SQLite's VACUUM INTO) used to carry that as an implicit
// "the caller surely synced" precondition -- exactly the kind that drifts. The seam records which
// file is synced, and the target must not exist yet when it happens.
func TestInstallSyncsTheTemporaryFileBeforeTheRename(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, ".atomic-456.tmp")
	if err := os.WriteFile(tmp, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "final")

	var synced []string
	orig := syncFile
	syncFile = func(f *os.File) error {
		synced = append(synced, f.Name())
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Errorf("the target already exists when Sync runs (%s): the sync must precede the rename", f.Name())
		}
		return f.Sync()
	}
	t.Cleanup(func() { syncFile = orig })

	if err := Install(tmp, target, 0o600, dir); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if len(synced) != 1 || synced[0] != tmp {
		t.Errorf("expected exactly one fsync, on the temporary file; got %v", synced)
	}
}

// A failed sync inside Install must fail the install before the rename, and leave the temporary
// file in place: on failure the caller owns the cleanup.
func TestAFailedInstallSyncRenamesNothing(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, ".atomic-789.tmp")
	if err := os.WriteFile(tmp, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "final")

	orig := syncFile
	syncFile = func(*os.File) error { return errors.New("EIO") }
	t.Cleanup(func() { syncFile = orig })

	if err := Install(tmp, target, 0o600, dir); err == nil {
		t.Fatal("a sync failure must be reported: the caller has to know the install is not durable")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Error("nothing may be installed when the sync failed")
	}
	if _, err := os.Stat(tmp); err != nil {
		t.Errorf("the temporary file must be left in place for the caller's cleanup: %v", err)
	}
}

// dir is the directory synced after the rename; a mismatched one would make that sync succeed
// quietly while the rename itself stays volatile.
func TestInstallRefusesAMismatchedDirectory(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, ".atomic-012.tmp")
	if err := os.WriteFile(tmp, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "final")

	if err := Install(tmp, target, 0o600, t.TempDir()); err == nil {
		t.Fatal("a directory that does not hold the target must be refused: the directory sync " +
			"would land on the wrong directory")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Error("nothing may be installed when the directory is wrong")
	}
	if _, err := os.Stat(tmp); err != nil {
		t.Errorf("the temporary file must be left in place for the caller's cleanup: %v", err)
	}
}
