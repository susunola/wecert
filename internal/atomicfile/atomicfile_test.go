package atomicfile

import (
	"os"
	"path/filepath"
	"strings"
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
