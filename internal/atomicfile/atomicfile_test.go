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
