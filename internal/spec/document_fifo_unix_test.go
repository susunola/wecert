//go:build unix

package spec

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A FIFO at the document path must be refused, not opened.
//
// open(2) on a FIFO with no writer BLOCKS until one appears, so the regular-file check the reader
// already has was unreachable: a FIFO planted at desiredState.path hung the daemon inside
// newProvider -- before metrics, the webhook and the snapshot loop start -- and a Type=simple unit
// never notices, because the process is alive and never exits. O_NONBLOCK (see openflags_unix.go)
// makes the open return immediately; the stat then sees a non-regular file and the reader refuses
// it. Unix-only: syscall.Mkfifo does not exist elsewhere, and neither does the O_NONBLOCK dance
// the test exercises.
func TestAFIFOAtTheDocumentPathIsRefusedNotOpened(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "desired-state.yaml")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}

	done := make(chan error, 1)
	go func() { _, err := LoadDocument(path); done <- err }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO is not a document")
		}
		if !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("the refusal must say what it saw, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("LoadDocument blocked on a FIFO: open(2) waits for a writer, so the daemon would " +
			"hang at startup with no error and no exit")
	}
}

// os.O_RDONLY alone is not the unix contract: without O_NOFOLLOW the symlink refusal is a
// check-then-open race, and without O_NONBLOCK the FIFO test above would hang instead of fail.
func TestDocumentOpenFlags(t *testing.T) {
	t.Parallel()
	if documentOpenFlags&syscall.O_NOFOLLOW == 0 {
		t.Error("documentOpenFlags must include O_NOFOLLOW on unix")
	}
	if documentOpenFlags&syscall.O_NONBLOCK == 0 {
		t.Error("documentOpenFlags must include O_NONBLOCK on unix")
	}
}
