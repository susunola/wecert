package onboarding

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A corrupt state file must fail outright, never continue as empty state: "treat as
// empty" zeroes every grace period, turning deletion from conservative into
// aggressive -- exactly what §5.3 exists to prevent.
func TestLoadStateRefusesACorruptFile(t *testing.T) {
	for _, data := range []string{
		`{"absentSince": {`,   // truncated mid-object
		`not json at all`,     // not JSON
		`[1, 2, 3]`,           // JSON, but the wrong shape
		`{"changes": "soon"}`, // right shape, wrong types
	} {
		path := filepath.Join(t.TempDir(), "onboard-state.json")
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}

		st, err := LoadState(path)
		if err == nil {
			t.Errorf("corrupt state %q must fail, got state %+v", data, st)
			continue
		}
		if !strings.Contains(err.Error(), "parse onboarding state") {
			t.Errorf("the error must say what could not be parsed, got %v", err)
		}
	}
}

// Only genuine absence counts as empty state: a missing file (the first run has no
// baseline yet) or an empty file (a truncated write left zero bytes, which holds no
// information to misread). Anything with content that does not parse is refused --
// see TestLoadStateRefusesACorruptFile.
func TestLoadStateTreatsMissingAndEmptyFilesAsEmptyState(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "onboard-state.json")
	st, err := LoadState(missing)
	if err != nil {
		t.Fatalf("a missing state file must count as empty state (the first run), got %v", err)
	}
	if st == nil || st.AbsentSince == nil || len(st.AbsentSince) != 0 {
		t.Errorf("empty state must still carry an initialised absence ledger, got %+v", st)
	}

	empty := filepath.Join(t.TempDir(), "onboard-state.json")
	if err := os.WriteFile(empty, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(empty); err != nil {
		t.Errorf("a whitespace-only state file must count as empty state, got %v", err)
	}
}

// A FIFO at the state path must be refused, not opened.
//
// The onboarding run takes the cross-process lock before it reads this file, so a blocking open here
// does not just hang one run: every later run fails with ErrLocked behind it.
func TestAFIFOAtTheStatePathIsRefusedNotOpened(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no FIFOs on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "onboard-state.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}

	done := make(chan error, 1)
	go func() { _, err := LoadState(path); done <- err }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a FIFO is not a state file")
		}
		if !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("the refusal must say what it saw, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("LoadState blocked on a FIFO; the run holds the lock by then, so every later round " +
			"would queue up behind it forever")
	}

	// A symlinked state file is refused too: Save replaces the link, so reading through it and
	// writing over it would leave two files disagreeing about the grace period.
	target := filepath.Join(dir, "real.json")
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(link); err == nil {
		t.Error("a symlinked state file must be refused: Save would destroy the link and leave the " +
			"target stale")
	}
}

// The state file is the grace-period clock and the change ledger, so whoever can rewrite it
// can turn deletion from conservative into aggressive. spec.LoadDocument refuses a group- or
// world-writable document for the same reason; the state file now holds the same line.
func TestLoadStateRefusesAGroupOrWorldWritableFile(t *testing.T) {
	for _, perm := range []os.FileMode{0o664, 0o646, 0o606} {
		path := filepath.Join(t.TempDir(), "onboard-state.json")
		if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, perm); err != nil {
			t.Fatal(err)
		}

		_, err := LoadState(path)
		if err == nil {
			t.Errorf("a %04o state file must be refused: its grace clocks are writable by others", perm)
			continue
		}
		if !strings.Contains(err.Error(), "group- or world-writable") {
			t.Errorf("the refusal must say what is wrong, got %v", err)
		}
	}

	// The control: the mode Save writes must load, so the checks above cannot be satisfied by
	// refusing every file.
	path := filepath.Join(t.TempDir(), "onboard-state.json")
	st := &State{AbsentSince: map[string]time.Time{}}
	if err := st.Save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(path); err != nil {
		t.Errorf("a state file written by Save must load, got %v", err)
	}
}
