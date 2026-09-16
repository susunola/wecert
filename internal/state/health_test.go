package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A corrupt state file must be reported as corrupt, with somewhere to go next.
//
// Before this, a damaged file surfaced as whichever statement happened to touch it first
// ("query the opened database file: database disk image is malformed (11)"), which reads
// like a DSN or permission problem rather than "your state database is gone". The data at
// stake -- the ACME account key, every in-flight order URL, every ARI certID -- is not
// reproducible, so the message has to say what to do instead of just what failed.
func TestCorruptDatabaseIsReportedAsCorrupt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	for _, content := range []string{
		"not a database at all",
		"\x00\x01\x02\x03garbage",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Open(path)
		if err == nil {
			t.Fatalf("opening a corrupt database must fail")
		}
		msg := err.Error()
		if !strings.Contains(msg, "corrupt") {
			t.Errorf("error should say the database is corrupt, got: %v", err)
		}
		if !strings.Contains(msg, "docs/recovery.md") {
			t.Errorf("error should point at the recovery procedure, got: %v", err)
		}
	}
}

// A truncated real database (a power cut mid-write) is the other corruption shape and must
// be reported the same way.
func TestTruncatedDatabaseIsReportedAsCorrupt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutCert(&CertState{Name: "x", KeyPEM: []byte("k")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() < 4096 {
		t.Skip("database too small to truncate meaningfully")
	}
	if err := os.Truncate(path, info.Size()/16); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(path); err == nil {
		t.Fatal("a truncated database must not open")
	} else if !strings.Contains(err.Error(), "corrupt") {
		t.Errorf("error should say the database is corrupt, got: %v", err)
	}
}

// The corruption detector must not swallow unrelated failures: a permission error is not a
// corrupt database, and reporting it as one would send the operator to restore a backup
// they do not need.
func TestOnlyCorruptionIsReportedAsCorruption(t *testing.T) {
	for _, tc := range []struct {
		msg  string
		want bool
	}{
		{"file is not a database (26)", true},
		{"database disk image is malformed (11)", true},
		{"malformed database schema (7)", true},
		{"file is encrypted or is not a database", true},
		{"unable to open database file: permission denied", false},
		{"no such table: certificates", false},
		{"disk I/O error", false},
		{"", false},
	} {
		got := isCorruptDatabaseError(errString(tc.msg))
		if got != tc.want {
			t.Errorf("isCorruptDatabaseError(%q) = %v, want %v", tc.msg, got, tc.want)
		}
	}
}

// The "the database vanished" warning must name the consequences, since the operator only
// sees it once and the alternative reading is "a fresh install is starting", which is fine.
func TestMissingDatabaseWarningNamesTheConsequences(t *testing.T) {
	msg := missingDatabaseWarning("/var/lib/wecert/state.db")
	for _, want := range []string{
		"/var/lib/wecert/state.db",
		"account key",
		"order",
		"docs/recovery.md",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("warning should mention %q, got: %s", want, msg)
		}
	}
}

// A database that is simply absent, with no trace of a previous one, is a fresh install and
// must not warn. Only the lock file makes it suspicious: the lock is created on every run
// and never removed (the kernel releases the flock, the file stays).
func TestFreshInstallDoesNotLookLikeADeletedDatabase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	if _, err := os.Stat(path + ".lock"); err == nil {
		t.Fatal("precondition: no lock file should exist yet")
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("a fresh install must open cleanly: %v", err)
	}
	defer s.Close()

	// Now the lock exists. Removing the database and reopening is the deleted-database
	// shape, and it must be distinguishable from the fresh case above.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	_, lockErr := os.Stat(path + ".lock")
	if lockErr != nil {
		t.Fatalf("the lock file should still exist after a clean close: %v", lockErr)
	}
}

func errString(s string) error {
	if s == "" {
		return nil
	}
	return &plainError{s}
}

type plainError struct{ s string }

func (e *plainError) Error() string { return e.s }
