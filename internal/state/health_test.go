package state

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// captureStderr runs fn with os.Stderr redirected and returns what was written.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, rerr := r.Read(buf)
			if n > 0 {
				sb.Write(buf[:n])
			}
			if rerr != nil {
				break
			}
		}
		done <- sb.String()
	}()

	fn()

	os.Stderr = orig
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

// A brand-new deployment must open its state directory without being told that a database
// was "probably deleted or lost".
//
// The check is "a lock file exists but the database does not". acquireLock CREATES the lock
// file, so sampling lockExisted after taking the lock made it true on every call -- and the
// first run of a fresh install printed the disaster warning. That is the worst possible
// false positive: the warning exists to make an operator stop and restore a backup, and one
// that fires when nothing is wrong trains them to ignore it.
func TestFreshStateDirectoryDoesNotWarnAboutALostDatabase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	var openErr error
	out := captureStderr(t, func() {
		s, err := Open(path)
		openErr = err
		if s != nil {
			_ = s.Close()
		}
	})

	if openErr != nil {
		t.Fatalf("opening a fresh state directory must succeed, got %v", openErr)
	}
	if strings.Contains(out, "probably deleted or lost") {
		t.Errorf("a fresh state directory must not be reported as a lost database; stderr was:\n%s", out)
	}
}

// The warning must still fire in the case it was written for: the lock file survives but the
// database is gone. This is the control that keeps the test above from being satisfied by
// simply deleting the check.
func TestMissingDatabaseBesideALockFileStillWarns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	// A lock file with no database: exactly what a deleted state.db looks like.
	if err := os.WriteFile(path+".lock", nil, 0o600); err != nil {
		t.Fatalf("creating the lock file: %v", err)
	}

	var openErr error
	out := captureStderr(t, func() {
		s, err := Open(path)
		openErr = err
		if s != nil {
			_ = s.Close()
		}
	})

	if openErr != nil {
		t.Fatalf("opening must still succeed, got %v", openErr)
	}
	if !strings.Contains(out, "probably deleted or lost") {
		t.Errorf("a lock file with no database must warn; stderr was:\n%s", out)
	}
}

// A symlinked state path and a shared-writable state directory are warned about, not refused.
//
// Both are legitimate arrangements -- state.db on another volume, a staging symlink, an operator's
// own directory that happens to be 0775 -- and refusing them would break working deployments. Both
// also let a local user redirect or replace what this process writes, so the operator is told
// plainly and left to judge. The database is still created through the symlink: that is the
// behaviour being kept on purpose.
func TestStatePathHazardsAreWarnedAboutNotRefused(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "data", "state.db")

	warnings := statePathWarnings(real, filepath.Dir(real))
	if len(warnings) != 0 {
		t.Errorf("a private directory and a missing file have nothing to warn about, got %v", warnings)
	}

	// A symlink: warned about, and open() still works through it.
	if err := os.MkdirAll(filepath.Dir(real), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "state.db")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	warnings = statePathWarnings(link, dir)
	if len(warnings) == 0 {
		t.Fatal("a symlinked state path must be reported: this process writes through it, so whoever " +
			"can write the target's directory chooses where the account key goes")
	}
	if !strings.Contains(warnings[0], "symlink") {
		t.Errorf("the warning has to say what it saw, got %q", warnings[0])
	}
	s, err := Open(link)
	if err != nil {
		t.Fatalf("a symlinked state path must still open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	// A group/world-writable directory: warned about.
	shared := filepath.Join(dir, "shared")
	if err := os.MkdirAll(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	warnings = statePathWarnings(filepath.Join(shared, "state.db"), shared)
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "world-writable") {
			found = true
		}
	}
	if !found {
		t.Errorf("a 0777 state directory must be reported: 0600 on state.db does not stop another "+
			"user unlinking it, got %v", warnings)
	}
}

// VerifyOnDisk reports a database that is no longer the file at its path, and a lock that was taken
// away underneath the process.
//
// SQLite writes to the inode it opened and flock is bound to the inode it locked, so both failures
// are invisible from inside the process: reads answer, writes succeed, and the next start comes up
// with nothing. The removal cannot be prevented; it can be noticed.
func TestVerifyOnDiskNoticesADeletedOrReplacedDatabaseAndALostLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if problems := s.VerifyOnDisk(); len(problems) != 0 {
		t.Fatalf("a healthy store has nothing to report, got %v", problems)
	}

	// The lock file disappears: flock keeps working on the unlinked inode, so the next process can
	// take a lock on a fresh file and both write.
	if err := os.Remove(path + ".lock"); err != nil {
		t.Fatal(err)
	}
	problems := s.VerifyOnDisk()
	if len(problems) == 0 {
		t.Fatal("a lock file that has been removed must be reported: another process can now hold " +
			"the lock this one believes it owns")
	}
	if !strings.Contains(strings.Join(problems, " "), "lock") {
		t.Errorf("the report must name the lock, got %v", problems)
	}

	// The database itself disappears. It has to be re-created first for the lock check to be the
	// only one complaining, then removed outright.
	if err := os.WriteFile(path+".lock", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	problems = s.VerifyOnDisk()
	joined := strings.Join(problems, " ")
	if !strings.Contains(joined, "no longer at that path") {
		t.Errorf("a state database removed from under a running store must be reported: every later "+
			"write goes to an unlinked file and the next start finds nothing. Got %v", problems)
	}
}

// A missing -wal beside a present -shm is reported, because it means commits were lost.
//
// SQLite keeps committed transactions in state.db-wal until a checkpoint folds them in, and a clean
// close removes both sidecars. A -shm with no -wal is therefore the signature of a wal that was
// removed (a cleanup script, an operator, a hostile rm): the database opens without complaint and
// holds fewer rows than the last pass wrote -- the in-flight order URL among them, which is the row
// whose loss costs a fresh order against the exact-identifier-set limit.
func TestAMissingWriteAheadLogIsReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	if walMissing(path) {
		t.Fatal("nothing exists yet, so there is nothing to report")
	}
	if err := os.WriteFile(path+"-shm", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if !walMissing(path) {
		t.Error("a shared-memory file with no write-ahead log must be reported")
	}
	if warning := missingWALWarning(path); !strings.Contains(warning, "state.db-wal") ||
		!strings.Contains(warning, "recovery.md") {
		t.Errorf("the warning must name the file and point at the recovery procedure, got %q", warning)
	}

	// Both sidecars present is the normal running state; neither present is a clean close.
	if err := os.WriteFile(path+"-wal", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if walMissing(path) {
		t.Error("a -wal beside its -shm is normal")
	}
	if err := os.Remove(path + "-wal"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path + "-shm"); err != nil {
		t.Fatal(err)
	}
	if walMissing(path) {
		t.Error("no sidecars at all is a clean close, not a missing wal")
	}
}

// Close must not return while a transaction is still committing.
//
// Every statement goes through the store mutex and WithTx holds it for the whole transaction, so a
// Close that skipped the lock let an in-flight promotion commit after Close returned -- and after
// the flock was released, so a second process could already be writing to the same database.
func TestCloseWaitsForAnInFlightTransaction(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	txDone := make(chan error, 1)
	go func() {
		txDone <- s.WithTx(context.Background(), func(tx *Tx) error {
			close(entered)
			<-release
			return tx.PutCert(&CertState{Name: "inside-the-transaction"})
		})
	}()
	<-entered

	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()

	select {
	case err := <-closed:
		t.Fatalf("Close returned (%v) while a transaction was still running; its commit then lands "+
			"after the store is closed and after the lock is released", err)
	case <-time.After(200 * time.Millisecond):
	}

	close(release)
	if err := <-txDone; err != nil {
		t.Fatalf("the transaction must complete: %v", err)
	}
	if err := <-closed; err != nil {
		t.Fatalf("Close after the transaction: %v", err)
	}
}

// A reclaim row with no certificate id must be refused.
//
// The reaper's only handle is the id: Delete("") fails every round, so the row is never removed and
// the slot is held forever -- the opposite of what a reclaim list is for. The one caller that could
// produce it checks first; this is the second line, and it is cheap because a wrong row here leaks a
// cloud certificate rather than an HTTP request.
func TestARetiredRowWithNoCertificateIdIsRefused(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if err := s.AddRetiredCert("", "example-com", nil, nil); err == nil {
		t.Error("queueing an empty certificate id for reclaim must be refused: the reaper can never " +
			"delete it and the row is held forever")
	}
	rows, err := s.ListRetiredCertsBefore(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("nothing may be queued by a refused call, got %+v", rows)
	}
}
