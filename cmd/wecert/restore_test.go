package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/state"
)

// seedRestorableState leaves a state database with a snapshot of one certificate and a second
// certificate written afterwards -- the "restore me" situation, and one where the answer to "did the
// restore work?" is visible in the certificate list.
func seedRestorableState(t *testing.T) (cfg *config.Config, snapshotDir string) {
	t.Helper()
	dir := t.TempDir()
	snapshotDir = filepath.Join(dir, "snapshots")

	store, err := state.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := store.PutCert(&state.CertState{Name: "old-cert", KeyPEM: []byte("OLD")}); err != nil {
		t.Fatalf("PutCert: %v", err)
	}
	if _, err := store.Snapshot(snapshotDir, 3); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if err := store.PutCert(&state.CertState{Name: "new-cert", KeyPEM: []byte("NEW")}); err != nil {
		t.Fatalf("PutCert: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	return &config.Config{
		StatePath:   filepath.Join(dir, "state.db"),
		StateBackup: config.StateBackup{Dir: snapshotDir},
	}, snapshotDir
}

func certNames(t *testing.T, path string) []string {
	t.Helper()
	store, err := state.Open(path)
	if err != nil {
		t.Fatalf("Open %s: %v", path, err)
	}
	defer store.Close()
	names, err := store.ListCertNames()
	if err != nil {
		t.Fatalf("ListCertNames: %v", err)
	}
	return names
}

func TestRestoreStateAcceptsAFileADirectoryAndLatest(t *testing.T) {
	cfg, snapshotDir := seedRestorableState(t)
	snaps, err := state.SnapshotsIn(snapshotDir, cfg.StatePath)
	if err != nil {
		t.Fatalf("SnapshotsIn: %v", err)
	}
	if len(snaps) != 1 {
		t.Fatalf("expected one snapshot, got %v", snaps)
	}

	for _, tc := range []struct {
		name string
		arg  string
	}{
		{"a snapshot file", snaps[0]},
		{"the snapshot directory", snapshotDir},
		{"latest", "latest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := restoreState(cfg, tc.arg); err != nil {
				t.Fatalf("restoreState(%q): %v", tc.arg, err)
			}
			if got := certNames(t, cfg.StatePath); len(got) != 1 || got[0] != "old-cert" {
				t.Errorf("the restored database should hold the snapshot's certificate, got %v", got)
			}
			notice, err := state.LoadRestoreNotice(cfg.StatePath)
			if err != nil || notice == nil {
				t.Fatalf("the restore must leave a record: notice=%v err=%v", notice, err)
			}
			if !notice.CaveatApplies(time.Now()) {
				t.Error("a restore that just happened must still be inside the caveat window")
			}
		})
	}
}

func TestRestoreStateSaysWhatToDoWhenThereIsNoSnapshot(t *testing.T) {
	cfg, _ := seedRestorableState(t)
	// Point the snapshot directory at one that holds none of this store's snapshots: the operator
	// has to be told that nothing was touched, because the alternative is starting the daemon on a
	// database they believe was restored.
	cfg.StateBackup.Dir = t.TempDir()

	err := restoreState(cfg, "latest")
	if err == nil {
		t.Fatal("restoring with no snapshot available must fail")
	}
	for _, want := range []string{"no snapshots", "Nothing was changed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error should carry %q, got: %v", want, err)
		}
	}
	if got := certNames(t, cfg.StatePath); len(got) != 2 {
		t.Errorf("a failed restore must not touch the database, got %v", got)
	}
}

// The warning the next start prints is the only place the rate-limit cost of a restore is stated,
// and it has to disappear on its own once the longest window it is about has passed.
func TestTheRestoreWarningAppearsAndThenStops(t *testing.T) {
	cfg, _ := seedRestorableState(t)

	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))

	// Before any restore there is nothing to say.
	logRestoreNotice(log, cfg.StatePath, time.Now())
	if logs.Len() != 0 {
		t.Errorf("an ordinary start must not warn about a restore, got:\n%s", logs.String())
	}

	if err := restoreState(cfg, "latest"); err != nil {
		t.Fatalf("restoreState: %v", err)
	}
	logRestoreNotice(log, cfg.StatePath, time.Now())
	out := logs.String()
	for _, want := range []string{"restored from a snapshot", "rate-limit", "refuse one order"} {
		if !strings.Contains(out, want) {
			t.Errorf("the warning should carry %q, got:\n%s", want, out)
		}
	}

	// Past the window the ledger is whole again and the start is ordinary.
	logs.Reset()
	logRestoreNotice(log, cfg.StatePath, time.Now().Add(state.RestoreCaveatWindow+time.Hour))
	if logs.Len() != 0 {
		t.Errorf("after the window the restore is no longer news, got:\n%s", logs.String())
	}

	// An unreadable record is reported, not skipped: the question it answers is "may this database's
	// quota accounting be short", and silence would answer "no".
	if err := os.WriteFile(cfg.StatePath+state.RestoreMarkerSuffix, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	logs.Reset()
	logRestoreNotice(log, cfg.StatePath, time.Now())
	if !strings.Contains(logs.String(), "restore record that cannot be read") {
		t.Errorf("an unreadable restore record must be reported, got:\n%s", logs.String())
	}
}
