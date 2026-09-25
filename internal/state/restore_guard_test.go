package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The restore guards are the last thing standing between a mistyped path and a live database with
// a hole in it, and each one answers a question that a plain "does the file exist" check cannot:
// is this really one of our snapshots, is the restore record readable, and is the staged copy the
// same bytes that were verified.

// LoadRestoreNotice: (nil, nil) means "this database was never restored". An unreadable or
// malformed record is an error instead, because the caller's next question is whether the
// rate-limit ledger came from an older database, and "no" on the strength of a broken file is the
// same mistake this project already made once with an unreadable quota bucket.
func TestLoadRestoreNoticeSeparatesAnAbsentRecordFromAnUnreadableOne(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.db")

	notice, err := LoadRestoreNotice(statePath)
	if err != nil || notice != nil {
		t.Fatalf("no record must be (nil, nil), got %+v, %v", notice, err)
	}

	if err := os.WriteFile(statePath+RestoreMarkerSuffix, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRestoreNotice(statePath); err == nil {
		t.Error("a malformed restore record must be an error: it is the only evidence of when the " +
			"ledger stopped")
	}

	if err := os.WriteFile(statePath+RestoreMarkerSuffix, []byte(`{"source":"/tmp/x.db"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRestoreNotice(statePath); err == nil {
		t.Error("a record with no timestamp must be refused: how old the restored ledger is cannot " +
			"be told from it")
	}

	restoredAt := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
	body := `{"restoredAt":"` + restoredAt.Format(time.RFC3339) + `","source":"/backup/state.db.backup-x.db"}`
	if err := os.WriteFile(statePath+RestoreMarkerSuffix, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	notice, err = LoadRestoreNotice(statePath)
	if err != nil {
		t.Fatalf("a complete record must load: %v", err)
	}
	if notice == nil || !notice.RestoredAt.Equal(restoredAt) {
		t.Errorf("notice = %+v, want RestoredAt %s", notice, restoredAt)
	}
	if !notice.CaveatApplies(time.Now()) {
		t.Error("a restore two hours old still carries the rate-limit caveat")
	}
	if !notice.CaveatApplies(restoredAt.Add(-time.Hour)) {
		t.Error("a clock that stepped backwards must not silence the warning: before the restore " +
			"instant the caveat applies too")
	}
	if notice.CaveatApplies(restoredAt.Add(RestoreCaveatWindow + time.Minute)) {
		t.Error("once the window has passed the caveat stops applying")
	}
	// The nil receiver is the ordinary "no record" case, and it must answer false rather than
	// panic on the path where nothing was ever restored.
	var absent *RestoreNotice
	if absent.CaveatApplies(time.Now()) {
		t.Error("no record means no caveat")
	}
}

// SnapshotsIn and IsSnapshotName are what the restore path uses when there is no store to ask:
// the ordinary reason to restore is that the state database cannot be opened at all.
func TestSnapshotsInListsOnlyThisDatabasesSnapshotsOldestFirst(t *testing.T) {
	dir := t.TempDir()
	stateBase := "state.db"
	ours := []string{
		"state.db.backup-20260101T000000.000Z.db",
		"state.db.backup-20260102T000000.000Z.db",
	}
	for _, name := range ours {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Everything below must be invisible to the restore path: a hand-made copy, a snapshot of a
	// different database, and a directory that merely looks like one.
	for _, name := range []string{
		"state.db.backup-before-upgrade.db",
		"other.db.backup-20260101T000000.000Z.db",
		"state.db",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "state.db.backup-20260103T000000.000Z.db"), 0o700); err != nil {
		t.Fatal(err)
	}

	snaps, err := SnapshotsIn(dir, filepath.Join(dir, stateBase))
	if err != nil {
		t.Fatalf("SnapshotsIn: %v", err)
	}
	if len(snaps) != 2 {
		t.Fatalf("SnapshotsIn = %v, want exactly this database's two snapshots", snaps)
	}
	if filepath.Base(snaps[0]) != ours[0] || filepath.Base(snaps[1]) != ours[1] {
		t.Errorf("SnapshotsIn = %v, want oldest first (%v)", snaps, ours)
	}

	if _, err := SnapshotsIn(filepath.Join(dir, "missing"), filepath.Join(dir, stateBase)); err == nil {
		t.Error("a directory that does not exist must be an error, not an empty list: the caller " +
			"reports \"no recovery point\" from that list")
	}

	valid := "state.db.backup-20260101T000000.000Z.db"
	if !IsSnapshotName(valid, stateBase) {
		t.Errorf("%s is one of ours", valid)
	}
	// The pre-separator form is still accepted: snapshots written before the separator changed
	// must keep counting as ours, or retention stops seeing them and they stay on disk forever.
	if !IsSnapshotName("state.db.backup-20260101T000000.000Z~2.db", stateBase) {
		t.Error("a collision suffix is part of the name, not of the timestamp: the file must keep " +
			"counting as ours, or retention stops seeing it and it stays on disk forever")
	}
	for _, name := range []string{"state.db.backup-before-upgrade.db", "state.db", "state.db.backup-.db"} {
		if IsSnapshotName(name, stateBase) {
			t.Errorf("%s must not be treated as a recovery point", name)
		}
	}
}

// InspectSnapshot proves a file is a wecert state database before it is allowed to replace one.
// Each rejection is a mistake an operator really makes: a truncated copy, a file that is not a
// database, and a well-formed SQLite file that belongs to something else.
func TestInspectSnapshotRefusesAnythingThatIsNotOneOfOurDatabases(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.db")
	store, err := Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	// Real PEM, like every other fixture here: inspectSnapshot decodes the material before it lets
	// a snapshot replace a database, so placeholder bytes make a sound snapshot look damaged and the
	// test would fail for a reason that has nothing to do with what it is checking.
	if err := store.PutCert(&CertState{Name: "example-com", KeyPEM: testCertKeyPEM}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Snapshot(dir, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	info, err := InspectSnapshot(snapshot)
	if err != nil {
		t.Fatalf("a snapshot this deployment wrote must inspect cleanly: %v", err)
	}
	if info.Certificates != 1 {
		t.Errorf("Certificates = %d, want the one certificate the snapshot holds", info.Certificates)
	}
	if info.Account {
		t.Error("no ACME account was registered, so the snapshot must not claim one")
	}

	if _, err := InspectSnapshot(filepath.Join(dir, "missing.db")); err == nil {
		t.Error("a missing file must be refused")
	}

	garbage := filepath.Join(dir, "garbage.db")
	if err := os.WriteFile(garbage, []byte("this is not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectSnapshot(garbage); err == nil {
		t.Error("a file that is not a database must be refused before SQLite is asked to open it")
	}

	short := filepath.Join(dir, "short.db")
	if err := os.WriteFile(short, []byte("SQLite"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectSnapshot(short); err == nil {
		t.Error("a truncated snapshot must be refused")
	}
}

// StagePendingRestore writes the verified bytes beside the live database for the next start. It
// runs while the daemon holds the lock, so the two things that matter are that it never touches
// the live file and that it refuses to stage anything it could not verify.
func TestStagePendingRestoreStagesOnlyAVerifiedRegularFile(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.db")
	store, err := Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.Snapshot(dir, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	live, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := StagePendingRestore("", snapshot); err == nil {
		t.Error("staging needs a destination")
	}
	if _, err := StagePendingRestore(statePath, ""); err == nil {
		t.Error("staging needs a source")
	}
	if _, err := StagePendingRestore(statePath, filepath.Join(dir, "missing.db")); err == nil {
		t.Error("a source that does not exist must be refused")
	}
	garbage := filepath.Join(dir, "garbage.db")
	if err := os.WriteFile(garbage, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := StagePendingRestore(statePath, garbage); err == nil {
		t.Error("an unverified source must never be staged: the next start would apply it")
	}

	link := filepath.Join(dir, "link.db")
	if err := os.Symlink(snapshot, link); err == nil {
		if _, err := StagePendingRestore(statePath, link); err == nil {
			t.Error("a symlinked source must be refused: the bytes that get staged are not the ones " +
				"the operator pointed at")
		}
	}

	pending, err := StagePendingRestore(statePath, snapshot)
	if err != nil {
		t.Fatalf("a verified snapshot must stage: %v", err)
	}
	if pending != statePath+restorePendingSuffix {
		t.Errorf("pending = %q, want %s%s", pending, statePath, restorePendingSuffix)
	}
	staged, err := os.ReadFile(pending)
	if err != nil {
		t.Fatalf("the staged file must exist: %v", err)
	}
	if len(staged) == 0 {
		t.Error("the staged file is empty")
	}
	if _, err := InspectSnapshot(pending); err != nil {
		t.Errorf("the staged copy must itself be a readable database: %v", err)
	}
	after, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(live) {
		t.Error("staging must not touch the live database: the daemon still has it open")
	}
}
