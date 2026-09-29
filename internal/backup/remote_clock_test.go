package backup

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFutureDatedSnapshotName(t *testing.T) {
	past := time.Now().Add(-48 * time.Hour).UTC().Format(snapshotStamp)
	future := time.Now().Add(48 * time.Hour).UTC().Format(snapshotStamp)
	if futureDatedSnapshot("state.db.backup-" + past + ".db") {
		t.Error("an honest past stamp must not read as future")
	}
	if !futureDatedSnapshot("state.db.backup-" + future + ".db") {
		t.Error("a future stamp must be recognised")
	}
	if futureDatedSnapshot("state.db.backup-not-a-stamp.db") {
		t.Error("an unparseable stamp is not a future stamp")
	}
	// Collision suffix is not part of the timestamp.
	if !futureDatedSnapshot("state.db.backup-" + future + "~2.db") {
		t.Error("a future stamp with a collision suffix is still future")
	}
}

// The upload must not prune the recovery point it just published, whatever the
// clock says. After a forward step current's stamp is "future"; after a backward
// step it sorts as the oldest. Either way it survives -- including the signed
// path's second prune, where `current` is the .hmac sidecar and the snapshot
// must still be protected.
func TestPruneSFTPProtectsTheSnapshotItJustPublished(t *testing.T) {
	dir := t.TempDir()
	remoteDir := filepath.Join(dir, "remote")
	if err := os.Mkdir(remoteDir, 0o700); err != nil {
		t.Fatal(err)
	}
	addr, knownHosts, stop := startTestSFTP(t)
	defer stop()
	t.Setenv("WECERT_EDGE_SFTP_PASSWORD", "password")

	future := time.Now().Add(48 * time.Hour).UTC().Format(snapshotStamp)
	src := writeSnapshot(t, dir, "state.db.backup-"+future+".db", "just published")
	target := sftpTarget(addr, knownHosts, remoteDir, 1, []byte("sig-key"))
	if err := Upload(context.Background(), target, src); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	// The future-stamped object just published must still be there, with its sidecar.
	if _, err := os.Stat(filepath.Join(remoteDir, filepath.Base(src))); err != nil {
		t.Fatalf("the upload deleted the snapshot it just published: %v", err)
	}
	if _, err := os.Stat(filepath.Join(remoteDir, filepath.Base(src)+".hmac")); err != nil {
		t.Fatalf("the upload deleted the sidecar it just published: %v", err)
	}
}
