package backup

import (
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
