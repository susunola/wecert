package state

import (
	"os"
	"path/filepath"
	"testing"
)

// A restore that installed the snapshot but could not write its .restored
// notice must still be a success. Returning an error kept the pending file and
// made open() refuse to start, so a disk that filled up during the install
// looped the restore forever and piled up .replaced-* copies.
func TestRestoreSucceedsWhenNoticeCannotBeWritten(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "state.db.backup-20260101T000000.000Z.db")
	snap, err := OpenSealed(src, []byte("master"))
	if err != nil {
		t.Fatal(err)
	}
	if err := snap.PutAccount(&Account{Directory: "https://acme.example/d", KID: "kid", PrivateKeyPEM: []byte("KEY")}); err != nil {
		t.Fatal(err)
	}
	_ = snap.Close()

	dest := filepath.Join(dir, "state.db")
	// Occupy the marker path so writing the notice fails.
	if err := os.Mkdir(dest+RestoreMarkerSuffix, 0o700); err != nil {
		t.Fatal(err)
	}

	res, err := Restore(dest, src)
	if err != nil {
		t.Fatalf("a restore that installed the snapshot must succeed even if the notice fails: %v", err)
	}
	if res.NoticeWarning == "" {
		t.Error("the caller must be told the notice could not be written")
	}
	// The snapshot really is in place.
	installed, err := OpenSealed(dest, []byte("master"))
	if err != nil {
		t.Fatalf("restored database must open: %v", err)
	}
	defer installed.Close()
	account, err := installed.GetAccount("https://acme.example/d")
	if err != nil || string(account.PrivateKeyPEM) != "KEY" {
		t.Fatalf("restored account = %#v, %v", account, err)
	}
}
