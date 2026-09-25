package state

import (
	"path/filepath"
	"testing"
	"time"
)

// The identifier cut of the failure ledger must see every certificate's rows for the name:
// the budget it feeds belongs to the identifier, not to whichever certificate recorded the
// failure.
func TestListIdentifierFailuresByIdentifierCrossesCertificates(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	now := time.Now()
	if err := store.RecordIdentifierFailure("cert-a", "shared.example.com", "first", now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordIdentifierFailure("cert-b", "shared.example.com", "second", now); err != nil {
		t.Fatal(err)
	}
	// An unrelated identifier under the same certificates must not leak into the answer.
	if err := store.RecordIdentifierFailure("cert-a", "other.example.com", "noise", now); err != nil {
		t.Fatal(err)
	}

	rows, err := store.ListIdentifierFailuresByIdentifier("shared.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("want both certificates' rows for the shared identifier, got %+v", rows)
	}
	// Sorted by certificate name, like ListIdentifierFailures is by identifier.
	if rows[0].CertName != "cert-a" || rows[1].CertName != "cert-b" {
		t.Fatalf("rows must come back sorted by certificate name, got %+v", rows)
	}
	if rows[0].Identifier != "shared.example.com" || rows[1].Identifier != "shared.example.com" {
		t.Errorf("every row must be for the queried identifier, got %+v", rows)
	}
	if !rows[1].LastFailedAt.After(rows[0].LastFailedAt) {
		t.Errorf("the rows must carry their own failure instants, got %+v", rows)
	}

	none, err := store.ListIdentifierFailuresByIdentifier("never-failed.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Errorf("an identifier nobody failed must have no rows, got %+v", none)
	}
}
