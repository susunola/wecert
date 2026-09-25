package state

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("opening state db: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestIdentifierFailureLedgerCounts(t *testing.T) {
	s := newStore(t)
	now := time.Now().Truncate(time.Second)

	for i := 0; i < 3; i++ {
		if err := s.RecordIdentifierFailure("c1", "bad.example.com", "dns says no", now); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RecordIdentifierFailure("c1", "good.example.com", "one blip", now); err != nil {
		t.Fatal(err)
	}

	got, err := s.ListIdentifierFailures("c1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want two records, got %d", len(got))
	}
	// Sorted by identifier, so identical input yields identical output.
	if got[0].Identifier != "bad.example.com" || got[0].Failures != 3 {
		t.Errorf("first row = %+v, want bad.example.com with 3 failures", got[0])
	}
	if got[1].Identifier != "good.example.com" || got[1].Failures != 1 {
		t.Errorf("second row = %+v", got[1])
	}
	if !got[0].LastFailedAt.Equal(now) {
		t.Errorf("LastFailedAt = %v, want %v", got[0].LastFailedAt, now)
	}
}

// The ledger is isolated per certificate: one certificate's bad name must not affect
// another.
func TestIdentifierFailureLedgerIsPerCertificate(t *testing.T) {
	s := newStore(t)
	now := time.Now()

	if err := s.RecordIdentifierFailure("c1", "bad.example.com", "x", now); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListIdentifierFailures("c2")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("another certificate should not see this record, got %v", got)
	}
}

func TestClearIdentifierFailures(t *testing.T) {
	s := newStore(t)
	now := time.Now()

	if err := s.RecordIdentifierFailure("c1", "bad.example.com", "x", now); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearIdentifierFailures("c1"); err != nil {
		t.Fatal(err)
	}

	got, err := s.ListIdentifierFailures("c1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty after clearing, got %v", got)
	}
}

// Old records must be droppable: a name that was dropped will never be attempted again,
// so it can never wait for a success to clear it -- expiring is its only way out.
func TestPruneIdentifierFailuresDropsOnlyStaleRows(t *testing.T) {
	s := newStore(t)
	now := time.Now().Truncate(time.Second)

	if err := s.RecordIdentifierFailure("c1", "stale.example.com", "x", now.Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordIdentifierFailure("c1", "fresh.example.com", "x", now); err != nil {
		t.Fatal(err)
	}

	if err := s.PruneIdentifierFailures("c1", now, 24*time.Hour); err != nil {
		t.Fatal(err)
	}

	got, err := s.ListIdentifierFailures("c1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Identifier != "fresh.example.com" {
		t.Fatalf("only the fresh record should remain, got %v", got)
	}
}

func TestFallbackRoundTrip(t *testing.T) {
	s := newStore(t)
	now := time.Now().Truncate(time.Second)

	fb, err := s.GetFallback("c1")
	if err != nil {
		t.Fatal(err)
	}
	if fb != nil {
		t.Fatalf("want nil when there is no record, got %+v", fb)
	}

	if err := s.PutFallback(&Fallback{
		CertName: "c1",
		// Deliberately out of order: it should be sorted on write so reads are stable.
		Dropped: []string{"z.example.com", "a.example.com"},
		Since:   now,
		Reason:  "keeps failing",
	}); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetFallback("c1")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("the fallback record should be read back")
	}
	if len(got.Dropped) != 2 || got.Dropped[0] != "a.example.com" || got.Dropped[1] != "z.example.com" {
		t.Errorf("dropped names should be read back sorted, got %v", got.Dropped)
	}
	if !got.Since.Equal(now) {
		t.Errorf("Since = %v, want %v", got.Since, now)
	}
	if got.Reason != "keeps failing" {
		t.Errorf("Reason = %q", got.Reason)
	}

	if err := s.ClearFallback("c1"); err != nil {
		t.Fatal(err)
	}
	if again, err := s.GetFallback("c1"); err != nil || again != nil {
		t.Fatalf("want empty after clearing, got %+v, %v", again, err)
	}
}

// A nil record is an error, matching PutAuthorization and PutRateBucket: accepting it would panic
// on the dereference with the store mutex held, turning a caller bug into a crash.
func TestPutFallbackRefusesANilRecord(t *testing.T) {
	s := openTestStore(t)

	if err := s.PutFallback(nil); err == nil {
		t.Fatal("a nil fallback record must be refused")
	} else if !strings.Contains(err.Error(), "nil") {
		t.Errorf("the error must say what was wrong, got: %v", err)
	}

	// And the refusal must not get in the way of a real write.
	if err := s.PutFallback(&Fallback{CertName: "example-com", Dropped: []string{"www.example.com"}}); err != nil {
		t.Fatalf("PutFallback: %v", err)
	}
}
