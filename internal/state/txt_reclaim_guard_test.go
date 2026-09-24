package state

import (
	"path/filepath"
	"testing"
	"time"
)

func TestMarkAndListStuckTXTReclaims(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	a := &Authorization{
		CertName: "www", AuthzURL: "https://acme.test/authz/1",
		Identifier: "www.example.com", TxtName: "_acme-challenge.www.example.com.",
		TxtValue: "v", ChallengeToken: "tok", Presented: true,
		ChallengePreparedAt: time.Now().Add(-time.Hour),
	}
	if err := s.PutAuthorization(a); err != nil {
		t.Fatal(err)
	}

	// Not stuck until a reclaim fails.
	rows, err := s.ListStuckTXTReclaims()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("queue must start empty, got %d", len(rows))
	}

	if err := s.MarkTXTReclaimStuck(a.CertName, a.AuthzURL, "ns unreachable"); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkTXTReclaimStuck(a.CertName, a.AuthzURL, "still unreachable"); err != nil {
		t.Fatal(err)
	}
	rows, err = s.ListStuckTXTReclaims()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 stuck row, got %d", len(rows))
	}
	e := rows[0]
	if e.Attempts != 2 {
		t.Errorf("attempts = %d, want 2", e.Attempts)
	}
	if e.LastError != "still unreachable" {
		t.Errorf("lastError = %q", e.LastError)
	}
	if e.StuckSince.IsZero() {
		t.Error("stuckSince must be set on the first failure")
	}

	// Clear drops it from the queue.
	if err := s.ClearTXTReclaimStuck(a.CertName, a.AuthzURL); err != nil {
		t.Fatal(err)
	}
	rows, err = s.ListStuckTXTReclaims()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("queue should be empty after clear, got %d", len(rows))
	}
}
