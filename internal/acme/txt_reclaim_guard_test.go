package acme

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/state"
)

// errTestCleanFail is a provider CleanUp that never confirms.
var errTestCleanFail = errors.New("provider cannot delete this record")

// The guardian retries stuck rows even when the certificate is not walked this pass.
func TestSweepStuckTXTRetriesAndClearsProvenAbsent(t *testing.T) {
	solver := &fakeSolver{lookupFound: false}
	m, store := newTestManager(t, solver, fakeKeyAuth{})

	prepared := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return prepared.Add(2 * time.Hour) })

	if err := store.PutAuthorization(&state.Authorization{
		CertName: "c", AuthzURL: "authz-1", Identifier: "example.com",
		ChallengeToken: "tok-1", Presented: false, ChallengePreparedAt: prepared,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTXTReclaimStuck("c", "authz-1", "ns unreachable"); err != nil {
		t.Fatal(err)
	}

	// Fake denies the record and the challenge is past the window: proven absent -> clear.
	retried, cleared, err := m.SweepStuckTXT(context.Background())
	if err != nil {
		t.Fatalf("SweepStuckTXT: %v", err)
	}
	if retried != 1 || cleared != 1 {
		t.Fatalf("retried=%d cleared=%d, want 1/1", retried, cleared)
	}
	if rows, _ := store.ListStuckTXTReclaims(); len(rows) != 0 {
		t.Errorf("queue should be empty, got %d", len(rows))
	}
	if as, _ := store.ListAuthorizations("c"); len(as) != 0 {
		t.Errorf("the reclaimed row should be deleted, %d remain", len(as))
	}
}

// A presented row whose cleanup cannot confirm stays on the queue with a fresh stamp.
func TestSweepStuckTXTKeepsUnconfirmedPresentedRow(t *testing.T) {
	solver := &fakeSolver{lookupFound: true, cleanErr: errTestCleanFail}
	m, store := newTestManager(t, solver, fakeKeyAuth{})

	if err := store.PutAuthorization(&state.Authorization{
		CertName: "c", AuthzURL: "authz-1", Identifier: "example.com",
		ChallengeToken: "tok-1", TxtName: "_acme-challenge.example.com.", TxtValue: "v",
		Presented: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkTXTReclaimStuck("c", "authz-1", "clean failed"); err != nil {
		t.Fatal(err)
	}

	retried, cleared, err := m.SweepStuckTXT(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if retried != 1 || cleared != 0 {
		t.Fatalf("retried=%d cleared=%d, want 1/0", retried, cleared)
	}
	rows, err := store.ListStuckTXTReclaims()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("row must stay stuck, got %d", len(rows))
	}
	if rows[0].Attempts < 2 {
		t.Errorf("attempts = %d, want at least 2 (mark + sweep failure)", rows[0].Attempts)
	}
}
