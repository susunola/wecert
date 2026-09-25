package acme

import (
	"testing"
	"time"
)

// The authorization-failure budget belongs to the IDENTIFIER, so a restart must re-arm the
// cooldown for every certificate carrying the name -- not just the one whose pass failed.
//
// The seed used to read only the asking certificate's own ledger rows, while the failure is
// recorded under whichever certificate happened to fail the validation: a restart then
// re-armed one certificate and let every OTHER certificate sharing the name straight through,
// and N certificates on one name spent the whole 5-per-hour budget one restart per round.
func TestARestartSeedsTheCooldownFromAnotherCertificatesFailure(t *testing.T) {
	store, m, _, cert := newAPITestHarness(t, []string{"shared.example.com"})

	// The failure is on the ledger under a DIFFERENT certificate; this manager's in-memory
	// map is empty, which is exactly the post-restart shape.
	if err := store.RecordIdentifierFailure("other-cert", "shared.example.com", "invalid", m.now()); err != nil {
		t.Fatal(err)
	}

	name, until, cooling := m.coolingDown(cert.Name, cert.Domains)
	if !cooling || name != "shared.example.com" {
		t.Fatalf("a failure another certificate recorded must still cool the shared name down, "+
			"got name=%q cooling=%v", name, cooling)
	}
	if want := m.now().Add(identifierCooldownFor); !until.After(m.now()) || until.After(want.Add(time.Minute)) {
		t.Errorf("the seeded cooldown should be about an hour out, got %s", until)
	}

	// A failure older than the window no longer holds the name back: the budget has refilled.
	old := m.now().Add(-2 * time.Hour)
	if err := store.RecordIdentifierFailure("other-cert", "aged.example.com", "invalid", old); err != nil {
		t.Fatal(err)
	}
	if _, _, cooling := m.coolingDown(cert.Name, []string{"aged.example.com"}); cooling {
		t.Error("a failure from two hours ago is outside the one-hour budget window; it must not seed")
	}
}
