package acme

import (
	"context"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/state"
)

// A challenge timestamp in the FUTURE means the clock stepped backwards, not that the write is
// still propagating. now.Sub(preparedAt) is then negative, and "younger than the propagation
// window" is true forever -- so the row (and the stale TXT it exists to reclaim) was kept until
// the clock caught up, which on a stepped clock can be never. A future timestamp must read as
// "age unknown, old enough", the same rule bindingCheckDue applies to its stored instant.
func TestAFutureChallengeTimestampDoesNotBlockReclaim(t *testing.T) {
	_, m, _, cert := newAPITestHarness(t, []string{"example.com"})
	m.dns = &fakeSolver{lookupFound: false, propagationTimeout: 5 * time.Minute}

	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return fixed }

	futureRow := &state.Authorization{
		CertName: cert.Name, AuthzURL: "https://ca.test/authz/future", Identifier: "example.com",
		ChallengeToken: "tok-1", ChallengePreparedAt: fixed.Add(10 * time.Minute),
	}
	got, err := m.reclaimUnpresentedTXT(context.Background(), futureRow)
	if err != nil || got != txtReclaimDone {
		t.Errorf("a timestamp ahead of the clock cannot be 'still propagating': got %v, err %v, want txtReclaimDone", got, err)
	}

	// The window still protects a genuinely fresh write: a denial proves nothing while the
	// record may not have reached the authoritative servers yet.
	freshRow := &state.Authorization{
		CertName: cert.Name, AuthzURL: "https://ca.test/authz/fresh", Identifier: "example.com",
		ChallengeToken: "tok-1", ChallengePreparedAt: fixed.Add(-time.Minute),
	}
	got, err = m.reclaimUnpresentedTXT(context.Background(), freshRow)
	if err != nil || got != txtReclaimKeptPropagating {
		t.Errorf("a one-minute-old write may still be propagating: got %v, err %v, want txtReclaimKeptPropagating", got, err)
	}
}
