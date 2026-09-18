package acme

import (
	"strings"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/state"
)

// The reason string must not print a negative duration.
//
// The fallback can be entered with an already-expired certificate -- "keep most names alive" is
// the whole point when the full set cannot issue -- and `left` is then negative, so the log used
// to read "expires in -72h0m0s". That buries the one fact the reader most needs: there is no
// valid certificate left at all.
func TestFallbackReasonSaysExpiredRatherThanANegativeDuration(t *testing.T) {
	store, m, cert, now := fallbackFixture(t, fallbackPolicyPtr())

	for i := 0; i < 3; i++ {
		if err := store.RecordIdentifierFailure(cert.Name, "b.example.com", "dns says no", now); err != nil {
			t.Fatal(err)
		}
	}
	st := &state.CertState{
		Name:                cert.Name,
		NotAfter:            now.Add(-3 * 24 * time.Hour), // expired three days ago
		ConsecutiveFailures: 9,
	}

	_, dropped, reason := m.fallbackDomains(cert, st, false)
	if len(dropped) == 0 {
		t.Fatal("an expired certificate with a repeatedly failing name must fall back")
	}
	if strings.Contains(reason, "expires in -") {
		t.Errorf("a negative duration reads as a bug, not as a state: %q", reason)
	}
	if !strings.Contains(reason, "expired") {
		t.Errorf("the reason must say the certificate has already expired, got: %q", reason)
	}
}
