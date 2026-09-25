package acme

import (
	"context"
	"errors"
	"testing"

	legoacme "github.com/go-acme/lego/v4/acme"

	"github.com/susunola/wecert/internal/state"
)

// A pass that finds the authorization ALREADY valid on entry must clear the identifier's
// cooldown, exactly like the awaitAuthorizations poll does when it observes the transition.
//
// The two paths see the same fact at different times: an authorization that failed in one pass
// (booking the cooldown) and stands valid when the next pass first looks never goes through the
// polling loop -- so without the phase-1 clear, a validated name kept its cooldown until it
// expired on its own, and the certificate's next order was refused for up to an hour over a
// failure that had already been proven wrong.
func TestAPhaseOneValidClearsTheIdentifiersCooldown(t *testing.T) {
	_, m, fake, cert := newAPITestHarness(t, []string{"example.com"})

	// First look: invalid (books the cooldown). Second look: valid.
	fake.authzSeq = map[string][]legoacme.Authorization{
		"https://ca.test/authz/1": {
			{
				Status:     "invalid",
				Identifier: legoacme.Identifier{Value: "example.com"},
				Challenges: []legoacme.Challenge{{
					Type: "dns-01", Token: "tok-1", URL: "https://ca.test/chall/1",
					Error: &legoacme.ProblemDetails{Detail: "dns is broken"},
				}},
			},
			{
				Status:     "valid",
				Identifier: legoacme.Identifier{Value: "example.com"},
				Challenges: []legoacme.Challenge{{
					Type: "dns-01", Token: "tok-1", URL: "https://ca.test/chall/1",
				}},
			},
		},
	}
	order := legoacme.ExtendedOrder{
		Order:    legoacme.Order{Status: "pending", Authorizations: []string{"https://ca.test/authz/1"}},
		Location: "https://ca.test/order/1",
	}
	st := &state.CertState{Name: cert.Name}

	if err := m.solveChallenges(context.Background(), cert, st, order); err == nil {
		t.Fatal("the invalid authorization must fail the first pass")
	}
	assertCooling := func(want bool, when string) {
		t.Helper()
		m.identifierMu.Lock()
		_, cooling := m.identifierCooldown["example.com"]
		m.identifierMu.Unlock()
		if cooling != want {
			t.Errorf("%s: identifierCooldown[example.com] present=%v, want %v", when, cooling, want)
		}
	}
	assertCooling(true, "after the failed pass")

	// The next pass sees the authorization valid on entry: phase 1, not the polling loop.
	if err := m.solveChallenges(context.Background(), cert, st, order); err != nil {
		t.Fatalf("the recovered authorization must pass: %v", err)
	}
	assertCooling(false, "once the authorization validates")
}

// The phase-3 budget claim is deliberately check-then-act-proof: it is taken BEFORE
// AcceptChallenge. But a request that never reached the CA spent nothing, so a pure transport
// failure must withdraw the claim -- otherwise one network hiccup freezes the identifier (and
// every certificate sharing it) for an hour.
func TestATransportFailureReleasesTheBudgetClaim(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	// A dial failure: no HTTP status, no ACME problem detail, the CA never saw the request.
	fake.acceptErr = errors.New("dial tcp 203.0.113.1:443: i/o timeout")

	const authzURL = "https://ca.test/authz/1"
	fake.authzByURL = map[string]legoacme.Authorization{
		authzURL: {
			Status:     "pending",
			Identifier: legoacme.Identifier{Value: "example.com"},
			Challenges: []legoacme.Challenge{{
				Type: "dns-01", Token: "tok-1", URL: "https://ca.test/chall/1",
			}},
		},
	}
	order := legoacme.ExtendedOrder{
		Order:    legoacme.Order{Status: "pending", Authorizations: []string{authzURL}},
		Location: "https://ca.test/order/1",
	}

	if err := m.solveChallenges(context.Background(), cert, &state.CertState{Name: cert.Name}, order); err == nil {
		t.Fatal("a failed AcceptChallenge must fail the pass")
	}
	if len(fake.accepted) != 1 {
		t.Fatalf("the challenge must have been offered to the CA exactly once, got %v", fake.accepted)
	}
	// The claim is withdrawn, so the name is free to order again immediately...
	if _, _, cooling := m.coolingDown(cert.Name, cert.Domains); cooling {
		t.Error("the CA was never reached, so nothing was spent: the identifier must not cool down")
	}
	// ...and no failure was booked against it anywhere else either.
	if fails, err := store.ListIdentifierFailures(cert.Name); err != nil || len(fails) != 0 {
		t.Errorf("a transport failure is not the identifier's fault, ledger must stay empty: %+v, %v", fails, err)
	}
}

// The other half of the contract: when the CA DID answer and refused, the claim stands --
// the request arrived, so the budget may genuinely be spent.
func TestACARefusalKeepsTheBudgetClaim(t *testing.T) {
	_, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	fake.acceptErr = &legoacme.ProblemDetails{
		HTTPStatus: 400, Type: "urn:ietf:params:acme:error:malformed", Detail: "challenge unacceptable",
	}

	const authzURL = "https://ca.test/authz/1"
	fake.authzByURL = map[string]legoacme.Authorization{
		authzURL: {
			Status:     "pending",
			Identifier: legoacme.Identifier{Value: "example.com"},
			Challenges: []legoacme.Challenge{{
				Type: "dns-01", Token: "tok-1", URL: "https://ca.test/chall/1",
			}},
		},
	}
	order := legoacme.ExtendedOrder{
		Order:    legoacme.Order{Status: "pending", Authorizations: []string{authzURL}},
		Location: "https://ca.test/order/1",
	}

	if err := m.solveChallenges(context.Background(), cert, &state.CertState{Name: cert.Name}, order); err == nil {
		t.Fatal("a refused AcceptChallenge must fail the pass")
	}
	if _, _, cooling := m.coolingDown(cert.Name, cert.Domains); !cooling {
		t.Error("the CA answered, so the budget may be spent: the identifier must keep its cooldown")
	}
}
