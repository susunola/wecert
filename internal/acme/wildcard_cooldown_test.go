package acme

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	legoacme "github.com/go-acme/lego/v4/acme"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/state"
)

// The phase-3 budget claim must name the identifier as the operator wrote it.
//
// Phase 3 of solveChallenges claims the identifier's failure budget (the in-memory
// cooldown) just before AcceptChallenge. It used to claim it under the authorization
// row's Identifier -- which for a wildcard is deliberately the BARE apex, because the
// apex and its wildcard share one TXT name -- while every other writer and the reading
// side (coolingDown) key on challenge.GetTargetedDomain, i.e. "*.example.com". The
// result: the wildcard's own budget was never cooled down, and the healthy apex of a
// DIFFERENT certificate was frozen for an hour by a failure it had nothing to do with.
func TestTheBudgetClaimNamesTheWildcardNotTheApex(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	// pending when the pass first looks, invalid once the CA has been asked to validate.
	fake := &fakeAPI{authzSeq: map[string][]legoacme.Authorization{
		"https://ca.test/authz/1": {
			{
				Status:     "pending",
				Identifier: legoacme.Identifier{Value: "example.com"}, Wildcard: true,
				Challenges: []legoacme.Challenge{{
					Type: "dns-01", Token: "tok-1", URL: "https://ca.test/chall/1",
				}},
			},
			{
				Status:     "invalid",
				Identifier: legoacme.Identifier{Value: "example.com"}, Wildcard: true,
				Challenges: []legoacme.Challenge{{
					Type: "dns-01", Token: "tok-1", URL: "https://ca.test/chall/1",
					Error: &legoacme.ProblemDetails{Detail: "dns is broken"},
				}},
			},
		},
	}}
	m := newManager(store, fake, &fakeSolver{}, fakeKeyAuth{}, deploy.Noop{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	cert := &config.Certificate{Name: "c", Domains: []string{"*.example.com"}}
	order := legoacme.ExtendedOrder{
		Order:    legoacme.Order{Status: "pending", Authorizations: []string{"https://ca.test/authz/1"}},
		Location: "https://ca.test/order/1",
	}
	if err := m.solveChallenges(context.Background(), cert, &state.CertState{Name: "c"}, order); err == nil {
		t.Fatal("the invalid authorization must fail the pass")
	}

	// The wildcard is cooling down...
	if name, _, cooling := m.coolingDown("c", []string{"*.example.com"}); !cooling || name != "*.example.com" {
		t.Errorf("the wildcard's failed validation must cool \"*.example.com\" down, got name=%q cooling=%v",
			name, cooling)
	}
	// ...and the bare apex is not: another certificate for the apex alone must keep ordering.
	if name, _, cooling := m.coolingDown("other-cert", []string{"example.com"}); cooling {
		t.Errorf("the apex was cooled down by the wildcard's failed validation (name %q); "+
			"the apex and its wildcard share a TXT name but not a failure budget", name)
	}
}
