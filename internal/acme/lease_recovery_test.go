package acme

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"

	"github.com/susunola/wecert/internal/state"
)

// A challenge name can be shared by two certificates: certificate names are deduplicated by
// the config, domains are not. lego's provider CleanUp deletes **every** TXT record at the
// name, so the lease registry (challengeLeases) is what keeps one certificate's cleanup from
// wiping a sibling's live challenge.
//
// The registry only knows the values *this process* wrote. A row recovered from a previous
// process -- the pass that wrote the record died before it could mark Presented -- is a live
// value the registry cannot see, so cleanup would find "no other live values" and delete it
// out from under a pending challenge, burning the per-identifier authorization-failure quota.
//
// cleanup must therefore re-register the presented rows before removing anything.
func TestCleanupKeepsARecoveredSiblingsTXTAlive(t *testing.T) {
	// GetChallengeInfo chases the CNAME over the network unless this is set.
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")

	// The registry is package state; give this test a private one so the assertion does not
	// depend on what other tests wrote.
	saved := challengeLeases
	challengeLeases = newTXTLeases()
	t.Cleanup(func() { challengeLeases = saved })

	provider := &recordingProvider{}
	solver := &DNSSolver{
		newProvider: func(context.Context) (challenge.Provider, error) { return provider, nil },
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	m, store := newTestManager(t, solver, fakeKeyAuth{})

	// Both authorizations point at the same challenge name; their key authorizations hash to
	// two different TXT values.
	const domain = "shared.example.com"
	fqdn := dns01.GetChallengeInfo(domain, "keyauth(tok-b)").EffectiveFQDN
	recoveredValue := dns01.GetChallengeInfo(domain, "keyauth(tok-b)").Value
	liveValue := dns01.GetChallengeInfo(domain, "keyauth(tok-a)").Value

	// Certificate B's row survives from a pass that died before cleaning up: its record is
	// still in DNS, but this process never wrote it.
	recovered := &state.Authorization{
		CertName:       "cert-b",
		AuthzURL:       "https://acme.example/authz/b",
		Identifier:     domain,
		TxtName:        fqdn,
		TxtValue:       recoveredValue,
		ChallengeToken: "tok-b",
		Presented:      true,
	}
	seedOrderWithAuthzs(t, store, "cert-b", []*state.Authorization{recovered})

	// Certificate A is being cleaned up now, at that same name.
	live := &state.Authorization{
		CertName:       "cert-a",
		AuthzURL:       "https://acme.example/authz/a",
		Identifier:     domain,
		TxtName:        fqdn,
		TxtValue:       liveValue,
		ChallengeToken: "tok-a",
		Presented:      true,
	}

	m.cleanup(context.Background(), "cert-a", []*state.Authorization{live})

	if len(provider.cleanups) != 0 {
		t.Fatalf("cleanup deleted every TXT at %s while cert-b's recovered value was still live: %v",
			fqdn, provider.cleanups)
	}
	if live.Presented {
		t.Error("cert-a's own record was dealt with, so its row must be marked not-presented")
	}
	rows, err := store.ListAuthorizations("cert-b")
	if err != nil {
		t.Fatalf("ListAuthorizations: %v", err)
	}
	if len(rows) != 1 || !rows[0].Presented {
		t.Errorf("the recovered row must be left untouched, got %+v", rows)
	}
}
