package deploy

import (
	"context"
	"errors"
	"testing"
)

// Compile-time interface check.
//
// Noop is selected by deploy.enabled=false, which is the normal configuration for the
// acceptance case and for anyone who only wants the certificate material on disk. If the
// Deployer interface gains a method, this assertion fails at build time instead of leaving
// Noop silently non-conforming.
var _ Deployer = Noop{}

// With deployment disabled, Deploy must hand back the ID it was given.
//
// It must not invent an ID, and it must not return an empty string in place of a real one:
// the caller records this value as DeployedCertID, and the reaper later uses it to decide
// whether there is a cloud certificate to reclaim. A fabricated or dropped ID would send
// the reaper after something that does not exist, or leave a real certificate untracked.
func TestNoopDeployReturnsTheIDItWasGiven(t *testing.T) {
	var n Noop

	got, err := n.Deploy(context.Background(), "cert", "apJRqDsC", []byte("cert-pem"), []byte("key-pem"))
	if err != nil {
		t.Fatalf("Deploy must not fail when deployment is disabled: %v", err)
	}
	if got != "apJRqDsC" {
		t.Errorf("Deploy returned %q, want the old ID %q unchanged", got, "apJRqDsC")
	}
}

// First issuance has no old ID. That is a normal state, not an error.
func TestNoopDeployAcceptsAnEmptyOldID(t *testing.T) {
	var n Noop

	got, err := n.Deploy(context.Background(), "cert", "", nil, nil)
	if err != nil {
		t.Fatalf("Deploy with an empty old ID must not fail: %v", err)
	}
	if got != "" {
		t.Errorf("Deploy returned %q, want the empty old ID unchanged", got)
	}
}

// Deleting a certificate that was never uploaded is a no-op.
//
// An empty ID cannot identify anything on the cloud side, so there is nothing to reclaim
// and nothing to warn about. Returning an error here would make the reaper retry a queue
// entry that can never succeed.
func TestNoopDeleteOfAnEmptyIDIsANoOp(t *testing.T) {
	var n Noop

	if err := n.Delete(context.Background(), ""); err != nil {
		t.Errorf("Delete(\"\") returned %v, want nil: an empty ID identifies nothing", err)
	}
}

// This is the one that matters. Delete must NOT report success for a real certificate ID.
//
// Noop performs no remote operation, so a certificate that does exist in Tencent Cloud
// cannot be removed while deployment is disabled. Returning nil here would make the reaper
// believe the certificate was deleted and drop its queue entry -- while the certificate
// keeps occupying the account's upload quota forever. Quota exhaustion is what stops
// renewal, so a silent leak here eventually breaks the whole system.
//
// ErrDeploymentDisabled is distinct from a generic failure on purpose: the caller is
// expected to keep the retry state, and a future re-enable of deployment should be able to
// clear the backlog.
func TestNoopDeleteOfARealIDReportsDeploymentDisabled(t *testing.T) {
	var n Noop

	err := n.Delete(context.Background(), "apJdfyPa")
	if err == nil {
		t.Fatal("Delete reported success for a real certificate ID; the reaper would drop " +
			"its queue entry and the cloud certificate would leak forever")
	}
	if !errors.Is(err, ErrDeploymentDisabled) {
		t.Errorf("Delete returned %v, want ErrDeploymentDisabled so callers can keep retrying", err)
	}
}

// Nothing is deployed anywhere, so nothing can be bound.
func TestNoopBindingsIsZero(t *testing.T) {
	var n Noop

	got, _, err := n.Bindings(context.Background(), "cert")
	if err != nil {
		t.Fatalf("Bindings must not fail when deployment is disabled: %v", err)
	}
	if got != 0 {
		t.Errorf("Bindings = %d, want 0: deployment is disabled, so nothing is bound", got)
	}
}
