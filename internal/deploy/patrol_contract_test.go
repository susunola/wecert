package deploy

import (
	"testing"

	"github.com/susunola/wecert/internal/config"
)

// The account-wide patrol is reached through a duck-typed assertion (internal/acme's
// bindingPatroller), so a deployer that forwards Deploy and Bindings but not PatrolBindings does
// not fail loudly: the patrol reports "no findings", the binding memo the console reads is never
// filled, and the page silently falls back to "Deployment record only".
//
// That is what enforce mode did for as long as its deployer was *LazyTencentCLB, and it is the
// reason this test exists rather than a comment: the assertion has to happen where a missing
// method is a compile error, not at run time where it looks like an empty answer.
func TestDeployersImplementThePatrolContract(t *testing.T) {
	t.Parallel()

	if _, ok := any((*TencentCLB)(nil)).(patrolContract); !ok {
		t.Error("*TencentCLB must implement PatrolBindings")
	}
	lazy := NewLazyTencentCLB(config.Tencent{}, nil)
	if _, ok := any(lazy).(patrolContract); !ok {
		t.Error("*LazyTencentCLB must forward PatrolBindings: enforce mode uses this deployer, and " +
			"without the forward the console loses every binding detail of a confirmed certificate")
	}
}

// Noop is the opposite case and has to stay that way: nothing is deployed, so there is nothing to
// patrol, and the caller should skip the account-wide enumeration instead of inventing findings.
func TestNoopIsNotAPatroller(t *testing.T) {
	t.Parallel()
	if _, ok := any(Noop{}).(patrolContract); ok {
		t.Error("Noop must not look like a patroller: with nothing deployed there is nothing to audit")
	}
}
