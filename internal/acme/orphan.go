package acme

import "context"

// CleanupOrphan reclaims everything an in-flight issuance left behind for a
// certificate that is no longer in the desired state: the challenge TXT records
// in DNS, then the order and authorization rows in the state store.
//
// The order cannot be reversed, and the authorization row (TxtName /
// ChallengeToken / TxtValue) is the only clue for reclaiming DNS, so the TXT
// records must come down before the rows go away -- that sequencing is exactly
// what discardOrder already guarantees, and this method is that teardown
// exposed for callers that manage the desired-state lifecycle (the orphan path
// in the reconcile loop) rather than an order.
//
// Without it, removing a certificate mid-order leaks its challenge leases: the
// _acme-challenge rows stay on DNSPod forever, and because a wildcard and its
// apex share one TXT name, a stale value poisons every later order that writes
// the same name. A certificate with no order and no leftover authorizations is
// a no-op.
func (m *Manager) CleanupOrphan(ctx context.Context, certName string) error {
	return m.discardOrder(ctx, certName)
}
