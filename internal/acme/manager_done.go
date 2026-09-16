package acme

import (
	"context"
	"errors"
	"fmt"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/state"
)

// download downloads and verifies the certificate, then deploys it and advances the state.
//
// The ordering here is deliberate: until the deploy succeeds, never overwrite the
// certificate and private key currently in effect in CertState. Otherwise a failed deploy
// leaves nothing to roll back to.
func (m *Manager) download(
	ctx context.Context, c *config.Certificate, st *state.CertState,
	o *state.Order, order legoacme.ExtendedOrder,
) error {
	if order.Certificate == "" {
		return m.recordFailure(st, errors.New("the order is valid but has no certificate URL"))
	}

	// Idempotent backstop: the order's certificate is already the live one, which means the
	// previous round's "download + deploy" actually succeeded and only the finishing move
	// (discarding the order) never completed.
	//
	// Going any further would trip the notAfter gate below -- a new certificate cannot be
	// newer than itself -- so every round would log an error and back off to 6 hours,
	// reporting one successful renewal as a persistent fault with consecutive_failures
	// climbing until a human has to intervene. The outcome is already the desired state, so
	// just finish up.
	if st.CertURL != "" && st.CertURL == order.Certificate && !st.NotAfter.IsZero() {
		m.log.Info("the order's certificate is already the live one; skipping the duplicate deploy",
			"cert", c.Name, "certUrl", order.Certificate)
		if !st.DeployConfirmed && c.Deploy.Enabled {
			m.log.Warn("but this certificate is not confirmed deployed to a cloud resource; check that the CLB listener has it bound",
				"cert", c.Name, "deployedCertId", st.DeployedCertID)
		}
		return m.discardOrder(ctx, c.Name)
	}

	// bundle=true returns the fullchain (leaf + intermediate certificates), which is exactly
	// the format CLB needs.
	fullchain, _, err := m.core.GetCertificate(order.Certificate, true)
	if err != nil {
		return m.recordFailure(st, fmt.Errorf("download certificate: %w", err))
	}

	leaf, err := ParseLeaf(fullchain)
	if err != nil {
		return m.recordFailure(st, err)
	}

	if err := VerifyCoverage(leaf, c.Domains); err != nil {
		return m.recordFailure(st, err)
	}
	if !st.NotAfter.IsZero() && !leaf.NotAfter.After(st.NotAfter) {
		return m.recordFailure(st, fmt.Errorf(
			"the new certificate's notAfter (%s) is not later than the current one (%s); refusing to deploy", leaf.NotAfter, st.NotAfter))
	}
	if len(o.KeyPEM) == 0 {
		return m.recordFailure(st, errors.New("the order has no private key; cannot deploy"))
	}

	// Deploy. On a first issuance DeployedCertID is empty, so this only uploads and waits
	// for a human to bind it once in the CLB console. A successful upload does not mean the
	// listener is bound: DeployConfirmed is only set once the one-click update has really
	// finished switching over.
	oldDeployedID := st.DeployedCertID
	deployedID := oldDeployedID
	rebound := false
	if c.Deploy.Enabled {
		id, derr := m.deployer.Deploy(ctx, c.Name, oldDeployedID, fullchain, o.KeyPEM)
		if derr != nil {
			// The Deployer contract is: on error it still returns the ID of the certificate
			// that was uploaded successfully (see Deploy in internal/deploy/tencent.go). That
			// ID must be recorded in the reclaim list -- otherwise it is in neither the
			// certificates table nor the retired table, ReapRetired never sees it, and one
			// failure leaks one certificate in Tencent Cloud until the account quota is hit.
			// The reclaim machinery exists precisely to prevent that.
			m.recordOrphanCert(id, oldDeployedID, c.Name)
			return m.recordFailure(st, fmt.Errorf("deploy to Tencent Cloud: %w", derr))
		}
		deployedID = id
		rebound = oldDeployedID != ""
	} else {
		// A local-only renewal must never claim the older cloud certificate is this
		// newly issued one: keeping DeployConfirmed would make the deployed metric
		// green and point the network probe at a certificate that is no longer the
		// one in state.
		//
		// The ID is dropped rather than queued for reclaim. Reclaiming it is
		// tempting -- it is the only local record that a wecert-uploaded certificate
		// exists in Tencent Cloud -- but the certificate may still be bound to a
		// listener, and with deploy switched off wecert has no evidence either way.
		// The reaper would delete it and rely on IsCheckResource to refuse a bound
		// certificate; when that check is the only thing between a bookkeeping
		// cleanup and production HTTPS, the conservative direction is to leave it
		// alone. See TestLocalOnlyRenewalClearsDeploymentStateWithoutRetiringLiveCloudCert.
		//
		// So the ID goes to the journal instead of being lost silently. It is worth
		// logging: the leak is bounded (oldDeployedID is empty from the next renewal
		// on, so at most one certificate per name can be stranded), but nothing else
		// in the system will ever mention it again.
		if oldDeployedID != "" {
			m.log.Warn("deploy is disabled for this certificate: the cloud certificate it was previously bound to is now unmanaged, "+
				"and is left in place because it may still be serving traffic",
				"cert", c.Name, "certId", oldDeployedID,
				"hint", "if it is no longer needed, delete it from the Tencent Cloud console or with wecert-preflight prune")
		}
		deployedID = ""
		st.DeployConfirmed = false
	}

	ariCertID, err := CertID(leaf)
	if err != nil {
		// ARI being unavailable must not block issuance; it only costs us the rate-limit
		// exemption.
		m.log.Warn("could not build the ARI certID; this renewal will go out without replaces", "cert", c.Name, "err", err)
	}

	// The deploy succeeded; only now is the new certificate promoted to the live version.
	st.NotAfter = leaf.NotAfter
	st.CertURL = order.Certificate
	st.CertPEM = fullchain
	st.KeyPEM = o.KeyPEM
	st.IssuedAt = m.now()
	st.DeployedCertID = deployedID
	if rebound {
		st.DeployConfirmed = true
	} else if oldDeployedID == "" {
		// First upload: record the CertId so a human can bind it, but the metric should still
		// read "not deployed".
		st.DeployConfirmed = false
	}
	st.ARICertID = ariCertID
	st.ARIWindowStart = time.Time{}
	st.ARIWindowEnd = time.Time{}
	st.ARICheckedAt = time.Time{}
	st.ARIRetryAfter = 0
	st.ConsecutiveFailures = 0
	st.NextAttemptAt = time.Time{}
	st.LastError = ""

	if err := m.store.PutCert(st); err != nil {
		return err
	}

	// Only once the switch from the old certificate to the new one is confirmed does the old
	// one go on the reclaim list. On a first upload nothing is bound to a listener yet, and
	// retiring it would delete, 7 days later, the very certificate a human just bound.
	if rebound && oldDeployedID != "" && oldDeployedID != deployedID {
		if err := m.store.AddRetiredCert(oldDeployedID, c.Name); err != nil {
			m.log.Warn("failed to record the certificate for reclaim", "cert", c.Name, "certId", oldDeployedID, "err", err)
		}
	}

	if err := m.discardOrder(ctx, c.Name); err != nil {
		return err
	}

	// After a successful issuance, and only if we are not degraded right now, clear the
	// per-identifier failure ledger.
	//
	// The ledger means "who has been broken lately", not "who has ever been broken". Keeping
	// it would let a long-since-fixed fault keep that name out of the certificate forever --
	// and because a dropped name is never tried again, it can never earn the one success that
	// would clear its name.
	if fb, err := m.store.GetFallback(c.Name); err == nil && fb == nil {
		if cerr := m.store.ClearIdentifierFailures(c.Name); cerr != nil {
			m.log.Warn("cannot clear the identifier failure ledger", "cert", c.Name, "err", cerr)
		}
	}

	if !c.Deploy.Enabled {
		m.log.Info("certificate issued and recorded locally (cloud deploy is off)",
			"cert", c.Name, "notAfter", st.NotAfter,
			"daysLeft", int(time.Until(st.NotAfter).Hours()/24))
	} else if !st.DeployConfirmed {
		m.log.Info("certificate uploaded; waiting for a one-time manual bind in the CLB console",
			"cert", c.Name, "notAfter", st.NotAfter,
			"uploadedCertId", deployedID,
			"hint", "once bound, later renewals switch it automatically via UpdateCertificateInstance")
	} else {
		m.log.Info("certificate renewed and live",
			"cert", c.Name, "notAfter", st.NotAfter,
			"daysLeft", int(time.Until(st.NotAfter).Hours()/24),
			"deployedCertId", deployedID, "ariCertId", ariCertID != "")
	}
	return nil
}

// ReapRetired reclaims retired certificates that are past the retention period.
func (m *Manager) ReapRetired(ctx context.Context) {
	retired, err := m.store.ListRetiredCertsBefore(m.now().Add(-m.retention))
	if err != nil {
		m.log.Warn("failed to list retired certificates", "err", err)
		return
	}
	for _, r := range retired {
		if err := m.deployer.Delete(ctx, r.CertID); err != nil {
			m.log.Warn("failed to reclaim a retired certificate", "certId", r.CertID, "cert", r.CertName, "err", err)
			continue
		}
		m.log.Info("reclaimed a retired certificate",
			"certId", r.CertID, "cert", r.CertName, "retiredAt", r.RetiredAt)
		if err := m.store.DeleteRetiredCert(r.CertID); err != nil {
			m.log.Warn("failed to remove the reclaim record", "certId", r.CertID, "err", err)
		}
	}
}

// recordFailure records a failure and schedules exponential backoff.
//
// The 6-hour cap is not arbitrary: once we have hit "5 authorization failures per
// identifier per hour", hammering retries only makes things worse. Backing off to 6 hours
// means at most 4 attempts a day, far below the rate-limit threshold, while still
// guaranteeing that a fixed problem heals itself.
func (m *Manager) recordFailure(st *state.CertState, err error) error {
	// A stopped process / cancelled parent context is not a business failure. Recording it
	// would lengthen the backoff, so after a restart the same order should have been pushed
	// on immediately but is instead locked out of the window.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		m.log.Warn("pass cancelled; not counted as a failure and no backoff applied", "cert", st.Name, "err", err)
		return err
	}

	st.ConsecutiveFailures++
	st.LastError = err.Error()

	shift := st.ConsecutiveFailures - 1
	if shift > 10 {
		shift = 10
	}
	backoff := time.Minute << shift
	if backoff > 6*time.Hour || backoff <= 0 {
		backoff = 6 * time.Hour
	}
	st.NextAttemptAt = m.now().Add(backoff)

	if perr := m.store.PutCert(st); perr != nil {
		return errors.Join(err, perr)
	}

	m.log.Error("pass failed; a retry has been scheduled",
		"cert", st.Name, "err", err,
		"consecutiveFailures", st.ConsecutiveFailures, "nextAttemptAt", st.NextAttemptAt)
	return err
}

// discardOrder discards the current order and **reclaims the TXT records before deleting the
// authorization rows**.
//
// The order cannot be reversed. The authorization row (TxtName / ChallengeToken / TxtValue)
// is the only clue for cleaning up DNS; once the row is deleted those _acme-challenge
// records can never be reclaimed.
//
// This used to delete the rows without touching DNS, so every trip down the "the order is
// already ready, finalize directly" path (the common path where solveChallenges is skipped
// entirely) piled up one zombie TXT on DNSPod -- and cross-round authorization validation is
// the norm when propagation takes over 2 minutes on the free tier.
//
// Cleanup is handed to cleanupOrphanTXT: it deletes the rows it has finished with, and keeps
// the rows whose token cannot be located around for the next round to retry.
func (m *Manager) discardOrder(ctx context.Context, certName string) error {
	if err := m.cleanupOrphanTXT(ctx, certName); err != nil {
		// A cleanup failure must not stop us discarding the order -- that would leave us stuck
		// on an order that can never produce a result, which is far worse than one extra TXT
		// record.
		m.log.Warn("failed to clean up TXT before discarding the order", "cert", certName, "err", err)
	}
	return m.store.DeleteOrder(certName)
}

// parseOrderExpires parses an ACME order's expires. On an empty or unparsable value it
// falls back to now+defaultOrderTTL, so the persisted ExpiresAt is never the zero value.
func parseOrderExpires(raw string, now time.Time) (time.Time, error) {
	fallback := now.Add(defaultOrderTTL)
	if raw == "" {
		return fallback, nil
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t, nil
	}
	return fallback, fmt.Errorf("cannot parse expires %q", raw)
}

// persistOrder returns the write error instead of only logging it: a failed
// PutOrder means the crash-recovery path would resume from stale state, which
// contradicts the order-persistence invariants this package is built around.
func (m *Manager) persistOrder(o *state.Order, order legoacme.ExtendedOrder) error {
	o.Status = order.Status
	// Never overwrite a persisted finalize URL with an empty value -- losing it makes
	// submitting the CSR impossible later.
	if order.Finalize != "" {
		o.FinalizeURL = order.Finalize
	}
	if order.Certificate != "" {
		o.CertURL = order.Certificate
	}
	if err := m.store.PutOrder(o); err != nil {
		return fmt.Errorf("update the order state: %w", err)
	}
	return nil
}

func pickDNS01(authz legoacme.Authorization) (legoacme.Challenge, error) {
	for _, ch := range authz.Challenges {
		if ch.Type == "dns-01" {
			return ch, nil
		}
	}
	return legoacme.Challenge{}, fmt.Errorf(
		"the authorization for identifier %s offers no dns-01 challenge (wildcards can only use DNS-01)", authz.Identifier.Value)
}

func authzError(authz legoacme.Authorization) string {
	for _, ch := range authz.Challenges {
		if ch.Error != nil {
			return ch.Error.Detail
		}
	}
	return "the CA gave no specific reason"
}

// recordOrphanCert records a certificate that "already exists in the cloud but has no local
// owner" in the reclaim list.
//
// The scenario is a Deploy whose upload succeeded but whose rebind failed. Without recording
// it, the certificate is in neither the certificates table nor the retired table and the
// reaper never sees it -- and uploaded certificates count against a quota in the Tencent
// Cloud account, so after a few leaks renewal becomes impossible.
func (m *Manager) recordOrphanCert(newID, liveID, certName string) {
	if newID == "" || newID == liveID {
		return
	}
	if err := m.store.AddRetiredCert(newID, certName); err != nil {
		m.log.Warn("failed to record the orphaned certificate (it will occupy Tencent Cloud certificate quota indefinitely)",
			"cert", certName, "certId", newID, "err", err)
		return
	}
	m.log.Info("the certificate uploaded during the failed deploy has been recorded for reclaim and will be deleted later",
		"cert", certName, "certId", newID)
}
