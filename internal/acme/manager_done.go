package acme

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/group"
	"github.com/susunola/wecert/internal/metrics"
	"github.com/susunola/wecert/internal/ratelimit"
	"github.com/susunola/wecert/internal/state"
)

// download downloads and verifies the certificate, then deploys it and advances the state.
//
// The ordering here is deliberate: until the deploy succeeds, never overwrite the
// certificate and private key currently in effect in CertState. Otherwise a failed deploy
// leaves nothing to roll back to.
func (m *Manager) download(
	ctx context.Context, c *config.Certificate, st *state.CertState,
	o *state.Order, order legoacme.ExtendedOrder, rd round,
) error {
	if order.Certificate == "" {
		return m.recordFailure(ctx, st, errors.New("the order is valid but has no certificate URL"))
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
		if err := m.discardOrder(ctx, c.Name); err != nil {
			// The issuance is already the live one; what failed is the bookkeeping that finishes the
			// order. That is still a failed pass -- and the one thing it must not do is come back
			// immediately, because discardOrder is what reclaims TXT records through authoritative
			// DNS probes.
			return m.recordFailure(ctx, st, fmt.Errorf("discard the already-live order: %w", err))
		}
		return nil
	}

	// bundle=true returns the fullchain (leaf + intermediate certificates), which is exactly
	// the format CLB needs.
	fullchain, _, err := m.core.GetCertificate(order.Certificate, true)
	if err != nil {
		return m.recordFailure(ctx, st, fmt.Errorf("download certificate: %w", err))
	}

	leaf, err := ParseLeaf(fullchain)
	if err != nil {
		return m.recordFailure(ctx, st, err)
	}

	if err := VerifyCoverage(leaf, c.Domains); err != nil {
		return m.recordFailure(ctx, st, err)
	}

	// A certificate exists at the CA now, so the two certificate budgets are spent -- here, not
	// after the deploy, because the CA counts the issuance and a later failure of ours (the
	// deploy, or the epilogue transaction) does not give that budget back.
	//
	// ARI-exempt renewals are counted too, which makes this estimate a LOWER bound on what is
	// left. That is the direction this package promises to be wrong in: the alerting rule for
	// "certs per exact identifier set" -- the limit with no override path -- must not be the one
	// number that is structurally always full.
	//
	// A later failure of ours can double-count as well: the epilogue transaction may roll back
	// after this point, and the next pass downloads the same certificate again (the CA issues it
	// once, and the order is still valid) and spends a second slot. Also the conservative
	// direction, and also bounded by one per retry.
	m.quota.Spend(ratelimit.CertsPerExactIdentifierSet, c.DomainKey(), 1)
	for _, domain := range uniqueRegisteredDomains(c.Domains) {
		m.quota.Spend(ratelimit.CertsPerRegisteredDomain, domain, 1)
	}
	// Reject a certificate that is not actually a REPLACEMENT for the live one.
	//
	// This used to be "the new notAfter must be strictly later", which is wrong whenever the
	// new certificate legitimately lives LESS long than the old one. Two ordinary ways that
	// happens:
	//
	//   - the operator switches profile, e.g. classic (90d) -> shortlived (160h). At the
	//     moment ARI asks for renewal the live classic certificate still has weeks left, so
	//     every attempt is refused, and the refusal repeats on every pass until the live
	//     certificate has decayed below 160h. The profile change silently fails to take
	//     effect, consecutive_failures sits at its cap, and the renewal collapses into the
	//     last few days of validity instead of happening 30 days early;
	//   - the CA shortens lifetimes. Let's Encrypt has announced 90 -> 45 -> 6 days, so
	//     "the replacement must expire later" would break every certificate in the fleet on
	//     the day the CA switches.
	//
	// In both cases the new certificate is unambiguously newer: it was issued after the live
	// one. That is the property worth testing. notAfter remains the fallback for when the
	// live certificate's material is unavailable or unparseable, where "later expiry" is the
	// only evidence available.
	if !st.NotAfter.IsZero() && !leaf.NotAfter.After(st.NotAfter) && !certIsNewer(leaf, st) {
		return m.recordFailure(ctx, st, fmt.Errorf(
			"the new certificate's notAfter (%s) is not later than the current one (%s), and it was not "+
				"issued after it either, so it is not a replacement; refusing to deploy",
			leaf.NotAfter, st.NotAfter))
	}
	if len(o.KeyPEM) == 0 {
		return m.recordFailure(ctx, st, errors.New("the order has no private key; cannot deploy"))
	}
	// The last gate of the same triad as coverage and notAfter: a certificate that covers
	// the right names and lives long enough, but belongs to a different key, would be
	// deployed over a working one and break every handshake.
	if err := VerifyKeyMatch(leaf, o.KeyPEM); err != nil {
		return m.recordFailure(ctx, st, err)
	}

	// Deploy. On a first issuance DeployedCertID is empty, so this only uploads and waits
	// for a human to bind it once in the CLB console. A successful upload does not mean the
	// listener is bound: DeployConfirmed is only set once the one-click update has really
	// finished switching over.
	oldDeployedID := st.DeployedCertID
	deployedID := oldDeployedID
	rebound := false
	// Set by the deploy-disabled branch below, applied to the STAGED promotion once it is staged:
	// the flag belongs to the promotion, and the promotion is not real until the transaction that
	// records it commits.
	forceUndeployed := false
	// Set when the switch is reported done but its binding could not be verified in time
	// (deploy.ErrSwitchUnverified): the certificate is promoted, but not as a confirmed
	// deployment.
	unverified := false
	// Set when nothing is bound to either certificate (deploy.ErrNothingBoundYet): the renewed
	// certificate is promoted as uploaded-but-unbound, exactly like a first issuance.
	waitingFirstBind := false
	if c.Deploy.Enabled {
		var id string
		var derr error
		if o.DeploymentCertID != "" {
			if retry, ok := m.deployer.(deploy.RetryableDeployer); ok {
				id, derr = retry.ResumeDeploy(ctx, c.Name, oldDeployedID, o.DeploymentCertID)
			} else {
				id, derr = m.deployer.Deploy(ctx, c.Name, oldDeployedID, fullchain, o.KeyPEM)
			}
		} else if staged, ok := m.deployer.(deploy.StagedDeployer); ok {
			id, derr = staged.Upload(ctx, c.Name, fullchain, o.KeyPEM)
			if derr == nil {
				o.DeploymentCertID = id
				if err := m.store.PutOrder(o); err != nil {
					// The certificate is uploaded; only recording its id failed. That id is the resume
					// anchor, so losing it means the next pass uploads a SECOND copy and leaks the
					// first -- and a bare `return err` also skips the backoff, so it retries at the
					// pass rate instead. recordFailure keeps both (it schedules the retry and leaves
					// the failure visible), which is what the sibling call sites already do.
					return m.recordFailure(ctx, st, fmt.Errorf(
						"the certificate %s was uploaded but recording it for the resume anchor failed: %w",
						id, err))
				}
				id, derr = staged.DeployUploaded(ctx, c.Name, oldDeployedID, id)
			}
		} else {
			id, derr = m.deployer.Deploy(ctx, c.Name, oldDeployedID, fullchain, o.KeyPEM)
		}
		if derr != nil {
			// The Deployer contract is: on error it still returns the ID of the certificate
			// that was uploaded successfully (see Deploy in internal/deploy/tencent.go). That
			// ID must be recorded in the reclaim list -- otherwise it is in neither the
			// certificates table nor the retired table, ReapRetired never sees it, and one
			// failure leaks one certificate in Tencent Cloud until the account quota is hit.
			// The reclaim machinery exists precisely to prevent that.
			//
			// One error is not a failure: ErrSwitchUnverified means the cloud already reported
			// the switch as done and only the independent binding enumeration did not answer in
			// time. Failing the pass there is not self-correcting -- the old certificate has no
			// bindings left by then, so every later round re-runs the same deploy and the state
			// never records the certificate that is serving traffic. It is recorded as deployed
			// but unconfirmed instead, which the next pass's binding probe turns into a
			// confirmed deployment; DeployConfirmed stays false until then, so the deployed
			// metric keeps telling the truth.
			if errors.Is(derr, deploy.ErrSwitchUnverified) && id != "" {
				m.log.Warn("the one-click switch is reported as done but its binding could not be verified in time; "+
					"recording the new certificate as deployed but unconfirmed",
					"cert", c.Name, "certId", id, "err", derr)
				unverified = true
			} else if errors.Is(derr, deploy.ErrNothingBoundYet) && id != "" {
				// The documented first-issuance state, met on a renewal because nobody bound the
				// first upload. There was no switch to perform, so this is not a failed deploy:
				// before this case existed the pass failed every time, the promotion below never
				// ran, and the state kept pointing at the certificate that was expiring while
				// each cycle issued and uploaded another one.
				//
				// The hint names THIS certificate rather than "either certificate": the promotion
				// below retires the predecessor onto the reclaim list, so binding that one would
				// leave the row this program tracks unbound -- the next pass would report "nothing
				// bound yet" again, overwrite the promoted row with a third upload, and burn one
				// issuance per cycle. Naming the uploaded id (the field above) is what makes the
				// instruction followable.
				m.log.Warn("the renewed certificate is uploaded but neither it nor its predecessor is "+
					"bound to any cloud resource; nothing was switched, and the one-time manual bind "+
					"is still outstanding",
					"cert", c.Name, "certId", id, "hint",
					"bind this certificate (the certId above, also recorded as the deployed id) once "+
						"in the CLB console; later renewals switch the binding automatically, and the "+
						"unbound predecessor is deleted only once the cloud confirms nothing references it")
				waitingFirstBind = true
			} else {
				if id != "" {
					o.DeploymentCertID = id
					if err := m.store.PutOrder(o); err != nil {
						// As above: the upload happened, so the id is the only record of a cloud object,
						// and the failure has to cost a backoff rather than a bare retry.
						return m.recordFailure(ctx, st, fmt.Errorf(
							"the certificate %s was uploaded but recording it for reclaim failed: %w", id, err))
					}
				}
				return m.recordFailure(ctx, st, fmt.Errorf("deploy to Tencent Cloud: %w", derr))
			}
		}
		deployedID = id
		// The order's DeploymentCertID is deliberately NOT cleared here.
		//
		// It used to be, with a best-effort PutOrder that was allowed to fail ("a successful
		// issuance must not fail because a bookkeeping write did"). Two things were wrong with
		// that. The write is a durable statement outside the transaction below, so a rollback
		// left the order without its resume anchor: the uploaded certificate was then in neither
		// certificates nor retired_certificates, the next pass uploaded a second copy of it
		// instead of resuming, and the first copy leaked against the account quota. And the
		// orphan decision below reads the order back from the store, so when that write failed
		// the order still named the certificate being promoted -- which the guard, comparing
		// against the not-yet-promoted row, could only read as "an orphan".
		//
		// tx.DeleteOrder below removes the row (and with it the ID) inside the transaction, which
		// is both atomic and sufficient: on success nothing stale survives, and on failure the
		// anchor survives too, which is what lets the next pass resume instead of re-uploading.
		// A first bind that has not happened yet is not a rebind: claiming DeployConfirmed here
		// would make the deployed metric green for a certificate that is serving nothing, and the
		// next renewal would try to switch from it.
		rebound = oldDeployedID != "" && !waitingFirstBind
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
		// Applied to the staged copy below, not to st: the flag belongs to the promotion, and the
		// promotion is not real until the transaction commits.
		forceUndeployed = true
	}

	ariCertID, err := CertID(leaf)
	if err != nil {
		// ARI being unavailable must not block issuance; it only costs us the rate-limit
		// exemption.
		m.log.Warn("could not build the ARI certID; this renewal will go out without replaces", "cert", c.Name, "err", err)
	}

	// Archive the outgoing certificate's material before the row is overwritten below.
	// After that point the old key exists nowhere: the retired_certificates row used to keep
	// only a CertId, so once the cloud copy was reclaimed the certificate could never be
	// re-uploaded and "rollback" was a 7-day window on someone else's system.
	oldCertPEM := st.CertPEM
	oldKeyPEM := st.KeyPEM

	// The deploy succeeded; only now is the new certificate promoted to the live version.
	//
	// Staged on a copy, because the promotion is not real until the transaction below commits. It
	// used to be written into st first, and that quietly defeated the transaction: the failure path
	// calls recordFailure, which persists st, so a rollback was immediately overwritten by a
	// recordFailure carrying the NEW certificate -- the promotion landed anyway, one statement
	// later, outside the transaction it was supposed to be part of.
	promoted := *st
	promoted.NotAfter = leaf.NotAfter
	promoted.CertURL = order.Certificate
	promoted.CertPEM = fullchain
	promoted.KeyPEM = o.KeyPEM
	promoted.IssuedAt = m.now()
	promoted.DeployedCertID = deployedID
	if forceUndeployed {
		promoted.DeployConfirmed = false
	}
	if rebound {
		promoted.DeployConfirmed = true
	} else if oldDeployedID == "" {
		// First upload: record the CertId so a human can bind it, but the metric should still
		// read "not deployed".
		promoted.DeployConfirmed = false
	}
	if unverified {
		// Last word on the flag: the switch is reported as done but was not independently
		// confirmed, so "deployed" is not something this program can claim yet. The next
		// pass's binding probe sets it once the enumeration answers (see confirmBinding),
		// which is why this does not have to be settled here.
		promoted.DeployConfirmed = false
	}
	if waitingFirstBind {
		// Neither certificate is bound, so the flag must be cleared rather than inherited from the
		// row being replaced: the seed value came from an earlier confirmed deployment, and this
		// promotion replaces a certificate that nothing is serving with one that nothing is
		// serving either. Leaving it true would make the deployed metric green and let the next
		// renewal try to switch away from a certificate no listener has.
		promoted.DeployConfirmed = false
	}
	promoted.ARICertID = ariCertID
	promoted.ARIWindowStart = time.Time{}
	promoted.ARIWindowEnd = time.Time{}
	promoted.ARICheckedAt = time.Time{}
	promoted.ARIRetryAfter = 0
	promoted.NextAttemptAt = time.Time{}
	promoted.LastError = ""

	// The failure counter is cleared only when this round actually ordered the full
	// configured set. A successful issuance for the degraded subset is not evidence that
	// the dropped identifiers recovered -- they were never attempted -- and zeroing the
	// counter here is what let the next pass re-order the full set.
	//
	// The cost of keeping it is nil: the counter feeds the fallback trigger and the
	// documented backoff, and both are things we want to stay alert while names are
	// missing.
	if rd.fullSet {
		promoted.ConsecutiveFailures = 0
	}

	// ── the epilogue, in ONE transaction ────────────────────────────────────────────────
	//
	// Everything below decides what the state of the world is after a successful renewal, and the
	// pieces only make sense together:
	//
	//   - promote the new certificate (it is live in the cloud right now);
	//   - retire the old one, so the reaper can delete it and it stops holding a slot in the
	//     uploaded-certificate quota;
	//   - clear the fallback record and, for a full-set issuance, the identifier ledger;
	//   - discard the order, which is what tells the next pass there is nothing in flight.
	//
	// Committed separately they could half-happen, and both halves are bad in ways no later pass
	// repairs: promote without retire leaves the certificate that was serving in no table at all
	// (never reaped, never deleted from the cloud, quota consumed forever), and retire without
	// promote marks the certificate that IS serving for deletion. See internal/state/tx.go.
	//
	// The TXT cleanup that goes with discarding the order is NOT in here: it is network I/O to the
	// DNS provider. It runs first, because it is idempotent and safe to repeat, while the state
	// change below is not.
	//
	// What the transaction deliberately does not do is make a failure invisible. If it fails, the
	// certificate has still been issued and deployed -- the cloud does not roll back -- and the
	// next pass re-orders, which costs an issuance against the exact-set limit. That is the price
	// of not being able to write the database, and the error below says so rather than reporting a
	// generic failure.

	// Read what the transaction needs BEFORE opening it: the store's own reads use the pool, and
	// the pool's single connection is held by the transaction while it is open (see WithTx).
	clearFallback := false
	if fb, err := m.store.GetFallback(c.Name); err == nil && fb != nil && containsAll(c.Domains, fb.Dropped) {
		// The fallback record is cleared only when THIS round issued the full desired set --
		// containsAll(c.Domains, fb.Dropped) is exactly that test, and it is why the record is no
		// longer cleared by applyFallback: trying the full set is not recovery, issuing it is.
		clearFallback = true
	}
	// Only once the switch from the old certificate to the new one is confirmed does the old one go
	// on the reclaim list. On a first upload nothing is bound to a listener yet, and retiring it
	// would delete, 7 days later, the very certificate a human just bound.
	retireOld := rebound && oldDeployedID != "" && oldDeployedID != deployedID

	// A renewed certificate that replaces an upload nobody ever bound is not "retired" in the
	// rollback sense -- nothing is serving it -- but the row that named it is about to be
	// overwritten, so without this the id is lost: not in certificates, not in retired_certificates,
	// and therefore never deleted. It is billed against the account's uploaded-certificate quota
	// forever. Reclaiming it is safe because the deployer only reports ErrNothingBoundYet from
	// COMPLETE enumerations of both certificates (see nothingBoundYet), and the delete itself still
	// asks the cloud to refuse if anything is bound.
	reclaimFirstBind := waitingFirstBind && oldDeployedID != "" && oldDeployedID != deployedID

	// The order may also carry the ID of a certificate that was uploaded but never rebound. Hand it
	// to the reclaim list inside the same transaction -- see discardOrder for why losing it is
	// expensive.
	orphanID, orphanPEM, orphanKey := m.orphanToRecord(c.Name, deployedID)

	// The TXT records first: idempotent, repeatable, and useless to redo if the state change fails.
	if err := m.cleanupOrphanTXT(ctx, c.Name); err != nil {
		// A cleanup failure must not stop the renewal from being recorded -- that would leave us
		// stuck on an order that can never produce a result, which is worse than one extra TXT.
		m.log.Warn("failed to clean up TXT before discarding the order", "cert", c.Name, "err", err)
	}

	txErr := m.store.WithTx(ctx, func(tx *state.Tx) error {
		if err := tx.PutCert(&promoted); err != nil {
			return fmt.Errorf("promote the new certificate: %w", err)
		}
		if retireOld || reclaimFirstBind {
			if err := tx.AddRetiredCert(oldDeployedID, c.Name, oldCertPEM, oldKeyPEM); err != nil {
				return fmt.Errorf("retire the previous certificate: %w", err)
			}
		}
		if orphanID != "" {
			if err := tx.AddRetiredCert(orphanID, c.Name, orphanPEM, orphanKey); err != nil {
				return fmt.Errorf("record the uploaded-but-unbound certificate: %w", err)
			}
		}
		if clearFallback {
			if err := tx.ClearFallback(c.Name); err != nil {
				return fmt.Errorf("clear the fallback record: %w", err)
			}
		}
		// After an issuance of the FULL set, clear the per-identifier failure ledger.
		//
		// The ledger means "who has been broken lately", not "who has ever been broken", so a fully
		// healthy issuance should retire it -- otherwise a long-since-fixed fault keeps a name out
		// of the certificate forever, and since a dropped name is never attempted again it can
		// never earn the success that would clear its name.
		//
		// A round that deployed the degraded subset must NOT clear it. Tying this to "is a fallback
		// record present" (the previous test) meant the record was cleared by applyFallback during
		// the subset round that followed, so the evidence was gone exactly when it was needed and
		// the next pass re-ordered the broken full set. Keying on what was actually ordered is the
		// honest question.
		if rd.fullSet {
			if err := tx.ClearIdentifierFailures(c.Name); err != nil {
				return fmt.Errorf("clear the identifier failure ledger: %w", err)
			}
		}
		return tx.DeleteOrder(c.Name)
	})
	if txErr != nil {
		// st is deliberately untouched: the promotion did not commit, so neither the in-memory
		// state nor the failure row this records may claim it did. (It also keeps the operator's
		// failure count attached to the certificate that is actually still live.)
		return m.recordFailure(ctx, st, fmt.Errorf(
			"the certificate was issued and deployed, but recording that in state.db failed, so it "+
				"is unchanged on disk and this pass is reported as failed: %w. The next pass will "+
				"re-order (which costs an issuance against the per-identifier-set limit); if this "+
				"repeats, the state database is the problem, not the certificate", txErr))
	}
	// Committed, so the in-memory state may now become the durable one.
	*st = promoted
	if clearFallback {
		metrics.CertificateFallbackActive.WithLabelValues(c.Name).Set(0)
		metrics.CertificateFallbackDropped.WithLabelValues(c.Name).Set(0)
	}
	if !rd.fullSet && rd.degraded {
		// c.Domains is the set that was ORDERED (the kept subset), so labelling it "dropped" told an
		// operator the opposite of what happened -- and the count they need is on the ledger rows.
		m.log.Warn("issued the degraded name set; keeping the identifier failure ledger so the "+
			"next pass does not immediately re-order the full set",
			"cert", c.Name, "issued", len(c.Domains))
	}
	if orphanID != "" {
		m.log.Info("the certificate uploaded during the failed deploy has been recorded for reclaim "+
			"and will be deleted later", "cert", c.Name, "certId", orphanID)
	}

	if !c.Deploy.Enabled {
		m.log.Info("certificate issued and recorded locally (cloud deploy is off)",
			"cert", c.Name, "notAfter", st.NotAfter,
			"daysLeft", config.DaysUntil(st.NotAfter, m.now()))
	} else if !st.DeployConfirmed {
		m.log.Info("certificate uploaded; waiting for a one-time manual bind in the CLB console",
			"cert", c.Name, "notAfter", st.NotAfter,
			"uploadedCertId", deployedID,
			"hint", "once bound, later renewals switch it automatically via UpdateCertificateInstance")
	} else {
		m.log.Info("certificate renewed and live",
			"cert", c.Name, "notAfter", st.NotAfter,
			"daysLeft", config.DaysUntil(st.NotAfter, m.now()),
			"deployedCertId", deployedID, "ariCertId", ariCertID != "")
	}
	return nil
}

func containsAll(domains, want []string) bool {
	available := make(map[string]bool, len(domains))
	for _, d := range domains {
		available[d] = true
	}
	for _, d := range want {
		if !available[d] {
			return false
		}
	}
	return true
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

// uniqueRegisteredDomains returns the registered domains a certificate's names belong to, once
// each: "certs per registered domain" is counted per registered domain the certificate covers, and
// a certificate spanning several of them spends that many slots.
func uniqueRegisteredDomains(domains []string) []string {
	seen := make(map[string]bool, len(domains))
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		rd := group.RegisteredDomain(d)
		if rd == "" || seen[rd] {
			continue
		}
		seen[rd] = true
		out = append(out, rd)
	}
	return out
}

// recordFailure records a failure and schedules exponential backoff.
//
// The 6-hour cap is not arbitrary: once we have hit "5 authorization failures per
// identifier per hour", hammering retries only makes things worse. Backing off to 6 hours
// means at most 4 attempts a day, far below the rate-limit threshold, while still
// guaranteeing that a fixed problem heals itself.
func (m *Manager) recordFailure(ctx context.Context, st *state.CertState, err error) error {
	// A stopped process / cancelled parent context is not a business failure. Recording it
	// would lengthen the backoff, so after a restart the same order should have been pushed
	// on immediately but is instead locked out of the window.
	//
	// The question is whether THIS PASS was stopped, not what the error happens to wrap. Testing
	// errors.Is against context.Canceled/DeadlineExceeded also matched every http.Client timeout,
	// because net/http wraps its own deadline in *url.Error, whose Unwrap is
	// context.DeadlineExceeded -- so an ordinary CA-side timeout, the commonest failure there is,
	// was filed as "pass cancelled": no consecutive_failures, no last_error, no backoff, and on a
	// first issuance not even a certificate row for the next pass to find. The context is the
	// authority on why the pass stopped; if it is still alive, the error is a real failure whatever
	// it unwraps to.
	if ctx.Err() != nil {
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
		// The deadline computed above cannot be persisted, so hold it in memory as well.
		//
		// Without this the failure is forgotten the moment this function returns: the next
		// pass reads the OLD row, which has no NextAttemptAt, runs immediately and fails
		// again. When the cause is a full disk -- exactly when PutCert fails -- that pass
		// creates another order at the CA, so the order rate follows the pass rate instead of
		// the backoff: 1440 a day at a 1-minute interval, against "300 new orders per account
		// per 3 hours", which blocks every certificate on the account rather than just this one.
		m.setTransientBackoff(st.Name, st.NextAttemptAt)
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
// discardOrder cleans up after an order that is going away and returns nothing to record.
//
// Kept for callers that are not finishing a renewal (an order that can never produce a result
// still has to be cleaned up and removed). The renewal epilogue does the same work through one
// transaction instead; see orphanToRecord for the half of it that has to be decided in advance.
func (m *Manager) discardOrder(ctx context.Context, certName string) error {
	// No promotion is in flight on this path, so the store's deployed_cert_id is the live one.
	orphanID, orphanPEM, orphanKey := m.orphanToRecord(certName, "")

	if err := m.cleanupOrphanTXT(ctx, certName); err != nil {
		// A cleanup failure must not stop us discarding the order -- that would leave us stuck
		// on an order that can never produce a result, which is far worse than one extra TXT
		// record.
		m.log.Warn("failed to clean up TXT before discarding the order", "cert", certName, "err", err)
	}

	err := m.store.WithTx(ctx, func(tx *state.Tx) error {
		if orphanID != "" {
			if err := tx.AddRetiredCert(orphanID, certName, orphanPEM, orphanKey); err != nil {
				return err
			}
		}
		return tx.DeleteOrder(certName)
	})
	if err == nil && orphanID != "" {
		m.log.Info("the certificate uploaded during the failed deploy has been recorded for reclaim "+
			"and will be deleted later", "cert", certName, "certId", orphanID)
	}
	return err
}

// orphanToRecord decides whether the order's uploaded certificate has to go on the reclaim list,
// and returns its id and material.
//
// An order can carry the ID of a certificate that was uploaded to Tencent Cloud but whose
// asynchronous rebind never completed. Deleting the row throws away the only local record of that
// certificate: it is then in neither the certificates table nor the retired table, ReapRetired never
// sees it, and it occupies the account's uploaded-certificate quota forever -- and quota exhaustion
// is what stops renewal.
//
// promotedID is the certificate id this pass is about to make live, and it is not optional
// information: on the renewal path the promotion is still staged on a copy when this decision is
// made (the transaction that writes it has not opened yet), so certificates.deployed_cert_id still
// names the OUTGOING certificate. Comparing the order's id against that stale value could never
// match the id being promoted, so the guard silently stopped guarding and the certificate that was
// about to serve traffic was written to the reclaim list in the same transaction that promoted it.
// Callers that are not promoting anything pass "" and the store's value is used instead.
//
// Split out of discardOrder because the renewal epilogue has to make this decision *before* it
// opens the transaction that writes it: the store's reads use the pool, and the pool's connection
// is held by the transaction while it is open.
func (m *Manager) orphanToRecord(certName, promotedID string) (certID string, certPEM, keyPEM []byte) {
	o, err := m.store.GetOrder(certName)
	if err != nil {
		m.log.Warn("cannot read the order before discarding it; an uploaded certificate may be left unreclaimed",
			"cert", certName, "err", err)
		return "", nil, nil
	}
	if o == nil || o.DeploymentCertID == "" {
		return "", nil, nil
	}

	liveID := promotedID
	if liveID == "" {
		if st, cerr := m.store.GetCert(certName); cerr != nil {
			m.log.Warn("cannot read the certificate before discarding its order", "cert", certName, "err", cerr)
		} else if st != nil {
			liveID = st.DeployedCertID
		}
	}
	// liveID == "" errs toward reclaiming: recordOrphanCert only skips on an exact match, and a
	// certificate still bound to a listener is protected by IsCheckResource refusing the delete.
	if o.DeploymentCertID == liveID {
		return "", nil, nil
	}
	return o.DeploymentCertID, nil, nil
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

// certIsNewer reports whether the freshly issued leaf was issued after the certificate
// currently in effect.
//
// Two sources, in order of directness:
//
//  1. The live certificate's own NotBefore, parsed from the stored PEM. This is the real
//     issuance instant and needs no bookkeeping.
//  2. CertState.IssuedAt, the record wecert wrote when it deployed that certificate. It is
//     the fallback for a stored PEM that cannot be parsed, and it is why the field exists --
//     it was being persisted on every issuance and read by nothing.
//
// A false result is not "the certificate is bad": it means there is no evidence this is a
// replacement, which is exactly when the caller should keep refusing.
func certIsNewer(fresh *x509.Certificate, st *state.CertState) bool {
	if fresh == nil {
		return false
	}
	if live, err := ParseLeaf(st.CertPEM); err == nil && live != nil {
		return fresh.NotBefore.After(live.NotBefore)
	}
	if !st.IssuedAt.IsZero() {
		return fresh.NotBefore.After(st.IssuedAt)
	}
	return false
}
