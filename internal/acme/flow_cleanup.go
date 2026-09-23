package acme

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"

	"github.com/susunola/wecert/internal/state"
)

// Split out so one concern lives in one file. Same package.

// providerForgotRecord is what "CleanUp failed because this provider does not know that record"
// looks like from the manager's side. The phrasing each provider uses is listed here once, with the
// spot it comes from, because the match is a string one and the operator-facing behaviour hangs on
// it: only this outcome is allowed to be probed away and then be treated as done.
//
//   - "cloudflare: unknown record ID for '_acme-challenge.example.com.'" -- lego v4.35.2,
//     providers/dns/cloudflare/cloudflare.go:215, the wording observed in production. Cloudflare's
//     provider keeps the record IDs it created in a map keyed by the challenge token and deletes by
//     ID, so once the process that created the record is gone (or that record is already deleted),
//     this is all its CleanUp can say.
//   - "unknown record ID for '%s' '%s'" (no provider prefix: providers/dns/internal/westcn),
//     "unknown record ID or zone ID for '%s' '%s'" (providers/dns/internal/tecnocratica/provider.go)
//     and "unknown recordID for %q" (providers/dns/auroradns, cloudru, yandex360) -- the variants in
//     the rest of lego's ~198 providers, which `dns.provider: lego` can wire in by name. All of them
//     are matched by the same substring (see providerForgotRecordError); everything outside it keeps
//     the old behaviour, because a wrong "it is gone" would be acted on.
//
// The providers wired without the build tag do NOT belong in this list, and the contrast is why it
// is worth writing down: dnspod's CleanUp (providers/dns/dnspod/dnspod.go:119) and tencentcloud's
// (providers/dns/tencentcloud/tencentcloud.go:151) look the record up by name, delete what they find
// and return nil when there is nothing to delete, and route53's upserts a record set with an empty
// value list -- so for all three an already-deleted record is already a success and never reaches
// this branch.
const providerForgotRecord = "unknown record ID"

// providerLostRecordWait is how long the reclaim path waits before re-probing after the provider
// reported that it does not know the record.
//
// The wait exists because the usual reason the provider forgot the record is that the record was
// deleted a moment ago -- Cloudflare's provider drops the ID from its map after a successful
// delete, and this path is asking for a second delete. The re-probe asks the authoritative servers
// again, and right after the API call an anycast node can still answer from its own cache, so a
// probe with no gap at all would report a record that is on its way out. Bounded and short on
// purpose: a false "still there" keeps a row for one more round, while a long wait delays every
// cleanup that hits this.
const providerLostRecordWait = 2 * time.Second

// errProviderLostRecord marks a cleanup that failed only because the provider no longer knows the
// record. The caller words its summary from this: what the operator has to do about it (delete the
// record in the DNS console) is different from what a timeout or an API failure asks for.
var errProviderLostRecord = errors.New("the DNS provider does not know this record")

// providerForgotRecordError reports whether a CleanUp error is one of the "this provider does not
// know that record" phrasings above.
func providerForgotRecordError(err error) bool {
	return err != nil && strings.Contains(err.Error(), providerForgotRecord)
}

// providerLostRecordMessage is the operator-facing wording of that situation, used both as the
// returned error and as the WARN: the provider cannot delete a record it did not create in this
// process, so the record has to come out of the DNS console.
func providerLostRecordMessage(record string) string {
	return fmt.Sprintf("the DNS provider cannot delete %s: it only removes records it created in "+
		"this process and has already forgotten this one, so delete it in the DNS console", record)
}

func (m *Manager) registerRecoveredLeases() {
	rows, err := m.store.ListPresentedAuthorizations()
	if err != nil {
		// Not fatal: the worst case is the behaviour without this call, which is what
		// every version before it did.
		m.log.Warn("cannot list presented authorizations to re-register their TXT leases", "err", err)
		return
	}
	for _, a := range rows {
		if a.TxtName != "" && a.TxtValue != "" {
			// Under the name's mutex: these are exactly the leases that must be visible to a
			// concurrent CleanUp's check-then-delete (see addUnderLock).
			challengeLeases.addUnderLock(a.TxtName, a.TxtValue)
		}
	}
}

// releaseStaleLease drops one TXT lease whose value the caller has established is dead.
//
// The registry cannot tell a dead value from a live one by itself: a value stays in it until
// someone removes it, and while one is held every later cleanup at that name takes the "another
// challenge is still live" branch -- so the provider's delete-EVERY-TXT call never fires again for
// the rest of the process, every TXT record written at that name afterwards stays in DNS until a
// restart, and the name's record quota fills up with values nothing will ever collect. The two
// callers are the places where a value's fate is actually known: a row repointed at a different
// challenge token, and a probe that proved the record absent.
//
// A presented authorization row that still claims the same (name, value) keeps the lease. That is
// the one way a value the caller has given up on can still be needed: another certificate's record
// at the same name, whose rows this call does not own. The check reads the store, so a store that
// cannot be read keeps the lease -- the safe direction, because a leftover lease only delays a
// delete-all, while dropping a live one takes out a record another certificate is waiting on.
func (m *Manager) releaseStaleLease(fqdn, value string) {
	m.releaseStaleLeaseExcept(fqdn, value, nil)
}

// releaseStaleLeaseExcept is releaseStaleLease with one row excluded from the "another row still
// claims this value" check.
//
// The exclusion exists for the row being cleaned up right now: that row is itself a presented
// authorization claiming (name, TxtValue), so asking "does any presented row still need this value"
// would always answer yes and the lease would never be released. See releaseRowStaleLease.
func (m *Manager) releaseStaleLeaseExcept(fqdn, value string, except *state.Authorization) {
	if fqdn == "" || value == "" {
		return
	}
	// The per-name mutex, held across the whole check-then-act.
	//
	// DNSSolver.CleanUp holds this same mutex across "is any other value still live?" and the
	// provider's delete-EVERY-TXT call, so releasing a lease without it inverted that guard:
	// CleanUp would see this value live, skip the delete-all and return, and this call would
	// then remove the last lease -- leaving no live value and nobody left to run the delete.
	// The record then stays in DNS with no row and no lease pointing at it, so cleanupOrphanTXT
	// (which walks the authorizations) cannot see it either, and it poisons every later order
	// that writes the same challenge name.
	mu, release := challengeLeases.lock(fqdn)
	defer release()
	mu.Lock()
	defer mu.Unlock()

	rows, err := m.store.ListPresentedAuthorizations()
	if err != nil {
		m.log.Warn("cannot check whether another authorization still needs a TXT record; keeping its lease",
			"name", fqdn, "err", err)
		return
	}
	for _, r := range rows {
		if except != nil && r.CertName == except.CertName && r.AuthzURL == except.AuthzURL {
			continue
		}
		if r.TxtName == fqdn && r.TxtValue == value {
			return
		}
	}
	if othersLive := challengeLeases.remove(fqdn, value); othersLive {
		m.log.Info("another challenge is still live at the TXT name; the provider's delete-all waits for the last leaver",
			"name", fqdn)
		return
	}
	m.log.Info("released a TXT lease whose record is gone; the name can be cleaned up again",
		"name", fqdn)
}

// releaseRowStaleLease drops the lease a row's PERSISTED value is holding when its token no longer
// hashes to that value.
//
// The registry has two writers for one row. registerRecoveredLeases (and Present) register
// a.TxtValue, because that is the value recorded as being in DNS; CleanUp removes the value derived
// from the challenge token, because that is what lego's provider deletes by. For a row written
// before the token was refreshed -- the shape the comment in removeAuthzTXT describes as real -- the
// two differ, so the lease that went in can never come out: every later cleanup at that name takes
// the "another challenge is still live" branch, the provider's delete-all never fires again for the
// process lifetime, and the record this row owns stays in DNS. Releasing it here is what makes the
// decision correct rather than making it earlier: the value is this row's own record, and the
// exclusion keeps a different certificate's claim on it intact.
func (m *Manager) releaseRowStaleLease(a *state.Authorization, keyAuth string) {
	if a == nil || a.TxtName == "" || a.TxtValue == "" {
		return
	}
	if dns01.GetChallengeInfo(a.Identifier, keyAuth).Value == a.TxtValue {
		return
	}
	m.releaseStaleLeaseExcept(a.TxtName, a.TxtValue, a)
}

// cleanup deletes every TXT this round wrote. It is only called once all authorizations pass.
func (m *Manager) cleanup(ctx context.Context, certName string, authzs []*state.Authorization) {
	m.registerRecoveredLeases()

	for _, a := range authzs {
		cleaned, err := m.removeAuthzTXT(ctx, a)
		if err != nil {
			// Keep Presented=true: the next round (or cleanupOrphanTXT at wrap-up) will retry.
			m.log.Warn("failed to clean up TXT",
				"cert", certName, "identifier", a.Identifier, "name", a.TxtName, "err", err)
			continue
		}
		if !cleaned {
			// The record cannot even be located, so Presented must stay -- do not rub out the
			// only clue there is.
			continue
		}
		a.Presented = false
		if err := m.store.PutAuthorization(a); err != nil {
			m.log.Warn("failed to update the authorization state", "cert", certName, "identifier", a.Identifier, "err", err)
		}
	}
}

// removeAuthzTXT deletes the TXT record that one authorization wrote into DNS.
//
// The cleaned return means "this record is no longer in DNS": either it was never written or
// this call deleted it. cleaned=false with err=nil means the record cannot be located (the
// token is missing), and the caller **must keep the authorization row** -- the TxtName in it
// is the only remaining clue a human can use to investigate.
func (m *Manager) removeAuthzTXT(ctx context.Context, a *state.Authorization) (cleaned bool, err error) {
	if a == nil || !a.Presented {
		return true, nil
	}
	if a.ChallengeToken == "" || a.Identifier == "" {
		m.log.Warn("the authorization has no token, so the TXT record cannot be located (keeping the row for manual investigation)",
			"cert", a.CertName, "identifier", a.Identifier, "name", a.TxtName)
		return false, nil
	}
	keyAuth, err := m.keyAuth.GetKeyAuthorization(a.ChallengeToken)
	if err != nil {
		return false, fmt.Errorf("compute the key authorization: %w", err)
	}
	// Register exactly the value CleanUp is about to remove, so the registry stays
	// symmetric: a lease that goes in must be the one that comes out, or the leftover
	// entry makes "another challenge is still live here" true forever and the provider's
	// delete-all never fires again for the name for the lifetime of this process.
	//
	// It cannot be a.TxtValue unconditionally. A row written before the challenge token
	// was refreshed can carry a TxtValue that its token no longer hashes to, and
	// registering that stale value would create precisely that phantom lease.
	if a.TxtName != "" {
		challengeLeases.add(a.TxtName, dns01.GetChallengeInfo(a.Identifier, keyAuth).Value)
	}
	// And release the lease the row's own persisted value is holding, if it is not the value this
	// call is about to remove: otherwise that lease blocks the delete-all forever.
	m.releaseRowStaleLease(a, keyAuth)
	if err := m.dns.CleanUp(ctx, a.Identifier, a.ChallengeToken, keyAuth); err != nil {
		return false, fmt.Errorf("clean up TXT %s: %w", a.TxtName, err)
	}
	return true, nil
}

// cleanupOrphanTXT reclaims TXT records that "were written into DNS but no longer belong to
// any order in progress".
//
// Two sources:
//   - the normal cleanup when an order is discarded (discardOrder calls it first);
//   - the previous wrap-up only half succeeded (order deleted, authorization delete failed),
//     or the process was killed.
//
// The second source is exactly why this function exists: it is idempotent and self-healing,
// and nobody has to go digging around in the DNSPod console.
func (m *Manager) cleanupOrphanTXT(ctx context.Context, certName string) error {
	m.registerRecoveredLeases()

	authzs, err := m.store.ListAuthorizations(certName)
	if err != nil {
		return err
	}

	var cleaned, stuck, deferred, lostByProvider int
	for _, a := range authzs {
		if !a.Presented {
			// A row carrying a token may still have its record up: the pass that wrote
			// it died (or its persist failed) before marking Presented. Probe and try to
			// reclaim before deleting the row -- deleting it blind would orphan that TXT
			// for good, because the row is the only clue to the record's value.
			if a.ChallengeToken != "" {
				switch outcome, err := m.reclaimUnpresentedTXT(ctx, a); outcome {
				case txtReclaimKeptPropagating:
					// Deliberately kept, not stuck: the record was denied but the challenge is
					// younger than the propagation window, so the row is the safety net for a record
					// that may still appear. Counting it as "could not be reclaimed" made a normal
					// pass (any pass within five minutes of an issuance) print a WARN that reads
					// like a DNS cleanup failure -- observed in the round-11 production run.
					deferred++
					continue
				case txtReclaimFailed:
					// Worded from what actually failed. A provider that cannot delete a record it
					// did not create in this process leaves a record the operator has to remove by
					// hand, and the generic "could not be reclaimed automatically" reads like a
					// DNS cleanup failure rather than like that instruction.
					if errors.Is(err, errProviderLostRecord) {
						lostByProvider++
					} else {
						stuck++
					}
					continue
				}
			}
			// Rows that provably never reached DNS are deleted outright; leave no
			// rubbish behind.
			if err := m.store.DeleteAuthorization(certName, a.AuthzURL); err != nil {
				m.log.Warn("failed to delete authorization rows", "cert", certName, "authz", a.AuthzURL, "err", err)
			}
			continue
		}

		ok, err := m.removeAuthzTXT(ctx, a)
		if err != nil {
			m.log.Warn("failed to reclaim a leftover TXT record",
				"cert", certName, "identifier", a.Identifier, "name", a.TxtName, "err", err)
			continue
		}
		if !ok {
			// The record cannot be located: keep the authorization row, do not lose the TxtName
			// clue as well.
			stuck++
			continue
		}
		cleaned++
		if err := m.store.DeleteAuthorization(certName, a.AuthzURL); err != nil {
			m.log.Warn("failed to delete authorization rows", "cert", certName, "authz", a.AuthzURL, "err", err)
		}
	}

	if cleaned > 0 {
		m.log.Info("reclaimed a leftover _acme-challenge TXT record", "cert", certName, "count", cleaned)
	}
	if deferred > 0 {
		m.log.Info("kept an unpresented authorization row until its propagation window has passed; the "+
			"record was not found in DNS, and the row is what would reclaim it if the write were still "+
			"in flight", "cert", certName, "count", deferred)
	}
	if stuck > 0 {
		m.log.Warn("some TXT records could not be reclaimed automatically; their rows are kept and retried next round",
			"cert", certName, "count", stuck,
			"hint", "if this persists, clean the records up in the DNS console; the kept rows carry their names")
	}
	if lostByProvider > 0 {
		// Deliberately not folded into the generic line above. Nothing failed on this side: the
		// provider only deletes records it created in this process, so the record left behind is
		// one the operator has to delete, and saying so is the whole point of the branch.
		m.log.Warn("some TXT records are still in DNS and the DNS provider cannot delete them: it "+
			"only removes records it created in this process and has already forgotten these; delete "+
			"them in the DNS console -- the kept rows carry their names",
			"cert", certName, "count", lostByProvider)
	}
	return nil
}

// txtReclaim is the outcome of probing for the TXT of an interrupted pass.
//
// It is an enum rather than a bool because two outcomes that both mean "keep the row" have very
// different meanings to the operator: one is a deliberate wait (the record was denied, but the
// challenge is younger than the propagation window, so the row is the safety net for a write that may
// still land) and the other is a failure to find out. The caller counts them separately, and only the
// second is worth a WARN.
//
// The error is returned beside it only for txtReclaimFailed, and only so the caller can word its
// summary from what actually failed -- an unrecognised provider error and a record the provider
// cannot delete at all ask the operator for different things (see errProviderLostRecord). It is
// deliberately not a channel for the ordinary keep-the-row cases: those are decisions, not errors.
func (m *Manager) reclaimUnpresentedTXT(ctx context.Context, a *state.Authorization) (txtReclaim, error) {
	keyAuth, err := m.keyAuth.GetKeyAuthorization(a.ChallengeToken)
	if err != nil {
		m.log.Warn("cannot compute the key authorization for an unpresented row; keeping it",
			"cert", a.CertName, "identifier", a.Identifier, "err", err)
		return txtReclaimFailed, err
	}
	rec, found, err := m.dns.LookupTXT(ctx, a.Identifier, keyAuth)
	if err != nil {
		m.log.Warn("could not probe for the TXT of an interrupted pass; keeping the row",
			"cert", a.CertName, "identifier", a.Identifier, "err", err)
		return txtReclaimFailed, err
	}
	if !found {
		// A denial is only evidence once the write would have had time to appear.
		//
		// The row this probes exists for the pass that died between the DNS write and the state
		// persist -- but it also exists for the one that died between persisting the challenge and
		// writing DNS, and the two are indistinguishable from the record alone. What separates them
		// is time: if the challenge was chosen moments ago, every authoritative server may simply
		// not have it yet (DNSPod's addresses lag the API write, measured at up to ~60s for a
		// deletion this session), and deleting the row then drops the only clue to a record that is
		// about to appear -- which stays in DNS and can poison a later challenge at the same name.
		//
		// A row with no timestamp predates the column, so its age is unknown and the previous
		// behaviour is kept: refusing to delete those would strand every one of them forever.
		if age := m.now().Sub(a.ChallengePreparedAt); !a.ChallengePreparedAt.IsZero() &&
			age < m.dns.PropagationTimeout() {
			m.log.Info("an unpresented row's record was denied, but its challenge is newer than the "+
				"propagation window; keeping the row so a record that is still propagating is not lost",
				"cert", a.CertName, "identifier", a.Identifier, "name", a.TxtName,
				"preparedAgo", age.Round(time.Second),
				"window", m.dns.PropagationTimeout())
			return txtReclaimKeptPropagating, nil
		}

		// Every reachable authoritative nameserver denied this value, which is the
		// only answer that licenses deleting the row: the write genuinely never
		// happened. Any other outcome -- including one that merely could not be
		// confirmed -- reaches the caller as err, and the row is kept.
		//
		// The lease an interrupted Present registered for this value is dead for the same
		// reason, and leaving it behind is not harmless: the registry would keep reporting
		// "another challenge is still live at this name" for a record that is not there, so
		// the provider's delete-EVERY-TXT call would never fire again for the rest of the
		// process and every record written here afterwards would stay in DNS. Proof of
		// absence is what makes dropping it safe: nothing can depend on a record that is not
		// there, and the probe is the same evidence the row deletion rests on.
		m.releaseStaleLease(rec.FQDN, rec.Value)
		return txtReclaimDone, nil
	}
	m.log.Info("found the TXT of an interrupted pass; reclaiming it before deleting the row",
		"cert", a.CertName, "identifier", a.Identifier, "name", rec.FQDN)
	// Register it before asking for cleanup. CleanUp removes one lease and only fires the
	// provider's delete-all when no other value is live at the name; without registering,
	// this value is invisible to the registry and the delete-all would go ahead -- taking
	// out any other certificate's record at the same name.
	challengeLeases.add(rec.FQDN, rec.Value)
	// The row's persisted value may be a different one (a token refresh before either was written);
	// its lease would block the delete-all for the rest of the process. See releaseRowStaleLease.
	m.releaseRowStaleLease(a, keyAuth)
	if err := m.dns.CleanUp(ctx, a.Identifier, a.ChallengeToken, keyAuth); err != nil {
		if providerForgotRecordError(err) {
			// The provider deletes only what it created in this process -- Cloudflare keeps the
			// record IDs in a map keyed by the challenge token -- so a record that is already gone
			// (the normal cleanup deleted it, or the process that wrote it is not this one) comes
			// back as an error that says nothing about DNS.
			//
			// The record was still visible on an anycast node a moment ago, which is why this path
			// probed and asked for the delete at all, so re-probe rather than trust either side:
			// the authoritative servers are the only party that can say whether the record is
			// really gone. A short bounded wait comes first, because the node that answered is the
			// one most likely to have just lost the record -- see providerLostRecordWait.
			select {
			case <-ctx.Done():
			case <-time.After(providerLostRecordWait):
			}
			_, stillThere, probeErr := m.dns.LookupTXT(ctx, a.Identifier, keyAuth)
			switch {
			case probeErr != nil:
				// Not confirmed absent, so this is not the "done" branch. The row is kept with the
				// error that says why the provider could not do it, and the next round retries.
				m.log.Warn("failed to reclaim the TXT of an interrupted pass; keeping the row",
					"cert", a.CertName, "identifier", a.Identifier, "name", rec.FQDN, "err", err)
				return txtReclaimFailed, fmt.Errorf("%w: %s", errProviderLostRecord, err)
			case !stillThere:
				// Every reachable authoritative server now denies the record: it is gone, and the
				// provider's "unknown record ID" was the truth about its own bookkeeping rather
				// than a cleanup failure. Done, exactly as the confirmed-absent branch above is:
				// the row goes, and the lease this call registered is released -- leave it behind
				// and the registry keeps reporting a challenge that is not there, so the
				// provider's delete-all never fires again at this name (see releaseStaleLease).
				m.log.Info("the DNS provider had already forgotten the TXT record of an interrupted "+
					"pass and the authoritative servers agree it is gone; reclaiming it as done",
					"cert", a.CertName, "identifier", a.Identifier, "name", rec.FQDN, "err", err)
				m.releaseStaleLease(rec.FQDN, rec.Value)
				return txtReclaimDone, nil
			default:
				// The servers still hold the record and the provider cannot remove it: a real
				// leftover, and only a human can take it out. The row stays for the record's
				// name -- and so does the record's wording, which reaches the caller's summary
				// through errProviderLostRecord.
				m.log.Warn("the TXT record of an interrupted pass is still in DNS and the provider "+
					"cannot delete it; keeping the row",
					"cert", a.CertName, "identifier", a.Identifier, "name", rec.FQDN,
					"hint", providerLostRecordMessage(rec.FQDN))
				return txtReclaimFailed, fmt.Errorf("%w: %s", errProviderLostRecord, providerLostRecordMessage(rec.FQDN))
			}
		}
		m.log.Warn("failed to reclaim the TXT of an interrupted pass; keeping the row",
			"cert", a.CertName, "identifier", a.Identifier, "name", rec.FQDN, "err", err)
		return txtReclaimFailed, err
	}
	return txtReclaimDone, nil
}
