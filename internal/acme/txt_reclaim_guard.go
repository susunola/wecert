package acme

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/susunola/wecert/internal/state"
)

// errMissingTXTClue is what markReclaimStuck stores when a presented row's record
// could not be located at all: the row is kept as the only clue to the name, and the
// guardian retries it even though there is no provider error to quote.
var errMissingTXTClue = errors.New("the presented TXT could not be located to reclaim it")

// markReclaimStuck enqueues this row on the DNS cleanup guardian.
//
// Called when a reclaim could not be *confirmed*: the authoritative NS was unreachable,
// the provider refused / forgot the record, or the record could not be located at all.
// A deliberate keep (still inside the propagation window) is NOT stuck -- that is a
// wait, and counting it would page an operator for a normal pass.
func (m *Manager) markReclaimStuck(a *state.Authorization, err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	if serr := m.store.MarkTXTReclaimStuck(a.CertName, a.AuthzURL, msg); serr != nil {
		m.log.Warn("could not record a stuck TXT reclaim", "cert", a.CertName, "authz", a.AuthzURL, "err", serr)
	}
}

// TXTReclaimStuck re-exports the state row for callers outside this package (the
// read-only view).
type TXTReclaimStuck = state.TXTReclaimStuck

// ListStuckTXTReclaims is the read-only queue the guardian is working.
func (m *Manager) ListStuckTXTReclaims() ([]*state.TXTReclaimStuck, error) {
	return m.store.ListStuckTXTReclaims()
}

// SweepStuckTXT retries every row the guardian has marked stuck, independent of which
// certificates a pass is walking. Called once per reconcile wrap-up: cleanupOrphanTXT
// only runs for a certificate that reached its no-order branch or discarded an order,
// so a certificate that keeps renewing happily would otherwise never retry a leftover
// TXT from an older crash.
//
// It is the same reclaim path as cleanupOrphanTXT -- probe, then provider cleanup --
// just driven from the stuck queue instead of "all authorizations of cert X".
func (m *Manager) SweepStuckTXT(ctx context.Context) (retried, cleared int, err error) {
	m.registerRecoveredLeases()
	rows, err := m.store.ListStuckTXTReclaims()
	if err != nil {
		return 0, 0, err
	}
	for _, e := range rows {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return retried, cleared, ctxErr
		}
		retried++
		a := &state.Authorization{
			CertName:            e.CertName,
			AuthzURL:            e.AuthzURL,
			Identifier:          e.Identifier,
			TxtName:             e.TxtName,
			TxtValue:            e.TxtValue,
			ChallengeToken:      e.ChallengeToken,
			Presented:           e.Presented,
			ChallengePreparedAt: e.PreparedAt,
		}
		outcome, rerr := m.reclaimOneStuck(ctx, a)
		switch outcome {
		case txtReclaimDone:
			cleared++
			_ = m.store.ClearTXTReclaimStuck(e.CertName, e.AuthzURL)
			// The row has no live TXT any more: same as cleanupOrphanTXT's success path.
			if err := m.store.DeleteAuthorization(e.CertName, e.AuthzURL); err != nil {
				m.log.Warn("failed to delete a reclaimed authorization row",
					"cert", e.CertName, "authz", e.AuthzURL, "err", err)
			}
		case txtReclaimKeptPropagating:
			// Fresh denial inside the window: leave the stuck stamp (it entered the queue
			// for a reason) but do not treat this as another failure either.
		case txtReclaimFailed:
			m.markReclaimStuck(a, rerr)
		}
	}
	return retried, cleared, nil
}

// reclaimOneStuck is reclaimUnpresentedTXT for a row that may already be Presented
// (the common stuck case: CleanUp could not confirm). Presented rows go through
// removeAuthzTXT; unpresented ones through the probe+reclaim path.
func (m *Manager) reclaimOneStuck(ctx context.Context, a *state.Authorization) (txtReclaim, error) {
	if a.Presented {
		ok, err := m.removeAuthzTXT(ctx, a)
		if err != nil {
			return txtReclaimFailed, err
		}
		if !ok {
			return txtReclaimFailed, errMissingTXTClue
		}
		return txtReclaimDone, nil
	}
	return m.reclaimUnpresentedTXT(ctx, a)
}

// StuckTXTGuardianLag is how old the oldest stuck reclaim is. Zero when the queue is
// empty -- the number an alert should fire on, so it is exported for the metrics mirror.
func StuckTXTGuardianLag(rows []*state.TXTReclaimStuck, now time.Time) time.Duration {
	var oldest time.Duration
	for _, e := range rows {
		if e.StuckSince.IsZero() {
			continue
		}
		if age := now.Sub(e.StuckSince); age > oldest {
			oldest = age
		}
	}
	return oldest
}

// DescribeStuckTXT is the operator-facing one-liner for a stuck row (view + logs).
func DescribeStuckTXT(e *state.TXTReclaimStuck, now time.Time) string {
	age := time.Duration(0)
	if !e.StuckSince.IsZero() {
		age = now.Sub(e.StuckSince)
	}
	return fmt.Sprintf("%s %s (cert %s, attempts %d, stuck %s): %s",
		e.TxtName, e.TxtValue, e.CertName, e.Attempts, age.Round(time.Second), e.LastError)
}
