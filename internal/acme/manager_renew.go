package acme

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/acme/api"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/state"
)

// renewalDecision returns "when to renew" and "which replaces to send when ordering".
//
// ARI comes first: a renewal that goes through ARI and carries replaces is exempt from every
// Let's Encrypt rate limit. When ARI is unavailable it degrades to notAfter - renewBefore,
// with deterministic jitter layered on top.
func (m *Manager) renewalDecision(
	ctx context.Context, c *config.Certificate, st *state.CertState,
) (renewAt time.Time, replaces string, ariErr error) {
	// lego's ACME API does not take a context, so cancellation cannot reach the network calls
	// themselves; but at least check once here, so a stop signal does not leave us grinding
	// through a whole round for nothing.
	if err := ctx.Err(); err != nil {
		return time.Time{}, "", err
	}

	now := m.now()

	if st.ARICertID != "" && m.ariCheckDue(st, now) {
		info, retryAfter, err := FetchRenewalInfo(m.core, st.ARICertID)
		switch {
		case err == nil:
			st.ARIWindowStart = info.SuggestedWindow.Start
			st.ARIWindowEnd = info.SuggestedWindow.End
			st.ARICheckedAt = now
			st.ARIRetryAfter = retryAfter
			if perr := m.store.PutCert(st); perr != nil {
				return time.Time{}, "", perr
			}
			m.log.Info("ARI window refreshed",
				"cert", c.Name, "start", st.ARIWindowStart, "end", st.ARIWindowEnd, "retryAfter", retryAfter)
		case errors.Is(err, api.ErrNoARI):
			// The CA does not support ARI: degrade permanently. Recording it once is enough;
			// retrying every round buys nothing.
			st.ARICheckedAt = now
			st.ARIRetryAfter = 0
			if perr := m.store.PutCert(st); perr != nil {
				return time.Time{}, "", perr
			}
			ariErr = err
		default:
			// A failure has to be recorded too.
			//
			// The throttling test ariCheckDue is based entirely on ARICheckedAt, so if we did not
			// write it here, every reconcile round (1 hour by default) would hit ARI all over
			// again; and the server's Retry-After would be thrown away -- even though
			// FetchRenewalInfo has already parsed it for us, covering even non-200 responses.
			st.ARICheckedAt = now
			st.ARIRetryAfter = retryAfter
			if perr := m.store.PutCert(st); perr != nil {
				return time.Time{}, "", perr
			}
			ariErr = err
		}
	}

	if !st.ARIWindowStart.IsZero() && st.ARIWindowEnd.After(st.ARIWindowStart) {
		return RenewalTime(c.Name, st.ARIWindowStart, st.ARIWindowEnd), st.ARICertID, ariErr
	}

	// Fallback: no ARI, but the identifier set still stays identical, so at least we keep the
	// "non-ARI renewal" exemptions on the order count and on certificates per domain.
	base := st.NotAfter.Add(-c.RenewBeforeDur)
	return DeterministicTime(c.Name, base, c.RenewBeforeDur/8), st.ARICertID, ariErr
}

func (m *Manager) ariCheckDue(st *state.CertState, now time.Time) bool {
	if st.ARICheckedAt.IsZero() {
		return true
	}
	// Let's Encrypt recommends checking renewalInfo at most once every 6 hours.
	if now.Before(st.ARICheckedAt.Add(m.ariInterval)) {
		return false
	}
	// And respect the Retry-After the server gave us.
	if st.ARIRetryAfter > 0 && now.Before(st.ARICheckedAt.Add(st.ARIRetryAfter)) {
		return false
	}
	return true
}

// issue creates an order. Mind the order of operations: persist the order (including the
// private key generated here) first, and only then advance it.
func (m *Manager) issue(ctx context.Context, c *config.Certificate, st *state.CertState, replaces string) error {
	key, err := GenerateKey(c.KeyType)
	if err != nil {
		return m.recordFailure(st, err)
	}
	keyPEM, err := MarshalPrivateKeyPEM(key)
	if err != nil {
		return m.recordFailure(st, err)
	}

	order, err := m.core.NewOrder(c.Domains, &api.OrderOptions{
		Profile:        c.Profile,
		ReplacesCertID: replaces,
	})
	if err != nil && replaces != "" && mentionsReplaces(err) {
		// A rejected `replaces` must never be a dead end.
		//
		// The CA validates the field against the certificate it names, and a refusal
		// comes back from newOrder -- so no order exists, and every later round sends
		// the same value and is refused identically. The certificate would then never
		// renew again, silently, until someone noticed it had expired. Losing the
		// rate-limit exemption is a far smaller cost than that, so retry once without
		// it. Covered here rather than only at the call site because the value flows in
		// from the ARI state, which any future change could get wrong.
		m.log.Warn("the CA refused the ARI replaces field; retrying the order without it "+
			"(this renewal loses the rate-limit exemption, which beats not renewing at all)",
			"cert", c.Name, "replaces", replaces, "err", err)
		order, err = m.core.NewOrder(c.Domains, &api.OrderOptions{Profile: c.Profile})
	}
	if err != nil {
		return m.recordFailure(st, fmt.Errorf("create order: %w", err))
	}
	if order.Location == "" {
		return m.recordFailure(st, errors.New("create order: the server returned no order URL"))
	}

	expiresAt, expErr := parseOrderExpires(order.Expires, m.now())
	if expErr != nil {
		m.log.Warn("cannot parse the order's expires; using a conservative TTL",
			"cert", c.Name, "raw", order.Expires, "err", expErr, "ttl", defaultOrderTTL)
	}

	o := &state.Order{
		CertName:    c.Name,
		OrderURL:    order.Location,
		FinalizeURL: order.Finalize,
		CertURL:     order.Certificate,
		ExpiresAt:   expiresAt,
		Status:      order.Status,
		KeyPEM:      keyPEM,
		// Record this order's identifier set. If the configured domains change later, Reconcile
		// spots it immediately and discards the order, instead of advancing it until it expires.
		Identifiers: c.DomainKey(),
	}
	if err := m.store.PutOrder(o); err != nil {
		return err
	}

	m.log.Info("ACME order created",
		"cert", c.Name, "status", order.Status, "expiresAt", expiresAt,
		"names", len(c.Domains), "profile", order.Profile, "replaces", replaces != "")
	return m.advance(ctx, c, st, o)
}

// mentionsReplaces reports whether an order-creation error is the CA refusing the ARI
// `replaces` field.
//
// Matching on the message is a best-effort signal, and deliberately so: it only decides
// whether to retry once without `replaces`, so a false negative leaves the caller where it
// already was (the order fails, the pass is retried on the usual backoff), while a false
// positive costs one extra newOrder call and still creates the order. Neither outcome can
// damage state, which is why this does not need a typed error out of lego.
func mentionsReplaces(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "replaces")
}
