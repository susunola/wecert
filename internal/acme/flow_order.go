package acme

import (
	"strings"

	"context"
	"errors"
	"fmt"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/ratelimit"
	"github.com/susunola/wecert/internal/state"
)

// Split out so one concern lives in one file. Same package.

func (m *Manager) finalize(
	ctx context.Context, c *config.Certificate, st *state.CertState,
	o *state.Order, order legoacme.ExtendedOrder, rd round,
) error {
	key, err := ParsePrivateKeyPEM(o.KeyPEM)
	if err != nil {
		return m.recordFailure(ctx, st, fmt.Errorf("load the order's private key: %w", err))
	}
	csr, err := CreateCSRDER(key, c.Domains)
	if err != nil {
		return m.recordFailure(ctx, st, err)
	}

	if o.FinalizeURL == "" {
		return m.recordFailure(ctx, st, errors.New("the order has no finalize URL; cannot submit the CSR"))
	}

	// RFC 8555 section 7.4: the CSR must be POSTed to the order's finalize URL.
	//
	// lego's parameter is named orderURL, which is misleading -- UpdateForCSR POSTs straight to
	// whatever URL you hand it. Passing the order URL makes LE treat it as POST-as-GET and
	// fail with "POST-as-GET requests must have an empty payload".
	if _, err := m.core.UpdateOrderForCSR(o.FinalizeURL, csr); err != nil {
		return m.recordFailure(ctx, st, fmt.Errorf("submit CSR (finalize): %w", err))
	}

	final, err := m.awaitOrderStatus(ctx, o.OrderURL, "valid", orderWaitTimeout)
	if err != nil {
		return m.recordFailure(ctx, st, err)
	}
	if err := m.persistOrder(o, final); err != nil {
		return m.recordFailure(ctx, st, err)
	}
	return m.download(ctx, c, st, o, final, rd)
}

func (m *Manager) awaitOrderStatus(
	ctx context.Context, orderURL, want string, timeout time.Duration,
) (legoacme.ExtendedOrder, error) {
	deadline := m.now().Add(timeout)
	var last legoacme.ExtendedOrder

	for {
		o, err := m.core.GetOrder(orderURL)
		if err != nil {
			return last, fmt.Errorf("poll order: %w", err)
		}
		last = o

		switch o.Status {
		case want, "valid":
			return o, nil
		case "invalid":
			return o, fmt.Errorf("order became invalid: %v", o.Err())
		}

		if m.now().After(deadline) {
			// The argument order matters and nothing checks it: %q accepts a time.Duration (it is
			// a string verb, and Duration has a String method), so swapping the first two produced
			// `did not reach "3m0s" within ready` with go vet still clean.
			return last, fmt.Errorf("the order did not reach %q within %s (currently %q)", want, timeout, o.Status)
		}
		select {
		case <-ctx.Done():
			return last, ctx.Err()
		case <-time.After(m.pollInterval):
		}
	}
}

// spendAuthzFailure books one failed authorization against the identifier's hourly budget.
//
// This is one of the five failed authorizations per identifier per hour that Let's Encrypt allows.
// Nobody spent it while a gauge for it was published anyway, and Remaining on a bucket nobody
// writes returns Capacity by design -- so the number was structurally always full and the alert
// built on it could never fire, on the limit a DNS-01 misconfiguration burns first.
//
// The scope matches the one publishQuota derives (the lowercased identifier), so the spend and the
// gauge land on the same series.
func (m *Manager) spendAuthzFailure(identifier string) {
	if m.quota == nil {
		return
	}
	m.quota.Spend(ratelimit.AuthzFailuresPerIdentifier, strings.ToLower(identifier), 1)
}
