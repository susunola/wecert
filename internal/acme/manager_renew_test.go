package acme

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/ratelimit"
	"github.com/susunola/wecert/internal/state"
)

// dueForRenewal stores a certificate whose expiry is inside the renewal window, with no order row,
// so the next pass decides to place an order.
func dueForRenewal(t *testing.T, store *state.Store, cert *config.Certificate, now time.Time) {
	t.Helper()
	expiry := now.Add(10 * 24 * time.Hour)
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: expiry,
		CertPEM: selfSignedCertPEM(t, expiry, cert.Domains...),
	}); err != nil {
		t.Fatal(err)
	}
}

// The CA's own deadline must stop the order before it is placed.
//
// The bucket was written, published as a metric and otherwise ignored: a "retry after 3h" was
// followed by new-order attempts at our own 1m..6h backoff, eight of them inside one three-hour
// window in a measured run. Each of those is a request the CA has already said cannot succeed, and
// on the identifier limits they also count against the budget every certificate for that name
// shares.
func TestARecordedDeadlineStopsTheOrderBeforeItIsPlaced(t *testing.T) {
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

	t.Run("account wide", func(t *testing.T) {
		store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
		m.SetNow(func() time.Time { return fixed })
		dueForRenewal(t, store, cert, fixed)
		// The CA said "not before 15:00".
		if err := store.UpdateRateBucket(ratelimit.NewOrdersPerAccount.Name, "", func(rec *state.RateBucket) error {
			rec.ResetAt = fixed.Add(3 * time.Hour)
			rec.ResetReason = ratelimit.NewOrdersPerAccount.Name
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		if err := m.Reconcile(context.Background(), cert); err == nil {
			t.Fatal("a pass inside the CA's own window must be reported as not converged")
		}
		for _, call := range fake.calls {
			if strings.HasPrefix(call, "NewOrder") {
				t.Errorf("no order may be placed inside the window the CA named, calls: %v", fake.calls)
			}
		}
	})

	t.Run("per domain, only for that domain", func(t *testing.T) {
		store, m, fake, cert := newAPITestHarness(t, []string{"a.example.com"})
		m.SetNow(func() time.Time { return fixed })
		dueForRenewal(t, store, cert, fixed)
		if err := store.UpdateRateBucket(ratelimit.CertsPerRegisteredDomain.Name, "example.com",
			func(rec *state.RateBucket) error {
				rec.ResetAt = fixed.Add(3 * time.Hour)
				rec.ResetReason = ratelimit.CertsPerRegisteredDomain.Name
				return nil
			}); err != nil {
			t.Fatal(err)
		}
		fake.orders = []legoacme.ExtendedOrder{terminalOrder(
			"https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/1")}

		if at, why, blocked := m.quota.BlockedUntil(ratelimit.CertsPerRegisteredDomain, "example.com"); !blocked {
			t.Fatalf("the fixture did not record a deadline (at=%s why=%q)", at, why)
		}
		if err := m.Reconcile(context.Background(), cert); err == nil {
			t.Fatal("the paused domain's own certificate must not order")
		}
		for _, call := range fake.calls {
			if strings.HasPrefix(call, "NewOrder") {
				t.Errorf("NewOrder was called for a domain the CA has paused: %v", fake.calls)
			}
		}

		// A different REGISTERED domain is unaffected: refusing every order because one domain is
		// paused would stall the whole fleet.
		otherStore, otherM, otherFake, other := newAPITestHarness(t, []string{"b.other.com"})
		otherM.SetNow(func() time.Time { return fixed })
		_ = otherStore
		dueForRenewal(t, otherStore, other, fixed)
		otherFake.orders = []legoacme.ExtendedOrder{terminalOrder(
			"https://ca.test/order/2", "https://ca.test/finalize/2", "https://ca.test/cert/2")}
		_ = otherM.Reconcile(context.Background(), other)
		var ordered bool
		for _, call := range otherFake.calls {
			if strings.HasPrefix(call, "NewOrder") {
				ordered = true
			}
		}
		if !ordered {
			t.Errorf("a certificate for another domain must still be able to order, calls: %v", otherFake.calls)
		}
	})
}

// Boulder's fourth new-order limit is per DOMAIN, and its wording names the domain.
//
// Booking it against new-orders (the fallback for anything unrecognised) put the deadline on a
// bucket that has nothing to do with the refusal: the operator saw the whole account marked blocked
// while the paused identifier's own series still read "5 of 5 left".
func TestTheFailedAuthorizationRefusalIsBookedOnTheIdentifier(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"bad.example.com"})
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return fixed })
	dueForRenewal(t, store, cert, fixed)
	fake.orders = []legoacme.ExtendedOrder{terminalOrder(
		"https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/1")}
	fake.newOrderErr = errors.New("acme: error: 429 :: urn:ietf:params:acme:error:rateLimited :: too many " +
		"failed authorizations (5) for \"bad.example.com\" in the last 1h0m0s, retry after " +
		"2026-09-16 15:00:00 UTC: see https://letsencrypt.org/docs/rate-limits/")

	if err := m.Reconcile(context.Background(), cert); err == nil {
		t.Fatal("a rate-limited order must be reported as a failure")
	}

	at, reason, blocked := m.quota.BlockedUntil(ratelimit.AuthzFailuresPerIdentifier, "bad.example.com")
	if !blocked {
		t.Fatalf("the refusal names the identifier's failed-authorization budget, so that deadline "+
			"must gate the identifier; got blocked=false (reason=%q at=%s)", reason, at)
	}
	if _, _, wrong := m.quota.BlockedUntil(ratelimit.NewOrdersPerAccount, ""); wrong {
		t.Error("the account-wide order budget was marked blocked by a refusal that names an identifier")
	}
}

// A 429 that carries the instant only in the Retry-After HEADER must still record a deadline, and
// must not be followed by the immediate replaces-less retry.
func TestTheRetryAfterHeaderIsHonouredAndNotRetriedInto(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return fixed })
	dueForRenewal(t, store, cert, fixed)
	fake.orders = []legoacme.ExtendedOrder{terminalOrder(
		"https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/1")}
	// The message carries no parsable instant; lego's typed error carries the header.
	fake.newOrderErr = &legoacme.RateLimitedError{
		ProblemDetails: &legoacme.ProblemDetails{Type: "urn:ietf:params:acme:error:rateLimited",
			Detail: "too many certificates already issued for this exact set of identifiers"},
		RetryAfter: "10800", // three hours, the delay-seconds form
	}
	// A pass that already has an ARI certID would send `replaces`; this one does not, so the retry
	// path is not what is being measured here -- the deadline is.
	if err := m.Reconcile(context.Background(), cert); err == nil {
		t.Fatal("a rate-limited order must be reported as a failure")
	}

	_, _, blocked := m.quota.BlockedUntil(ratelimit.CertsPerExactIdentifierSet, cert.DomainKey())
	if !blocked {
		t.Error("a Retry-After header with no instant in the message must still record a deadline; " +
			"otherwise the bucket reads optimistic and the pass comes straight back")
	}
}

// An expired certificate must not be polled for ARI.
//
// RFC 9773 section 4.3: clients MUST NOT send requests for certificates that have expired. The CA's
// answer cannot change anything -- there is nothing left to renew -- and a certificate that expired
// long ago (a fleet member failing for months) would otherwise be polled for as long as it stays in
// the desired state.
func TestAnExpiredCertificateDoesNotAskTheCAForARI(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return fixed })

	st := &state.CertState{
		Name:      cert.Name,
		NotAfter:  fixed.Add(-30 * 24 * time.Hour), // expired a month ago
		ARICertID: "ari-id",
		CertPEM:   selfSignedCertPEM(t, fixed.Add(-30*24*time.Hour), "example.com"),
	}
	if err := store.PutCert(st); err != nil {
		t.Fatal(err)
	}
	fake.orders = []legoacme.ExtendedOrder{terminalOrder(
		"https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/1")}

	_ = m.Reconcile(context.Background(), cert)
	if fake.renewalInfoHits != 0 {
		t.Errorf("an expired certificate must not be the subject of a renewalInfo request, got %d",
			fake.renewalInfoHits)
	}
}

var _ = config.ProfileClassic

// A refusal must be booked against the name the CA actually named.
//
// The scope extractor recognised only the "already issued for %q" phrasing, so Boulder's
// failed-authorization refusal fell through to the certificate's FIRST domain. That was invisible
// while nothing read the deadline; round 8 made the deadline gate ordering, and then it became an
// availability bug in both directions: the certificate containing the paused name kept ordering
// inside the CA's window, and an unrelated certificate that happened to share the first domain was
// refused for the whole window.
func TestARefusalIsBookedAgainstTheNameTheCANamed(t *testing.T) {
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

	// A certificate whose FIRST domain is not the one the CA paused.
	cert := &config.Certificate{Name: "site", Domains: []string{"a.example.com", "b.example.com"}}
	msg := "acme: error: 429 :: urn:ietf:params:acme:error:rateLimited :: too many failed " +
		"authorizations (5) for \"b.example.com\" in the last 1h0m0s, retry after " +
		"2026-09-16 15:00:00 UTC: see https://letsencrypt.org/docs/rate-limits/"

	got := newOrderRefusalScope(ratelimit.AuthzFailuresPerIdentifier, cert, msg)
	if got != "b.example.com" {
		t.Fatalf("the refusal names b.example.com, so the deadline must be booked against it; got %q. "+
			"Booked against a.example.com instead, the certificate that actually holds the paused name "+
			"is not gated and an unrelated one sharing that first domain is", got)
	}

	// The registered-domain wording must keep working (it never contains the words "registered
	// domain"): the name it counts is the quoted one.
	got = newOrderRefusalScope(ratelimit.CertsPerRegisteredDomain, cert,
		"acme: error: 429 :: too many certificates (50) already issued for \"example.com\" in the "+
			"last 168h0m0s, retry after 2026-09-16 15:00:00 UTC")
	if got != "example.com" {
		t.Errorf("registered-domain scope = %q, want example.com", got)
	}

	// No quoted name at all: the fallback stays the certificate's own first domain, which is the
	// best guess available and is what the wildcard case relies on.
	got = newOrderRefusalScope(ratelimit.AuthzFailuresPerIdentifier, cert,
		"acme: error: 429 :: too many failed authorizations, retry after 2026-09-16 15:00:00 UTC")
	if got != "a.example.com" {
		t.Errorf("with nothing quoted the first domain is the only answer available, got %q", got)
	}
	_ = fixed
}
