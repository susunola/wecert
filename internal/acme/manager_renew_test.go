package acme

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
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
	// And it must NOT be booked as the fifth limit's pause. This message carries an instant, which
	// Boulder's per-hour budget template always does and the pausing limit never does; reading it as
	// a pause would stop this certificate for a day over a budget that refills in twelve minutes.
	if _, _, paused := m.quota.BlockedUntil(
		ratelimit.ConsecutiveAuthzFailuresPerIdentifier, "bad.example.com"); paused {
		t.Error("a budget refusal that names its instant was booked as the identifier pause; the " +
			"instant is the only thing that tells the two apart")
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

// The FIFTH published limit is the PAUSED identifier, and its refusals have to be told apart from
// the fourth limit's -- with the right limit and the right scope for each.
//
// Both wordings are quoted from their source rather than invented here:
//
//   - the bare form is Let's Encrypt's own documented failed-validation error,
//     "too many failed authorizations recently: see https://letsencrypt.org/docs/failed-validation-limit/",
//     and the rate-limits page describes what crossing the consecutive-failure budget does: the
//     subscriber "will receive an error containing a link to our Self-Service Portal where they can
//     unpause issuance for the paused identifier";
//   - the second form is what Boulder's WFE builds today (wfe2/wfe.go, probs.Paused): "Your account
//     is temporarily prevented from requesting certificates for %s and possibly others. Please
//     visit: <portal>", where %s is strings.Join(names, ", ") -- NOT quoted, which is why
//     quotedDomain alone cannot scope it.
//
// The discriminator against the per-hour failure BUDGET is the instant, and that is not a guess:
// Boulder's budget message comes from a template that always ends ", retry after %s"
// (ratelimits/limiter.go), and the pausing limit deliberately has no case in that switch -- "There
// is no case for FailedAuthorizationsForPausingPerDomainPerAccount because the RA will pause
// clients who exceed that ratelimit". The Retry-After header is no help either: Boulder emits it
// only for the limiter's own typed errors, not for the pause problem. So a "failed authorizations"
// refusal that names no instant anywhere is the pause.
func TestThePauseRefusalIsRecognisedByItsWordingAndItsMissingInstant(t *testing.T) {
	// The certificate's FIRST domain is not the one the CA names in the scoped cases, so a
	// "certificate's first domain" guess cannot pass by accident.
	cert := &config.Certificate{Name: "site", Domains: []string{"a.example.com", "b.example.com"}}

	cases := []struct {
		name string
		// message is the text lego surfaces: "acme: error: <status> :: <problem type> :: <detail>".
		message string
		// pause is what isPauseRefusal must answer.
		pause bool
		// limits are the limit names refusedLimits must map the message to, in order.
		limits []string
		// pauseScope is the bucket the pause must be booked against, "" to skip the check.
		pauseScope string
		// budgetScope is the bucket the failure BUDGET must be booked against, "" to skip.
		budgetScope string
	}{
		{
			name: "the documented bare form names no identifier",
			message: "acme: error: 429 :: urn:ietf:params:acme:error:rateLimited :: too many failed " +
				"authorizations recently: see https://letsencrypt.org/docs/failed-validation-limit/",
			pause: true,
			limits: []string{
				ratelimit.AuthzFailuresPerIdentifier.Name,
				ratelimit.ConsecutiveAuthzFailuresPerIdentifier.Name,
			},
			// Nothing quoted: the certificate's own first domain is the only handle there is.
			pauseScope:  "a.example.com",
			budgetScope: "a.example.com",
		},
		{
			name: "the counter form names the identifier it counted",
			message: "acme: error: 429 :: urn:ietf:params:acme:error:rateLimited :: too many failed " +
				"authorizations (5) for \"b.example.com\" in the last 1h0m0s",
			pause: true,
			limits: []string{
				ratelimit.AuthzFailuresPerIdentifier.Name,
				ratelimit.ConsecutiveAuthzFailuresPerIdentifier.Name,
			},
			pauseScope:  "b.example.com",
			budgetScope: "b.example.com",
		},
		{
			name: "the counter form WITH its instant is the budget, not the pause",
			message: "acme: error: 429 :: urn:ietf:params:acme:error:rateLimited :: too many failed " +
				"authorizations (5) for \"b.example.com\" in the last 1h0m0s, retry after " +
				"2026-09-16 15:00:00 UTC: see https://letsencrypt.org/docs/rate-limits/",
			pause:       false,
			limits:      []string{ratelimit.AuthzFailuresPerIdentifier.Name},
			pauseScope:  "b.example.com",
			budgetScope: "b.example.com",
		},
		{
			name: "Boulder's current portal wording lists the names unquoted",
			message: "acme: error: 429 :: urn:ietf:params:acme:error:rateLimited :: Your account is " +
				"temporarily prevented from requesting certificates for b.example.com, a.example.com " +
				"and possibly others. Please visit: https://unpause.letsencrypt.org/?jwt=eyJhbGciOi",
			pause:      true,
			limits:     []string{ratelimit.ConsecutiveAuthzFailuresPerIdentifier.Name},
			pauseScope: "b.example.com",
		},
		{
			name: "an unrelated refusal is not a pause",
			message: "acme: error: 429 :: urn:ietf:params:acme:error:rateLimited :: too many " +
				"certificates (50) already issued for \"example.com\" in the last 168h0m0s",
			pause:  false,
			limits: []string{ratelimit.CertsPerRegisteredDomain.Name},
		},
		{
			name: "a new-orders refusal is not a pause either",
			message: "acme: error: 429 :: urn:ietf:params:acme:error:rateLimited :: too many new " +
				"orders (300) from this account in the last 3h0m0s",
			pause:  false,
			limits: []string{ratelimit.NewOrdersPerAccount.Name},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPauseRefusal(tc.message); got != tc.pause {
				t.Errorf("isPauseRefusal = %v, want %v: the pause is the failure-family refusal with NO "+
					"instant, because the pausing limit has no retry-after message of its own", got, tc.pause)
			}
			if got := strings.Join(refusedLimitNames(tc.message), ", "); got != strings.Join(tc.limits, ", ") {
				t.Errorf("refusedLimits = [%s], want [%s]", got, strings.Join(tc.limits, ", "))
			}
			if tc.pauseScope != "" {
				got := newOrderRefusalScope(ratelimit.ConsecutiveAuthzFailuresPerIdentifier, cert, tc.message)
				if got != tc.pauseScope {
					t.Errorf("pause scope = %q, want %q: the identifier named in the message wins, and "+
						"only an unnamed message falls back to the certificate's first domain", got, tc.pauseScope)
				}
			}
			if tc.budgetScope != "" {
				got := newOrderRefusalScope(ratelimit.AuthzFailuresPerIdentifier, cert, tc.message)
				if got != tc.budgetScope {
					t.Errorf("failure-budget scope = %q, want %q", got, tc.budgetScope)
				}
			}
		})
	}
}

// An identifier the CA has paused must stop ordering, and the journal has to say so.
//
// Before this, a pause refusal parsed no instant, so the booking loop recorded nothing and the pass
// fell back to its own 1m..6h backoff. The pause is a latch in the CA's database that only its
// self-service portal clears, so every one of those retries was a request the CA had already
// refused, and the operator saw ordinary "pass failed" lines instead of the one fact that matters.
func TestAPausedIdentifierStopsOrderingForADayAndTheLogNamesThePause(t *testing.T) {
	fixed := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	var logs bytes.Buffer
	store, m, fake, cert := newAPITestHarnessAt(t, filepath.Join(t.TempDir(), "state.db"),
		[]string{"bad.example.com"}, slog.New(slog.NewTextHandler(&logs, nil)))
	now := fixed
	m.SetNow(func() time.Time { return now })
	dueForRenewal(t, store, cert, fixed)
	fake.orders = []legoacme.ExtendedOrder{terminalOrder(
		"https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/1")}
	fake.newOrderErr = errors.New(pauseRefusal)

	if err := m.Reconcile(context.Background(), cert); err == nil {
		t.Fatal("a rate-limited order must be reported as a failure")
	}

	at, reason, blocked := m.quota.BlockedUntil(ratelimit.ConsecutiveAuthzFailuresPerIdentifier, "bad.example.com")
	if !blocked {
		t.Fatalf("the CA paused this identifier and named no instant; the deadline has to be booked from "+
			"the published refill rate, or the next pass retries into the pause (reason=%q)", reason)
	}
	// One refill interval at the published "1 per identifier per day" rate. That number is a FLOOR
	// on our own wait -- the shortest wait the published model can justify -- not the CA's answer,
	// which is why the assertion is on the published constant rather than on a literal.
	want := fixed.Add(ratelimit.ConsecutiveAuthzFailuresPerIdentifier.Refill)
	if !at.Equal(want) {
		t.Errorf("pause deadline = %s, want %s (one published refill interval)", at, want)
	}
	if reason != ratelimit.ConsecutiveAuthzFailuresPerIdentifier.Name {
		t.Errorf("the deadline must name the paused-identifier limit, got %q", reason)
	}
	if !strings.Contains(logs.String(), "PAUSED") {
		t.Errorf("the refusal has to be reported as a pause, not as an ordinary rate-limit refusal; "+
			"the journal says:\n%s", logs.String())
	}
	// The pause is per IDENTIFIER: the account-wide budget must not be marked by it.
	if _, _, wrong := m.quota.BlockedUntil(ratelimit.NewOrdersPerAccount, ""); wrong {
		t.Error("the account-wide order budget was marked blocked by a refusal about one identifier")
	}

	// The next pass, an hour later and well inside the floor: no order is placed, and the journal
	// says why (and what actually clears it).
	logs.Reset()
	now = fixed.Add(time.Hour)
	before := newOrderCalls(fake)
	err := m.Reconcile(context.Background(), cert)
	if err == nil {
		t.Fatal("a pass inside the pause must not report convergence")
	}
	if got := newOrderCalls(fake); got != before {
		t.Errorf("a paused identifier must not be ordered for inside the floor: NewOrder calls %d -> %d",
			before, got)
	}
	out := logs.String()
	if !strings.Contains(out, "PAUSED") || !strings.Contains(out, "self-service portal") {
		t.Errorf("the blocked pass must name the pause and the only thing that lifts it; the journal says:\n%s", out)
	}
	if !strings.Contains(err.Error(), "paused") {
		t.Errorf("the pass error must say the identifier is paused, got %q", err)
	}
}

// A pause deadline outlives the process that recorded it.
//
// A restart (a deploy, a reboot, an upgrade) is far more frequent than the day-long floor, so an
// in-memory-only deadline would be forgotten by exactly the pass that follows the restart -- and
// that pass would order straight back into the pause. The deadline lives in the rate_buckets row,
// which is what this asserts by closing the store and reopening the file.
func TestThePauseDeadlineSurvivesARestart(t *testing.T) {
	fixed := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	dbPath := filepath.Join(t.TempDir(), "state.db")
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	store, m, fake, cert := newAPITestHarnessAt(t, dbPath, []string{"bad.example.com"}, logger)
	m.SetNow(func() time.Time { return fixed })
	dueForRenewal(t, store, cert, fixed)
	fake.orders = []legoacme.ExtendedOrder{terminalOrder(
		"https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/1")}
	fake.newOrderErr = errors.New(pauseRefusal)

	if err := m.Reconcile(context.Background(), cert); err == nil {
		t.Fatal("a rate-limited order must be reported as a failure")
	}

	// The process ends here. Everything the next one knows has to come off the disk.
	if err := store.Close(); err != nil {
		t.Fatalf("closing the state store: %v", err)
	}
	reopened, err := state.Open(dbPath)
	if err != nil {
		t.Fatalf("reopening the state store: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })

	restarted := newManager(reopened, fake, &fakeSolver{}, fakeKeyAuth{}, deploy.Noop{}, logger)
	restarted.SetNow(func() time.Time { return fixed.Add(time.Hour) })

	at, _, blocked := restarted.quota.BlockedUntil(
		ratelimit.ConsecutiveAuthzFailuresPerIdentifier, "bad.example.com")
	if !blocked {
		t.Fatal("the pause deadline is persisted in rate_buckets; a restart must not clear it, or the " +
			"first pass of the new process orders straight back into the pause")
	}
	if want := fixed.Add(ratelimit.ConsecutiveAuthzFailuresPerIdentifier.Refill); !at.Equal(want) {
		t.Errorf("reloaded deadline = %s, want %s", at, want)
	}

	before := newOrderCalls(fake)
	if err := restarted.Reconcile(context.Background(), cert); err == nil {
		t.Fatal("a restarted pass inside the pause must not report convergence")
	}
	if got := newOrderCalls(fake); got != before {
		t.Errorf("the restarted process ordered into a pause the previous one had already recorded: "+
			"NewOrder calls %d -> %d", before, got)
	}
}

// The new recognition must not swallow refusals that are not the pause.
//
// A recognised limit whose refusal names no instant (a truncated message, a proxy that ate the
// tail) has to keep today's behaviour: nothing is booked, the pass counts as a failure, and the
// next one retries at our own backoff. Booking a day-long pause out of it would delay a renewal the
// CA never refused for that long -- and the fifth limit is the only refusal the CA leaves without
// an instant on purpose, which is what makes the discrimination possible at all.
func TestARefusalWithoutAnInstantThatIsNotAPauseStillRetries(t *testing.T) {
	fixed := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	now := fixed
	m.SetNow(func() time.Time { return now })
	dueForRenewal(t, store, cert, fixed)
	fake.orders = []legoacme.ExtendedOrder{terminalOrder(
		"https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/1")}
	fake.newOrderErr = errors.New("acme: error: 429 :: urn:ietf:params:acme:error:rateLimited :: " +
		"too many certificates (50) already issued for \"example.com\" in the last 168h0m0s")

	if err := m.Reconcile(context.Background(), cert); err == nil {
		t.Fatal("a rate-limited order must be reported as a failure")
	}

	checks := []struct {
		limit ratelimit.Limit
		scope string
	}{
		{ratelimit.NewOrdersPerAccount, ""},
		{ratelimit.CertsPerRegisteredDomain, "example.com"},
		{ratelimit.CertsPerExactIdentifierSet, cert.DomainKey()},
		{ratelimit.AuthzFailuresPerIdentifier, "example.com"},
		{ratelimit.ConsecutiveAuthzFailuresPerIdentifier, "example.com"},
	}
	for _, chk := range checks {
		if at, _, blocked := m.quota.BlockedUntil(chk.limit, chk.scope); blocked {
			t.Errorf("%s/%q was marked blocked until %s by a refusal that names no instant and is not "+
				"the pause; an unparseable refusal keeps the backoff path", chk.limit.Name, chk.scope, at)
		}
	}

	// The ordinary backoff is one minute for the first failure, so the next pass at +2m tries again.
	now = fixed.Add(2 * time.Minute)
	before := newOrderCalls(fake)
	_ = m.Reconcile(context.Background(), cert)
	if got := newOrderCalls(fake); got != before+1 {
		t.Errorf("an unparseable refusal must still retry at our own backoff: NewOrder calls %d -> %d",
			before, got)
	}
}

// pauseRefusal is the bare wording Let's Encrypt documents for the failed-validation limit, with no
// instant in it -- the shape that reaches us when the CA has PAUSED the identifier rather than
// spent a bucket. It is a package-level constant so the three tests above refuse with the same text.
const pauseRefusal = "acme: error: 429 :: urn:ietf:params:acme:error:rateLimited :: too many failed " +
	"authorizations recently: see https://letsencrypt.org/docs/failed-validation-limit/"

// refusedLimitNames renders refusedLimits for a test failure message.
func refusedLimitNames(msg string) []string {
	var names []string
	for _, l := range refusedLimits(msg) {
		names = append(names, l.Name)
	}
	return names
}

// newOrderCalls counts the NewOrder attempts in the fake's call log.
func newOrderCalls(fake *fakeAPI) int {
	var n int
	for _, call := range fake.calls {
		if strings.HasPrefix(call, "NewOrder") {
			n++
		}
	}
	return n
}

// The identifier pause and the failed-authorization budget must key on the same name for a wildcard.
//
// The CA's pause names (or is recorded against) the authorization identifier, which never carries the
// wildcard's "*." prefix -- the same rule the budget's own scope follows. Keying the pause gate on
// the configured domain instead split the pair: the refusal was booked against "example.com" and the
// gate asked about "*.example.com", so a paused wildcard identifier kept ordering inside the window
// the CA had just named -- the one thing this limit is checked for.
func TestAWildcardIdentifierPauseGatesTheWildcardCertificate(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"*.example.com"})
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return fixed })
	dueForRenewal(t, store, cert, fixed)
	fake.orders = []legoacme.ExtendedOrder{terminalOrder(
		"https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/1")}
	// Boulder's pause wording, naming the bare identifier (never the wildcard form).
	fake.newOrderErr = errors.New("acme: error: 429 :: urn:ietf:params:acme:error:rateLimited :: " +
		"too many failed authorizations recently: see https://letsencrypt.org/docs/rate-limits/ " +
		"temporarily prevented from requesting certificates for example.com")

	if err := m.Reconcile(context.Background(), cert); err == nil {
		t.Fatal("a refused order must be reported as a failure")
	}

	// The refusal is booked against the bare name, and the gate for this wildcard certificate has to
	// find it there.
	if _, _, blocked := m.quota.BlockedUntil(
		ratelimit.ConsecutiveAuthzFailuresPerIdentifier, "example.com"); !blocked {
		t.Fatal("the pause was not booked against the identifier the CA named")
	}
	if _, _, blocked := m.quota.BlockedUntil(ratelimit.ConsecutiveAuthzFailuresPerIdentifier, "*.example.com"); blocked {
		t.Error("the pause was booked against the wildcard form, which no other scope of this limit uses")
	}

	// And ordering stops: the next due pass must not place another order while the pause stands.
	//
	// The clock moves past our own backoff and past the failure cooldown first, so the pause is the
	// only thing left that can stop the order -- at the same instant the pass would be refused for
	// being inside its retry window, and the test would pass without testing the gate at all. The
	// pause's floor is a day, so six hours later it is still in force.
	fake.newOrderErr = nil
	fake.orders = nil
	advanced := fixed.Add(6 * time.Hour)
	m.SetNow(func() time.Time { return advanced })
	before := newOrderCalls(fake)
	if err := m.Reconcile(context.Background(), cert); err == nil {
		t.Error("a paused identifier must not be ordered again")
	}
	if got := newOrderCalls(fake); got != before {
		t.Errorf("an order was placed for a paused wildcard identifier (%d new call(s))", got-before)
	}
}
