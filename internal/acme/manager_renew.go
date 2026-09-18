package acme

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/ratelimit"
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

	// RFC 9773 section 4.3: "clients MUST NOT send requests for certificates that have expired".
	// An expired certificate has nothing to renew and the CA's answer cannot change the decision --
	// and a certificate that expired long ago (a fleet member that has been failing for months)
	// would otherwise be polled for as long as it stays in the desired state.
	expired := !st.NotAfter.IsZero() && !now.Before(st.NotAfter)

	if st.ARICertID != "" && !expired && m.ariCheckDue(st, now) {
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
			if errors.Is(err, ErrRenewalInfoLongTerm) {
				// A long-term answer: the CA does not know this certificate, so a short Retry-After
				// would have us asking again in a minute for the rest of the deployment's life.
				// The floor applies.
				st.ARIRetryAfter = 0
			}
			if perr := m.store.PutCert(st); perr != nil {
				return time.Time{}, "", perr
			}
			ariErr = err
		}
	}

	if !st.ARIWindowStart.IsZero() && st.ARIWindowEnd.After(st.ARIWindowStart) {
		return RenewalTime(c.Name, st.ARIWindowStart, st.ARIWindowEnd), st.ARICertID, ariErr
	}
	// RFC 9773 section 4.2 makes the window a half-open interval, so end == start is malformed: it
	// describes no instant at all. The fallback below handles it (the schedule comes from NotAfter),
	// but silently -- and a CA that keeps sending one is worth seeing in the journal.
	if !st.ARIWindowStart.IsZero() && st.ARIWindowEnd.Equal(st.ARIWindowStart) {
		m.log.Warn("the CA returned an empty ARI window (start == end), which RFC 9773 section 4.2 "+
			"does not allow; falling back to the deterministic schedule for this renewal",
			"cert", c.Name, "start", st.ARIWindowStart)
	}

	// Fallback: no ARI, but the identifier set still stays identical, so at least we keep the
	// "non-ARI renewal" exemptions on the order count and on certificates per domain.
	base := st.NotAfter.Add(-c.RenewBeforeDur)
	return DeterministicTime(c.Name, base, c.RenewBeforeDur/8), st.ARICertID, ariErr
}

// spendNewOrder records one new-order spend against the account-wide bucket.
func (m *Manager) spendNewOrder() {
	m.quota.Spend(ratelimit.NewOrdersPerAccount, "", 1)
}

// noteNewOrderRefusal turns a new-order failure into the CA's deadline when it names one, on the
// limit the CA actually refused.
//
// A newOrder can be refused by any of the three certificate limits, and Boulder's message says
// which. Booking every refusal against new-orders marked the wrong series blocked AND left the
// refused limit reading optimistic -- and the exact-set limit is the one with no override path, so
// it is precisely the number an operator cannot appeal. Which scopes the per-certificate limits
// use is the same rule the spend path applies (see download): the exact identifier set, and each
// registered domain the order covers.
//
// NoteRetryAfter only answers for errors that actually carry a Retry-After (in the message or, via
// lego's typed error, in the header), so a refusal of any other kind is left to the caller's own
// failure accounting. The answer is also "should this pass retry right now": a refusal that named a
// deadline must not be followed by the immediate replaces-less retry, which would spend a second
// request inside the window the CA just named.
func (m *Manager) noteNewOrderRefusal(c *config.Certificate, err error) bool {
	named := refusedLimits(err.Error())
	if len(named) == 0 {
		// A rate-limited refusal that names no specific limit is most likely the account-wide
		// order budget, which is what this used to assume for all of them.
		named = []ratelimit.Limit{ratelimit.NewOrdersPerAccount}
	}

	// lego exposes the 429's Retry-After HEADER on its typed error, and only the free text used to be
	// parsed. A CA may send the header without repeating the instant in the message -- the field is
	// the protocol's own answer, the prose is commentary -- and then no deadline was recorded at all,
	// so the pass came straight back inside the window the CA had just named.
	headerAt, headerOK := time.Time{}, false
	var rle *legoacme.RateLimitedError
	if errors.As(err, &rle) && rle.RetryAfter != "" {
		headerAt, headerOK = ratelimit.ParseRetryAfterHeader(rle.RetryAfter)
	}

	blocked := false
	for _, l := range named {
		scope := newOrderRefusalScope(l, c, err.Error())
		at, ok := m.quota.NoteRetryAfter(l, scope, err.Error())
		if !ok && headerOK {
			// The message had no parsable instant; the header did.
			m.quota.NoteDeadline(l, scope, headerAt, "retry-after header")
			at, ok = headerAt, true
		}
		if !ok {
			continue
		}
		blocked = true
		m.log.Error("the CA refused a new order against a documented rate limit; every request "+
			"against that limit must wait for the reported instant",
			"cert", c.Name, "limit", l.Name, "scope", scope, "until", at)
	}
	return blocked
}

// blockedByRecordedDeadline reports whether the CA has told us not to come back yet.
//
// The account-wide new-order limit gates everything, so it is checked first; the per-scope limits
// (the exact identifier set, each registered domain, each identifier) gate only the certificate in
// front of us. Returns the instant, the limit name, the scope and whether anything blocked.
func (m *Manager) blockedByRecordedDeadline(c *config.Certificate) (time.Time, string, string, bool) {
	type check struct {
		limit ratelimit.Limit
		scope string
	}
	checks := []check{{limit: ratelimit.NewOrdersPerAccount}}
	checks = append(checks, check{limit: ratelimit.CertsPerExactIdentifierSet, scope: c.DomainKey()})
	for _, d := range uniqueRegisteredDomains(c.Domains) {
		checks = append(checks, check{limit: ratelimit.CertsPerRegisteredDomain, scope: d})
	}
	for _, d := range c.Domains {
		checks = append(checks, check{limit: ratelimit.AuthzFailuresPerIdentifier, scope: strings.ToLower(d)})
	}
	for _, ch := range checks {
		if ch.scope == "" && ch.limit.Scope != "account" {
			continue
		}
		if at, _, blocked := m.quota.BlockedUntil(ch.limit, ch.scope); blocked {
			return at, ch.limit.Name, ch.scope, true
		}
	}
	return time.Time{}, "", "", false
}

// scopeLabel renders a scope for a log or error message.
func scopeLabel(scope string) string {
	if scope == "" {
		return ""
	}
	return " for " + scope
}

// newOrderRefusalScope is the bucket a refused limit is recorded against, matching the scope the
// spend path uses for the same limit.
//
// For the registered-domain limit the CA names the domain it counted (Boulder:
// `too many certificates (%d) already issued for %q in the last %s, retry after %s`), and that name
// is preferred over guessing from the certificate's own domains: a certificate spanning several
// registered domains would otherwise have the deadline recorded against whichever one happens to
// come first, and the alert would point the operator at a domain that is not the exhausted one.
func newOrderRefusalScope(l ratelimit.Limit, c *config.Certificate, msg string) string {
	switch l.Name {
	case ratelimit.CertsPerExactIdentifierSet.Name:
		return c.DomainKey()
	case ratelimit.CertsPerRegisteredDomain.Name:
		if named := quotedDomain(msg); named != "" {
			return named
		}
		if doms := uniqueRegisteredDomains(c.Domains); len(doms) > 0 {
			return doms[0]
		}
	case ratelimit.AuthzFailuresPerIdentifier.Name:
		// The identifier budget is per NAME, and Boulder names the one it counted
		// (`too many failed authorizations (5) for "bad.example.com"`). Preferring the name in the
		// message over the certificate's first domain matters for the same reason it does above: a
		// certificate with several names would otherwise have the deadline recorded against one that
		// is fine -- and because the deadline now GATES ordering, that is not cosmetic: measured with
		// two certificates sharing a first domain, the one containing the paused name kept ordering
		// inside the CA's window while the unrelated one was refused.
		if named := quotedDomain(msg); named != "" {
			return named
		}
		if len(c.Domains) > 0 {
			return strings.ToLower(c.Domains[0])
		}
	}
	return ""
}

// quotedDomain extracts the FIRST quoted name from a refusal, or "" when there is none.
//
// Boulder names the thing it counted with %q in every limit message that has a scope:
//
//	too many certificates (%d) already issued for %q in the last %s, retry after %s
//	too many failed authorizations (%d) for %q in the last %s, retry after %s
//
// Matching on the whole phrase ("already issued for ") recognised only the first of those, so the
// second fell through to "the certificate's first domain" -- which books the deadline against a
// name the CA never mentioned. That was invisible while nothing read the deadline; once ordering
// consulted it, the certificate holding the paused name kept ordering and an unrelated certificate
// sharing the first domain was refused. A rate-limit message quotes the identifier it counted and
// nothing else, so the first quoted token is the right answer for both.
func quotedDomain(msg string) string {
	i := strings.IndexByte(msg, '"')
	if i < 0 {
		return ""
	}
	rest := msg[i+1:]
	j := strings.IndexByte(rest, '"')
	if j <= 0 {
		return ""
	}
	return strings.ToLower(rest[:j])
}

// refusedLimits maps the CA's own wording to the limits it refused.
//
// The phrases are Boulder's, taken from the limiter that produces them
// (ratelimits/limiter.go):
//
//	too many new orders (%d) from this account in the last %s, retry after %s
//	too many certificates (%d) already issued for %q in the last %s, retry after %s
//	too many certificates (%d) already issued for this exact set of identifiers in the last %s, retry after %s
//
// Matching text is not ideal -- the wording is the CA's to choose -- but a rate-limit refusal is
// exactly the case the protocol gives no machine-readable field for (the deadline itself is inside
// free text too, see ParseRetryAfter). Note the registered-domain message does NOT contain the words
// "registered domain": it names the domain instead, which is why the match is on the
// "already issued for \"..." shape. An unrecognised message falls back to new-orders, which is where
// every refusal used to be booked.
func refusedLimits(msg string) []ratelimit.Limit {
	lower := strings.ToLower(msg)
	var out []ratelimit.Limit
	exactSet := strings.Contains(lower, "exact set of identifiers") ||
		strings.Contains(lower, "exact-identifier-set")
	if exactSet {
		out = append(out, ratelimit.CertsPerExactIdentifierSet)
	}
	if !exactSet && strings.Contains(lower, "already issued for") {
		out = append(out, ratelimit.CertsPerRegisteredDomain)
	}
	// The fourth limit Boulder checks at new-order time is the per-domain failed-authorization
	// budget, and its wording names the domain:
	//
	//	too many failed authorizations (5) for %q in the last %s, retry after %s
	//
	// Booking it against new-orders (the fallback for anything unrecognised) pointed the operator at
	// the whole account while the paused identifier's own series still read "5 of 5 left", because
	// the deadline landed on a bucket that has nothing to do with the refusal.
	if strings.Contains(lower, "failed authorizations") {
		out = append(out, ratelimit.AuthzFailuresPerIdentifier)
	}
	if strings.Contains(lower, "new orders") || strings.Contains(lower, "new-orders") {
		out = append(out, ratelimit.NewOrdersPerAccount)
	}
	return out
}

func (m *Manager) ariCheckDue(st *state.CertState, now time.Time) bool {
	if st.ARICheckedAt.IsZero() {
		return true
	}
	// One effective interval: the server's Retry-After when it gives one, our own floor otherwise
	// (both clamped to the RFC's reasonableness bounds below).
	//
	// The two used to be checked in sequence with the fixed six-hour floor first, which made a
	// SHORTER Retry-After impossible to honour -- the floor had already returned false, so the
	// server's "come back in an hour" was silently extended to six. The comment on the second check
	// claimed the opposite ("respect the Retry-After the server gave us"), and RFC 9773 §4.3 makes
	// Retry-After both the earliest and the target time.
	//
	// The floor still applies when the server says nothing (or asks us to wait longer than it),
	// because renewalInfo is not free to poll; the clamps are the RFC's own reasonableness bounds.
	// When the server gave a Retry-After, that IS the interval (clamped to the RFC's reasonableness
	// bounds below); only without one does our own six-hour floor apply. Taking the minimum of the
	// two would let the floor stretch a server's "come back in an hour" to six.
	wait := m.ariInterval
	if st.ARIRetryAfter > 0 {
		wait = st.ARIRetryAfter
	}
	if wait < time.Minute {
		wait = time.Minute
	}
	if wait > 24*time.Hour {
		wait = 24 * time.Hour
	}
	return !now.Before(st.ARICheckedAt.Add(wait))
}

// issue creates an order. Mind the order of operations: persist the order (including the
// private key generated here) first, and only then advance it.
func (m *Manager) issue(ctx context.Context, c *config.Certificate, st *state.CertState, replaces string, rd round) error {
	// Do not spend an order on a name that just failed validation.
	//
	// The certificate backoff starts at a minute and doubles, so the first hour of a
	// persistently failing name costs six attempts against "5 authorization failures per
	// identifier per hour" -- and that budget belongs to the IDENTIFIER, so N certificates
	// sharing the name attack the same five. At ten certificates the first hour costs sixty
	// failures, of which at most five could ever have produced a different answer; past the
	// limit every further order for that name is rejected outright, so the attempts bought
	// nothing and the consecutive-failure counter (which feeds an account pause needing
	// manual intervention) kept climbing.
	//
	// Checked here, at the point an order would be created, so resuming an order that is
	// already in flight is unaffected -- that costs no new order and is how a pass that was
	// interrupted mid-validation finishes.
	if name, until, cooling := m.coolingDown(c.Name, c.Domains); cooling {
		m.log.Warn("an identifier's authorizations failed recently, so no new order is placed until its "+
			"failure budget refills; retrying inside the window cannot succeed and spends the budget "+
			"that other certificates for this name also depend on",
			"cert", c.Name, "identifier", name, "cooldownUntil", until,
			"remaining", until.Sub(m.now()).Round(time.Minute))
		return m.recordFailure(ctx, st, fmt.Errorf(
			"identifier %s is in its authorization-failure cooldown until %s; not placing an order",
			name, until.UTC().Format(time.RFC3339)))
	}

	// The CA's own deadline wins over our backoff.
	//
	// Nothing used to consult a recorded refusal before ordering: the bucket was written, published
	// as a metric and otherwise ignored, so a "retry after 3h" was followed by new-order attempts at
	// our own 1m..6h backoff -- eight of them inside one three-hour window in a measured run. Every
	// one of those is a request the CA has already said cannot succeed, and on the identifier limits
	// they also count against the budget the whole account shares.
	//
	// The account-wide limit stops the pass outright; a per-scope one stops only the certificates it
	// names, because refusing every order because one domain is paused would stall the fleet.
	if until, limit, scope, blocked := m.blockedByRecordedDeadline(c); blocked {
		m.log.Warn("the CA has refused this limit recently and named when it will listen again; no "+
			"order is placed before then, because the refusal is the CA's own answer and retrying "+
			"inside the window cannot change it",
			"cert", c.Name, "limit", limit, "scope", scope, "until", until,
			"remaining", until.Sub(m.now()).Round(time.Minute))
		return m.recordFailure(ctx, st, fmt.Errorf(
			"limit %s%s is blocked until %s according to the CA's own Retry-After; not placing an order",
			limit, scopeLabel(scope), until.UTC().Format(time.RFC3339)))
	}

	key, err := GenerateKey(c.KeyType)
	if err != nil {
		return m.recordFailure(ctx, st, err)
	}
	keyPEM, err := MarshalPrivateKeyPEM(key)
	if err != nil {
		return m.recordFailure(ctx, st, err)
	}

	order, err := m.core.NewOrder(c.Domains, &api.OrderOptions{
		Profile:        c.Profile,
		ReplacesCertID: replaces,
	})
	// Accounting sits here, before the retry below, and NOT only on the final error.
	//
	// Both halves used to run on the first call alone, which is wrong in exactly the case the
	// retry exists for. A `replaces` attempt refused by the CA created no order, so counting it
	// made the published lower bound optimistic by one -- in the flow that spends orders in
	// bursts -- and a rate-limit refusal from the retry was dropped on the floor instead of
	// becoming the deadline that gates every other certificate.
	refusedDeadline := false
	if err == nil {
		// An order was created, so it counts -- whether or not this pass goes on to finish.
		// The CA's own documentation is explicit that the resource is consumed at new-order
		// time, which is why deleting or failing later does not return the quota.
		m.spendNewOrder()
	} else {
		// Worth reading even though a retry follows: a rate-limited account is not a `replaces`
		// problem, and the instant it names governs every certificate on this account. A true
		// answer also means "do not retry now".
		refusedDeadline = m.noteNewOrderRefusal(c, err)
	}
	if err != nil && replaces != "" && !refusedDeadline {
		// ... except when the CA has told us not to come back yet: a rate-limit refusal is not a
		// `replaces` problem, and retrying immediately spends a second request inside the window the
		// CA just named, where it cannot succeed (the limit applies to placing the order, replaces
		// or not). This retry exists for the opposite case, a refusal about the replacement itself.
		// A `replaces` that the CA will not honour must never be a dead end, so retry once
		// without it. Losing the rate-limit exemption is a far smaller cost than not renewing
		// at all -- and a renewal that never happens is the worst failure this system has.
		//
		// WHY THIS RETRIES ON ANY ERROR rather than only on a recognised refusal. This used to
		// gate on an error mentioning the literal word "replaces". The refusals that actually
		// occur do not contain it:
		//
		//	Boulder: "parsing ARI CertID failed"
		//	Boulder: "requester account did not request the certificate being replaced by
		//	          this order"          <- "replaced", not "replaces"
		//	Pebble:  "could not find an order for the given certificate"
		//
		// With the word-matching gate, all three fell through to `recordFailure`, the same
		// `replaces` was sent again next round, and the certificate never renewed again --
		// silently, until it expired. That is not a hypothetical: it is reachable whenever the
		// stored ari_cert_id cannot be honoured by the current CA, and accounts are keyed by
		// ACME directory while orders are not, so pointing wecert at staging and back is
		// enough. Matching on a message string also cannot be made correct in principle: the
		// wording is the CA's to choose.
		//
		// The asymmetry settles it. Retrying on a non-replaces error costs one extra newOrder
		// call, and the order is created either way. NOT retrying on an unrecognised refusal
		// costs the renewal. lego already handles the one status that must not be retried (409
		// on a duplicate order), so this cannot mask a real conflict.
		m.log.Warn("creating the order failed while an ARI replaces field was set; retrying without it "+
			"(a CA that will not honour replaces must not stop the renewal; this attempt loses the "+
			"rate-limit exemption)",
			"cert", c.Name, "replaces", replaces, "err", err)
		order, err = m.core.NewOrder(c.Domains, &api.OrderOptions{Profile: c.Profile})
		if err == nil {
			m.spendNewOrder()
		} else {
			// The retry is the attempt that decided the outcome, so its refusal is the one that
			// must be read: this is where a rate-limit deadline was being lost.
			m.noteNewOrderRefusal(c, err)
		}
	}
	if err != nil {
		return m.recordFailure(ctx, st, fmt.Errorf("create order: %w", err))
	}
	if order.Location == "" {
		return m.recordFailure(ctx, st, errors.New("create order: the server returned no order URL"))
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
		// A bare return here (which is what this used to be) is the worst of both worlds: the
		// order was created at the CA but not recorded, so the next pass has no order URL to
		// resume and creates ANOTHER one -- and because recordFailure never ran, no backoff
		// was scheduled either. The order rate then follows the pass rate instead of the
		// backoff: at a 1-minute interval that is 1440 orders a day against
		// "300 new orders per account per 3 hours", and hitting that ceiling blocks EVERY
		// certificate on the account, not just this one.
		//
		// recordFailure is what makes the next attempt wait, so a state-store failure cannot
		// turn into a rate-limit incident. Note that it also has to be able to record: if the
		// disk is full enough that PutOrder failed, PutCert may fail too, which is why
		// recordFailure's own persistence error is logged rather than fatal (see there).
		//
		// The order URL is logged because it is the only remaining handle on the order that
		// now exists at the CA and nowhere else -- an operator reading the log can still
		// recover it by hand.
		return m.recordFailure(ctx, st, fmt.Errorf(
			"record the new order (the CA has it as %s, and it is not in the state store, so the next "+
				"attempt will create another one): %w", order.Location, err))
	}

	// "replaces" here is what this program ASKED for, not proof of what went on the wire.
	//
	// lego drops the field when the directory does not advertise renewalInfo, so a journal line
	// reading replaces=true next to an order that carried nothing is not a contradiction -- but it
	// was written as if it were a statement about the request that reached the CA, which is the one
	// thing an operator would use it to check. The wire itself is visible in lego's payloads (and
	// in the CA's own accounting); this line now says which of the two it is.
	m.log.Info("ACME order created",
		"cert", c.Name, "status", order.Status, "expiresAt", expiresAt,
		"names", len(c.Domains), "profile", order.Profile, "replacesRequested", replaces != "")
	return m.advance(ctx, c, st, o, rd)
}
