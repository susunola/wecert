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
//
// The FIFTH limit, the paused identifier, is the exception to that rule and is handled in the loop
// below: it is the one refusal that arrives with no instant at all, so waiting for the CA to name
// one means waiting forever. See refusedLimits and isPauseRefusal.
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
		headerAt, headerOK = ratelimit.ParseRetryAfterHeaderAt(rle.RetryAfter, m.now())
	}

	blocked := false
	for _, l := range named {
		scope := newOrderRefusalScope(l, c, err.Error())
		at, ok := m.quota.NoteRetryAfter(l, scope, err.Error())
		if l.SpentByCA {
			// The identifier PAUSE. The pausing limit has no limiter message of its own -- Boulder
			// pauses the account instead of answering with a reset instant ("There is no case for
			// FailedAuthorizationsForPausingPerDomainPerAccount because the RA will pause clients who
			// exceed that ratelimit", ratelimits/limiter.go) -- and the CA's refusal links to its
			// self-service portal rather than naming a time.
			//
			// So the deadline has to come from the published model instead: the ability to incur
			// these failures refills at ONE PER IDENTIFIER PER DAY, which makes one refill interval
			// the shortest wait that can possibly free the identifier. That is a FLOOR on our own
			// wait, NOT a measurement of this pause and NOT a promise: nothing but the portal clears
			// the pause, so a pass that comes back after the floor may simply be refused again and
			// re-book it. Booking nothing (the old behaviour, because no instant parsed) was worse in
			// both directions: the certificate retried at our own 1m..6h backoff against a state the
			// CA had already refused, and the operator saw ordinary backoff noise instead of the one
			// line that says the identifier is paused.
			//
			// The floor therefore sets the FLOOR of the deadline, and an instant -- from the message
			// or from the header -- can only push it later. Never earlier: those instants belong to
			// whichever limiter produced the response, and this bucket is not one of them. A pause
			// read as a twelve-minute backoff is exactly the retry loop this recognition exists to
			// stop.
			floor := m.now().Add(l.Refill)
			if ok && at.After(floor) {
				floor = at
			}
			if headerOK && headerAt.After(floor) {
				floor = headerAt
			}
			if _, noted := m.quota.NoteDeadline(l, scope, floor,
				"identifier pause floor: the CA named no instant, so one published refill interval "+
					"(1 per identifier per day) is the shortest supportable wait"); !noted {
				continue
			}
			at, ok = floor, true
		} else if !ok && headerOK {
			// The message had no parsable instant; the header did.
			m.quota.NoteDeadline(l, scope, headerAt, "retry-after header")
			at, ok = headerAt, true
		}
		if !ok {
			continue
		}
		blocked = true
		if l.SpentByCA {
			m.log.Error("the CA has PAUSED this identifier after repeated failed authorizations; no "+
				"order for it is placed before the recorded time, and only the CA's self-service "+
				"portal lifts the pause -- the CA named no instant, so that time is the shortest wait "+
				"the published one-refill-per-day rate can justify, not the CA's own answer",
				"cert", c.Name, "identifier", scope, "limit", l.Name, "until", at,
				"remaining", at.Sub(m.now()).Round(time.Minute))
			continue
		}
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
		// The bare identifier, matching the spend path and the CA's own refusal: the
		// authorization identifier never carries the wildcard's "*." prefix (RFC 8555
		// §7.1.3), so gating on "*.example.com" would consult a bucket the refusal was
		// never recorded against -- and the wildcard would keep ordering inside the very
		// window the CA named.
		checks = append(checks, check{limit: ratelimit.AuthzFailuresPerIdentifier, scope: bareIdentifierScope(d)})
		// The identifier PAUSE is per identifier too, and its deadline is a day or more rather than
		// minutes: an identifier the CA has paused cannot be ordered at all until the operator clears
		// it in the CA's portal, so this is the check that turns a refusal into "stop knocking"
		// instead of "knock again at the next backoff step".
		checks = append(checks, check{
			limit: ratelimit.ConsecutiveAuthzFailuresPerIdentifier, scope: strings.ToLower(d),
		})
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
			// Defensive: the authorization identifier is always the bare name, but the scope
			// must stay bare even if a CA ever quotes the wildcard form.
			return bareIdentifierScope(named)
		}
		if len(c.Domains) > 0 {
			return bareIdentifierScope(c.Domains[0])
		}
	case ratelimit.ConsecutiveAuthzFailuresPerIdentifier.Name:
		// The pause names what it paused when it names anything, in one of two forms: the legacy
		// counter message quotes one identifier (%q, see quotedDomain), and Boulder's current wording
		// lists them unquoted after "certificates for" (see pausedDomain). The bare "recently" form
		// names nothing at all, and the certificate's own first domain is then the only handle -- the
		// same fallback, for the same reason, as the failure budget above.
		//
		// The unnamed case is deliberately narrow rather than generous: booking the deadline against
		// EVERY name of the certificate would gate unrelated certificates that merely share a SAN,
		// which is the over-blocking the quoted-name rule above exists to stop. The certificate in
		// front of us is the one the CA just refused, so gating it is the part that is certain; when
		// the CA names more, each name is booked on the refusal that named it.
		if named := quotedDomain(msg); named != "" {
			return named
		}
		if named := pausedDomain(msg); named != "" {
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

// pausedDomain extracts the FIRST identifier from Boulder's current pause refusal, or "".
//
// The wording is built in wfe2/wfe.go and is the one a paused identifier actually gets today:
//
//	Your account is temporarily prevented from requesting certificates for %s and possibly others.
//	Please visit: <self-service portal link>
//
// where %s is strings.Join(pausedValues, ", "). The identifiers are NOT quoted, so quotedDomain
// cannot see them, and falling through to the certificate's first domain would book the deadline
// against a name the CA did not mention whenever the certificate's first SAN is not the paused one
// -- the exact failure the quoted-name rule exists to prevent.
//
// Only the first entry is read. That is enough to gate the certificate the CA just refused, and it
// keeps the parse to a bounded slice of prose: the rest of the list is a comma-separated tail this
// does not need to enumerate, because the next refusal names its first entry again.
func pausedDomain(msg string) string {
	const marker = "temporarily prevented from requesting certificates for "
	i := indexOfFold(msg, marker)
	if i < 0 {
		return ""
	}
	rest := msg[i+len(marker):]
	// Boulder's own suffix ends the list; a comma starts the next name.
	if j := indexOfFold(rest, " and possibly"); j >= 0 {
		rest = rest[:j]
	}
	if j := strings.IndexByte(rest, ','); j >= 0 {
		rest = rest[:j]
	}
	rest = strings.TrimSpace(rest)
	if !looksLikeIdentifier(rest) {
		return ""
	}
	return strings.ToLower(rest)
}

// looksLikeIdentifier reports whether s could be the DNS name this parse is looking for.
//
// A refusal is prose, and the field after the marker is followed by a URL and a signed token, so a
// mis-parse is possible in principle. The guard is deliberately crude and one-directional: anything
// with a space, a quote, a slash or a bracket in it is not a single name, and for those the caller
// falls back to the certificate's own first domain.
func looksLikeIdentifier(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	return !strings.ContainsAny(s, " \t\r\n/\\\"'<>[]()")
}

// indexOfFold is strings.Index with ASCII case folding, written out rather than done by lowercasing
// both sides: strings.ToLower is Unicode-aware and can change the BYTE LENGTH of the text in front
// of the marker, so the offset it returns would then point into the wrong place.
func indexOfFold(s, sub string) int {
	if sub == "" {
		return 0
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if strings.EqualFold(s[i:i+len(sub)], sub) {
			return i
		}
	}
	return -1
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
	// The FIFTH limit, the paused identifier, is the only one with no limiter message of its own:
	// the CA pauses (account, identifier) instead of answering with a reset instant, and the refusal
	// points at its self-service portal. See isPauseRefusal for the two wordings and for why the
	// ABSENCE of an instant is what identifies it.
	if isPauseRefusal(msg) {
		out = append(out, ratelimit.ConsecutiveAuthzFailuresPerIdentifier)
	}
	if strings.Contains(lower, "new orders") || strings.Contains(lower, "new-orders") {
		out = append(out, ratelimit.NewOrdersPerAccount)
	}
	return out
}

// isPauseRefusal reports whether a refusal is the CA's answer to a PAUSED identifier -- the fifth
// published limit -- rather than one of the token-bucket limiters' answers.
//
// Two wordings reach an ACME client, and both are quoted here from their source:
//
//	too many failed authorizations recently: see https://letsencrypt.org/docs/failed-validation-limit/
//
// is Let's Encrypt's own documented error for the failed-validation limit
// (website content/en/docs/failed-validation-limit.md; the rate-limits page's own section is
// "Consecutive Authorization Failures per Identifier per Account"), and
//
//	Your account is temporarily prevented from requesting certificates for <names> and possibly
//	others. Please visit: <self-service portal>
//
// is what Boulder's WFE sends today for a paused identifier (wfe2/wfe.go, probs.Paused).
//
// WHAT IDENTIFIES THE PAUSE IS THE MISSING INSTANT, not the wording alone. Boulder's per-hour
// failure-budget message is superficially identical --
//
//	too many failed authorizations (5) for %q in the last 1h0m0s, retry after <instant>
//
// -- but that template ALWAYS carries "retry after" (ratelimits/limiter.go), and the pausing limit
// deliberately has no case there at all: "There is no case for
// FailedAuthorizationsForPausingPerDomainPerAccount because the RA will pause clients who exceed
// that ratelimit". So a "failed authorizations" refusal that names no instant anywhere is the
// pause, and one that names an instant is the budget. Matching text is not ideal -- the wording is
// the CA's to choose -- and the only reason it is defensible here is that the two readings lead to
// opposite actions: treating the pause as routine backoff burns attempts against a state the CA has
// already refused, while treating the budget as a day-long pause delays a renewal that a
// twelve-minute refill would have allowed. The instant tells them apart without guessing.
//
// The portal wording needs no such test, because nothing else says it: it is a pause whatever else
// the message carries. (Booking it still cannot shorten the wait -- the pause deadline takes an
// instant as a floor, never as a ceiling; see noteNewOrderRefusal.)
func isPauseRefusal(msg string) bool {
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "temporarily prevented from requesting certificates") {
		return true
	}
	if _, ok := ratelimit.ParseRetryAfter(msg); ok {
		// An instant in the message: a token bucket's own answer, and the deadline is that instant.
		return false
	}
	return strings.Contains(lower, "failed authorizations")
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
//
// The two pre-order gates (identifier cooldown, CA-recorded refusal) are separate methods:
// both only decide "may we spend an order right now", and both end in recordFailure when
// the answer is no.
func (m *Manager) issue(ctx context.Context, c *config.Certificate, st *state.CertState, replaces string, rd round) error {
	if err := m.refuseWhileCoolingDown(ctx, c, st); err != nil {
		return err
	}
	if err := m.refuseWhileCALockedOut(ctx, c, st); err != nil {
		return err
	}

	key, err := GenerateKey(c.KeyType)
	if err != nil {
		return m.recordFailure(ctx, st, err)
	}
	keyPEM, err := MarshalPrivateKeyPEM(key)
	if err != nil {
		return m.recordFailure(ctx, st, err)
	}

	order, err := m.createOrderWithReplacesRetry(c, replaces)
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

// refuseWhileCoolingDown blocks a new order while one of the certificate's names is
// inside its authorization-failure cooldown.
//
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
// Checked at the point an order would be created, so resuming an order that is already
// in flight is unaffected -- that costs no new order and is how a pass that was
// interrupted mid-validation finishes.
func (m *Manager) refuseWhileCoolingDown(ctx context.Context, c *config.Certificate, st *state.CertState) error {
	name, until, cooling := m.coolingDown(c.Name, c.Domains)
	if !cooling {
		return nil
	}
	m.log.Warn("an identifier's authorizations failed recently, so no new order is placed until its "+
		"failure budget refills; retrying inside the window cannot succeed and spends the budget "+
		"that other certificates for this name also depend on",
		"cert", c.Name, "identifier", name, "cooldownUntil", until,
		"remaining", until.Sub(m.now()).Round(time.Minute))
	return m.recordFailure(ctx, st, fmt.Errorf(
		"identifier %s is in its authorization-failure cooldown until %s; not placing an order",
		name, until.UTC().Format(time.RFC3339)))
}

// refuseWhileCALockedOut blocks a new order while a recorded CA refusal is still in force.
//
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
func (m *Manager) refuseWhileCALockedOut(ctx context.Context, c *config.Certificate, st *state.CertState) error {
	until, limit, scope, blocked := m.blockedByRecordedDeadline(c)
	if !blocked {
		return nil
	}
	if limit == ratelimit.ConsecutiveAuthzFailuresPerIdentifier.Name {
		// The pause, said once and in full: what happened, why the recorded time is ours rather
		// than the CA's, and what actually clears it. An operator reading only "rate limit"
		// would wait, and waiting is the one thing that cannot lift a pause.
		m.log.Error("the CA has PAUSED this identifier after repeated failed authorizations; "+
			"nothing is ordered for it until the recorded floor, and only the CA's self-service "+
			"portal lifts the pause -- the CA named no instant, so the floor is the published "+
			"one-refill-per-day rate, not a deadline the CA gave",
			"cert", c.Name, "limit", limit, "scope", scope, "until", until,
			"remaining", until.Sub(m.now()).Round(time.Minute))
		return m.recordFailure(ctx, st, fmt.Errorf(
			"the CA has paused identifier %s (too many consecutive failed authorizations) and "+
				"names no instant; no order is placed before %s, our floor from the published "+
				"one-refill-per-day rate. Clear the pause in the CA's self-service portal: "+
				"https://letsencrypt.org/docs/rate-limits/#consecutive-authorization-failures-per-identifier-per-account",
			scope, until.UTC().Format(time.RFC3339)))
	}
	m.log.Warn("the CA has refused this limit recently and named when it will listen again; no "+
		"order is placed before then, because the refusal is the CA's own answer and retrying "+
		"inside the window cannot change it",
		"cert", c.Name, "limit", limit, "scope", scope, "until", until,
		"remaining", until.Sub(m.now()).Round(time.Minute))
	return m.recordFailure(ctx, st, fmt.Errorf(
		"limit %s%s is blocked until %s according to the CA's own Retry-After; not placing an order",
		limit, scopeLabel(scope), until.UTC().Format(time.RFC3339)))
}

// createOrderWithReplacesRetry places the new-order call, spending quota and honouring a
// single retry that drops `replaces` when the CA refuses the replacement itself.
func (m *Manager) createOrderWithReplacesRetry(c *config.Certificate, replaces string) (legoacme.ExtendedOrder, error) {
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
	return order, err
}
