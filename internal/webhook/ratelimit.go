package webhook

import (
	"sync"
	"time"
)

// Defaults for authLimiter. Not exposed in config.Webhook on purpose: this is a
// local, best-effort backstop against a leaked or guessed token being hammered
// from one address, not a substitute for a firewall or a CDN in front of the
// endpoint -- it does not need to be tunable to do that job.
const (
	authMaxFailures = 10
	authWindow      = 5 * time.Minute
	authBlockFor    = 15 * time.Minute

	// authLimiterGCThreshold bounds how large the tracking map is allowed to grow
	// before a sweep runs. Kept well above any realistic number of legitimate
	// callers (this endpoint is meant for CI/automation, not the public
	// internet), so the sweep almost never has to touch a live entry.
	authLimiterGCThreshold = 4096
)

// authLimiterState is one source address's failure record.
type authLimiterState struct {
	failures     int
	windowStart  time.Time
	blockedUntil time.Time
}

// authLimiter is a small in-memory, per-source-address lockout for the webhook's
// auth check.
//
// Why it exists: this endpoint triggers real ACME issuance (see the package doc),
// so a leaked token is not just an information leak, it is a rate-limit-quota
// leak -- someone hammering /hook/reconcile with a guessed or stolen token can
// burn the account's issuance quota for every certificate wecert manages. The
// token length check in config.Webhook.normalize already makes guessing
// impractical, but this adds a second, independent layer: after authMaxFailures
// failed attempts from one address inside authWindow, that address is refused
// outright for authBlockFor, regardless of what token it presents next.
//
// This is deliberately not a general-purpose rate limiter (no token bucket, no
// per-route budget): it only ever counts *failed* authentications, so a
// legitimate caller retrying with the right token is never affected by it.
//
// Not a defense against a distributed attacker spraying attempts across many
// source addresses, or one behind a shared NAT/proxy where the address is not
// attacker-controlled evidence -- that class of protection belongs at the
// network edge (a firewall, a CDN, an allowlist), not inside the process being
// protected.
type authLimiter struct {
	mu     sync.Mutex
	byAddr map[string]*authLimiterState
}

func newAuthLimiter() *authLimiter {
	return &authLimiter{byAddr: make(map[string]*authLimiterState)}
}

// allowed reports whether addr may attempt authentication right now, and if not,
// how long until it may try again.
func (l *authLimiter) allowed(addr string, now time.Time) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	st := l.byAddr[addr]
	if st == nil || !now.Before(st.blockedUntil) {
		return true, 0
	}
	return false, st.blockedUntil.Sub(now)
}

// recordFailure counts one failed authentication attempt from addr.
func (l *authLimiter) recordFailure(addr string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.gc(now)

	st := l.byAddr[addr]
	// A window that has fully elapsed starts counting fresh -- this is a lockout
	// on a burst of failures, not a permanent mark against an address that failed
	// once a long time ago.
	if st == nil || now.Sub(st.windowStart) > authWindow {
		st = &authLimiterState{windowStart: now}
		l.byAddr[addr] = st
	}
	st.failures++
	if st.failures >= authMaxFailures {
		st.blockedUntil = now.Add(authBlockFor)
	}
}

// recordSuccess clears addr's record. A legitimate caller that mistyped the
// token a few times and then got it right should not stay under a cloud from
// its earlier mistakes.
func (l *authLimiter) recordSuccess(addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.byAddr, addr)
}

// gc drops entries that are no longer relevant, so a burst of distinct source
// addresses cannot grow this map without bound. Called with the lock already
// held, and only once the map has grown past authLimiterGCThreshold, so the
// common case (few distinct callers) never pays for it.
func (l *authLimiter) gc(now time.Time) {
	if len(l.byAddr) < authLimiterGCThreshold {
		return
	}
	for addr, st := range l.byAddr {
		if now.After(st.blockedUntil) && now.Sub(st.windowStart) > authWindow {
			delete(l.byAddr, addr)
		}
	}
}
