package webhook

import (
	"sync"
	"time"
)

const (
	authMaxFailures        = 10
	authWindow             = 5 * time.Minute
	authBlockFor           = 15 * time.Minute
	authLimiterGCThreshold = 4096

	// authSuccessForgiveFloor is the failure count below which a success clears
	// the address state entirely. See recordSuccess for the tradeoff.
	authSuccessForgiveFloor = 2

	// authLimiterGCInterval amortizes the sweep once the map is large.
	//
	// Sweeping on every failure is itself a lever: an attacker sending one failed request
	// from each of many source addresses makes every failure cost a full-map scan, so the
	// total work grows with the square of the request count exactly when the endpoint is
	// under load. One sweep per interval keeps it linear and still reclaims promptly.
	authLimiterGCInterval = time.Minute

	// authLimiterMaxEntries is the hard ceiling on tracked source addresses.
	//
	// The time-based sweep cannot bound the map while a flood is in progress, because
	// entries younger than the window are deliberately kept. Without a ceiling, a client
	// with an IPv6 /64 (or any distributed source) grows this map without limit.
	authLimiterMaxEntries = 65536
)

type authLimiterState struct {
	failures     int
	windowStart  time.Time
	blockedUntil time.Time
}

// authLimiter locks out a source address after repeated failed authentications.
type authLimiter struct {
	mu     sync.Mutex
	byAddr map[string]*authLimiterState
	// lastGC is when the map was last swept; it bounds how often gc may scan.
	lastGC time.Time
}

func newAuthLimiter() *authLimiter {
	return &authLimiter{byAddr: make(map[string]*authLimiterState)}
}

func (l *authLimiter) allowed(addr string, now time.Time) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.byAddr[addr]
	if st == nil || !now.Before(st.blockedUntil) {
		return true, 0
	}
	return false, st.blockedUntil.Sub(now)
}

func (l *authLimiter) recordFailure(addr string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.gc(now)
	st := l.byAddr[addr]
	// Reset the window only when no block is active: resetting it mid-block
	// would also drop blockedUntil, shrinking the 15-minute lockout to the
	// 5-minute window under a sustained attack.
	if st == nil || (now.Sub(st.windowStart) > authWindow && !now.Before(st.blockedUntil)) {
		// Past the ceiling, refuse to track a new address rather than grow without
		// limit. Existing entries keep their state -- including active blocks -- so a
		// flood cannot evict the protections it is trying to escape; an untracked
		// address simply starts counting if it ever gets a slot back.
		if st == nil && len(l.byAddr) >= authLimiterMaxEntries {
			return
		}
		st = &authLimiterState{windowStart: now}
		l.byAddr[addr] = st
	}
	st.failures++
	if st.failures >= authMaxFailures {
		st.blockedUntil = now.Add(authBlockFor)
	}
}

// recordSuccess decays the failure count instead of wiping it.
//
// Wiping it outright forgave a shared-egress-IP attacker with every interleaved
// legitimate success: the office NAT's one valid call erased the brute-force
// count the attacker's requests had just built up, so the lockout never
// engaged. Halving keeps recovery possible for a legit caller who occasionally
// mistypes a token, while sustained brute force still accumulates faster than
// the successes can drain it -- each success can only halve the count once, but
// the failures between two successes are unbounded.
//
// The tradeoff: a low-rate attack interleaved with frequent legit successes
// converges to a steady state below the limit and never locks out. That is
// accepted on purpose -- locking out a shared IP hard would hand the attacker a
// way to deny service to everyone behind it.
//
// The token is checked BEFORE the lockout (see auth), so a success always reaches this decay:
// a fully blocked caller presenting the correct token is admitted -- the block only ever
// applies to requests that failed the token check, which is what keeps a shared-IP attacker
// from locking out the legitimate caller behind the same TLS terminator.
//
// now is taken so the sweep below can run here as well as on failure.
func (l *authLimiter) recordSuccess(addr string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Sweep here too, not only on failure.
	//
	// The map used to be collected only from recordFailure, so a burst of failed
	// authentications left its entries behind forever once the failures stopped: no
	// later success reached gc, and there is no background ticker. On a listener
	// reachable over IPv6 a single client with a /64 can produce unbounded distinct
	// source addresses, so "the map is bounded by the number of attackers" is not a
	// bound at all. gc is amortised (at most once per interval), so calling it on the
	// success path costs nothing measurable.
	l.gc(now)

	st := l.byAddr[addr]
	if st == nil {
		return
	}
	st.failures /= 2
	if st.failures < authSuccessForgiveFloor {
		// Below the floor the residue is noise (a typo or two), not a signal
		// worth keeping; forgive it entirely.
		delete(l.byAddr, addr)
	}
}

func (l *authLimiter) gc(now time.Time) {
	if len(l.byAddr) < authLimiterGCThreshold {
		return
	}
	if now.Sub(l.lastGC) < authLimiterGCInterval {
		return
	}
	l.lastGC = now
	for addr, st := range l.byAddr {
		if now.After(st.blockedUntil) && now.Sub(st.windowStart) > authWindow {
			delete(l.byAddr, addr)
		}
	}

	// Hard cap as a last resort. The sweep above only removes entries that are neither
	// blocked nor inside the current window, so a flood keeps the map at roughly
	// (rate x window) entries; past the cap, evict the oldest windows until it fits.
	// Evicting limiter state can only make an attacker's next attempt count from zero,
	// which is strictly less bad than unbounded memory growth.
	for len(l.byAddr) > authLimiterMaxEntries {
		var (
			oldestAddr string
			oldest     time.Time
			found      bool
		)
		for addr, st := range l.byAddr {
			if !found || st.windowStart.Before(oldest) {
				oldestAddr, oldest, found = addr, st.windowStart, true
			}
		}
		if !found {
			break
		}
		delete(l.byAddr, oldestAddr)
	}
}
