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
	if st == nil || now.Sub(st.windowStart) > authWindow {
		st = &authLimiterState{windowStart: now}
		l.byAddr[addr] = st
	}
	st.failures++
	if st.failures >= authMaxFailures {
		st.blockedUntil = now.Add(authBlockFor)
	}
}

func (l *authLimiter) recordSuccess(addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.byAddr, addr)
}

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
