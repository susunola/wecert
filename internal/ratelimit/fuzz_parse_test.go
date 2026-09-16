package ratelimit

import (
	"testing"
	"time"
)

// ParseRetryAfter reads a date out of text the CA controls.
//
// It is the one place in this package that consumes foreign input, and it is load-bearing:
// the instant it returns is treated as authoritative and suppresses issuance until then. Two
// properties therefore matter more than "it parses the documented format" -- it must never
// panic on arbitrary bytes, and it must never invent an instant it did not actually read.
func FuzzParseRetryAfter(f *testing.F) {
	f.Add("too many new registrations (10) from this IP address in the last 3h0m0s, retry after 1970-01-01 00:18:15 UTC.")
	f.Add("retry after 2026-09-23 04:00:00 UTC")
	f.Add("retry after")
	f.Add("retry after ")
	f.Add("retry after not a date")
	f.Add("RETRY AFTER 2026-09-23 04:00:00 UTC")
	f.Add("retry after 2026-09-23 04:00:00.123456789 UTC")
	f.Add("retry after 0001-01-01 00:00:00 UTC")
	f.Add("retry after 9999-12-31 23:59:59 UTC")
	f.Add("retry after 2026-13-45 99:99:99 UTC")
	f.Add("\x00\xff retry after \x00")
	f.Add("retry after 2026-09-23 04:00:00 UTC, retry after 2027-01-01 00:00:00 UTC")

	f.Fuzz(func(t *testing.T, msg string) {
		at, ok := ParseRetryAfter(msg)
		if !ok {
			return
		}
		// The reported instant must be a real, normalised one. A zero value returned as "found"
		// would be read by callers as "blocked until the zero time", i.e. not blocked at all,
		// while looking like a successful parse.
		if at.IsZero() {
			t.Fatalf("claimed to parse an instant but returned the zero time for %q", msg)
		}
		if at.Location() != time.UTC {
			t.Errorf("instant is not in UTC: %v (from %q)", at, msg)
		}
		// And it must be reproducible.
		again, ok2 := ParseRetryAfter(msg)
		if !ok2 || !again.Equal(at) {
			t.Errorf("ParseRetryAfter is not deterministic for %q: %v/%v then %v/%v",
				msg, at, ok, again, ok2)
		}
	})
}
