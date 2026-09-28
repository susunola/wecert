package config

import (
	"fmt"
	"time"
)

// FailureFallback configures the "issue a subset before expiry" degradation.
//
// It solves one very specific scenario: one name in a 25-name certificate has
// the wrong DNS record, so the whole certificate cannot be issued — and the
// other 24, which were fine, expire along with it. Partial availability beats
// total failure.
//
// **Off by default.** It changes what a certificate covers; that call is the
// operator's to make, not the program's.
type FailureFallback struct {
	// Enabled defaults to false.
	Enabled *bool `yaml:"enabled"`

	// AfterFailures is how many consecutive failures this certificate needs before
	// degradation is considered. Default 5.
	AfterFailures int `yaml:"afterFailures"`

	// BeforeExpiry is how close to expiry degradation is considered. Default 168h.
	//
	// Do not set it too large: degrading early swaps a fully valid certificate for
	// one missing names, a net loss.
	BeforeExpiry string `yaml:"beforeExpiry"`

	// MinIdentifierFailures is how many times an identifier must fail before it
	// may be dropped. Default 3. Setting it to 1 lets one network blip drop a name.
	MinIdentifierFailures int `yaml:"minIdentifierFailures"`

	// FailureWindow is how long a failure record counts, default 24h.
	//
	// It doubles as the self-healing mechanism: once records age out, that
	// identifier is no longer dropped and the next pass retries the full set.
	// Recovery after a fix takes at most this long, with no extra retry state.
	FailureWindow string `yaml:"failureWindow"`

	// MinNames is how many names must remain after degradation. Default 1.
	//
	// Refuse to degrade if fewer names would remain: that is total failure wearing
	// a disguise, while making people believe part of it still works.
	MinNames int `yaml:"minNames"`

	// Parsed durations, filled in by normalize.
	BeforeExpiryDur  time.Duration `yaml:"-"`
	FailureWindowDur time.Duration `yaml:"-"`
}

// EnabledOr returns the degradation switch, or def when it is unset.
func (f *FailureFallback) EnabledOr(def bool) bool {
	if f.Enabled == nil {
		return def
	}
	return *f.Enabled
}

// The Or methods below supply a default when the field is unset (<= 0).
// Treating 0 as "not written" is safe here: no legal value of these fields is 0, and
// normalize rejects negative values rather than letting them be replaced silently.
func (f *FailureFallback) AfterFailuresOr(def int) int {
	if f.AfterFailures <= 0 {
		return def
	}
	return f.AfterFailures
}

func (f *FailureFallback) MinIdentifierFailuresOr(def int) int {
	if f.MinIdentifierFailures <= 0 {
		return def
	}
	return f.MinIdentifierFailures
}

func (f *FailureFallback) MinNamesOr(def int) int {
	if f.MinNames <= 0 {
		return def
	}
	return f.MinNames
}

func (f *FailureFallback) normalize() error {
	var err error
	if f.BeforeExpiryDur, err = parseDuration(f.BeforeExpiry, 7*24*time.Hour, "failureFallback.beforeExpiry"); err != nil {
		return err
	}
	if f.FailureWindowDur, err = parseDuration(f.FailureWindow, 24*time.Hour, "failureFallback.failureWindow"); err != nil {
		return err
	}

	// A negative count is a typo, not "unset". The *Or helpers treat <= 0 as unset so 0
	// can mean "use the default", but silently replacing -5 with the default would throw
	// away the number the operator wrote while the sibling knobs in this block
	// (dropThreshold, budget, maxNames) all reject out-of-range values -- so the same
	// mistake would be loud in one place and silent in another.
	for _, c := range []struct {
		name string
		v    int
	}{
		{"failureFallback.afterFailures", f.AfterFailures},
		{"failureFallback.minIdentifierFailures", f.MinIdentifierFailures},
		{"failureFallback.minNames", f.MinNames},
	} {
		if c.v < 0 {
			return fmt.Errorf("%s must not be negative, got %d (0 means \"use the default\")", c.name, c.v)
		}
	}
	return nil
}
