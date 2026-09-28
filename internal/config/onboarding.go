package config

import (
	"fmt"
	"math"
	"time"
)

// Onboarding configures how the desired state is generated; wecert-onboard
// reads it.
//
// wecert itself does not read this section — deliberately: generation policy
// gets tuned repeatedly, while convergence must stay stable. It lives in the
// config rather than in constants because these numbers can only come from
// real drift data: run observe to collect some, then come back and tune them.
type Onboarding struct {
	// Zones limits which DNS zones are enumerated. Empty means every zone in the
	// account.
	Zones []string `yaml:"zones"`

	// RequireCLBRule means a declaration only takes effect if a CLB rule also
	// exists (guard 1). Default true.
	//
	// It is a pointer because false is meaningful, and Go's zero value cannot
	// distinguish "not written" from "written false".
	RequireCLBRule *bool `yaml:"requireCLBRule"`

	// Allowlist limits the registered domains certificates may be issued for.
	// Empty means no limit.
	Allowlist []string `yaml:"allowlist"`

	// MaxNames is the per-certificate SAN cap, default 25 (aligned with tlsserver
	// so a future profile switch needs no structural change).
	MaxNames int `yaml:"maxNames"`

	Profile string `yaml:"profile"`
	KeyType string `yaml:"keyType"`
	Deploy  *bool  `yaml:"deploy"`

	// GracePeriod is the deletion grace period, default 24h.
	GracePeriod string `yaml:"gracePeriod"`

	// Budget / BudgetWindow are the quota budget, default 25 operations / 7 days.
	Budget       int    `yaml:"budget"`
	BudgetWindow string `yaml:"budgetWindow"`

	// DropThreshold is the sudden-drop circuit-breaker threshold, default 0.30.
	DropThreshold float64 `yaml:"dropThreshold"`

	StatePath  string `yaml:"statePath"`
	ReportPath string `yaml:"reportPath"`

	// Parsed durations, filled in by normalize.
	GraceDur  time.Duration `yaml:"-"`
	BudgetDur time.Duration `yaml:"-"`
}

// RequireCLBRuleOr returns the guard switch, or def when it is unset.
func (o *Onboarding) RequireCLBRuleOr(def bool) bool {
	if o.RequireCLBRule == nil {
		return def
	}
	return *o.RequireCLBRule
}

// DeployOr returns the deploy default, or def when it is unset.
func (o *Onboarding) DeployOr(def bool) bool {
	if o.Deploy == nil {
		return def
	}
	return *o.Deploy
}

func (o *Onboarding) normalize() error {
	var err error
	if o.GraceDur, err = parseDuration(o.GracePeriod, 24*time.Hour, "onboarding.gracePeriod"); err != nil {
		return err
	}
	if o.BudgetDur, err = parseDuration(o.BudgetWindow, 7*24*time.Hour, "onboarding.budgetWindow"); err != nil {
		return err
	}

	// These knobs configure the safety invariants, so an out-of-range value has to
	// be rejected here rather than quietly switching the guard off.
	//
	// DropThreshold is a *fraction*: the abrupt-change fuse freezes the round when
	// the declared name set loses more than this much, and the ratio it is compared
	// against is always <= 1. Anything at or above 1 can never be exceeded, so the
	// fuse would never fire -- which is the "upstream returned partial data, mass SAN
	// deletion" case it exists for. A percentage written as `30` is the common typo.
	//
	// NaN is checked explicitly: every comparison against it is false, so `.nan`
	// sails past both bounds below and would only be caught later by onboarding.New
	// -- a config that loads but can never run.
	if math.IsNaN(o.DropThreshold) || o.DropThreshold < 0 || o.DropThreshold >= 1 {
		return fmt.Errorf(
			"onboarding.dropThreshold is a fraction in [0,1): 0.3 means 30%%, and 0 uses the default 0.3; got %v "+
				"(a value of 1 or more can never be exceeded, so the abrupt-change fuse would never fire)",
			o.DropThreshold)
	}
	if o.Budget < 0 {
		return fmt.Errorf("onboarding.budget must not be negative, got %d", o.Budget)
	}
	if o.MaxNames < 0 {
		return fmt.Errorf("onboarding.maxNames must not be negative, got %d", o.MaxNames)
	}
	// Profile and keyType are copied into every generated certificate, so a typo
	// here is not a local failure: the document fails validation on every round and
	// nothing is ever written again. Catch it at load time instead.
	if o.Profile != "" {
		if _, ok := profileMaxNames[o.Profile]; !ok {
			return fmt.Errorf("onboarding.profile: unknown profile %q (want %s/%s/%s)",
				o.Profile, ProfileClassic, ProfileTLSServer, ProfileShortLived)
		}
	}
	if o.KeyType != "" {
		switch o.KeyType {
		case KeyTypeECDSAP256, KeyTypeECDSAP384, KeyTypeRSA2048, KeyTypeRSA4096:
		default:
			return fmt.Errorf("onboarding.keyType: unknown keyType %q", o.KeyType)
		}
	}
	return nil
}
