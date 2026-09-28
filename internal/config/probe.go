package config

import (
	"fmt"
	"time"
)

// Probe configures network-side certificate probing.
//
// The cloud API saying "bound successfully" and a browser actually getting this
// certificate are two things: the former goes through the control plane, the
// latter dials a real TLS connection. This switch decides whether to dial.
//
// On by default: it catches failures the control plane cannot see (a rebind
// that did not take effect, another certificate winning SNI on the CLB), and
// "the probe did not run" is reported separately from "the certificate is
// wrong" — being unable to dial out only raises probe_errors, it never makes
// certificates look broken.
type Probe struct {
	// Enabled defaults to true.
	Enabled *bool `yaml:"enabled"`

	// Port defaults to 443.
	Port int `yaml:"port"`

	// Timeout defaults to 10s. Cross-AZ handshakes routinely take 3-5 seconds;
	// set it too low and false alarms become frequent, and false alarms train
	// people to ignore alerts.
	Timeout string `yaml:"timeout"`

	// MaxHostsPerCert is how many names per certificate to probe. Unset means
	// DefaultMaxHostsPerCert; an explicit 0 means "probe nothing".
	//
	// Not exhaustive: a 25-name certificate would mean 25 handshakes every pass,
	// with diminishing returns and linear cost.
	//
	// A pointer, like Enabled: 0 is a meaningful setting -- it is how probing is paused
	// during an investigation -- and as a plain int it was indistinguishable from unset,
	// so normalize() rewrote 0 to the default and reconcile's "the per-certificate host
	// cap is 0, so probing is off" branch was unreachable in production.
	MaxHostsPerCert *int `yaml:"maxHostsPerCert"`

	// RequireTrusted defaults to true: a served chain that does not verify against the
	// system roots counts as a failed probe.
	//
	// "The right certificate, in the right place, still broken" is a real shape -- a listener
	// serving the leaf without its intermediate passes every other check and fails in every
	// real client. Set it to false when the CA is internal: those certificates never verify
	// against the system roots, so the strict answer would be a permanent mismatch that
	// trains everyone to ignore this alert.
	RequireTrusted *bool `yaml:"requireTrusted"`

	// MinValidFor is "at least this much validity must remain". Empty means skip.
	//
	// The check is redundant — expiry alerts should be based on notAfter anyway.
	// But it fails differently: it verifies "the live endpoint really is serving a
	// non-expired certificate", not "I believe one is deployed".
	MinValidFor string `yaml:"minValidFor"`

	// Parsed durations, filled in by normalize.
	TimeoutDur  time.Duration `yaml:"-"`
	MinValidDur time.Duration `yaml:"-"`
}

// EnabledOr returns the probe switch, or def when it is unset.
func (p *Probe) EnabledOr(def bool) bool {
	if p.Enabled == nil {
		return def
	}
	return *p.Enabled
}

// RequireTrustedOr returns the chain-verification switch, or def when it is unset.
func (p *Probe) RequireTrustedOr(def bool) bool {
	if p.RequireTrusted == nil {
		return def
	}
	return *p.RequireTrusted
}

// DefaultMaxHostsPerCert is the per-certificate probe cap when probe.maxHostsPerCert is unset.
const DefaultMaxHostsPerCert = 3

// MaxHostsPerCertOr returns the per-certificate probe cap, or def when it is unset.
//
// An explicit 0 is honoured rather than defaulted: it is the documented way to turn probing
// off, and defaulting it (as the old int field forced) silently undid the operator's setting
// every time the config was loaded.
func (p *Probe) MaxHostsPerCertOr(def int) int {
	if p.MaxHostsPerCert == nil {
		return def
	}
	return *p.MaxHostsPerCert
}

func (p *Probe) normalize() error {
	var err error
	if p.TimeoutDur, err = parseDuration(p.Timeout, 10*time.Second, "probe.timeout"); err != nil {
		return err
	}
	// A floor, like dns.pollingInterval's: cross-AZ handshakes routinely take 3-5 seconds,
	// so a timeout far below that fails every probe -- and every failed probe raises
	// probe_errors, which is an alarm that fires without a single real failure.
	if p.TimeoutDur < time.Second {
		return fmt.Errorf("probe.timeout is %s, which is below the 1s minimum: cross-AZ handshakes "+
			"routinely take 3-5 seconds, so a timeout this short fails every probe and turns into "+
			"false alarms that train people to ignore the real ones", p.TimeoutDur)
	}

	// minValidFor cannot go through parseDuration: that helper reads "default 0"
	// as "required", whereas leaving this empty is legal and meaningful here —
	// it means "do not check remaining validity".
	if p.MinValidFor != "" {
		d, err := time.ParseDuration(p.MinValidFor)
		if err != nil {
			return fmt.Errorf("probe.minValidFor: %w", err)
		}
		if d <= 0 {
			return fmt.Errorf("probe.minValidFor must be positive, got %s", p.MinValidFor)
		}
		p.MinValidDur = d
	}
	if p.Port == 0 {
		p.Port = 443
	}
	if p.Port < 1 || p.Port > 65535 {
		return fmt.Errorf("probe.port must be between 1 and 65535, got %d", p.Port)
	}
	// Only a negative value is rejected. 0 used to be rewritten to the default here, which made
	// "probe nothing" -- a setting the caller in reconcile explicitly documents and reports --
	// impossible to configure.
	if p.MaxHostsPerCert != nil && *p.MaxHostsPerCert < 0 {
		return fmt.Errorf("probe.maxHostsPerCert must not be negative, got %d", *p.MaxHostsPerCert)
	}
	return nil
}
