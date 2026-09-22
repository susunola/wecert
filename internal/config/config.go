// Package config defines wecert's declarative desired state (the spec).
//
// Design principle: the YAML says only "what I want" and carries no runtime
// state at all. Runtime state (order URL, ARI window, Tencent Cloud CertId and
// so on) always goes into SQLite, because losing it directly causes duplicate
// orders and runs into Let's Encrypt rate limits.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"golang.org/x/net/publicsuffix"
	"io"
	"math"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ACME profile names. The Max Names cap varies by profile.
const (
	ProfileClassic    = "classic"
	ProfileTLSServer  = "tlsserver"
	ProfileShortLived = "shortlived"
)

// Let's Encrypt directory URLs.
const (
	DirectoryStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
	DirectoryProduction = "https://acme-v02.api.letsencrypt.org/directory"
)

const (
	KeyTypeECDSAP256 = "ecdsa-p256"
	KeyTypeECDSAP384 = "ecdsa-p384"
	KeyTypeRSA2048   = "rsa2048"
	KeyTypeRSA4096   = "rsa4096"
)

const (
	CredentialStatic  = "static"
	CredentialCVMRole = "cvm-role"
)

// DNS-01 solver implementations. Their credential systems are completely
// different, so do not mix them up:
//
// dnspod uses DNSPod's own API Token (dnspod.cn console -> key management) and
// calls dnsapi.cn. That is not Tencent Cloud CAM's SecretId/SecretKey.
//
// tencentcloud uses Tencent Cloud CAM credentials (AK/SK or CVM role temporary
// credentials) and calls dnspod.tencentcloudapi.com. The upside is one shared
// credential set with certificate deployment, plus SessionToken and roles.
const (
	DNSProviderDNSPod       = "dnspod"
	DNSProviderTencentCloud = "tencentcloud"
	// DNSProviderLego selects any provider from lego's registry by name (dns.legoProvider).
	// It requires a binary built with -tags lego_dns; see internal/acme/provider_notags.go for
	// why the registry is not compiled in by default.
	DNSProviderLego = "lego"
)

// acmeSupportsLegoProviders reports whether this binary was built with lego's provider registry.
//
// A variable rather than a constant because the acme package owns the build tag that decides it,
// and config must not import acme's dependency graph merely to ask.
var acmeSupportsLegoProviders = false

// profileMaxNames is the maximum identifier count each profile allows.
// classic allows 100, but the newer tlsserver / shortlived only 25 — reject
// locally rather than send an order the CA will refuse and burn quota on.
var profileMaxNames = map[string]int{
	ProfileClassic:    100,
	ProfileTLSServer:  25,
	ProfileShortLived: 25,
}

// profileRenewBefore is each profile's default renew-ahead duration.
// A fallback only when ARI is unavailable; otherwise suggestedWindow wins.
var profileRenewBefore = map[string]time.Duration{
	ProfileClassic:    30 * 24 * time.Hour,
	ProfileTLSServer:  15 * 24 * time.Hour,
	ProfileShortLived: 48 * time.Hour,
}

// Config is the whole configuration.
type Config struct {
	StatePath    string          `yaml:"statePath"`
	StateBackup  StateBackup     `yaml:"stateBackup"`
	ACME         ACME            `yaml:"acme"`
	DNS          DNS             `yaml:"dns"`
	Tencent      Tencent         `yaml:"tencent"`
	Metrics      Metrics         `yaml:"metrics"`
	Webhook      Webhook         `yaml:"webhook"`
	DesiredState DesiredState    `yaml:"desiredState"`
	Onboarding   Onboarding      `yaml:"onboarding"`
	Probe        Probe           `yaml:"probe"`
	Fallback     FailureFallback `yaml:"failureFallback"`
	Certificates []Certificate   `yaml:"certificates"`
}

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

// Snapshot defaults. Defined here rather than in internal/state because this is the lower
// layer: the store takes the policy as arguments, the config decides it.
const (
	DefaultBackupInterval = 24 * time.Hour
	DefaultBackupKeep     = 7
)

// StateBackup controls the periodic consistent snapshot of state.db.
//
// Why it exists: losing state.db is the one documented disaster in this system -- the ACME
// account key (accounts are limited to 10 per IP per 3 hours), every in-flight order URL
// and every ARI certID live in it. Losing an order URL does not just cost an issuance: the
// replacement order counts against "5 certificates per exact set of identifiers / 7 days",
// a limit with no override. Until now the only guidance was a line in the README saying it
// is "the one thing to back up", with nothing implementing or checking it.
//
// On by default where it can be useful, off where it cannot: see normalize.
type StateBackup struct {
	// Enabled defaults to true when the state directory is writable, false otherwise.
	Enabled *bool `yaml:"enabled"`

	// Interval between snapshots. Default 24h; the minimum is 1 minute.
	Interval string `yaml:"interval"`

	// Keep is how many snapshots to retain, newest first. Default 7.
	Keep int `yaml:"keep"`

	// Dir is where snapshots are written. Empty means the directory holding state.db,
	// which is already 0700 and on the same filesystem (so SQLite's write and the rename
	// are cheap and atomic).
	Dir string `yaml:"dir"`

	// Parsed, filled in by normalize.
	IntervalDur time.Duration `yaml:"-"`
}

// EnabledOr returns the snapshot switch, or def when it is unset.
func (b *StateBackup) EnabledOr(def bool) bool {
	if b.Enabled == nil {
		return def
	}
	return *b.Enabled
}

func (b *StateBackup) normalize() error {
	var err error
	if b.IntervalDur, err = parseDuration(b.Interval, DefaultBackupInterval, "stateBackup.interval"); err != nil {
		return err
	}
	// A snapshot per pass would be pointless churn; a snapshot per hour is the useful
	// floor. The bound also keeps a typo like "1s" from filling the disk.
	if b.IntervalDur < time.Minute {
		return fmt.Errorf("stateBackup.interval is %s, which is below the 1m minimum: "+
			"snapshots are a recovery mechanism, not a change log, and a very short interval just "+
			"fills the disk with near-identical copies", b.IntervalDur)
	}
	if b.Keep == 0 {
		b.Keep = DefaultBackupKeep
	}
	if b.Keep < 1 {
		return fmt.Errorf("stateBackup.keep must be at least 1, got %d "+
			"(0 means \"use the default\"; there is no way to disable retention without disabling backups)", b.Keep)
	}
	if b.Keep > 365 {
		return fmt.Errorf("stateBackup.keep is %d, which would retain more than a year of snapshots "+
			"of a file holding private keys; keep at most 365", b.Keep)
	}
	return nil
}

// normalizeList trims, lowercases, rejects empties and removes duplicates, preserving order.
func normalizeList(field string, in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, v := range in {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			return nil, fmt.Errorf("%s contains an empty entry; every entry must name a value "+
				"(a blank one would be sent to the cloud API as-is)", field)
		}
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out, nil
}

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

// The three DesiredState modes.
//
// The difference is **who gets the final say**, not "how many files are read".
const (
	// ModeStatic: the certificates block in the config is the desired state.
	// Historical behaviour, zero risk.
	ModeStatic = "static"

	// ModeObserve: still converges on certificates, but also reads the document
	// and reports the differences.
	//
	// This is the required stage between static and enforce: it issues nothing and
	// only answers "if the document really won, what would be added and removed".
	ModeObserve = "observe"

	// ModeEnforce: the document is the desired state.
	ModeEnforce = "enforce"
)

// DesiredState configures the source of the desired state.
//
// Why the inference does not live inside wecert itself: every known pitfall in
// this system (rate limits, accidental deletion, state drift) comes from
// "judgement", which inevitably keeps changing, while the certificate
// lifecycle must stay stable. Split apart, a source failure degrades into "the
// desired state stops updating" (safe), not "domains look like they vanished"
// (disastrous).
type DesiredState struct {
	// Mode is static / observe / enforce.
	Mode string `yaml:"mode"`

	// Path is the desired-state document path. Required for observe and enforce.
	Path string `yaml:"path"`

	// MaxStaleness is how long the document may go unrefreshed before alerting,
	// default 48h.
	//
	// This is the failure mode this architecture newly introduces: after the
	// onboarding component dies, wecert keeps renewing from the old document
	// perfectly normally, everything looks fine, but no new domain ever enters.
	// Without this alert, that state persists until someone remembers to add one.
	MaxStaleness string `yaml:"maxStaleness"`

	// Parsed durations, filled in by normalize.
	MaxStalenessDur time.Duration `yaml:"-"`
}

func (d *DesiredState) normalize(hasCertificates bool) error {
	if d.Mode == "" {
		d.Mode = ModeStatic
	}

	var err error
	if d.MaxStalenessDur, err = parseDuration(d.MaxStaleness, 48*time.Hour, "desiredState.maxStaleness"); err != nil {
		return err
	}

	switch d.Mode {
	case ModeStatic:
		if d.Path != "" {
			return fmt.Errorf("desiredState.path is set but desiredState.mode is %q: "+
				"an unused path is almost always a half-finished switch to observe/enforce, "+
				"so it is rejected instead of silently ignored", ModeStatic)
		}
	case ModeObserve, ModeEnforce:
		if d.Path == "" {
			return fmt.Errorf("desiredState.mode=%q requires desiredState.path", d.Mode)
		}
	default:
		return fmt.Errorf("desiredState.mode must be %q, %q or %q, got %q",
			ModeStatic, ModeObserve, ModeEnforce, d.Mode)
	}

	if d.Mode == ModeEnforce && hasCertificates {
		return fmt.Errorf("desiredState.mode=%q but certificates is not empty: "+
			"in enforce mode the document is the single source of truth, "+
			"and leaving a stale certificates block behind means editing it would silently do nothing", d.Mode)
	}
	return nil
}

// reservedContactDomains and reservedContactTLDs are the names a CA refuses as a contact address.
//
// Let's Encrypt answers 400 invalidContact ("contact email has forbidden domain") for these, and it
// does so at ACCOUNT REGISTRATION -- before a single certificate is issued. The shipped example config
// used ops@example.com, so the documented quick start failed at the documented `-dry-run` step with a
// CA-side error that names neither the file nor the line, and the operator had to work out that the
// address in the example was the problem. Catching it here turns that into a local, specific error.
//
// The lists are the documented reserved names (RFC 2606 / RFC 6761): the "example" domains and the
// special-use TLDs. Nothing else is guessed at -- a typo in a real domain is not this check's
// business, and the CA will refuse what it refuses.
var reservedContactDomains = map[string]bool{
	"example.com": true,
	"example.net": true,
	"example.org": true,
	"example.edu": true,
}

var reservedContactTLDs = map[string]bool{
	"example":   true,
	"invalid":   true,
	"test":      true,
	"localhost": true,
}

// validateContactEmail refuses an address a CA will not accept, before it reaches the CA.
func validateContactEmail(email string) error {
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return fmt.Errorf("acme.email %q is not a usable contact address: it must look like "+
			"user@domain, and it should be a mailbox you can read -- it is where a CA sends expiry "+
			"and revocation notices", email)
	}
	domain := strings.ToLower(strings.TrimSuffix(email[at+1:], "."))

	// The domain and every parent of it: mail to anything under a reserved domain goes nowhere, so
	// `ops@sub.example.net` is the same mistake as `ops@example.net` and a CA refuses it the same way.
	for suffix := domain; suffix != ""; {
		if reservedContactDomains[suffix] {
			return fmt.Errorf("acme.email is %q, and %s is a reserved documentation domain: Let's "+
				"Encrypt refuses it as a contact address (\"contact email has forbidden domain\") when "+
				"it registers the account, so nothing is issued at all. Set acme.email to a mailbox you "+
				"control", email, suffix)
		}
		dot := strings.IndexByte(suffix, '.')
		if dot < 0 {
			// A single label ("localhost", or a bare name): the whole thing is the last label, so the
			// special-use check below has to see it too.
			if reservedContactTLDs[suffix] {
				return fmt.Errorf("acme.email is %q, and %q is a reserved special-use name: a CA refuses "+
					"it as a contact address, so nothing is issued at all. Set acme.email to a mailbox "+
					"you control", email, suffix)
			}
			break
		}
		suffix = suffix[dot+1:]
		if reservedContactTLDs[suffix] {
			return fmt.Errorf("acme.email is %q, and .%s is a reserved special-use TLD: a CA refuses it "+
				"as a contact address, so nothing is issued at all. Set acme.email to a mailbox you "+
				"control", email, suffix)
		}
	}
	return nil
}

// ACME is the ACME account and directory configuration.
type ACME struct {
	Directory string `yaml:"directory"`
	Email     string `yaml:"email"`
}

// DNS is the DNS-01 solver configuration.
type DNS struct {
	Provider string `yaml:"provider"`

	// LegoProvider names a provider from lego's registry, used only when Provider is "lego".
	// Its credentials come from the environment, in lego's own variable names.
	LegoProvider string `yaml:"legoProvider,omitempty"`

	// Required when provider=dnspod.
	// This is DNSPod's own API Token (of the form "12345,abcdef0123456789..."),
	// not a Tencent Cloud CAM SecretId/SecretKey.
	LoginToken string `yaml:"loginToken"`

	// LoginTokenFile reads the token from a file instead: a 0600 file, a systemd credential, or
	// anything else that keeps it out of config.yaml. Environment-expanded, so
	// ${CREDENTIALS_DIRECTORY}/dnspod-token works under LoadCredential. Mutually exclusive with
	// loginToken.
	LoginTokenFile string `yaml:"loginTokenFile,omitempty"`

	// TTL is the value used when writing the _acme-challenge TXT record.
	//
	// The default is 600, not 60: on DNSPod's free tier the TTL floor is 600, and
	// 60 is rejected by the API with LimitExceeded.RecordTtlLimit. Paid tiers may
	// go lower to speed up propagation and cleanup.
	TTL                int    `yaml:"ttl"`
	PropagationTimeout string `yaml:"propagationTimeout"`
	PollingInterval    string `yaml:"pollingInterval"`

	// RecursiveNameservers is the trusted recursive resolver set used to find
	// CNAME targets, SOA and NS delegation before querying authoritative servers
	// directly. Entries must be IP literals, optionally with an explicit port.
	// Empty means the nameservers from /etc/resolv.conf are used.
	RecursiveNameservers []string `yaml:"recursiveNameservers"`

	// Parsed durations, filled in by normalize.
	Propagation time.Duration `yaml:"-"`
	Polling     time.Duration `yaml:"-"`
}

// Tencent is the Tencent Cloud credential and deployment target configuration.
type Tencent struct {
	CredentialMode string `yaml:"credentialMode"`
	SecretID       string `yaml:"secretId"`
	SecretKey      string `yaml:"secretKey"`
	// SecretIDFile / SecretKeyFile are the file variants of the two above, for the same reason as
	// LoginTokenFile. With credentialMode=cvm-role they are unnecessary: the role is read from the
	// instance metadata service and no static key exists at all.
	SecretIDFile  string   `yaml:"secretIdFile,omitempty"`
	SecretKeyFile string   `yaml:"secretKeyFile,omitempty"`
	RoleName      string   `yaml:"roleName"`
	ResourceTypes []string `yaml:"resourceTypes"`
	Regions       []string `yaml:"regions"`
	// UIN is the Tencent Cloud account this daemon deploys into. Optional. The
	// inventory page groups certificates by it; a certificate-level uin in the
	// desired-state document overrides this when more than one account is in view.
	UIN string `yaml:"uin,omitempty"`
}

// Metrics is the Prometheus exposition configuration.
type Metrics struct {
	Listen string `yaml:"listen"`
}

// Webhook lets wecert be triggered by external events, not only by polling.
//
// Typical use: call it once from CI or an event bus after a domain is added,
// rather than waiting for the next top of the hour.
type Webhook struct {
	// Listen is the listen address of the trigger endpoint. Empty disables the
	// webhook.
	Listen string `yaml:"listen"`

	// Token is the shared secret and is required.
	//
	// This endpoint triggers real issuance and consumes Let's Encrypt rate-limit
	// quota, so it must never be left unauthenticated. Two forms are accepted:
	//   Authorization: Bearer <token>
	//   X-Wecert-Token: <token>
	Token string `yaml:"token"`

	// NotifyURL is optional. When set, every finished renewal attempt POSTs a JSON
	// event to it, to wire "certificate renewed" into downstream flows (triggering
	// a config reload, for example).
	NotifyURL string `yaml:"notifyURL"`

	// NotifySecret is optional and only meaningful with NotifyURL. When set, each
	// notification carries X-Wecert-Signature: sha256=<hex HMAC-SHA256 of the raw
	// body>, which lets the receiver distinguish a genuine event from anything else
	// that can reach its URL.
	NotifySecret string `yaml:"notifySecret"`
}

// WebhookTokenMinLen is the minimum token length.
// A short token is no authentication at all on this endpoint — an attacker who
// triggers issuance can burn the rate-limit quota.
const WebhookTokenMinLen = 16

// WebhookNotifySecretMinLen is the minimum HMAC secret length.
// An HMAC key shorter than its hash's output can be recovered by brute force from
// a single signed event, so a short secret gives a false sense of authenticity.
const WebhookNotifySecretMinLen = 32

// Certificate is the desired state of one certificate.
type Certificate struct {
	Name        string   `yaml:"name" json:"name"`
	Domains     []string `yaml:"domains" json:"domains"`
	Profile     string   `yaml:"profile" json:"profile"`
	KeyType     string   `yaml:"keyType" json:"keyType"`
	RenewBefore string   `yaml:"renewBefore,omitempty" json:"renewBefore,omitempty"`
	Deploy      Deploy   `yaml:"deploy" json:"deploy"`
	// UIN tags this certificate with a Tencent Cloud account. Empty means inherit
	// tencent.uin. The inventory uses it only for display and grouping; it does
	// not change which credentials deploy the certificate.
	UIN string `yaml:"uin,omitempty" json:"uin,omitempty"`

	// Parsed durations, filled in by normalize.
	RenewBeforeDur time.Duration `yaml:"-" json:"-"`
}

// Deploy describes where the issued certificate should be deployed.
// On first issuance there is no binding on the Tencent Cloud side yet, so a
// manual bind is needed once; after that every 90/45-day renewal is swapped in
// automatically by UpdateCertificateInstance.
type Deploy struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}

// ProfileMaxNames returns the identifier cap a profile allows, or 0 for an unknown profile.
//
// Exported because onboarding has to cap a group by the profile the group will actually be issued
// with, not by a configured default: splitting by the default alone let a tlsserver group exceed
// 25 identifiers, and the document was then rejected at write time on every round.
func ProfileMaxNames(profile string) int {
	if n, ok := profileMaxNames[profile]; ok {
		return n
	}
	return 0
}

// MaxNames returns the maximum domain count allowed by this certificate's
// profile.
func (c *Certificate) MaxNames() int { return ProfileMaxNames(c.Profile) }

// Load reads and validates the configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	// Unknown fields are a hard error, so a misspelled config never takes effect
	// silently.
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	// A second YAML document is a mistake, not a feature: KnownFields catches a misspelled
	// key but says nothing about everything after a stray "---", which a copy-paste or a
	// template edit produces. Silently ignoring half the file is exactly the "why isn't my
	// certificate being issued" failure this loader exists to prevent.
	if err := RejectExtraDocuments(dec, path); err != nil {
		return nil, err
	}

	// Captured before resolveSecretFiles fills the empty fields from files and the
	// environment: the permission warning at the end of Load is about secrets written
	// IN the file, which is only answerable while the inline values are still
	// distinguishable from the resolved ones.
	inlineSecrets := inlineSecretFields(cfg)

	// Resolve file- and environment-backed secrets before validation, so the validation rules see
	// the credential that will actually be used rather than the field the operator left empty.
	if err := cfg.resolveSecretFiles(); err != nil {
		return nil, err
	}

	if err := cfg.normalize(); err != nil {
		return nil, err
	}

	// Warnings, not refusals -- the same call state.open makes. Each of these names a
	// posture the program cannot tell apart from a deliberate choice (a loopback-only
	// deployment cannot know the operator did not mean 0.0.0.0), so they are stated
	// plainly and left to the operator. See the helpers below; they are pure so the
	// wording is testable without capturing stderr.
	var warns []string
	warns = append(warns, notifyURLWarnings(cfg.Webhook.NotifyURL)...)
	warns = append(warns, listenWarnings("metrics.listen", cfg.Metrics.Listen)...)
	warns = append(warns, listenWarnings("webhook.listen", cfg.Webhook.Listen)...)
	if len(inlineSecrets) > 0 {
		if fi, statErr := os.Stat(path); statErr == nil {
			warns = append(warns, configPermWarnings(path, fi.Mode().Perm(), inlineSecrets)...)
		}
	}
	for _, w := range warns {
		fmt.Fprintf(os.Stderr, "wecert: WARNING: %s\n", w)
	}
	return cfg, nil
}

// RejectExtraDocuments fails when the input holds more than one YAML document.
//
// An **empty** trailing document is not a second document: yaml.v3 decodes "---\n" to a nil
// value with no error, so a file that merely ends with a separator looked like a second
// document here and was refused. Load failing means the daemon does not start at all, so that
// guard was refusing a file whose meaning was never in doubt. Empty documents are skipped and
// only a document with content in it is rejected.
//
// Exported because the desired-state document uses the same rule and used to carry its own
// copy -- which fixed this for config only, and left the document path still refusing a
// trailing "---". One implementation is what keeps them from drifting again.
func RejectExtraDocuments(dec *yaml.Decoder, path string) error {
	for {
		var extra any
		if err := dec.Decode(&extra); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("parse config %s: %w", path, err)
		}
		if extra == nil {
			// "---" with nothing behind it. Keep reading: the next Decode is what says
			// whether the file really continues.
			continue
		}
		return fmt.Errorf("%s contains more than one YAML document (a stray '---'?); "+
			"everything after the first document would be ignored, so it is rejected instead", path)
	}
}

// ── startup warnings ────────────────────────────────────────────────────────────────
//
// These are warnings, not refusals -- the same call state.open makes for the state
// database. Each names a posture this program cannot tell apart from a deliberate
// choice, so each is stated plainly and left to the operator. The helpers are pure
// (the file's mode arrives as an argument) so the wording and the decision are
// testable without capturing stderr, exactly like state.statePathWarnings.

// inlineSecretFields lists the credential fields written directly into the config
// file. Called before resolveSecretFiles, which would fill the empty fields from
// files and the environment and make the inline ones indistinguishable.
func inlineSecretFields(c *Config) []string {
	var out []string
	if c.DNS.LoginToken != "" {
		out = append(out, "dns.loginToken")
	}
	if c.Tencent.SecretID != "" {
		out = append(out, "tencent.secretId")
	}
	if c.Tencent.SecretKey != "" {
		out = append(out, "tencent.secretKey")
	}
	if c.Webhook.Token != "" {
		out = append(out, "webhook.token")
	}
	if c.Webhook.NotifySecret != "" {
		out = append(out, "webhook.notifySecret")
	}
	return out
}

// configPermWarnings warns when a config file that carries inline secrets is readable
// by anyone but its owner. A warning rather than a refusal: 0644 configs are common
// in the wild, and refusing would push operators toward deleting the check rather
// than tightening the mode. The *_file fields and the environment fallbacks exist so
// the secrets need not be in this file at all.
func configPermWarnings(path string, perm os.FileMode, inlineSecrets []string) []string {
	if len(inlineSecrets) == 0 || perm&0o077 == 0 {
		return nil
	}
	return []string{fmt.Sprintf(
		"the config file %s is readable by group or other (%04o) while carrying inline "+
			"credentials (%s). A credential in a 0644 file is in every backup and every "+
			"backup's off-site copy; use the *_file variants or the environment instead, or "+
			"chmod 0600 the file", path, perm, strings.Join(inlineSecrets, ", "))}
}

// notifyURLWarnings warns about a plaintext notification URL to another host.
//
// Chat/CI webhook endpoints (Slack, Feishu, DingTalk) carry their credential in the
// URL path itself, so http to a non-loopback host exposes the credential to anyone on
// the path. Loopback is exempt: nothing leaves the machine.
func notifyURLWarnings(notifyURL string) []string {
	if notifyURL == "" {
		return nil
	}
	u, err := url.Parse(notifyURL)
	if err != nil {
		// normalize already rejected an unparseable or non-http(s) URL; reaching this
		// branch would mean the two drifted apart, and silence is the wrong drift.
		return []string{fmt.Sprintf("webhook.notifyURL %q could not be re-parsed for the plaintext check: %v", notifyURL, err)}
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return []string{fmt.Sprintf(
			"webhook.notifyURL %q uses plaintext http to a non-loopback host. Notification "+
				"endpoints usually carry their credential in the URL path, so anyone on the "+
				"network path can read it; use https", notifyURL)}
	}
	return nil
}

// listenWarnings warns when a server binds beyond this machine.
//
// metrics.listen serves the expiry state of every certificate, and webhook.listen can
// trigger real issuance (it is token-guarded, but a wider bind widens the brute-force
// surface). Both default to loopback; binding further is sometimes exactly what is
// wanted -- Prometheus scraping from another host -- so this is a warning, not a refusal.
func listenWarnings(field, listen string) []string {
	if listen == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		// normalize already rejected a malformed address; as above, drift must be loud.
		return []string{fmt.Sprintf("%s %q could not be re-parsed for the bind-scope check: %v", field, listen, err)}
	}
	if isLoopbackHost(host) {
		return nil
	}
	// The trigger endpoint carries a bearer token over plaintext HTTP and can spend
	// real ACME quota. The generic "reachable from beyond this machine" warning is
	// the right tone for /metrics; for the hook it understates what a same-segment
	// observer can do with a sniffed token.
	if field == "webhook.listen" {
		return []string{fmt.Sprintf(
			"%s binds %s, which is reachable from beyond this machine (an empty host means "+
				"every interface). The trigger carries a bearer token over plaintext HTTP and "+
				"can spend real ACME rate-limit quota: put a TLS terminator in front of it, or "+
				"bind 127.0.0.1:<port> and reach it through a tunnel", field, listen)}
	}
	return []string{fmt.Sprintf(
		"%s binds %s, which is reachable from beyond this machine (an empty host means every "+
			"interface). If that is deliberate -- a Prometheus scraper on another host -- ignore "+
			"this; otherwise 127.0.0.1:<port> keeps it local", field, listen)}
}

// isLoopbackHost reports whether host names only this machine.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// normalize validates and defaults every section of the configuration.
//
// Split by section so each block can be read (and tested) without scrolling past the
// others: root identity, DNS-01, listeners, Tencent Cloud deploy, the already-structured
// subsections, and the certificate list. The order is the dependency order -- DNS
// settings are only meaningful once the provider is chosen, and the certificate checks
// come last because they consult profile defaults filled in above.
func (c *Config) normalize() error {
	if err := c.normalizeRoot(); err != nil {
		return err
	}
	if err := c.normalizeDNS(); err != nil {
		return err
	}
	if err := c.normalizeListeners(); err != nil {
		return err
	}
	if err := c.normalizeTencent(); err != nil {
		return err
	}
	if err := c.normalizeSubsections(); err != nil {
		return err
	}
	return c.normalizeCertificatesBlock()
}

// normalizeRoot validates the process identity: where state lives and who the CA
// account is.
func (c *Config) normalizeRoot() error {
	if c.StatePath == "" {
		return fmt.Errorf("statePath is required")
	}
	if c.ACME.Directory == "" {
		return fmt.Errorf("acme.directory is required")
	}
	if c.ACME.Email == "" {
		return fmt.Errorf("acme.email is required")
	}
	return validateContactEmail(c.ACME.Email)
}

// normalizeDNS picks the DNS-01 provider and the propagation knobs. Provider first:
// every later field is only meaningful relative to which API will write the TXT.
func (c *Config) normalizeDNS() error {
	// The DNS provider must be chosen explicitly. Defaulting to dnspod suggests
	// Tencent Cloud AK/SK would be enough, then fails confusingly at the DNS-01
	// step.
	switch c.DNS.Provider {
	case "":
		c.DNS.Provider = DNSProviderDNSPod
	case DNSProviderDNSPod, DNSProviderTencentCloud:
	case DNSProviderLego:
		if c.DNS.LegoProvider == "" {
			return fmt.Errorf("dns.provider=%q requires dns.legoProvider to name one of lego's DNS "+
				"providers (e.g. cloudflare, route53, alidns); that provider then reads its own "+
				"credentials from the environment, using lego's documented variable names",
				DNSProviderLego)
		}
		if !acmeSupportsLegoProviders {
			return fmt.Errorf("dns.provider=%q needs a binary built with -tags lego_dns: the default "+
				"build carries only the native dnspod and tencentcloud providers, because lego's "+
				"registry pulls in hundreds of third-party SDKs", DNSProviderLego)
		}
	default:
		return fmt.Errorf("dns.provider must be %q, %q or %q, got %q",
			DNSProviderDNSPod, DNSProviderTencentCloud, DNSProviderLego, c.DNS.Provider)
	}
	// legoProvider is read only when provider is "lego". Leaving it set next to a native
	// provider means the operator believes challenges go through, say, Cloudflare while they
	// actually go through dnspod -- rejected loudly rather than silently ignored, for the same
	// reason desiredState.path under mode=static is rejected above.
	if c.DNS.Provider != DNSProviderLego && c.DNS.LegoProvider != "" {
		return fmt.Errorf("dns.legoProvider is set but dns.provider is %q: the field is only read "+
			"when dns.provider=%q, so it would be silently ignored -- remove it, or switch "+
			"dns.provider to %q if lego's registry is what you meant",
			c.DNS.Provider, DNSProviderLego, DNSProviderLego)
	}
	if c.DNS.Provider == DNSProviderDNSPod && c.DNS.LoginToken == "" {
		return fmt.Errorf("dns.provider=dnspod requires dns.loginToken, dns.loginTokenFile or " +
			"$" + EnvDNSPodLoginToken + " " +
			"(a DNSPod API token, not a Tencent Cloud SecretId/SecretKey;" +
			"to use Tencent Cloud CAM credentials instead, set dns.provider=tencentcloud)")
	}

	var err error
	if c.DNS.Propagation, err = parseDuration(c.DNS.PropagationTimeout, 5*time.Minute, "dns.propagationTimeout"); err != nil {
		return err
	}
	if c.DNS.Polling, err = parseDuration(c.DNS.PollingInterval, 5*time.Second, "dns.pollingInterval"); err != nil {
		return err
	}
	// Both of these are only checked to be positive by parseDuration, and both are dangerous at
	// the small end in ways that look harmless in a config file.
	//
	// pollingInterval is how long the propagation wait sleeps between rounds, and each round asks
	// every authoritative nameserver of the zone for every record of that zone. `1ms` is therefore
	// not "check more often", it is a flood of UDP queries at the operator's own DNS provider --
	// the exact thing dns.go's own comment warns gets you rate limited or dropped, which then
	// affects every other DNS user on that host.
	//
	// propagationTimeout is the whole budget for a record to appear. Below the zone's own TTL there
	// is no chance it can: the write is invisible to the resolvers for at least the negative-cache
	// TTL, measured at ~600s on DNSPod. A small value does not fail fast in a useful way; it turns
	// each fresh write into a failed round plus an escalating backoff (1m, 2m, 4m ...), which
	// delays issuance by minutes to hours.
	if c.DNS.Polling < time.Second {
		return fmt.Errorf("dns.pollingInterval is %s, which is below the 1s minimum: each round asks "+
			"every authoritative nameserver of the zone for every record, so a very short interval is "+
			"a burst of queries at your DNS provider rather than a faster check", c.DNS.Polling)
	}
	if c.DNS.Propagation < 30*time.Second {
		return fmt.Errorf("dns.propagationTimeout is %s, which is below the 30s minimum: a zone's "+
			"negative caching alone can hide a fresh record for its SOA TTL (about 600s on DNSPod), "+
			"so a short budget only guarantees a failed round and a backoff", c.DNS.Propagation)
	}
	if c.DNS.Polling >= c.DNS.Propagation {
		return fmt.Errorf("dns.pollingInterval (%s) must be shorter than dns.propagationTimeout (%s): "+
			"the interval is the sleep between rounds inside that budget, so an interval at or above "+
			"it means the propagation wait probes once and gives up", c.DNS.Polling, c.DNS.Propagation)
	}
	if c.DNS.TTL == 0 {
		// The default is 600, not 60: on DNSPod's free tier the TTL floor is 600, and
		// 60 is rejected by the API with LimitExceeded.RecordTtlLimit. Paid tiers may
		// go lower, but the default must hold on every tier.
		c.DNS.TTL = 600
	}
	// A negative TTL is a typo, not "unset" -- the same rule failureFallback.* applies:
	// silently replacing it with the default would throw away the number the operator wrote.
	if c.DNS.TTL < 0 {
		return fmt.Errorf("dns.ttl must not be negative, got %d (0 means \"use the default\")", c.DNS.TTL)
	}
	if len(c.DNS.RecursiveNameservers) > 0 {
		resolvers, err := normalizeRecursiveNameservers(c.DNS.RecursiveNameservers)
		if err != nil {
			return err
		}
		c.DNS.RecursiveNameservers = resolvers
	}
	return nil
}

// normalizeListeners validates the two HTTP listeners. Both default to loopback;
// binding further is allowed but warned about at load (see listenWarnings).
func (c *Config) normalizeListeners() error {
	if c.Metrics.Listen == "" {
		c.Metrics.Listen = "127.0.0.1:9800"
	}
	// A malformed listen address used to surface only when the metrics server tried to bind --
	// after the ACME account had been touched. /metrics is this system's only expiry alerting
	// channel, so a typo there must be a load-time error.
	if _, _, err := net.SplitHostPort(c.Metrics.Listen); err != nil {
		return fmt.Errorf("metrics.listen must be a host:port address, got %q: %w", c.Metrics.Listen, err)
	}
	return c.Webhook.normalize()
}

// normalizeTencent validates how credentials are obtained and which regions/types
// the deployer is allowed to touch.
func (c *Config) normalizeTencent() error {
	switch c.Tencent.CredentialMode {
	case "":
		c.Tencent.CredentialMode = CredentialCVMRole
	case CredentialStatic, CredentialCVMRole:
	default:
		return fmt.Errorf("tencent.credentialMode must be %q or %q, got %q",
			CredentialStatic, CredentialCVMRole, c.Tencent.CredentialMode)
	}

	// With credentialMode=static, secretId/secretKey need not live in the config:
	// the TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY env vars are accepted
	// too, so no long-lived secret has to appear in the file. The real validation
	// happens in deploy.NewCredentialSource.
	if c.Tencent.CredentialMode == CredentialCVMRole && c.Tencent.RoleName == "" {
		return fmt.Errorf("tencent.credentialMode=cvm-role requires roleName")
	}
	if len(c.Tencent.ResourceTypes) == 0 {
		c.Tencent.ResourceTypes = []string{"clb"}
	}
	if len(c.Tencent.Regions) == 0 {
		return fmt.Errorf("tencent.regions is required (CLB is regional; list every region you have CLBs in)")
	}
	// Both lists are multiplied into the UpdateCertificateInstance request (types x regions) and
	// into the onboarding rule enumeration, so a duplicate costs a bigger request and a typo is only
	// found by the cloud API at deploy time -- the expensive place to learn about one. Every other
	// list in this file is normalised (domains, recursiveNameservers); these two were the exception.
	var err error
	if c.Tencent.Regions, err = normalizeList("tencent.regions", c.Tencent.Regions); err != nil {
		return err
	}
	if c.Tencent.ResourceTypes, err = normalizeList("tencent.resourceTypes", c.Tencent.ResourceTypes); err != nil {
		return err
	}
	return nil
}

// normalizeSubsections delegates to the typed sections that already own their own
// rules (backup, desired state, onboarding, probe, fallback).
func (c *Config) normalizeSubsections() error {
	if err := c.StateBackup.normalize(); err != nil {
		return err
	}
	if err := c.DesiredState.normalize(len(c.Certificates) > 0); err != nil {
		return err
	}
	if err := c.Onboarding.normalize(); err != nil {
		return err
	}
	if err := c.Probe.normalize(); err != nil {
		return err
	}
	return c.Fallback.normalize()
}

// normalizeCertificatesBlock checks the certificate list and the one cross-cutting
// rule that needs both the list and a profile default filled in above (the probe floor).
func (c *Config) normalizeCertificatesBlock() error {
	// Both static and observe converge on certificates, so a non-empty list is a
	// hard requirement. In enforce mode certificates must be empty (rejected
	// above); the document is the only source.
	if c.DesiredState.Mode != ModeEnforce && len(c.Certificates) == 0 {
		return fmt.Errorf("at least one certificate is required "+
			"(desiredState.mode=%q still converges on this list; "+
			"set desiredState.mode=%q to take the whole list from the desired-state document instead)",
			c.DesiredState.Mode, ModeEnforce)
	}

	if err := NormalizeCertificates(c.Certificates); err != nil {
		return err
	}

	// probe.minValidFor must be satisfiable by the shortest profile in use.
	//
	// probe.Verify fails every probe whose remaining validity is below this floor, and the runner
	// turns that into wecert_certificate_probe_match = 0 -- so an unsatisfiable floor pins the
	// metric at zero forever and fires the critical "not serving the deployed certificate" alert
	// with a diagnosis that blames the rebind or SNI. The file already rejects the analogous
	// "renewBefore >= validity" for the same reason: cheap to check, and the failure it prevents
	// looks like something else entirely.
	//
	// In enforce mode this loop sees an empty list -- the document is the only source of
	// certificates there -- so the same check runs again where the document is resolved, which is
	// the only place the two can meet. See CheckProbeFloor.
	return CheckProbeFloor(c.Probe.MinValidDur, c.Certificates)
}

// CheckProbeFloor rejects a probe.minValidFor that no profile in use can satisfy.
//
// probe.Verify fails every probe whose remaining validity is below this floor, and the runner turns
// that into wecert_certificate_probe_match = 0 -- so an unsatisfiable floor pins the metric at zero
// forever and fires the critical "not serving the deployed certificate" alert with a diagnosis that
// blames the rebind or SNI.
//
// It is exported because the certificates are not always in the config file: in enforce mode
// c.Certificates must be empty, so the only place the floor and the certificates can meet is where
// the document is resolved. Config.normalize calls it for the static and observe modes; the
// reconciler calls it on every resolved pass and reports the mismatch, because a document may
// change between passes and failing the pass there would stop renewals over a probe setting.
func CheckProbeFloor(minValid time.Duration, certs []Certificate) error {
	if minValid <= 0 {
		return nil
	}
	for i := range certs {
		cert := &certs[i]
		validity, ok := profileValidity[cert.Profile]
		if !ok {
			continue
		}
		if minValid >= validity {
			return fmt.Errorf(
				"probe.minValidFor %s is not shorter than certificate %q's %s profile validity %s, "+
					"so every probe of it would fail while the certificate is still perfectly valid "+
					"(wecert_certificate_probe_match stays 0 and the alert blames the rebind); "+
					"use less than %s",
				minValid, cert.Name, cert.Profile, validity, validity)
		}
	}
	return nil
}

func (w *Webhook) normalize() error {
	// Checked before the listen-address branch below: NotifyURL is independent of the
	// trigger endpoint and may be used alone, so it is validated on every path that
	// carries it.
	if w.NotifyURL != "" {
		u, err := url.Parse(w.NotifyURL)
		if err != nil {
			return fmt.Errorf("webhook.notifyURL: %w", err)
		}
		// A URL without a host or with another scheme would be POSTed to by the notifier
		// and fail there, one renewal at a time, with the cause far from the config line.
		if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("webhook.notifyURL must be an http or https URL with a host, got %q", w.NotifyURL)
		}
	}

	// Checked before the listen-address branch below: NotifySecret is about the
	// outbound event target, which is independent of the trigger endpoint.
	if w.NotifySecret != "" {
		if w.NotifyURL == "" {
			return fmt.Errorf("webhook.notifySecret is set but webhook.notifyURL is empty: " +
				"there is no outgoing event for the signature to cover")
		}
		if len(w.NotifySecret) < WebhookNotifySecretMinLen {
			return fmt.Errorf("webhook.notifySecret is too short (%d characters, minimum %d): "+
				"a key this short can be recovered from a single signed event, so it would not "+
				"prove the notification came from wecert",
				len(w.NotifySecret), WebhookNotifySecretMinLen)
		}
	}

	// An empty Listen means disabled, in which case Token is not needed either.
	if w.Listen == "" {
		if w.Token != "" {
			return fmt.Errorf("webhook.token is set but webhook.listen is empty: " +
				"with no listen address there is no endpoint for the token to guard")
		}
		if w.NotifyURL != "" {
			// NotifyURL is independent of the listen endpoint and may be used alone.
			return nil
		}
		return nil
	}

	// Same rule as metrics.listen: a malformed address must fail at load time, not at the
	// first bind.
	if _, _, err := net.SplitHostPort(w.Listen); err != nil {
		return fmt.Errorf("webhook.listen must be a host:port address, got %q: %w", w.Listen, err)
	}

	if w.Token == "" {
		return fmt.Errorf("webhook.listen is set but webhook.token is missing: " +
			"this endpoint triggers real issuance and consumes rate-limit quota, so it must be authenticated")
	}
	if len(w.Token) < WebhookTokenMinLen {
		return fmt.Errorf("webhook.token is too short (%d characters, minimum %d): "+
			"this endpoint can trigger real issuance, so a weak token is no better than none",
			len(w.Token), WebhookTokenMinLen)
	}
	return nil
}

// ValidProfile reports whether name is a certificate profile this build knows.
//
// Exported so the callers that produce a profile BEFORE a Certificate exists -- the declaration
// parser in internal/onboarding, which reads "profile=tlsserver" out of a TXT record -- can reject
// a bad value where it is written, instead of letting it reach NormalizeCertificates at document
// write time. That path made one typo in one TXT record fail Commit for EVERY certificate, every
// round, until a human edited DNS.
func ValidProfile(name string) bool {
	_, ok := profileMaxNames[name]
	return ok
}

// ValidKeyType reports whether kt is a key type this build can generate.
func ValidKeyType(kt string) bool {
	switch kt {
	case KeyTypeECDSAP256, KeyTypeECDSAP384, KeyTypeRSA2048, KeyTypeRSA4096:
		return true
	default:
		return false
	}
}

func (c *Certificate) normalize(seen map[string]bool) error {
	if c.Name == "" {
		return fmt.Errorf("certificates[].name is required")
	}
	if seen[c.Name] {
		return fmt.Errorf("certificate name %q is duplicated", c.Name)
	}
	seen[c.Name] = true

	if c.Profile == "" {
		c.Profile = ProfileClassic
	}
	maxNames, ok := profileMaxNames[c.Profile]
	if !ok {
		return fmt.Errorf("certificate %q: unknown profile %q (want %s/%s/%s)",
			c.Name, c.Profile, ProfileClassic, ProfileTLSServer, ProfileShortLived)
	}

	if c.KeyType == "" {
		c.KeyType = KeyTypeECDSAP256
	}
	if !ValidKeyType(c.KeyType) {
		return fmt.Errorf("certificate %q: unknown keyType %q", c.Name, c.KeyType)
	}

	if len(c.Domains) == 0 {
		return fmt.Errorf("certificate %q: domains is empty", c.Name)
	}

	// Normalize the domains first (lowercase, dedupe, validate), then check the cap.
	//
	// The order matters: on certificates with many SANs the domains list is usually
	// pasted in wholesale from elsewhere, so duplicates and mixed case are the
	// norm. Checking the cap first would count a 100-domain config with 1
	// accidental duplicate as 101 and reject it, even though it is legal.
	normalized, err := normalizeDomains(c.Domains)
	if err != nil {
		return fmt.Errorf("certificate %q: %w", c.Name, err)
	}
	c.Domains = normalized

	if len(c.Domains) > maxNames {
		return fmt.Errorf(
			"certificate %q: %d domains exceeds the %s profile's max of %d identifiers; "+
				"split it into smaller certificates (and remember every name fails together)",
			c.Name, len(c.Domains), c.Profile, maxNames)
	}

	c.RenewBeforeDur, err = parseDuration(c.RenewBefore, profileRenewBefore[c.Profile],
		fmt.Sprintf("certificate %q renewBefore", c.Name))
	if err != nil {
		return err
	}

	// renewBefore must be shorter than the certificate's own lifetime.
	//
	// The renewal time is notAfter - renewBefore, so a value at or beyond the validity
	// puts that instant in the past from the moment the certificate is issued: every pass
	// then decides "renew now". ARI normally masks this -- it takes precedence, and its
	// window is always inside the lifetime -- so the mistake only surfaces when ARI is
	// unavailable, and then it re-orders the same identifier set every hour until the
	// account's 5-per-exact-set/7-day quota is gone.
	//
	// Rejecting it is cheap and the failure it prevents is a week-long stall, which is the
	// same trade the domain validation above makes.
	if v, ok := profileValidity[c.Profile]; ok && c.RenewBeforeDur >= v {
		return fmt.Errorf(
			"certificate %q: renewBefore %s is not shorter than the %s profile's %s validity, "+
				"so renewal would be due the moment the certificate is issued (and would re-order every pass "+
				"whenever ARI is unavailable); use less than %s",
			c.Name, c.RenewBeforeDur, c.Profile, v, v)
	}
	return nil
}

// normalizeDomains trims whitespace, lowercases, dedupes as a set, and
// validates each entry.
//
// Keeping the original config order is deliberate: the classic profile promotes
// the first dNSName to CN, so changing the order changes the certificate's
// Subject CN with it.
func normalizeDomains(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))

	for _, raw := range in {
		d := strings.ToLower(strings.TrimSpace(raw))
		if err := validateDomain(d); err != nil {
			return nil, err
		}
		if seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out, nil
}

// DomainKey returns the fingerprint of the domain set this certificate wants.
func (c *Certificate) DomainKey() string { return DomainKey(c.Domains) }

// DomainKey compresses a set of domains into a string independent of order,
// case and duplicates.
//
// It exists to compare "the set the config wants" against "the SANs actually in
// the certificate": comparing []string directly is disturbed by order and case,
// neither of which has any semantic effect on a certificate.
func DomainKey(domains []string) string {
	seen := make(map[string]bool, len(domains))
	cp := make([]string, 0, len(domains))
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		cp = append(cp, d)
	}
	sort.Strings(cp)
	return strings.Join(cp, ",")
}

// DiffDomains returns what want has and have lacks (missing), and what have has
// and want lacks (extra).
//
// Both directions matter: checking only missing would overlook "a domain was
// deleted from the config", where the extra SAN in the certificate is just as
// much a deviation that needs converging.
func DiffDomains(want, have []string) (missing, extra []string) {
	inWant := make(map[string]bool, len(want))
	inHave := make(map[string]bool, len(have))
	for _, d := range want {
		inWant[strings.ToLower(strings.TrimSpace(d))] = true
	}
	for _, d := range have {
		inHave[strings.ToLower(strings.TrimSpace(d))] = true
	}
	for d := range inWant {
		if !inHave[d] {
			missing = append(missing, d)
		}
	}
	for d := range inHave {
		if !inWant[d] {
			extra = append(extra, d)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra
}

// validateDomain blocks several forms that are known to be rejected by the CA,
// or whose coverage is easily misunderstood.
//
// Why not let the CA report the error: every rejected order consumes order
// quota, and on a certificate with many SANs one typo costs a full re-issue.
// Blocking locally is cheaper.
// ValidateDomain validates one domain, allowing a single wildcard label on the
// far left.
//
// It is exported so desired-state sources reuse the same rules: if a source
// accepted a name wecert rejects, convergence would get stuck on an error that
// can never be fixed, with the reported failure far from the real cause.
func ValidateDomain(d string) error { return validateDomain(d) }

// NormalizeCertificates validates and normalizes a set of certificates: fills
// in defaults, dedupes names, validates domains and count caps.
//
// Both the static config and the desired-state document come through this one
// entry point, so the two paths cannot differ in strictness — that is where
// bizarre "passes in the document, fails in the config" gaps come from.
//
// The one check it cannot host is spec.checkNameStability, which needs the grouping
// package; that imports this one, so hosting it here would be a cycle. It is named here
// so the claim above stays honest instead of quietly becoming false.
func NormalizeCertificates(certs []Certificate) error {
	seen := make(map[string]bool, len(certs))
	byDomainSet := make(map[string]string, len(certs))
	for i := range certs {
		if err := certs[i].normalize(seen); err != nil {
			return err
		}

		// Reject two certificates that ask for the same identifier set AND the same key
		// type under different names.
		//
		// Both count against the same "5 certificates per exact set of identifiers /
		// 7 days" bucket and both spend "Certificates per Registered Domain", and they
		// cover the same names with the same key algorithm, so the second one buys
		// nothing while halving the number of attempts left for the first. This is
		// exactly the cheap local rejection the domain validation above exists for.
		//
		// The key type is part of the dedupe key because the same names with a DIFFERENT
		// algorithm are a legitimate dual-certificate setup (an RSA certificate beside an
		// ECDSA one, so clients without ECDSA still get served): those are distinct
		// certificates with distinct keys, not duplicates.
		//
		// The desired-state path additionally requires a certificate name to be derived
		// from its registered domain (spec.checkNameStability); that rule lives there
		// because it needs the grouping package, which imports this one. The overlap
		// check needs nothing beyond DomainKey and the key type, so it protects both
		// entry points -- which is what the "same entry point, same strictness" claim
		// requires.
		key := certs[i].DomainKey() + "|" + certs[i].KeyType
		if prev, dup := byDomainSet[key]; dup {
			return fmt.Errorf(
				"certificates %q and %q ask for the same identifier set (%s) with the same keyType: "+
					"they would share the 5-per-exact-set/7-days quota and cover the same names, so one of "+
					"them can only waste it (an RSA+ECDSA pair over the same names is fine -- that is "+
					"exactly what the keyType in this check is for)",
				prev, certs[i].Name, certs[i].DomainKey())
		}
		byDomainSet[key] = certs[i].Name
	}
	return nil
}

func validateDomain(d string) error {
	if d == "" {
		return fmt.Errorf("empty domain")
	}
	if strings.HasSuffix(d, ".") {
		return fmt.Errorf("domain %q has a trailing dot", d)
	}
	if len(d) > 253 {
		return fmt.Errorf("domain %q is longer than 253 characters", d)
	}
	if strings.ContainsAny(d, " \t\r\n/") {
		return fmt.Errorf("domain %q contains whitespace or a slash", d)
	}

	// An IP literal cannot be validated with DNS-01, and it does not fail on its own: lego promotes
	// a literal to an RFC 8738 "ip" identifier, the CA then offers only tls-alpn-01 and http-01 for
	// it, and pickDNS01 finds no dns-01 challenge -- so the WHOLE certificate stops issuing, every
	// pass, with an error that names the challenge type rather than the domain that caused it.
	// Rejecting it here turns "this certificate never works" into "this line of the document is
	// wrong". (IPv6 literals are not even expressible as a hostname label, and a wildcard over an
	// address is nonsense, so the base name is what is checked.)
	if net.ParseIP(strings.TrimPrefix(d, "*.")) != nil {
		return fmt.Errorf("domain %q is an IP address: Let's Encrypt issues certificates for DNS "+
			"names, and this program validates with DNS-01, which an address identifier cannot "+
			"answer -- use a name that resolves to it instead", d)
	}
	// A single label, or a public suffix ("co.uk"), cannot be issued either: the CA needs a name
	// under a registrable domain it can validate, and an identifier with nothing above it is
	// exactly the "internal name" the CA/Browser Forum baseline requirements forbid a public CA to
	// sign. The PSL is consulted here rather than through internal/group because group imports this
	// package (it validates through ValidateDomain), so the dependency only runs one way.
	if base := strings.TrimPrefix(d, "*."); base != "" {
		if suffix, _ := publicsuffix.PublicSuffix(base); suffix == base {
			return fmt.Errorf("domain %q IS a public suffix (or has no suffix above it at all), so no "+
				"certificate authority can validate it; use a name under it, e.g. www.%s", d, base)
		}
	}

	// Check label by label. Empty labels (a..example.com), over-long labels and
	// illegal characters are all rejected by the CA.
	for _, label := range strings.Split(d, ".") {
		if label == "*" {
			// The wildcard label itself is legal; its position is checked separately below.
			continue
		}
		if label == "" {
			return fmt.Errorf("domain %q has an empty label", d)
		}
		if len(label) > 63 {
			return fmt.Errorf("domain %q: label %q exceeds 63 characters", d, label)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("domain %q: label %q must not start or end with a hyphen", d, label)
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' {
				continue
			}
			return fmt.Errorf("domain %q: label %q contains an invalid character %q", d, label, string(ch))
		}
	}

	if strings.Contains(d, "*") {
		// LE allows only a single wildcard label, at the far left.
		if !strings.HasPrefix(d, "*.") {
			return fmt.Errorf("domain %q: wildcard must be the leftmost label (e.g. *.example.com)", d)
		}
		if strings.Contains(d[2:], "*") {
			return fmt.Errorf("domain %q: *.*.example.com is not allowed by Let's Encrypt", d)
		}
	}
	return nil
}

func parseDuration(s string, def time.Duration, field string) (time.Duration, error) {
	if s == "" {
		if def == 0 {
			return 0, fmt.Errorf("%s is required", field)
		}
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%s: %w (note: there is no day unit; use hours, e.g. 720h for 30 days)", field, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive, got %s", field, s)
	}
	return d, nil
}

// normalizeRecursiveNameservers accepts IP literals with an optional UDP/TCP
// port. Resolver hostnames are deliberately rejected: resolving the resolver
// name through the system resolver would reintroduce the trust ambiguity this
// setting exists to remove.
func normalizeRecursiveNameservers(in []string) ([]string, error) {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		v := strings.TrimSpace(raw)
		if v == "" {
			return nil, fmt.Errorf("dns.recursiveNameservers contains an empty resolver")
		}
		host, port, err := splitResolverAddress(v)
		if err != nil {
			return nil, fmt.Errorf("dns.recursiveNameservers entry %q: %w", raw, err)
		}
		if net.ParseIP(host) == nil {
			return nil, fmt.Errorf("dns.recursiveNameservers entry %q must use an IP address, not a hostname", raw)
		}
		if port == "" {
			port = "53"
		}
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("dns.recursiveNameservers entry %q has an invalid port", raw)
		}
		addr := net.JoinHostPort(host, port)
		if !seen[addr] {
			seen[addr] = true
			out = append(out, addr)
		}
	}
	return out, nil
}

func splitResolverAddress(v string) (host, port string, err error) {
	if ip := net.ParseIP(v); ip != nil {
		return v, "", nil
	}
	host, port, err = net.SplitHostPort(v)
	if err == nil {
		if host == "" || port == "" {
			return "", "", fmt.Errorf("host and port are both required when a port is specified")
		}
		return host, port, nil
	}
	if strings.Contains(v, ":") {
		return "", "", fmt.Errorf("must be an IP literal optionally followed by a numeric port")
	}
	return v, "", nil
}

// profileValidity is each profile's nominal certificate lifetime as Let's Encrypt
// issues it. It is not used to decide anything -- ARI and renewBefore own that -- only
// to scale the local "approaching expiry" warning below.
var profileValidity = map[string]time.Duration{
	ProfileClassic:    90 * 24 * time.Hour,
	ProfileTLSServer:  45 * 24 * time.Hour,
	ProfileShortLived: 160 * time.Hour,
}

// ExpiryWarningThreshold is how close to expiry a certificate has to get before the
// daemon logs a warning about it.
//
// Scaled to the profile rather than fixed. A fixed 21 days is most of a `shortlived`
// certificate's 160-hour life, so that profile warned from the moment it was issued --
// on every pass, for its whole life, which is exactly the kind of alarm that trains
// people to ignore logs. A quarter of the validity is early enough to act on and late
// enough to mean something. The metrics remain the primary expiry signal; this is a
// secondary log line.
func ExpiryWarningThreshold(profile string) time.Duration {
	v, ok := profileValidity[profile]
	if !ok {
		v = profileValidity[ProfileClassic]
	}
	return v / 4
}

// DaysUntil is the whole number of days left before notAfter, rounded **up**.
//
// Rounded up, because truncation makes "23 hours left" read as 0 days, and 0 days is a
// meaningless thing to report for a certificate that is still valid -- a consumer that
// treats 0 as expired reads a healthy certificate as down. probe.DaysLeft uses the same
// rule; keep the two in step.
func DaysUntil(notAfter, now time.Time) int {
	left := notAfter.Sub(now)
	if left <= 0 {
		return 0
	}
	return int((left + 24*time.Hour - 1) / (24 * time.Hour))
}

// ── secrets from files ──────────────────────────────────────────────────────────────
//
// A credential in config.yaml is a credential in every backup, every paste into a chat window and
// every `cat` while debugging. These three fields let an operator keep them out of the file
// entirely, which is the difference between "rotate the token" and "rotate the token and also
// rewrite every copy of the config that ever existed".
//
// The shape follows systemd's LoadCredential, which is what the shipped unit can use:
//
//	# deploy/systemd/wecert.service.d/credentials.conf
//	[Service]
//	LoadCredential=dnspod-token:/etc/wecert/dnspod.token
//
// systemd then exposes the file at $CREDENTIALS_DIRECTORY/dnspod-token, and the config says
// `loginTokenFile: ${CREDENTIALS_DIRECTORY}/dnspod-token`. That is why the path is
// environment-expanded: CREDENTIALS_DIRECTORY only exists once systemd has started the unit, so a
// literal path cannot express it.

// resolveSecretFiles fills in the *_file variants, and the environment fallbacks.
//
// Called from Load, before validation, so a typo'd path is reported while the operator is looking
// at it rather than after an order has been placed and a challenge has failed -- a rate-limited
// failure is much more expensive than a config error.
//
// Every configured path is read, even one the chosen provider does not use. A config that names a
// file which is not there is wrong whether or not today's provider reads it, and failing now is
// cheaper than failing on the day the provider changes.
func (c *Config) resolveSecretFiles() error {
	resolve := func(field, value, file string, envs []string, target *string) error {
		if value != "" && file != "" {
			return fmt.Errorf("%s and its file variant are both set; keep one of them so it is "+
				"unambiguous which one is in use", field)
		}
		if value != "" {
			return nil
		}
		if file != "" {
			// Environment-expanded so ${CREDENTIALS_DIRECTORY} works: systemd sets it only after
			// the unit starts, so the path cannot be written literally in the file.
			path := os.ExpandEnv(file)
			raw, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read %s from %s: %w (the path is environment-expanded, so "+
					"${CREDENTIALS_DIRECTORY} is only set when systemd runs this)", field, path, err)
			}
			secret := strings.TrimSpace(string(raw))
			if secret == "" {
				return fmt.Errorf("%s file %s is empty; a blank credential would be sent to the "+
					"provider as an empty string and rejected there, far from the cause", field, path)
			}
			*target = secret
			return nil
		}
		for _, env := range envs {
			if v := strings.TrimSpace(os.Getenv(env)); v != "" {
				*target = v
				return nil
			}
		}
		return nil
	}

	if err := resolve("dns.loginToken", c.DNS.LoginToken, c.DNS.LoginTokenFile,
		[]string{EnvDNSPodLoginToken}, &c.DNS.LoginToken); err != nil {
		return err
	}
	if err := resolve("tencent.secretId", c.Tencent.SecretID, c.Tencent.SecretIDFile,
		[]string{"TENCENTCLOUD_SECRET_ID"}, &c.Tencent.SecretID); err != nil {
		return err
	}
	if err := resolve("tencent.secretKey", c.Tencent.SecretKey, c.Tencent.SecretKeyFile,
		[]string{"TENCENTCLOUD_SECRET_KEY"}, &c.Tencent.SecretKey); err != nil {
		return err
	}
	return nil
}

// EnvDNSPodLoginToken is the environment variable read when neither dns.loginToken nor
// dns.loginTokenFile is set. It exists so a container or a systemd EnvironmentFile can supply the
// token without touching the config at all.
const EnvDNSPodLoginToken = "DNSPOD_LOGIN_TOKEN"
