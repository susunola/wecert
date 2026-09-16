// Package config defines wecert's declarative desired state (the spec).
//
// Design principle: the YAML says only "what I want" and carries no runtime
// state at all. Runtime state (order URL, ARI window, Tencent Cloud CertId and
// so on) always goes into SQLite, because losing it directly causes duplicate
// orders and runs into Let's Encrypt rate limits.
package config

import (
	"bytes"
	"fmt"
	"math"
	"net"
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
)

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
// Treating 0 as "not written" is safe here: no legal value of these fields is 0.
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
	return nil
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

	// MaxHostsPerCert is how many names per certificate to probe. Default 3.
	//
	// Not exhaustive: a 25-name certificate would mean 25 handshakes every pass,
	// with diminishing returns and linear cost.
	MaxHostsPerCert int `yaml:"maxHostsPerCert"`

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

func (p *Probe) normalize() error {
	var err error
	if p.TimeoutDur, err = parseDuration(p.Timeout, 10*time.Second, "probe.timeout"); err != nil {
		return err
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
	if p.MaxHostsPerCert == 0 {
		p.MaxHostsPerCert = 3
	}
	if p.MaxHostsPerCert < 0 {
		return fmt.Errorf("probe.maxHostsPerCert must not be negative, got %d", p.MaxHostsPerCert)
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

// ACME is the ACME account and directory configuration.
type ACME struct {
	Directory string `yaml:"directory"`
	Email     string `yaml:"email"`
}

// DNS is the DNS-01 solver configuration.
type DNS struct {
	Provider string `yaml:"provider"`

	// Required when provider=dnspod.
	// This is DNSPod's own API Token (of the form "12345,abcdef0123456789..."),
	// not a Tencent Cloud CAM SecretId/SecretKey.
	LoginToken string `yaml:"loginToken"`

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
	CredentialMode string   `yaml:"credentialMode"`
	SecretID       string   `yaml:"secretId"`
	SecretKey      string   `yaml:"secretKey"`
	RoleName       string   `yaml:"roleName"`
	ResourceTypes  []string `yaml:"resourceTypes"`
	Regions        []string `yaml:"regions"`
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
}

// WebhookTokenMinLen is the minimum token length.
// A short token is no authentication at all on this endpoint — an attacker who
// triggers issuance can burn the rate-limit quota.
const WebhookTokenMinLen = 16

// Certificate is the desired state of one certificate.
type Certificate struct {
	Name        string   `yaml:"name" json:"name"`
	Domains     []string `yaml:"domains" json:"domains"`
	Profile     string   `yaml:"profile" json:"profile"`
	KeyType     string   `yaml:"keyType" json:"keyType"`
	RenewBefore string   `yaml:"renewBefore,omitempty" json:"renewBefore,omitempty"`
	Deploy      Deploy   `yaml:"deploy" json:"deploy"`

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

// MaxNames returns the maximum domain count allowed by this certificate's
// profile.
func (c *Certificate) MaxNames() int {
	if n, ok := profileMaxNames[c.Profile]; ok {
		return n
	}
	return 0
}

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

	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) normalize() error {
	if c.StatePath == "" {
		return fmt.Errorf("statePath is required")
	}
	if c.ACME.Directory == "" {
		return fmt.Errorf("acme.directory is required")
	}
	if c.ACME.Email == "" {
		return fmt.Errorf("acme.email is required")
	}

	// The DNS provider must be chosen explicitly. Defaulting to dnspod suggests
	// Tencent Cloud AK/SK would be enough, then fails confusingly at the DNS-01
	// step.
	switch c.DNS.Provider {
	case "":
		c.DNS.Provider = DNSProviderDNSPod
	case DNSProviderDNSPod, DNSProviderTencentCloud:
	default:
		return fmt.Errorf("dns.provider must be %q or %q, got %q",
			DNSProviderDNSPod, DNSProviderTencentCloud, c.DNS.Provider)
	}
	if c.DNS.Provider == DNSProviderDNSPod && c.DNS.LoginToken == "" {
		return fmt.Errorf("dns.provider=dnspod requires dns.loginToken " +
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
	if c.DNS.TTL <= 0 {
		// The default is 600, not 60: on DNSPod's free tier the TTL floor is 600, and
		// 60 is rejected by the API with LimitExceeded.RecordTtlLimit. Paid tiers may
		// go lower, but the default must hold on every tier.
		c.DNS.TTL = 600
	}
	if len(c.DNS.RecursiveNameservers) > 0 {
		resolvers, err := normalizeRecursiveNameservers(c.DNS.RecursiveNameservers)
		if err != nil {
			return err
		}
		c.DNS.RecursiveNameservers = resolvers
	}

	if c.Metrics.Listen == "" {
		c.Metrics.Listen = "127.0.0.1:9800"
	}

	if err := c.Webhook.normalize(); err != nil {
		return err
	}

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

	if err := c.DesiredState.normalize(len(c.Certificates) > 0); err != nil {
		return err
	}
	if err := c.Onboarding.normalize(); err != nil {
		return err
	}
	if err := c.Probe.normalize(); err != nil {
		return err
	}
	if err := c.Fallback.normalize(); err != nil {
		return err
	}

	// Both static and observe converge on certificates, so a non-empty list is a
	// hard requirement. In enforce mode certificates must be empty (rejected
	// above); the document is the only source.
	if c.DesiredState.Mode != ModeEnforce && len(c.Certificates) == 0 {
		return fmt.Errorf("at least one certificate is required "+
			"(desiredState.mode=%q still converges on this list; "+
			"set desiredState.mode=%q to take the whole list from the desired-state document instead)",
			c.DesiredState.Mode, ModeEnforce)
	}

	return NormalizeCertificates(c.Certificates)
}

func (w *Webhook) normalize() error {
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
	switch c.KeyType {
	case KeyTypeECDSAP256, KeyTypeECDSAP384, KeyTypeRSA2048, KeyTypeRSA4096:
	default:
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
func NormalizeCertificates(certs []Certificate) error {
	seen := make(map[string]bool, len(certs))
	for i := range certs {
		if err := certs[i].normalize(seen); err != nil {
			return err
		}
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
		return 0, fmt.Errorf("%s: %w", field, err)
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
