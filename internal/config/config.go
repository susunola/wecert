// Package config defines wecert's declarative desired state (the spec).
//
// Design principle: the YAML says only "what I want" and carries no runtime
// state at all. Runtime state (order URL, ARI window, Tencent Cloud CertId and
// so on) always goes into SQLite, because losing it directly causes duplicate
// orders and runs into Let's Encrypt rate limits.
package config

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
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
//
// cloudflare uses a scoped Cloudflare API token and calls api.cloudflare.com.
// route53 uses AWS credentials and calls Route 53, either from its own static
// pair or from the AWS SDK's default chain (which is what lets an instance role
// work with no key on disk).
const (
	DNSProviderDNSPod       = "dnspod"
	DNSProviderTencentCloud = "tencentcloud"
	// DNSProviderCloudflare and DNSProviderRoute53 are native providers, not entries in the
	// `lego` + `legoProvider` pair: they are compiled into every build, so no -tags lego_dns
	// rebuild is needed for the two providers this program is most often asked for. See
	// internal/acme/dns_provider.go for how each is constructed.
	DNSProviderCloudflare = "cloudflare"
	DNSProviderRoute53    = "route53"
	// DNSProviderLego selects any provider from lego's registry by name (dns.legoProvider).
	// It requires a binary built with -tags lego_dns; see internal/acme/provider_notags.go for
	// why the registry is not compiled in by default.
	DNSProviderLego = "lego"
)

// cloudflareMinTTL is the Cloudflare API's floor for a DNS record's TTL, in seconds.
//
// lego enforces the same floor (providers/dns/cloudflare/cloudflare.go, `minTTL = 120` in
// v4.35.2) when the provider is built, so a lower dns.ttl would not corrupt anything -- it would
// fail at startup, from NewDNSSolver, with cloudflare's own wording, which names neither the
// config file nor the field that has to change. dns.ttl defaults to 600 for DNSPod, so this only
// meets an operator who deliberately lowered it.
const cloudflareMinTTL = 120

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
	StatePath   string      `yaml:"statePath"`
	StateBackup StateBackup `yaml:"stateBackup"`
	ACME        ACME        `yaml:"acme"`
	DNS         DNS         `yaml:"dns"`
	Tencent     Tencent     `yaml:"tencent"`
	// Deploy picks where issued certificates go: the Tencent Cloud CLB path (default,
	// the shape this program was built for) or a local nginx directory + reload.
	Deploy       DeploySettings  `yaml:"deploy"`
	Nginx        NginxTarget     `yaml:"nginx"`
	Metrics      Metrics         `yaml:"metrics"`
	Webhook      Webhook         `yaml:"webhook"`
	DesiredState DesiredState    `yaml:"desiredState"`
	Onboarding   Onboarding      `yaml:"onboarding"`
	Probe        Probe           `yaml:"probe"`
	Fallback     FailureFallback `yaml:"failureFallback"`
	Certificates []Certificate   `yaml:"certificates"`
}

// Deploy target names for DeploySettings.Target and Certificate.Deploy.Target.
const (
	DeployTargetTencent = "tencent"
	DeployTargetNginx   = "nginx"
)

// DeploySettings is the process-wide deploy backend choice.
//
// Per-certificate deploy.enabled still decides whether anything is pushed at all;
// this field only says *where* a pushed certificate lands. Keeping the two apart
// is what lets a fleet mix "local state only", "CLB" and "nginx" certificates in
// one config without inventing a third flag that means "enabled but where?".
type DeploySettings struct {
	// Target is DeployTargetTencent (default) or DeployTargetNginx.
	Target string `yaml:"target,omitempty"`
}

// NginxTarget describes the local nginx certificate directory layout and the
// command that makes nginx pick up a new file set.
//
// This is for the deployment where TLS does **not** terminate at a cloud LB:
// wecert writes fullchain.pem + privkey.pem on disk and reloads nginx. There is
// no cloud certificate id and no console bind -- the "binding" is the pair of
// files nginx's config already points at.
type NginxTarget struct {
	// DirTemplate is the directory per certificate. "%s" is replaced with the
	// certificate name. Default: /etc/nginx/ssl/%s
	//
	// A template rather than one shared directory: nginx server blocks usually
	// name their ssl_certificate paths, and one directory per certificate keeps
	// a name's key out of every other certificate's directory.
	DirTemplate string `yaml:"dirTemplate,omitempty"`

	// CertFile is the leaf+chain file name inside the directory. Default fullchain.pem.
	// nginx's ssl_certificate should point at this file.
	CertFile string `yaml:"certFile,omitempty"`

	// KeyFile is the private key file name inside the directory. Default privkey.pem.
	// Written 0600: the key is the credential that makes the certificate worth anything.
	KeyFile string `yaml:"keyFile,omitempty"`

	// Reload is the command run after the files land. Default: systemctl reload nginx.
	//
	// An argv slice, not a shell string: quoting rules and PATH lookups are exactly
	// how a deploy path becomes a root command-injection story. Empty means "write
	// the files and do not reload", which is only honest for an operator who reloads
	// on a schedule and knows it.
	Reload []string `yaml:"reload,omitempty"`
}

// NginxCert lets one certificate override the directory only. File names and the
// reload command stay global -- a fleet that needs two reload commands is two
// processes, not one config fighting itself.
type NginxCert struct {
	Dir string `yaml:"dir,omitempty"`
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

	// LocalDirs are additional local snapshot destinations, for example another
	// physical disk or a separately mounted backup volume. Each receives a
	// SQLite-consistent snapshot; state.db itself is never copied.
	LocalDirs []string `yaml:"localDirs"`

	// RemoteTargets deliver the consistent local snapshot to S3-compatible
	// storage (including COS) or SFTP. Credentials are deliberately references,
	// never YAML values.
	RemoteTargets []BackupTarget `yaml:"remoteTargets"`

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
	seen := map[string]bool{}
	if b.Dir != "" {
		seen[filepath.Clean(b.Dir)] = true
	}
	for i, dir := range b.LocalDirs {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			return fmt.Errorf("stateBackup.localDirs[%d] is empty", i)
		}
		clean := filepath.Clean(dir)
		if seen[clean] {
			return fmt.Errorf("stateBackup.localDirs[%d] duplicates another snapshot destination %q", i, clean)
		}
		seen[clean] = true
		b.LocalDirs[i] = clean
	}
	for i := range b.RemoteTargets {
		if err := b.RemoteTargets[i].normalize(i); err != nil {
			return err
		}
	}
	return nil
}

// BackupTarget is one off-host snapshot destination.
type BackupTarget struct {
	Type                    string `yaml:"type"` // s3, cos, or sftp
	Name                    string `yaml:"name"`
	Bucket                  string `yaml:"bucket"`
	Prefix                  string `yaml:"prefix"`
	Endpoint                string `yaml:"endpoint"`
	Region                  string `yaml:"region"`
	Host                    string `yaml:"host"`
	Username                string `yaml:"username"`
	RemoteDir               string `yaml:"remoteDir"`
	PasswordEnv             string `yaml:"passwordEnv"`
	PrivateKeyFile          string `yaml:"privateKeyFile"`
	PrivateKeyPassphraseEnv string `yaml:"privateKeyPassphraseEnv"`
	KnownHostsFile          string `yaml:"knownHostsFile"`
	// SecretIDEnv / SecretKeyEnv are COS credential environment-variable names.
	// They default to TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY for COS
	// and are ignored by AWS S3, which keeps using its standard credential chain.
	SecretIDEnv  string        `yaml:"secretIdEnv"`
	SecretKeyEnv string        `yaml:"secretKeyEnv"`
	Keep         int           `yaml:"keep"`
	Timeout      string        `yaml:"timeout"`
	TimeoutDur   time.Duration `yaml:"-"`
}

func (t *BackupTarget) normalize(i int) error {
	t.Type = strings.ToLower(strings.TrimSpace(t.Type))
	t.Name = strings.TrimSpace(t.Name)
	switch t.Type {
	case "s3", "cos":
		if t.Bucket == "" {
			return fmt.Errorf("stateBackup.remoteTargets[%d].bucket is required for %s", i, t.Type)
		}
		if t.Type == "cos" && strings.TrimSpace(t.Endpoint) == "" {
			return fmt.Errorf("stateBackup.remoteTargets[%d].endpoint is required for cos", i)
		}
		if t.Type == "cos" {
			if t.SecretIDEnv == "" {
				t.SecretIDEnv = "TENCENTCLOUD_SECRET_ID"
			}
			if t.SecretKeyEnv == "" {
				t.SecretKeyEnv = "TENCENTCLOUD_SECRET_KEY"
			}
		}
	case "sftp":
		if t.Host == "" || t.Username == "" || t.RemoteDir == "" || t.KnownHostsFile == "" {
			return fmt.Errorf("stateBackup.remoteTargets[%d] sftp requires host, username, remoteDir and knownHostsFile", i)
		}
		if t.PrivateKeyFile == "" && t.PasswordEnv == "" {
			return fmt.Errorf("stateBackup.remoteTargets[%d] sftp requires privateKeyFile or passwordEnv", i)
		}
	default:
		return fmt.Errorf("stateBackup.remoteTargets[%d].type must be s3, cos or sftp, got %q", i, t.Type)
	}
	if t.Name == "" {
		t.Name = fmt.Sprintf("%s-%d", t.Type, i+1)
	}
	if t.Keep == 0 {
		t.Keep = DefaultBackupKeep
	}
	if t.Keep < 1 {
		return fmt.Errorf("stateBackup.remoteTargets[%d].keep must be at least 1", i)
	}
	var err error
	if t.TimeoutDur, err = parseDuration(t.Timeout, 5*time.Minute, fmt.Sprintf("stateBackup.remoteTargets[%d].timeout", i)); err != nil {
		return err
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
type ACME struct {
	Directory string `yaml:"directory"`
	// FallbackDirectories are used only when the primary ACME directory is
	// unavailable at transport level (or explicitly rejects new orders for the
	// account). They are not a retry for DNS or authorization failures.
	FallbackDirectories []string `yaml:"fallbackDirectories,omitempty"`
	Email               string   `yaml:"email"`
	// EAB supplies the External Account Binding credentials required by some
	// commercial and private ACME directories. HMACFile keeps the binding secret
	// out of config.yaml and works with systemd LoadCredential.
	EAB ACMEExternalAccountBinding `yaml:"eab,omitempty"`
}

type ACMEExternalAccountBinding struct {
	KID      string `yaml:"kid,omitempty"`
	HMAC     string `yaml:"hmac,omitempty"`
	HMACFile string `yaml:"hmacFile,omitempty"`
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

	// Cloudflare is the credential block for provider=cloudflare. It is read only then: a
	// cloudflare block left behind while another provider is selected would silently keep sending
	// the challenges through that other provider, so normalizeDNS rejects it rather than ignoring
	// it -- the same call dns.legoProvider already gets.
	Cloudflare Cloudflare `yaml:"cloudflare,omitempty"`

	// Route53 is the credential and zone block for provider=route53, read under the same rule.
	Route53 Route53 `yaml:"route53,omitempty"`

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

// Cloudflare is the credential block for the native cloudflare provider.
//
// One scoped API token, not the legacy global API key: a token is limited to the permissions it
// was created with (Zone:Read + DNS:Edit is enough) and to the zones it may touch, and revoking it
// does not invalidate anything else in the account.
type Cloudflare struct {
	// APIToken is required when provider=cloudflare, unless one of the two other sources below
	// supplies it. Looks like a 40-character opaque string.
	APIToken string `yaml:"apiToken"`

	// APITokenFile reads the token from a file instead: a 0600 file, a systemd credential, or
	// anything else that keeps it out of config.yaml. Environment-expanded, so
	// ${CREDENTIALS_DIRECTORY}/cloudflare-token works under LoadCredential. Mutually exclusive with
	// apiToken.
	APITokenFile string `yaml:"apiTokenFile,omitempty"`
}

// configured reports whether the block carries anything, which is what tells an unused block (the
// shape every config that selects another provider has) from one the operator believes is in
// effect.
func (c *Cloudflare) configured() bool { return c.APIToken != "" || c.APITokenFile != "" }

// Route53 is the credential and zone block for the native route53 provider.
//
// Two credential paths, and they are alternatives rather than a hierarchy:
//
//   - static keys (accessKeyId + secretAccessKey): used only when they are configured, and then
//     they replace the chain outright.
//   - nothing configured: the AWS SDK's own default chain resolves them -- the AWS_ACCESS_KEY_ID /
//     AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN environment, then the shared config and
//     credentials files, then the instance role. That last one is why the keys are optional rather
//     than required: on an EC2 instance the role is the best credential source there is, with
//     nothing on disk to leak or rotate, and a required key pair would make it unusable.
type Route53 struct {
	// Region is what the AWS SDK signs every request for. Route 53 itself is a global service, but
	// the SDK refuses to build a client without a region ("an AWS region is required"), so this has
	// to be set unless AWS_REGION or AWS_DEFAULT_REGION is in the environment.
	Region string `yaml:"region"`

	// HostedZoneID pins the zone the challenge records are written into. Empty means lego looks up
	// the public hosted zone that contains the challenge FQDN, which is what a wildcard+SAN
	// certificate wants; AWS_HOSTED_ZONE_ID is lego's own fallback and still applies.
	HostedZoneID string `yaml:"hostedZoneId,omitempty"`

	// AccessKeyID and SecretAccessKey are the static pair. Leave BOTH empty to use the default
	// chain described above.
	AccessKeyID     string `yaml:"accessKeyId"`
	SecretAccessKey string `yaml:"secretAccessKey"`

	// SecretAccessKeyFile reads the secret key from a file instead, under the same rules as
	// LoginTokenFile: 0600, environment-expanded, mutually exclusive with secretAccessKey. The
	// accessKeyId is not a secret and has no file variant.
	SecretAccessKeyFile string `yaml:"secretAccessKeyFile,omitempty"`

	// SessionToken / SessionTokenFile carry the temporary-credential token that belongs to a static
	// accessKeyId + secretAccessKey pair (an STS session, or a profile that assumed a role). They
	// are read only with that pair: with the default chain the SDK obtains its own token, and one
	// supplied without the pair would be refused by lego as a token with no credentials to carry.
	SessionToken     string `yaml:"sessionToken,omitempty"`
	SessionTokenFile string `yaml:"sessionTokenFile,omitempty"`
}

// configured reports whether the block carries anything; see Cloudflare.configured.
func (r *Route53) configured() bool {
	return r.Region != "" || r.HostedZoneID != "" || r.AccessKeyID != "" ||
		r.SecretAccessKey != "" || r.SecretAccessKeyFile != "" ||
		r.SessionToken != "" || r.SessionTokenFile != ""
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

	// AdminToken is a SECOND shared secret for the guarded write/diagnostic surface
	// (/admin/...). Optional: without it the admin routes are not mounted, and the
	// process stays read-only over the network.
	//
	// Deliberately separate from Token: the read-only token is what a CI job holds to
	// poll status; the admin token is what can restore a snapshot. Sharing one would
	// give every status poller the ability to overwrite state.db.
	AdminToken string `yaml:"adminToken,omitempty"`
}

// WebhookAdminTokenMinLen is the minimum admin token length. Longer than the
// read-only token's floor: this one can restore state.
const WebhookAdminTokenMinLen = 32

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
	// FailureFallback overrides the global failureFallback policy for this
	// certificate only. A non-nil block with enabled: false explicitly opts this
	// certificate out while other certificates may still degrade near expiry.
	FailureFallback *FailureFallback `yaml:"failureFallback,omitempty" json:"failureFallback,omitempty"`
	// Export writes the issued full chain and private key to operator-selected
	// local and/or remote destinations after a successful promotion.
	Export *CertificateExport `yaml:"export,omitempty" json:"export,omitempty"`
	// UIN tags this certificate with a Tencent Cloud account. Empty means inherit
	// tencent.uin. The inventory uses it only for display and grouping; it does
	// not change which credentials deploy the certificate.
	UIN string `yaml:"uin,omitempty" json:"uin,omitempty"`

	// Parsed durations, filled in by normalize.
	RenewBeforeDur time.Duration `yaml:"-" json:"-"`
}

// CertificateExport is an opt-in private-key distribution target. RemoteTargets
// use the same credential-reference-only shape as state backups.
type CertificateExport struct {
	LocalDir      string         `yaml:"localDir,omitempty" json:"localDir,omitempty"`
	RemoteTargets []BackupTarget `yaml:"remoteTargets,omitempty" json:"remoteTargets,omitempty"`
}

// Deploy describes where the issued certificate should be deployed.
//
// On Tencent Cloud, first issuance only uploads: there is no binding on that side
// yet, so a human binds once in the console and later renewals are swapped by
// UpdateCertificateInstance. On nginx there is no console step -- writing the
// files and reloading *is* the bind.
type Deploy struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Target overrides DeploySettings.Target for this certificate only.
	Target string `yaml:"target,omitempty" json:"target,omitempty"`
	// Nginx is read only when this certificate's target is nginx.
	Nginx *NginxCert `yaml:"nginx,omitempty" json:"nginx,omitempty"`
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
func (c *Config) resolveSecretFiles() ([]string, error) {
	var warns []string
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
			if fi, statErr := os.Stat(path); statErr == nil {
				warns = append(warns, secretFilePermWarnings(field, path, fi.Mode().Perm())...)
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
		return warns, err
	}
	if err := resolve("acme.eab.hmac", c.ACME.EAB.HMAC, c.ACME.EAB.HMACFile,
		[]string{"WECERT_ACME_EAB_HMAC"}, &c.ACME.EAB.HMAC); err != nil {
		return warns, err
	}

	// The two provider blocks below are resolved only when their provider is the selected one.
	//
	// Otherwise the ambient environment would decide: a host that exports CLOUDFLARE_DNS_API_TOKEN
	// for some other tool, or AWS_ACCESS_KEY_ID for the AWS CLI, would have a field filled in on a
	// config that selects dnspod -- and normalizeDNS rejects a provider block that belongs to
	// another provider, so an unrelated variable in the environment would turn a working config
	// into a load error. Which provider is in use comes from the file, so only the file can put a
	// value in these fields.
	if c.DNS.Provider == DNSProviderCloudflare {
		if err := resolve("dns.cloudflare.apiToken", c.DNS.Cloudflare.APIToken,
			c.DNS.Cloudflare.APITokenFile,
			[]string{EnvCloudflareAPIToken, EnvCloudflareAPITokenAlt},
			&c.DNS.Cloudflare.APIToken); err != nil {
			return warns, err
		}
	}
	if c.DNS.Provider == DNSProviderRoute53 {
		// Region has no file variant -- it is not a secret -- but it has the two environment
		// fallbacks the AWS SDK itself reads, so a deployment that already sets AWS_REGION does not
		// have to repeat it here.
		if c.DNS.Route53.Region == "" {
			for _, env := range []string{EnvAWSRegion, EnvAWSDefaultRegion} {
				if v := strings.TrimSpace(os.Getenv(env)); v != "" {
					c.DNS.Route53.Region = v
					break
				}
			}
		}
		// The static secret key has a file variant for the same reason as loginToken. There is no
		// environment fallback here on purpose: AWS_SECRET_ACCESS_KEY belongs to the SDK's default
		// chain, which is used when no static pair is configured, and copying it into the config
		// field would instead build a static provider out of half of a pair.
		if err := resolve("dns.route53.secretAccessKey", c.DNS.Route53.SecretAccessKey,
			c.DNS.Route53.SecretAccessKeyFile, nil, &c.DNS.Route53.SecretAccessKey); err != nil {
			return warns, err
		}
		if err := resolve("dns.route53.sessionToken", c.DNS.Route53.SessionToken,
			c.DNS.Route53.SessionTokenFile, nil, &c.DNS.Route53.SessionToken); err != nil {
			return warns, err
		}
	}

	if err := resolve("tencent.secretId", c.Tencent.SecretID, c.Tencent.SecretIDFile,
		[]string{"TENCENTCLOUD_SECRET_ID"}, &c.Tencent.SecretID); err != nil {
		return warns, err
	}
	if err := resolve("tencent.secretKey", c.Tencent.SecretKey, c.Tencent.SecretKeyFile,
		[]string{"TENCENTCLOUD_SECRET_KEY"}, &c.Tencent.SecretKey); err != nil {
		return warns, err
	}
	return warns, nil
}

// secretFilePermWarnings warns when a *_file credential path is readable by group or
// other. Pure like configPermWarnings so the wording is testable without capturing
// stderr. The file's own mode is the check: the config may live anywhere, and a
// systemd LoadCredential directory is already 0400. A warning rather than a refusal,
// matching configPermWarnings: refusing would push operators toward copying the secret
// back into config.yaml.
func secretFilePermWarnings(field, path string, perm os.FileMode) []string {
	if perm&0o077 == 0 {
		return nil
	}
	return []string{fmt.Sprintf(
		"the credential file for %s (%s) is readable by group or other (%04o). "+
			"A secret in a wide file is in every backup and every archive of that path; "+
			"chmod 0600 it (a systemd LoadCredential path is usually already 0400)",
		field, path, perm)}
}

// EnvDNSPodLoginToken is the environment variable read when neither dns.loginToken nor
// dns.loginTokenFile is set. It exists so a container or a systemd EnvironmentFile can supply the
// token without touching the config at all.
const EnvDNSPodLoginToken = "DNSPOD_LOGIN_TOKEN"

// EnvCloudflareAPIToken is the variable lego's cloudflare provider documents for the scoped API
// token, and EnvCloudflareAPITokenAlt the short alias it also accepts. Either can supply
// dns.cloudflare.apiToken when neither the field nor its file variant is set.
const (
	EnvCloudflareAPIToken    = "CLOUDFLARE_DNS_API_TOKEN"
	EnvCloudflareAPITokenAlt = "CF_DNS_API_TOKEN"
)

// EnvAWSRegion and EnvAWSDefaultRegion are the two variables the AWS SDK reads for a region; they
// stand in for dns.route53.region when it is empty, so a config that already sets one works here.
const (
	EnvAWSRegion        = "AWS_REGION"
	EnvAWSDefaultRegion = "AWS_DEFAULT_REGION"
)
