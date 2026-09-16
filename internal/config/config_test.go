package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("failed to write temporary config: %v", err)
	}
	return path
}

const minimalPrefix = `
statePath: /tmp/wecert-test.db
acme:
  directory: https://acme-staging-v02.api.letsencrypt.org/directory
  email: ops@example.com
dns:
  provider: dnspod
  loginToken: token
tencent:
  credentialMode: static
  secretId: id
  secretKey: key
  regions: [ap-guangzhou]
`

func TestLoadMinimal(t *testing.T) {
	path := writeConfig(t, minimalPrefix+`
certificates:
  - name: example-com
    domains: ["example.com", "*.example.com"]
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	c := cfg.Certificates[0]
	if c.Profile != ProfileClassic {
		t.Errorf("default profile should be classic, got %q", c.Profile)
	}
	if c.KeyType != KeyTypeECDSAP256 {
		t.Errorf("default keyType should be ecdsa-p256, got %q", c.KeyType)
	}
	// classic renews 30 days ahead by default.
	if c.RenewBeforeDur != 30*24*time.Hour {
		t.Errorf("classic default renewBefore should be 720h, got %v", c.RenewBeforeDur)
	}
	if c.MaxNames() != 100 {
		t.Errorf("classic MaxNames should be 100, got %d", c.MaxNames())
	}
	// Duration defaults should be filled in, not left at zero.
	if cfg.DNS.Propagation != 5*time.Minute {
		t.Errorf("dnspod.propagationTimeout default should be 5m, got %v", cfg.DNS.Propagation)
	}
	if cfg.Metrics.Listen == "" {
		t.Error("metrics.listen should have a default")
	}
}

func TestRecursiveNameserversAreNormalized(t *testing.T) {
	body := strings.Replace(minimalPrefix, "  loginToken: token\n", "  loginToken: token\n  recursiveNameservers: [\"1.1.1.1\", \"[2606:4700:4700::1111]:5353\", \"1.1.1.1:53\"]\n", 1)
	cfg, err := Load(writeConfig(t, body+`
certificates:
  - name: example-com
    domains: ["example.com"]
`))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"1.1.1.1:53", "[2606:4700:4700::1111]:5353"}
	if strings.Join(cfg.DNS.RecursiveNameservers, ",") != strings.Join(want, ",") {
		t.Errorf("recursiveNameservers = %v, want %v", cfg.DNS.RecursiveNameservers, want)
	}
}

func TestRecursiveNameserversRejectHostnamesAndBadPorts(t *testing.T) {
	for _, resolver := range []string{"resolver.example", "1.1.1.1:not-a-port", "[2606:4700:4700::1111"} {
		body := strings.Replace(minimalPrefix, "  loginToken: token\n", "  loginToken: token\n  recursiveNameservers: [\""+resolver+"\"]\n", 1)
		_, err := Load(writeConfig(t, body+`
certificates:
  - name: example-com
    domains: ["example.com"]
`))
		if err == nil || !strings.Contains(err.Error(), "recursiveNameservers") {
			t.Errorf("resolver %q should be rejected, got %v", resolver, err)
		}
	}
}

// The tlsserver profile caps Max Names at 25, so it must be blocked locally,
// or an order the CA would certainly refuse goes out and burns order quota.
func TestProfileMaxNamesEnforcedLocally(t *testing.T) {
	domains := make([]string, 0, 26)
	for i := 0; i < 26; i++ {
		domains = append(domains, "d"+string(rune('a'+i))+".example.com")
	}

	body := minimalPrefix + `
certificates:
  - name: too-many
    profile: tlsserver
    domains: [` + strings.Join(quoteAll(domains), ", ") + `]
`
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("a tlsserver profile with more than 25 domains should error")
	}
	if !strings.Contains(err.Error(), "25") {
		t.Errorf("the error should mention the 25 cap, got: %v", err)
	}
}

// classic's 100 is a hard cap; 101 must be rejected.
func TestClassicMaxNames(t *testing.T) {
	domains := make([]string, 0, 101)
	for i := 0; i < 101; i++ {
		domains = append(domains, "d"+itoa(i)+".example.com")
	}
	body := minimalPrefix + `
certificates:
  - name: too-many
    profile: classic
    domains: [` + strings.Join(quoteAll(domains), ", ") + `]
`
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("a classic profile with more than 100 domains should error")
	}
}

func TestWildcardValidation(t *testing.T) {
	cases := []struct {
		domain  string
		wantErr bool
		why     string
	}{
		{"example.com", false, "ordinary domain"},
		{"*.example.com", false, "valid wildcard"},
		{"a.b.example.com", false, "multi-level subdomain"},
		{"*.*.example.com", true, "LE does not allow *.*"},
		{"a.*.example.com", true, "wildcard must be leftmost"},
		{"example.com.", true, "trailing dot"},
		{"", true, "empty domain"},
	}

	for _, tc := range cases {
		body := minimalPrefix + `
certificates:
  - name: t
    domains: ["` + tc.domain + `"]
`
		_, err := Load(writeConfig(t, body))
		if tc.wantErr && err == nil {
			t.Errorf("%s (%s): expected an error but got none", tc.domain, tc.why)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%s (%s): expected success but got error: %v", tc.domain, tc.why, err)
		}
	}
}

// A misspelled config must surface immediately, never be silently ignored.
func TestUnknownFieldRejected(t *testing.T) {
	body := minimalPrefix + `
certificates:
  - name: t
    domains: ["example.com"]
    renewwBefore: 30d
`
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("an unknown field should cause an error")
	}
}

func TestDuplicateCertificateNameRejected(t *testing.T) {
	body := minimalPrefix + `
certificates:
  - name: dup
    domains: ["a.example.com"]
  - name: dup
    domains: ["b.example.com"]
`
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("a duplicate certificate name should error")
	}
}

func TestMissingRegionsRejected(t *testing.T) {
	body := `
statePath: /tmp/wecert-test.db
acme:
  directory: https://acme-staging-v02.api.letsencrypt.org/directory
  email: ops@example.com
dns:
  provider: dnspod
  loginToken: token
tencent:
  credentialMode: static
  secretId: id
  secretKey: key
certificates:
  - name: t
    domains: ["example.com"]
`
	// CLB is a regional resource; without regions not one instance gets updated.
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("missing tencent.regions should error")
	}
}

func TestStagingAndProductionConstants(t *testing.T) {
	if DirectoryStaging == DirectoryProduction {
		t.Fatal("the staging and production directories must differ")
	}
}

// dns.provider=dnspod uses DNSPod's own API Token, not a Tencent Cloud AK/SK.
// When it is missing the error must be understandable, or users will sit there
// baffled, holding a Tencent Cloud AK/SK.
func TestDNSPodProviderRequiresLoginToken(t *testing.T) {
	body := `
statePath: /tmp/wecert-test.db
acme:
  directory: https://acme-staging-v02.api.letsencrypt.org/directory
  email: ops@example.com
dns:
  provider: dnspod
tencent:
  credentialMode: static
  secretId: id
  secretKey: key
  regions: [ap-guangzhou]
certificates:
  - name: t
    domains: ["example.com"]
`
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("dns.provider=dnspod without loginToken should error")
	}
	if !strings.Contains(err.Error(), "SecretId") {
		t.Errorf("the error should make clear it is not a Tencent Cloud SecretId/SecretKey, got: %v", err)
	}
}

// Conversely, the tencentcloud provider must not require a DNSPod token.
func TestTencentCloudProviderNeedsNoLoginToken(t *testing.T) {
	body := `
statePath: /tmp/wecert-test.db
acme:
  directory: https://acme-staging-v02.api.letsencrypt.org/directory
  email: ops@example.com
dns:
  provider: tencentcloud
tencent:
  credentialMode: static
  secretId: id
  secretKey: key
  regions: [ap-guangzhou]
certificates:
  - name: t
    domains: ["example.com"]
`
	cfg, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatalf("dns.provider=tencentcloud should not require loginToken: %v", err)
	}
	if cfg.DNS.Provider != DNSProviderTencentCloud {
		t.Errorf("provider = %q", cfg.DNS.Provider)
	}
}

func TestUnknownDNSProviderRejected(t *testing.T) {
	body := `
statePath: /tmp/wecert-test.db
acme:
  directory: https://acme-staging-v02.api.letsencrypt.org/directory
  email: ops@example.com
dns:
  provider: route53
tencent:
  credentialMode: static
  secretId: id
  secretKey: key
  regions: [ap-guangzhou]
certificates:
  - name: t
    domains: ["example.com"]
`
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("an unknown dns.provider should error")
	}
}

func quoteAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = `"` + s + `"`
	}
	return out
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// ── webhook validation ────────────────────────────────────────────────────────────

func TestWebhookDisabledByDefault(t *testing.T) {
	path := writeConfig(t, minimalPrefix+`
certificates:
  - name: t
    domains: ["example.com"]
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Webhook.Listen != "" {
		t.Errorf("webhook should be disabled by default, got listen=%q", cfg.Webhook.Listen)
	}
}

// This endpoint triggers real issuance and burns rate-limit quota, so a
// missing token must be refused outright.
func TestWebhookRequiresToken(t *testing.T) {
	body := minimalPrefix + `
webhook:
  listen: "127.0.0.1:9801"
certificates:
  - name: t
    domains: ["example.com"]
`
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("enabling the webhook without a token should error")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Errorf("the error should point out the missing token, got: %v", err)
	}
}

// A weak token is no authentication at all on this endpoint.
func TestWebhookRejectsShortToken(t *testing.T) {
	body := minimalPrefix + `
webhook:
  listen: "127.0.0.1:9801"
  token: "short"
certificates:
  - name: t
    domains: ["example.com"]
`
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("a too-short token should error")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("the error should say it is too short, got: %v", err)
	}
}

// A token with no listen address is a config written backwards — the endpoint
// does not exist, so the token guards nothing.
func TestWebhookTokenWithoutListenIsRejected(t *testing.T) {
	body := minimalPrefix + `
webhook:
  token: "0123456789abcdef0123"
certificates:
  - name: t
    domains: ["example.com"]
`
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("a token without listen should error")
	}
}

// NotifyURL is outbound notification, independent of the listen endpoint; it
// may be used alone.
func TestWebhookNotifyURLAloneIsAllowed(t *testing.T) {
	body := minimalPrefix + `
webhook:
  notifyURL: "https://example.com/hook"
certificates:
  - name: t
    domains: ["example.com"]
`
	cfg, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatalf("notifyURL alone should be allowed: %v", err)
	}
	if cfg.Webhook.NotifyURL == "" {
		t.Error("notifyURL was not preserved")
	}
}

func TestWebhookValidConfig(t *testing.T) {
	body := minimalPrefix + `
webhook:
  listen: "127.0.0.1:9801"
  token: "0123456789abcdef0123456789abcdef"
  notifyURL: "https://example.com/hook"
  notifySecret: "0123456789abcdef0123456789abcdef"
certificates:
  - name: t
    domains: ["example.com"]
`
	cfg, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatalf("a valid config should not error: %v", err)
	}
	if cfg.Webhook.Listen != "127.0.0.1:9801" || cfg.Webhook.Token == "" {
		t.Errorf("webhook config was not parsed correctly: %+v", cfg.Webhook)
	}
	if cfg.Webhook.NotifySecret == "" {
		t.Error("notifySecret was not preserved")
	}
}

// A secret with no notifyURL signs nothing: it is a configuration mistake, and
// silently ignoring it would leave the operator believing events are signed.
func TestWebhookNotifySecretWithoutURLIsRejected(t *testing.T) {
	body := minimalPrefix + `
webhook:
  notifySecret: "0123456789abcdef0123456789abcdef"
certificates:
  - name: t
    domains: ["example.com"]
`
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("notifySecret without notifyURL should be rejected")
	}
}

// A short HMAC key is recoverable from a single signed event, so it would not
// actually prove the event came from wecert.
func TestWebhookNotifySecretTooShortIsRejected(t *testing.T) {
	body := minimalPrefix + `
webhook:
  notifyURL: "https://example.com/hook"
  notifySecret: "tooshort"
certificates:
  - name: t
    domains: ["example.com"]
`
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("a short notifySecret should be rejected")
	}
}

// The onboarding knobs configure the safety invariants, so an out-of-range value
// has to be rejected at load time rather than quietly switching the guard off.
//
// DropThreshold is the sharpest case. It is compared against a loss ratio that is
// always <= 1, so a percentage written as `30` -- or any value >= 1 -- makes the
// comparison unsatisfiable and the abrupt-change fuse silently never fires. That
// fuse is the documented protection against "the upstream returned partial data and
// we stripped every SAN"; nothing else reports it, so a typo removes the guard with
// no error anywhere.
func TestOnboardingPolicyValuesAreRangeChecked(t *testing.T) {
	minimalCert := `
certificates:
  - name: example-com
    domains: ["example.com"]
`

	bad := []struct{ name, body string }{
		{"dropThreshold written as a percentage", "onboarding:\n  dropThreshold: 30\n"},
		{"dropThreshold above 1", "onboarding:\n  dropThreshold: 1.5\n"},
		{"dropThreshold exactly 1 (can never be exceeded)", "onboarding:\n  dropThreshold: 1\n"},
		{"negative dropThreshold", "onboarding:\n  dropThreshold: -0.1\n"},
		{"dropThreshold NaN slips past every comparison", "onboarding:\n  dropThreshold: .nan\n"},
		{"negative budget", "onboarding:\n  budget: -1\n"},
		{"negative maxNames", "onboarding:\n  maxNames: -5\n"},
		{"unknown profile", "onboarding:\n  profile: tls-server\n"},
		{"unknown keyType", "onboarding:\n  keyType: rsa-2048\n"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, minimalPrefix+tc.body+minimalCert)); err == nil {
				t.Fatalf("Load accepted %s; the guard this configures would be silently disabled", tc.name)
			}
		})
	}

	good := []string{
		"onboarding:\n  dropThreshold: 0.3\n",
		"onboarding:\n  dropThreshold: 0\n", // 0 means "use the default"
		"onboarding:\n  budget: 25\n",
		"onboarding:\n  maxNames: 25\n",
		"onboarding:\n  profile: tlsserver\n  keyType: rsa2048\n",
		"", // no onboarding block at all
	}
	for _, body := range good {
		if _, err := Load(writeConfig(t, minimalPrefix+body+minimalCert)); err != nil {
			t.Errorf("Load rejected a valid setting %q: %v", body, err)
		}
	}
}

// DaysUntil round **up**: truncation makes "23 hours left" read as 0 days, and 0 is a
// meaningless answer for a certificate that is still valid -- a caller that treats 0 as
// expired reads a healthy certificate as down. probe.DaysLeft uses the same rule.
func TestDaysUntilRoundsUp(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		left time.Duration
		want int
	}{
		{0, 0},
		{-time.Hour, 0},     // already expired
		{time.Minute, 1},    // a minute left is still "1 day", not 0
		{23 * time.Hour, 1}, // the case truncation gets wrong
		{24 * time.Hour, 1}, // exactly one day
		{25 * time.Hour, 2}, // just over a day
		{48 * time.Hour, 2}, //
		{90 * 24 * time.Hour, 90},
	}
	for _, tc := range cases {
		if got := DaysUntil(now.Add(tc.left), now); got != tc.want {
			t.Errorf("DaysUntil(%v left) = %d, want %d", tc.left, got, tc.want)
		}
	}
}

// The expiry warning has to scale with the profile. A fixed 21-day window is most of a
// shortlived certificate's 160-hour life, so that profile would warn from the moment it
// was issued -- every pass, for its whole life -- which is the kind of alarm that trains
// people to ignore logs.
func TestExpiryWarningThresholdScalesWithTheProfile(t *testing.T) {
	classic := ExpiryWarningThreshold(ProfileClassic)
	short := ExpiryWarningThreshold(ProfileShortLived)

	if short >= classic {
		t.Errorf("shortlived threshold %v must be well below classic %v", short, classic)
	}
	if short >= 160*time.Hour {
		t.Errorf("the shortlived threshold %v is not below that profile's whole validity", short)
	}
	// Every profile's threshold must leave room to act: it has to be a fraction of the
	// validity, not all of it.
	for _, p := range []string{ProfileClassic, ProfileTLSServer, ProfileShortLived} {
		if th := ExpiryWarningThreshold(p); th <= 0 || th >= 90*24*time.Hour {
			t.Errorf("threshold for %s = %v, outside a sane range", p, th)
		}
	}
	// An unknown profile falls back to classic rather than warning at zero.
	if got := ExpiryWarningThreshold("bogus"); got != classic {
		t.Errorf("unknown profile = %v, want the classic threshold %v", got, classic)
	}
}

// renewBefore must be shorter than the profile's own validity.
//
// The renewal instant is notAfter - renewBefore. A value at or beyond the validity puts
// that instant in the past the moment the certificate is issued, so every pass decides
// "renew now" -- and since the same identifier set is ordered each time, the account's
// 5-per-exact-set/7-day quota is gone within days. ARI normally hides it (its window owns
// the decision and always sits inside the lifetime), so the mistake only bites when ARI
// is unavailable.
func TestLoadRejectsRenewBeforeLongerThanTheValidity(t *testing.T) {
	path := writeConfig(t, minimalPrefix+`
certificates:
  - name: example-com
    domains: ["example.com"]
    renewBefore: 2400h
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("classic validity is 90d; a 100d renewBefore must be rejected")
	}
	if !strings.Contains(err.Error(), "renewBefore") {
		t.Errorf("the error should name the field, got %v", err)
	}
}

// A sane value still loads, so the bound cannot be satisfied by rejecting everything.
func TestLoadAcceptsAReasonableRenewBefore(t *testing.T) {
	path := writeConfig(t, minimalPrefix+`
certificates:
  - name: example-com
    domains: ["example.com"]
    renewBefore: 480h
`)
	if _, err := Load(path); err != nil {
		t.Fatalf("a 20d renewBefore on the 90d classic profile must load: %v", err)
	}
}

// A negative failureFallback count is a typo, not "unset". It used to be silently
// replaced by the default while every sibling knob in the same block rejects
// out-of-range values.
func TestLoadRejectsNegativeFailureFallbackCounts(t *testing.T) {
	for _, body := range []string{
		"failureFallback:\n  enabled: true\n  afterFailures: -5\n",
		"failureFallback:\n  enabled: true\n  minIdentifierFailures: -2\n",
		"failureFallback:\n  enabled: true\n  minNames: -1\n",
	} {
		path := writeConfig(t, minimalPrefix+body+`
certificates:
  - name: example-com
    domains: ["example.com"]
`)
		if _, err := Load(path); err == nil {
			t.Errorf("a negative value must be rejected rather than silently defaulted:\n%s", body)
		}
	}
}

// A second YAML document is dropped by a single Decode call. KnownFields catches a
// misspelled key but says nothing about everything after a stray "---", so half a config
// silently never takes effect -- typically after a copy-paste or a template edit.
func TestLoadRejectsASecondYAMLDocument(t *testing.T) {
	path := writeConfig(t, minimalPrefix+`
certificates:
  - name: example-com
    domains: ["example.com"]
---
certificates:
  - name: other-com
    domains: ["other.com"]
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("a config with two YAML documents must be rejected, not half-ignored")
	}
	if !strings.Contains(err.Error(), "more than one YAML document") {
		t.Errorf("the error should explain the cause, got %v", err)
	}
}

// Two certificates asking for the same identifier set share one quota bucket and cover
// the same names, so the second buys nothing. The desired-state path already rejected
// this shape via checkNameStability; static and observe mode did not.
func TestNormalizeRejectsTwoCertificatesWithTheSameIdentifierSet(t *testing.T) {
	certs := []Certificate{
		{Name: "a-com", Domains: []string{"a.example.com", "b.example.com"}},
		{Name: "b-com", Domains: []string{"b.example.com", "a.example.com"}},
	}
	err := NormalizeCertificates(certs)
	if err == nil {
		t.Fatal("two certificates with the same identifier set must be rejected")
	}
	if !strings.Contains(err.Error(), "same identifier set") {
		t.Errorf("the error should say why, got %v", err)
	}
}

// The snapshot interval has a floor. Snapshots are a recovery mechanism, not a change log,
// and a short interval just fills the disk with near-identical copies of a file holding
// private keys.
func TestStateBackupIntervalHasAFloor(t *testing.T) {
	path := writeConfig(t, minimalPrefix+`
stateBackup:
  interval: 5s
certificates:
  - name: example-com
    domains: ["example.com"]
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("a 5s snapshot interval must be rejected")
	}
	if !strings.Contains(err.Error(), "stateBackup.interval") {
		t.Errorf("the error should name the field, got %v", err)
	}
}

// Defaults must be usable without any stateBackup block at all: the whole point is that
// backups happen even when nobody configured them.
func TestStateBackupDefaults(t *testing.T) {
	path := writeConfig(t, minimalPrefix+`
certificates:
  - name: example-com
    domains: ["example.com"]
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.StateBackup.EnabledOr(true) {
		t.Error("snapshots should be on by default")
	}
	if cfg.StateBackup.IntervalDur != DefaultBackupInterval {
		t.Errorf("interval = %s, want %s", cfg.StateBackup.IntervalDur, DefaultBackupInterval)
	}
	if cfg.StateBackup.Keep != DefaultBackupKeep {
		t.Errorf("keep = %d, want %d", cfg.StateBackup.Keep, DefaultBackupKeep)
	}
}

// Retention bounds must reject values that mean nothing sensible.
func TestStateBackupKeepIsBounded(t *testing.T) {
	for _, keep := range []string{"-1", "500"} {
		path := writeConfig(t, minimalPrefix+`
stateBackup:
  keep: `+keep+`
certificates:
  - name: example-com
    domains: ["example.com"]
`)
		if _, err := Load(path); err == nil {
			t.Errorf("keep: %s must be rejected", keep)
		}
	}
}

const minimalWithDNS = `
statePath: /tmp/wecert-test.db
acme:
  directory: https://acme-staging-v02.api.letsencrypt.org/directory
  email: ops@example.com
tencent:
  credentialMode: static
  secretId: id
  secretKey: key
  regions: [ap-guangzhou]
certificates:
  - name: example-com
    domains: ["example.com"]
`

// dns.provider "lego" must be validated where the operator can act on it.
//
// The full lego provider registry is behind a build tag (see internal/acme/provider_notags.go),
// so a config that asks for it in a default binary has to be rejected at load time carrying the
// rebuild instruction -- not accepted and then failing when the solver is constructed, which is
// after the ACME account has already been touched.
func TestLegoProviderRequiresAName(t *testing.T) {
	path := writeConfig(t, minimalWithDNS+`
dns:
  provider: lego
`)
	if _, err := Load(path); err == nil {
		t.Error("dns.provider=lego without dns.legoProvider must be rejected")
	}
}

func TestLegoProviderInADefaultBuildSaysHowToEnableIt(t *testing.T) {
	path := writeConfig(t, minimalWithDNS+`
dns:
  provider: lego
  legoProvider: cloudflare
`)
	_, err := Load(path)
	if err == nil {
		t.Skip("this binary was built with -tags lego_dns, so the provider is available")
	}
	if !strings.Contains(err.Error(), "lego_dns") {
		t.Errorf("the error must name the build tag that enables it, got %q", err)
	}
}

// A provider name that is not one of wecert's own must not fall through to a default: silently
// issuing with dnspod credentials because someone wrote "cloudflare" is the kind of mistake that
// only surfaces when a challenge fails.
func TestUnknownProviderDoesNotFallThroughToADefault(t *testing.T) {
	path := writeConfig(t, minimalWithDNS+`
dns:
  provider: cloudflare
  loginToken: token
`)
	if _, err := Load(path); err == nil {
		t.Error("an unknown dns.provider must be rejected")
	}
}
