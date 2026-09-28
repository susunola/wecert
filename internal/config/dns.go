package config

import (
	"time"
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
