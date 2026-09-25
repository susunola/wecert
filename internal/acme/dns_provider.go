package acme

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/dnspod"
	"github.com/go-acme/lego/v4/providers/dns/route53"
	"github.com/go-acme/lego/v4/providers/dns/tencentcloud"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
)

// Split out so one concern lives in one file. Same package.

func NewDNSSolver(dnsCfg config.DNS, tencentCfg config.Tencent, log *slog.Logger) (*DNSSolver, error) {
	var newProvider func(ctx context.Context) (challenge.Provider, error)

	switch dnsCfg.Provider {
	case config.DNSProviderDNSPod:
		// Hazard: lego wraps this provider's HTTP client in its debug dumper, which is
		// enabled by LEGO_DEBUG_DNS_API_HTTP_CLIENT. It redacts Authorization/Token/
		// Api-Key *headers*, but dnspod-go puts the credential in the POST *body* as
		// `login_token=...`, which no redaction rule matches -- so setting that variable
		// on the service writes a never-expiring DNSPod token (record write over every
		// zone in the account) into stdout, which under systemd means the journal.
		//
		// Keep it out of the unit and out of any drop-in; debug DNS locally instead.
		if os.Getenv("LEGO_DEBUG_DNS_API_HTTP_CLIENT") != "" {
			log.Warn("LEGO_DEBUG_DNS_API_HTTP_CLIENT is set: lego's debug dump of the dnspod " +
				"provider logs request BODIES, and the never-expiring login_token travels in the " +
				"POST body, which no redaction rule matches -- unset it anywhere but a local " +
				"debugging session")
		}
		p, err := dnspod.NewDNSProviderConfig(dnspodConfig(dnsCfg))
		if err != nil {
			return nil, fmt.Errorf("initialise the dnspod provider: %w", err)
		}
		// A DNSPod-native token never expires, so one reused instance is enough.
		newProvider = func(context.Context) (challenge.Provider, error) { return p, nil }

	case config.DNSProviderTencentCloud:
		creds, err := deploy.NewCredentialSource(tencentCfg)
		if err != nil {
			return nil, err
		}
		// Fetch and build on the spot every time, so the API is never called with credentials
		// that have expired since they were fetched -- the CVM instance role hands out temporary
		// ones.
		//
		// The cost is not quite negligible, and it is worth writing down because it is invisible
		// here: the SDK builds each client's HTTP client around a CLONE of http.DefaultTransport
		// (common.Client.Init, unless common.DefaultHttpClient is set, which this program does not
		// set), so every provider instance has its own connection pool. One Present or CleanUp is
		// therefore one fresh TLS handshake, plus one connection left idle for the SDK's 30s
		// IdleConnTimeout. That is the price of not reusing a client; sharing one is not free
		// either, because the SDK applies ReqTimeout by mutating the client it was given, so a
		// shared client would couple unrelated timeouts.
		newProvider = func(ctx context.Context) (challenge.Provider, error) {
			cred, err := creds(ctx)
			if err != nil {
				return nil, err
			}
			return tencentcloud.NewDNSProviderConfig(tencentDNSConfig(
				cred.GetSecretId(), cred.GetSecretKey(), cred.GetToken(), dnsCfg))
		}

	case config.DNSProviderCloudflare:
		// A scoped Cloudflare API token is revoked rather than refreshed, so -- like dnspod's --
		// one built instance is reused for as long as the token stays the same.
		//
		// No LEGO_DEBUG_DNS_API_HTTP_CLIENT warning here, unlike the dnspod case above: that
		// variable makes lego wrap the client in its request dumper, but in lego v4.35.2 the
		// dumper is only installed on the email + global-key path
		// (providers/dns/cloudflare/internal/client.go: NewClient returns at line 53 when a token
		// is set, and the clientdebug.Wrap call is at line 65). Re-check that when the lego
		// dependency is bumped: a token-authenticated client that started dumping requests would
		// put this token in the journal, which is the hazard the dnspod warning exists for.
		//
		// When the token lives in a file, the file is re-read on every use so a rotated or revoked
		// token takes effect without restarting the daemon -- but the instance is kept while its
		// content is unchanged. Rebuilding on every call is not the harmless extra API client it
		// looks like: lego's cloudflare provider deletes a record by the ID it remembered when it
		// created that record, keyed by the challenge token
		// (providers/dns/cloudflare/cloudflare.go: Present stores d.recordIDs[token], CleanUp
		// looks it up and answers "cloudflare: unknown record ID" when it is missing). A provider
		// built between Present and CleanUp has an empty map, so CleanUp fails and the TXT record
		// stays in the zone -- observed on every issuance in the staging runs, one stale
		// _acme-challenge TXT per certificate per renewal, and a stale value is what a later
		// validation can be answered from.
		static := cloudflareConfig(dnsCfg)
		if dnsCfg.Cloudflare.APITokenFile == "" {
			p, err := cloudflare.NewDNSProviderConfig(static)
			if err != nil {
				return nil, fmt.Errorf("initialise the cloudflare provider: %w", err)
			}
			newProvider = func(context.Context) (challenge.Provider, error) { return p, nil }
			break
		}
		tokenFile := dnsCfg.Cloudflare.APITokenFile
		var cache tokenFileProviderCache
		newProvider = func(context.Context) (challenge.Provider, error) {
			cfg := *static
			cfg.AuthToken = rereadSecretFile(tokenFile, cfg.AuthToken)
			return cache.get(cfg.AuthToken, func() (challenge.Provider, error) {
				return cloudflare.NewDNSProviderConfig(&cfg)
			})
		}

	case config.DNSProviderRoute53:
		// Built once as well, and the contrast with tencentcloud above is the point: what expires
		// here is not the provider but the credentials inside it, and those are re-fetched by the
		// AWS SDK's credential chain on the client it already holds (an instance role's temporary
		// credentials included). Rebuilding would buy nothing and would re-resolve the whole AWS
		// config on every Present and CleanUp.
		p, err := route53.NewDNSProviderConfig(route53Config(dnsCfg))
		if err != nil {
			return nil, fmt.Errorf("initialise the route53 provider: %w", err)
		}
		newProvider = func(context.Context) (challenge.Provider, error) { return p, nil }

	case config.DNSProviderLego:
		// Any provider from lego's registry, by name, with its credentials taken from the
		// environment in lego's own variable names. See the build-tag files for why this is
		// opt-in rather than always compiled in.
		newProvider = newLegoProvider(dnsCfg.LegoProvider)

	default:
		return nil, fmt.Errorf("unknown dns.provider %q", dnsCfg.Provider)
	}

	resolvers, err := recursiveNameservers(dnsCfg.RecursiveNameservers)
	if err != nil {
		return nil, err
	}
	providerResolvers, err := recursiveNameservers(nil)
	if err != nil {
		return nil, err
	}
	if err := applyLegoRecursiveNameservers(resolvers, log); err != nil {
		return nil, err
	}
	solver := &DNSSolver{newProvider: newProvider, providerResolvers: providerResolvers, timeout: dnsCfg.Propagation, interval: dnsCfg.Polling, log: log, recursiveNameservers: resolvers, exchange: exchangeDNS, valueScopedCleanup: cleanupIsValueScoped(dnsCfg.Provider)}
	if dnsCfg.Provider == config.DNSProviderCloudflare {
		solver.recoverCloudflareTXT = newCloudflareTXTRecovery(dnsCfg.Cloudflare.APIToken, dnsCfg.Cloudflare.APITokenFile)
	}
	return solver, nil
}

// legoResolvers guards the one piece of process-wide state NewDNSSolver cannot avoid writing:
// lego keeps the recursive resolver list its own lookups use in a package-level variable (see
// applyLegoRecursiveNameservers), so all solvers in a process necessarily share one list and
// the write has to be serialised here -- lego's assignment carries no synchronisation at all.
var legoResolvers struct {
	mu      sync.Mutex
	applied []string
}

// applyLegoRecursiveNameservers configures the resolver list lego's own DNS lookups use.
//
// Applying the option to a throwaway Challenge works by side effect, and only because of how
// lego implements it: in lego v4.35.2 (challenge/dns01/nameserver.go -- the package-level
// `recursiveNameservers` variable at line 27, the option at line 65) AddRecursiveNameservers
// ignores its *Challenge argument and assigns that package-level variable, which every later
// lego DNS lookup (FindZoneByFqdn inside a provider's Present, CNAME chasing) then uses.
// Re-check both spots when the lego dependency is bumped.
//
// The consequence is a global constraint: one process can have ONE such list, and every solver
// agrees on it or the process runs on mixed resolver views. A repeated construction with the
// same list is a no-op; a DIFFERENT list cannot be refused without breaking legitimate rebuilds
// (the CLI constructs a solver more than once), so it overwrites -- there is no per-instance
// override to offer -- and warns, because solvers built earlier change behaviour with it.
func applyLegoRecursiveNameservers(resolvers []string, log *slog.Logger) error {
	legoResolvers.mu.Lock()
	defer legoResolvers.mu.Unlock()

	if slices.Equal(legoResolvers.applied, resolvers) {
		return nil
	}
	if legoResolvers.applied != nil {
		log.Warn("lego's recursive nameservers are a process-wide global already set to a DIFFERENT "+
			"list; overwriting it, so solvers built earlier resolve through the new list too",
			"was", legoResolvers.applied, "now", resolvers)
	}
	if err := dns01.AddRecursiveNameservers(resolvers)(&dns01.Challenge{}); err != nil {
		return fmt.Errorf("configure lego recursive nameservers: %w", err)
	}
	legoResolvers.applied = append([]string(nil), resolvers...)
	return nil
}

// cleanupIsValueScoped reports whether the configured provider's CleanUp removes only the record
// matching the (token, keyAuth) it was called with, leaving every other value at the challenge name
// in place.
//
// The distinction decides whether CleanUp may defer to a "last leaver", and getting it wrong is
// silent. lego's dnspod and tencentcloud providers delete **every** TXT at the name
// (providers/dns/dnspod/dnspod.go, providers/dns/tencentcloud/tencentcloud.go), so the last
// leaver's single call collects the values the earlier callers skipped. Route 53's and Cloudflare's
// do not:
//
//   - route53 (providers/dns/route53/route53.go, CleanUp) reads the record set, keeps every value
//     that is not its own, upserts the remainder, and only deletes the whole set when nothing else
//     is left;
//   - cloudflare (providers/dns/cloudflare/cloudflare.go) keeps the record IDs it created in a map
//     keyed by the challenge token and deletes by ID.
//
// For those two a deferred value is never removed by anyone, so the cleanup would leave one stale
// _acme-challenge TXT behind per shared challenge name -- the wildcard + apex shape, or two
// certificates on one domain -- and a stale value is what a later validation can be answered from.
// Deferring buys nothing there either: each call removes only its own record.
//
// Everything reached through `dns.provider: lego` is treated as delete-all on purpose: the
// semantics of ~198 providers cannot be known here, and deferring is the conservative choice for
// the ones that remove everything at the name.
func cleanupIsValueScoped(provider string) bool {
	switch provider {
	case config.DNSProviderRoute53, config.DNSProviderCloudflare:
		return true
	default:
		return false
	}
}

// dnsAPITimeout bounds one call to the DNS provider's API.
//
// It has to be set explicitly, because a provider built from a struct literal does NOT get lego's
// NewDefaultConfig defaults: the tencentcloud provider would leave the SDK's ReqTimeout at 0, and
// the SDK then builds an http.Client with Timeout 0 -- no timeout at all. Present and CleanUp hold
// the per-name TXT lease mutex across that call (see challengeLeases), so one stalled connection
// would wedge every certificate sharing the challenge FQDN for as long as the TCP connection
// lives, with the pass never finishing and the TXT records left in DNS. Sixty seconds matches the
// other Tencent Cloud client in this program (internal/deploy).
func tencentDNSConfig(secretID, secretKey, sessionToken string, dnsCfg config.DNS) *tencentcloud.Config {
	return &tencentcloud.Config{
		SecretID:           secretID,
		SecretKey:          secretKey,
		SessionToken:       sessionToken,
		TTL:                dnsCfg.TTL,
		PropagationTimeout: dnsCfg.Propagation,
		PollingInterval:    dnsCfg.Polling,
		HTTPTimeout:        dnsAPITimeout,
	}
}

// dnspodConfig builds the DNSPod provider's config, with a bounded HTTP client for the same reason
// as tencentDNSConfig: a nil client falls back to http.DefaultClient, which has no timeout either.
func dnspodConfig(dnsCfg config.DNS) *dnspod.Config {
	return &dnspod.Config{
		LoginToken:         dnsCfg.LoginToken,
		TTL:                dnsCfg.TTL,
		PropagationTimeout: dnsCfg.Propagation,
		PollingInterval:    dnsCfg.Polling,
		HTTPClient:         &http.Client{Timeout: dnsAPITimeout},
	}
}

// cloudflareConfig builds the Cloudflare provider's config.
//
// Unlike the two above it starts from lego's NewDefaultConfig instead of a literal, because that is
// where the provider's own guard rails live (the 30s HTTP client, the BaseURL default). Everything
// this program owns is then written over the top; what is NOT taken from the environment is the
// credential -- dns.cloudflare.apiToken is resolved in internal/config, from the config, a file or
// the two variables lego documents, and putting it here is the only way it reaches the provider.
func cloudflareConfig(dnsCfg config.DNS) *cloudflare.Config {
	cfg := cloudflare.NewDefaultConfig()
	cfg.AuthToken = dnsCfg.Cloudflare.APIToken
	cfg.TTL = dnsCfg.TTL
	cfg.PropagationTimeout = dnsCfg.Propagation
	cfg.PollingInterval = dnsCfg.Polling
	// Same bound as the other providers (see dnsAPITimeout): the provider's HTTPClient is used for
	// both the zone lookup and the record write, and Present/CleanUp hold the per-name TXT lease
	// mutex across that call, so an unbounded request would wedge every certificate sharing the
	// challenge FQDN.
	cfg.HTTPClient = &http.Client{Timeout: dnsAPITimeout}
	return cfg
}

// route53Config builds the Route 53 provider's config.
//
// NewDefaultConfig is the starting point on purpose here, because the fields a literal would leave
// at their zero values are real behaviour rather than formatting: MaxRetries (5, since Route 53
// throttles at 5 requests/second per account) and the AWS_HOSTED_ZONE_ID fallback for a deployment
// that pinned its zone that way under the old `dns.provider: lego` path.
//
// The credential fields are copied verbatim, empty included: an empty AccessKeyID/SecretAccessKey
// pair is what tells lego to load the AWS default chain (environment, shared config, instance
// role), and filling either one from anywhere else here would replace that chain with a static
// provider built from half a pair.
//
// WaitForRecordSetsChanged is turned **off**, against lego's default of true, and the reason is a
// measured one. With it on, Present (and CleanUp, which shares changeRecord) waits for the change
// to reach INSYNC, polling every PollingInterval for up to PropagationTimeout -- five minutes,
// inside a call this program bounds at dnsAPITimeout (60s, see callProviderBounded). On this
// machine that wait plus the API call took 32.7s, 38.4s and 32.1s over three measured changes
// (ChangeResourceRecordSets itself 6.5-8.6s, INSYNC 23.5-31.9s later), leaving roughly twenty
// seconds of headroom on a bound that exists to keep a wedged call from holding the per-name lease
// forever. A staging round then failed exactly there: "present TXT timed out after 1m0s", one
// failed pass, a discarded order and a backoff, for a record Route 53 had already accepted.
//
// Nothing is lost by not waiting here: this solver never lets lego decide when a record is live.
// WaitAll probes the zone's authoritative nameservers itself, needs two independent servers to
// agree (recursive resolvers included), holds the full propagation budget, and prints the evidence
// -- for every provider, not just this one. The provider-side wait was a second, shorter, silently
// enforced version of that check. Without it, a write is confirmed as soon as Route 53 accepts the
// change (seconds), the per-name lease is released sooner, and the waiting happens where the
// budget and the diagnostics are.
func route53Config(dnsCfg config.DNS) *route53.Config {
	cfg := route53.NewDefaultConfig()
	cfg.Region = dnsCfg.Route53.Region
	// Only overridden when the config sets it, so lego's own AWS_HOSTED_ZONE_ID fallback survives.
	if dnsCfg.Route53.HostedZoneID != "" {
		cfg.HostedZoneID = dnsCfg.Route53.HostedZoneID
	}
	cfg.AccessKeyID = dnsCfg.Route53.AccessKeyID
	cfg.SecretAccessKey = dnsCfg.Route53.SecretAccessKey
	cfg.SessionToken = dnsCfg.Route53.SessionToken
	cfg.TTL = dnsCfg.TTL
	cfg.PropagationTimeout = dnsCfg.Propagation
	cfg.PollingInterval = dnsCfg.Polling
	cfg.WaitForRecordSetsChanged = false
	// No HTTP-timeout knob exists on this config in lego v4.35.2: the request goes through the AWS
	// SDK's own transport, bounded by its dial/TLS timeouts and the retryer above rather than by one
	// overall deadline. Re-check for such a field when the lego dependency is bumped.
	return cfg
}

// PropagationTimeout reports the budget WaitAll waits for a record to appear.
func (s *DNSSolver) PropagationTimeout() time.Duration { return s.timeout }

// DNSRecord is one _acme-challenge TXT record that is to be written or verified.

// rereadSecretFile re-reads a credential file, falling back to fallback when the read
// fails (so a transient I/O error does not tear down a working provider). The path is
// environment-expanded, matching config.resolveSecretFiles.
func rereadSecretFile(path, fallback string) string {
	raw, err := os.ReadFile(os.ExpandEnv(path))
	if err != nil {
		return fallback
	}
	if s := strings.TrimSpace(string(raw)); s != "" {
		return s
	}
	return fallback
}

// tokenFileProviderCache keeps a credential-file provider alive while the file still holds the
// same secret, and rebuilds it the moment that changes.
//
// The two halves are both load-bearing, which is why this is not simply "build once":
//
//   - Keeping the instance is what makes lego's token-keyed record bookkeeping work. See the
//     Cloudflare case in NewDNSSolver: a provider rebuilt between Present and CleanUp cannot
//     delete the record Present created, and the record stays in the operator's zone.
//   - Rebuilding on change is what makes a rotated token take effect without a restart. Caching
//     the first instance forever means every Present fails 401/403 until the daemon restarts, and
//     consecutive failures walk the identifier budget toward a CA pause.
//
// The zero value is ready to use. It is safe for concurrent use: Present and CleanUp for different
// certificates can run at the same time.
type tokenFileProviderCache struct {
	mu       sync.Mutex
	token    string
	provider challenge.Provider
}

// get returns the cached provider when it was built from this token, and otherwise builds one.
//
// build is called with the cache locked so two callers cannot race into two instances for the same
// token, and only the first of them can become the cached one whose record IDs CleanUp needs.
func (c *tokenFileProviderCache) get(token string, build func() (challenge.Provider, error)) (challenge.Provider, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.provider != nil && c.token == token {
		return c.provider, nil
	}
	p, err := build()
	if err != nil {
		return nil, err
	}
	c.provider, c.token = p, token
	return p, nil
}
