package acme

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/providers/dns/dnspod"
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
	// Applying the option to a throwaway Challenge works by side effect, and only because of how
	// lego implements it: in lego v4.35.2 (challenge/dns01/nameserver.go -- the package-level
	// `recursiveNameservers` variable at line 27, the option at line 65) AddRecursiveNameservers
	// ignores its *Challenge argument and assigns that package-level variable, which every later
	// lego DNS lookup then uses. Re-check both spots when the lego dependency is bumped.
	if err := dns01.AddRecursiveNameservers(resolvers)(&dns01.Challenge{}); err != nil {
		return nil, fmt.Errorf("configure lego recursive nameservers: %w", err)
	}
	return &DNSSolver{newProvider: newProvider, timeout: dnsCfg.Propagation, interval: dnsCfg.Polling, log: log, recursiveNameservers: resolvers, exchange: exchangeDNS}, nil
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

// PropagationTimeout reports the budget WaitAll waits for a record to appear.
func (s *DNSSolver) PropagationTimeout() time.Duration { return s.timeout }

// DNSRecord is one _acme-challenge TXT record that is to be written or verified.
