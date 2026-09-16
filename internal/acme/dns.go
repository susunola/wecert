package acme

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/providers/dns/dnspod"
	"github.com/go-acme/lego/v4/providers/dns/tencentcloud"
	"github.com/miekg/dns"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
)

// DNSSolver adds one step on top of lego's DNS providers: "wait until every
// authoritative NS for the zone returns this TXT".
//
// Why it cannot be skipped: Let's Encrypt validates from several vantage points and
// demands that all of them agree. Querying only the local recursive resolver is fooled
// by its cache, so locally everything looks ready while LE's validation fails. And a
// failed validation is rate limited per identifier (5 per hour) -- a very real cost.
//
// The step holds for CNAME delegation too: GetChallengeInfo follows the CNAME and
// reports the EffectiveFQDN, so what we query is the zone that really carries the TXT
// after delegation.
type DNSSolver struct {
	// newProvider fetches a fresh provider instance on every use. The tencentcloud path
	// goes through CAM temporary credentials that expire, so it must not be held long
	// term.
	newProvider func(ctx context.Context) (challenge.Provider, error)

	timeout  time.Duration
	interval time.Duration
	log      *slog.Logger
}

// NewDNSSolver picks an implementation from dns.provider.
//
// The two implementations use completely different credential systems:
//   - dnspod       uses a DNSPod-native API token (never expires, build once, reuse)
//   - tencentcloud uses Tencent Cloud CAM credentials, shared with certificate
//     deployment (supports temporary credentials from a CVM role)
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
		p, err := dnspod.NewDNSProviderConfig(&dnspod.Config{
			LoginToken:         dnsCfg.LoginToken,
			TTL:                dnsCfg.TTL,
			PropagationTimeout: dnsCfg.Propagation,
			PollingInterval:    dnsCfg.Polling,
		})
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
		// Fetch and build on the spot every time. Constructing a provider only creates
		// an SDK client, a negligible cost, and what we get for it is never calling the
		// API with expired credentials.
		newProvider = func(ctx context.Context) (challenge.Provider, error) {
			cred, err := creds(ctx)
			if err != nil {
				return nil, err
			}
			return tencentcloud.NewDNSProviderConfig(&tencentcloud.Config{
				SecretID:           cred.GetSecretId(),
				SecretKey:          cred.GetSecretKey(),
				SessionToken:       cred.GetToken(),
				TTL:                dnsCfg.TTL,
				PropagationTimeout: dnsCfg.Propagation,
				PollingInterval:    dnsCfg.Polling,
			})
		}

	default:
		return nil, fmt.Errorf("unknown dns.provider %q", dnsCfg.Provider)
	}

	return &DNSSolver{
		newProvider: newProvider,
		timeout:     dnsCfg.Propagation,
		interval:    dnsCfg.Polling,
		log:         log,
	}, nil
}

// DNSRecord is one _acme-challenge TXT record that is to be written or verified.
type DNSRecord struct {
	FQDN  string
	Value string
}

// Present writes the TXT into DNS but **does not wait for propagation**.
//
// Splitting "write" from "wait" is deliberate, for two reasons:
//
//  1. Correctness: a wildcard + its apex write to the same _acme-challenge name, so
//     both records must exist at the same time. "Write, wait, then write the second"
//     works too, but hoisting every write up front is harder to get wrong.
//  2. Performance: waiting for propagation is the slowest step in the whole chain --
//     DNSPod's free tier has a 600s TTL floor and 9 authoritative NS, so one
//     propagation round takes over 2 minutes. Waiting per record makes records on the
//     same name wait twice for nothing.
func (s *DNSSolver) Present(ctx context.Context, domain, token, keyAuth string) (DNSRecord, error) {
	provider, err := s.newProvider(ctx)
	if err != nil {
		return DNSRecord{}, fmt.Errorf("get the DNS provider: %w", err)
	}

	if err := provider.Present(domain, token, keyAuth); err != nil {
		return DNSRecord{}, fmt.Errorf("present TXT: %w", err)
	}

	info := dns01.GetChallengeInfo(domain, keyAuth)
	return DNSRecord{
		FQDN:  dns01.ToFqdn(info.EffectiveFQDN),
		Value: info.Value,
	}, nil
}

// WaitAll waits until every record is visible on all authoritative NS of its zone.
//
// It deduplicates by (FQDN, Value), and resolves each zone's authoritative NS list once.
func (s *DNSSolver) WaitAll(ctx context.Context, records []DNSRecord) error {
	byZone := map[string][]DNSRecord{}
	seen := map[string]bool{}

	for _, r := range records {
		key := r.FQDN + "|" + r.Value
		if seen[key] {
			continue
		}
		seen[key] = true

		zone, err := dns01.FindZoneByFqdn(r.FQDN)
		if err != nil {
			return fmt.Errorf("find the zone for %s: %w", r.FQDN, err)
		}
		byZone[zone] = append(byZone[zone], r)
	}

	if len(byZone) == 0 {
		return nil
	}

	// The budget is global: every zone shares one deadline, so the overall wait does not
	// inflate linearly as zones are added. The error below carries the real elapsed
	// time, so that a zone handled later cannot report "not confirmed within 5m" when it
	// actually waited a few seconds.
	start := time.Now()
	deadline := start.Add(s.timeout)

	for zone, recs := range byZone {
		servers, err := s.authoritativeNS(ctx, zone)
		if err != nil {
			return err
		}
		if err := s.waitZone(ctx, zone, servers, recs, start, deadline); err != nil {
			return err
		}
	}
	return nil
}

// maxProbeConcurrency caps how many record probes are in flight at once.
//
// Each record then probes all the authoritative NS of its zone concurrently, so real
// concurrency is this number x the NS count. Set it too high and we fire off thousands
// of DNS queries in an instant, which is exactly how you get rate limited or dropped.
const maxProbeConcurrency = 8

// recordProbe is the probe result for one record.
type recordProbe struct {
	record  DNSRecord
	ready   bool
	summary string
}

// probeRecords probes several records concurrently; results keep the input order.
//
// Concurrency is mandatory: one round for a single record asks every authoritative NS
// in its zone (9 for DNSPod), so handling 100 domains serially is 100 polling rounds at
// up to 3 seconds each -- one round then runs far past the 5-second polling interval.
// Propagation waiting would degrade into "advance a little every 5 seconds", and a
// 5-minute budget would not survive even a few rounds.
func probeRecords(servers []string, recs []DNSRecord) []recordProbe {
	out := make([]recordProbe, len(recs))
	if len(recs) == 0 {
		return out
	}

	limit := maxProbeConcurrency
	if len(recs) < limit {
		limit = len(recs)
	}

	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup

	for i, r := range recs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, r DNSRecord) {
			defer wg.Done()
			defer func() { <-sem }()

			ready, summary := probeReady(servers, r.FQDN, r.Value)
			// Each goroutine writes only its own index; no overlap, so no lock is needed.
			out[i] = recordProbe{record: r, ready: ready, summary: summary}
		}(i, r)
	}
	wg.Wait()

	return out
}

// waitZone polls the zone's authoritative NS until the records are confirmed propagated.
func (s *DNSSolver) waitZone(
	ctx context.Context, zone string, servers []string, recs []DNSRecord,
	start, deadline time.Time,
) error {
	for {
		results := probeRecords(servers, recs)

		// Summarise only the records that are **not ready yet**.
		//
		// This used to unconditionally reuse the last record's summary, so with the two
		// same-name TXT records of wildcard + apex, as soon as the second one was ready
		// the timeout error printed "confirmed 9 / denied 0 / unreachable 0" -- a summary
		// that looks perfectly healthy, and is the most baffling kind of log there is.
		var pending []string
		for _, res := range results {
			if res.ready {
				continue
			}
			pending = append(pending,
				fmt.Sprintf("%s = %s (%s)", res.record.FQDN, res.record.Value, res.summary))
		}

		if len(pending) == 0 {
			s.log.Info("TXT propagated",
				"zone", zone, "nameservers", len(servers), "records", len(recs))
			return nil
		}

		if !time.Now().Before(deadline) {
			return fmt.Errorf(
				"TXT propagation not confirmed: waited %s (budget %s), zone=%s, ns=%d, "+
					"%d/%d records still not ready: %s",
				time.Since(start).Round(time.Second), s.timeout,
				zone, len(servers), len(pending), len(recs),
				strings.Join(pending, " | "))
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.interval):
		}
	}
}

// nsProbe is the probe result for one authoritative NS.
type nsProbe struct {
	server   string
	hasValue bool
	err      error // non-nil means this NS is simply unreachable from here
}

// probeTXT probes every authoritative NS concurrently.
//
// Concurrency is necessary here: 9 servers in series with a 5-second timeout each makes
// a worst-case round of 45 seconds.
func probeTXT(servers []string, fqdn, want string) []nsProbe {
	results := make([]nsProbe, len(servers))

	var wg sync.WaitGroup
	for i, server := range servers {
		wg.Add(1)
		go func(i int, server string) {
			defer wg.Done()
			results[i] = nsProbe{server: server}

			c := &dns.Client{Timeout: 3 * time.Second}
			m := new(dns.Msg)
			m.SetQuestion(fqdn, dns.TypeTXT)
			m.RecursionDesired = false

			resp, _, err := c.Exchange(m, server)
			if err != nil {
				results[i].err = err
				return
			}
			results[i].hasValue = responseHasTXT(resp, want)
		}(i, server)
	}
	wg.Wait()

	return results
}

// probeReady decides whether a record can count as propagated, and returns a
// plain-language summary.
//
// The rule: **no reachable NS denies the value**, and at least one confirms it. When the
// zone has multiple authorities, at least 2 must confirm independently, so "only one
// server was reachable" cannot slip through.
//
// Not requiring all 9 to be reachable is deliberate: any single NS being unreachable
// from here would make "everything agrees" permanently unsatisfiable -- and that has
// nothing to do with whether the record propagated. LE validates from several of its own
// locations, so an NS we cannot reach may be reachable for LE.
//
// Conversely, if even one reachable NS plainly says "no such value", we must never let it
// through -- that really is propagation incomplete, and letting it through burns a
// failed-validation quota slot (5 per hour) for nothing.
//
// A single-authority zone has to be able to pass: requiring 2 confirmations would leave
// such a zone waiting for propagation forever.
func probeReady(servers []string, fqdn, want string) (bool, string) {
	results := probeTXT(servers, fqdn, want)

	var confirmed, missing, unreachable int
	for _, r := range results {
		switch {
		case r.err != nil:
			unreachable++
		case r.hasValue:
			confirmed++
		default:
			missing++
		}
	}

	summary := fmt.Sprintf("confirmed %d / denied %d / unreachable %d (of %d)",
		confirmed, missing, unreachable, len(results))

	// Any reachable NS denies it -> not propagated yet.
	if missing > 0 {
		return false, summary
	}
	// Not a single confirmation (everything unreachable) -> must not let it through.
	if confirmed == 0 {
		return false, summary
	}
	// With multiple authorities require at least 2 independent confirmations, so
	// "only one server was reachable" cannot slip through.
	// A zone with a single authority is exempt from this rule.
	if len(results) >= 2 && confirmed < 2 {
		return false, summary
	}
	return true, summary
}

// CleanUp deletes the TXT record this call wrote.
//
// The provider locates the record by the exact (domain, token, keyAuth) triple, so when
// a wildcard and its apex share one _acme-challenge name, deleting one of them does not
// take out the other.
func (s *DNSSolver) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	provider, err := s.newProvider(ctx)
	if err != nil {
		return fmt.Errorf("get the DNS provider: %w", err)
	}
	return provider.CleanUp(domain, token, keyAuth)
}

// authoritativeNS resolves the zone's authoritative NS and turns them into "ip:53".
func (s *DNSSolver) authoritativeNS(ctx context.Context, zone string) ([]string, error) {
	names, err := net.DefaultResolver.LookupNS(ctx, dns01.UnFqdn(zone))
	if err != nil {
		return nil, fmt.Errorf("lookup NS for %s: %w", zone, err)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("%s has no NS records", zone)
	}

	var servers []string
	for _, ns := range names {
		ips, err := net.DefaultResolver.LookupHost(ctx, strings.TrimSuffix(ns.Host, "."))
		if err != nil {
			s.log.Warn("could not resolve an authoritative nameserver; skipping it", "ns", ns.Host, "err", err)
			continue
		}
		for _, ip := range ips {
			servers = append(servers, net.JoinHostPort(ip, "53"))
		}
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("none of %s's nameservers resolve to an address", zone)
	}
	return servers, nil
}

func responseHasTXT(resp *dns.Msg, want string) bool {
	for _, rr := range resp.Answer {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		// A TXT record can be split into several string segments; join them, then compare.
		if strings.Join(txt.Txt, "") == want {
			return true
		}
	}
	return false
}
