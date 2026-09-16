package acme

import (
	"context"
	"errors"
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

	timeout              time.Duration
	interval             time.Duration
	log                  *slog.Logger
	recursiveNameservers []string
	exchange             func(ctx context.Context, msg *dns.Msg, server string) (*dns.Msg, error)
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

	resolvers, err := recursiveNameservers(dnsCfg.RecursiveNameservers)
	if err != nil {
		return nil, err
	}
	if err := dns01.AddRecursiveNameservers(resolvers)(&dns01.Challenge{}); err != nil {
		return nil, fmt.Errorf("configure lego recursive nameservers: %w", err)
	}
	return &DNSSolver{newProvider: newProvider, timeout: dnsCfg.Propagation, interval: dnsCfg.Polling, log: log, recursiveNameservers: resolvers, exchange: exchangeDNS}, nil
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

		zone, err := s.findZone(ctx, r.FQDN)
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
func probeRecordsWithExchange(servers []string, recs []DNSRecord, exchange func(*dns.Msg, string) (*dns.Msg, error)) []recordProbe {
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

			ready, summary := probeReadyWithExchange(servers, r.FQDN, r.Value, exchange)
			// Each goroutine writes only its own index; no overlap, so no lock is needed.
			out[i] = recordProbe{record: r, ready: ready, summary: summary}
		}(i, r)
	}
	wg.Wait()

	return out
}

func probeRecords(servers []string, recs []DNSRecord) []recordProbe {
	return probeRecordsWithExchange(servers, recs, func(msg *dns.Msg, server string) (*dns.Msg, error) {
		client := &dns.Client{Timeout: 3 * time.Second}
		resp, _, err := client.Exchange(msg, server)
		return resp, err
	})
}

// waitZone polls the zone's authoritative NS until the records are confirmed propagated.
func (s *DNSSolver) waitZone(
	ctx context.Context, zone string, servers []string, recs []DNSRecord,
	start, deadline time.Time,
) error {
	for {
		results := s.probeRecords(servers, recs)

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
	server        string
	hasValue      bool
	authoritative bool
	err           error // non-nil means this NS is simply unreachable from here
}

// probeTXT probes every authoritative NS concurrently.
//
// Concurrency is necessary here: 9 servers in series with a 5-second timeout each makes
// a worst-case round of 45 seconds.
func probeTXTWithExchange(servers []string, fqdn, want string, exchange func(*dns.Msg, string) (*dns.Msg, error)) []nsProbe {
	results := make([]nsProbe, len(servers))

	var wg sync.WaitGroup
	for i, server := range servers {
		wg.Add(1)
		go func(i int, server string) {
			defer wg.Done()
			results[i] = nsProbe{server: server}

			m := new(dns.Msg)
			m.SetQuestion(fqdn, dns.TypeTXT)
			m.RecursionDesired = false

			resp, err := exchange(m, server)
			if err != nil {
				results[i].err = err
				return
			}
			results[i].authoritative = resp != nil && resp.Authoritative
			results[i].hasValue = results[i].authoritative && responseHasTXT(resp, want)
		}(i, server)
	}
	wg.Wait()

	return results
}

func probeTXT(servers []string, fqdn, want string) []nsProbe {
	return probeTXTWithExchange(servers, fqdn, want, func(msg *dns.Msg, server string) (*dns.Msg, error) {
		client := &dns.Client{Timeout: 3 * time.Second}
		resp, _, err := client.Exchange(msg, server)
		return resp, err
	})
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
func probeReadyWithExchange(servers []string, fqdn, want string, exchange func(*dns.Msg, string) (*dns.Msg, error)) (bool, string) {
	results := probeTXTWithExchange(servers, fqdn, want, exchange)

	var confirmed, missing, nonAuthoritative, unreachable int
	for _, r := range results {
		switch {
		case r.err != nil:
			unreachable++
		case !r.authoritative:
			nonAuthoritative++
		case r.hasValue:
			confirmed++
		default:
			missing++
		}
	}

	summary := fmt.Sprintf("confirmed %d / denied %d / non-authoritative %d / unreachable %d (of %d)", confirmed, missing, nonAuthoritative, unreachable, len(results))

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

func probeReady(servers []string, fqdn, want string) (bool, string) {
	return probeReadyWithExchange(servers, fqdn, want, func(msg *dns.Msg, server string) (*dns.Msg, error) {
		client := &dns.Client{Timeout: 3 * time.Second}
		resp, _, err := client.Exchange(msg, server)
		return resp, err
	})
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

func (s *DNSSolver) findZone(ctx context.Context, fqdn string) (string, error) {
	for _, domain := range domainSequence(fqdn) {
		msg := new(dns.Msg)
		msg.SetQuestion(domain, dns.TypeSOA)
		msg.RecursionDesired = true
		resp, err := s.queryRecursive(ctx, msg)
		if err != nil || resp == nil || resp.Rcode == dns.RcodeNameError {
			continue
		}
		if resp.Rcode != dns.RcodeSuccess {
			return "", fmt.Errorf("SOA lookup for %s returned %s", domain, dns.RcodeToString[resp.Rcode])
		}
		for _, rr := range resp.Answer {
			if soa, ok := rr.(*dns.SOA); ok {
				return dns.Fqdn(soa.Hdr.Name), nil
			}
		}
	}
	return "", fmt.Errorf("could not find an SOA for %s via recursive resolvers %s", fqdn, strings.Join(s.recursiveNameservers, ","))
}

// authoritativeNS resolves the public NS delegation through the configured recursive resolver set.
func (s *DNSSolver) authoritativeNS(ctx context.Context, zone string) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(zone, dns.TypeNS)
	msg.RecursionDesired = true
	resp, err := s.queryRecursive(ctx, msg)
	if err != nil {
		return nil, fmt.Errorf("lookup NS for %s: %w", zone, err)
	}
	var names []string
	for _, rr := range resp.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			names = append(names, dns.Fqdn(ns.Ns))
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("%s has no NS records", zone)
	}

	var servers []string
	seen := make(map[string]bool)
	for _, ns := range names {
		ips, err := s.lookupHost(ctx, ns)
		if err != nil {
			s.log.Warn("could not resolve an authoritative nameserver; skipping it", "ns", ns, "err", err)
			continue
		}
		for _, ip := range ips {
			server := net.JoinHostPort(ip, "53")
			if !seen[server] {
				seen[server] = true
				servers = append(servers, server)
			}
		}
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("none of %s's nameservers resolve to an address", zone)
	}
	return servers, nil
}

func (s *DNSSolver) probeRecords(servers []string, recs []DNSRecord) []recordProbe {
	return probeRecordsWithExchange(servers, recs, func(msg *dns.Msg, server string) (*dns.Msg, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return s.exchange(ctx, msg, server)
	})
}

func (s *DNSSolver) queryRecursive(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	var errs []error
	for _, resolver := range s.recursiveNameservers {
		resp, err := s.exchange(ctx, msg.Copy(), resolver)
		if err == nil && resp != nil && (resp.Rcode == dns.RcodeSuccess || resp.Rcode == dns.RcodeNameError) {
			return resp, nil
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", resolver, err))
		} else if resp == nil {
			errs = append(errs, fmt.Errorf("%s: empty response", resolver))
		} else {
			errs = append(errs, fmt.Errorf("%s: DNS response %s", resolver, dns.RcodeToString[resp.Rcode]))
		}
	}
	return nil, fmt.Errorf("all configured recursive resolvers failed: %w", errors.Join(errs...))
}

func (s *DNSSolver) lookupHost(ctx context.Context, host string) ([]string, error) {
	var ips []string
	var errs []error
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		msg := new(dns.Msg)
		msg.SetQuestion(host, qtype)
		msg.RecursionDesired = true
		resp, err := s.queryRecursive(ctx, msg)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, rr := range resp.Answer {
			switch r := rr.(type) {
			case *dns.A:
				ips = append(ips, r.A.String())
			case *dns.AAAA:
				ips = append(ips, r.AAAA.String())
			}
		}
	}
	if len(ips) == 0 {
		if len(errs) == 0 {
			return nil, errors.New("no A or AAAA records")
		}
		return nil, fmt.Errorf("no A or AAAA records: %w", errors.Join(errs...))
	}
	return ips, nil
}

func recursiveNameservers(configured []string) ([]string, error) {
	if len(configured) > 0 {
		return append([]string(nil), configured...), nil
	}
	resolv, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("read recursive nameservers from /etc/resolv.conf: %w", err)
	}
	if len(resolv.Servers) == 0 {
		return nil, errors.New("/etc/resolv.conf contains no nameservers")
	}
	servers := make([]string, 0, len(resolv.Servers))
	for _, server := range resolv.Servers {
		servers = append(servers, net.JoinHostPort(server, resolv.Port))
	}
	return servers, nil
}

func exchangeDNS(ctx context.Context, msg *dns.Msg, server string) (*dns.Msg, error) {
	client := &dns.Client{Timeout: 3 * time.Second}
	resp, _, err := client.ExchangeContext(ctx, msg, server)
	if err == nil && resp != nil && resp.Truncated {
		tcp := &dns.Client{Net: "tcp", Timeout: 3 * time.Second}
		resp, _, err = tcp.ExchangeContext(ctx, msg, server)
	}
	return resp, err
}

func domainSequence(fqdn string) []string {
	labels := dns.SplitDomainName(dns.Fqdn(fqdn))
	out := make([]string, 0, len(labels))
	for i := range labels {
		out = append(out, strings.Join(labels[i:], ".")+".")
	}
	return out
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
