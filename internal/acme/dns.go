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

	"github.com/atom/wecert/internal/config"
	"github.com/atom/wecert/internal/deploy"
)

// DNSSolver 在 lego 的 DNS provider 之上补了一步：
// "等该 zone 的所有权威 NS 都返回这条 TXT"。
//
// 为什么不能省：Let's Encrypt 会从多个 vantage point 校验，并要求全部一致。
// 只查本地递归解析器会被缓存骗过，结果本地以为好了、LE 那头验证失败。
// 而验证失败是按 identifier 计费限速的（5 次/小时），代价很实在。
//
// 这一步对 CNAME 委派同样成立：GetChallengeInfo 会跟随 CNAME 给出
// EffectiveFQDN，我们查的就是委派之后真正承载 TXT 的那个 zone。
type DNSSolver struct {
	newProvider func(ctx context.Context) (challenge.Provider, error)
	timeout     time.Duration
	interval    time.Duration
	log         *slog.Logger
}

func NewDNSSolver(dnsCfg config.DNS, tencentCfg config.Tencent, log *slog.Logger) (*DNSSolver, error) {
	var newProvider func(ctx context.Context) (challenge.Provider, error)

	switch dnsCfg.Provider {
	case config.DNSProviderDNSPod:
		p, err := dnspod.NewDNSProviderConfig(&dnspod.Config{
			LoginToken:         dnsCfg.LoginToken,
			TTL:                dnsCfg.TTL,
			PropagationTimeout: dnsCfg.Propagation,
			PollingInterval:    dnsCfg.Polling,
		})
		if err != nil {
			return nil, fmt.Errorf("初始化 dnspod provider: %w", err)
		}
		newProvider = func(context.Context) (challenge.Provider, error) { return p, nil }

	case config.DNSProviderTencentCloud:
		creds, err := deploy.NewCredentialSource(tencentCfg)
		if err != nil {
			return nil, err
		}
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
		return nil, fmt.Errorf("未知的 dns.provider %q", dnsCfg.Provider)
	}

	return &DNSSolver{
		newProvider: newProvider,
		timeout:     dnsCfg.Propagation,
		interval:    dnsCfg.Polling,
		log:         log,
	}, nil
}

type DNSRecord struct {
	FQDN  string
	Value string
}

func (s *DNSSolver) Present(ctx context.Context, domain, token, keyAuth string) (DNSRecord, error) {
	provider, err := s.newProvider(ctx)
	if err != nil {
		return DNSRecord{}, fmt.Errorf("获取 DNS provider: %w", err)
	}

	if err := provider.Present(domain, token, keyAuth); err != nil {
		return DNSRecord{}, fmt.Errorf("写入 TXT: %w", err)
	}

	info := dns01.GetChallengeInfo(domain, keyAuth)
	return DNSRecord{
		FQDN:  dns01.ToFqdn(info.EffectiveFQDN),
		Value: info.Value,
	}, nil
}

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
			return fmt.Errorf("定位 %s 所属 zone: %w", r.FQDN, err)
		}
		byZone[zone] = append(byZone[zone], r)
	}

	if len(byZone) == 0 {
		return nil
	}

	deadline := time.Now().Add(s.timeout)
	for zone, recs := range byZone {
		servers, err := s.authoritativeNS(ctx, zone)
		if err != nil {
			return err
		}
		if err := s.waitZone(ctx, zone, servers, recs, deadline); err != nil {
			return err
		}
	}
	return nil
}

func (s *DNSSolver) waitZone(
	ctx context.Context, zone string, servers []string, recs []DNSRecord, deadline time.Time,
) error {
	var lastSummary string

	for {
		ready := true
		for _, r := range recs {
			ok, summary := probeReady(servers, r.FQDN, r.Value)
			lastSummary = fmt.Sprintf("%s: %s", r.FQDN, summary)
			if !ok {
				ready = false
			}
		}

		if ready {
			s.log.Info("TXT 已传播开",
				"zone", zone, "nameservers", len(servers), "records", len(recs), "detail", lastSummary)
			return nil
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("TXT 在 %s 内未确认传播 (zone=%s, ns=%d, records=%d): %s",
				s.timeout, zone, len(servers), len(recs), lastSummary)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.interval):
		}
	}
}

type nsProbe struct {
	server   string
	hasValue bool
	err      error
}

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

// probeReady 判断记录是否已经可以认为传播开了。
//
// 判定标准：没有任一台可达 NS 否认该值，且至少有一台确认。
// 多台权威时还要求至少 2 台独立确认，避免"只连上一台"就放行。
// zone 只有 1 台权威 NS 时，一台确认即可。
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

	summary := fmt.Sprintf("确认 %d / 否认 %d / 不可达 %d (共 %d)",
		confirmed, missing, unreachable, len(results))

	if missing > 0 {
		return false, summary
	}
	if confirmed == 0 {
		return false, summary
	}
	if len(results) >= 2 && confirmed < 2 {
		return false, summary
	}
	return true, summary
}

func (s *DNSSolver) CleanUp(domain, token, keyAuth string) error {
	provider, err := s.newProvider(context.Background())
	if err != nil {
		return fmt.Errorf("获取 DNS provider: %w", err)
	}
	return provider.CleanUp(domain, token, keyAuth)
}

func (s *DNSSolver) authoritativeNS(ctx context.Context, zone string) ([]string, error) {
	names, err := net.DefaultResolver.LookupNS(ctx, dns01.UnFqdn(zone))
	if err != nil {
		return nil, fmt.Errorf("查询 %s 的 NS: %w", zone, err)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("%s 没有 NS 记录", zone)
	}

	var servers []string
	for _, ns := range names {
		ips, err := net.DefaultResolver.LookupHost(ctx, strings.TrimSuffix(ns.Host, "."))
		if err != nil {
			s.log.Warn("权威 NS 解析失败，跳过", "ns", ns.Host, "err", err)
			continue
		}
		for _, ip := range ips {
			servers = append(servers, net.JoinHostPort(ip, "53"))
		}
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("%s 的 NS 全部无法解析成地址", zone)
	}
	return servers, nil
}

func responseHasTXT(resp *dns.Msg, want string) bool {
	for _, rr := range resp.Answer {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		if strings.Join(txt.Txt, "") == want {
			return true
		}
	}
	return false
}
