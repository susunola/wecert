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
	// newProvider 每次使用时取一个新的 provider 实例。
	// tencentcloud 走 CAM 临时凭证，会过期，所以不能长期持有。
	newProvider func(ctx context.Context) (challenge.Provider, error)

	timeout  time.Duration
	interval time.Duration
	log      *slog.Logger
}

// NewDNSSolver 按 dns.provider 选择实现。
//
// 两种实现的凭证体系完全不同：
//   - dnspod       用 DNSPod 自有 API Token（不过期，构造一次复用）
//   - tencentcloud 用腾讯云 CAM 凭证，与证书部署共用（支持 CVM 角色临时凭证）
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
		// DNSPod 自有 Token 不会过期，复用一个实例即可。
		newProvider = func(context.Context) (challenge.Provider, error) { return p, nil }

	case config.DNSProviderTencentCloud:
		creds, err := deploy.NewCredentialSource(tencentCfg)
		if err != nil {
			return nil, err
		}
		// 每次现取现建。provider 构造只是创建一个 SDK client，代价可忽略，
		// 换来的是永远不会拿着过期凭证去调 API。
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

// DNSRecord 是一条待写入 / 待验证的 _acme-challenge TXT 记录。
type DNSRecord struct {
	FQDN  string
	Value string
}

// Present 把 TXT 写进 DNS，但**不等待传播**。
//
// 把"写入"和"等待"分开是有意的，两个原因：
//
//  1. 正确性：wildcard + apex 会写到同一个 _acme-challenge 名字上，
//     两条记录必须同时存在。逐条"写完就等、等完再写第二条"虽然也能用，
//     但把写入全部前置更不容易出错。
//  2. 性能：等待传播是整条链路最慢的一步 —— DNSPod 免费套餐 TTL 下限 600、
//     有 9 个权威 NS，一轮传播要 2 分钟以上。逐条等待会让同名记录白等两遍。
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

// WaitAll 等到所有记录在所属 zone 的全部权威 NS 都可见。
//
// 同 (FQDN, Value) 去重；同一个 zone 只解析一次权威 NS 列表。
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

// waitZone 轮询 zone 的权威 NS，直到确认记录已经传播开。
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

// nsProbe 是单台权威 NS 的探测结果。
type nsProbe struct {
	server   string
	hasValue bool
	err      error // 非 nil 表示这台 NS 从我们这里根本连不上
}

// probeTXT 并发探测所有权威 NS。
//
// 并发是必要的：9 台串行、每台 5 秒超时，一轮最坏要 45 秒。
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

// probeReady 判断记录是否已经可以认为传播开了，并给出一句人话摘要。
//
// 判定标准：**没有任何一台可达的 NS 否认该值**，且至少有 2 台确认。
//
// 不要求 9 台全部可达是有意的：任何一台从我们这里网络不通，
// 都会让"全部一致"这个条件永远无法满足 —— 而这跟记录有没有传播开
// 根本是两件事。LE 是从它自己的多个位置去校验的，
// 我们这里连不上的 NS 对 LE 可能是通的。
//
// 反过来，只要有一台可达的 NS 明确说"没有这个值"，就绝不能放行 ——
// 那才是真正的传播未完成，放行会白白消耗一次验证失败配额（5 次/小时）。
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

	// 有任一可达 NS 否认 → 还没传播开。
	if missing > 0 {
		return false, summary
	}
	// 至少要有 2 台独立权威确认，避免"只连上一台"就放行。
	if confirmed < 2 {
		return false, summary
	}
	return true, summary
}

// CleanUp 删除本次写入的那条 TXT。
//
// provider 是按 (domain, token, keyAuth) 精确定位记录的，所以
// wildcard 和 apex 共用一个 _acme-challenge 名字时，删掉其中一条
// 不会误伤另一条。
func (s *DNSSolver) CleanUp(domain, token, keyAuth string) error {
	provider, err := s.newProvider(context.Background())
	if err != nil {
		return fmt.Errorf("获取 DNS provider: %w", err)
	}
	return provider.CleanUp(domain, token, keyAuth)
}

// authoritativeNS 解析 zone 的权威 NS，并把它们解析成 "ip:53"。
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
		// TXT 记录可能被切成多个字符串片段，拼接后再比较。
		if strings.Join(txt.Txt, "") == want {
			return true
		}
	}
	return false
}
