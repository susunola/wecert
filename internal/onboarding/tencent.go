package onboarding

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	clbsdk "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/clb/v20180317"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	dnssdk "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/dnspod/v20210323"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
)

// 分页大小。DNSPod 的 DescribeRecordList 单页上限是 3000，这里取 100：
// 少一次调用换来的收益，远小于"某个 zone 记录多到 API 拒了"的风险，
// 而这是一个几分钟跑一次的定时任务，多几页并不贵。
const (
	dnsPageSize = 100
	clbPageSize = 100

	// maxRecordsPerZone 是防御性上限。真触到它说明 zone 大到不正常
	// （或者 API 的分页语义和我们假设的不一样），此时继续翻页只会
	// 无限打 API，不如带着清晰的报错停下来。
	maxRecordsPerZone = 50000
	maxLoadBalancers  = 5000
)

// TencentSources 按配置装配腾讯云来源。
//
// 声明枚举走 CAM 凭证调 dnspod.tencentcloudapi.com，与证书部署共用
// tencent 那一节凭证。注意这跟 dns.provider=dnspod 用的 DNSPod 自有
// API Token 是两套东西：那个 token 只能写 DNS-01 挑战，读不了记录列表。
func TencentSources(cfg config.Tencent, zones []string, log *slog.Logger) (Sources, error) {
	decl, err := NewDNSPodDeclarations(cfg, zones, log)
	if err != nil {
		return Sources{}, err
	}
	rules, err := NewCLBRules(cfg, cfg.Regions, log)
	if err != nil {
		return Sources{}, err
	}
	return Sources{Declarations: decl, Rules: rules}, nil
}

// DNSPodDeclarations 从 DNSPod 的 TXT 记录里枚举 _wecert 声明。
type DNSPodDeclarations struct {
	credential deploy.CredentialFunc

	// zones 限定要枚举的 zone。留空表示枚举账号下所有 zone。
	zones []string

	log *slog.Logger
}

// NewDNSPodDeclarations 构造声明枚举器。
func NewDNSPodDeclarations(cfg config.Tencent, zones []string, log *slog.Logger) (*DNSPodDeclarations, error) {
	src, err := deploy.NewCredentialSource(cfg)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	clean := make([]string, 0, len(zones))
	for _, z := range zones {
		if z = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(z), ".")); z != "" {
			clean = append(clean, z)
		}
	}
	sort.Strings(clean)
	return &DNSPodDeclarations{credential: src, zones: clean, log: log}, nil
}

func (d *DNSPodDeclarations) client(ctx context.Context) (*dnssdk.Client, error) {
	cred, err := d.credential(ctx)
	if err != nil {
		return nil, err
	}
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "dnspod.tencentcloudapi.com"
	cpf.HttpProfile.ReqTimeout = 30
	// DNSPod 在腾讯云 API 里是全局服务，Region 传空。
	return dnssdk.NewClient(cred, "", cpf)
}

// ListDeclarations 实现 DeclarationLister。
//
// 任何一个 zone 读失败都会让整轮失败。这是刻意的：部分成功的枚举
// 和"这些声明被删了"在调用方眼里长得一模一样，而两者需要的反应完全相反。
// 宁可整轮冻结，也不要把一次权限故障读成一次批量下线。
func (d *DNSPodDeclarations) ListDeclarations(ctx context.Context) ([]RawDeclaration, error) {
	client, err := d.client(ctx)
	if err != nil {
		return nil, err
	}

	zones, err := d.listZones(ctx, client)
	if err != nil {
		return nil, err
	}
	if len(zones) == 0 {
		return nil, fmt.Errorf("no DNS zone is visible to these credentials: " +
			"either the account has no domain, or the credential lost access to them " +
			"(a permissions change looks exactly like 'every declaration was deleted', so this is never treated as an empty declaration set)")
	}

	var out []RawDeclaration
	for _, zone := range zones {
		recs, err := d.listTXTRecords(ctx, client, zone)
		if err != nil {
			return nil, fmt.Errorf("zone %s: %w", zone, err)
		}
		out = append(out, recs...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Record < out[j].Record })
	return out, nil
}

func (d *DNSPodDeclarations) listZones(ctx context.Context, client *dnssdk.Client) ([]string, error) {
	if len(d.zones) > 0 {
		return d.zones, nil
	}

	var zones []string
	var offset int64
	for {
		req := dnssdk.NewDescribeDomainListRequest()
		req.Offset = common.Int64Ptr(offset)
		req.Limit = common.Int64Ptr(dnsPageSize)

		resp, err := client.DescribeDomainListWithContext(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("list DNS zones: %w", err)
		}
		list := resp.Response.DomainList
		for _, z := range list {
			if z.Name != nil && *z.Name != "" {
				zones = append(zones, strings.ToLower(*z.Name))
			}
		}
		if len(list) < dnsPageSize {
			break
		}
		offset += int64(len(list))
		if offset > 10000 {
			return nil, fmt.Errorf("more than %d DNS zones; refusing to keep paging", offset)
		}
	}
	sort.Strings(zones)
	return zones, nil
}

// listTXTRecords 读一个 zone 里的 TXT 记录，挑出 _wecert.* 那些。
//
// 不加 Keyword 过滤是有意的：服务端的模糊搜索是否覆盖记录名，
// 不同 API 版本行为不完全一致，而漏掉一条声明的表现是
// "我声明了但没签"，比多翻几页贵得多。本地按前缀过滤，逻辑确定。
func (d *DNSPodDeclarations) listTXTRecords(ctx context.Context, client *dnssdk.Client, zone string) ([]RawDeclaration, error) {
	byName := map[string]*RawDeclaration{}

	var offset uint64
	for {
		req := dnssdk.NewDescribeRecordListRequest()
		req.Domain = common.StringPtr(zone)
		req.RecordType = common.StringPtr("TXT")
		req.Offset = common.Uint64Ptr(offset)
		req.Limit = common.Uint64Ptr(dnsPageSize)

		resp, err := client.DescribeRecordListWithContext(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("list TXT records: %w", err)
		}

		list := resp.Response.RecordList
		for _, rec := range list {
			if rec.Type == nil || !strings.EqualFold(*rec.Type, "TXT") || rec.Name == nil {
				continue
			}
			full := joinRecordName(*rec.Name, zone)
			if !strings.HasPrefix(full, DeclarationPrefix) {
				continue
			}

			rd := byName[full]
			if rd == nil {
				rd = &RawDeclaration{Zone: zone, Record: full}
				byName[full] = rd
			}
			if rec.Value != nil {
				rd.Values = append(rd.Values, *rec.Value)
			}
		}

		if len(list) < dnsPageSize {
			break
		}
		offset += uint64(len(list))
		if offset > maxRecordsPerZone {
			return nil, fmt.Errorf("more than %d TXT records in this zone; refusing to keep paging", maxRecordsPerZone)
		}
	}

	out := make([]RawDeclaration, 0, len(byName))
	for _, rd := range byName {
		out = append(out, *rd)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Record < out[j].Record })
	return out, nil
}

// joinRecordName 把 DNSPod 返回的相对记录名拼成完整名字。
//
// DNSPod 的 Name 是相对于 zone 的子域，"@" 表示 zone 本身。
func joinRecordName(name, zone string) string {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" || name == "@" {
		return zone
	}
	return name + "." + zone
}

// CLBRules 枚举所有七层规则上配置的域名。
//
// 它是**守卫**：只负责否掉已经声明的意图，不负责推断意图。
// 这个区别决定了它的失败模式 —— 最坏情况是"该签的没签"，
// 而不是"不该删的删了"。
type CLBRules struct {
	credential deploy.CredentialFunc
	regions    []string
	log        *slog.Logger
}

// NewCLBRules 构造规则枚举器。
func NewCLBRules(cfg config.Tencent, regions []string, log *slog.Logger) (*CLBRules, error) {
	src, err := deploy.NewCredentialSource(cfg)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	return &CLBRules{credential: src, regions: regions, log: log}, nil
}

// ListRuleDomains 实现 RuleLister。
//
// 和声明枚举一样，任何一个 region 读失败都让整轮失败：
// 部分结果会让"规则还在"被误判成"规则没了"，而那会走进删除路径。
func (r *CLBRules) ListRuleDomains(ctx context.Context) ([]string, error) {
	if len(r.regions) == 0 {
		return nil, fmt.Errorf("no region is configured (tencent.regions); CLB is regional, so an empty list would silently guard nothing")
	}

	cred, err := r.credential(ctx)
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	for _, region := range r.regions {
		cpf := profile.NewClientProfile()
		cpf.HttpProfile.Endpoint = "clb.tencentcloudapi.com"
		cpf.HttpProfile.ReqTimeout = 30

		client, err := clbsdk.NewClient(cred, region, cpf)
		if err != nil {
			return nil, fmt.Errorf("region %s: build CLB client: %w", region, err)
		}

		lbs, err := r.listLoadBalancers(ctx, client)
		if err != nil {
			return nil, fmt.Errorf("region %s: %w", region, err)
		}
		for _, lb := range lbs {
			domains, err := r.listRuleDomainsFor(ctx, client, lb)
			if err != nil {
				return nil, fmt.Errorf("region %s load balancer %s: %w", region, lb, err)
			}
			for _, d := range domains {
				seen[d] = true
			}
		}
	}

	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out, nil
}

// listLoadBalancers 返回该 region 下所有七层（HTTP/HTTPS）负载均衡实例。
func (r *CLBRules) listLoadBalancers(ctx context.Context, client *clbsdk.Client) ([]string, error) {
	var out []string
	var offset int64
	for {
		req := clbsdk.NewDescribeLoadBalancersRequest()
		// Forward=1 只取应用型（七层）。四层实例没有规则域名，
		// 把它们拉进来只会多出一堆必然失败的调用。
		req.Forward = common.Int64Ptr(1)
		req.Offset = common.Int64Ptr(offset)
		req.Limit = common.Int64Ptr(clbPageSize)

		resp, err := client.DescribeLoadBalancersWithContext(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("describe load balancers: %w", err)
		}
		list := resp.Response.LoadBalancerSet
		for _, lb := range list {
			if lb.LoadBalancerId != nil && *lb.LoadBalancerId != "" {
				out = append(out, *lb.LoadBalancerId)
			}
		}
		if len(list) < clbPageSize {
			break
		}
		offset += int64(len(list))
		if offset > maxLoadBalancers {
			return nil, fmt.Errorf("more than %d load balancers; refusing to keep paging", offset)
		}
	}
	sort.Strings(out)
	return out, nil
}

// listRuleDomainsFor 返回某个负载均衡上所有监听器规则配置的域名。
//
// 规则域名就在 DescribeListeners 返回的 Listener.Rules 里，
// 不需要再单独调一次 DescribeRules（这个 API 版本也没有它）。
func (r *CLBRules) listRuleDomainsFor(ctx context.Context, client *clbsdk.Client, lbID string) ([]string, error) {
	req := clbsdk.NewDescribeListenersRequest()
	req.LoadBalancerId = common.StringPtr(lbID)

	resp, err := client.DescribeListenersWithContext(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("describe listeners: %w", err)
	}

	var out []string
	for _, l := range resp.Response.Listeners {
		for _, rule := range l.Rules {
			if rule.Domain == nil {
				continue
			}
			if d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(*rule.Domain), ".")); d != "" {
				out = append(out, d)
			}
		}
	}
	return out, nil
}
