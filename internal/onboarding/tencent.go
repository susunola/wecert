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

// Page sizes. DNSPod's DescribeRecordList caps a page at 3000; 100 is used here:
// one fewer call is worth far less than the risk of a zone with so many records
// the API refuses. This runs every few minutes, so extra pages are cheap.
const (
	dnsPageSize = 100
	clbPageSize = 100

	// maxRecordsPerZone is a defensive cap. Hitting it means the zone is
	// abnormally large (or the API's paging semantics differ from our assumption);
	// paging on would just hammer the API forever, so stop with a clear error.
	maxRecordsPerZone = 50000
	maxLoadBalancers  = 5000
)

// TencentSources assembles the Tencent Cloud sources from configuration.
//
// Declaration enumeration uses CAM credentials against dnspod.tencentcloudapi.com,
// sharing the tencent credentials section with certificate deployment. Note this
// is distinct from the DNSPod-native API token used by dns.provider=dnspod: that
// token can only write DNS-01 challenges, it cannot read record lists.
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

// DNSPodDeclarations enumerates _wecert declarations from DNSPod TXT records.
type DNSPodDeclarations struct {
	credential deploy.CredentialFunc

	// zones limits which zones are enumerated. Empty means every zone in the account.
	zones []string

	log *slog.Logger
}

// NewDNSPodDeclarations constructs the declaration enumerator.
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
	// DNSPod is a global service in the Tencent Cloud API, so Region is empty.
	return dnssdk.NewClient(cred, "", cpf)
}

// ListDeclarations implements DeclarationLister.
//
// A failure to read any one zone fails the whole round. That is deliberate: a
// partially successful enumeration and "these declarations were deleted" look
// identical to the caller, yet the two call for opposite reactions. Better to
// freeze the whole round than read a permissions failure as a mass decommission.
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

// listTXTRecords reads a zone's TXT records and picks out the _wecert.* ones.
//
// Deliberately no Keyword filter: whether the server-side fuzzy search covers
// record names is not consistent across API versions, and missing one declaration
// shows up as "I declared it but nothing was issued", far more expensive than a
// few extra pages. Filtering by prefix locally is deterministic.
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

// joinRecordName joins the relative record name DNSPod returns into a full name.
//
// DNSPod's Name is the subdomain relative to the zone, and "@" means the zone itself.
func joinRecordName(name, zone string) string {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" || name == "@" {
		return zone
	}
	return name + "." + zone
}

// CLBRules enumerates the domains configured on all layer-7 rules.
//
// It is a **guard**: it only vetoes already-declared intent, it never infers
// intent. That distinction fixes its failure mode -- the worst case is "something
// that should have been issued was not", never "something that should not have
// been deleted got deleted".
type CLBRules struct {
	credential deploy.CredentialFunc
	regions    []string
	log        *slog.Logger
}

// NewCLBRules constructs the rule enumerator.
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

// ListRuleDomains implements RuleLister.
//
// As with declaration enumeration, failure to read any one region fails the whole
// round: a partial result would misread "the rule is still there" as "the rule is
// gone", and that walks into the deletion path.
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

// listLoadBalancers returns every layer-7 (HTTP/HTTPS) load balancer in the region.
func (r *CLBRules) listLoadBalancers(ctx context.Context, client *clbsdk.Client) ([]string, error) {
	var out []string
	var offset int64
	for {
		req := clbsdk.NewDescribeLoadBalancersRequest()
		// Forward=1 fetches application (layer-7) only. Layer-4 instances have no
		// rule domains, and pulling them in just adds calls that always fail.
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

// listRuleDomainsFor returns the domains configured on every listener rule of one
// load balancer.
//
// They live in the Listener.Rules returned by DescribeListeners, so no separate
// DescribeRules call is needed (this API version does not have it either).
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
