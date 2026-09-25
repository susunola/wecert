package onboarding

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"

	clbsdk "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/clb/v20180317"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	dnssdk "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/dnspod/v20210323"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/tcerr"
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
	maxZones          = 10000
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
	// A zone listed twice would be enumerated twice: every record in it read and parsed a
	// second time, per round. Normalising first means the compact catches spellings of the
	// same zone too ("Example.COM.").
	sort.Strings(clean)
	clean = slices.Compact(clean)
	return &DNSPodDeclarations{credential: src, zones: clean, log: log}, nil
}

// dnspodAPI is the narrower slice of the DNSPod client this package uses.
//
// The SDK returns concrete structs with no interface seam, which left the whole enumeration --
// paging, filtering, and the "an empty zone list is not an empty declaration set" check --
// untestable without network access. Declaring only the used methods lets tests substitute a
// fake while production keeps the real client.
type dnspodAPI interface {
	DescribeDomainListWithContext(ctx context.Context, req *dnssdk.DescribeDomainListRequest) (*dnssdk.DescribeDomainListResponse, error)
	DescribeRecordListWithContext(ctx context.Context, req *dnssdk.DescribeRecordListRequest) (*dnssdk.DescribeRecordListResponse, error)
}

// newDNSPodClient builds the DNSPod client. A package variable so tests can substitute a fake;
// production code never reassigns it.
var newDNSPodClient = func(cred common.CredentialIface) (dnspodAPI, error) {
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "dnspod.tencentcloudapi.com"
	cpf.HttpProfile.ReqTimeout = 30
	// DNSPod is a global service in the Tencent Cloud API, so Region is empty.
	return dnssdk.NewClient(cred, "", cpf)
}

func (d *DNSPodDeclarations) client(ctx context.Context) (dnspodAPI, error) {
	cred, err := d.credential(ctx)
	if err != nil {
		return nil, err
	}
	return newDNSPodClient(cred)
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

func (d *DNSPodDeclarations) listZones(ctx context.Context, client dnspodAPI) ([]string, error) {
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
		// The typed Response is a pointer the SDK leaves nil when the body carries no
		// result, so this must be checked before it is dereferenced. Without it a
		// well-formed HTTP 200 with `{"Response":null}` -- or an API/version mismatch --
		// panics the whole onboarding command, and no desired state is written that round.
		if resp == nil || resp.Response == nil {
			return nil, fmt.Errorf("list DNS zones: the API returned no result")
		}
		list := resp.Response.DomainList
		for _, z := range list {
			if z == nil {
				continue
			}
			if z.Name != nil && *z.Name != "" {
				zones = append(zones, strings.ToLower(*z.Name))
			}
		}
		if len(list) < dnsPageSize {
			break
		}
		offset += int64(len(list))
		if offset > maxZones {
			return nil, fmt.Errorf("more than %d DNS zones; refusing to keep paging", maxZones)
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
func (d *DNSPodDeclarations) listTXTRecords(ctx context.Context, client dnspodAPI, zone string) ([]RawDeclaration, error) {
	byName := map[string]*RawDeclaration{}

	var offset uint64
	for {
		req := dnssdk.NewDescribeRecordListRequest()
		req.Domain = common.StringPtr(zone)
		req.RecordType = common.StringPtr("TXT")
		req.Offset = common.Uint64Ptr(offset)
		req.Limit = common.Uint64Ptr(dnsPageSize)
		// The server default is to FAIL a query that matches nothing
		// (ResourceNotFound.NoDataOfRecord), not to return an empty list. Leaving it at the
		// default makes one TXT-less zone -- or one page request past the end, which this loop
		// makes whenever a zone's TXT count is an exact multiple of the page size -- fail the
		// whole declaration read, and a failed declaration source freezes the round: the desired
		// state document and the state file are then not written for ANY certificate until a
		// human edits DNS. Ask for an empty list instead, and keep the code below tolerant of
		// older API behaviour that reports the error anyway.
		req.ErrorOnEmpty = common.StringPtr("no")

		resp, err := client.DescribeRecordListWithContext(ctx, req)
		if err != nil {
			if tcerr.IsNoDataOfRecord(err) {
				break
			}
			return nil, fmt.Errorf("list TXT records: %w", err)
		}
		if resp == nil || resp.Response == nil {
			return nil, fmt.Errorf("list TXT records: the API returned no result")
		}

		list := resp.Response.RecordList
		for _, rec := range list {
			if rec == nil || rec.Type == nil || !strings.EqualFold(*rec.Type, "TXT") || rec.Name == nil {
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

// joinRecordName joins the record name DNSPod returns into a full name.
//
// DNSPod's Name is normally the subdomain relative to the zone, and "@" means the zone itself --
// but the API does NOT enforce that: a SubDomain written as a full host ("_wecert.x.example.com")
// is accepted and returned verbatim (verified against the live API in the round-11 verification
// pass, which is why this is no longer a plain concatenation). Appending the zone to a name that
// already carries it produced "x.example.com.example.com", and ParseDeclaration accepted that as a
// hostname: the desired state then contained a name that does not exist under the zone, whose order
// can only fail validation -- spending one authorization-failure credit per attempt on it.
func joinRecordName(name, zone string) string {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" || name == "@" {
		return zone
	}
	// Already absolute for this zone: return it as it is rather than doubling the zone.
	//
	// The comparison runs on the trimmed, lower-cased copies so a case or dot difference in the
	// returned name still de-duplicates, while the ZONE itself is still passed through untouched
	// (the property the tests below pin: normalising it here would hide a caller that stopped
	// passing a normalised zone).
	trimmedZone := strings.TrimSuffix(strings.TrimSpace(zone), ".")
	if lower := strings.ToLower(trimmedZone); lower != "" &&
		(name == lower || strings.HasSuffix(name, "."+lower)) {
		return name
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
//
// An empty region list is refused here rather than left for ListRuleDomains to trip over:
// the guard's caller treats a read error as weather (the round keeps every name, and with
// RequireRule on it also stops vetting new ones), so "no regions configured" surfacing only
// at enumeration time looked exactly like a transient outage -- while RequireRule silently
// vetted nothing. A misconfigured guard must fail loud at construction, where the mistake
// is made.
func NewCLBRules(cfg config.Tencent, regions []string, log *slog.Logger) (*CLBRules, error) {
	src, err := deploy.NewCredentialSource(cfg)
	if err != nil {
		return nil, err
	}
	clean := make([]string, 0, len(regions))
	for _, r := range regions {
		if r = strings.TrimSpace(r); r != "" {
			clean = append(clean, r)
		}
	}
	// A region listed twice would be enumerated twice: every load balancer and listener in it
	// read a second time, per round. Sorting first is what lets the compact catch duplicates
	// that are not adjacent.
	sort.Strings(clean)
	clean = slices.Compact(clean)
	if len(clean) == 0 {
		return nil, fmt.Errorf("no region is configured (tencent.regions); CLB is regional, " +
			"so an empty list would silently guard nothing")
	}
	if log == nil {
		log = slog.Default()
	}
	return &CLBRules{credential: src, regions: clean, log: log}, nil
}

// errIncompleteRuleList marks a guard reading that came back short of what the API itself said
// existed.
//
// It is deliberately distinct from "the guard could not be read at all". Both make the round treat
// the guard as unavailable (no deletions), but this one means the API answered and the answer was
// TRUNCATED -- a partial success, which is the shape of failure that used to be invisible: the
// guard silently sees fewer rules, concludes a name is unserved, and walks into the deletion path.
// Nothing in the API contract promises a short list; a default page limit or a proxy cutting a
// response would produce exactly this.
var errIncompleteRuleList = errors.New("the CLB rule list is incomplete")

// ListRuleDomains implements RuleLister.
//
// As with declaration enumeration, failure to read any one region fails the whole
// round: a partial result would misread "the rule is still there" as "the rule is
// gone", and that walks into the deletion path. The count each response carries is
// checked against what it returned, so "partial" cannot arrive looking complete.
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

		client, err := newCLBClient(cred, region, cpf)
		if err != nil {
			return nil, fmt.Errorf("region %s: build CLB client: %w", region, err)
		}

		lbs, err := r.listLoadBalancers(ctx, client, region)
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

// clbAPI is the narrower slice of the CLB client this package uses. See dnspodAPI.
type clbAPI interface {
	DescribeLoadBalancersWithContext(ctx context.Context, req *clbsdk.DescribeLoadBalancersRequest) (*clbsdk.DescribeLoadBalancersResponse, error)
	DescribeListenersWithContext(ctx context.Context, req *clbsdk.DescribeListenersRequest) (*clbsdk.DescribeListenersResponse, error)
}

// newCLBClient builds a regional CLB client. A package variable so tests can substitute a fake.
var newCLBClient = func(cred common.CredentialIface, region string, cpf *profile.ClientProfile) (clbAPI, error) {
	return clbsdk.NewClient(cred, region, cpf)
}

// listLoadBalancers returns every load balancer in the region, of either instance
// generation.
func (r *CLBRules) listLoadBalancers(ctx context.Context, client clbAPI, region string) ([]string, error) {
	var out []string
	var offset, read, reported int64
	for {
		req := clbsdk.NewDescribeLoadBalancersRequest()
		// Forward is deliberately NOT set. Despite the name it is not "layer 7 only": the
		// SDK documents it as the instance GENERATION -- 1 is a general instance, 0 is a
		// classic one, and omitting it returns both. The code here used to send 1 with a
		// comment claiming it meant "application (layer-7) only".
		//
		// That mattered because of what the result feeds: listLoadBalancers supplies the
		// ids whose listener rules become the CLB guard, and guard 1 REJECTS a declaration
		// when no rule serves its name ("guard 1 not satisfied"). A name fronted by a
		// classic instance would therefore be invisible, judged unreferenced, and dropped
		// from the desired state -- the dangerous direction, and silent.
		//
		// Asking for both costs one extra DescribeListeners per classic instance, and that
		// call is already tolerated: a layer-4 instance simply has no rules, so it
		// contributes nothing rather than failing.
		req.Offset = common.Int64Ptr(offset)
		req.Limit = common.Int64Ptr(clbPageSize)

		resp, err := client.DescribeLoadBalancersWithContext(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("describe load balancers: %w", err)
		}
		if resp == nil || resp.Response == nil {
			return nil, fmt.Errorf("describe load balancers: the API returned no result")
		}
		list := resp.Response.LoadBalancerSet
		read += int64(len(list))
		if resp.Response.TotalCount != nil {
			reported = int64(*resp.Response.TotalCount)
		}
		for _, lb := range list {
			if lb == nil || lb.LoadBalancerId == nil || *lb.LoadBalancerId == "" {
				// One unusable entry is enough to make the whole guard answer incomplete: the
				// listeners of the load balancer we could not name are never enumerated, so its
				// rules are missing from the list the guard checks declarations against.
				return nil, fmt.Errorf("%w: region %s returned a load balancer without an id",
					errIncompleteRuleList, region)
			}
			out = append(out, *lb.LoadBalancerId)
		}
		if len(list) < clbPageSize {
			break
		}
		offset += int64(len(list))
		if offset > maxLoadBalancers {
			return nil, fmt.Errorf("more than %d load balancers; refusing to keep paging", offset)
		}
	}

	// The count is compared AFTER the loop, against everything the pages returned.
	//
	// It used to be compared inside the loop, against the bytes read so far -- which is wrong by
	// construction: TotalCount ("the total number of load balancers matching the filter; this
	// value is independent of Limit") is larger than the first page for ANY region with more
	// instances than one page, so paging was dead code and the guard reported itself incomplete
	// for every account with more than clbPageSize load balancers in a region -- disabling guard
	// 1 entirely (no rule check, no removals) and printing a false "the rule list is truncated"
	// every round.
	if reported > read {
		return nil, fmt.Errorf("%w: region %s reported %d load balancers and the pages returned %d",
			errIncompleteRuleList, region, reported, read)
	}
	sort.Strings(out)
	return out, nil
}

// listRuleDomainsFor returns the domains configured on every listener rule of one
// load balancer.
//
// They live in the Listener.Rules returned by DescribeListeners, so no separate
// DescribeRules call is needed (this API version does not have it either).
func (r *CLBRules) listRuleDomainsFor(ctx context.Context, client clbAPI, lbID string) ([]string, error) {
	req := clbsdk.NewDescribeListenersRequest()
	req.LoadBalancerId = common.StringPtr(lbID)

	resp, err := client.DescribeListenersWithContext(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("describe listeners: %w", err)
	}
	if resp == nil || resp.Response == nil {
		return nil, fmt.Errorf("describe listeners: the API returned no result")
	}

	// The listeners of one load balancer are not paged (this request has no offset or limit), so
	// the count it reports is the count it must have returned. A short answer means rules are
	// missing from the guard's view, which is the one thing that must never pass unnoticed here.
	if resp.Response.TotalCount != nil && int64(*resp.Response.TotalCount) != int64(len(resp.Response.Listeners)) {
		return nil, fmt.Errorf("%w: load balancer %s reported %d listeners and returned %d",
			errIncompleteRuleList, lbID, *resp.Response.TotalCount, len(resp.Response.Listeners))
	}

	var out []string
	for _, l := range resp.Response.Listeners {
		if l == nil {
			continue
		}
		for _, rule := range l.Rules {
			if rule == nil || rule.Domain == nil {
				continue
			}
			if d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(*rule.Domain), ".")); d != "" {
				out = append(out, d)
			}
		}
	}
	return out, nil
}
