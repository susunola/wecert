package onboarding

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	clbsdk "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/clb/v20180317"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tcerrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	dnssdk "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/dnspod/v20210323"

	"github.com/susunola/wecert/internal/config"
)

// These cover the enumeration that the guards depend on. It was entirely untested because the
// SDK clients are concrete types; the constructors are package variables now, the same shape
// internal/deploy uses for its SSL client.

// ── fakes ────────────────────────────────────────────────────────────────────────────

type fakeDNSPod struct {
	domains []*dnssdk.DomainListItem
	records map[string][]*dnssdk.RecordListItem // zone -> records

	domainCalls int
	recordCalls int

	domainErr error
	recordErr error

	// nilResponse makes both calls answer a well-formed HTTP 200 whose body carries no
	// result object. The SDK leaves the typed Response pointer nil in that case (its own
	// error check only fires when Error.Code is set, and ErrorResponse.Response is an
	// inline struct), so this is what a version mismatch or a proxy looks like.
	nilResponse bool

	// realEmptyError makes DescribeRecordListWithContext behave like the API: a query that
	// matches no record is an ERROR (ResourceNotFound.NoDataOfRecord) unless the caller asked for
	// an empty list with ErrorOnEmpty=no. Without this the fake is friendlier than production and
	// the request field can be dropped without any test noticing.
	realEmptyError bool
}

func (f *fakeDNSPod) DescribeDomainListWithContext(_ context.Context, req *dnssdk.DescribeDomainListRequest) (*dnssdk.DescribeDomainListResponse, error) {
	f.domainCalls++
	if f.domainErr != nil {
		return nil, f.domainErr
	}
	if f.nilResponse {
		return &dnssdk.DescribeDomainListResponse{}, nil
	}
	offset, limit := int64(0), int64(dnsPageSize)
	if req.Offset != nil {
		offset = *req.Offset
	}
	if req.Limit != nil {
		limit = *req.Limit
	}
	end := offset + limit
	if end > int64(len(f.domains)) {
		end = int64(len(f.domains))
	}
	if offset > int64(len(f.domains)) {
		offset = int64(len(f.domains))
	}
	return &dnssdk.DescribeDomainListResponse{
		Response: &dnssdk.DescribeDomainListResponseParams{DomainList: f.domains[offset:end]},
	}, nil
}

func (f *fakeDNSPod) DescribeRecordListWithContext(_ context.Context, req *dnssdk.DescribeRecordListRequest) (*dnssdk.DescribeRecordListResponse, error) {
	f.recordCalls++
	if f.recordErr != nil {
		return nil, f.recordErr
	}
	if f.nilResponse {
		return &dnssdk.DescribeRecordListResponse{}, nil
	}
	zone := ""
	if req.Domain != nil {
		zone = *req.Domain
	}
	all := f.records[zone]
	offset, limit := uint64(0), uint64(dnsPageSize)
	if req.Offset != nil {
		offset = *req.Offset
	}
	if req.Limit != nil {
		limit = *req.Limit
	}
	emptyMatch := len(all) == 0 || offset >= uint64(len(all))
	wantsEmpty := req.ErrorOnEmpty != nil && *req.ErrorOnEmpty == "no"
	if f.realEmptyError && emptyMatch && !wantsEmpty {
		return nil, &tcerrors.TencentCloudSDKError{
			Code:    "ResourceNotFound.NoDataOfRecord",
			Message: "No records on the list.",
		}
	}
	end := offset + limit
	if end > uint64(len(all)) {
		end = uint64(len(all))
	}
	if offset > uint64(len(all)) {
		offset = uint64(len(all))
	}
	return &dnssdk.DescribeRecordListResponse{
		Response: &dnssdk.DescribeRecordListResponseParams{RecordList: all[offset:end]},
	}, nil
}

func txtRecord(name, value string) *dnssdk.RecordListItem {
	return &dnssdk.RecordListItem{
		Name: common.StringPtr(name), Type: common.StringPtr("TXT"), Value: common.StringPtr(value),
	}
}

func stubDNSPod(t *testing.T, fake *fakeDNSPod) {
	t.Helper()
	orig := newDNSPodClient
	newDNSPodClient = func(common.CredentialIface) (dnspodAPI, error) { return fake, nil }
	t.Cleanup(func() { newDNSPodClient = orig })
}

func newDeclarations(t *testing.T, zones []string) *DNSPodDeclarations {
	t.Helper()
	d, err := NewDNSPodDeclarations(config.Tencent{
		CredentialMode: config.CredentialStatic, SecretID: "id", SecretKey: "key",
	}, zones, testLogger())
	if err != nil {
		t.Fatalf("NewDNSPodDeclarations: %v", err)
	}
	return d
}

// ── declaration enumeration ──────────────────────────────────────────────────────────

// Only the _wecert. records are declarations. A TXT record that merely shares the zone is not
// one, and pulling it in would invent a certificate for whatever it happens to contain.
func TestListDeclarationsKeepsOnlyTheWecertPrefix(t *testing.T) {
	fake := &fakeDNSPod{
		domains: []*dnssdk.DomainListItem{{Name: common.StringPtr("example.com")}},
		records: map[string][]*dnssdk.RecordListItem{
			"example.com": {
				txtRecord("_wecert.www", "v=1"),
				txtRecord("@", "v=spf1 -all"),
				txtRecord("_dmarc", "v=DMARC1"),
				txtRecord("_wecert", "wildcard=1"),
			},
		},
	}
	stubDNSPod(t, fake)

	got, err := newDeclarations(t, nil).ListDeclarations(context.Background())
	if err != nil {
		t.Fatalf("ListDeclarations: %v", err)
	}
	var names []string
	for _, d := range got {
		names = append(names, d.Record)
	}
	want := []string{"_wecert.example.com", "_wecert.www.example.com"}
	if len(names) != len(want) {
		t.Fatalf("declarations = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("declarations = %v, want %v", names, want)
		}
	}
}

// A record name is relative to its zone, and "@" means the zone itself.
func TestJoinRecordNameHandlesApexAndSubdomains(t *testing.T) {
	cases := map[string]string{
		"@":            "example.com",
		"":             "example.com",
		"_wecert":      "_wecert.example.com",
		"_wecert.www":  "_wecert.www.example.com",
		"_wecert.www.": "_wecert.www.example.com",
		"_WECERT.WWW":  "_wecert.www.example.com",
	}
	for in, want := range cases {
		if got := joinRecordName(in, "example.com"); got != want {
			t.Errorf("joinRecordName(%q) = %q, want %q", in, got, want)
		}
	}
}

// A name that carries no value must still appear as a declaration: the record's presence is
// the intent, and dropping it would silently skip a certificate.
func TestListDeclarationsKeepsRecordsWithoutValues(t *testing.T) {
	fake := &fakeDNSPod{
		domains: []*dnssdk.DomainListItem{{Name: common.StringPtr("example.com")}},
		records: map[string][]*dnssdk.RecordListItem{
			"example.com": {{Name: common.StringPtr("_wecert.www"), Type: common.StringPtr("TXT")}},
		},
	}
	stubDNSPod(t, fake)

	got, err := newDeclarations(t, nil).ListDeclarations(context.Background())
	if err != nil {
		t.Fatalf("ListDeclarations: %v", err)
	}
	if len(got) != 1 || got[0].Record != "_wecert.www.example.com" {
		t.Fatalf("declarations = %+v, want the value-less record", got)
	}
	if len(got[0].Values) != 0 {
		t.Errorf("a record with no Value must produce no values, got %v", got[0].Values)
	}
}

// Several TXT records at one name are one declaration carrying several values: the parser
// rejects conflicting keys, so they must arrive together rather than as separate declarations.
func TestListDeclarationsGroupsValuesAtOneName(t *testing.T) {
	fake := &fakeDNSPod{
		domains: []*dnssdk.DomainListItem{{Name: common.StringPtr("example.com")}},
		records: map[string][]*dnssdk.RecordListItem{
			"example.com": {
				txtRecord("_wecert.www", "profile=tlsserver"),
				txtRecord("_wecert.www", ""),
			},
		},
	}
	stubDNSPod(t, fake)

	got, err := newDeclarations(t, nil).ListDeclarations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d declarations, want them grouped into one: %+v", len(got), got)
	}
	if len(got[0].Values) != 2 {
		t.Errorf("values = %v, want both records' values", got[0].Values)
	}
}

// Enumeration must page through every zone and record. Stopping early silently drops
// declarations, which reads as "the operator removed them".
func TestListDeclarationsPagesThroughEverything(t *testing.T) {
	domains := make([]*dnssdk.DomainListItem, 0, dnsPageSize+1)
	records := map[string][]*dnssdk.RecordListItem{}
	for i := 0; i <= dnsPageSize; i++ {
		zone := "z" + strings.Repeat("0", 3-len(itoa(i))) + itoa(i) + ".example.com"
		domains = append(domains, &dnssdk.DomainListItem{Name: common.StringPtr(zone)})
		// Each zone gets one extra record beyond a page.
		rs := make([]*dnssdk.RecordListItem, 0, dnsPageSize+1)
		for j := 0; j <= dnsPageSize; j++ {
			rs = append(rs, txtRecord("_wecert.n"+itoa(j), "v=1"))
		}
		records[zone] = rs
	}
	fake := &fakeDNSPod{domains: domains, records: records}
	stubDNSPod(t, fake)

	got, err := newDeclarations(t, nil).ListDeclarations(context.Background())
	if err != nil {
		t.Fatalf("ListDeclarations: %v", err)
	}
	// Every zone's first page plus the one extra record on the second page.
	want := (dnsPageSize + 1) * (dnsPageSize + 1)
	if len(got) != want {
		t.Errorf("enumerated %d declarations, want %d: paging stopped early", len(got), want)
	}
	if fake.domainCalls < 2 {
		t.Errorf("the zone list was fetched %d time(s), so the second page was never read", fake.domainCalls)
	}
}

// Records that are not TXT must be ignored: a CNAME or A record named _wecert.something carries
// no declaration, and parsing its value would fail the whole round.
func TestListDeclarationsIgnoresNonTXTRecords(t *testing.T) {
	fake := &fakeDNSPod{
		domains: []*dnssdk.DomainListItem{{Name: common.StringPtr("example.com")}},
		records: map[string][]*dnssdk.RecordListItem{
			"example.com": {{
				Name: common.StringPtr("_wecert.www"), Type: common.StringPtr("CNAME"),
				Value: common.StringPtr("target.example.net"),
			}},
		},
	}
	stubDNSPod(t, fake)

	got, err := newDeclarations(t, nil).ListDeclarations(context.Background())
	if err != nil {
		t.Fatalf("a non-TXT record must be skipped, not fail the round: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("declarations = %+v, want none", got)
	}
}

// No visible zone is an error, never an empty declaration set. A permission change looks
// exactly like "every declaration was deleted", and acting on that strips every name.
func TestListDeclarationsFailsWhenNoZoneIsVisible(t *testing.T) {
	stubDNSPod(t, &fakeDNSPod{})

	_, err := newDeclarations(t, nil).ListDeclarations(context.Background())
	if err == nil {
		t.Fatal("no visible zone must be an error, not an empty declaration set")
	}
	if !strings.Contains(err.Error(), "no DNS zone is visible") {
		t.Errorf("the error must explain the ambiguity, got: %v", err)
	}
}

// An explicit zone list must be used verbatim rather than enumerating the account, so an
// operator can restrict the round.
func TestListDeclarationsUsesConfiguredZones(t *testing.T) {
	fake := &fakeDNSPod{
		domains: []*dnssdk.DomainListItem{{Name: common.StringPtr("other.com")}},
		records: map[string][]*dnssdk.RecordListItem{
			"example.com": {txtRecord("_wecert.www", "v=1")},
		},
	}
	stubDNSPod(t, fake)

	d := newDeclarations(t, []string{"Example.COM."})
	got, err := d.ListDeclarations(context.Background())
	if err != nil {
		t.Fatalf("ListDeclarations: %v", err)
	}
	if fake.domainCalls != 0 {
		t.Errorf("the account's zone list was fetched %d time(s) despite a configured list", fake.domainCalls)
	}
	if len(got) != 1 || got[0].Zone != "example.com" {
		t.Errorf("declarations = %+v, want one from example.com", got)
	}
}

// A failure reading one zone must fail the whole round: a partial result is indistinguishable
// from "these declarations were deleted", and those two call for opposite reactions.
func TestListDeclarationsFailsWhenOneZoneCannotBeRead(t *testing.T) {
	fake := &fakeDNSPod{
		domains:   []*dnssdk.DomainListItem{{Name: common.StringPtr("example.com")}},
		recordErr: errors.New("permission denied"),
	}
	stubDNSPod(t, fake)

	if _, err := newDeclarations(t, nil).ListDeclarations(context.Background()); err == nil {
		t.Fatal("a zone that cannot be read must fail the round rather than yield a partial set")
	}
}

// A network failure from the metadata/credential source must surface, not be read as "no
// declarations".
func TestListDeclarationsSurfacesACredentialFailure(t *testing.T) {
	d := &DNSPodDeclarations{
		credential: func(context.Context) (common.CredentialIface, error) {
			return nil, errors.New("the role is not attached")
		},
		log: testLogger(),
	}
	if _, err := d.ListDeclarations(context.Background()); err == nil {
		t.Fatal("a credential failure must surface")
	}
}

// ── CLB rule enumeration ─────────────────────────────────────────────────────────────

type fakeCLB struct {
	lbs map[string][]*clbsdk.LoadBalancer // region -> load balancers
	// rules maps load balancer id -> rule domains.
	rules map[string][]string

	lbErr   error
	ruleErr error

	// nilResponse mirrors fakeDNSPod.nilResponse for the CLB calls.
	nilResponse bool

	// forward records the generation filter the last DescribeLoadBalancers call sent, so a
	// test can assert that none is sent.
	forward *int64

	// lbTotal and listenerTotal override the count each response reports, so a test can model a
	// TRUNCATED answer: the API says more objects exist than it returned.
	lbTotal       *uint64
	listenerTotal *uint64

	// paging makes DescribeLoadBalancers answer one page at a time, as the API does. Without it
	// the fake returns every load balancer at once and the page loop is never entered.
	paging bool
}

func (f *fakeCLB) DescribeLoadBalancersWithContext(_ context.Context, req *clbsdk.DescribeLoadBalancersRequest) (*clbsdk.DescribeLoadBalancersResponse, error) {
	f.forward = req.Forward
	if f.lbErr != nil {
		return nil, f.lbErr
	}
	if f.nilResponse {
		return &clbsdk.DescribeLoadBalancersResponse{}, nil
	}
	var all []*clbsdk.LoadBalancer
	for _, v := range f.lbs {
		all = append(all, v...)
	}
	// TotalCount is the number of instances matching the filter -- documented as independent of
	// Limit -- so it is computed BEFORE the page is cut. Computing it from the page made the fake
	// report "one page is everything", which is exactly the shape that hides a paging bug.
	total := uint64(len(all))
	if f.lbTotal != nil {
		total = *f.lbTotal
	}
	out := all
	// Honour Offset/Limit the way the API does. Returning everything in one page (what this fake
	// used to do) hides the paging bugs entirely: the completeness check and the page loop can
	// only be exercised by an answer that really is a page.
	if f.paging {
		limit := int64(100)
		if req.Limit != nil && *req.Limit > 0 {
			limit = *req.Limit
		}
		offset := int64(0)
		if req.Offset != nil && *req.Offset > 0 {
			offset = *req.Offset
		}
		if offset > int64(len(all)) {
			offset = int64(len(all))
		}
		end := offset + limit
		if end > int64(len(all)) {
			end = int64(len(all))
		}
		out = all[offset:end]
	}
	return &clbsdk.DescribeLoadBalancersResponse{
		Response: &clbsdk.DescribeLoadBalancersResponseParams{
			TotalCount: common.Uint64Ptr(total), LoadBalancerSet: out,
		},
	}, nil
}

func (f *fakeCLB) DescribeListenersWithContext(_ context.Context, req *clbsdk.DescribeListenersRequest) (*clbsdk.DescribeListenersResponse, error) {
	if f.ruleErr != nil {
		return nil, f.ruleErr
	}
	if f.nilResponse {
		return &clbsdk.DescribeListenersResponse{}, nil
	}
	id := ""
	if req.LoadBalancerId != nil {
		id = *req.LoadBalancerId
	}
	// Rule domains live on the listener's layer-7 rules, not on the listener itself.
	var rules []*clbsdk.RuleOutput
	for i, d := range f.rules[id] {
		rules = append(rules, &clbsdk.RuleOutput{
			LocationId: common.StringPtr("loc-" + itoa(i)), Domain: common.StringPtr(d),
		})
	}
	listeners := []*clbsdk.Listener{{ListenerId: common.StringPtr("lbl-0"), Rules: rules}}
	total := uint64(len(listeners))
	if f.listenerTotal != nil {
		total = *f.listenerTotal
	}
	return &clbsdk.DescribeListenersResponse{
		Response: &clbsdk.DescribeListenersResponseParams{
			TotalCount: common.Uint64Ptr(total), Listeners: listeners,
		},
	}, nil
}

func stubCLB(t *testing.T, fake *fakeCLB) {
	t.Helper()
	orig := newCLBClient
	newCLBClient = func(common.CredentialIface, string, *profile.ClientProfile) (clbAPI, error) { return fake, nil }
	t.Cleanup(func() { newCLBClient = orig })
}

func newRules(t *testing.T, regions []string) *CLBRules {
	t.Helper()
	r, err := NewCLBRules(config.Tencent{
		CredentialMode: config.CredentialStatic, SecretID: "id", SecretKey: "key",
	}, regions, testLogger())
	if err != nil {
		t.Fatalf("NewCLBRules: %v", err)
	}
	return r
}

// Rule domains, including wildcards, are what guard 1 checks declarations against. Missing a
// wildcard rule makes onboarding reject names it should issue.
func TestListRuleDomainsCollectsListenerDomainsIncludingWildcards(t *testing.T) {
	fake := &fakeCLB{
		lbs: map[string][]*clbsdk.LoadBalancer{
			"ap-guangzhou": {{LoadBalancerId: common.StringPtr("lb-1")}},
		},
		rules: map[string][]string{
			"lb-1": {"www.example.com", "*.example.com", "www.example.com"},
		},
	}
	stubCLB(t, fake)

	got, err := newRules(t, []string{"ap-guangzhou"}).ListRuleDomains(context.Background())
	if err != nil {
		t.Fatalf("ListRuleDomains: %v", err)
	}
	want := []string{"*.example.com", "www.example.com"}
	if len(got) != len(want) {
		t.Fatalf("domains = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("domains = %v, want %v (sorted and deduplicated)", got, want)
		}
	}
}

// An empty region list would guard nothing while looking configured, so the constructor
// refuses it: surfacing only at enumeration time looked exactly like a transient guard
// outage (the round keeps every name and, with RequireRule on, vets no new one either),
// which let a misconfiguration degrade RequireRule silently for every round.
func TestNewCLBRulesRefusesAnEmptyRegionList(t *testing.T) {
	cred := config.Tencent{CredentialMode: config.CredentialStatic, SecretID: "id", SecretKey: "key"}

	for _, regions := range [][]string{nil, {}, {"", "  "}} {
		_, err := NewCLBRules(cred, regions, testLogger())
		if err == nil {
			t.Errorf("NewCLBRules(regions=%v) must fail: an empty guard looks configured", regions)
			continue
		}
		if !strings.Contains(err.Error(), "regions") {
			t.Errorf("the error must name the setting, got: %v", err)
		}
	}

	// A hand-built CLBRules (skipping the constructor) must still refuse at read time:
	// the runtime check is the second line, not the only one.
	r := &CLBRules{credential: nil, log: testLogger()}
	if _, err := r.ListRuleDomains(context.Background()); err == nil {
		t.Error("ListRuleDomains on a region-less CLBRules must still fail")
	}

	// And a configured region still constructs fine.
	if _, err := NewCLBRules(cred, []string{"ap-guangzhou"}, testLogger()); err != nil {
		t.Errorf("a configured region must construct: %v", err)
	}
}

// Every configured region must be enumerated: CLB is regional, so skipping one silently drops
// the rules that live there.
func TestListRuleDomainsReadsEveryConfiguredRegion(t *testing.T) {
	fake := &fakeCLB{
		lbs: map[string][]*clbsdk.LoadBalancer{},
		rules: map[string][]string{
			"lb-gz": {"gz.example.com"},
			"lb-sh": {"sh.example.com"},
		},
	}
	// Two distinct clients, one per region, each answering with that region's load balancer.
	var seenRegions []string
	orig := newCLBClient
	newCLBClient = func(_ common.CredentialIface, region string, _ *profile.ClientProfile) (clbAPI, error) {
		seenRegions = append(seenRegions, region)
		id := "lb-gz"
		if region == "ap-shanghai" {
			id = "lb-sh"
		}
		return &regionCLB{fake: fake, lbID: id}, nil
	}
	t.Cleanup(func() { newCLBClient = orig })

	got, err := newRules(t, []string{"ap-guangzhou", "ap-shanghai"}).ListRuleDomains(context.Background())
	if err != nil {
		t.Fatalf("ListRuleDomains: %v", err)
	}
	if len(seenRegions) != 2 {
		t.Errorf("clients built for %v, want both regions", seenRegions)
	}
	if len(got) != 2 {
		t.Errorf("domains = %v, want one from each region", got)
	}
}

// regionCLB answers with the one load balancer its region owns, so the test can tell whether
// every configured region was actually queried.
type regionCLB struct {
	fake *fakeCLB
	lbID string
}

func (c *regionCLB) DescribeLoadBalancersWithContext(context.Context, *clbsdk.DescribeLoadBalancersRequest) (*clbsdk.DescribeLoadBalancersResponse, error) {
	return &clbsdk.DescribeLoadBalancersResponse{
		Response: &clbsdk.DescribeLoadBalancersResponseParams{
			TotalCount:      common.Uint64Ptr(1),
			LoadBalancerSet: []*clbsdk.LoadBalancer{{LoadBalancerId: common.StringPtr(c.lbID)}},
		},
	}, nil
}

func (c *regionCLB) DescribeListenersWithContext(_ context.Context, req *clbsdk.DescribeListenersRequest) (*clbsdk.DescribeListenersResponse, error) {
	id := ""
	if req.LoadBalancerId != nil {
		id = *req.LoadBalancerId
	}
	var rules []*clbsdk.RuleOutput
	for i, d := range c.fake.rules[id] {
		rules = append(rules, &clbsdk.RuleOutput{
			LocationId: common.StringPtr("loc-" + itoa(i)), Domain: common.StringPtr(d),
		})
	}
	listeners := []*clbsdk.Listener{{ListenerId: common.StringPtr("lbl-0"), Rules: rules}}
	return &clbsdk.DescribeListenersResponse{
		Response: &clbsdk.DescribeListenersResponseParams{
			TotalCount: common.Uint64Ptr(uint64(len(listeners))), Listeners: listeners,
		},
	}, nil
}

// A failure in one region must fail the round: reading "the rule is gone" from a failed query
// walks straight into deleting a name that is still served.
func TestListRuleDomainsFailsOnAPartialRead(t *testing.T) {
	stubCLB(t, &fakeCLB{lbErr: errors.New("permission denied")})

	if _, err := newRules(t, []string{"ap-guangzhou"}).ListRuleDomains(context.Background()); err == nil {
		t.Fatal("a failed region read must fail the round, not yield a partial rule set")
	}
}

// CLB with no rules at all is zero domains, not an error: that is a real configuration.
func TestListRuleDomainsHandlesNoRules(t *testing.T) {
	stubCLB(t, &fakeCLB{lbs: map[string][]*clbsdk.LoadBalancer{}, rules: map[string][]string{}})

	got, err := newRules(t, []string{"ap-guangzhou"}).ListRuleDomains(context.Background())
	if err != nil {
		t.Fatalf("ListRuleDomains: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("domains = %v, want none", got)
	}
}

// itoa avoids strconv for one call site.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// A well-formed 200 whose body carries no result must be an error, never a panic.
//
// The SDK's typed Response field is a pointer and its own error check only inspects
// Error.Code, so `{"Response":null}` reaches wecert as (resp, nil). wecert-onboard has no
// recover, so dereferencing it kills the process -- and the round writes no desired state,
// bypassing the freeze path that exists to make a bad round harmless. All four enumeration
// calls are checked here because all four dereferenced the response.
func TestEnumerationRejectsANilResultInsteadOfPanicking(t *testing.T) {
	t.Run("dns zones", func(t *testing.T) {
		fake := &fakeDNSPod{nilResponse: true}
		stubDNSPod(t, fake)
		if _, err := newDeclarations(t, nil).ListDeclarations(context.Background()); err == nil {
			t.Error("a response with no result must be an error, not an empty zone list")
		}
	})

	t.Run("txt records", func(t *testing.T) {
		fake := &fakeDNSPod{nilResponse: true}
		stubDNSPod(t, fake)
		d := newDeclarations(t, []string{"example.com"})
		if _, err := d.ListDeclarations(context.Background()); err == nil {
			t.Error("a response with no result must be an error, not an empty declaration set")
		}
	})

	t.Run("load balancers", func(t *testing.T) {
		fake := &fakeCLB{nilResponse: true}
		stubCLB(t, fake)
		if _, err := newRules(t, []string{"ap-guangzhou"}).ListRuleDomains(context.Background()); err == nil {
			t.Error("a response with no result must be an error, not an empty rule set")
		}
	})

	t.Run("listeners", func(t *testing.T) {
		fake := &fakeCLB{nilResponse: true, lbs: map[string][]*clbsdk.LoadBalancer{
			"ap-guangzhou": {{LoadBalancerId: common.StringPtr("lb-1")}},
		}}
		stubCLB(t, fake)
		if _, err := newRules(t, []string{"ap-guangzhou"}).ListRuleDomains(context.Background()); err == nil {
			t.Error("a response with no result must be an error, not an empty rule set")
		}
	})
}

// A nil element inside an otherwise valid list must be skipped, not dereferenced.
func TestEnumerationSkipsNilListElements(t *testing.T) {
	t.Run("dns zones", func(t *testing.T) {
		fake := &fakeDNSPod{domains: []*dnssdk.DomainListItem{
			nil, {Name: common.StringPtr("example.com")},
		}}
		stubDNSPod(t, fake)
		d := newDeclarations(t, []string{"example.com"})
		recs, err := d.ListDeclarations(context.Background())
		if err != nil {
			t.Fatalf("a nil element must be skipped, got %v", err)
		}
		if len(recs) != 0 {
			t.Errorf("the nil zone element must contribute nothing, got %v", recs)
		}
	})

	t.Run("load balancers", func(t *testing.T) {
		// A nil element is not dereferenced -- and it is not skipped either. An element without an
		// id is a load balancer whose listeners can never be enumerated, so its rules are missing
		// from the list the guard checks declarations against: answering with the rules of the
		// OTHER load balancers is a knowingly short answer, and a short guard list is what makes a
		// served name look unreferenced.
		fake := &fakeCLB{
			lbs: map[string][]*clbsdk.LoadBalancer{
				"ap-guangzhou": {nil, {LoadBalancerId: common.StringPtr("lb-1")}},
			},
			rules: map[string][]string{"lb-1": {"api.example.com"}},
		}
		stubCLB(t, fake)
		_, err := newRules(t, []string{"ap-guangzhou"}).ListRuleDomains(context.Background())
		if err == nil {
			t.Fatal("an unusable element must make the read fail as incomplete, not silently drop the " +
				"rules of the load balancer it names")
		}
		if !errors.Is(err, errIncompleteRuleList) {
			t.Errorf("the failure must be recognisable as an incomplete list, got %v", err)
		}
	})
}

// A response that reports more objects than it returned must not be used as a complete list.
//
// Both enumerations feed the CLB guard, and the guard's answer decides whether a name still has a
// rule. A silently short list therefore reads "this name is unserved", which (before the carry rule)
// took the name out of the desired state -- a guard bug turning into lost coverage. The count the
// API sends with the response is what makes that failure visible.
func TestListRuleDomainsRefusesATruncatedAnswer(t *testing.T) {
	t.Run("load balancers", func(t *testing.T) {
		fake := &fakeCLB{
			lbs: map[string][]*clbsdk.LoadBalancer{
				"ap-guangzhou": {{LoadBalancerId: common.StringPtr("lb-1")}},
			},
			rules: map[string][]string{"lb-1": {"api.example.com"}},
		}
		// The API says three instances exist and hands over one.
		fake.lbTotal = common.Uint64Ptr(3)
		stubCLB(t, fake)

		_, err := newRules(t, []string{"ap-guangzhou"}).ListRuleDomains(context.Background())
		if err == nil {
			t.Fatal("a load-balancer list shorter than the reported total must not be used as the guard")
		}
		if !errors.Is(err, errIncompleteRuleList) {
			t.Errorf("the failure must be recognisable as an incomplete list, got %v", err)
		}
		if !strings.Contains(err.Error(), "3") {
			t.Errorf("the error must carry the counts, got %v", err)
		}
	})

	t.Run("listeners", func(t *testing.T) {
		fake := &fakeCLB{
			lbs: map[string][]*clbsdk.LoadBalancer{
				"ap-guangzhou": {{LoadBalancerId: common.StringPtr("lb-1")}},
			},
			rules: map[string][]string{"lb-1": {"api.example.com"}},
		}
		fake.listenerTotal = common.Uint64Ptr(4)
		stubCLB(t, fake)

		_, err := newRules(t, []string{"ap-guangzhou"}).ListRuleDomains(context.Background())
		if err == nil {
			t.Fatal("a listener list shorter than the reported total must not be used as the guard")
		}
		if !errors.Is(err, errIncompleteRuleList) {
			t.Errorf("the failure must be recognisable as an incomplete list, got %v", err)
		}
	})
}

// The load-balancer enumeration must not filter by instance generation.
//
// `Forward` reads like a layer-7 selector but the SDK documents it as the instance
// GENERATION: 1 = general, 0 = classic, omitted = both. Sending 1 hides every classic
// instance, and that list supplies the CLB guard -- which REJECTS a declaration when no
// rule serves its name. A name fronted by a classic instance would be judged unreferenced
// and dropped from the desired state: silent, and in the direction that removes coverage.
func TestLoadBalancerEnumerationDoesNotFilterByInstanceGeneration(t *testing.T) {
	fake := &fakeCLB{lbs: map[string][]*clbsdk.LoadBalancer{
		"ap-guangzhou": {{LoadBalancerId: common.StringPtr("lb-1")}},
	}}
	stubCLB(t, fake)

	if _, err := newRules(t, []string{"ap-guangzhou"}).ListRuleDomains(context.Background()); err != nil {
		t.Fatalf("ListRuleDomains: %v", err)
	}
	if fake.forward != nil {
		t.Errorf("DescribeLoadBalancers sent Forward=%d; that is the instance generation, not a "+
			"layer-7 filter, so it hides classic load balancers and their rule domains with them",
			*fake.forward)
	}
}

// A zone with no TXT records -- or one page request past the end -- must not fail the whole
// declaration read.
//
// The API's default is to report "nothing matched" as an ERROR, not as an empty list, and a
// failed declaration source freezes the round: the desired-state document and the state file are
// then not written for any certificate until a human edits DNS. Two ordinary situations reach it:
// any enumerated zone without TXT records, and the page request this loop makes whenever a zone's
// TXT count is an exact multiple of the page size.
func TestAnEmptyZoneDoesNotFreezeTheDeclarationRead(t *testing.T) {
	fake := &fakeDNSPod{
		realEmptyError: true,
		domains: []*dnssdk.DomainListItem{
			{Name: common.StringPtr("empty.example.com")},
			{Name: common.StringPtr("full.example.com")},
		},
		records: map[string][]*dnssdk.RecordListItem{},
	}
	// Exactly one full page, so the loop asks for the page after it.
	for i := 0; i < int(dnsPageSize); i++ {
		fake.records["full.example.com"] = append(fake.records["full.example.com"], &dnssdk.RecordListItem{
			Name:  common.StringPtr(fmt.Sprintf("_wecert.api.n%03d", i)),
			Type:  common.StringPtr("TXT"),
			Value: common.StringPtr("domains=a.example.com"),
		})
	}
	stubDNSPod(t, fake)

	got, err := newDeclarations(t, nil).ListDeclarations(context.Background())
	if err != nil {
		t.Fatalf("a zone with no TXT records must read as \"no declarations\", not fail the round: %v", err)
	}
	if len(got) != int(dnsPageSize) {
		t.Errorf("declarations = %d, want the %d from the full zone", len(got), dnsPageSize)
	}
}

// A region with more load balancers than one page must be paged, not called incomplete.
//
// The completeness check compared TotalCount against the bytes read SO FAR, inside the page loop.
// TotalCount is the total matching the filter and is documented as independent of Limit, so for
// any region with more instances than one page the first iteration saw "100 returned, 250
// reported" and returned errIncompleteRuleList: paging was dead code, and guard 1 was reported
// incomplete (and therefore disabled: no rule check, no removals) for the whole account. The
// in-tree fake returned every instance in one page, which is why no test could see it.
func TestListRuleDomainsPagesPastOnePage(t *testing.T) {
	const count = 250
	lbs := make([]*clbsdk.LoadBalancer, 0, count)
	rules := map[string][]string{}
	for i := range count {
		id := "lb-" + itoa(i)
		lbs = append(lbs, &clbsdk.LoadBalancer{LoadBalancerId: common.StringPtr(id)})
		rules[id] = []string{"host-" + itoa(i) + ".example.com"}
	}
	fake := &fakeCLB{
		paging: true,
		lbs:    map[string][]*clbsdk.LoadBalancer{"ap-guangzhou": lbs},
		rules:  rules,
	}
	stubCLB(t, fake)

	got, err := newRules(t, []string{"ap-guangzhou"}).ListRuleDomains(context.Background())
	if err != nil {
		t.Fatalf("a region with %d load balancers must be paged, not reported incomplete: %v", count, err)
	}
	if len(got) != count {
		t.Errorf("the guard saw %d rule domains, want %d: the pages after the first were skipped", len(got), count)
	}

	// And a genuinely short answer is still reported: the check moved, it did not disappear.
	fake.lbTotal = common.Uint64Ptr(count + 50)
	if _, err := newRules(t, []string{"ap-guangzhou"}).ListRuleDomains(context.Background()); !errors.Is(err, errIncompleteRuleList) {
		t.Errorf("a response that reports more instances than its pages returned must stay an error, got %v", err)
	}
}
