package onboarding

import (
	"context"
	"errors"
	"strings"
	"testing"

	clbsdk "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/clb/v20180317"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
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
}

func (f *fakeCLB) DescribeLoadBalancersWithContext(_ context.Context, req *clbsdk.DescribeLoadBalancersRequest) (*clbsdk.DescribeLoadBalancersResponse, error) {
	f.forward = req.Forward
	if f.lbErr != nil {
		return nil, f.lbErr
	}
	if f.nilResponse {
		return &clbsdk.DescribeLoadBalancersResponse{}, nil
	}
	var out []*clbsdk.LoadBalancer
	for _, v := range f.lbs {
		out = append(out, v...)
	}
	return &clbsdk.DescribeLoadBalancersResponse{
		Response: &clbsdk.DescribeLoadBalancersResponseParams{
			TotalCount: common.Uint64Ptr(uint64(len(out))), LoadBalancerSet: out,
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
	return &clbsdk.DescribeListenersResponse{
		Response: &clbsdk.DescribeListenersResponseParams{
			TotalCount: common.Uint64Ptr(uint64(len(listeners))), Listeners: listeners,
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

// An empty region list would guard nothing while looking configured, so it is an error.
func TestListRuleDomainsRefusesAnEmptyRegionList(t *testing.T) {
	_, err := newRules(t, nil).ListRuleDomains(context.Background())
	if err == nil {
		t.Fatal("no configured region must be an error: an empty guard looks configured")
	}
	if !strings.Contains(err.Error(), "regions") {
		t.Errorf("the error must name the setting, got: %v", err)
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
		if _, err := newRules(t, nil).ListRuleDomains(context.Background()); err == nil {
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

	t.Run("load balancers and rules", func(t *testing.T) {
		fake := &fakeCLB{
			lbs: map[string][]*clbsdk.LoadBalancer{
				"ap-guangzhou": {nil, {LoadBalancerId: common.StringPtr("lb-1")}},
			},
			rules: map[string][]string{"lb-1": {"api.example.com"}},
		}
		stubCLB(t, fake)
		got, err := newRules(t, []string{"ap-guangzhou"}).ListRuleDomains(context.Background())
		if err != nil {
			t.Fatalf("a nil element must be skipped, got %v", err)
		}
		if len(got) != 1 || got[0] != "api.example.com" {
			t.Errorf("got %v, want the rule of the non-nil load balancer only", got)
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
