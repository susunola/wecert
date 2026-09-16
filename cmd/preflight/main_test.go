package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tcerrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	dnspod "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/dnspod/v20210323"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

// The delegation check is the highest-value check this tool runs, and its old
// substring matching failed both ways at once: a lookalike host containing "dnsv"
// false-passed (ns1.dnsvault.example) and a mixed-case record could false-fail even
// though DNS is case-insensitive. Suffix matching on the lowercased host pins both.
func TestIsDNSPodNS(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		// The real shapes (docs.dnspod.cn/dns/dns-plan-address): free-tier dedicated
		// addresses under dnspod.net / dnspod.com, paid tiers under dnsv1..dnsv5.com.
		{"f1g1ns1.dnspod.net", true},
		{"namerich2.dnspod.net", true},
		{"abc123xyz.dnspod.com", true},
		{"ns1.dnsv1.com", true},
		{"ns3.dnsv2.com", true},
		{"ns4.dnsv5.com", true},
		// DNS is case-insensitive, so the check must be too.
		{"NS3.DNSV2.COM", true},
		{"F1G1NS1.DNSPOD.NET", true},
		// Lookalikes that a substring match would false-pass.
		{"ns1.dnsvault.example", false},
		{"cdn.dnsvideo.example", false},
		{"evil.dnspod.net.attacker.example", false},
		// Genuinely other hosts.
		{"ns1.cloudflare.com", false},
		{"dns1.p08.nsone.net", false},
		// The bare apex carries no label in front of the suffix; a real NS hostname
		// always has one, and a false here is the conservative answer.
		{"dnspod.net", false},
	}
	for _, c := range cases {
		if got := isDNSPodNS(c.host); got != c.want {
			t.Errorf("isDNSPodNS(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

// stubDescribeDomainList swaps the SDK seam for paged fake responses and restores it.
func stubDescribeDomainList(t *testing.T, pages func(offset int64) *dnspod.DescribeDomainListResponse) {
	t.Helper()
	orig := describeDomainList
	describeDomainList = func(_ context.Context, _ *dnspod.Client, req *dnspod.DescribeDomainListRequest) (*dnspod.DescribeDomainListResponse, error) {
		return pages(*req.Offset), nil
	}
	t.Cleanup(func() { describeDomainList = orig })
}

func domainPage(total uint64, names ...string) *dnspod.DescribeDomainListResponse {
	resp := &dnspod.DescribeDomainListResponse{
		Response: &dnspod.DescribeDomainListResponseParams{
			DomainCountInfo: &dnspod.DomainCountInfo{DomainTotal: common.Uint64Ptr(total)},
		},
	}
	for _, n := range names {
		resp.Response.DomainList = append(resp.Response.DomainList, &dnspod.DomainListItem{Name: common.StringPtr(n)})
	}
	return resp
}

// Keyword is a substring filter capped by the page size, so the exact domain can sit
// behind a page of unrelated matches. findDomain must keep paging instead of
// concluding "not under DNSPod" from the first page.
func TestFindDomainPagesUntilCovered(t *testing.T) {
	// 150 matches for the keyword, 100 per page, the exact hit on page two.
	stubDescribeDomainList(t, func(offset int64) *dnspod.DescribeDomainListResponse {
		switch offset {
		case 0:
			names := make([]string, 100)
			for i := range names {
				names[i] = "sub.example.com"
			}
			return domainPage(150, names...)
		case 100:
			return domainPage(150, "www.example.com", "example.com")
		default:
			t.Fatalf("unexpected extra page fetched at offset %d", offset)
			return nil
		}
	})

	found, err := findDomain(context.Background(), nil, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found == nil {
		t.Fatal("the exact hit on page two must be found; one page of substring matches is not the whole answer")
	}
}

// Matching must stay case-insensitive across pages, the way DNSPod treats names.
func TestFindDomainMatchesCaseInsensitively(t *testing.T) {
	stubDescribeDomainList(t, func(offset int64) *dnspod.DescribeDomainListResponse {
		return domainPage(1, "EXAMPLE.com")
	})

	found, err := findDomain(context.Background(), nil, "example.com")
	if err != nil || found == nil {
		t.Fatalf("found=%v err=%v, want a case-insensitive match", found, err)
	}
}

// When the filtered total is genuinely covered without a hit, the domain is absent --
// (nil, nil), not an error: the caller prints the "not under DNSPod" diagnosis.
func TestFindDomainAbsentAfterFullPaging(t *testing.T) {
	var pages int
	stubDescribeDomainList(t, func(offset int64) *dnspod.DescribeDomainListResponse {
		pages++
		return domainPage(1, "other.example")
	})

	found, err := findDomain(context.Background(), nil, "example.com")
	if err != nil {
		t.Fatalf("an absent domain is a (nil, nil) answer, got err=%v", err)
	}
	if found != nil {
		t.Errorf("found = %v, want nil", found)
	}
	if pages != 1 {
		t.Errorf("pages = %d, want the search to stop once the total is covered", pages)
	}
}

// A missing DomainTotal must not truncate the search: keep paging until an empty page
// says stop.
func TestFindDomainWithoutTotalStopsAtEmptyPage(t *testing.T) {
	stubDescribeDomainList(t, func(offset int64) *dnspod.DescribeDomainListResponse {
		if offset == 0 {
			resp := domainPage(0, "sub.example.com")
			resp.Response.DomainCountInfo = nil
			return resp
		}
		resp := domainPage(0)
		resp.Response.DomainCountInfo = nil
		return resp
	})

	found, err := findDomain(context.Background(), nil, "example.com")
	if err != nil || found != nil {
		t.Fatalf("found=%v err=%v, want (nil, nil) after the empty page", found, err)
	}
}

// An API error mid-paging must abort with the wrapped cause, not read as "absent".
func TestFindDomainPropagatesAPIErrors(t *testing.T) {
	sentinel := errors.New("dnspod throttled")
	orig := describeDomainList
	describeDomainList = func(context.Context, *dnspod.Client, *dnspod.DescribeDomainListRequest) (*dnspod.DescribeDomainListResponse, error) {
		return nil, sentinel
	}
	t.Cleanup(func() { describeDomainList = orig })

	_, err := findDomain(context.Background(), nil, "example.com")
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want it to wrap the API error", err)
	}
	if !strings.Contains(err.Error(), "DescribeDomainList") {
		t.Errorf("err = %v, want the failing operation named", err)
	}
}

func cert(id string) *ssl.Certificates {
	return &ssl.Certificates{CertificateId: &id}
}

func ids(certs []*ssl.Certificates) []string {
	out := make([]string, 0, len(certs))
	for _, c := range certs {
		out = append(out, *c.CertificateId)
	}
	return out
}

// The regression this pins: the API leaves TotalCount null in some responses, and reading
// a nil total as 0 stopped the walk after the first page. The walk decides what gets
// deleted, so the command then reported a complete cleanup over a truncated list.
func TestListAllPagesWalksPastTheFirstPageWithoutTotalCount(t *testing.T) {
	var offsets []uint64
	got, err := listAllPages(2, 10, func(offset, limit uint64) (certPage, error) {
		offsets = append(offsets, offset)
		switch offset {
		case 0:
			return certPage{certs: []*ssl.Certificates{cert("a"), cert("b")}}, nil
		case 2:
			// No TotalCount, exactly like the responses that caused the bug.
			return certPage{certs: []*ssl.Certificates{cert("c"), cert("d")}}, nil
		default:
			return certPage{certs: []*ssl.Certificates{cert("e")}}, nil
		}
	})
	if err != nil {
		t.Fatalf("listAllPages: %v", err)
	}
	if want := []string{"a", "b", "c", "d", "e"}; fmt.Sprint(ids(got)) != fmt.Sprint(want) {
		t.Errorf("walked %v, want %v", ids(got), want)
	}
	if fmt.Sprint(offsets) != "[0 2 4]" {
		t.Errorf("offsets = %v, want [0 2 4]", offsets)
	}
}

// A page smaller than the limit means the list is exhausted, even when the server reported
// a larger total (or none at all).
func TestListAllPagesStopsOnAShortPage(t *testing.T) {
	calls := 0
	total := uint64(10)
	got, err := listAllPages(3, 10, func(offset, _ uint64) (certPage, error) {
		calls++
		if offset == 0 {
			return certPage{certs: []*ssl.Certificates{cert("a"), cert("b"), cert("c")}, total: &total}, nil
		}
		return certPage{certs: []*ssl.Certificates{cert("d")}, total: &total}, nil
	})
	if err != nil {
		t.Fatalf("listAllPages: %v", err)
	}
	if calls != 2 {
		t.Errorf("made %d calls, want 2", calls)
	}
	if len(got) != 4 {
		t.Errorf("collected %d certificates, want 4", len(got))
	}
}

// A present TotalCount still ends the walk at the end of the list, without a wasted request.
func TestListAllPagesHonoursTotalCount(t *testing.T) {
	calls := 0
	total := uint64(2)
	got, err := listAllPages(2, 10, func(offset, _ uint64) (certPage, error) {
		calls++
		return certPage{certs: []*ssl.Certificates{cert("a"), cert("b")}, total: &total}, nil
	})
	if err != nil {
		t.Fatalf("listAllPages: %v", err)
	}
	if calls != 1 {
		t.Errorf("made %d calls, want 1: TotalCount was reached", calls)
	}
	if len(got) != 2 {
		t.Errorf("collected %d certificates, want 2", len(got))
	}
}

// A server that ignores Offset never returns a short page, so the walk needs its own stop
// rather than looping forever inside a command that then deletes things.
func TestListAllPagesRefusesToLoopForever(t *testing.T) {
	got, err := listAllPages(1, 3, func(uint64, uint64) (certPage, error) {
		return certPage{certs: []*ssl.Certificates{cert("same")}}, nil
	})
	if err == nil {
		t.Fatalf("a non-advancing listing must be an error, got %d certificates", len(got))
	}
}

func TestListAllPagesPropagatesFetchErrors(t *testing.T) {
	boom := fmt.Errorf("ssl api is down")
	if _, err := listAllPages(2, 10, func(uint64, uint64) (certPage, error) {
		return certPage{}, boom
	}); err == nil {
		t.Fatal("a fetch failure must be returned")
	}
}

// ── error classification ─────────────────────────────────────────────────────────────

// isNoRecord decides whether a DNS failure means "there is no such record" (fine) or "the call
// failed" (not fine). Reading a permission error as "no record" would make the delegation check
// pass on a zone that is not delegated at all.
func TestIsNoRecordOnlyMatchesTheAbsenceCode(t *testing.T) {
	for _, tc := range []struct {
		code string
		want bool
	}{
		{"ResourceNotFound.NoDataOfRecord", true},
		// A real failure must never be swallowed as "no record".
		{"AuthFailure.SignatureFailure", false},
		{"RequestLimitExceeded", false},
		{"InternalError", false},
		// A near-miss code is still not the absence code.
		{"ResourceNotFound", false},
		{"InvalidParameter.DomainNotExist", false},
	} {
		var err error
		if tc.code != "" {
			err = tcerrors.NewTencentCloudSDKError(tc.code, "message", "request-1")
		}
		if got := isNoRecord(err); got != tc.want {
			t.Errorf("isNoRecord(%q) = %v, want %v", tc.code, got, tc.want)
		}
	}
}

// A non-SDK error still gets the substring check, which is what a wrapped or re-worded error
// from a different layer looks like.
func TestIsNoRecordFallsBackToTheSubstring(t *testing.T) {
	if !isNoRecord(errors.New("dnspod: ResourceNotFound.NoDataOfRecord")) {
		t.Error("a non-SDK error carrying the code should still be recognised")
	}
	if isNoRecord(errors.New("dnspod: something else went wrong")) {
		t.Error("an unrelated error must not be read as an absent record")
	}
	if isNoRecord(nil) {
		t.Error("nil must not be read as an absent record")
	}
}
