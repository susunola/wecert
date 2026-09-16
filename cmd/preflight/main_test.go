package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	dnspod "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/dnspod/v20210323"
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
