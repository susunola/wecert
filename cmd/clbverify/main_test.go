package main

import (
	"strings"
	"testing"

	clb "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/clb/v20180317"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
)

// The assertion has to see every certificate a listener carries.
//
// A listener serving the managed certificate as an SNI extension certificate (the shape
// this project's own e2e uses) reports it in ExtCertIds, not in the primary CertId. A
// check that only compared the primary ID therefore both passed when the old certificate
// was still bound as an extension cert and failed when the rebind had actually worked.
func TestBoundCertIDsIncludesSNIExtensions(t *testing.T) {
	c := &clb.CertificateOutput{
		CertId:     common.StringPtr("primary"),
		ExtCertIds: []*string{common.StringPtr("sni-1"), common.StringPtr("sni-2")},
	}
	got := boundCertIDs(c)
	if len(got) != 3 {
		t.Fatalf("boundCertIDs = %v, want the primary plus both SNI certificates", got)
	}
	if !contains(got, "primary") || !contains(got, "sni-1") || !contains(got, "sni-2") {
		t.Errorf("boundCertIDs = %v, want all three IDs", got)
	}
}

func TestBoundCertIDsSkipsEmptyAndNil(t *testing.T) {
	c := &clb.CertificateOutput{
		CertId:     common.StringPtr(""),
		ExtCertIds: []*string{nil, common.StringPtr(""), common.StringPtr("sni-1")},
	}
	got := boundCertIDs(c)
	if len(got) != 1 || got[0] != "sni-1" {
		t.Errorf("boundCertIDs = %v, want just [sni-1]", got)
	}
}

func TestBoundCertIDsHandlesNilCertificate(t *testing.T) {
	if got := boundCertIDs(nil); len(got) != 0 {
		t.Errorf("boundCertIDs(nil) = %v, want empty", got)
	}
}

// -not-expect must fail when the ID is present anywhere, which is the whole point of
// including the extension certificates.
func TestContainsFindsAnSNICertificate(t *testing.T) {
	bound := boundCertIDs(&clb.CertificateOutput{
		CertId:     common.StringPtr("new"),
		ExtCertIds: []*string{common.StringPtr("old")},
	})
	if !contains(bound, "old") {
		t.Error("the old certificate is still bound as an SNI certificate; -not-expect must see it")
	}
	if contains(bound, "absent") {
		t.Error("contains reported a certificate that is not bound")
	}
}

// The empty-listener failure must fit how the query was made: an unfiltered query that
// comes back empty means the CLB has no listeners, but a filtered one means *that
// listener* matched nothing (deleted, or a typo) -- blaming the CLB then sends the
// operator debugging the wrong object.
func TestNoListenersError(t *testing.T) {
	plain := noListenersError("lb-abc", "")
	if !strings.Contains(plain.Error(), "CLB lb-abc has no listeners") {
		t.Errorf("unfiltered wording = %q, want the CLB blamed", plain)
	}

	filtered := noListenersError("lb-abc", "lbl-xyz")
	if !strings.Contains(filtered.Error(), "lbl-xyz") || !strings.Contains(filtered.Error(), "deleted") {
		t.Errorf("filtered wording = %q, want the listener ID named with the deleted/typo hint", filtered)
	}
	if strings.Contains(filtered.Error(), "has no listeners") {
		t.Errorf("filtered wording = %q, must not claim the whole CLB is empty", filtered)
	}
}
