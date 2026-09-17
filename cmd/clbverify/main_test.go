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

// A listener whose certificates live on its rules must not read as "nothing is bound".
//
// With SNI on, CLB ignores the listener-level certificate fields and the rule is what decides
// which certificate a hostname is served -- which is how this project's test account works (SNI
// cannot be turned off there, and the listener reports no certificate at all). A tool that only
// looked at Listener.Certificate answered "the listener has no certificate bound" for a listener
// that was serving fine, and it could equally report "-not-expect <old> passed" while the old
// certificate was still bound on the rule that serves the name.
func TestAssertedCertificatesIncludeRuleBindings(t *testing.T) {
	l := &clb.Listener{
		ListenerId: common.StringPtr("lbl-1"),
		Certificate: &clb.CertificateOutput{
			CertId: common.StringPtr("listener-level"),
		},
		Rules: []*clb.RuleOutput{
			{
				Domain:      common.StringPtr("a.example.com"),
				LocationId:  common.StringPtr("loc-a"),
				Certificate: &clb.CertificateOutput{CertId: common.StringPtr("rule-a")},
			},
			{
				Domain:      common.StringPtr("b.example.com"),
				LocationId:  common.StringPtr("loc-b"),
				Certificate: &clb.CertificateOutput{CertId: common.StringPtr("rule-b")},
			},
		},
	}

	ids, scope, err := assertedCertificates(l, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"listener-level", "rule-a", "rule-b"} {
		if !contains(ids, want) {
			t.Errorf("the asserted set must include %s, got %v (%s)", want, ids, scope)
		}
	}
}

// Naming a domain asserts that domain's rule alone, and a domain no rule serves is an error.
func TestAssertedCertificatesForOneDomain(t *testing.T) {
	l := &clb.Listener{
		ListenerId: common.StringPtr("lbl-1"),
		Rules: []*clb.RuleOutput{
			{
				Domain:      common.StringPtr("a.example.com"),
				Certificate: &clb.CertificateOutput{CertId: common.StringPtr("rule-a")},
			},
			{
				Domain:      common.StringPtr("b.example.com"),
				Certificate: &clb.CertificateOutput{CertId: common.StringPtr("rule-b")},
			},
		},
	}

	ids, scope, err := assertedCertificates(l, "a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "rule-a" {
		t.Errorf("asserting on one domain must look at that rule's certificate, got %v (%s)", ids, scope)
	}
	if contains(ids, "rule-b") {
		t.Error("another rule's certificate must not be part of this assertion")
	}

	// A typo has to fail loudly: an empty set would make -not-expect pass for the wrong reason.
	if _, _, err := assertedCertificates(l, "typo.example.com"); err == nil {
		t.Error("a domain no rule serves must be an error, not an empty assertion set")
	}
}

// A listener with no listener-level certificate but rules that carry one is still assertable.
func TestAssertedCertificatesWithNoListenerLevelCertificate(t *testing.T) {
	l := &clb.Listener{
		ListenerId: common.StringPtr("lbl-1"),
		Rules: []*clb.RuleOutput{{
			Domain:      common.StringPtr("a.example.com"),
			Certificate: &clb.CertificateOutput{CertId: common.StringPtr("rule-a")},
		}},
	}
	ids, _, err := assertedCertificates(l, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "rule-a" {
		t.Errorf("the rule's certificate is the binding that matters here, got %v", ids)
	}
}
