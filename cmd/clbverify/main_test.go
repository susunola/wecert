package main

import (
	"strings"
	"testing"

	"context"
	clb "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/clb/v20180317"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"time"
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

// -wait must bound elapsed time, not just the number of attempts.
//
// The loop slept a flat interval before evaluating the deadline, so `-wait 1s` blocked for the
// full interval and only then queried -- the flag's own help says it is how long to poll. A caller
// budgeting its own time (CI, a systemd unit) reads that as a promise.
func TestPollUntilBoundBoundsElapsedTime(t *testing.T) {
	if bindingsPollInterval <= 80*time.Millisecond {
		t.Fatalf("this test needs the production poll interval to exceed the budget to mean anything; "+
			"it is %s", bindingsPollInterval)
	}

	var calls int
	fetch := func() ([]string, error) {
		calls++
		return []string{"old-cert"}, nil
	}

	const budget = 80 * time.Millisecond
	start := time.Now()
	ids, err := pollUntilBound(context.Background(), budget, fetch, "new-cert", nil)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("a query that succeeds is not an error: %v", err)
	}
	if len(ids) != 1 || ids[0] != "old-cert" {
		t.Errorf("the last observed set must be returned, got %v", ids)
	}
	if elapsed > 2*time.Second {
		t.Errorf("a %s wait took %s: the sleep between polls is not capped to what is left of the "+
			"budget, so -wait does not bound the command's runtime", budget, elapsed)
	}
	if calls == 0 {
		t.Error("the first poll must happen within the budget, not after a flat interval")
	}
}

// The expected certificate appearing ends the wait immediately.
func TestPollUntilBoundStopsWhenTheCertificateAppears(t *testing.T) {
	calls := 0
	fetch := func() ([]string, error) {
		calls++
		if calls >= 2 {
			return []string{"new-cert"}, nil
		}
		return []string{"old-cert"}, nil
	}
	ids, err := pollUntilBound(context.Background(), 200*time.Millisecond, fetch, "new-cert", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(ids, "new-cert") {
		t.Errorf("the wait must return as soon as the expected certificate is bound, got %v", ids)
	}
	if calls != 2 {
		t.Errorf("expected two polls (one immediately, one after the capped wait), got %d", calls)
	}
}

// The wait must update the set the assertions read.
//
// The wait branch used to read `bound, lastErr := pollUntilBound(...)`, which declares a NEW bound
// and shadows the outer one: the polling found the new certificate, printed progress, and then the
// assertions checked the stale pre-wait set and failed with "is still not bound" -- precisely the
// case -wait exists for. The old code assigned the outer variable (`bound = ids`), so this was a
// regression introduced when the loop moved into pollUntilBound, and nothing covered it.
func TestTheWaitResultReachesTheAssertions(t *testing.T) {
	calls := 0
	fetch := func() ([]string, error) {
		calls++
		if calls == 1 {
			return []string{"old-cert"}, nil
		}
		return []string{"new-cert"}, nil
	}

	// What run() does: poll, then assert against the set the poll produced.
	bound, err := pollUntilBound(context.Background(), 200*time.Millisecond, fetch, "new-cert", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := assertBindings(bound, "new-cert", "old-cert", "rule for a.example.com", 200*time.Millisecond); err != nil {
		t.Fatalf("the wait produced the expected set, so the assertion must pass: %v", err)
	}

	// And the assertion itself must still reject the two wrong states.
	if err := assertBindings([]string{"old-cert"}, "new-cert", "", "listener", time.Second); err == nil {
		t.Error("an absent -expect certificate is a failed assertion")
	}
	if err := assertBindings([]string{"new-cert", "old-cert"}, "", "old-cert", "listener", time.Second); err == nil {
		t.Error("-not-expect must fail while the certificate is still bound")
	}
}
