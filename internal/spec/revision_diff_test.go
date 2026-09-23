package spec

import (
	"testing"

	"github.com/susunola/wecert/internal/config"
)

// The certificate list's own order is not semantic: the same set listed in a
// different order is the same desired state, and Revision must answer "did the
// desired state actually change?", so neither kind of ordering may disturb it.
func TestRevisionIgnoresCertificateOrder(t *testing.T) {
	t.Parallel()
	a := []config.Certificate{
		{Name: "example-com", Domains: []string{"example.com", "www.example.com"}},
		{Name: "other-net", Domains: []string{"other.net"}},
	}
	b := []config.Certificate{a[1], a[0]}

	if Revision(a) != Revision(b) {
		t.Errorf("certificate order must not affect the fingerprint: %s vs %s", Revision(a), Revision(b))
	}
	// And the input must not be reordered as a side effect.
	if a[0].Name != "example-com" {
		t.Errorf("Revision must hash a copy, not sort the caller's slice: %+v", a)
	}
	if Revision(a) == Revision([]config.Certificate{a[1]}) {
		t.Error("dropping a certificate must change the fingerprint")
	}
}

// diffCert compares renewBefore semantically: both sides came through
// config.NormalizeCertificates, so "720h" written on one side and the empty default
// on the other are the SAME 30 days on the classic profile -- a string comparison
// reported that as a change against the observe-mode gate.
func TestDiffDoesNotFlagEquivalentRenewBefore(t *testing.T) {
	t.Parallel()
	cur := []config.Certificate{{
		Name: "example-com", Domains: []string{"example.com"}, RenewBefore: "720h",
	}}
	want := []config.Certificate{{
		Name: "example-com", Domains: []string{"example.com"},
	}}
	if err := config.NormalizeCertificates(cur); err != nil {
		t.Fatal(err)
	}
	if err := config.NormalizeCertificates(want); err != nil {
		t.Fatal(err)
	}

	got := Diff(&Result{Certificates: cur}, &Result{Certificates: want})
	if !got.Empty() {
		t.Errorf("\"720h\" and the classic default are the same 30 days; the diff must be empty, got %+v", got)
	}
}

// A genuinely different renewBefore must still be reported: Revision() hashes it,
// so without the diff entry two revisions would differ with an empty diff -- and an
// empty diff is the documented gate for switching to enforce.
func TestDiffFlagsARealRenewBeforeChange(t *testing.T) {
	t.Parallel()
	cur := []config.Certificate{{
		Name: "example-com", Domains: []string{"example.com"}, RenewBefore: "720h",
	}}
	want := []config.Certificate{{
		Name: "example-com", Domains: []string{"example.com"}, RenewBefore: "360h",
	}}
	if err := config.NormalizeCertificates(cur); err != nil {
		t.Fatal(err)
	}
	if err := config.NormalizeCertificates(want); err != nil {
		t.Fatal(err)
	}

	got := Diff(&Result{Certificates: cur}, &Result{Certificates: want})
	if len(got.ChangeCertificates) != 1 {
		t.Fatalf("a real renewBefore change must be reported, got %+v", got)
	}
	ch := got.ChangeCertificates[0]
	if len(ch.Changed) != 1 || ch.Changed[0] != "renewBefore" {
		t.Errorf("changedFields = %v, want [renewBefore]", ch.Changed)
	}
}
