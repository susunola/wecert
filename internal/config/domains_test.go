package config

import (
	"strings"
	"testing"
)

func TestCertificateRejectsRedundantWildcardIdentifier(t *testing.T) {
	body := minimalPrefix + `
certificates:
  - name: wildcard
    domains: ["*.example.com", "www.example.com"]
`
	if _, err := Load(writeConfig(t, body)); err == nil || !strings.Contains(err.Error(), "redundant with the wildcard") {
		t.Fatalf("wildcard plus covered explicit hostname must be rejected before contacting the CA, got %v", err)
	}
}

func TestCertificateAllowsANameOutsideWildcardCoverage(t *testing.T) {
	body := minimalPrefix + `
certificates:
  - name: wildcard
    domains: ["*.example.com", "a.b.example.com"]
`
	if _, err := Load(writeConfig(t, body)); err != nil {
		t.Fatalf("a wildcard covers only one label, so a deeper name must remain valid: %v", err)
	}
}

// On certificates with many SANs the domains list is usually pasted in
// wholesale from elsewhere. Deduplication must happen **before** the cap check,
// or 100 domains plus 1 accidental duplicate is counted as 101 and a legal
// config is rejected.
func TestDuplicateDomainsDedupedBeforeMaxNames(t *testing.T) {
	// 100 unique domains plus 5 duplicates — classic's cap is exactly 100.
	domains := make([]string, 0, 105)
	for i := 0; i < 100; i++ {
		domains = append(domains, "d"+itoa(i)+".example.com")
	}
	for i := 0; i < 5; i++ {
		domains = append(domains, "d"+itoa(i)+".example.com")
	}

	body := minimalPrefix + `
certificates:
  - name: dedup
    profile: classic
    domains: [` + strings.Join(quoteAll(domains), ", ") + `]
`
	cfg, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatalf("100 unique domains + 5 duplicates should pass (exactly 100 after dedup): %v", err)
	}
	if got := len(cfg.Certificates[0].Domains); got != 100 {
		t.Errorf("expected 100 domains after dedup, got %d", got)
	}
}

// A genuine overflow must still be blocked.
func TestRealOverflowStillRejected(t *testing.T) {
	domains := make([]string, 0, 101)
	for i := 0; i < 101; i++ {
		domains = append(domains, "d"+itoa(i)+".example.com")
	}
	body := minimalPrefix + `
certificates:
  - name: over
    profile: classic
    domains: [` + strings.Join(quoteAll(domains), ", ") + `]
`
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("101 unique domains should be rejected")
	}
}

// Casing must not produce two different identifiers.
func TestDomainsLowercased(t *testing.T) {
	body := minimalPrefix + `
certificates:
  - name: mixed
    domains: ["Example.COM", "example.com", "API.Example.Com"]
`
	cfg, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	got := cfg.Certificates[0].Domains
	want := []string{"example.com", "api.example.com"}
	if len(got) != len(want) {
		t.Fatalf("domains = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("domains[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// Order must be preserved: the classic profile promotes the first dNSName to CN.
func TestDomainOrderPreserved(t *testing.T) {
	body := minimalPrefix + `
certificates:
  - name: ordered
    domains: ["z.example.com", "a.example.com", "m.example.com"]
`
	cfg, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	got := cfg.Certificates[0].Domains
	if got[0] != "z.example.com" || got[1] != "a.example.com" || got[2] != "m.example.com" {
		t.Errorf("order was changed: %v (the first domain becomes the CN)", got)
	}
}

// DomainKey must be independent of order, case and duplicates — it is the basis
// for comparing "the set the config wants" with "the actual certificate SANs".
func TestDomainKeyIsSetSemantics(t *testing.T) {
	base := DomainKey([]string{"a.example.com", "b.example.com"})

	same := [][]string{
		{"b.example.com", "a.example.com"},                  // different order
		{"A.Example.COM", "B.example.com"},                  // different case
		{"a.example.com", "b.example.com", "a.example.com"}, // duplicate present
		{"a.example.com", " b.example.com "},                // whitespace present
	}
	for _, candidate := range same {
		if got := DomainKey(candidate); got != base {
			t.Errorf("DomainKey(%v) = %q, should equal %q", candidate, got, base)
		}
	}

	different := [][]string{
		{"a.example.com"}, // one fewer
		{"a.example.com", "b.example.com", "c.example.com"}, // one more
		{"a.example.com", "c.example.com"},                  // one swapped
	}
	for _, candidate := range different {
		if got := DomainKey(candidate); got == base {
			t.Errorf("DomainKey(%v) should not equal %q", candidate, base)
		}
	}
}

// DiffDomains must report both directions: reporting only missing would miss "a
// domain was deleted from the config".
func TestDiffDomainsBothDirections(t *testing.T) {
	missing, extra := DiffDomains(
		[]string{"keep.example.com", "added.example.com"},
		[]string{"keep.example.com", "removed.example.com"},
	)

	if len(missing) != 1 || missing[0] != "added.example.com" {
		t.Errorf("missing = %v, want [added.example.com]", missing)
	}
	if len(extra) != 1 || extra[0] != "removed.example.com" {
		t.Errorf("extra = %v, want [removed.example.com]", extra)
	}

	// When the sets match exactly, both should be empty.
	missing, extra = DiffDomains([]string{"a.com", "b.com"}, []string{"b.com", "a.com"})
	if len(missing) != 0 || len(extra) != 0 {
		t.Errorf("identical sets should show no diff, got missing=%v extra=%v", missing, extra)
	}
}

// Bad domains must be blocked locally — every order sent out that the CA will
// certainly reject burns order quota, and re-issuing a many-SAN certificate is
// expensive.
func TestDomainValidation(t *testing.T) {
	cases := []struct {
		domain  string
		wantErr bool
		why     string
	}{
		{"example.com", false, "ordinary domain"},
		{"a.b.c.example.com", false, "multi-level subdomain"},
		{"xn--fiqs8s.example.com", false, "punycode"},
		{"my-host.example.com", false, "hyphen"},
		{"*.example.com", false, "valid wildcard"},
		{"*.*.example.com", true, "LE does not allow *.*"},
		{"a.*.example.com", true, "wildcard must be leftmost"},
		{"example.com.", true, "trailing dot"},
		{"", true, "empty domain"},
		{"a..example.com", true, "empty label"},
		{".example.com", true, "leading dot"},
		{"example..com", true, "empty label in the middle"},
		{"exa mple.com", true, "contains a space"},
		{"example.com/path", true, "contains a slash"},
		{"under_score.example.com", true, "underscore is not a legal hostname character"},
		{"-lead.example.com", true, "label starts with a hyphen"},
		{"trail-.example.com", true, "label ends with a hyphen"},
		{strings.Repeat("a", 64) + ".example.com", true, "label longer than 63 characters"},
		{strings.Repeat("a", 63) + ".example.com", false, "label exactly 63 characters"},
	}

	for _, tc := range cases {
		err := validateDomain(tc.domain)
		if tc.wantErr && err == nil {
			t.Errorf("%q (%s): expected an error but got none", tc.domain, tc.why)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%q (%s): expected success but got error: %v", tc.domain, tc.why, err)
		}
	}
}

// For a wildcard with illegal characters the error should point at the real
// problem.
func TestWildcardPositionErrorIsClear(t *testing.T) {
	err := validateDomain("a.*.example.com")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "wildcard") {
		t.Errorf("the error should point at the wildcard position, got: %v", err)
	}
}
