package group

import (
	"errors"
	"reflect"
	"testing"
)

func TestRegisteredDomainUsesThePublicSuffixList(t *testing.T) {
	cases := map[string]string{
		"example.com":            "example.com",
		"api.example.com":        "example.com",
		"a.b.example.com":        "example.com",
		"*.example.com":          "example.com",
		"api.example.com.":       "example.com",
		"API.Example.COM":        "example.com",
		"example.co.uk":          "example.co.uk",
		"api.example.co.uk":      "example.co.uk",
		"deep.api.example.co.uk": "example.co.uk",
		"localhost":              "localhost",
	}

	for in, want := range cases {
		if got := RegisteredDomain(in); got != want {
			t.Errorf("RegisteredDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

// Taking the last two labels is the easy mistake here: a.b.co.uk would count as
// co.uk, bundling a whole swathe of unrelated sites into one certificate -- and
// LE counts quota by the PSL too, so both sides must use the same ruler.
func TestRegisteredDomainDoesNotJustTakeTwoLabels(t *testing.T) {
	if got := RegisteredDomain("a.b.example.co.uk"); got == "co.uk" {
		t.Fatalf("must use the PSL rather than taking two labels, got %q", got)
	}
}

// *.example.com covers exactly one label. This is the most common misunderstanding
// and the top cause of "I added a domain but it never entered the certificate".
func TestWildcardCoversExactlyOneLabel(t *testing.T) {
	cases := []struct {
		wc, host string
		want     bool
	}{
		{"*.example.com", "foo.example.com", true},
		{"*.example.com", "example.com", false}, // a wildcard does not cover its own parent name
		{"*.example.com", "a.b.example.com", false},
		{"*.example.com", "foo.example.org", false},
		{"*.a.example.com", "x.a.example.com", true},
		{"example.com", "foo.example.com", false}, // not a wildcard
	}

	for _, c := range cases {
		if got := WildcardCovers(c.wc, c.host); got != c.want {
			t.Errorf("WildcardCovers(%q, %q) = %v, want %v", c.wc, c.host, got, c.want)
		}
	}
}

// This is the most valuable rule in the whole design: once *.example.com is
// declared, adding foo.example.com does not touch the SAN set, i.e. 0 issuances.
// Without it, bulk-importing 50 subdomains is 50 re-issues = quota blown.
func TestCoveredNamesDoNotEnterTheSANSet(t *testing.T) {
	g := Group{
		Registered: "example.com",
		Name:       "example-com",
		Wildcards:  []string{"*.example.com"},
		Names:      []string{"api.example.com", "example.com", "www.example.com"},
	}

	cov, err := g.Cover(100)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"example.com", "*.example.com"}
	if !reflect.DeepEqual(cov.Domains, want) {
		t.Errorf("SAN set = %v, want %v", cov.Domains, want)
	}
	for _, n := range []string{"api.example.com", "www.example.com"} {
		if cov.Covered[n] != "*.example.com" {
			t.Errorf("%s must be recorded as covered by *.example.com, got %q", n, cov.Covered[n])
		}
	}
	if _, ok := cov.Covered["example.com"]; ok {
		t.Error("example.com must not be covered by *.example.com")
	}
}

// With no wildcard, every name has to enter the SAN set on its own.
func TestWithoutWildcardsEveryNameEntersTheSANSet(t *testing.T) {
	g := Group{
		Registered: "example.com",
		Name:       "example-com",
		Names:      []string{"www.example.com", "example.com", "api.example.com"},
	}

	cov, err := g.Cover(100)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"example.com", "api.example.com", "www.example.com"}
	if !reflect.DeepEqual(cov.Domains, want) {
		t.Errorf("SAN set = %v, want %v (registered domain first, the rest lexicographic)", cov.Domains, want)
	}
}

// It must never invent a wildcard: that lets the certificate handshake for any
// subdomain, which is privilege expansion and must be an explicit declaration.
func TestCoverNeverInventsAWildcard(t *testing.T) {
	g := Group{
		Registered: "example.com",
		Name:       "example-com",
		Names:      []string{"a.example.com", "b.example.com"},
	}

	cov, err := g.Cover(100)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range cov.Domains {
		if IsWildcard(d) {
			t.Fatalf("a wildcard %q appeared although none was declared", d)
		}
	}
}

// Name derives from the registered domain alone and never follows the domain set.
//
// Once that breaks, adding one domain conjures a new record in the state store
// and the old record's order URL, ARI certID and deployed CertID all become orphans.
func TestCertNameIsStableAsDomainsChange(t *testing.T) {
	before, err := GroupBy([]string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	after, err := GroupBy([]string{"example.com", "api.example.com", "*.example.com", "www.example.com"})
	if err != nil {
		t.Fatal(err)
	}

	if len(before) != 1 || len(after) != 1 {
		t.Fatalf("expected exactly one group, got %d / %d", len(before), len(after))
	}
	if before[0].Name != after[0].Name {
		t.Fatalf("certificate name followed the domain set: %q -> %q", before[0].Name, after[0].Name)
	}
	if before[0].Name != "example-com" {
		t.Errorf("certificate name = %q, want example-com", before[0].Name)
	}
}

// CertName must be injective: two different registered domains may never produce
// the same certificate name.
//
// A plain "." -> "-" rewrite collides whenever one domain has a dot exactly where
// the other has a hyphen. That is fatal rather than cosmetic: the two groups both
// claim the same Name, so WriteDocument fails with "certificate name %q is
// duplicated" on every round, -force does not help, and no certificate is ever
// updated again.
func TestCertNameIsInjective(t *testing.T) {
	pairs := [][2]string{
		{"a.co.uk", "a-co.uk"},       // multi-label public suffix
		{"foo.com.au", "foo-com.au"}, // same shape, different suffix
		{"x.org.uk", "x-org.uk"},     //
		{"a.com", "a-com"},           // single-label fallback path
	}
	for _, p := range pairs {
		na, nb := CertName(p[0]), CertName(p[1])
		if na == nb {
			t.Errorf("CertName(%q) and CertName(%q) both give %q: the mapping is not injective",
				p[0], p[1], na)
		}
	}
}

// The end-to-end consequence: declaring two colliding registered domains has to
// yield two groups with distinct names.
func TestGroupByGivesCollidingRegisteredDomainsDistinctNames(t *testing.T) {
	groups, err := GroupBy([]string{"a.co.uk", "a-co.uk"})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 {
		t.Fatalf("want 2 groups, got %d: %+v", len(groups), groups)
	}
	if groups[0].Name == groups[1].Name {
		t.Fatalf("both registered domains produced the certificate name %q; "+
			"WriteDocument would then reject the document every round", groups[0].Name)
	}
}

// Only registered domains containing a hyphen change name under the injective
// mapping, and only once: everything else has to stay byte-for-byte the same, or
// existing deployments get a spurious new certificate.
func TestCertNameKeepsHyphenFreeNamesUnchanged(t *testing.T) {
	unchanged := map[string]string{
		"example.com": "example-com",
		"a.co.uk":     "a-co-uk",
		"x.org.uk":    "x-org-uk",
	}
	for in, want := range unchanged {
		if got := CertName(in); got != want {
			t.Errorf("CertName(%q) = %q, want %q", in, got, want)
		}
	}

	// A literal dash is doubled, which is what buys injectivity.
	changed := map[string]string{
		"my-site.com":   "my--site-com",
		"a-co.uk":       "a--co-uk",
		"my-site.co.uk": "my--site-co-uk",
	}
	for in, want := range changed {
		if got := CertName(in); got != want {
			t.Errorf("CertName(%q) = %q, want %q", in, got, want)
		}
	}
}

// Identical input must yield byte-for-byte identical output, in the same order;
// otherwise every generated document diffs all over and reviewability is zero.
func TestGroupByIsIdempotent(t *testing.T) {
	in := []string{"b.example.com", "a.example.com", "*.example.com", "example.com", "A.EXAMPLE.COM"}
	first, err := GroupBy(in)
	if err != nil {
		t.Fatal(err)
	}
	second, err := GroupBy(in)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("two GroupBy runs differ:\n%+v\n%+v", first, second)
	}
	if len(first) != 1 {
		t.Fatalf("expected exactly one group, got %d", len(first))
	}
	if !reflect.DeepEqual(first[0].Names, []string{"a.example.com", "b.example.com", "example.com"}) {
		t.Errorf("concrete names must be deduplicated, lowercased and sorted, got %v", first[0].Names)
	}
}

func TestGroupBySplitsByRegisteredDomain(t *testing.T) {
	got, err := GroupBy([]string{"a.example.com", "b.example.net", "c.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected two groups, got %d: %+v", len(got), got)
	}
	// Sort by certificate name to keep the order stable.
	if got[0].Name != "example-com" || got[1].Name != "example-net" {
		t.Errorf("groups must be ordered by certificate name, got %q, %q", got[0].Name, got[1].Name)
	}
}

// Exceeding the SAN limit returns a recognizable error so callers keep the
// previous revision instead of dropping the whole group.
func TestCoverRejectsOversizedGroups(t *testing.T) {
	var names []string
	for _, p := range []string{"a", "b", "c", "d"} {
		names = append(names, p+".example.com")
	}
	g := Group{Registered: "example.com", Name: "example-com", Names: names}

	if _, err := g.Cover(3); !errors.Is(err, ErrTooManyNames) {
		t.Fatalf("must return ErrTooManyNames, got %v", err)
	}
	if _, err := g.Cover(4); err != nil {
		t.Fatalf("exactly at the limit must pass, got %v", err)
	}
}

func TestNormalizeRejectsInvalidNames(t *testing.T) {
	for _, bad := range []string{"", " ", "a..example.com", "-bad.example.com", "a.*.example.com"} {
		if _, err := Normalize(bad); err == nil {
			t.Errorf("Normalize(%q) must fail", bad)
		}
	}
	if got, err := Normalize(" API.Example.COM. "); err != nil || got != "api.example.com" {
		t.Errorf("Normalize must accept and normalize case and a trailing dot, got %q, %v", got, err)
	}
}
