// Package group turns "names declared to need certificates" into certificate groups.
//
// These rules are not an optional optimization: they directly decide how fast
// Let's Encrypt quota burns. One change to the domain set is one new certificate,
// spending real "Certificates per Registered Domain" quota (50 / 7 days, shared
// across accounts); wildcard-first can cut "add a subdomain" from 1 issuance to 0.
//
// Two properties must be pinned down:
//  1. Idempotent: identical input always yields identical output, in the same order
//  2. Name-stable: names derive only from the grouping key, never from the domain set
//
// Once property 2 breaks, adding one domain conjures a new record in the state
// store and the old record's order URL, ARI certID and deployed CertID all become
// orphans -- "at most one in-flight order per certificate" stops holding, both
// orders fly at once, and they hit the exact-set rate limit (no override).
package group

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/susunola/wecert/internal/config"
)

// Normalize normalizes a declared name: trim space, lowercase, strip a trailing
// dot, and validate.
func Normalize(raw string) (string, error) {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if n == "" {
		return "", errors.New("empty name")
	}
	if err := config.ValidateDomain(n); err != nil {
		return "", err
	}
	return n, nil
}

// IsWildcard reports whether the name is a wildcard, shaped like *.example.com.
//
// The input must already be normalized (see Normalize: lowercased, trailing dot stripped);
// the check is a byte-level prefix test.
func IsWildcard(name string) bool { return strings.HasPrefix(name, "*.") }

// Base strips the wildcard prefix and returns the parent name it hangs off.
//
// The input must already be normalized (see Normalize); the strip is byte-level.
func Base(name string) string { return strings.TrimPrefix(name, "*.") }

// RegisteredDomain returns the host's registered domain (eTLD+1).
//
// It uses the Public Suffix List rather than a naive "take the last two labels":
// the latter counts a.b.co.uk as co.uk, bundling a whole swathe of unrelated
// sites into one certificate -- and LE counts quota by the PSL too, so both sides
// must use the same ruler.
func RegisteredDomain(host string) string {
	h := Base(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), "."))
	if h == "" {
		return ""
	}
	if net.ParseIP(h) != nil {
		return h
	}
	etld1, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err != nil {
		// Single-label hostname ("localhost") or no PSL entry: fall back to itself.
		return h
	}
	return etld1
}

// CertName derives the certificate name from the grouping key.
//
// This is where Name stability lands: the input can only be the registered
// domain, never the domain set.
//
// The mapping also has to be **injective**. Two registered domains that collapse
// to the same certificate name make the whole document invalid ("certificate
// name %q is duplicated"), so WriteDocument fails on every round and no
// certificate is ever updated again. A naive `.` -> `-` mapping collides:
//
//	a.co.uk  vs a-co.uk
//	a.com    vs a-com
//
// So a literal `-` is doubled before dots become dashes:
//
//	a.co.uk  -> a-co-uk
//	a-co.uk  -> a--co-uk
//
// Decoding is unambiguous -- scan for `--` first (a literal dash); a lone `-`
// was a dot -- which is what makes the map injective. Registered domains
// without a hyphen are named exactly as before.
//
// Two caveats, both outside the injection argument above rather than violations of
// it, recorded here so the claim is not read as stronger than it is:
//
//   - `:` is replaced by `-` as well, and a colon is invalid in a hostname
//     (validateDomain rejects it), so no two *registered domains* collide over it.
//     For an arbitrary string -- RegisteredDomain falls back to the raw input for a
//     single-label host -- the mapping is not injective: "a.co:uk" and "a.co-uk" both
//     become "a--co--uk". Every caller passes a hostname, so this is unreachable
//     today; if that ever stops being true, the colon rule needs its own escape.
//   - a leading/trailing dash is trimmed, which maps distinct malformed inputs onto
//     one name for the same reason.
func CertName(registered string) string {
	s := strings.ReplaceAll(strings.ToLower(registered), "-", "--")
	s = strings.NewReplacer(".", "-", ":", "-").Replace(s)
	// Only ever strips a leading/trailing dash from a malformed hostname: the
	// inputs are registered domains, which by RFC 1123 cannot start or end with
	// one. Kept because RegisteredDomain falls back to the raw hostname.
	return strings.Trim(s, "-")
}

// Group is the set of declarations under one registered domain.
type Group struct {
	// Registered is the eTLD+1.
	Registered string

	// Name is the certificate name, derived from Registered alone.
	Name string

	// Wildcards are the declared wildcards, sorted.
	Wildcards []string

	// Names are the declared concrete names, sorted.
	Names []string
}

// GroupBy groups declarations by registered domain.
//
// The result is sorted by certificate name so identical input yields
// byte-for-byte identical output.
func GroupBy(declared []string) ([]Group, error) {
	byReg := make(map[string]*Group)
	seen := make(map[string]map[string]struct{}) // registered domain -> names already recorded
	for _, raw := range declared {
		n, err := Normalize(raw)
		if err != nil {
			return nil, fmt.Errorf("declared name %q: %w", raw, err)
		}
		reg := RegisteredDomain(n)
		if reg == "" {
			return nil, fmt.Errorf("declared name %q has no registered domain", raw)
		}

		g := byReg[reg]
		if g == nil {
			g = &Group{Registered: reg, Name: CertName(reg)}
			byReg[reg] = g
			seen[reg] = make(map[string]struct{})
		}
		// Dedup runs against a per-group set rather than a scan of the slices: a bulk import
		// declares thousands of names under one registered domain, and a linear membership
		// check per declaration makes exactly that case quadratic.
		if _, dup := seen[reg][n]; dup {
			continue
		}
		seen[reg][n] = struct{}{}
		if IsWildcard(n) {
			g.Wildcards = append(g.Wildcards, n)
		} else {
			g.Names = append(g.Names, n)
		}
	}

	out := make([]Group, 0, len(byReg))
	for _, g := range byReg {
		sort.Strings(g.Wildcards)
		sort.Strings(g.Names)
		// Wildcard-first: must it come first here? No. This only sorts; Cover chooses.
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Coverage is the minimal SAN set needed to cover a group's declarations.
type Coverage struct {
	// Domains is the SAN set, in stable order.
	Domains []string

	// Covered records which names are covered by which wildcard, so they need no
	// separate SAN entry. The table is part of observability: it answers "why
	// didn't the subdomain I added show up in the certificate?".
	Covered map[string]string
}

// ErrTooManyNames means a group's SAN set exceeds the profile's limit.
//
// Callers must **not** read it as "drop this group": the correct reaction is to
// keep the previous desired state and alert. Dropping it makes wecert see a
// certificate vanish into thin air.
var ErrTooManyNames = errors.New("group exceeds the profile's max number of names")

// Cover computes the minimal SAN set needed to cover every declaration in the group.
//
// Rules:
//   - declared wildcards go into the SAN set as-is
//   - names covered by a declared wildcard do not (this is where quota is saved)
//   - every remaining name goes in on its own
//
// Note that it never **invents a wildcard**: adding a *.example.com means the
// certificate can complete a handshake for any subdomain, which is privilege
// expansion and must be an explicit declaration.
//
// A maxNames <= 0 means no limit: the check below only runs when it is positive, so a
// profile that leaves the limit unset asks for every declaration to fit, however many
// that is.
func (g Group) Cover(maxNames int) (*Coverage, error) {
	cov := &Coverage{Covered: make(map[string]string, len(g.Names))}

	uncovered := make([]string, 0, len(g.Names))
	for _, n := range g.Names {
		coverer := ""
		for _, w := range g.Wildcards {
			if WildcardCovers(w, n) {
				coverer = w
				break
			}
		}
		if coverer != "" {
			cov.Covered[n] = coverer
			continue
		}
		uncovered = append(uncovered, n)
	}
	sort.Strings(uncovered)

	domains := make([]string, 0, len(g.Wildcards)+len(uncovered))
	// The registered domain goes first: classic promotes the first dNSName to
	// Subject CN, and a bare domain reads far better as CN than some subdomain.
	if i := sort.SearchStrings(uncovered, g.Registered); i < len(uncovered) && uncovered[i] == g.Registered {
		domains = append(domains, g.Registered)
		uncovered = append(uncovered[:i], uncovered[i+1:]...)
	}
	domains = append(domains, g.Wildcards...)
	domains = append(domains, uncovered...)
	cov.Domains = domains

	if maxNames > 0 && len(domains) > maxNames {
		return nil, fmt.Errorf(
			"%w: certificate %q needs %d names (%d declared, %d covered by wildcards), max is %d; "+
				"declare a wildcard for one of the busier sub-namespaces, or move some names to another group",
			ErrTooManyNames, g.Name, len(domains), len(g.Names)+len(g.Wildcards),
			len(cov.Covered), maxNames)
	}
	return cov, nil
}

// WildcardCovers reports whether wildcard wc covers host.
//
// It covers **one** label only: *.example.com covers foo.example.com, but not
// example.com (the most common misunderstanding) and not a.b.example.com.
//
// Both names must already be normalized (see Normalize: lowercased, trailing dot
// stripped); the comparison is byte-level, so "FOO.Example.COM." is not covered by
// "*.example.com".
func WildcardCovers(wc, host string) bool {
	if !IsWildcard(wc) {
		return false
	}
	parent := Base(wc)
	if host == parent {
		return false
	}
	rest, ok := strings.CutSuffix(host, "."+parent)
	if !ok {
		return false
	}
	return rest != "" && !strings.Contains(rest, ".")
}
