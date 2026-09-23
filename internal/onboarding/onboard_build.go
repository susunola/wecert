// Package onboarding is the "infer intent" half.
//
// It enumerates declarations, applies the grouping policy and the various fuses,
// and finally writes a desired-state document. wecert only reads that document and
// never infers anything.
//
// The boundary is deliberate: every known pitfall in this system (rate limits,
// accidental deletion, state drift) comes from "judgement", and judgement logic
// inevitably changes again and again -- new sources, tuned thresholds, fixed edge
// cases. Certificate lifecycle must stay stable, so inference has to live in its
// own component and be disposable and rewritable without affecting issuance.
//
// The five invariants that must never break, mapped to their code:
//
//	5.1 source failure ≠ name gone    → the sourceErr branch in run.gather
//	5.2 abrupt desired-state fuse     → run.fuse
//	5.3 deletion conservative by an order of magnitude
//	                                  → grace period and reference check in run.resolve
//	5.4 quota fuse                    → run.budget
//	5.5 explicit authorization        → Declaration itself + Options.Allowlist
package onboarding

import (
	"errors"
	"fmt"
	"sort"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/group"
	"github.com/susunola/wecert/internal/spec"
)

// Split out so one concern lives in one file. Same package.

func (r *run) build() {
	names := make([]string, 0, len(r.eligible))
	for n := range r.eligible {
		names = append(names, n)
	}
	sort.Strings(names)
	r.rep.Included = len(names)

	groups, err := group.GroupBy(names)
	if err != nil {
		// Reaching here means a name failed group.Normalize, although declarations were
		// validated long ago. The only possibility is a name left behind in state that
		// is no longer valid (rules tightened, say).
		r.freeze(fmt.Sprintf("cannot group the declared names: %v", err))
		return
	}

	for _, g := range groups {
		// The settings come first, because they decide the SAN cap.
		//
		// Cover used the configured default cap alone, so a group whose declarations ask for a
		// shorter profile (tlsserver / shortlived allow 25 identifiers) was split by the default
		// -- legal at 100 for classic -- and the resulting document was then rejected by
		// spec.WriteDocument on EVERY round for EVERY certificate: no document, no state, no
		// report, while Run still reported mode "written". Capping by the profile the group will
		// actually use routes that case through overLimit instead, which keeps the previous
		// revision for that certificate and says why.
		profile, keyType, deploy, err := r.groupSettings(g)
		if err != nil {
			r.overSettingsConflict(g, err)
			continue
		}

		cov, err := g.Cover(groupNameCap(r.o.opts.MaxNames, profile))
		if err != nil {
			if errors.Is(err, group.ErrTooManyNames) {
				r.overLimit(g, err)
				continue
			}
			r.freeze(fmt.Sprintf("certificate %q: %v", g.Name, err))
			return
		}

		r.certs = append(r.certs, config.Certificate{
			Name:    g.Name,
			Domains: cov.Domains,
			Profile: profile,
			KeyType: keyType,
			Deploy:  config.Deploy{Enabled: deploy},
		})

		for _, n := range append(append([]string(nil), g.Names...), g.Wildcards...) {
			reason := r.reasons[n]
			if coverer, ok := cov.Covered[n]; ok {
				// The wildcard note is ADDED to whatever reason the name already carries, not
				// written over it. Overwriting it hid the fact that a filter rejected this name
				// (the carried-by-declaration case): the report then said only "covered by the
				// wildcard", so the guard that is dropping it was invisible in the one artifact
				// an operator reads.
				note := fmt.Sprintf("covered by the declared wildcard %s, so it costs no extra issuance", coverer)
				if reason == "" {
					reason = note
				} else {
					reason += "; " + note
				}
				r.rep.CoveredByWildcard++
			} else if reason == "" {
				reason = "declared via a " + DeclarationPrefix + " TXT record"
				if r.o.opts.RequireRule && !group.IsWildcard(n) {
					reason += " and served by a CLB rule"
				}
			}
			r.include(spec.Decision{
				Hostname:    n,
				Included:    true,
				Reason:      reason,
				Certificate: g.Name,
			})
		}
	}
}

// overLimit handles a group that exceeds the SAN cap.
//
// The whole group must not be dropped: that makes wecert see a certificate vanish
// into thin air. The correct reaction is to keep the previous revision's certificate
// and shout the reason -- the fix (add a wildcard declaration, or move names to
// another group) can only be done by a human.
func (r *run) overLimit(g group.Group, cause error) {
	all := append(append([]string(nil), g.Names...), g.Wildcards...)

	if prev := r.previousCert(g.Name); prev != nil {
		r.certs = append(r.certs, *prev)
		for _, n := range all {
			r.include(spec.Decision{
				Hostname:    n,
				Included:    true,
				Reason:      fmt.Sprintf("kept at the previous revision: %v", cause),
				Certificate: g.Name,
			})
		}
		r.rep.CarriedForward += len(all)
		return
	}

	for _, n := range all {
		r.reject(n, fmt.Sprintf("cannot be expressed: %v", cause))
	}
}

func (r *run) previousCert(name string) *config.Certificate {
	if r.prev == nil {
		return nil
	}
	for i := range r.prev.Certificates {
		if r.prev.Certificates[i].Name == name {
			return &r.prev.Certificates[i]
		}
	}
	return nil
}

// groupNameCap is the SAN cap a group may use: the smaller of the configured onboarding cap and
// the cap of the profile the group will actually be issued with.
func groupNameCap(configured int, profile string) int {
	cap := configured
	if pm := config.ProfileMaxNames(profile); pm > 0 && (cap <= 0 || pm < cap) {
		cap = pm
	}
	return cap
}

// settingsStillApply reports whether a declaration a filter did not accept still contributes its
// profile / keyType / deploy settings.
//
// It does when the names it contributes are still covered this round: applyGrace carries a
// still-declared name whose filter rejected it, so the certificate keeps that name -- and it must
// also keep the settings that declaration asked for. Dropping them would rebuild the certificate
// from the onboarding defaults, which changes the document's revision, reissues the certificate,
// and can even turn deployment ON for a declaration that said deploy=0: the opposite of "the name
// keeps its coverage and nothing is reissued", and a second issuance on a guard wobble -- exactly
// what the carry exists to avoid.
func (r *run) settingsStillApply(d *Declaration) bool {
	for _, n := range d.Names() {
		if r.eligible[n] {
			return true
		}
	}
	return false
}

// groupSettings aggregates the metadata of the declarations in a group.
//
// Only declarations that survived the guards contribute: see run.accepted.
func (r *run) groupSettings(g group.Group) (profile, keyType string, deploy bool, err error) {
	profile, keyType, deploy = r.o.opts.Profile, r.o.opts.KeyType, r.o.opts.Deploy
	var profileSet, keyTypeSet, deploySet bool

	for _, d := range r.declarations {
		if !r.accepted[d.Hostname] && !r.settingsStillApply(d) {
			// Excluded this round (allowlist or guard 1) and NOT still covered: its settings
			// must not leak onto names it is not part of.
			continue
		}
		if group.RegisteredDomain(d.Hostname) != g.Registered {
			continue
		}
		if d.Profile != "" {
			if profileSet && profile != d.Profile {
				return "", "", false, fmt.Errorf("conflicting profile declarations %q and %q", profile, d.Profile)
			}
			profile = d.Profile
			profileSet = true
		}
		if d.KeyType != "" {
			if keyTypeSet && keyType != d.KeyType {
				return "", "", false, fmt.Errorf("conflicting keyType declarations %q and %q", keyType, d.KeyType)
			}
			keyType = d.KeyType
			keyTypeSet = true
		}
		if d.Deploy != nil {
			if deploySet && deploy != *d.Deploy {
				return "", "", false, fmt.Errorf("conflicting deploy declarations %t and %t", deploy, *d.Deploy)
			}
			deploy = *d.Deploy
			deploySet = true
		}
	}
	return profile, keyType, deploy, nil
}

func (r *run) overSettingsConflict(g group.Group, cause error) {
	if prev := r.previousCert(g.Name); prev != nil {
		r.certs = append(r.certs, *prev)
		for _, n := range append(append([]string(nil), g.Names...), g.Wildcards...) {
			r.include(spec.Decision{Hostname: n, Included: true, Certificate: g.Name, Reason: fmt.Sprintf("kept at the previous revision: %v", cause)})
		}
		r.rep.CarriedForward += len(g.Names) + len(g.Wildcards)
		return
	}
	for _, n := range append(append([]string(nil), g.Names...), g.Wildcards...) {
		r.reject(n, fmt.Sprintf("cannot choose group-level certificate settings: %v", cause))
	}
}

// budget is §5.4: the quota fuse.
//
// A domain-set change does **not** count as a renewal of the same name; it really
// spends "Certificates per Registered Domain" (50 / 7 days, shared across accounts).
// Half the allowance is kept in reserve, default budget 25/week; exceeding it freezes
// and alerts rather than gambling the user's quota away.
