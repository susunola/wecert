package spec

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/susunola/wecert/internal/config"
)

// ShadowReport is the comparison of "what would happen if the shadow source won".
//
// It is the entire output of observe mode: it issues nothing and deletes
// nothing, and only answers "what would be added, removed or changed".
type ShadowReport struct {
	Revision    string    `json:"revision,omitempty"`
	GeneratedAt time.Time `json:"generatedAt,omitempty"`

	// A non-empty Error means the shadow source was unreadable this round, so
	// there is no comparison to report.
	Error string `json:"error,omitempty"`

	AddCertificates    []string            `json:"addCertificates,omitempty"`
	RemoveCertificates []string            `json:"removeCertificates,omitempty"`
	ChangeCertificates []CertificateChange `json:"changeCertificates,omitempty"`

	AddedDomains   int `json:"addedDomains"`
	RemovedDomains int `json:"removedDomains"`
}

// CertificateChange describes a change to one certificate's domain set.
type CertificateChange struct {
	Name    string   `json:"name"`
	Added   []string `json:"addedDomains,omitempty"`
	Removed []string `json:"removedDomains,omitempty"`
	Changed []string `json:"changedFields,omitempty"`
}

// Empty reports whether the shadow source agrees with what is being enforced.
func (s *ShadowReport) Empty() bool {
	if s == nil {
		return false // No comparison was produced, so do not claim agreement.
	}
	return s.Error == "" &&
		len(s.AddCertificates) == 0 && len(s.RemoveCertificates) == 0 && len(s.ChangeCertificates) == 0
}

// Observer wraps a primary source, also reads a shadow source and reports the diff.
//
// This is the mandatory stage between static and enforce, and it **changes no
// behaviour**: convergence still follows primary, the shadow only reports.
//
// It is singled out because jumping straight to automatic issuance gambles quota
// blind to the real shape of drift: how wide the debounce window must be,
// whether bulk imports or odd records exist -- questions only weeks of real data
// can answer.
type Observer struct {
	primary Provider
	shadow  Provider
	log     *slog.Logger
}

// NewObserver constructs an observer.
func NewObserver(primary, shadow Provider, log *slog.Logger) *Observer {
	if log == nil {
		log = slog.Default()
	}
	return &Observer{primary: primary, shadow: shadow, log: log}
}

// Kind implements Named.
func (o *Observer) Kind() string { return "observe(" + KindOf(o.primary) + ")" }

// Desired implements Provider and always goes through the primary source.
func (o *Observer) Desired(ctx context.Context) ([]config.Certificate, error) {
	return o.primary.Desired(ctx)
}

// DesiredWithReasons attaches a shadow comparison to the primary result.
//
// A shadow source error does **not** fail the whole evaluation: during
// observation an unreadable document is normal (generation has not started yet),
// and the correct behaviour is to converge as usual and record the fact.
func (o *Observer) DesiredWithReasons(ctx context.Context) (*Result, error) {
	res, err := Desired(ctx, o.primary)
	if err != nil {
		return nil, err
	}

	sh, err := Desired(ctx, o.shadow)
	if err != nil {
		res.Shadow = &ShadowReport{Error: err.Error()}
		o.log.Warn("cannot read the shadow desired state; there is nothing to compare against",
			"shadow", KindOf(o.shadow), "err", err)
		return res, nil
	}

	// A frozen shadow source is "no comparison", not "no differences".
	//
	// A file source never returns an error once it has read the document successfully: a later
	// unreadable revision comes back as a FROZEN result with a nil error, carrying the last good
	// revision. Comparing against that and reporting the result as a fresh diff is the false
	// confidence this mode is supposed to be free of -- the diff would be computed against a
	// document nobody can read, ShadowReport.Error would stay empty, and the gate that decides
	// whether it is safe to switch to enforce (shadow_errors_total quiet, shadow_last_read recent)
	// would report a quiet, up-to-date comparison.
	if sh.Frozen {
		res.Shadow = &ShadowReport{
			Revision:    sh.Revision,
			GeneratedAt: sh.GeneratedAt,
			Error: fmt.Sprintf("the shadow source is frozen on revision %s: %s",
				sh.Revision, sh.FreezeReason),
		}
		o.log.Warn("the shadow desired state is frozen, so there is nothing to compare against",
			"shadow", KindOf(o.shadow), "revision", sh.Revision, "reason", sh.FreezeReason)
		return res, nil
	}

	res.Shadow = Diff(res, sh)
	if !res.Shadow.Empty() {
		o.log.Warn("the shadow desired state differs from what is being enforced; "+
			"this is expected while observing -- switch desiredState.mode to \"enforce\" once the diff stays quiet",
			"shadowRevision", sh.Revision,
			"certificatesToAdd", len(res.Shadow.AddCertificates),
			"certificatesToRemove", len(res.Shadow.RemoveCertificates),
			"certificatesToChange", len(res.Shadow.ChangeCertificates))
	}
	return res, nil
}

// Diff compares the enforced desired state with the shadow one.
func Diff(enforced, shadow *Result) *ShadowReport {
	rep := &ShadowReport{Revision: shadow.Revision, GeneratedAt: shadow.GeneratedAt}

	byName := func(r *Result) map[string]*config.Certificate {
		m := make(map[string]*config.Certificate, len(r.Certificates))
		for i := range r.Certificates {
			m[r.Certificates[i].Name] = &r.Certificates[i]
		}
		return m
	}
	cur, want := byName(enforced), byName(shadow)

	for name, w := range want {
		c, ok := cur[name]
		if !ok {
			rep.AddCertificates = append(rep.AddCertificates, name)
			rep.AddedDomains += len(w.Domains)
			continue
		}
		ch := diffCert(c, w)
		if ch != nil {
			rep.ChangeCertificates = append(rep.ChangeCertificates, *ch)
			rep.AddedDomains += len(ch.Added)
			rep.RemovedDomains += len(ch.Removed)
		}
	}
	for name := range cur {
		if _, ok := want[name]; !ok {
			rep.RemoveCertificates = append(rep.RemoveCertificates, name)
			rep.RemovedDomains += len(cur[name].Domains)
		}
	}

	sort.Strings(rep.AddCertificates)
	sort.Strings(rep.RemoveCertificates)
	sort.Slice(rep.ChangeCertificates, func(i, j int) bool {
		return rep.ChangeCertificates[i].Name < rep.ChangeCertificates[j].Name
	})
	return rep
}

func diffCert(cur, want *config.Certificate) *CertificateChange {
	ch := &CertificateChange{
		Name:    cur.Name,
		Added:   onlyIn(want.Domains, cur.Domains),
		Removed: onlyIn(cur.Domains, want.Domains),
	}
	if cur.Profile != want.Profile {
		ch.Changed = append(ch.Changed, "profile")
	}
	if cur.KeyType != want.KeyType {
		ch.Changed = append(ch.Changed, "keyType")
	}
	if cur.Deploy.Enabled != want.Deploy.Enabled {
		ch.Changed = append(ch.Changed, "deploy")
	}

	if len(ch.Added) == 0 && len(ch.Removed) == 0 && len(ch.Changed) == 0 {
		return nil
	}
	return ch
}

// onlyIn returns the names in a that are not in b.
func onlyIn(a, b []string) []string {
	if len(a) == 0 {
		return nil
	}
	have := make(map[string]bool, len(b))
	for _, x := range b {
		have[x] = true
	}
	var out []string
	for _, x := range a {
		if !have[x] {
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
