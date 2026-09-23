package reconcile

import (
	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/probe"
)

// The read-only inventory asks the reconciler three questions it cannot answer from
// the store: is this process probing at all, what did the last probes conclude, and
// which resource types does the deployment enumerate. They are plain methods here
// rather than a wider interface, so the webhook can treat the whole capability as
// optional and say "no answer yet" when it is missing.

// ProbeEnabled reports whether this process dials deployed endpoints at all.
//
// This is configuration, not a constant. The page used to hardcode "probing is on",
// so a deployment with probe.enabled:false -- or with probe.maxHostsPerCert:0, which is
// the documented way to pause probing -- showed every deployed certificate as
// unverified and counted them under a status that claims the bindings are unknown.
func (r *Reconciler) ProbeEnabled() bool {
	if r.getProber() == nil {
		return false
	}
	return r.cfg.Probe.MaxHostsPerCertOr(config.DefaultMaxHostsPerCert) > 0
}

// ProbeAnswers returns the last answer recorded for each host of one certificate.
//
// An empty result means "no answer this process life" and is reported as such; it is
// not a match. The conditions mirror probeCert exactly (deploy enabled, deployment
// confirmed, wildcards skipped, same per-certificate cap), because a host list that
// differs from the one actually dialled would attach one certificate's answer to
// another's name.
func (r *Reconciler) ProbeAnswers(name string) []probe.Answer {
	if !r.ProbeEnabled() {
		return nil
	}
	answers, ok := r.getProber().(interface {
		Answer(host string) (probe.Answer, bool)
	})
	if !ok {
		return nil
	}
	res := r.LastResult()
	if res == nil {
		return nil
	}
	c := res.Find(name)
	if c == nil || !c.Deploy.Enabled {
		return nil
	}
	st, err := r.store.GetCert(name)
	if err != nil || st == nil || !st.DeployConfirmed {
		return nil
	}
	domains := r.issuedSANs(st)
	if len(domains) == 0 {
		domains = c.Domains
	}
	hosts := probeHosts(domains, r.cfg.Probe.MaxHostsPerCertOr(config.DefaultMaxHostsPerCert))
	out := make([]probe.Answer, 0, len(hosts))
	for _, h := range hosts {
		if a, found := answers.Answer(h); found {
			out = append(out, a)
		}
	}
	return out
}

// ResourceTypes reports what the deployment enumerates, so the page can name the
// scope of a binding count instead of leaving it unstated.
func (r *Reconciler) ResourceTypes() []string {
	return append([]string(nil), r.cfg.Tencent.ResourceTypes...)
}
