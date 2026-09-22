package webhook

import (
	"net/http"

	"github.com/susunola/wecert/internal/inventory"
	"github.com/susunola/wecert/internal/probe"
	"github.com/susunola/wecert/internal/state"
)

// BindingReader is an optional cache of bind-resource rows. The inventory page
// uses it when present and stays store-side when not. It must not call the SSL
// API on the request path.
type BindingReader interface {
	BindingSnapshot(certID string) (inventory.Bindings, bool)
}

// DaemonFacts is the read-only daemon context the inventory cannot invent: whether
// this process probes at all, what the last probes concluded, and which resource
// types the deployment enumerates.
//
// Optional in the same way BindingReader is. A daemon that does not implement it gets
// a page that says "no answer yet" for every probe instead of one that hardcodes
// "probing is on", which is how every deployed certificate came to be reported as an
// unknown binding.
type DaemonFacts interface {
	ProbeEnabled() bool
	ProbeAnswers(certName string) []probe.Answer
	ResourceTypes() []string
}

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use GET"})
		return
	}
	writeJSON(w, http.StatusOK, s.assembleInventory())
}

func (s *Server) handleInventoryPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use GET"})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := inventory.WritePage(w, s.assembleInventory()); err != nil {
		s.log.Warn("failed to render the inventory page", "err", err)
	}
}

func (s *Server) assembleInventory() inventory.Snapshot {
	in := inventory.Input{
		Now:           s.now(),
		Names:         s.rec.CertNames(),
		Certs:         map[string]*state.CertState{},
		CertErrors:    map[string]string{},
		RevokePending: map[string]bool{},
		UIN:           s.uin,
	}
	facts, haveFacts := s.rec.(DaemonFacts)
	if haveFacts {
		in.ProbeEnabled = facts.ProbeEnabled()
		in.ResourceTypes = facts.ResourceTypes()
	}
	if dr, ok := s.rec.(DesiredReader); ok {
		if res := dr.LastResult(); res != nil {
			in.Desired = res
		}
	}

	names := append([]string(nil), in.Names...)
	if in.Desired != nil {
		names = append(names, in.Desired.CertNames()...)
	}
	seen := map[string]struct{}{}
	for _, name := range names {
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		rec, err := s.store.GetCert(name)
		if err != nil {
			s.log.Warn("failed to read the certificate state", "cert", name, "err", err)
			in.CertErrors[name] = err.Error()
			continue
		}
		if rec != nil {
			in.Certs[name] = rec
		}
	}

	reqs, err := s.store.ListRevokeRequests()
	if err != nil {
		s.log.Warn("failed to list pending revocations for the inventory", "err", err)
	} else {
		for _, req := range reqs {
			if req != nil {
				in.RevokePending[req.CertName] = true
			}
		}
	}

	// Live rows go into the assembly, not onto it afterwards. The status and the
	// summary are derived from the bindings, so a row that was assembled store-side
	// and then patched would keep saying "ok" for a certificate whose enumeration
	// came back incomplete -- and the summary would not count it either.
	if br, ok := s.rec.(BindingReader); ok {
		in.LiveBindings = map[string]inventory.Bindings{}
		for name, rec := range in.Certs {
			if rec == nil || rec.DeployedCertID == "" {
				continue
			}
			if live, hit := br.BindingSnapshot(rec.DeployedCertID); hit {
				in.LiveBindings[name] = live
			}
		}
	}
	if haveFacts {
		in.Probes = map[string][]inventory.HostSample{}
		for name := range in.Certs {
			answers := facts.ProbeAnswers(name)
			if len(answers) == 0 {
				continue
			}
			in.Probes[name] = hostSamples(answers)
		}
	}
	return inventory.Assemble(in)
}

// hostSamples converts probe answers into the page's sample rows. The served notAfter
// stays absent when the probe never read a certificate, so the JSON says "unknown"
// rather than year one.
func hostSamples(answers []probe.Answer) []inventory.HostSample {
	out := make([]inventory.HostSample, 0, len(answers))
	for _, a := range answers {
		row := inventory.HostSample{
			Host:        a.Host,
			Match:       a.Match,
			Trusted:     a.Trusted,
			ProblemKind: a.ProblemKind,
		}
		if !a.NotAfter.IsZero() {
			at := a.NotAfter
			row.NotAfter = &at
		}
		out = append(out, row)
	}
	return out
}
