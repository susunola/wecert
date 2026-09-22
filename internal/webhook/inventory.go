package webhook

import (
	"net/http"

	"github.com/susunola/wecert/internal/inventory"
	"github.com/susunola/wecert/internal/state"
)

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
		ProbeEnabled:  true,
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
	return inventory.Assemble(in)
}
