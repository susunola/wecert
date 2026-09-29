package webhook

import (
	"encoding/json"
	"net/http"
	"strings"
)

func writeOpsMissing(w http.ResponseWriter, what string) {
	writeJSON(w, http.StatusNotFound, map[string]string{
		"error": what + " is not wired on this daemon",
	})
}

func (s *Server) handleListAccounts() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use GET"})
			return
		}
		if s.ops.ListAccounts == nil {
			writeOpsMissing(w, "accounts")
			return
		}
		out, err := s.ops.ListAccounts(r.Context())
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func (s *Server) handleListBindings() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use GET"})
			return
		}
		if s.ops.ListBindings == nil {
			writeOpsMissing(w, "bindings")
			return
		}
		out, err := s.ops.ListBindings(r.Context())
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func (s *Server) handleAdminAccounts() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use POST"})
			return
		}
		if s.ops.AddAccount == nil {
			writeOpsMissing(w, "account management")
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be JSON"})
			return
		}
		s.audit(r, "admin_add_account", map[string]any{"name": body["name"], "uin": body["uin"]})
		out, err := s.ops.AddAccount(r.Context(), body)
		if err != nil {
			s.audit(r, "admin_add_account_failed", map[string]any{"err": err.Error()})
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func (s *Server) handleAdminAccountOne() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uin := strings.TrimPrefix(r.URL.Path, "/admin/accounts/")
		if uin == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "uin required"})
			return
		}
		if r.Method != http.MethodDelete {
			w.Header().Set("Allow", "DELETE")
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use DELETE"})
			return
		}
		if s.ops.RemoveAccount == nil {
			writeOpsMissing(w, "account management")
			return
		}
		s.audit(r, "admin_remove_account", map[string]any{"uin": uin})
		out, err := s.ops.RemoveAccount(r.Context(), uin)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func (s *Server) handleAdminCertificates() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use POST"})
			return
		}
		if s.ops.CreateCertificate == nil {
			writeOpsMissing(w, "certificate management")
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be JSON"})
			return
		}
		s.audit(r, "admin_create_certificate", map[string]any{"name": body["name"]})
		out, err := s.ops.CreateCertificate(r.Context(), body)
		if err != nil {
			s.audit(r, "admin_create_certificate_failed", map[string]any{"err": err.Error()})
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func (s *Server) handleAdminCertificateOne() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/admin/certificates/")
		name := rest
		action := ""
		if i := strings.LastIndex(rest, "/"); i >= 0 {
			name, action = rest[:i], rest[i+1:]
		}
		if name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "certificate name required"})
			return
		}
		switch {
		case r.Method == http.MethodDelete && action == "":
			if s.ops.DeleteCertificate == nil {
				writeOpsMissing(w, "certificate management")
				return
			}
			s.audit(r, "admin_delete_certificate", map[string]any{"name": name})
			out, err := s.ops.DeleteCertificate(r.Context(), name)
			if err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, out)
		case r.Method == http.MethodPost && action == "bind":
			if s.ops.BindCertificate == nil {
				writeOpsMissing(w, "certificate binding")
				return
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			s.audit(r, "admin_bind_certificate", map[string]any{"name": name, "body": body})
			out, err := s.ops.BindCertificate(r.Context(), name, body)
			if err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, out)
		case r.Method == http.MethodPost && action == "unbind":
			if s.ops.UnbindCertificate == nil {
				writeOpsMissing(w, "certificate binding")
				return
			}
			s.audit(r, "admin_unbind_certificate", map[string]any{"name": name})
			out, err := s.ops.UnbindCertificate(r.Context(), name)
			if err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, out)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use DELETE on the name, or POST .../bind, POST .../unbind"})
		}
	}
}
