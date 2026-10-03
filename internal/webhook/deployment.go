package webhook

import "net/http"

// Only backend capabilities are exposed; there is no console Nginx write API.
func (s *Server) handleDeploymentSettings() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use GET"})
			return
		}
		if s.ops.DeploymentSettings == nil {
			writeOpsMissing(w, "deployment capabilities")
			return
		}
		out, err := s.ops.DeploymentSettings(r.Context())
		if err != nil {
			writeOpError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}
