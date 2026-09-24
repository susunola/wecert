package webhook

import "net/http"

// handleDesiredDiagnostic refreshes just the read-side declaration pipeline.
// It exists for the incident question "can we still read what should exist?"
// without making the dangerous jump to "therefore issue and deploy now".
func (s *Server) handleDesiredDiagnostic(dr DesiredRefresher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use POST"})
			return
		}
		dr.Prime(r.Context())
		res := dr.LastResult()
		if res == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "desired state could not be read; no issuance or deployment was attempted"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"readOnly":     true,
			"revision":     res.Revision,
			"certificates": res.CertNames(),
			"count":        len(res.Certificates),
		})
	}
}
