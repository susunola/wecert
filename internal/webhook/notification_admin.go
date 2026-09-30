package webhook

import (
	"encoding/json"
	"net/http"
)

func (s *Server) handleNotifications(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPut && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, PUT, POST")
		writeJSON(w, 405, map[string]string{"error": "use GET, PUT or POST"})
		return
	}
	if s.ops.Notifications == nil {
		writeOpsMissing(w, "notifications")
		return
	}
	body := map[string]any{}
	if r.Method != http.MethodGet {
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
		if err := dec.Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid JSON"})
			return
		}
	}
	out, err := s.ops.Notifications(r.Context(), r.Method, body)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	s.audit(r, "notification_settings", map[string]any{"method": r.Method})
	writeJSON(w, 200, out)
}
