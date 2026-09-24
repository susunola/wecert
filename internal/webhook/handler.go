package webhook

import "net/http"

// Handler returns the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Health checks need no auth: they leak nothing and liveness probes must reach
	// them.
	mux.HandleFunc("/healthz", s.handleHealth)

	mux.HandleFunc("/hook/reconcile", s.auth(s.handleReconcile))
	mux.HandleFunc("/hook/status", s.auth(s.handleStatus))
	mux.HandleFunc("/api/inventory", s.auth(s.handleInventory))
	mux.HandleFunc("/status", s.auth(s.handleInventoryPage))

	if dr, ok := s.rec.(DesiredReader); ok {
		mux.HandleFunc("/hook/desired", s.auth(s.handleDesired(dr)))
	}
	if dr, ok := s.rec.(DesiredRefresher); ok {
		mux.HandleFunc("/diagnostics/desired-state", s.auth(s.handleDesiredDiagnostic(dr)))
	}

	return mux
}
