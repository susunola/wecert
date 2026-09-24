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
	if g, ok := s.rec.(TXTReclaimLister); ok {
		mux.HandleFunc("/diagnostics/txt-reclaims", s.auth(s.handleTXTReclaims(g)))
	}

	// Guarded admin surface. Mounted only when an admin token is configured: a
	// read-only token (Token) cannot reach these routes, and without AdminToken the
	// process stays read-only over the network.
	if s.adminToken != "" {
		mux.HandleFunc("/admin/backup-health", s.adminAuth(s.handleAdminBackupHealth()))
		mux.HandleFunc("/admin/recovery-plan", s.adminAuth(s.handleAdminRecoveryPlan()))
		mux.HandleFunc("/admin/recovery-drill", s.adminAuth(s.handleAdminRecoveryDrill()))
		mux.HandleFunc("/admin/challenge", s.adminAuth(s.handleAdminChallenge()))
		mux.HandleFunc("/admin/restore", s.adminAuth(s.handleAdminRestore()))
	}

	return mux
}
