package webhook

import "net/http"

// Handler returns the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Health checks need no auth: they leak nothing and liveness probes must reach
	// them.
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/api/session", s.handleSession())

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

	// Admin routes are always registered. adminAuth answers 404 while adminToken is
	// unset, so the surface stays closed -- and a later SIGHUP that supplies the token
	// enables it without a restart. Mounting here on a one-shot adminEnabled() check
	// made "add adminToken + SIGHUP" look like it worked while /admin/* stayed 404.
	mux.HandleFunc("/api/bindings", s.auth(s.handleListBindings()))
	mux.HandleFunc("/api/deployment", s.auth(s.handleDeploymentSettings()))
	mux.HandleFunc("/api/accounts", s.auth(s.handleListAccounts()))
	mux.HandleFunc("/admin/accounts", s.adminAuth(s.handleAdminAccounts()))
	mux.HandleFunc("/admin/accounts/", s.adminAuth(s.handleAdminAccountOne()))
	mux.HandleFunc("/admin/certificates", s.adminAuth(s.handleAdminCertificates()))
	mux.HandleFunc("/admin/notifications", s.adminAuth(s.handleNotifications))
	mux.HandleFunc("/admin/certificates/", s.adminAuth(s.handleAdminCertificateOne()))
	mux.HandleFunc("/admin/backup-health", s.adminAuth(s.handleAdminBackupHealth()))
	mux.HandleFunc("/admin/recovery-plan", s.adminAuth(s.handleAdminRecoveryPlan()))
	mux.HandleFunc("/admin/recovery-drill", s.adminAuth(s.handleAdminRecoveryDrill()))
	mux.HandleFunc("/admin/challenge", s.adminAuth(s.handleAdminChallenge()))
	mux.HandleFunc("/admin/restore", s.adminAuth(s.handleAdminRestore()))

	// Reject browser cross-origin mutations, including requests from sibling subdomains.
	// Non-browser clients without Origin/Fetch Metadata headers remain supported.
	return http.NewCrossOriginProtection().Handler(mux)
}
