package webhook

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"
)

// AdminOps is what the guarded /admin surface can do. Each field is a seam the
// process wires to the real implementation (cmd/wecert): this package must not
// know how to restore a database -- only that someone asked, twice.
//
// All four are optional: a nil field simply is not mounted, so a deployment that
// only wants backup-health cannot accidentally expose restore.
type AdminOps struct {
	// BackupHealth reports local + remote snapshot posture (ages, last verify).
	BackupHealth func(ctx context.Context) (any, error)
	// RecoveryPlan is the non-destructive "what would a restore do" report.
	RecoveryPlan func(ctx context.Context) (any, error)
	// RecoveryDrill downloads/opens a snapshot without touching live state.
	RecoveryDrill func(ctx context.Context) (any, error)
	// Restore actually replaces the state database. Requires a confirm challenge.
	Restore func(ctx context.Context, source string) (any, error)
}

// AdminTokenMinLen is re-exported for the config comment; see config.WebhookAdminTokenMinLen.
const adminConfirmTTL = 10 * time.Minute

// adminAuth wraps a handler with the admin token check. The read-only Token cannot
// reach these routes.
func (s *Server) adminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.adminToken == "" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "admin surface is not configured"})
			return
		}
		if !s.adminTokenMatches(r) {
			s.audit(r, "admin_auth_failed", map[string]any{"path": r.URL.Path})
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid admin token"})
			return
		}
		next(w, r)
	}
}

func (s *Server) adminTokenMatches(r *http.Request) bool {
	presented := ""
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		presented = strings.TrimPrefix(h, "Bearer ")
	} else if h := r.Header.Get("X-Wecert-Admin-Token"); h != "" {
		presented = h
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(s.adminToken)) == 1
}

// handleAdminBackupHealth is read-only.
func (s *Server) handleAdminBackupHealth() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use GET"})
			return
		}
		if s.ops.BackupHealth == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "backup health is not wired"})
			return
		}
		s.audit(r, "admin_backup_health", nil)
		out, err := s.ops.BackupHealth(r.Context())
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"readOnly": true, "result": out})
	}
}

// handleAdminRecoveryPlan is non-destructive: it says what a restore would do.
func (s *Server) handleAdminRecoveryPlan() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use POST"})
			return
		}
		if s.ops.RecoveryPlan == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "recovery plan is not wired"})
			return
		}
		s.audit(r, "admin_recovery_plan", nil)
		out, err := s.ops.RecoveryPlan(r.Context())
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"readOnly": true, "result": out})
	}
}

// handleAdminRecoveryDrill is non-destructive evidence that a snapshot restores.
func (s *Server) handleAdminRecoveryDrill() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use POST"})
			return
		}
		if s.ops.RecoveryDrill == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "recovery drill is not wired"})
			return
		}
		s.audit(r, "admin_recovery_drill", nil)
		out, err := s.ops.RecoveryDrill(r.Context())
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"result": out})
	}
}

// handleAdminChallenge issues a short-lived confirm token for a destructive op.
//
// Two steps rather than a boolean in the body: a status poller that can reach the
// admin token still cannot restore by copying a JSON example -- it must first call
// here, and the token expires in adminConfirmTTL.
func (s *Server) handleAdminChallenge() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use POST"})
			return
		}
		tok := newConfirmToken()
		s.confirmMu.Lock()
		if s.confirms == nil {
			s.confirms = map[string]time.Time{}
		}
		// Drop expired while we are here; the map is small but it is unbounded otherwise.
		now := s.now()
		for k, exp := range s.confirms {
			if now.After(exp) {
				delete(s.confirms, k)
			}
		}
		s.confirms[tok] = now.Add(adminConfirmTTL)
		s.confirmMu.Unlock()
		s.audit(r, "admin_challenge_issued", map[string]any{"ttlSeconds": int(adminConfirmTTL.Seconds())})
		writeJSON(w, http.StatusOK, map[string]any{
			"confirmToken": tok,
			"expiresAt":    s.now().Add(adminConfirmTTL).UTC().Format(time.RFC3339),
			"action":       "restore",
			"hint":         "POST /admin/restore with this token in confirmToken. It expires; issue a new one if it does.",
		})
	}
}

func (s *Server) consumeConfirmToken(tok string) bool {
	if tok == "" {
		return false
	}
	s.confirmMu.Lock()
	defer s.confirmMu.Unlock()
	exp, ok := s.confirms[tok]
	if !ok {
		return false
	}
	delete(s.confirms, tok) // one-shot
	return s.now().Before(exp)
}

// handleAdminRestore is the only destructive route. It needs BOTH the admin token
// and a fresh confirm token.
func (s *Server) handleAdminRestore() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use POST"})
			return
		}
		if s.ops.Restore == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "restore is not wired"})
			return
		}
		var body struct {
			Source       string `json:"source"`
			ConfirmToken string `json:"confirmToken"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be JSON with source and confirmToken"})
			return
		}
		if body.Source == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "source is required (snapshot path, directory, or \"latest\")"})
			return
		}
		if !s.consumeConfirmToken(body.ConfirmToken) {
			s.audit(r, "admin_restore_refused", map[string]any{"source": body.Source, "reason": "missing or expired confirmToken"})
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "a short-lived confirm token is required: POST /admin/challenge first, then retry with confirmToken",
			})
			return
		}
		s.audit(r, "admin_restore_started", map[string]any{"source": body.Source})
		out, err := s.ops.Restore(r.Context(), body.Source)
		if err != nil {
			s.audit(r, "admin_restore_failed", map[string]any{"source": body.Source, "err": err.Error()})
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}
		s.audit(r, "admin_restore_done", map[string]any{"source": body.Source})
		writeJSON(w, http.StatusOK, map[string]any{"result": out})
	}
}

// audit appends one JSON line to the audit file. Best effort: a failure to write is
// logged but does not fail the request -- the operator still gets the answer, and
// the journal carries that the audit file itself is broken.
func (s *Server) audit(r *http.Request, action string, fields map[string]any) {
	if s.auditPath == "" {
		return
	}
	rec := map[string]any{
		"at":     s.now().UTC().Format(time.RFC3339Nano),
		"action": action,
		"remote": r.RemoteAddr,
		"path":   r.URL.Path,
	}
	for k, v := range fields {
		rec[k] = v
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	f, err := os.OpenFile(s.auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		s.log.Warn("cannot write the admin audit log", "path", s.auditPath, "err", err)
		return
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		s.log.Warn("cannot append to the admin audit log", "path", s.auditPath, "err", err)
	}
}

func newConfirmToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fall back to a time-based token only if the CSPRNG is broken -- the audit
		// trail still records the challenge, and restore stays two-step.
		return hex.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(b[:])
}

// ErrAdminDisabled is returned when an admin op is attempted without a token.
var ErrAdminDisabled = errors.New("webhook admin surface is not configured")
