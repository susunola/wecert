// Package webhook lets wecert be triggered by external events instead of only
// waiting for the timer.
//
// Typical use: call it once from CI or an event bus after a domain is added,
// without waiting for the next top of the hour.
//
// This endpoint triggers **real issuance** and consumes Let's Encrypt
// rate-limit quota, so authentication is not optional — see the token checks in
// config.Webhook.
package webhook

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/susunola/wecert/internal/reconcile"
	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
)

// errBothForms rejects requests that send both cert and certs — ambiguous, so
// refuse outright.
var errBothForms = errors.New("cert and certs are mutually exclusive")

// Reconciler is the convergence capability the webhook needs. Defined at the
// consumer for easy test substitution.
type Reconciler interface {
	CertNames() []string
	StartCert(ctx context.Context, name string) error
	StartAll(ctx context.Context) []string
}

// DesiredReader is the capability the read-only diagnostic endpoint needs.
//
// It is defined separately rather than folded into Reconciler to keep that
// endpoint an "optional read-only add-on": not implementing it simply means it
// is not mounted, the trigger path is unaffected and no test double has to
// implement it.
type DesiredReader interface {
	LastResult() *spec.Result
}

// Server provides the trigger and status endpoints.
//
// baseCtx is a **process-level** context, not a request's. The background
// convergence can run for minutes, and a request context would be cancelled the
// moment the response returns — a trigger that triggers nothing.
type Server struct {
	rec     Reconciler
	store   *state.Store
	token   string
	baseCtx context.Context
	log     *slog.Logger
	now     func() time.Time
}

// New builds the webhook server.
//
// The empty-token check is defence in depth, not redundancy with the config
// layer: "Authorization: Bearer " would pass a constant-time compare against an
// empty configured token, so the invariant "an authed endpoint always requires a
// real token" must hold here rather than being outsourced to every caller.
func New(rec Reconciler, store *state.Store, token string, baseCtx context.Context, log *slog.Logger) (*Server, error) {
	if token == "" {
		return nil, errors.New("webhook: token must not be empty")
	}
	return &Server{
		rec:     rec,
		store:   store,
		token:   token,
		baseCtx: baseCtx,
		log:     log,
		now:     time.Now,
	}, nil
}

// Handler returns the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Health checks need no auth: they leak nothing and liveness probes must reach
	// them.
	mux.HandleFunc("/healthz", s.handleHealth)

	mux.HandleFunc("/hook/reconcile", s.auth(s.handleReconcile))
	mux.HandleFunc("/hook/status", s.auth(s.handleStatus))

	if dr, ok := s.rec.(DesiredReader); ok {
		mux.HandleFunc("/hook/desired", s.auth(s.handleDesired(dr)))
	}

	return mux
}

// ── Authentication ────────────────────────────────────────────────────────────────────

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.tokenMatches(r) {
			s.log.Warn("webhook authentication failed",
				"remote", r.RemoteAddr, "path", r.URL.Path, "method", r.Method)
			writeJSON(w, http.StatusUnauthorized,
				map[string]string{"error": "missing or invalid token"})
			return
		}
		next(w, r)
	}
}

// tokenMatches accepts both forms and compares in constant time.
func (s *Server) tokenMatches(r *http.Request) bool {
	presented := ""
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		presented = strings.TrimPrefix(h, "Bearer ")
	} else if h := r.Header.Get("X-Wecert-Token"); h != "" {
		presented = h
	}

	// Constant-time comparison: a byte-by-byte compare returns at the first
	// differing character, leaking the token prefix. This endpoint is valuable
	// enough for someone to probe it bit by bit.
	return subtle.ConstantTimeCompare([]byte(presented), []byte(s.token)) == 1
}

// ── Endpoints ────────────────────────────────────────────────────────────────────

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// reconcileRequest is the trigger request body. It may be omitted entirely — no
// body means "process everything".
type reconcileRequest struct {
	Cert  string   `json:"cert"`
	Certs []string `json:"certs"`
}

type reconcileResponse struct {
	Accepted []string `json:"accepted"`
	Skipped  []string `json:"skipped,omitempty"`
	Unknown  []string `json:"unknown,omitempty"`
}

func (s *Server) handleReconcile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed,
			map[string]string{"error": "use POST"})
		return
	}

	req, err := parseTrigger(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	targets, unknown := s.resolveTargets(req)

	resp := reconcileResponse{Unknown: unknown}

	// No cert/certs means a full trigger.
	if len(targets) == 0 && len(unknown) == 0 {
		resp.Skipped = s.rec.StartAll(s.baseCtx)
		resp.Accepted = s.rec.CertNames()
		resp.Accepted = subtract(resp.Accepted, resp.Skipped)
		s.log.Info("webhook triggered a full convergence",
			"accepted", len(resp.Accepted), "skipped", len(resp.Skipped), "remote", r.RemoteAddr)
	} else {
		for _, name := range targets {
			switch err := s.rec.StartCert(s.baseCtx, name); {
			case err == nil:
				resp.Accepted = append(resp.Accepted, name)
			case errors.Is(err, reconcile.ErrAlreadyRunning):
				resp.Skipped = append(resp.Skipped, name)
			default:
				resp.Unknown = append(resp.Unknown, name)
			}
		}
		s.log.Info("webhook triggered convergence",
			"accepted", resp.Accepted, "skipped", resp.Skipped, "unknown", resp.Unknown,
			"remote", r.RemoteAddr)
	}

	// 202 rather than 200: convergence is accepted but not finished. A pass can
	// take minutes (DNS propagation), and making the caller wait would only blow
	// its timeout. To learn the result, poll /hook/status.
	writeJSON(w, http.StatusAccepted, resp)
}

// parseTrigger reads the request body. An empty body is legal and means a full
// trigger.
func parseTrigger(r *http.Request) (reconcileRequest, error) {
	var req reconcileRequest
	if r.Body == nil {
		return req, nil
	}

	// Cap the size: this is a trigger endpoint and has no reason to accept large
	// bodies.
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		return req, err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return req, nil
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return req, err
	}
	if req.Cert != "" && len(req.Certs) > 0 {
		return req, errBothForms
	}
	return req, nil
}

// resolveTargets maps requested names onto certificates that actually exist.
func (s *Server) resolveTargets(req reconcileRequest) (targets, unknown []string) {
	known := make(map[string]struct{})
	for _, n := range s.rec.CertNames() {
		known[n] = struct{}{}
	}

	wanted := req.Certs
	if req.Cert != "" {
		wanted = []string{req.Cert}
	}

	for _, n := range wanted {
		if _, ok := known[n]; ok {
			targets = append(targets, n)
		} else {
			unknown = append(unknown, n)
		}
	}
	return targets, unknown
}

// ── Status endpoint ────────────────────────────────────────────────────────────────

type certStatus struct {
	Name                string `json:"name"`
	NotAfter            string `json:"notAfter,omitempty"`
	DaysLeft            *int   `json:"daysLeft,omitempty"`
	Deployed            bool   `json:"deployed"`
	DeployConfirmed     bool   `json:"deployConfirmed"`
	ConsecutiveFailures int    `json:"consecutiveFailures"`
	NextAttemptAt       string `json:"nextAttemptAt,omitempty"`
	LastError           string `json:"lastError,omitempty"`
}

// handleStatus lets the caller look up the result after triggering.
//
// Triggering is asynchronous (202), so something must answer "did it actually
// work" — otherwise the caller can only dig through logs.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed,
			map[string]string{"error": "use GET"})
		return
	}

	now := s.now()
	out := struct {
		Time         string       `json:"time"`
		Certificates []certStatus `json:"certificates"`
	}{Time: now.UTC().Format(time.RFC3339)}

	for _, name := range s.rec.CertNames() {
		st := certStatus{Name: name}

		rec, err := s.store.GetCert(name)
		if err != nil {
			s.log.Warn("failed to read the certificate state", "cert", name, "err", err)
			out.Certificates = append(out.Certificates, st)
			continue
		}
		if rec != nil {
			if !rec.NotAfter.IsZero() {
				st.NotAfter = rec.NotAfter.UTC().Format(time.RFC3339)
				days := int(rec.NotAfter.Sub(now).Hours() / 24)
				st.DaysLeft = &days
			}
			st.Deployed = rec.DeployedCertID != ""
			st.DeployConfirmed = rec.DeployConfirmed
			st.ConsecutiveFailures = rec.ConsecutiveFailures
			st.LastError = rec.LastError
			if !rec.NextAttemptAt.IsZero() {
				st.NextAttemptAt = rec.NextAttemptAt.UTC().Format(time.RFC3339)
			}
		}
		out.Certificates = append(out.Certificates, st)
	}

	writeJSON(w, http.StatusOK, out)
}

// ── Diagnostic endpoint ────────────────────────────────────────────────────────────────

// desiredCert puts "what is desired" next to "whether it actually exists".
type desiredCert struct {
	Name     string   `json:"name"`
	Domains  []string `json:"domains"`
	Profile  string   `json:"profile"`
	KeyType  string   `json:"keyType"`
	Deploy   bool     `json:"deploy"`
	Issued   bool     `json:"issued"`
	NotAfter string   `json:"notAfter,omitempty"`
	DaysLeft *int     `json:"daysLeft,omitempty"`
}

type desiredView struct {
	Revision string `json:"revision,omitempty"`
	Frozen   bool   `json:"frozen"`

	// A non-empty FreezeReason means the source was unreadable this pass and the
	// convergence is running on the last good revision.
	FreezeReason string `json:"freezeReason,omitempty"`

	GeneratedAt string             `json:"generatedAt,omitempty"`
	Shadow      *spec.ShadowReport `json:"shadow,omitempty"`

	Certificates []desiredCert   `json:"certificates"`
	Decisions    []spec.Decision `json:"decisions"`
}

// handleDesired answers the questions most often asked once this system is in
// production:
//
//	What is the desired state?           certificates
//	Why is a domain missing?             decisions[].reason
//	Where does it differ from a source?  shadow (in observe mode)
//	Desired but does it exist for real?  certificates[].issued
//
// Without it, every one of those questions means digging through logs, and logs
// get rotated away.
func (s *Server) handleDesired(dr DesiredReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			writeJSON(w, http.StatusMethodNotAllowed,
				map[string]string{"error": "use GET"})
			return
		}

		res := dr.LastResult()
		if res == nil {
			// No desired state has ever been read successfully. That is not "the desired
			// state is empty", so returning an empty certificate list is out of the
			// question — it would be read as "nothing".
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "no desired state has been read yet; this is not the same as an empty desired state",
			})
			return
		}

		now := s.now()
		out := desiredView{
			Revision:     res.Revision,
			Frozen:       res.Frozen,
			FreezeReason: res.FreezeReason,
			Shadow:       res.Shadow,
			Decisions:    res.Decisions,
			Certificates: make([]desiredCert, 0, len(res.Certificates)),
		}
		if !res.GeneratedAt.IsZero() {
			out.GeneratedAt = res.GeneratedAt.UTC().Format(time.RFC3339)
		}

		for i := range res.Certificates {
			c := &res.Certificates[i]
			dc := desiredCert{
				Name:    c.Name,
				Domains: c.Domains,
				Profile: c.Profile,
				KeyType: c.KeyType,
				Deploy:  c.Deploy.Enabled,
			}
			if st, err := s.store.GetCert(c.Name); err == nil && st != nil && !st.NotAfter.IsZero() {
				dc.Issued = true
				dc.NotAfter = st.NotAfter.UTC().Format(time.RFC3339)
				days := int(st.NotAfter.Sub(now).Hours() / 24)
				dc.DaysLeft = &days
			}
			out.Certificates = append(out.Certificates, dc)
		}

		writeJSON(w, http.StatusOK, out)
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func subtract(all, remove []string) []string {
	if len(remove) == 0 {
		return all
	}
	drop := make(map[string]struct{}, len(remove))
	for _, n := range remove {
		drop[n] = struct{}{}
	}
	out := make([]string, 0, len(all))
	for _, n := range all {
		if _, ok := drop[n]; !ok {
			out = append(out, n)
		}
	}
	return out
}
