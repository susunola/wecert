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
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
)

// errBothForms rejects requests that send both cert and certs — ambiguous, so
// refuse outright.
var errBothForms = errors.New("cert and certs are mutually exclusive")

// errEmptyCerts rejects an explicit "certs": [] or "certs": null. Both ask for
// nothing, and treating either like an absent body would silently widen it into
// a full convergence the caller never asked for.
var errEmptyCerts = errors.New("certs must not be empty; omit the body to process everything")

// errEmptyCert rejects an explicit "cert": "" or "cert": null, for the same
// reason as errEmptyCerts.
//
// This is the more likely of the two to arrive by accident: the documented call
// is {"cert":"<name>"} (README.md), so a CI job templating an unset $CERT sends
// {"cert":""} -- and widening that into "every certificate" burns issuance quota
// the caller never asked for. As a plain string it would additionally be
// indistinguishable from an absent field, which is why the field is a pointer.
var errEmptyCert = errors.New("cert must not be empty; omit the body to process everything")

// Reconciler is the convergence capability the webhook needs. Defined at the
// consumer for easy test substitution.
type Reconciler interface {
	CertNames() []string
	StartCert(ctx context.Context, name string) error
	// StartNamed starts a list of named certificates, resolving the desired state
	// once (rather than once per name: resolve() re-reads and validates the
	// document, and the whole loop runs synchronously inside one request).
	//
	// The buckets are the caller's answer body. A non-nil error means the
	// desired state could not be read, so *nothing* was started and every name
	// is unanswerable -- reporting the bucket as "unknown" would tell the caller
	// to give up on a certificate that may well exist and simply could not be
	// resolved this time.
	StartNamed(ctx context.Context, names []string) (started, alreadyRunning, unknown []string, err error)

	// StartAll reports the accepted names from the same resolution the starts
	// were made from; a non-nil error means nothing started at all (the desired
	// state is unreadable) and must not be reported as "accepted everything".
	StartAll(ctx context.Context) (accepted, skipped []string, err error)
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

// DesiredRefresher is the deliberately read-only diagnostic capability. It
// refreshes the desired-state cache (which may read DNS/CLB declarations) but
// never starts reconciliation, places an ACME order or changes cloud resources.
type DesiredRefresher interface {
	DesiredReader
	Prime(context.Context)
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
	tokenMu sync.RWMutex
	uin     string
	baseCtx context.Context
	log     *slog.Logger
	now     func() time.Time
	limiter *authLimiter

	// adminToken is the second secret for /admin/... (see config.Webhook.AdminToken).
	adminToken string
	// ops is the guarded surface's real work; nil fields are simply not mounted.
	ops AdminOps
	// auditPath is the append-only admin audit log (0600). Empty disables it.
	auditPath string
	// confirms holds one-shot restore confirm tokens with their expiry.
	confirmMu sync.Mutex
	confirms  map[string]time.Time
}

// New builds the webhook server.
//
// The empty-token check is defence in depth, not redundancy with the config
// layer: "Authorization: Bearer " would pass a constant-time compare against an
// empty configured token, so the invariant "an authed endpoint always requires a
// real token" must hold here rather than being outsourced to every caller.
// AdminOptions configures the guarded /admin surface. Optional: without AdminToken
// the routes are not mounted at all.
type AdminOptions struct {
	Token     string
	AuditPath string
	Ops       AdminOps
}

func New(rec Reconciler, store *state.Store, token string, baseCtx context.Context, log *slog.Logger) (*Server, error) {
	return NewWithAdmin(rec, store, token, AdminOptions{}, baseCtx, log)
}

// NewWithAdmin is New plus the optional admin surface.
func NewWithAdmin(rec Reconciler, store *state.Store, token string, admin AdminOptions, baseCtx context.Context, log *slog.Logger) (*Server, error) {
	if token == "" {
		return nil, errors.New("webhook: token must not be empty")
	}
	return &Server{
		rec:        rec,
		store:      store,
		token:      token,
		baseCtx:    baseCtx,
		log:        log,
		now:        time.Now,
		limiter:    newAuthLimiter(),
		adminToken: admin.Token,
		ops:        admin.Ops,
		auditPath:  admin.AuditPath,
	}, nil
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Key strictly by client IP: this endpoint sits behind no trusted proxy
		// in the default deployment, so RemoteAddr is the honest source.
		addr := clientIP(r)

		// The token is checked FIRST, and the lockout only ever applies to requests that failed
		// it. Checking the lockout first meant an unauthenticated caller spent the budget of the
		// address it shares with the legitimate one -- and the README's own deployment puts a TLS
		// terminator in front of this listener, which collapses every client onto one address. A
		// correct token then answered 429 for a renewable 15 minutes, on every hook route
		// including the read-only /hook/status. Brute force is bounded exactly as before: a wrong
		// token is counted, and after authMaxFailures the address is refused before the comparison.
		if s.tokenMatches(r) {
			// A good token is evidence this address also carries the legitimate
			// caller, so the accumulated failures are decayed -- not wiped, or one
			// interleaved success would forgive a shared-IP attacker indefinitely
			// (see recordSuccess).
			s.limiter.recordSuccess(addr, s.now())
			next(w, r)
			return
		}

		// Atomic check-and-count (see authLimiter.fail). The previous allowed() +
		// recordFailure() pair let a concurrent burst of wrong tokens all pass the
		// check before any of them counted.
		if blocked, retryAfter := s.limiter.fail(addr, s.now()); blocked {
			w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
			writeJSON(w, http.StatusTooManyRequests,
				map[string]string{"error": "too many failed authentication attempts"})
			return
		}

		s.log.Warn("webhook authentication failed",
			"remote", r.RemoteAddr, "path", r.URL.Path, "method", r.Method)
		writeJSON(w, http.StatusUnauthorized,
			map[string]string{"error": "missing or invalid token"})
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

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
	s.tokenMu.RLock()
	token := s.token
	s.tokenMu.RUnlock()
	return subtle.ConstantTimeCompare([]byte(presented), []byte(token)) == 1
}

// SetToken rotates the bearer token without rebinding the listener.  It is
// intentionally narrow: callers have already fully validated the replacement
// configuration before this method is reached.
func (s *Server) SetToken(token string) {
	s.tokenMu.Lock()
	s.token = token
	s.tokenMu.Unlock()
}

// SetAdminToken rotates the admin token without rebinding the listener, matching
// SetToken. Without it a SIGHUP after editing webhook.adminToken left the old
// token in force -- the operator believed the rotation had landed.
func (s *Server) SetAdminToken(token string) {
	s.tokenMu.Lock()
	defer s.tokenMu.Unlock()
	s.adminToken = token
}

// SetAccountUIN records the Tencent Cloud account this process deploys into.
// Empty is valid: the inventory then omits uin unless a certificate sets its own.
func (s *Server) SetAccountUIN(uin string) {
	s.uin = strings.TrimSpace(uin)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}
