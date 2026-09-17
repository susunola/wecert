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
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/susunola/wecert/internal/config"
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
	limiter *authLimiter
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
		limiter: newAuthLimiter(),
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
		// Key strictly by client IP: this endpoint sits behind no trusted proxy
		// in the default deployment, so RemoteAddr is the honest source.
		addr := clientIP(r)

		if ok, retryAfter := s.limiter.allowed(addr, s.now()); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
			writeJSON(w, http.StatusTooManyRequests,
				map[string]string{"error": "too many failed authentication attempts"})
			return
		}

		if !s.tokenMatches(r) {
			s.limiter.recordFailure(addr, s.now())
			s.log.Warn("webhook authentication failed",
				"remote", r.RemoteAddr, "path", r.URL.Path, "method", r.Method)
			writeJSON(w, http.StatusUnauthorized,
				map[string]string{"error": "missing or invalid token"})
			return
		}

		// A good token is evidence this address also carries the legitimate
		// caller, so the accumulated failures are decayed -- not wiped, or one
		// interleaved success would forgive a shared-IP attacker indefinitely
		// (see recordSuccess).
		s.limiter.recordSuccess(addr, s.now())
		next(w, r)
	}
}

// clientIP strips the port from RemoteAddr. It always carries one for HTTP
// requests, but fall back to the raw value rather than keying on "" if not.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
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
//
// Both fields are pointers so "field absent" (full trigger) is distinguishable
// from an explicit empty value, which asks for nothing and is rejected. Presence
// is additionally tracked separately because a pointer alone cannot make that
// distinction for a JSON null: encoding/json leaves both "certs" absent and
// "certs": null as a nil pointer, and null is what a Go caller marshalling a nil
// []string sends.
//
// Cert needs the same presence flag for the same reason, and the empty string
// makes it the more dangerous of the two: "cert" absent and "cert": "" are both
// the zero value there.
type reconcileRequest struct {
	Cert  *string   `json:"cert"`
	Certs *[]string `json:"certs"`

	// certsPresent reports that the body carried a "certs" key at all.
	certsPresent bool
	// certPresent reports that the body carried a "cert" key at all.
	certPresent bool
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

	// Cap the body with MaxBytesReader rather than a LimitReader.
	//
	// LimitReader reports a clean EOF at the cap, so an oversized body was silently truncated and
	// then parsed as if it were the whole request: a body cut at a valid JSON boundary was accepted,
	// and one cut mid-value failed as "invalid JSON", which sends the caller looking at their JSON
	// instead of at the size. MaxBytesReader reports the overflow, and the two answers stay apart.
	r.Body = http.MaxBytesReader(w, r.Body, maxTriggerBody)

	req, err := parseTrigger(r)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{
				"error": fmt.Sprintf("request body exceeds %d bytes", maxTriggerBody),
			})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	targets := requestedTargets(req)

	// Initialised, not nil: a trigger where nothing was accepted otherwise answers
	// `{"accepted": null, "skipped": [...]}`, and this package's own /hook/status documents the
	// convention that "clients that iterate the field read null as 'no answer'". An empty array is
	// the honest answer here -- we know nothing was accepted.
	resp := reconcileResponse{Accepted: []string{}}

	// No cert/certs means a full trigger.
	if len(targets) == 0 {
		accepted, skipped, err := s.rec.StartAll(s.baseCtx)
		if err != nil {
			// Two causes, both "nothing started", and both an answer of 202
			// with every certificate "accepted" would misreport as a
			// convergence that is on its way: the desired state is unreadable,
			// or the process is shutting down -- the HTTP server's shutdown is
			// asynchronous, so a trigger can still arrive while the reconciler
			// is draining and refuses new passes.
			s.log.Warn("full trigger failed: the desired state is unreadable or the process is shutting down",
				"err", err, "remote", r.RemoteAddr)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}
		// append, not assign: StartAll hands back a nil slice when it accepted nothing, and
		// assigning it would undo the initialisation above -- a full trigger that skipped every
		// certificate answered `{"accepted": null}`, the exact shape the comment rules out. The
		// named-trigger branch below already appends, which is why only this one regressed.
		resp.Accepted = append(resp.Accepted, accepted...)
		resp.Skipped = append(resp.Skipped, skipped...)
		s.log.Info("webhook triggered a full convergence",
			"accepted", len(resp.Accepted), "skipped", len(resp.Skipped), "remote", r.RemoteAddr)
	} else {
		// Resolve the desired state once for the whole list rather than once per name.
		// StartCert resolves internally, and resolve() is a file read plus a YAML decode,
		// a full validation and a document hash -- all synchronously inside this request,
		// which has a 15s write timeout.
		started, running, notFound, err := s.rec.StartNamed(s.baseCtx, targets)
		if err != nil {
			// Anything else -- an unreadable desired state, or a process that is
			// already draining and refuses new passes -- is a transient internal
			// failure, not "not managed". Reporting it in unknown would tell the
			// caller to give up on a certificate that may well exist and simply
			// could not be resolved this time.
			s.log.Warn("trigger failed: cannot resolve the desired state, or the process is shutting down",
				"certs", targets, "err", err, "remote", r.RemoteAddr)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}
		// The buckets are StartNamed's answer, from the desired state it just resolved. They used
		// to come from a pre-filter against CertNames(), the cache refreshed once per pass, and
		// that inverted the answer for exactly the flow this endpoint exists for: a name added
		// since the last pass was reported "not in the configuration" and -- because the pre-filter
		// had already emptied the target list -- the fresh resolution inside StartNamed never ran,
		// so the certificate was not started either. The caller was told the opposite of the truth
		// and issuance waited up to a full interval.
		resp.Accepted = append(resp.Accepted, started...)
		resp.Skipped = append(resp.Skipped, running...)
		resp.Unknown = append(resp.Unknown, notFound...)
		s.log.Info("webhook triggered convergence",
			"accepted", resp.Accepted, "skipped", resp.Skipped, "unknown", resp.Unknown,
			"remote", r.RemoteAddr)
	}

	// 202 rather than 200: convergence is accepted but not finished. A pass can
	// take minutes (DNS propagation), and making the caller wait would only blow
	// its timeout. To learn the result, poll /hook/status.
	writeJSON(w, http.StatusAccepted, resp)
}

// maxTriggerBody bounds a trigger request body. This endpoint names certificates; it has no
// legitimate large payload.
const maxTriggerBody = 64 << 10

// parseTrigger reads the request body. An empty body is legal and means a full
// trigger.
func parseTrigger(r *http.Request) (reconcileRequest, error) {
	var req reconcileRequest
	if r.Body == nil {
		return req, nil
	}

	// The caller has already wrapped the body in http.MaxBytesReader (see handleReconcile), so an
	// oversized request surfaces here as an error rather than as a truncated read.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return req, err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return req, nil
	}
	// Decode the keys first: whether "certs" appeared at all decides what the
	// request means, and the struct decode alone would report "absent" for a
	// "certs": null body. Treating that as "absent" escalates a caller that named
	// no certificates into a full-fleet convergence, burning issuance quota it
	// never asked for.
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(body, &keys); err != nil {
		return req, err
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return req, err
	}
	_, req.certsPresent = keys["certs"]
	_, req.certPresent = keys["cert"]

	if req.certPresent && (req.Cert == nil || *req.Cert == "") {
		// "cert": "" and "cert": null both ask for nothing; the presence key is what
		// tells a null apart from an absent field (both leave the pointer nil).
		// Treating either as absent is what made an unset $CERT in a CI template
		// trigger the whole fleet.
		return req, errEmptyCert
	}
	if req.certsPresent {
		if req.Certs == nil || len(*req.Certs) == 0 {
			return req, errEmptyCerts
		}
		if req.Cert != nil {
			return req, errBothForms
		}
	}
	return req, nil
}

// resolveTargets maps requested names onto certificates that actually exist.
// requestedTargets returns the names a trigger asked for, deduplicated and in order.
//
// It deliberately does NOT classify them. CertNames() reads the cache that a pass refreshes, while
// StartNamed resolves the desired-state document itself, so classifying here answers an older
// question than the one the caller asked -- and answering it here also decides whether StartNamed
// gets to run at all. Whether a name exists, is already running, or was started is StartNamed's
// answer to give.
func requestedTargets(req reconcileRequest) (targets []string) {
	var wanted []string
	if req.Cert != nil {
		wanted = []string{*req.Cert}
	} else if req.Certs != nil {
		wanted = *req.Certs
	}

	// Duplicates in the request would be started twice: the second start lands in
	// "already running", so one name would show up as both accepted and skipped.
	seen := make(map[string]struct{}, len(wanted))
	for _, n := range wanted {
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		targets = append(targets, n)
	}
	return targets
}

// ── Status endpoint ────────────────────────────────────────────────────────────────

type certStatus struct {
	Name                string `json:"name"`
	NotAfter            string `json:"notAfter,omitempty"`
	DaysLeft            *int   `json:"daysLeft,omitempty"`
	Uploaded            bool   `json:"uploaded"`
	DeployConfirmed     bool   `json:"deployConfirmed"`
	ConsecutiveFailures int    `json:"consecutiveFailures"`
	NextAttemptAt       string `json:"nextAttemptAt,omitempty"`
	LastError           string `json:"lastError,omitempty"`

	// Error reports that this certificate's state could not be read at all. Without it the entry
	// is the zero value, which a caller cannot tell from "no state recorded yet".
	Error string `json:"error,omitempty"`
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
	names := s.rec.CertNames()
	out := struct {
		Time         string       `json:"time"`
		Certificates []certStatus `json:"certificates"`
	}{Time: now.UTC().Format(time.RFC3339)}

	// Preallocate so an empty certificate list serializes as [] rather than
	// null -- clients that iterate the field treat null as "no answer".
	out.Certificates = make([]certStatus, 0, len(names))

	for _, name := range names {
		st := certStatus{Name: name}

		rec, err := s.store.GetCert(name)
		if err != nil {
			// Say that the state could not be READ, rather than answering with the zero value.
			//
			// The zero certStatus is indistinguishable from "this certificate has no state yet",
			// so a caller polling after a trigger could not tell "the store is unreadable" from
			// "nothing happened" -- on the endpoint whose whole job is to answer whether the
			// trigger worked.
			s.log.Warn("failed to read the certificate state", "cert", name, "err", err)
			st.Error = err.Error()
			out.Certificates = append(out.Certificates, st)
			continue
		}
		if rec != nil {
			if !rec.NotAfter.IsZero() {
				st.NotAfter = rec.NotAfter.UTC().Format(time.RFC3339)
				// config.DaysUntil rounds up, matching wecert-probe: truncation makes
				// "23 hours left" read as 0 days, and a caller that treats 0 as expired
				// reads a healthy certificate as down.
				days := config.DaysUntil(rec.NotAfter, now)
				st.DaysLeft = &days
			}
			// `uploaded` is "we hold a CertId", `deployConfirmed` is "it is bound".
			// They used to share the name `deployed` with the metric
			// wecert_certificate_deployed, which means the *confirmed* thing -- the exact
			// confusion that metric's help text was written to prevent.
			st.Uploaded = rec.DeployedCertID != ""
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
			st, err := s.store.GetCert(c.Name)
			if err != nil {
				s.log.Warn("failed to read the certificate state", "cert", c.Name, "err", err)
			} else if st != nil && !st.NotAfter.IsZero() {
				dc.Issued = true
				dc.NotAfter = st.NotAfter.UTC().Format(time.RFC3339)
				days := config.DaysUntil(st.NotAfter, now)
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
