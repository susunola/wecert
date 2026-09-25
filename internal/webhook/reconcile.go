package webhook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

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

type unknownNamesResponse struct {
	Error   string   `json:"error"`
	Unknown []string `json:"unknown"`
	// Present so the same parser works on both answers; always empty here -- nothing started.
	Accepted []string `json:"accepted"`
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
		if err != nil && len(accepted) == 0 && len(skipped) == 0 {
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
		if err != nil {
			// A shutdown that began mid-walk: StartAll hands back the accepted prefix with
			// the error (see reconcile.StartAll). Those passes are registered and Drain
			// waits for them, so they are honestly "accepted" and the answer stays 202 --
			// answering 503 would report passes that are running as ones that were refused.
			// The cutoff itself is named here, since the response shape has no place for it.
			s.log.Warn("the full trigger was cut short by shutdown; the accepted passes are "+
				"running and will finish, the rest were not started",
				"accepted", accepted, "skipped", skipped, "err", err, "remote", r.RemoteAddr)
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
		if err != nil && len(started) == 0 && len(running) == 0 {
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
		if err != nil {
			// Mid-walk shutdown with a partial answer (see reconcile.StartNamed): the
			// started prefix is really running and Drain waits for it, so it is reported
			// as accepted below and the cutoff is named here rather than hidden by a 503.
			s.log.Warn("the named trigger was cut short by shutdown; the started passes are "+
				"running and will finish, the rest were not started",
				"started", started, "certs", targets, "err", err, "remote", r.RemoteAddr)
		}
		resp.Accepted = append(resp.Accepted, started...)
		resp.Skipped = append(resp.Skipped, running...)
		resp.Unknown = append(resp.Unknown, notFound...)

		if len(resp.Accepted) == 0 && len(resp.Skipped) == 0 {
			s.log.Warn("trigger named no certificate this deployment manages",
				"unknown", resp.Unknown, "remote", r.RemoteAddr)
			writeJSON(w, http.StatusNotFound, unknownNamesResponse{
				Error:   "no certificate with any of those names is managed here",
				Unknown: resp.Unknown,
				// Initialised, not nil: the field is part of the shared response shape, and a
				// null would read as "no answer" to a client that iterates it -- we KNOW
				// nothing was accepted, so the honest value is an empty array.
				Accepted: []string{},
			})
			return
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

const maxTriggerBody = 64 << 10

func parseTrigger(r *http.Request) (reconcileRequest, error) {
	var req reconcileRequest
	if r.Body == nil {
		return req, nil
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return req, err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return req, nil
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(body, &keys); err != nil {
		return req, err
	}
	for k := range keys {
		if k != "cert" && k != "certs" {
			return req, fmt.Errorf("unknown field %q: the trigger accepts only \"cert\" and \"certs\"", k)
		}
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return req, err
	}
	_, req.certsPresent = keys["certs"]
	_, req.certPresent = keys["cert"]

	if req.certPresent && (req.Cert == nil || *req.Cert == "") {
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

func requestedTargets(req reconcileRequest) (targets []string) {
	var wanted []string
	if req.Cert != nil {
		wanted = []string{*req.Cert}
	} else if req.Certs != nil {
		wanted = *req.Certs
	}

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
