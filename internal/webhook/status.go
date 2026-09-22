package webhook

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/spec"
)

// certStatus is one row of GET /hook/status.
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

	// Error reports that this certificate's state could not be read at all. Without it a read
	// failure is indistinguishable from "desired but not issued yet" (Issued simply stays
	// false) -- the same distinction certStatus.Error keeps on /hook/status.
	Error string `json:"error,omitempty"`
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
				// Say that the state could not be READ rather than answering issued=false:
				// that is the same entry "not issued yet" produces, and this endpoint is
				// where an operator checks whether a desired certificate actually exists.
				s.log.Warn("failed to read the certificate state", "cert", c.Name, "err", err)
				dc.Error = err.Error()
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
