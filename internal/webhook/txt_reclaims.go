package webhook

import (
	"net/http"
	"time"

	"github.com/susunola/wecert/internal/acme"
)

// TXTReclaimLister is the DNS cleanup guardian's read-only queue. Implemented by the
// ACME manager; the webhook mounts this only when it is present (same optional pattern
// as DesiredReader).
type TXTReclaimLister interface {
	ListStuckTXTReclaims() ([]*acme.TXTReclaimStuck, error)
}

// handleTXTReclaims is the read-only view of leftover _acme-challenge TXT records whose
// cleanup could not be confirmed. GET only: this page exists so an operator can see what
// the guardian is still retrying and what to delete in the DNS console -- it must never
// become a second write path.
func (s *Server) handleTXTReclaims(l TXTReclaimLister) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use GET"})
			return
		}
		rows, err := l.ListStuckTXTReclaims()
		if err != nil {
			s.log.Warn("cannot list stuck TXT reclaims", "err", err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "the stuck TXT queue could not be read"})
			return
		}
		now := time.Now()
		type row struct {
			Cert         string `json:"cert"`
			Identifier   string `json:"identifier"`
			TxtName      string `json:"txtName"`
			TxtValue     string `json:"txtValue"`
			Presented    bool   `json:"presented"`
			Attempts     int    `json:"attempts"`
			LastError    string `json:"lastError,omitempty"`
			StuckSince   string `json:"stuckSince,omitempty"`
			StuckSeconds int64  `json:"stuckSeconds"`
			Summary      string `json:"summary"`
		}
		out := make([]row, 0, len(rows))
		for _, e := range rows {
			rr := row{
				Cert:       e.CertName,
				Identifier: e.Identifier,
				TxtName:    e.TxtName,
				TxtValue:   e.TxtValue,
				Presented:  e.Presented,
				Attempts:   e.Attempts,
				LastError:  e.LastError,
				Summary:    acme.DescribeStuckTXT(e, now),
			}
			if !e.StuckSince.IsZero() {
				rr.StuckSince = e.StuckSince.UTC().Format(time.RFC3339)
				rr.StuckSeconds = int64(now.Sub(e.StuckSince).Seconds())
			}
			out = append(out, rr)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"readOnly": true,
			"count":    len(out),
			"items":    out,
			"hint":     "these _acme-challenge TXT records could not be confirmed gone; the guardian retries them every pass. If one is stuck for hours, delete the name in the DNS console -- the rows carry txtName and txtValue.",
		})
	}
}
