package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// Notifier pushes renewal results to an external URL.
//
// It implements reconcile.Notifier. It lives here rather than in reconcile
// because "notify over HTTP" is only one implementation — the convergence layer
// should only know "someone wants to know the result", not how it is sent.
type Notifier struct {
	url    string
	client *http.Client
	log    *slog.Logger
}

// RenewalEvent is the event body pushed outward.
type RenewalEvent struct {
	Event     string `json:"event"`
	Cert      string `json:"cert"`
	Result    string `json:"result"` // ok | error
	Error     string `json:"error,omitempty"`
	Timestamp string `json:"timestamp"`
}

// NewNotifier builds a notifier. An empty url returns nil; callers treat nil as
// a no-op.
func NewNotifier(url string, log *slog.Logger) *Notifier {
	if url == "" {
		return nil
	}
	return &Notifier{
		url: url,
		// Notifications are best-effort, so keep the timeout short.
		client: &http.Client{Timeout: 10 * time.Second},
		log:    log,
	}
}

// Renewal pushes one event after each finished renewal attempt.
//
// Deliberately **asynchronous**: a slow or dead notification target must never
// stall the convergence loop — that is the same class of coupling error as "one
// certificate failing stalls the others".
func (n *Notifier) Renewal(ctx context.Context, certName string, reconcileErr error) {
	if n == nil {
		return
	}

	ev := RenewalEvent{
		Event:     "renewal",
		Cert:      certName,
		Result:    "ok",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	if reconcileErr != nil {
		ev.Result = "error"
		ev.Error = reconcileErr.Error()
	}

	// Detach from the caller's ctx: the convergence ctx may already be expired or
	// cancelled here, but "the renewal succeeded" is still worth sending.
	ctx = context.WithoutCancel(ctx)

	go n.send(ctx, ev)
}

func (n *Notifier) send(ctx context.Context, ev RenewalEvent) {
	body, err := json.Marshal(ev)
	if err != nil {
		n.log.Warn("failed to serialise the notification event", "cert", ev.Cert, "err", err)
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		n.log.Warn("failed to build the notification request", "cert", ev.Cert, "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		n.log.Warn("failed to deliver the renewal notification", "cert", ev.Cert, "result", ev.Result, "err", err)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode >= 300 {
		n.log.Warn("the renewal notification was rejected",
			"cert", ev.Cert, "status", resp.StatusCode)
		return
	}
	n.log.Debug("renewal notification delivered", "cert", ev.Cert, "result", ev.Result)
}
