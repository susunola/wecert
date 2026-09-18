package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// maxNotifyInFlight caps outstanding notification POSTs.
const maxNotifyInFlight = 8

type Notifier struct {
	url    string
	secret string
	client *http.Client
	log    *slog.Logger
	sem    chan struct{}

	// mu guards draining, which is only ever set once.
	mu sync.Mutex
	// draining stops new notifications from being accepted, so Drain has a fixed set of
	// in-flight sends to wait for instead of racing a moving target.
	draining bool
}

type RenewalEvent struct {
	Event     string `json:"event"`
	Cert      string `json:"cert"`
	Result    string `json:"result"`
	Error     string `json:"error,omitempty"`
	Timestamp string `json:"timestamp"`
}

// NewNotifier builds a notifier. An empty url returns nil; an empty secret
// simply skips the signature.
//
// When secret is set, every POST carries X-Wecert-Signature:
// sha256=<hex HMAC-SHA256 of the raw body>. The receiver can then tell a genuine
// renewal event from anything else that can reach its URL — the notify target is
// often a public endpoint that also accepts other traffic.
func NewNotifier(url, secret string, log *slog.Logger) *Notifier {
	if url == "" {
		return nil
	}
	return &Notifier{
		url:    url,
		secret: secret,
		client: &http.Client{
			Timeout: 10 * time.Second,
			// Redirects are refused rather than followed.
			//
			// The Go default follows up to ten of them, and every hop is wrong for this request:
			// a 301/302/303 turns the signed POST into a bodiless GET at the new location (the
			// event is lost, and a receiver that answers the GET with 200 is reported as a
			// delivery), and a 307/308 re-sends the body -- with the X-Wecert-Signature header --
			// to whatever host the redirect names. Treating it as a failure tells the operator
			// that the notify target moved, which is the actionable truth.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("the notify target answered with a redirect; point webhook.notifyURL at its final location")
			},
		},
		log: log,
		sem: make(chan struct{}, maxNotifyInFlight),
	}
}

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
	n.mu.Lock()
	if n.draining {
		n.mu.Unlock()
		n.log.Warn("dropping a renewal notification; the notifier is shutting down", "cert", ev.Cert)
		return
	}
	n.mu.Unlock()

	ctx = context.WithoutCancel(ctx)
	select {
	case n.sem <- struct{}{}:
	default:
		n.log.Warn("dropping a renewal notification; too many already in flight",
			"cert", ev.Cert, "limit", maxNotifyInFlight)
		return
	}
	go func() {
		defer func() { <-n.sem }()
		n.send(ctx, ev)
	}()
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
	if n.secret != "" {
		mac := hmac.New(sha256.New, []byte(n.secret))
		_, _ = mac.Write(body)
		req.Header.Set("X-Wecert-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := n.client.Do(req)
	if err != nil {
		n.log.Warn("failed to deliver the renewal notification", "cert", ev.Cert, "result", ev.Result,
			"target", RedactNotifyURL(n.url), "err", withoutURL(err))
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		n.log.Warn("the renewal notification was rejected", "cert", ev.Cert, "status", resp.StatusCode)
		return
	}
	n.log.Debug("renewal notification delivered", "cert", ev.Cert, "result", ev.Result)
}

// Drain waits for the notifications already in flight, up to the context's deadline.
//
// Delivery is fire-and-forget: Renewal hands the POST to a goroutine and returns, so
// nothing waited for it. That is fine while the daemon keeps running, but a one-shot run
// (-once) or a shutdown can exit with the POST still in flight, and the notification is
// then simply lost -- including the "result":"error" one, which is the notification an
// operator most needs. The 10s per-send timeout means the wait is bounded even if the
// receiver never answers.
//
// The wait is expressed through the semaphore rather than a WaitGroup because the
// semaphore already exists and is held for exactly the duration of a send: filling it means
// every holder has released, that is, every send has finished.
func (n *Notifier) Drain(ctx context.Context) {
	if n == nil {
		return
	}
	n.mu.Lock()
	n.draining = true
	n.mu.Unlock()

	// Filling the buffer means every holder released. The first acquisition cannot block
	// for long even when nothing is in flight (a free slot is taken immediately); the loop
	// is what makes it a barrier rather than a single probe.
	for i := 0; i < maxNotifyInFlight; i++ {
		select {
		case n.sem <- struct{}{}:
		case <-ctx.Done():
			return
		}
	}
}

// RedactNotifyURL keeps a notification target's scheme and host and withholds everything else.
//
// A chat or CI notification URL IS a credential: Slack, Feishu, DingTalk and friends put the
// secret in the path, and a signed target can carry it in the query. The journal is shipped
// somewhere with a wider audience than the daemon's owner, so the operator gets "where", not the
// bearer token for "where". cmd/wecert logs this form at startup, and every failed delivery logs
// it too.
func RedactNotifyURL(raw string) string {
	if raw == "" {
		return "(no notification URL)"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		// Unparseable: the host cannot be separated from the credential, so nothing is printed.
		return "(notification URL withheld)"
	}
	out := u.Scheme + "://" + u.Host
	if u.Path != "" && u.Path != "/" {
		out += "/...(path withheld)"
	}
	if u.RawQuery != "" || u.Fragment != "" {
		out += "?..."
	}
	return out
}

// withoutURL returns err without the URL a *url.Error embeds in its message.
//
// "Post \"https://hooks.example/T00/B00/SECRET\": dial tcp: connection refused" is the shape
// net/http produces, and it is logged on every failed delivery -- which for a wrong target is
// every renewal. The transport's own reason is what an operator needs; the URL is already in the
// redacted "target" field.
func withoutURL(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) && uerr.Err != nil {
		return uerr.Err
	}
	return err
}
