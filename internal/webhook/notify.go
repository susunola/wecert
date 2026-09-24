package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/susunola/wecert/internal/config"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// maxNotifyInFlight caps outstanding notification POSTs.
const maxNotifyInFlight = 8

type Notifier struct {
	url    string
	secret string
	// format is the POST body shape (see config.Webhook.NotifyFormat).
	format string
	// pdRoutingKey is the PagerDuty Events API v2 integration key (only for
	// format=notifyFormatPagerDuty).
	pdRoutingKey string
	// jira is the REST client config (only for format=notifyFormatJira).
	jira   JiraTarget
	client *http.Client
	log    *slog.Logger
	sem    chan struct{}

	// mu guards draining, which is only ever set once.
	mu sync.Mutex
	// draining stops new notifications from being accepted, so Drain has a fixed set of
	// in-flight sends to wait for instead of racing a moving target.
	draining bool
	// inFlight counts accepted sends that have not finished. Drain waits for this
	// rather than only filling the semaphore -- filling it races the accept path.
	inFlight int
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
// NewNotifier builds a generic-format notifier. See NewNotifierFormat for
// PagerDuty / chat-robot shapes.
func NewNotifier(url, secret string, log *slog.Logger) *Notifier {
	return NewNotifierFormat(url, secret, "generic", "", log)
}

// NewNotifierFormat builds a notifier whose POST body is shaped for the named
// product. format "" is treated as generic. An empty url still returns nil.
// jiraTarget is the construction input for the Jira REST adapter.
type JiraTarget struct {
	BaseURL        string
	ProjectKey     string
	IssueType      string
	Email          string
	APIToken       string
	Auth           string // basic | bearer
	Labels         []string
	ReuseOpenIssue bool
}

// NewNotifierFormat builds a notifier whose POST body is shaped for the named
// product. format "" is treated as generic. An empty url still returns nil (except
// jira, which uses the REST baseURL instead of a webhook URL).
func NewNotifierFormat(url, secret, format, pdRoutingKey string, log *slog.Logger) *Notifier {
	return NewNotifierJira(url, secret, format, pdRoutingKey, JiraTarget{}, log)
}

// NewNotifierJira is NewNotifierFormat plus the Jira REST settings. jt is only read
// when format is jira.
func NewNotifierJira(url, secret, format, pdRoutingKey string, jt JiraTarget, log *slog.Logger) *Notifier {
	if url == "" && format != "jira" {
		return nil
	}
	if format == "" {
		format = "generic"
	}
	return &Notifier{
		url:          url,
		secret:       secret,
		format:       format,
		pdRoutingKey: pdRoutingKey,
		jira:         jt,
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
		ev.Error = redactSecrets(reconcileErr.Error())
	}
	// Acquire the slot while still holding mu: the check-then-act window between
	// "not draining" and "slot taken" used to drop events and let Drain return while
	// a send was still about to start.
	n.mu.Lock()
	if n.draining {
		n.mu.Unlock()
		n.log.Warn("dropping a renewal notification; the notifier is shutting down", "cert", ev.Cert)
		return
	}
	select {
	case n.sem <- struct{}{}:
	default:
		n.mu.Unlock()
		n.log.Warn("dropping a renewal notification; too many already in flight",
			"cert", ev.Cert, "limit", maxNotifyInFlight)
		return
	}
	n.inFlight++
	n.mu.Unlock()

	ctx = context.WithoutCancel(ctx)
	go func() {
		defer func() {
			<-n.sem
			n.mu.Lock()
			n.inFlight--
			n.mu.Unlock()
		}()
		n.send(ctx, ev)
	}()
}

func (n *Notifier) send(ctx context.Context, ev RenewalEvent) {
	if n.format == config.NotifyFormatJira {
		if err := n.deliverJira(ctx, ev); err != nil {
			n.log.Warn("failed to deliver the jira notification", "cert", ev.Cert,
				"target", RedactNotifyURL(n.jira.BaseURL), "err", withoutURL(err))
		}
		return
	}
	body, err := n.notifyPayload(ev)
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
// operator most needs. The per-send timeout (10s generic, 15s Jira) means the wait is
// bounded even if the receiver never answers.
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

	// Wait for every accepted send to finish. The old "fill the semaphore" barrier
	// raced the accept path: a send that had passed the draining check but not yet
	// taken a slot would start after Drain returned.
	//
	// 40s, not 20s: Jira's worst case is find-open (15s) plus create-or-comment
	// (15s) per event, and a one-shot run that drains too early ships the
	// "result: error" ticket nowhere.
	deadline := time.Now().Add(40 * time.Second)
	for {
		n.mu.Lock()
		left := n.inFlight
		n.mu.Unlock()
		if left == 0 {
			return
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
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

// redactSecrets strips credentials from outbound event text before it is shipped
// to Jira / PagerDuty / a chat robot. withoutURL only protected the
// delivery-failure *log*; the event body itself still carried the raw error.
//
// Beyond URLs: an error string can embed a Bearer token, an AWS access key id, or
// a PEM block that fell out of a failed parse. Each is a credential that must not
// leave the host just because a renewal failed.
func redactSecrets(s string) string {
	s = urlRegexp.ReplaceAllStringFunc(s, func(u string) string {
		return RedactNotifyURL(u)
	})
	s = bearerRegexp.ReplaceAllString(s, "$1[redacted]")
	s = accessKeyRegexp.ReplaceAllString(s, "[redacted-access-key]")
	s = pemRegexp.ReplaceAllString(s, "[redacted-pem]")
	s = keyValSecretRegexp.ReplaceAllStringFunc(s, func(m string) string {
		i := strings.IndexByte(m, '=')
		if i < 0 {
			i = strings.IndexByte(m, ':')
		}
		if i < 0 {
			return "[redacted]"
		}
		return m[:i+1] + "[redacted]"
	})
	if len(s) > 512 {
		s = s[:512] + "…"
	}
	return s
}

var (
	// urlRegexp matches an absolute http(s) URL in free text. Deliberately simple: the
	// goal is to drop userinfo, path and query, not to parse RFC 3986 perfectly.
	urlRegexp = regexp.MustCompile(`https?://[^\s]+`)
	// bearerRegexp keeps the scheme so the operator can see a token was there.
	bearerRegexp = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._\-+/=]{8,}`)
	// accessKeyRegexp covers the AWS / Tencent CAM access-key-id shapes that show up
	// in SDK error strings.
	accessKeyRegexp = regexp.MustCompile(`\b(?:AKIA|ASIA|AKID)[0-9A-Za-z]{12,}\b`)
	// pemRegexp collapses a whole PEM block: the body is the secret.
	pemRegexp = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----`)
	// keyValSecretRegexp covers `token=...`, `secretKey: ...` and friends in free text.
	keyValSecretRegexp = regexp.MustCompile(`(?i)\b(?:secret[_-]?key|access[_-]?key|api[_-]?token|api[_-]?key|password|token|authorization)["']?\s*[:=]\s*["']?[A-Za-z0-9._\-+/=]{8,}`)
)
