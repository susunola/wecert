package webhook

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A redirect must not be reported as a delivered event.
//
// The default Go client follows redirects, and every hop loses the event: 301/302/303 turns the
// signed POST into a bodiless GET (a receiver answering that GET with 200 was judged a delivery),
// and 307/308 re-sends the body -- including the X-Wecert-Signature header -- to whatever host the
// redirect names. Refusing the redirect surfaces the real problem: the target moved, and the
// operator's notification channel is silently dead.
func TestANotifyRedirectIsNotADelivery(t *testing.T) {
	t.Parallel()
	var target string
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusFound)
	}))
	defer redirector.Close()

	// The redirect target answers 200 to anything and records what it received.
	var reached bool
	var method string
	target = ""
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached, method = true, r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer final.Close()
	target = final.URL

	var logs bytes.Buffer
	n := NewNotifier(redirector.URL, "0123456789abcdef0123456789abcdef",
		slog.New(slog.NewTextHandler(&logs, nil)))
	n.Renewal(context.Background(), "cert-a", nil)
	// Delivery is fire-and-forget, so wait for the send to finish before reading the log.
	n.Drain(context.Background())

	if reached {
		t.Errorf("the signed POST was followed to the redirect target (%s %s): the notify target is "+
			"not a redirect, and the event must not be re-sent to whatever host the 3xx names",
			method, final.URL)
	}
	if strings.Contains(logs.String(), "delivered") {
		t.Errorf("a refused redirect must not be logged as a delivery, got %s", logs.String())
	}
	if !strings.Contains(logs.String(), "redirect") {
		t.Errorf("the log must say the target redirected, got %s", logs.String())
	}
}

// A notification target must not be logged verbatim: the URL is the credential.
//
// Chat and CI webhooks put the secret in the path (Slack/Feishu/DingTalk) or in a signed query, and
// the journal is routinely shipped somewhere with a wider audience than the daemon's owner. A
// delivery failure logs the target on every attempt, so an unredacted URL here is a credential in
// the log forever -- and the transport error embeds it a second time.
func TestANotificationTargetIsNotLoggedVerbatim(t *testing.T) {
	t.Parallel()
	const secret = "T000/B000/SUPERSECRETVALUE"
	var logs bytes.Buffer

	// Nothing listens on this port, so the delivery fails at dial time and the failure path logs.
	n := NewNotifier("http://127.0.0.1:1/hook/"+secret, "", slog.New(slog.NewTextHandler(&logs, nil)))
	n.Renewal(context.Background(), "cert-a", nil)
	n.Drain(context.Background())

	got := logs.String()
	if strings.Contains(got, "SUPERSECRETVALUE") {
		t.Errorf("the notification URL's secret reached the log:\n%s", got)
	}
	if !strings.Contains(got, "127.0.0.1:1") {
		t.Errorf("the operator still has to learn WHICH target failed, got:\n%s", got)
	}
}

// The redactor keeps the host, withholds path and query, and never prints an unparseable URL.
func TestRedactNotifyURL(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"https://hooks.slack.com/services/T00/B00/SECRET", "https://hooks.slack.com/...(path withheld)"},
		{"https://example.com/hook?token=SECRET", "https://example.com/...(path withheld)?..."},
		{"https://example.com", "https://example.com"},
		{"https://example.com/", "https://example.com"},
		{"", "(no notification URL)"},
		{"://not a url", "(notification URL withheld)"},
		{"not-a-url", "(notification URL withheld)"},
	}
	for _, tc := range cases {
		if got := RedactNotifyURL(tc.in); got != tc.want {
			t.Errorf("RedactNotifyURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
