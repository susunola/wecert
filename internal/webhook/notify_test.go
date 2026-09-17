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
