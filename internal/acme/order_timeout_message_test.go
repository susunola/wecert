package acme

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"

	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/state"
)

// The order poll's timeout message must read as a sentence.
//
// It is the only thing that can catch a swapped argument here. `%q` is a string verb and
// time.Duration has a String method, so `fmt.Errorf("... did not reach %q within %s", timeout,
// want, ...)` compiles, passes `go vet`, and renders as `did not reach "3m0s" within ready` -- a
// message that puts a duration where the status belongs, in exactly the situation where an operator
// is trying to work out what the CA is waiting for.
func TestOrderTimeoutMessageNamesTheStatusAndTheTimeout(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	fake := &fakeAPI{}
	// "once exhausted it keeps returning the last one", so a single pending order is a poll that
	// can never reach the status it is waiting for.
	fake.orders = []legoacme.ExtendedOrder{{Order: legoacme.Order{Status: "pending"}}}

	m := newManager(store, fake, &fakeSolver{}, fakeKeyAuth{}, deploy.Noop{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	// A clock that jumps past the deadline on the first poll, so the loop does not sleep between
	// iterations: these tests share a package and a real sleep would slow every run of it.
	cur := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return cur })
	fake.beforeCall = func(call string) {
		if call == "GetOrder" {
			cur = cur.Add(2 * time.Minute)
		}
	}

	_, err = m.awaitOrderStatus(context.Background(), "https://ca/order/1", "ready", time.Minute)
	if err == nil {
		t.Fatal("an order that never reaches the wanted status must time out")
	}

	msg := err.Error()
	statusAt, timeoutAt := strings.Index(msg, `"ready"`), strings.Index(msg, "1m0s")
	if statusAt < 0 {
		t.Errorf("the message must name the status that was waited for, got %q", msg)
	}
	if timeoutAt < 0 {
		t.Errorf("the message must name the timeout, got %q", msg)
	}
	if statusAt >= 0 && timeoutAt >= 0 && statusAt > timeoutAt {
		t.Errorf("the status must be named before the duration, got %q -- the two arguments are "+
			"swapped, and %s accepts a time.Duration so nothing else catches it", msg, "%q")
	}
}
