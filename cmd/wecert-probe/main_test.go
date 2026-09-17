package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/probe"
)

// ── exit-code precedence ─────────────────────────────────────────────────────────────
//
// These codes are the command's interface to a script, and mixing them up makes a caller act on
// the wrong diagnosis: "cannot dial" is an environment problem on the probing machine, "wrong
// certificate" is production.

func TestWorseExitCodePrefersMismatch(t *testing.T) {
	// A mismatch wins over everything: it is the conclusion worth stopping a rollout for.
	if got := worseExitCode(exitUnreachable, exitMismatch); got != exitMismatch {
		t.Errorf("got %d, want mismatch to outrank unreachable", got)
	}
	if got := worseExitCode(exitOK, exitMismatch); got != exitMismatch {
		t.Errorf("got %d, want mismatch to outrank ok", got)
	}
	// Unreachable wins over ok, in both orders.
	if got := worseExitCode(exitOK, exitUnreachable); got != exitUnreachable {
		t.Errorf("got %d, want unreachable to outrank ok", got)
	}
	if got := worseExitCode(exitUnreachable, exitOK); got != exitUnreachable {
		t.Errorf("got %d, want the earlier unreachable to be kept", got)
	}
	// Two oks stay ok.
	if got := worseExitCode(exitOK, exitOK); got != exitOK {
		t.Errorf("got %d, want ok", got)
	}
	// And a mismatch already recorded is not downgraded by a later unreachable host.
	if got := worseExitCode(exitMismatch, exitUnreachable); got != exitMismatch {
		t.Errorf("got %d, want mismatch to be sticky", got)
	}
}

// The exit codes themselves are the documented interface (see the flag usage): changing one
// silently breaks every script that switches on it.
func TestExitCodesMatchTheDocumentedValues(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"ok", exitOK, 0},
		{"unreachable", exitUnreachable, 1},
		{"mismatch", exitMismatch, 2},
		{"usage", exitUsage, 64},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d (the usage text documents these)", tc.name, tc.got, tc.want)
		}
	}
}

// ── retry policy ─────────────────────────────────────────────────────────────────────
//
// The documented behaviour is that -wait polls "until the verdict is ok or this long elapses".
// Both failure modes are retried: an unreachable host is exit 1, a completed probe with the
// wrong certificate is exit 2, and either can be transient just after a rebind (~15s measured).
// What must NOT happen is waiting past the deadline.

// The -wait budget must bound ELAPSED TIME, not merely the number of attempts.
//
// This is the regression: checkOne slept a flat retryInterval (5s) between attempts and only
// checked the deadline before sleeping, so `-wait 80ms` blocked for five seconds and any wait
// shorter than the interval overshot by up to the whole interval. The test deliberately leaves
// the PRODUCTION retry interval in place -- shortening it would put the sleep and the budget on
// the same scale and hide exactly the bug this is here for.
func TestCheckOneWaitBoundsElapsedTimeNotJustAttempts(t *testing.T) {
	if retryInterval <= 80*time.Millisecond {
		t.Fatalf("this test needs the production retry interval to exceed the budget to mean "+
			"anything; retryInterval is %s", retryInterval)
	}

	var calls int
	prober := func(context.Context, string, probe.Options) (*probe.Result, error) {
		calls++
		return nil, errors.New("dial tcp: connection refused")
	}

	const budget = 80 * time.Millisecond
	start := time.Now()
	code := checkOne(context.Background(), "example.com", probe.Options{}, probe.Expectation{},
		budget, false, prober)
	elapsed := time.Since(start)

	if code != exitUnreachable {
		t.Errorf("code = %d, want unreachable", code)
	}
	if elapsed > 2*time.Second {
		t.Errorf("a %s wait took %s: the sleep between attempts is not capped to the remaining "+
			"budget, so -wait bounds the attempt count but not the time", budget, elapsed)
	}
	// The number of attempts is an implementation detail: with the sleep capped to the
	// remaining budget, a short budget legitimately fits a second attempt. What matters is that
	// the loop ended inside the budget, which the elapsed check above pins.
	if calls == 0 {
		t.Error("no attempt was made")
	}
}

// With no -wait there must be exactly one attempt: the caller asked for a single verdict.
func TestCheckOneWithoutWaitMakesOneAttempt(t *testing.T) {
	var calls int
	prober := func(context.Context, string, probe.Options) (*probe.Result, error) {
		calls++
		return nil, errors.New("connection refused")
	}

	if code := checkOne(context.Background(), "example.com", probe.Options{}, probe.Expectation{},
		0, false, prober); code != exitUnreachable {
		t.Errorf("code = %d, want unreachable", code)
	}
	if calls != 1 {
		t.Errorf("made %d attempt(s) with wait=0, want 1", calls)
	}
}

// A cancelled context must return promptly with the last verdict, not run the deadline out.
func TestCheckOneReturnsPromptlyWhenCancelled(t *testing.T) {
	prober := func(context.Context, string, probe.Options) (*probe.Result, error) {
		return &probe.Result{Host: "h", NotAfter: time.Now().Add(24 * time.Hour), SANs: []string{"other.example.com"}}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	code := checkOne(ctx, "example.com", probe.Options{}, probe.Expectation{}, time.Hour, false, prober)
	if code != exitMismatch {
		t.Errorf("code = %d, want mismatch (the last verdict)", code)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("a cancelled context took %s to return", elapsed)
	}
}

// The exit code for a failing probe distinguishes "could not probe" from "probed and it is
// wrong", which is the documented interface and the reason a caller can tell an environment
// problem from a production one.
func TestCheckOneDistinguishesUnreachableFromMismatch(t *testing.T) {
	unreachable := func(context.Context, string, probe.Options) (*probe.Result, error) {
		return nil, errors.New("no route to host")
	}
	if code := checkOne(context.Background(), "example.com", probe.Options{}, probe.Expectation{},
		0, false, unreachable); code != exitUnreachable {
		t.Errorf("a dial failure must be exit %d, got %d", exitUnreachable, code)
	}

	// A captured certificate that does not cover the dialled name: r.cert is private, so the
	// verdict cannot be faked, but the code path is the same one as a real mismatch.
	mismatch := func(context.Context, string, probe.Options) (*probe.Result, error) {
		return &probe.Result{Host: "example.com", SANs: []string{"other.example.com"}}, nil
	}
	if code := checkOne(context.Background(), "example.com", probe.Options{}, probe.Expectation{},
		0, false, mismatch); code != exitMismatch {
		t.Errorf("a non-matching result must be exit %d, got %d", exitMismatch, code)
	}
}

// ── flag parsing helpers ─────────────────────────────────────────────────────────────

func TestSplitListTrimsAndDropsEmptyEntries(t *testing.T) {
	got := splitList(" a.example.com , b.example.com ,,  , c.example.com ")
	want := []string{"a.example.com", "b.example.com", "c.example.com"}
	if len(got) != len(want) {
		t.Fatalf("splitList = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("splitList = %v, want %v", got, want)
		}
	}
	if got := splitList(""); len(got) != 0 {
		t.Errorf("splitList(\"\") = %v, want empty", got)
	}
}

// firstLine heads a multi-line chain error with something readable. The empty case must produce
// a phrase rather than an empty label, or the output line reads as a missing value.
func TestFirstLineKeepsOnlyTheFirstLine(t *testing.T) {
	if got := firstLine("first\nsecond\nthird"); got != "first" {
		t.Errorf("firstLine = %q, want first", got)
	}
	// A blank first line stays blank: the function truncates, it does not trim.
	if got := firstLine("  \nsecond"); got != "  " {
		t.Errorf("firstLine = %q, want the literal first line", got)
	}
	if got := firstLine(""); got != "no chain error reported" {
		t.Errorf("firstLine(\"\") = %q, want the placeholder phrase", got)
	}
}

// -wait must bound the attempt that is already in flight, not just the sleep between attempts.
//
// The deadline was checked only between attempts, so each attempt ran to its full per-attempt
// timeout: with the default 10s timeout `-wait 1s` took ten seconds (measured), and with
// -timeout 5s it took five. The flag's own help and the sleep comment both say -wait is how long
// the command may take.
func TestWaitBoundsAnAttemptAlreadyInFlight(t *testing.T) {
	// A prober that blocks until its context/attempt timeout expires, like a real dial to a black
	// hole: it must not be allowed to outlive the wait.
	prober := func(_ context.Context, _ string, opts probe.Options) (*probe.Result, error) {
		timeout := opts.Timeout
		if timeout <= 0 {
			timeout = probe.DefaultTimeout
		}
		time.Sleep(timeout)
		return nil, errors.New("dial tcp: i/o timeout")
	}

	const budget = 120 * time.Millisecond
	start := time.Now()
	checkOne(context.Background(), "example.com", probe.Options{Timeout: 5 * time.Second},
		probe.Expectation{}, budget, false, prober)
	elapsed := time.Since(start)

	if elapsed > 2*time.Second {
		t.Errorf("a %s wait took %s: the in-flight attempt ran to its own -timeout instead of what "+
			"was left of the wait, so -wait does not bound the command", budget, elapsed)
	}
}
