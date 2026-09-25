package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
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
	prober := func(context.Context, string, probe.Options) ([]probe.Attempt, error) {
		calls++
		return []probe.Attempt{{Address: "192.0.2.1", Err: errors.New("dial tcp: connection refused")}}, nil
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
	prober := func(context.Context, string, probe.Options) ([]probe.Attempt, error) {
		calls++
		return []probe.Attempt{{Address: "192.0.2.1", Err: errors.New("connection refused")}}, nil
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
	prober := func(context.Context, string, probe.Options) ([]probe.Attempt, error) {
		return []probe.Attempt{{Address: "192.0.2.1", Result: &probe.Result{Host: "h", NotAfter: time.Now().Add(24 * time.Hour), SANs: []string{"other.example.com"}}}}, nil
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
	unreachable := func(context.Context, string, probe.Options) ([]probe.Attempt, error) {
		return []probe.Attempt{{Address: "192.0.2.1", Err: errors.New("no route to host")}}, nil
	}
	if code := checkOne(context.Background(), "example.com", probe.Options{}, probe.Expectation{},
		0, false, unreachable); code != exitUnreachable {
		t.Errorf("a dial failure must be exit %d, got %d", exitUnreachable, code)
	}

	// A captured certificate that does not cover the dialled name: r.cert is private, so the
	// verdict cannot be faked, but the code path is the same one as a real mismatch.
	mismatch := func(context.Context, string, probe.Options) ([]probe.Attempt, error) {
		return []probe.Attempt{{Address: "192.0.2.1", Result: &probe.Result{Host: "example.com", SANs: []string{"other.example.com"}}}}, nil
	}
	if code := checkOne(context.Background(), "example.com", probe.Options{}, probe.Expectation{},
		0, false, mismatch); code != exitMismatch {
		t.Errorf("a non-matching result must be exit %d, got %d", exitMismatch, code)
	}
}

// ── the command line's own exit codes ────────────────────────────────────────────────

// -h is a request for help, not a command-line error.
//
// flag.ContinueOnError reports -h as flag.ErrHelp after printing the usage, and the parse
// error branch used to return exitUsage (64) for it -- the same code an unknown flag gets,
// and the opposite of what the exit-code table documents. tatrun makes the same
// distinction with its errHelp.
func TestHelpRequestExitsZero(t *testing.T) {
	restore := silenceStderr(t)
	defer restore()
	if code := runArgs([]string{"-h"}); code != exitOK {
		t.Errorf("-h exited %d, want %d: asking for help is not a command-line error", code, exitOK)
	}
}

// The distinction must not swallow real command-line errors: an unknown flag stays 64.
func TestUnknownFlagStaysAUsageError(t *testing.T) {
	restore := silenceStderr(t)
	defer restore()
	if code := runArgs([]string{"-definitely-not-a-flag"}); code != exitUsage {
		t.Errorf("an unknown flag exited %d, want %d", code, exitUsage)
	}
}

// silenceStderr redirects os.Stderr (where the flag package prints the usage) for the
// duration of one call; the returned function restores it.
func silenceStderr(t *testing.T) func() {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	return func() {
		_ = w.Close()
		os.Stderr = old
		_ = r.Close()
	}
}

// -require-trusted must reach the expectation, or the flag parses and does nothing.
//
// There was previously no way to turn the check on from the CLI at all, so the tool
// answered exit 0 for a certificate whose name matches but whose chain no client accepts
// -- while the daemon defaults the same check on (probe.requireTrusted).
func TestRequireTrustedFlagReachesTheExpectation(t *testing.T) {
	e, err := buildExpectation("", "", 0, true)
	if err != nil {
		t.Fatalf("buildExpectation: %v", err)
	}
	if !e.RequireTrusted {
		t.Error("RequireTrusted was dropped between the flag and the expectation")
	}
	e, err = buildExpectation("", "", 0, false)
	if err != nil || e.RequireTrusted {
		t.Errorf("the default must stay off (an internal CA never verifies), got %v, %v",
			e.RequireTrusted, err)
	}
}

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
	prober := func(_ context.Context, _ string, opts probe.Options) ([]probe.Attempt, error) {
		timeout := opts.Timeout
		if timeout <= 0 {
			timeout = probe.DefaultTimeout
		}
		time.Sleep(timeout)
		return []probe.Attempt{{Address: "192.0.2.1", Err: errors.New("dial tcp: i/o timeout")}}, nil
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

// A spent -wait budget must not turn into a successful probe that never dialled.
//
// The deadline check came before the first attempt, and its early return handed back lastCode's
// zero value -- which is exitOK. `wecert-probe -host H -wait 1ns` therefore exited 0, printing
// nothing, having opened no socket: the answer a script trusts most ("the listener serves the
// expected certificate") was produced without looking. -wait means "keep re-checking for this
// long"; it cannot mean "do not check at all".
func TestASpentWaitBudgetStillProbesOnce(t *testing.T) {
	attempts := 0
	prober := func(context.Context, string, probe.Options) ([]probe.Attempt, error) {
		attempts++
		return []probe.Attempt{{Address: "10.0.0.1", Err: errors.New("dial tcp 10.0.0.1:443: connect: connection refused")}}, nil
	}

	code := checkOne(context.Background(), "example.com", probe.Options{}, probe.Expectation{},
		time.Nanosecond, false, prober)

	if attempts == 0 {
		t.Fatal("the probe never dialled: a budget too small to wait must still produce one attempt, " +
			"not an answer")
	}
	if code == exitOK {
		t.Errorf("exit code = %d (ok) although nothing was ever dialled", code)
	}
}

// One stale backend must not hide behind a healthy one.
//
// The CLI probed with probe.Probe, which returns the FIRST address that answered, while the
// daemon's runner uses ProbeAll "so an updated node cannot hide a node still serving an old cert".
// A rebind rolls through the backends, so the tool whose whole purpose is "wait until the
// certificate took effect" answered from whichever address happened to answer first -- next to a
// printed list of every resolved IP.
//
// The evidence is coverage: every resolved address is examined and reported (the mutation that
// stops after the first is caught by the second line's absence), and any bad answer decides the
// exit code.
func TestEveryResolvedAddressDecidesTheVerdict(t *testing.T) {
	attempts := func(context.Context, string, probe.Options) ([]probe.Attempt, error) {
		return []probe.Attempt{
			{Address: "192.0.2.1", Result: &probe.Result{Host: "example.com", NotAfter: time.Now().Add(24 * time.Hour)}},
			{Address: "192.0.2.2", Result: &probe.Result{Host: "example.com", NotAfter: time.Now().Add(24 * time.Hour)}},
		}, nil
	}

	out := captureStdout(t)
	code := checkOne(context.Background(), "example.com", probe.Options{},
		probe.Expectation{Domains: []string{"example.com"}}, 0, true, attempts)
	printed := out()

	if !strings.Contains(printed, "192.0.2.2") {
		t.Errorf("the second resolved address was never examined:\n%s", printed)
	}
	if code != exitMismatch {
		t.Errorf("exit code = %d, want %d: neither address served the expected certificate",
			code, exitMismatch)
	}
}

// captureStdout redirects os.Stdout for the duration of one call and returns a function that
// restores it and hands back everything written.
func captureStdout(t *testing.T) func() string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	return func() string {
		_ = w.Close()
		os.Stdout = old
		data, _ := io.ReadAll(r)
		_ = r.Close()
		return string(data)
	}
}

// -json is one object per line, not one indented object per attempt.
//
// The documented contract (README.md, README.zh-cn.md, docs/test-cases.md TC-PROBE-20/21/21b) is
// NDJSON: one attempt, one line, so a line-oriented consumer -- `... | while read -r line; do jq .
// <<<"$line"; done`, a CI step, a log processor -- can read the stream. The encoder indented, so a
// single attempt spanned about thirty lines and no line was a JSON object on its own: the docs
// described the intent and the code did something else.
func TestJSONOutputIsOneObjectPerLine(t *testing.T) {
	attempts := func(context.Context, string, probe.Options) ([]probe.Attempt, error) {
		return []probe.Attempt{
			{Address: "192.0.2.1", Result: &probe.Result{Host: "example.com", NotAfter: time.Now().Add(24 * time.Hour)}},
			{Address: "192.0.2.2", Result: &probe.Result{Host: "example.com", NotAfter: time.Now().Add(24 * time.Hour)}},
		}, nil
	}

	out := captureStdout(t)
	checkOne(context.Background(), "example.com", probe.Options{},
		probe.Expectation{Domains: []string{"example.com"}}, 0, true, attempts)
	printed := out()

	lines := strings.Split(strings.TrimRight(printed, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("two addresses must produce two lines, got %d:\n%s", len(lines), printed)
	}
	for i, line := range lines {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Fatalf("line %d is not a JSON object on its own (%v): %q", i+1, err, line)
		}
		if obj["address"] == nil {
			t.Errorf("line %d does not name the address it judged: %v", i+1, obj)
		}
	}
}
