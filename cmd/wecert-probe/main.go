// Command wecert-probe dials a real TLS connection and reads back the certificate the
// far end **actually serves**.
//
// It is the first tool to reach for when troubleshooting: "the cloud API says the bind
// succeeded" and "a browser really gets this certificate" are two different things -- a rebind
// is asynchronous (~15s measured) and another certificate can win SNI, neither visible on the
// control plane.
//
// Usage:
//
//	wecert-probe -host www.example.com
//	wecert-probe -host www.example.com -min-valid 168h
//	wecert-probe -host www.example.com -wait 90s     # just rebound, wait for it to take effect
//	wecert-probe -host a.example.com,b.example.com -json
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/susunola/wecert/internal/probe"
)

// version can be injected through -ldflags "-X main.version=...".
var version = "dev"

// Exit codes. Keeping them apart is useful: in a script, "cannot dial" and "serving the
// wrong certificate" need completely different handling paths.
const (
	exitOK          = 0
	exitUnreachable = 1
	exitMismatch    = 2
	exitUsage       = 64
)

func main() { os.Exit(run()) }

func run() int { return runArgs(os.Args[1:]) }

// runArgs is run's body with the arguments passed in, so the exit-code contract
// (which parse failure maps to which code) is testable without spawning the binary.
func runArgs(args []string) int {
	fs := flag.NewFlagSet("wecert-probe", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `wecert-probe %s

Dial a real TLS connection and report the certificate the far end actually serves.

This is the only evidence in wecert that does not trust the cloud control plane:
a rebind is asynchronous, and another certificate can be winning SNI.
Neither is visible through the API.

Usage:
  wecert-probe -host www.example.com [-min-valid 168h] [-wait 90s]

Exit codes:
  0  every host served the expected certificate
  1  could not complete a probe (resolve / dial / handshake failed)
  2  a probe completed but the certificate served was not the expected one
  64 the command line itself was wrong (asking for help with -h is not; it exits 0)

Flags:
`, version)
		fs.PrintDefaults()
	}

	var (
		hostFlag = fs.String("host", "", "comma-separated names to probe (required)")
		port     = fs.Int("port", 443, "TCP port to dial")
		timeout  = fs.Duration("timeout", probe.DefaultTimeout, "per-attempt timeout")
		minValid = fs.Duration("min-valid", 0, "fail if the served certificate has less than this left, e.g. 168h")
		expectSA = fs.String("expect-san", "", "comma-separated SAN set that was deployed; the served set must match exactly")
		expectNA = fs.String("expect-not-after", "", "RFC3339 notAfter of the certificate that was deployed; catches a rebind that did not take effect")
		reqTrust = fs.Bool("require-trusted", false, "fail if the served chain does not verify against the system roots "+
			"(the daemon defaults this on; leave it off for an internal CA)")
		wait    = fs.Duration("wait", 0, "poll until the verdict is ok or this long elapses (e.g. 90s)")
		asJSON  = fs.Bool("json", false, "print the raw result as JSON")
		showVer = fs.Bool("version", false, "print the version and exit")
	)

	if err := fs.Parse(args); err != nil {
		// flag.ContinueOnError has already printed the message and the usage to
		// fs.Output(). Asking for help is not a command-line error -- the same
		// distinction tatrun's errHelp makes -- so -h exits 0 while a genuinely bad
		// command line keeps 64.
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if *showVer {
		fmt.Println("wecert-probe", version)
		return exitOK
	}

	hosts := splitList(*hostFlag)
	if len(hosts) == 0 {
		fs.Usage()
		return exitUsage
	}

	e, err := buildExpectation(*expectSA, *expectNA, *minValid, *reqTrust)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wecert-probe: %v\n", err)
		return exitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	opts := probe.Options{Port: *port, Timeout: *timeout}

	worst := exitOK
	for _, host := range hosts {
		worst = worseExitCode(worst, checkOne(ctx, host, opts, e, *wait, *asJSON, probe.ProbeAll))
	}
	return worst
}

// buildExpectation assembles what the served certificate is compared against.
//
// Split out of runArgs so the flag-to-field wiring is testable without a network: a flag
// that parses but never reaches the expectation is invisible to every test that goes
// through checkOne, because checkOne receives the Expectation already built -- which is
// exactly how this CLI spent its life with no way to turn RequireTrusted on.
func buildExpectation(expectSAN, expectNotAfter string, minValid time.Duration, requireTrusted bool) (probe.Expectation, error) {
	e := probe.Expectation{
		Domains:        splitList(expectSAN),
		MinValidFor:    minValid,
		RequireTrusted: requireTrusted,
	}
	if expectNotAfter != "" {
		t, err := time.Parse(time.RFC3339, expectNotAfter)
		if err != nil {
			return e, fmt.Errorf("-expect-not-after must be RFC3339: %w", err)
		}
		e.NotAfter = t
	}
	return e, nil
}

// worseExitCode folds one host's result into the summary.
//
// A mismatch outranks an unreachable host: it deserves to stop a script more than "could not
// dial" does, because the second is usually an environment problem on the machine running the
// probe while the first means production is serving the wrong certificate.
func worseExitCode(current, next int) int {
	if current == exitMismatch || next == exitMismatch {
		return exitMismatch
	}
	if current == exitUnreachable || next == exitUnreachable {
		return exitUnreachable
	}
	return exitOK
}

// minAttemptBudget is the floor an attempt gets when -wait leaves no room.
//
// It exists so "the budget is spent" cannot become "no probe happened": the first attempt runs
// whatever is left, with just enough time for a dial to fail. It is deliberately small -- a
// caller who asked for a nanosecond of waiting asked for a verdict, not for a ten-second dial.
const minAttemptBudget = 250 * time.Millisecond

// retryInterval is how long to wait between attempts under -wait.
//
// The comment used to read "only 'not in effect yet' is worth waiting for", which contradicted
// attemptOnce: it returns retry=true for an unreachable host too, and that is right -- a VIP
// that is not up yet, a DNS record mid-propagation and a momentary network blip all look exactly
// like that, and -wait exists to ride them out. What must not happen is waiting LONGER than
// asked.
//
// A package variable only so tests can shorten it; production never reassigns it.
var retryInterval = 5 * time.Second

// checkOne probes one name, polling while there is time, and returns its exit code.
func checkOne(ctx context.Context, host string, opts probe.Options, e probe.Expectation, wait time.Duration, asJSON bool, prober func(context.Context, string, probe.Options) ([]probe.Attempt, error)) int {
	deadline := time.Time{}
	if wait > 0 {
		deadline = time.Now().Add(wait)
	}

	attempt := 0
	var lastCode int
	for {
		attempt++
		// Each attempt is bounded by what is left of the wait, not just by its own -timeout.
		//
		// The deadline used to be checked only between attempts, so an attempt already in flight ran
		// to the full per-attempt timeout: with the default 10s timeout, `-wait 1s` took ten seconds
		// and `-wait 1s -timeout 5s` took five -- the flag bounded the attempt count and the sleep,
		// but not the command. The comment above the sleep already promises the caller that -wait is
		// how long the command may take.
		attemptOpts := opts
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining < minAttemptBudget {
				// The budget cannot cover another attempt. That is a reason to stop RETRYING, not
				// a reason to report a verdict without looking: the first attempt always runs,
				// with a floor that at least lets a socket fail. Returning before the first dial
				// handed back lastCode's zero value -- which is exitOK -- so
				// `wecert-probe -wait 1ns` reported "every host served the expected certificate"
				// having opened nothing. The documented contract agrees: one attempt with -wait
				// (TC-PROBE-11/15) and a total that stays close to the wait (TC-PROBE-13).
				if attempt > 1 {
					return lastCode
				}
				remaining = minAttemptBudget
			}
			if attemptOpts.Timeout <= 0 || attemptOpts.Timeout > remaining {
				attemptOpts.Timeout = remaining
			}
		}
		code, retry := attemptOnce(ctx, host, attemptOpts, e, asJSON, attempt, prober)
		lastCode = code

		// Retry on both outcomes. An unreachable host may be a network blip, a VIP that is not
		// up yet or DNS that has not propagated; a mismatch is the normal shape for roughly 15
		// seconds after a rebind, because the old certificate is still the one being served.
		// Only an OK verdict is final.
		//
		// (This comment used to claim the opposite -- that unreachable and wrong-cert "won't fix
		// themselves". They do, which is why -wait exists; the stale wording invited removing
		// the retry.)
		if !retry || deadline.IsZero() {
			return code
		}

		// Never sleep past the deadline.
		//
		// This used to be a flat `time.After(5 * time.Second)` with the deadline only checked
		// before the sleep, so -wait bounded the number of attempts but not the time: with
		// -wait 30ms the command still blocked for five seconds, and any -wait shorter than
		// the interval overshot by up to the whole interval. A CI step that asks for a 10s
		// wait to catch a rebind would sit there for up to 15.
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return code
		}
		if ctx.Err() != nil {
			return code
		}
		sleep := retryInterval
		if remaining < sleep {
			sleep = remaining
		}
		if !asJSON {
			fmt.Fprintf(os.Stderr, "  ... not there yet, retrying until %s\n",
				deadline.Format(time.RFC3339))
		}
		select {
		case <-ctx.Done():
			return code
		case <-time.After(sleep):
		}
	}
}

// attemptOnce probes once. A true retry means "waiting a little longer might help".
func attemptOnce(ctx context.Context, host string, opts probe.Options, e probe.Expectation, asJSON bool, attempt int, prober func(context.Context, string, probe.Options) ([]probe.Attempt, error)) (code int, retry bool) {
	attempts, err := prober(ctx, host, opts)
	if err != nil {
		if asJSON {
			emitJSON(map[string]any{"host": host, "error": err.Error(), "attempt": attempt})
		} else {
			fmt.Printf("%s\n  unreachable: %v\n\n", host, err)
		}
		// Network blips, a VIP not up yet, DNS not propagated -- all worth retrying.
		return exitUnreachable, true
	}

	if e.Now.IsZero() {
		e.Now = time.Now()
	}

	// EVERY resolved address decides the verdict, not the first one that answered.
	//
	// Probe (the first successful address) was what this used, while the daemon's runner uses
	// ProbeAll so that "an updated node cannot hide a node still serving an old cert". A rebind
	// rolls through the backends one at a time, so the CLI's whole reason to exist -- "wait until
	// the certificate took effect" -- was answered by whichever address happened to answer first,
	// next to a printed list of every resolved IP.
	code = exitOK
	for i, a := range attempts {
		if a.Err != nil {
			if asJSON {
				emitJSON(map[string]any{"host": host, "address": a.Address, "error": a.Err.Error(), "attempt": attempt})
			} else {
				fmt.Printf("%s (%s)\n  unreachable: %v\n\n", host, a.Address, a.Err)
			}
			code = worseExitCode(code, exitUnreachable)
			continue
		}
		if a.Result == nil {
			continue
		}
		v := a.Result.Verify(e)
		if asJSON {
			emitJSON(map[string]any{
				"host": host, "address": a.Address, "result": a.Result, "verdict": v,
				"attempt": attempt, "addressIndex": i,
			})
		} else {
			printHuman(a.Result, v, e.Now)
		}
		if !v.OK {
			code = worseExitCode(code, exitMismatch)
		}
	}

	// A mismatch outranks unreachable (see worseExitCode), and any bad answer means "waiting a
	// little longer might help": seeing the old certificate in the ~15s after a rebind is normal.
	return code, code != exitOK
}

func printHuman(res *probe.Result, v probe.Verdict, now time.Time) {
	fmt.Printf("%s\n", res.Host)
	fmt.Printf("  remote      %s\n", res.RemoteAddr)
	fmt.Printf("  resolved    %s\n", strings.Join(res.ResolvedIPs, ", "))
	fmt.Printf("  subject     %s\n", res.Subject)
	fmt.Printf("  issuer      %s\n", res.Issuer)
	if res.Trusted {
		fmt.Printf("  trusted     yes\n")
	} else {
		// Untrusted is not the same as bad: an internal CA is legitimate but turns browsers red.
		fmt.Printf("  trusted     no (%s)\n", firstLine(res.ChainError))
	}
	fmt.Printf("  validity    %s -> %s  (%d days left)\n",
		res.NotBefore.UTC().Format(time.RFC3339), res.NotAfter.UTC().Format(time.RFC3339), res.DaysLeft(now))
	fmt.Printf("  sans        %s\n", strings.Join(res.SANs, ", "))
	fmt.Printf("  handshake   %dms\n", res.HandshakeMS)

	if v.OK {
		fmt.Printf("  verdict     ok\n\n")
		return
	}
	fmt.Printf("  verdict     FAILED\n")
	for _, p := range v.Problems {
		fmt.Printf("    - %s\n", p)
	}
	fmt.Println()
}

// emitJSON writes one JSON object per line.
//
// It used to indent, which made each object span ~30 lines: the documented contract (README.md,
// README.zh-cn.md, docs/test-cases.md TC-PROBE-20/21/21b) is NDJSON -- one attempt per line, so
// `... | while read -r line; do jq . <<<"$line"; done` works -- and the docs were right about the
// intent while the code was not. A multi-address host or a -wait retry therefore produced a
// stream that no line-oriented consumer could read.
func emitJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(v)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	}) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return "no chain error reported"
	}
	return s
}
