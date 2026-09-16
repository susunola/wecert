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

func run() int {
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
		wait     = fs.Duration("wait", 0, "poll until the verdict is ok or this long elapses (e.g. 90s)")
		asJSON   = fs.Bool("json", false, "print the raw result as JSON")
		showVer  = fs.Bool("version", false, "print the version and exit")
	)

	if err := fs.Parse(os.Args[1:]); err != nil {
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

	e := probe.Expectation{
		Domains:     splitList(*expectSA),
		MinValidFor: *minValid,
	}
	if *expectNA != "" {
		t, err := time.Parse(time.RFC3339, *expectNA)
		if err != nil {
			fmt.Fprintf(os.Stderr, "wecert-probe: -expect-not-after must be RFC3339: %v\n", err)
			return exitUsage
		}
		e.NotAfter = t
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	opts := probe.Options{Port: *port, Timeout: *timeout}

	// Worst result for the summary: a mismatch deserves to stop a script more than an
	// unreachable host does, so it wins.
	worst := exitOK
	for _, host := range hosts {
		code := checkOne(ctx, host, opts, e, *wait, *asJSON)
		if code == exitMismatch {
			worst = exitMismatch
		} else if code == exitUnreachable && worst == exitOK {
			worst = exitUnreachable
		}
	}
	return worst
}

// checkOne probes one name, polling while there is time, and returns its exit code.
func checkOne(ctx context.Context, host string, opts probe.Options, e probe.Expectation, wait time.Duration, asJSON bool) int {
	deadline := time.Time{}
	if wait > 0 {
		deadline = time.Now().Add(wait)
	}

	attempt := 0
	for {
		attempt++
		code, retry := attemptOnce(ctx, host, opts, e, asJSON, attempt)

		// Retry on both outcomes. An unreachable host may be a network blip, a VIP that is not
		// up yet or DNS that has not propagated; a mismatch is the normal shape for roughly 15
		// seconds after a rebind, because the old certificate is still the one being served.
		// Only an OK verdict is final.
		//
		// (This comment used to claim the opposite -- that unreachable and wrong-cert "won't fix
		// themselves". They do, which is why -wait exists; the stale wording invited removing
		// the retry.)
		if !retry || deadline.IsZero() || time.Now().After(deadline) {
			return code
		}
		if ctx.Err() != nil {
			return code
		}
		if !asJSON {
			fmt.Fprintf(os.Stderr, "  ... not there yet, retrying until %s\n",
				deadline.Format(time.RFC3339))
		}
		select {
		case <-ctx.Done():
			return code
		case <-time.After(5 * time.Second):
		}
	}
}

// attemptOnce probes once. A true retry means "waiting a little longer might help".
func attemptOnce(ctx context.Context, host string, opts probe.Options, e probe.Expectation, asJSON bool, attempt int) (code int, retry bool) {
	res, err := probe.Probe(ctx, host, opts)
	if err != nil {
		if asJSON {
			emitJSON(map[string]any{"host": host, "error": err.Error()})
		} else {
			fmt.Printf("%s\n  unreachable: %v\n\n", host, err)
		}
		// Network blips, a VIP not up yet, DNS not propagated -- all worth retrying.
		return exitUnreachable, true
	}

	if e.Now.IsZero() {
		e.Now = time.Now()
	}
	v := res.Verify(e)

	if asJSON {
		emitJSON(map[string]any{"host": host, "result": res, "verdict": v, "attempt": attempt})
	} else {
		printHuman(res, v, e.Now)
	}

	if v.OK {
		return exitOK, false
	}
	// Retry on a bad verdict too: seeing the old certificate in the ~15s after a rebind is normal.
	return exitMismatch, true
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

func emitJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
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
