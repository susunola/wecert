// Command clbverify queries the certificate bound to a CLB listener, for end-to-end assertions.
//
// Why it is its own tool: after wecert calls UpdateCertificateInstance, the only
// authoritative fact is whether the listener's CertId actually changed. Trusting wecert's
// own logs is not enough -- that is the blind spot of "the program believed it succeeded but
// nothing took effect", the most insidious failure class. This tool gathers independent
// evidence from the Tencent Cloud side.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	clb "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/clb/v20180317"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
)

// exitUsage is the conventional "the command line itself is wrong" code, the same one wecert,
// wecert-onboard and wecert-probe use -- not 1 (documented here as "the program ran and failed") and
// not flag's default 2 (documented as wecert-onboard's "deliberately frozen" code).
const exitUsage = 64

// errUsage marks a command-line error; the flag package has already explained it on stderr.
var errUsage = errors.New("invalid command line")

func main() {
	if err := run(); err != nil {
		if errors.Is(err, errUsage) {
			os.Exit(exitUsage)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("clbverify", flag.ContinueOnError)
	var (
		region     = fs.String("region", "", "region, e.g. ap-guangzhou")
		lbID       = flag.String("clb", "", "CLB instance ID")
		listenerID = fs.String("listener", "", "listener ID; when omitted, the first listener on that CLB is used")
		expect     = fs.String("expect", "", "certificate ID that must be in the asserted set; when set the assertion must hold")
		domain     = fs.String("domain", "", "assert on the certificate the forwarding rule for this domain serves (SNI); when omitted every certificate on the listener and its rules is asserted")
		notExpect  = fs.String("not-expect", "", "certificate ID that must NOT be present")
		raw        = fs.Bool("raw", false, "dump the raw DescribeListeners JSON response for troubleshooting")
		wait       = fs.Duration("wait", 0, "how long to poll for the expected certificate (UpdateCertificateInstance is asynchronous)")
	)
	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return errUsage
	}

	if *region == "" || *lbID == "" {
		return fmt.Errorf("%w: -region and -clb are required (-listener is optional; when omitted, "+
			"the first listener on that CLB is used)", errUsage)
	}

	cred := common.NewCredential(
		os.Getenv("TENCENTCLOUD_SECRET_ID"),
		os.Getenv("TENCENTCLOUD_SECRET_KEY"),
	)
	if msg := missingCredential(cred.GetSecretId(), cred.GetSecretKey()); msg != "" {
		return fmt.Errorf("%s", msg)
	}

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "clb.tencentcloudapi.com"

	client, err := clb.NewClient(cred, *region, cpf)
	if err != nil {
		return fmt.Errorf("build CLB client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req := clb.NewDescribeListenersRequest()
	req.LoadBalancerId = common.StringPtr(*lbID)
	// With no ListenerIds, every listener on the CLB comes back.
	// Observed while debugging: filtering by ListenerIds can return entries without the
	// Certificate field, so the unfiltered path is kept for cross-checking.
	if *listenerID != "" {
		req.ListenerIds = []*string{common.StringPtr(*listenerID)}
	}

	resp, err := client.DescribeListenersWithContext(ctx, req)
	if err != nil {
		return fmt.Errorf("DescribeListeners: %w", err)
	}
	if resp.Response == nil || len(resp.Response.Listeners) == 0 {
		return noListenersError(*lbID, *listenerID)
	}

	// The verdict comes from one place, so -raw cannot skip the assertions. It used to return
	// here with the dump and no verdict, which silently disabled -expect/-not-expect: a script
	// that added -raw while debugging kept exiting 0 without asserting anything.
	return evaluateListener(os.Stdout, resp, verifyOptions{
		raw:       *raw,
		domain:    *domain,
		expect:    *expect,
		notExpect: *notExpect,
		wait:      *wait,
	}, func(ctx context.Context) ([]string, error) {
		return fetchBoundCertIDs(ctx, client, *lbID, *listenerID, *domain)
	})
}

// missingCredential reports the message to return when either credential half is empty, and "" when
// both are present.
//
// Both halves are required: checking only the secret id let an empty TENCENTCLOUD_SECRET_KEY through
// a guard whose message names both variables, so the failure surfaced later as an authentication
// error from the API client -- a layer that cannot say which variable is empty. Split out so the
// check itself has a test; the flags and the client are irrelevant to it.
func missingCredential(id, key string) string {
	if id == "" || key == "" {
		return "missing credentials: set TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY"
	}
	return ""
}

// verifyOptions are the flags that decide what gets printed and asserted.
type verifyOptions struct {
	raw       bool
	domain    string
	expect    string
	notExpect string
	wait      time.Duration
}

// evaluateListener prints what the listener serves and applies the assertions.
//
// The output writer and the refetch function are parameters so this logic has a test: it is the
// whole point of the tool, and the -raw branch is exactly where an assertion can go missing.
func evaluateListener(w io.Writer, resp *clb.DescribeListenersResponse, o verifyOptions, refetch func(context.Context) ([]string, error)) error {
	if o.raw {
		// For troubleshooting: print the server's response verbatim, so that a mismatch
		// between the field names we assume and what the API really returns is not a guess.
		b, err := json.MarshalIndent(resp.Response, "", "  ")
		if err != nil {
			return fmt.Errorf("encode response: %w", err)
		}
		fmt.Fprintln(w, string(b))
	}

	l := resp.Response.Listeners[0]
	fmt.Fprintf(w, "listener %s  (%s:%d)\n", derefStr(l.ListenerId), derefStr(l.Protocol), derefI64(l.Port))

	// What the listener itself carries. In CLB's SNI model this is often EMPTY and the
	// certificates live on the forwarding rules instead: the API ignores listener-level
	// certificate fields when SNI is on, and this project's own test account cannot turn SNI
	// off. Failing here with "the listener has no certificate bound" -- which is what this
	// tool used to do -- therefore reported a healthy, serving listener as broken.
	listenerCerts := boundCertIDs(l.Certificate)
	if len(listenerCerts) > 0 {
		fmt.Fprintf(w, "  listener certificates: %v\n", listenerCerts)
	} else {
		fmt.Fprintf(w, "  listener certificates: none\n")
	}

	// Per-rule certificates: one per SNI name, and the set that actually decides which
	// certificate a given hostname is served. Rotating one must not disturb another, which is
	// why they are printed and asserted individually rather than summarised.
	rules := ruleCertificates(l)
	for _, r := range rules {
		fmt.Fprintf(w, "  rule %-28s %v\n", r.domain, r.certIDs)
	}

	asserted, scope, err := assertedCertificates(l, o.domain)
	if err != nil {
		return err
	}
	if len(asserted) == 0 {
		if o.domain != "" {
			return fmt.Errorf("no certificate is bound to the rule serving %q, so nothing can be asserted", o.domain)
		}
		return fmt.Errorf("no certificate is bound to listener %s or to any of its %d rule(s)",
			derefStr(l.ListenerId), len(rules))
	}
	fmt.Fprintf(w, "  asserted set (%s): %v\n", scope, asserted)
	bound := asserted

	// UpdateCertificateInstance is asynchronous: a return means only that the task was
	// created; the real rebind waits on the backend (~15s measured), so the assertion must wait.
	if o.expect != "" && o.wait > 0 && !contains(bound, o.expect) {
		// The wait loop needs its own, long-enough ctx.
		//
		// Reusing the 30-second ctx above makes every request return deadline exceeded once
		// -wait exceeds 30s, while the continue below swallows the error -- so it spins until
		// the deadline and then falsely reports "still not the expected value", which is
		// precisely the one scenario this tool exists for.
		waitCtx, cancelWait := context.WithTimeout(context.Background(), o.wait+30*time.Second)
		defer cancelWait()

		// `=` and a declared lastErr, not `:=`: an := here declares a NEW bound that shadows the
		// one the assertions below read, so the wait would poll away and then assert against the
		// stale pre-wait set -- failing exactly when the rebind did land, which is the case -wait
		// exists for.
		var lastErr error
		bound, lastErr = pollUntilBound(waitCtx, o.wait, func() ([]string, error) {
			return refetch(waitCtx)
		}, o.expect, func(ids []string, err error) {
			if err != nil {
				// The query failing and "not switched over yet" are two different things, and
				// both have to be visible.
				fmt.Fprintf(w, "  ...query failed, retrying shortly: %v\n", err)
				return
			}
			fmt.Fprintf(w, "  ...waiting; currently bound to %v\n", ids)
		})
		if !contains(bound, o.expect) && lastErr != nil {
			fmt.Fprintf(w, "  ...note: the final query also failed, so the assertion above may not be trustworthy: %v\n", lastErr)
		}
		fmt.Fprintln(w)
	}

	// The assertions look at every certificate the listener carries, primary and SNI
	// alike. Reporting "-not-expect <old> passed" while the old certificate is still bound
	// as an extension cert is the exact failure this tool exists to catch.
	if err := assertBindings(bound, o.expect, o.notExpect, scope, o.wait); err != nil {
		return err
	}
	if o.expect != "" {
		fmt.Fprintf(w, "\nOK: assertion passed - %s is bound (%s)\n", o.expect, scope)
	}
	return nil
}

// assertBindings applies -expect and -not-expect to the set that was observed.
//
// Separated from the flags and the client so the assertion itself has a test: it is the whole point
// of this tool, and the wait path around it is exactly where a stale set can hide (a shadowed
// variable cost a false "still not bound" for every -wait run that succeeded).
func assertBindings(bound []string, expect, notExpect, scope string, wait time.Duration) error {
	if notExpect != "" && contains(bound, notExpect) {
		return fmt.Errorf("assertion failed: %s is still bound (%s: %v), which should be gone",
			notExpect, scope, bound)
	}
	if expect != "" && !contains(bound, expect) {
		return fmt.Errorf("assertion failed: after waiting %s %s is still not bound (%s: %v)",
			wait, expect, scope, bound)
	}
	return nil
}

// bindingsPollInterval is how long to wait between queries while -wait allows it.
//
// The sleep is capped to whatever remains of the budget, so this is a ceiling rather than a
// fixed delay.
const bindingsPollInterval = 5 * time.Second

// pollUntilBound polls fetch until the expected certificate appears or the budget runs out, and
// returns the last set it saw plus the last query error.
//
// The sleep is capped to whatever remains of the budget. Sleeping a flat interval before checking
// the deadline meant -wait bounded the number of attempts rather than the time: `-wait 1s` blocked
// for the full interval and then queried. The sibling tool in this repository was fixed for exactly
// that (see wecert-probe's TestCheckOneWaitBoundsElapsedTimeNotJustAttempts); a caller that budgets
// its own time -- CI, a systemd unit -- is entitled to have the flag mean what its help says.
func pollUntilBound(
	ctx context.Context,
	budget time.Duration,
	fetch func() ([]string, error),
	expect string,
	onAttempt func(ids []string, err error),
) (ids []string, lastErr error) {
	deadline := time.Now().Add(budget)

	for {
		// Query first, then wait. Sleeping before the first query meant a budget shorter than
		// the poll interval produced no query at all, which is the opposite of what -wait asks
		// for: it is a budget for how long to keep looking, not a delay before looking.
		got, err := fetch()
		if err != nil {
			// No more silent continue: the query itself failing and "not switched over yet" are
			// two completely different things, and both must be visible.
			lastErr = err
		} else {
			lastErr = nil
			ids = got
			if contains(ids, expect) {
				if onAttempt != nil {
					onAttempt(got, nil)
				}
				return ids, nil
			}
		}
		if onAttempt != nil {
			onAttempt(ids, lastErr)
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return ids, lastErr
		}
		if remaining > bindingsPollInterval {
			remaining = bindingsPollInterval
		}
		select {
		case <-ctx.Done():
			return ids, lastErr
		case <-time.After(remaining):
		}
	}
}

// ruleCert is one forwarding rule's SNI binding.
type ruleCert struct {
	domain     string
	locationID string
	certIDs    []string
}

// ruleCertificates returns the certificate each forwarding rule serves, in order.
//
// Rule-level bindings are not decoration: with SNI on, the rule is what decides the certificate
// for its hostname (that is how CLB implements multiple certificates on one listener), so a tool
// that only looks at Listener.Certificate is blind to the binding it is supposed to verify. This
// repository hit exactly that: the e2e account cannot turn SNI off, so the listener carries no
// certificate at all and every certificate lives on a rule.
func ruleCertificates(l *clb.Listener) []ruleCert {
	if l == nil {
		return nil
	}
	out := make([]ruleCert, 0, len(l.Rules))
	for _, r := range l.Rules {
		if r == nil {
			continue
		}
		out = append(out, ruleCert{
			domain:     derefStr(r.Domain),
			locationID: derefStr(r.LocationId),
			certIDs:    boundCertIDs(r.Certificate),
		})
	}
	return out
}

// assertedCertificates returns the set the flags are checked against, and a label saying what
// that set is.
//
// Without -domain it is every certificate the listener can serve: the listener-level primary and
// SNI extensions plus each rule's own certificate. Reporting "-not-expect <old> passed" while the
// old certificate is still bound on the rule that serves the name is the exact false assurance
// this tool exists to prevent.
//
// With -domain it is the certificate(s) of the rule(s) serving that name, because that is the
// binding that decides what a client is handed. Naming a domain that no rule serves is an error
// rather than an empty pass: a typo must not read as "nothing is bound to the old certificate".
func assertedCertificates(l *clb.Listener, domain string) (ids []string, scope string, err error) {
	seen := map[string]bool{}
	add := func(list []string) {
		for _, id := range list {
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			ids = append(ids, id)
		}
	}

	if domain == "" {
		add(boundCertIDs(l.Certificate))
		for _, r := range ruleCertificates(l) {
			add(r.certIDs)
		}
		return ids, "listener + rules", nil
	}

	matched := false
	for _, r := range ruleCertificates(l) {
		if strings.EqualFold(r.domain, domain) {
			matched = true
			add(r.certIDs)
		}
	}
	if !matched {
		return nil, "", fmt.Errorf("no forwarding rule on this listener serves %q, so there is nothing to assert "+
			"(rules: %s)", domain, ruleDomains(l))
	}
	return ids, "rule for " + domain, nil
}

// ruleDomains renders the listener's rule domains for an error message.
func ruleDomains(l *clb.Listener) string {
	rules := ruleCertificates(l)
	if len(rules) == 0 {
		return "none"
	}
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.domain)
	}
	return strings.Join(out, ", ")
}

// boundCertIDs is every certificate one binding carries: the primary one plus the SNI
// extension certificates, which are separate server certificates in the
// multi-certificate case.
func boundCertIDs(c *clb.CertificateOutput) []string {
	if c == nil {
		return nil
	}
	out := make([]string, 0, 1+len(c.ExtCertIds))
	if c.CertId != nil && *c.CertId != "" {
		out = append(out, *c.CertId)
	}
	for _, e := range c.ExtCertIds {
		if e != nil && *e != "" {
			out = append(out, *e)
		}
	}
	return out
}

func contains(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// noListenersError words the empty-listener failure to fit how the query was made:
// without a -listener filter an empty list really means the CLB has no listeners, but
// with one it means that specific listener matched nothing -- deleted, or a typo --
// while the CLB itself may be serving other listeners just fine. Blaming the CLB in
// that case sends the operator debugging the wrong object.
func noListenersError(lbID, listenerID string) error {
	if listenerID != "" {
		return fmt.Errorf("CLB %s returned no listener %s (it may have been deleted, or the ID is a typo)", lbID, listenerID)
	}
	return fmt.Errorf("CLB %s has no listeners", lbID)
}

// fetchBoundCertIDs returns every certificate the listener carries, primary first.
//
// The assertions need the whole set, not just the primary: a listener may serve the
// managed certificate as an SNI extension certificate, and comparing only the primary
// both misses a stale binding and rejects a correct one.
func fetchBoundCertIDs(ctx context.Context, client *clb.Client, lbID, listenerID, domain string) ([]string, error) {
	req := clb.NewDescribeListenersRequest()
	req.LoadBalancerId = common.StringPtr(lbID)
	if listenerID != "" {
		req.ListenerIds = []*string{common.StringPtr(listenerID)}
	}

	resp, err := client.DescribeListenersWithContext(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp.Response == nil || len(resp.Response.Listeners) == 0 {
		return nil, fmt.Errorf("the listener does not exist")
	}
	// The same asserted set the first query uses, domain filter included: polling the
	// listener-level field alone would spin until the deadline while the rule it is asked about
	// already serves the new certificate.
	ids, _, err := assertedCertificates(resp.Response.Listeners[0], domain)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no certificate bound")
	}
	return ids, nil
}

func derefStr(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

func derefI64(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}
