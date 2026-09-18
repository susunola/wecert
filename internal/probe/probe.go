// Package probe verifies from the network side that "this certificate is really serving".
//
// The cloud API reporting a successful binding and a browser actually receiving this
// certificate are two different things. Binding confirmation travels the control plane,
// whereas this package dials a real TLS connection and reads back the certificate the peer
// **actually presents**. It is the only evidence in this system that does not trust the
// control plane.
//
// Why not use Go's default verification and let the handshake fail outright:
// that would tell us only "it failed", never "what it presented". The most useful
// troubleshooting information is precisely the certificate that should not be there --
// whether it is expired, belongs to someone else's domain, or is simply the self-signed
// default. So the handshake is completed first to get the certificate in hand, and the
// judgment is made afterwards here.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultTimeout is the default timeout for a single probe.
//
// 10 seconds is deliberately generous: this probe usually dials from a CVM to a public VIP,
// and a cross-availability-zone handshake taking 3-5 seconds is normal. Setting it to 3
// seconds would make it cry wolf constantly, and false alarms train people to ignore
// alerts -- worse than not probing at all.
const DefaultTimeout = 10 * time.Second

// Result is the outcome of a successful probe: what the peer actually presented.
type Result struct {
	// Host is the name used for probing, and the SNI in the handshake.
	Host string `json:"host"`

	// RemoteAddr is the address the connection was actually established with.
	RemoteAddr string `json:"remoteAddr"`

	// ResolvedIPs is every address this name resolved to.
	//
	// Kept separately because one of the most common causes of "wrong certificate" is DNS
	// pointing at some other machine, and that information is the easiest thing to lose from
	// a failure summary.
	ResolvedIPs []string `json:"resolvedIPs"`

	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	Serial    string    `json:"serial"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
	SANs      []string  `json:"sans"`

	// Trusted reports whether this chain verifies against the system roots.
	//
	// Self-signed or internal-CA certificates will be false -- that is not an error, but it
	// has to be visible: a certificate issued by an internal CA passes in curl and shows red
	// in a browser.
	Trusted bool `json:"trusted"`

	// ChainError is why chain verification failed; empty when Trusted is true.
	ChainError string `json:"chainError,omitempty"`

	// HandshakeMS is the handshake duration, used to separate "wrong certificate" from
	// "absurdly slow".
	HandshakeMS int64 `json:"handshakeMs"`

	// cert keeps the leaf certificate itself, for VerifyHostname.
	// Hand-rolling wildcard matching is the most classic class of bug in this kind of code
	// and is not worth rewriting.
	cert *x509.Certificate
}

// Options controls a single probe.
type Options struct {
	// Port defaults to 443.
	Port int

	// Timeout defaults to DefaultTimeout.
	Timeout time.Duration
}

// Attempt is the TLS probe result for one resolved IP address.
//
// Exactly one of Result and Err is non-nil. Address is the dialled endpoint so
// a partially updated backend can be distinguished from an ordinary mismatch.
type Attempt struct {
	Address string
	Result  *Result
	Err     error
}

// Probe dials host:port, completes a TLS handshake with SNI=host, and reads back the
// leaf certificate the peer presents.
//
// This is the simple API for the CLI and callers: it tries addresses in order
// and returns the first successful result. Use ProbeAll to verify every backend;
// Runner uses it so an updated node cannot hide a node still serving an old cert.
func Probe(ctx context.Context, host string, opts Options) (*Result, error) {
	host, ips, opts, err := prepareProbe(ctx, host, opts)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, ip := range ips {
		attempt := probeIP(ctx, host, ip, opts)
		if attempt.Result != nil {
			attempt.Result.ResolvedIPs = append([]string(nil), ips...)
			return attempt.Result, nil
		}
		if attempt.Err != nil {
			lastErr = attempt.Err
		}
	}
	return nil, fmt.Errorf("probe: none of the %d address(es) of %s completed a TLS handshake on port %d "+
		"(last error: %w)", len(ips), host, opts.Port, lastErr)
}

// ProbeAll dials every address resolved for host and preserves each result.
//
// opts.Timeout is the full per-address budget after DNS resolution, shared by
// TCP dial and TLS handshake. Limiting dial alone lets a faulty endpoint that
// accepts TCP but never sends TLS bytes block reconciliation indefinitely.
func ProbeAll(ctx context.Context, host string, opts Options) ([]Attempt, error) {
	host, ips, opts, err := prepareProbe(ctx, host, opts)
	if err != nil {
		return nil, err
	}
	attempts := probeIPs(ctx, host, ips, opts)
	for i := range attempts {
		if attempts[i].Result != nil {
			attempts[i].Result.ResolvedIPs = append([]string(nil), ips...)
		}
	}
	return attempts, nil
}

func prepareProbe(ctx context.Context, host string, opts Options) (string, []string, Options, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return "", nil, opts, errors.New("probe: empty host")
	}
	if strings.HasPrefix(host, "*.") {
		return "", nil, opts, fmt.Errorf("probe: %q is a wildcard, which has no address of its own to dial; "+
			"probe a concrete name that the same certificate covers", host)
	}
	if opts.Port == 0 {
		opts.Port = 443
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}

	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return "", nil, opts, fmt.Errorf("probe: resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return "", nil, opts, fmt.Errorf("probe: %s resolved to no address", host)
	}
	// Refuse rather than sample a name with an implausible number of addresses.
	//
	// Every resolved address has to be checked (that is the whole point of ProbeAll: a rebind can
	// take effect on some backends and not others), so the honest answer to "there are more
	// addresses than this cap" is "this name cannot be verified", not "here are the first 32". The
	// cost of not capping is bounded but real: len(ips) dials of up to Timeout each, inside the
	// certificate's own pass claim, so one name with a thousand A records delays every other
	// certificate. 32 is far above any real deployment -- a name spread over more than a handful of
	// addresses is either a misconfiguration or a name whose owner is not trying to serve it.
	if err := capCheck(host, len(ips)); err != nil {
		return "", nil, opts, err
	}
	sort.Strings(ips)
	return host, ips, opts, nil
}

// maxProbeAddresses caps how many addresses one host may resolve to before the probe refuses it.
//
// See prepareProbe: the cap exists so that a single name cannot spend an unbounded amount of a
// pass's time, and it fails closed because a sample would be a claim the probe cannot support.
const maxProbeAddresses = 32

// probeIPConcurrency caps how many of one host's addresses are dialled at once.
//
// Small on purpose: this bounds a single host's address list, not a fan-out over
// hosts (that cap lives in the reconciler).
const probeIPConcurrency = 8

// probeIPs is ProbeAll's per-address work, separated so multi-address behavior
// can be tested without depending on local DNS ordering.
//
// The addresses are dialled concurrently. In series, a single blackholed address
// -- a dropped SYN, which is exactly what a security-group or route
// misconfiguration looks like -- costs the full per-address budget before the next
// address is even attempted. A host then spends len(ips) x Timeout, every probed
// certificate waits its turn behind it, and the whole pass stretches by minutes.
func probeIPs(ctx context.Context, host string, ips []string, opts Options) []Attempt {
	attempts := make([]Attempt, len(ips))
	if len(ips) == 0 {
		return attempts
	}

	limit := probeIPConcurrency
	if len(ips) < limit {
		limit = len(ips)
	}

	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup

	for i, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			// Each goroutine writes only its own index; no overlap, so no lock is needed.
			attempts[i] = probeIP(ctx, host, ip, opts)
		}(i, ip)
	}
	wg.Wait()

	return attempts
}

func probeIP(ctx context.Context, host, ip string, opts Options) Attempt {

	// Do not use tls.DialWithDialer: dial and handshake must share the same
	// context so every address is bound by the full probe budget.
	dialer := &net.Dialer{Timeout: opts.Timeout}
	addr := net.JoinHostPort(ip, strconv.Itoa(opts.Port))

	// A DialContext timeout is not enough: after TCP connects, TLS can wait
	// forever for peer data. Every IP needs its own full budget.
	attemptCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	res, err := probeAddr(attemptCtx, dialer, addr, host)
	if err != nil {
		return Attempt{Address: addr, Err: err}
	}
	return Attempt{Address: addr, Result: res}
}

func probeAddr(ctx context.Context, dialer *net.Dialer, addr, sni string) (*Result, error) {
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	// HandshakeContext observes cancellation, but an I/O deadline also guards
	// against transports that are stuck below the TLS state machine. Clear it
	// after the handshake so the captured connection state can be inspected
	// without inheriting a stale deadline.
	if deadline, ok := ctx.Deadline(); ok {
		if err := raw.SetDeadline(deadline); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("set probe deadline for %s: %w", addr, err)
		}
	}

	cfg := &tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS12,

		// This is the reason this package exists, not an oversight.
		// If Go were allowed to fail the handshake over a bad chain or name we would never get
		// that certificate, and "what exactly did it present" is the question being asked.
		// The judging happens in Verify instead.
		InsecureSkipVerify: true,
	}

	conn := tls.Client(raw, cfg)
	defer conn.Close()

	start := time.Now()
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS handshake with %s (SNI %s): %w", addr, sni, err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clear probe deadline for %s: %w", addr, err)
	}
	elapsed := time.Since(start)

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("%s completed a handshake without presenting a certificate", addr)
	}
	leaf := state.PeerCertificates[0]

	res := &Result{
		Host:        sni,
		RemoteAddr:  conn.RemoteAddr().String(),
		Subject:     leaf.Subject.String(),
		Issuer:      leaf.Issuer.String(),
		Serial:      leaf.SerialNumber.Text(16),
		NotBefore:   leaf.NotBefore,
		NotAfter:    leaf.NotAfter,
		SANs:        append([]string(nil), leaf.DNSNames...),
		HandshakeMS: elapsed.Milliseconds(),
		cert:        leaf,
	}

	// Chain verification is done separately; a failure does not affect the fields above.
	// Roots is left nil so x509 uses the system root pool.
	inter := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: sni, Intermediates: inter}); err != nil {
		res.ChainError = err.Error()
	} else {
		res.Trusted = true
	}

	return res, nil
}

// Expectation is "what this address is expected to exhibit".
type Expectation struct {
	// Domains is every domain (including wildcards) the deployed certificate should cover.
	//
	// When non-empty this is compared as a set, not as "covers at least one of them" -- with
	// several certificates on a CLB, the most dangerous shape is exactly "the name passes but
	// a different certificate is serving".
	Domains []string

	// NotAfter is the expiry time recorded in the state database.
	//
	// When non-zero it answers "is what the peer presented the one I deployed" rather than
	// weakening to "some certificate that has not expired yet". The difference between those
	// two is exactly "the rebind took effect" versus "the rebind never happened".
	NotAfter time.Time

	// MinValidFor is "how much validity must at least remain".
	MinValidFor time.Duration

	// Now is injectable to make testing easier.
	Now time.Time
}

// Verdict is the comparison outcome.
type Verdict struct {
	// OK is true when every check passed.
	OK bool `json:"ok"`

	// Problems is the human-facing list of problems, each standing as its own conclusion.
	Problems []string `json:"problems,omitempty"`
}

// Summary returns a one-line summary for logs and CLI output.
func (v Verdict) Summary() string {
	if v.OK {
		return "ok"
	}
	return strings.Join(v.Problems, "; ")
}

// Verify compares the probe result against the expectation.
//
// The four classes of problem are reported separately rather than merged into one
// "verification failed": they point in completely different directions -- a name mismatch
// means looking at DNS and CLB rules, a different certificate means checking whether the
// rebind took effect, and an expired one means finding out why renewal never ran.
func (r *Result) Verify(e Expectation) Verdict {
	now := e.Now
	if now.IsZero() {
		now = time.Now()
	}

	var problems []string

	// 1. Does this certificate cover the name I dialed?
	// This is the most fundamental one: if it does not cover it, the checks below are moot.
	if r.cert == nil {
		problems = append(problems, "no certificate was captured")
	} else if err := r.cert.VerifyHostname(r.Host); err != nil {
		problems = append(problems, fmt.Sprintf("the served certificate does not cover %s "+
			"(it covers %s)", r.Host, formatSANs(r.SANs)))
	}

	// 2. Does the coverage match the certificate that was deployed?
	if len(e.Domains) > 0 && r.cert != nil {
		missing, extra := diffDomains(e.Domains, r.SANs)
		if len(missing) > 0 {
			problems = append(problems, fmt.Sprintf(
				"the served certificate is missing names that were deployed: %s", strings.Join(missing, ", ")))
		}
		if len(extra) > 0 {
			problems = append(problems, fmt.Sprintf(
				"the served certificate has names that were not deployed: %s "+
					"(a different certificate is being served, or the deploy wrote something unexpected)",
				strings.Join(extra, ", ")))
		}
	}

	// 3. Is this the one I deployed?
	if !e.NotAfter.IsZero() && !r.NotAfter.Equal(e.NotAfter) {
		problems = append(problems, fmt.Sprintf(
			"the served certificate expires at %s but the deployed one expires at %s "+
				"(the rebind did not take effect, or another certificate is winning SNI)",
			r.NotAfter.UTC().Format(time.RFC3339), e.NotAfter.UTC().Format(time.RFC3339)))
	}

	// 4. How much time is left?
	if e.MinValidFor > 0 {
		left := r.NotAfter.Sub(now)
		if left < e.MinValidFor {
			problems = append(problems, fmt.Sprintf(
				"the served certificate has %s left, less than the required %s",
				left.Round(time.Hour), e.MinValidFor))
		}
	}

	return Verdict{OK: len(problems) == 0, Problems: problems}
}

// formatSANs compresses the SAN list into one readable phrase.
func formatSANs(sans []string) string {
	if len(sans) == 0 {
		return "no names at all"
	}
	if len(sans) > 4 {
		return strings.Join(sans[:4], ", ") + fmt.Sprintf(" and %d more", len(sans)-4)
	}
	return strings.Join(sans, ", ")
}

// diffDomains compares "what should be there" against "what is there", ignoring order,
// case and duplicates.
func diffDomains(want, got []string) (missing, extra []string) {
	w := normalizeSet(want)
	g := normalizeSet(got)

	for d := range w {
		if !g[d] {
			missing = append(missing, d)
		}
	}
	for d := range g {
		if !w[d] {
			extra = append(extra, d)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra
}

func normalizeSet(in []string) map[string]bool {
	out := make(map[string]bool, len(in))
	for _, d := range in {
		out[normalizeName(d)] = true
	}
	return out
}

// normalizeName canonicalises one name the same way however many times it is called.
//
// Trimming the spaces BEFORE stripping the dot is not idempotent: "www.example.com.." keeps one dot
// after the first pass and loses it on the second, and "www.example.com ." only loses the space on
// the second. The CLI splits -expect-san straight into the expectation, so either spelling made
// Verify report the same name as both "missing names that were deployed" and "has names that were
// not deployed" -- a self-contradictory verdict for one typo, with exit code 2. Loop until the
// string stops changing instead.
func normalizeName(d string) string {
	prev := d
	for {
		next := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(prev)), ".")
		if next == prev {
			return next
		}
		prev = next
	}
}

// DaysLeft returns the days remaining, rounded up -- "0 days left" is a meaningless thing
// to say.
func (r *Result) DaysLeft(now time.Time) int {
	if now.IsZero() {
		now = time.Now()
	}
	left := r.NotAfter.Sub(now)
	if left <= 0 {
		return 0
	}
	return int((left + 24*time.Hour - 1) / (24 * time.Hour))
}

// capCheck refuses an address list longer than maxProbeAddresses.
//
// Separated from prepareProbe so the boundary is testable without a DNS server that returns 33
// addresses: the decision is the whole behaviour.
func capCheck(host string, n int) error {
	if n <= maxProbeAddresses {
		return nil
	}
	return fmt.Errorf(
		"probe: %s resolves to %d addresses, more than the %d this program will dial; every "+
			"resolved address has to be checked, so the name is reported as unverified rather "+
			"than sampled", host, n, maxProbeAddresses)
}
