package reconcile

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/metrics"
	"github.com/susunola/wecert/internal/probe"
	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
)

// A wildcard has no address of its own to dial.
//
// Take the first N in declaration order, not randomly or lexicographically:
// declaration order puts the registered domain first, and that is usually the
// name most worth verifying.
func TestProbeHostsSkipsWildcardsInOrder(t *testing.T) {
	got := probeHosts([]string{"example.com", "*.example.com", "www.example.com", "api.example.com"}, 3)
	want := []string{"example.com", "www.example.com", "api.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("probeHosts = %v, want %v", got, want)
	}
}

// Not exhaustive: a 25-name certificate would mean 25 handshakes per pass,
// with diminishing returns and linear cost.
func TestProbeHostsRespectsTheCap(t *testing.T) {
	domains := []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com"}
	got := probeHosts(domains, 2)
	if len(got) != 2 || got[0] != "a.example.com" || got[1] != "b.example.com" {
		t.Errorf("probeHosts = %v, want the first two", got)
	}
}

// A certificate of nothing but wildcards has no dialable names — that should
// not error, there is simply nothing to verify.
func TestProbeHostsReturnsNothingForAWildcardOnlyCert(t *testing.T) {
	if got := probeHosts([]string{"*.example.com", "*.api.example.com"}, 3); len(got) != 0 {
		t.Errorf("wildcards should not be dialed, got %v", got)
	}
}

// A cap of 0 means "off", to pause probing temporarily during an
// investigation.
func TestProbeHostsHandlesAZeroCap(t *testing.T) {
	if got := probeHosts([]string{"example.com"}, 0); got != nil {
		t.Errorf("with a cap of 0 nothing should be dialed, got %v", got)
	}
}

// A host that is no longer probed must have its metric series reclaimed.
//
// The probe vectors are labelled by host while metrics.DeleteCertSeries is labelled by
// certificate, so without this a host whose certificate left the desired state keeps
// exporting wecert_certificate_probe_match{host} at its last value forever -- and the
// documented alert on that being 0 then fires permanently for a host that is not even
// part of the desired state.
func TestStaleProbeSeriesAreReclaimed(t *testing.T) {
	// A live host and a stale one both have series from previous passes.
	metrics.CertificateProbeMatch.WithLabelValues("live.example.com").Set(1)
	metrics.CertificateProbeMatch.WithLabelValues("gone.example.com").Set(0)

	fake := &fakeProber{hosts: []string{"live.example.com", "gone.example.com"}}
	r := &Reconciler{
		probedHosts: map[string]struct{}{"live.example.com": {}},
		prober:      fake,
	}

	r.reclaimStaleProbeSeries(nil)

	if !probeMatchSeriesExists(t, "live.example.com") {
		t.Error("a host probed this round must keep its series")
	}
	if probeMatchSeriesExists(t, "gone.example.com") {
		t.Error("a host that is no longer probed must have its series reclaimed")
	}
	// The record is per-round: the next round must not consider this round's hosts live.
	r.probeMu.Lock()
	n := len(r.probedHosts)
	r.probeMu.Unlock()
	if n != 0 {
		t.Errorf("probedHosts should be reset for the next round, holds %d", n)
	}
}

// A prober that cannot enumerate its hosts is skipped rather than panicking.
func TestReclaimSkipsAProberWithoutHostEnumeration(t *testing.T) {
	r := &Reconciler{probedHosts: map[string]struct{}{}, prober: &opaqueProber{}}
	r.reclaimStaleProbeSeries(nil) // must not panic
}

type fakeProber struct {
	hosts []string

	// forgotten records Forget calls so a test can assert that a host which left
	// the desired state has its remembered probe state dropped.
	forgotten []string
}

func (f *fakeProber) Check(context.Context, string, probe.Expectation) probe.Verdict {
	return probe.Verdict{}
}
func (f *fakeProber) ProbedHosts() []string { return f.hosts }
func (f *fakeProber) Forget(host string)    { f.forgotten = append(f.forgotten, host) }

// opaqueProber implements only the required method: the optional capability
// interfaces (ProbedHosts) must be probed for, not required.
type opaqueProber struct{}

func (o *opaqueProber) Check(context.Context, string, probe.Expectation) probe.Verdict {
	return probe.Verdict{}
}

func (o *opaqueProber) Forget(string) {}

// probeMatchSeriesExists reports whether the exported series for this host is still
// present in the registry (a deleted series is simply absent, it does not read as 0).
func probeMatchSeriesExists(t *testing.T, host string) bool {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() != "wecert_certificate_probe_match" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "host" && l.GetValue() == host {
					return true
				}
			}
		}
	}
	return false
}

// recordingProber captures the expectations probeCert hands out.
type recordingProber struct {
	mu   sync.Mutex
	seen map[string]probe.Expectation
}

func (p *recordingProber) Check(_ context.Context, host string, e probe.Expectation) probe.Verdict {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen == nil {
		p.seen = map[string]probe.Expectation{}
	}
	p.seen[host] = e
	return probe.Verdict{}
}

func (p *recordingProber) Forget(string) {}

func (p *recordingProber) expected(host string) (probe.Expectation, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.seen[host]
	return e, ok
}

// The probe's "is the served certificate the one I deployed?" comparison must be made
// against the certificate that is actually stored, not the configured domain set.
//
// During a fallback the deployed certificate is deliberately a SUBSET: the dropped names
// are the ones whose DNS is broken. Comparing against the config made probe.Verify report
// "the served certificate is missing names that were deployed" for every host, which drove
// wecert_certificate_probe_match to 0 -- the gauge documented as the actionable "the rebind
// did not take effect" alert -- and made the prober dial names whose DNS is known broken.
func TestProbeExpectationFollowsTheDeployedSubsetNotTheConfig(t *testing.T) {
	const certName = "degraded-cert"

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("opening the state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	// Deployed: the reduced set (b.example.com was dropped by the fallback).
	// Configured: the full set, which still lists b.example.com.
	deployed := []string{"a.example.com", "c.example.com"}
	configured := []string{"a.example.com", "b.example.com", "c.example.com"}
	if err := store.PutCert(&state.CertState{
		Name: certName, NotAfter: time.Now().Add(48 * time.Hour),
		CertPEM:         selfSignedCertPEM(t, deployed...),
		DeployConfirmed: true,
	}); err != nil {
		t.Fatalf("PutCert: %v", err)
	}

	prov := &mutableProvider{}
	prov.set(config.Certificate{Name: certName, Domains: configured})
	cfg := &config.Config{}
	cfg.Certificates = []config.Certificate{{Name: certName, Domains: configured}}
	cfg.Probe.MaxHostsPerCert = 10

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := New(cfg, prov, store, &fakeManager{}, nil, log)
	rec := &recordingProber{}
	r.prober = rec

	c := &config.Certificate{Name: certName, Domains: configured, Deploy: config.Deploy{Enabled: true}}
	r.probeCert(context.Background(), c)

	e, ok := rec.expected("a.example.com")
	if !ok {
		t.Fatal("a.example.com should have been probed")
	}
	if len(e.Domains) != len(deployed) {
		t.Errorf("the expectation must describe the deployed set %v, got %v -- comparing against the "+
			"configured set reports a permanent mismatch on a certificate that is behaving correctly",
			deployed, e.Domains)
	}
	if _, probed := rec.expected("b.example.com"); probed {
		t.Error("the dropped name was probed; its DNS is broken by definition, so this only adds " +
			"probe errors for a certificate that is behaving as designed")
	}
}

// A host's probe series must survive a round that could not probe it because its
// certificate's pass was already in flight.
//
// A pass skips a certificate whose claim is held, so that certificate never reaches
// probeCert and never lands in this round's probed set. Reclaiming on "absent from this
// round" alone then deletes the series of a host that is being probed right now -- the
// flicker reclaimStaleProbeSeries exists to avoid, and a false alert for anything paging on
// wecert_certificate_probe_match.
func TestReclaimStaleProbeSeriesKeepsHostsOfAClaimedCertificate(t *testing.T) {
	const (
		certName = "in-flight-cert"
		host     = "live.example.com"
		goneHost = "dropped.example.com"
	)

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("opening the state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	prov := &mutableProvider{}
	prov.set(config.Certificate{Name: certName, Domains: []string{host}})
	cfg := &config.Config{}
	cfg.Certificates = []config.Certificate{{Name: certName, Domains: []string{host}}}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := New(cfg, prov, store, &fakeManager{}, nil, log)
	r.prober = &fakeProber{hosts: []string{host, goneHost}}

	// Both hosts have exported series from an earlier round.
	for _, h := range []string{host, goneHost} {
		metrics.CertificateProbeMatch.WithLabelValues(h).Set(1)
	}

	// The certificate's own pass is still in flight, so this round skips it.
	if !r.acquire(certName) {
		t.Fatal("acquiring the claim should succeed on a fresh reconciler")
	}

	r.reclaimStaleProbeSeries(r.resolve(context.Background()))

	if !probeMatchSeriesExists(t, host) {
		t.Error("the series of a host whose certificate is still converging was reclaimed; " +
			"a probe_match value that blinks is a false alert for whoever is paging on it")
	}

	// Once nothing is in flight, the genuinely stale host must be reclaimed in BOTH places:
	// the exported series and the runner's transition memory. Reclaiming only the metric
	// leaks an entry in the runner for every host ever dropped from a SAN set.
	r.release(certName)
	r.reclaimStaleProbeSeries(r.resolve(context.Background()))

	if probeMatchSeriesExists(t, goneHost) {
		t.Error("a host that is no longer probed must have its exported series reclaimed")
	}
	var forgotGone bool
	for _, h := range r.prober.(*fakeProber).forgotten {
		if h == goneHost {
			forgotGone = true
		}
	}
	if !forgotGone {
		t.Errorf("the runner's transition memory must be reclaimed alongside the series, forgot=%v",
			r.prober.(*fakeProber).forgotten)
	}
}

// Reclaiming stale hosts must resolve the desired state once, not once per host.
//
// hostIsUnconfirmed called resolve() per host, and a resolve is a file read, a YAML decode, a
// validation pass and a sha256 of the document. The round-11 scale work measured the result at the
// default probe cap: 500 certificates, a pass that reclaims stale hosts took 27.8 s against 0.18 s
// for the same pass with nothing to reclaim (155x), and the cost was exactly O(staleHosts x
// fleetSize) -- the shape an ordinary fleet edit produces, since removing certificates or names is
// what leaves hosts behind.
func TestReclaimingManyStaleHostsResolvesOnce(t *testing.T) {
	const certs = 40

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("opening the state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	var (
		cfgCerts []config.Certificate
		stale    []string
	)
	for i := 0; i < certs; i++ {
		c := config.Certificate{
			Name:    fmt.Sprintf("cert-%02d", i),
			Domains: []string{fmt.Sprintf("live-%02d.example.com", i)},
		}
		cfgCerts = append(cfgCerts, c)
		stale = append(stale, fmt.Sprintf("stale-%02d.example.com", i))
	}

	prov := &countingProvider{inner: spec.NewStatic(cfgCerts)}
	r := New(&config.Config{Certificates: cfgCerts}, prov, store, &fakeManager{}, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	// Every host the runner remembers, live ones included: the stale ones are the difference from
	// this round's probed set, which is empty here.
	all := append([]string{}, stale...)
	for _, c := range cfgCerts {
		all = append(all, c.Domains...)
	}
	r.prober = &fakeProber{hosts: all}

	for _, h := range append(append([]string{}, stale...), "live-00.example.com") {
		metrics.CertificateProbeMatch.WithLabelValues(h).Set(1)
	}

	r.reclaimStaleProbeSeries(r.resolve(context.Background()))

	if got := prov.calls.Load(); got != 1 {
		t.Errorf("resolved the desired state %d times for %d stale hosts; one resolve per reclaim "+
			"pass is the difference between 0.18 s and 27.8 s at 500 certificates", got, len(stale))
	}
	if probeMatchSeriesExists(t, stale[0]) {
		t.Error("a host that is no longer probed must still have its series reclaimed")
	}
	if !probeMatchSeriesExists(t, "live-00.example.com") {
		t.Error("a host that is still probed must keep its series")
	}
}

// ── expiry-metric contract ──────────────────────────────────────────────────────────

// A certificate that was never issued must not report an expiry at all.
//
// README.reference.md documents the primary expiry alert as
//
//	(wecert_certificate_not_after_timestamp_seconds - time()) / 86400 < 21
//
// A never-issued certificate stored not_after = 0 (which the state schema defines as
// "never issued"), and this exported the zero through — so the rule evaluated to about
// -20,700 days and fired. The first deployment of every new certificate therefore paged
// someone about a certificate that did not exist yet, with an "overdue by 57 years" value,
// on the one signal the docs tell operators to trust.
//
// Absent is the honest answer: a certificate with no expiry has nothing to compare.
func TestNeverIssuedCertificateExportsNoExpirySeries(t *testing.T) {
	const certName = "brand-new-cert"

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("opening the state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	prov := &mutableProvider{}
	prov.set(config.Certificate{Name: certName})
	cfg := &config.Config{}
	cfg.Certificates = []config.Certificate{{Name: certName}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := New(cfg, prov, store, &fakeManager{}, nil, log)

	// A row that exists but has never had a certificate issued for it, which is the state
	// right after the first upload attempt or before it.
	if err := store.PutCert(&state.CertState{Name: certName}); err != nil {
		t.Fatalf("PutCert: %v", err)
	}

	r.publish(&config.Certificate{Name: certName})

	if v, ok := gaugeValue(t, "wecert_certificate_not_after_timestamp_seconds", certName); ok {
		t.Errorf("a never-issued certificate must not export an expiry, got %v (%.0f days from now); "+
			"the documented alert rule compares this against time() and would fire",
			v, (v-float64(time.Now().Unix()))/86400)
	}
}

// The control: an issued certificate must export its expiry, so the fix cannot be satisfied
// by simply never publishing the series.
func TestIssuedCertificateExportsItsExpiry(t *testing.T) {
	const certName = "issued-cert"

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("opening the state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	prov := &mutableProvider{}
	prov.set(config.Certificate{Name: certName})
	cfg := &config.Config{}
	cfg.Certificates = []config.Certificate{{Name: certName}}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := New(cfg, prov, store, &fakeManager{}, nil, log)

	notAfter := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	if err := store.PutCert(&state.CertState{Name: certName, NotAfter: notAfter}); err != nil {
		t.Fatalf("PutCert: %v", err)
	}

	r.publish(&config.Certificate{Name: certName})

	v, ok := gaugeValue(t, "wecert_certificate_not_after_timestamp_seconds", certName)
	if !ok {
		t.Fatal("an issued certificate must export its expiry; the expiry alert is the primary signal")
	}
	if int64(v) != notAfter.Unix() {
		t.Errorf("expiry gauge = %d, want %d", int64(v), notAfter.Unix())
	}
	// And the documented rule must NOT fire for a healthy 90-day certificate.
	if days := (v - float64(time.Now().Unix())) / 86400; days < 21 {
		t.Errorf("a 90-day certificate must not trip the 21-day rule, got %.0f days", days)
	}
}

// gaugeValue reads one label combination out of the default registry. ok=false means the
// series is absent (as opposed to present with a value).
func gaugeValue(t *testing.T, metric, label string) (float64, bool) {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() != metric {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "cert" && lp.GetValue() == label {
					return m.GetGauge().GetValue(), true
				}
			}
		}
	}
	return 0, false
}

// A host whose certificate is still desired but not confirmed deployed keeps its series.
//
// probeCert returns early for an unconfirmed deployment (there is no deployed certificate to compare
// against), so during a renewal's mid-rebind window -- up to the next binding check, six hours -- the
// host is absent from this round's probe set. Deleting there made probe_match, probe_not_after and
// probe_trusted flicker once per renewal, and for a rebind that then failed the series a
// `probe_match == 0` alert fires on were gone: the documented alert stayed silent for the failure it
// exists to catch.
func TestAnUnconfirmedDeploymentKeepsItsProbeSeries(t *testing.T) {
	mgr := &fakeManager{}
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	certs := []config.Certificate{{Name: "example-com", Domains: []string{"pending.example.com"}}}
	cfg := &config.Config{Certificates: certs}
	r := New(cfg, spec.NewStatic(certs), store, mgr, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Desired, but not confirmed deployed: the mid-rebind state.
	if err := store.PutCert(&state.CertState{Name: "example-com", DeployConfirmed: false}); err != nil {
		t.Fatal(err)
	}
	metrics.CertificateProbeMatch.WithLabelValues("pending.example.com").Set(0)

	fake := &fakeProber{hosts: []string{"pending.example.com"}}
	r.prober = fake
	r.probedHosts = map[string]struct{}{}

	r.reclaimStaleProbeSeries(r.resolve(context.Background()))

	if !probeMatchSeriesExists(t, "pending.example.com") {
		t.Error("a certificate that is merely unconfirmed is still being worked on: its probe series " +
			"must survive the mid-rebind window, or the alert for a failed rebind has nothing to fire on")
	}

	// Once the deployment is confirmed and the host is still not probed, it is stale as before.
	if err := store.PutCert(&state.CertState{Name: "example-com", DeployConfirmed: true}); err != nil {
		t.Fatal(err)
	}
	r.reclaimStaleProbeSeries(r.resolve(context.Background()))
	if probeMatchSeriesExists(t, "pending.example.com") {
		t.Error("a host that is no longer probed for a confirmed deployment must be reclaimed")
	}
}

// The stale-series sweep judges each candidate host against the desired state the pass
// already resolved. Resolving again per host meant a full document read, YAML decode,
// validation and hash -- plus resolve's metric and log side effects -- for EVERY
// candidate of EVERY pass.
func TestStaleProbeSweepUsesThePasssOwnResolution(t *testing.T) {
	certs := []config.Certificate{{Name: "kept", Domains: []string{"kept.example.com"}}}

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("opening the state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	prov := &countingProvider{inner: spec.NewStatic(certs)}
	cfg := &config.Config{Certificates: certs}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := New(cfg, prov, store, &fakeManager{}, nil, log)
	r.prober = &fakeProber{hosts: []string{"stale.example.com"}}

	// The stale host's series exists from an earlier round; it is not in the desired
	// state, so the sweep must reclaim it -- and must not re-resolve to decide that.
	metrics.CertificateProbeMatch.WithLabelValues("stale.example.com").Set(0)

	r.RunDetailed(context.Background())

	if got := prov.calls.Load(); got != 1 {
		t.Errorf("a full pass must resolve the desired state exactly once, resolved %d times "+
			"(each extra resolution is a document read, YAML decode, validation and hash)",
			got)
	}
	if probeMatchSeriesExists(t, "stale.example.com") {
		t.Error("the stale host's series must be reclaimed")
	}
}

// "Nothing to probe" has two causes -- a certificate of pure wildcards, and a probe cap
// of zero ("off", e.g. probing paused during an investigation) -- and the log used to
// blame wildcards for both, sending the diagnosis in the wrong direction when probing
// was paused by configuration.
func TestProbeCertLogDistinguishesAZeroCapFromAllWildcards(t *testing.T) {
	newProbingReconciler := func(t *testing.T, maxHosts int, domains ...string) (*Reconciler, *config.Certificate, *recordLogHandler) {
		t.Helper()
		store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })

		const name = "probe-log"
		if err := store.PutCert(&state.CertState{
			Name: name, DeployConfirmed: true, NotAfter: time.Now().Add(30 * 24 * time.Hour),
		}); err != nil {
			t.Fatal(err)
		}

		cfg := &config.Config{Probe: config.Probe{MaxHostsPerCert: maxHosts}}
		handler := &recordLogHandler{}
		r := New(cfg, spec.NewStatic(nil), store, &fakeManager{}, nil, slog.New(handler))
		r.prober = &fakeProber{}
		c := &config.Certificate{Name: name, Domains: domains, Deploy: config.Deploy{Enabled: true}}
		return r, c, handler
	}

	r, c, handler := newProbingReconciler(t, 0, "a.example.com")
	r.probeCert(context.Background(), c)
	if !handler.contains("host cap is 0") {
		t.Error("a zero cap must say probing is off, not blame the certificate")
	}
	if handler.contains("wildcard") {
		t.Error("a zero cap must not be diagnosed as an all-wildcard certificate")
	}

	r, c, handler = newProbingReconciler(t, 3, "*.example.com")
	r.probeCert(context.Background(), c)
	if !handler.contains("every name in this certificate is a wildcard") {
		t.Error("an all-wildcard certificate must still be diagnosed as such")
	}
}
