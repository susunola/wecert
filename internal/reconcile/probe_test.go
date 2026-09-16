package reconcile

import (
	"context"
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

	r.reclaimStaleProbeSeries()

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
	r.reclaimStaleProbeSeries() // must not panic
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
// RunAll skips a certificate whose claim is held, so that certificate never reaches
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

	r.reclaimStaleProbeSeries()

	if !probeMatchSeriesExists(t, host) {
		t.Error("the series of a host whose certificate is still converging was reclaimed; " +
			"a probe_match value that blinks is a false alert for whoever is paging on it")
	}

	// Once nothing is in flight, the genuinely stale host must be reclaimed in BOTH places:
	// the exported series and the runner's transition memory. Reclaiming only the metric
	// leaks an entry in the runner for every host ever dropped from a SAN set.
	r.release(certName)
	r.reclaimStaleProbeSeries()

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
