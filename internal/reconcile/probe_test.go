package reconcile

import (
	"context"
	"reflect"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/susunola/wecert/internal/metrics"
	"github.com/susunola/wecert/internal/probe"
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
