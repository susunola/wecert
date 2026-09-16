package acme

import (
	"sort"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/susunola/wecert/internal/metrics"
)

// quotaSeries returns every currently-exported {limit,scope} pair of the remaining-tokens gauge.
func quotaSeries(t *testing.T) []string {
	t.Helper()
	ch := make(chan prometheus.Metric, 64)
	go func() {
		metrics.RateLimitRemaining.Collect(ch)
		close(ch)
	}()

	var out []string
	for m := range ch {
		var d dto.Metric
		if err := m.Write(&d); err != nil {
			t.Fatalf("reading a metric: %v", err)
		}
		var limit, scope string
		for _, l := range d.GetLabel() {
			switch l.GetName() {
			case "limit":
				limit = l.GetValue()
			case "scope":
				scope = l.GetValue()
			}
		}
		out = append(out, limit+"|"+scope)
	}
	sort.Strings(out)
	return out
}

// A scope that leaves the desired state must leave the metric with it.
//
// The scope is derived from the first certificate's first domain, so it changes whenever the
// deployment renames or drops that certificate -- an ordinary edit. `WithLabelValues` only ever
// creates, so without an explicit reset the retired scope's series stays at its last value forever,
// and `WecertRateLimitNearlyExhausted` (remaining < 5) keeps firing for a domain this program no
// longer manages. That is a permanent false alarm, and the alert cannot tell it from a real one.
func TestQuotaSeriesFollowTheDesiredState(t *testing.T) {
	metrics.RateLimitRemaining.Reset()

	_, m, _, _ := newAPITestHarness(t, []string{"old-example.com"})
	m.PublishQuota(map[string]string{
		"registered-domain":    "old-example.com",
		"exact-identifier-set": "old-example.com",
		"identifier":           "old-example.com",
	})

	before := quotaSeries(t)
	if len(before) == 0 {
		t.Fatal("publishing quota must export something, otherwise this test proves nothing")
	}
	if !hasScope(before, "old-example.com") {
		t.Fatalf("the first scope must be exported, got %v", before)
	}

	// The domain is renamed. The old scope is no longer in the desired state.
	m.PublishQuota(map[string]string{
		"registered-domain":    "new-example.com",
		"exact-identifier-set": "new-example.com",
		"identifier":           "new-example.com",
	})

	after := quotaSeries(t)
	if !hasScope(after, "new-example.com") {
		t.Errorf("the current scope must be exported, got %v", after)
	}
	for _, s := range after {
		if hasSuffixScope(s, "old-example.com") {
			t.Errorf("series %q still reports the retired scope at its last value; it will keep "+
				"firing WecertRateLimitNearlyExhausted for a domain this deployment no longer "+
				"manages, and an operator has no way to tell that from a real exhaustion", s)
		}
	}
}

func hasScope(series []string, scope string) bool {
	for _, s := range series {
		if hasSuffixScope(s, scope) {
			return true
		}
	}
	return false
}

func hasSuffixScope(s, scope string) bool {
	return len(s) > len(scope) && s[len(s)-len(scope):] == scope
}
