package acme

import (
	"sort"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/susunola/wecert/internal/metrics"
	"github.com/susunola/wecert/internal/ratelimit"
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
	m.PublishQuota(map[string][]string{
		"registered-domain":    {"old-example.com"},
		"exact-identifier-set": {"old-example.com"},
		"identifier":           {"old-example.com"},
	})

	before := quotaSeries(t)
	if len(before) == 0 {
		t.Fatal("publishing quota must export something, otherwise this test proves nothing")
	}
	if !hasScope(before, "old-example.com") {
		t.Fatalf("the first scope must be exported, got %v", before)
	}

	// The domain is renamed. The old scope is no longer in the desired state.
	m.PublishQuota(map[string][]string{
		"registered-domain":    {"new-example.com"},
		"exact-identifier-set": {"new-example.com"},
		"identifier":           {"new-example.com"},
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

// A quota that could not be read must not be published as zero.
//
// `Remaining` reports (0, false) when the stored bucket cannot be read, and the report used to
// drop that `false` on the floor: the gauge was set to 0 -- the strongest claim the metric can
// make, "no quota left" -- on the strength of a failed read. `WecertRateLimitNearlyExhausted`
// fires below 5, so a single failed read blanked the estimate for every limit at once and raised
// a page for a fleet that had spent nothing. The next successful pass cleared it, which is what
// makes it hard to diagnose from the alert alone.
func TestUnreadableQuotaIsNotPublishedAsZero(t *testing.T) {
	metrics.RateLimitRemaining.Reset()

	store, m, _, _ := newAPITestHarness(t, []string{"example.com"})
	scopes := map[string][]string{
		"registered-domain":    {"example.com"},
		"exact-identifier-set": {"example.com"},
		"identifier":           {"example.com"},
	}

	m.PublishQuota(scopes)
	if before := quotaSeries(t); len(before) == 0 {
		t.Fatal("a readable bucket must be published, otherwise this test proves nothing")
	}

	// Now every read fails, as it does when the database is busy or gone.
	if err := store.Close(); err != nil {
		t.Fatalf("closing the state store: %v", err)
	}

	reports := m.QuotaStatus(scopes)
	if len(reports) == 0 {
		t.Fatal("the report must cover the spendable limits")
	}
	for _, rep := range reports {
		if !rep.Unreadable {
			t.Errorf("limit %s scope %q could not be read, yet the report offers %v remaining; "+
				"a failed read must not produce a number", rep.Limit, rep.Scope, rep.Remaining)
		}
	}

	m.PublishQuota(scopes)
	for _, s := range quotaSeries(t) {
		t.Errorf("series %q was published from a failed read; a scrape cannot tell that zero from "+
			"a genuine exhaustion", s)
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

// Every scope in a family is published, not just one.
//
// The publisher used to take one scope per family, and its only caller passed "the first
// certificate's first domain". For the normal one-certificate-per-domain layout that meant
// wecert_ratelimit_remaining_tokens had no series at all for the second domain onwards, so
// WecertRateLimitNearlyExhausted had nothing to compare and stayed silent for every domain but one
// -- an absent series is indistinguishable from a healthy one to anyone reading a dashboard.
func TestEveryScopeInAFamilyIsPublished(t *testing.T) {
	metrics.RateLimitRemaining.Reset()

	_, m, _, _ := newAPITestHarness(t, []string{"a.example.com"})
	m.PublishQuota(map[string][]string{
		"registered-domain":    {"a.example.com", "b.example.com", "c.example.com"},
		"exact-identifier-set": {"set-a", "set-b"},
		// The identifier family comes from the store (see PublishQuota), so these are ignored --
		// TestIdentifierQuotaSeriesCoverOnlyWhatWasSpent is where that contract lives.
		"identifier": {"a.example.com", "b.example.com", "c.example.com"},
	})

	series := quotaSeries(t)
	for _, scope := range []string{"a.example.com", "b.example.com", "c.example.com", "set-a", "set-b"} {
		if !hasScope(series, scope) {
			t.Errorf("scope %q has no series; the alert compares against a series that does not "+
				"exist, which reads as nothing to see. Exported: %v", scope, series)
		}
	}

	// The account-wide limit has no caller-supplied scope and must still be reported once.
	if !hasScope(series, "") {
		t.Errorf("the account-wide limit must still be published, got %v", series)
	}
}

// The per-identifier family is published for the identifiers that have been SPENT against, not for
// every SAN in the desired state.
//
// It is the only unbounded family -- "every name of every certificate" grows with the fleet -- while
// the buckets that can be exhausted grow with what has been attempted. Publishing one series per name
// cost the round-11 scale work 11,001 series of 17,052, a 1.67 MB scrape and 22,002 SQL statements in
// an ordinary scheduled pass at 500 certificates of 20 names. A name nobody has validated has a full
// budget, so the only number its series could carry is the limit's capacity.
func TestIdentifierQuotaSeriesCoverOnlyWhatWasSpent(t *testing.T) {
	metrics.RateLimitRemaining.Reset()

	_, m, _, _ := newAPITestHarness(t, []string{"unspent.example.com"})
	m.quota.Spend(ratelimit.AuthzFailuresPerIdentifier, "spent.example.com", 1)

	m.PublishQuota(map[string][]string{
		"registered-domain":    {"example.com"},
		"exact-identifier-set": {"set-a"},
		"identifier":           {"unspent.example.com", "spent.example.com"},
	})

	series := quotaSeries(t)
	if !hasScope(series, "spent.example.com") {
		t.Errorf("an identifier this program has spent against must be published: it is the one whose "+
			"budget can be exhausted. Exported: %v", series)
	}
	if hasScope(series, "unspent.example.com") {
		t.Errorf("an identifier with no spend must not be published; its budget is full and the series "+
			"is pure cardinality. Exported: %v", series)
	}

	// The other families still follow the desired state, so the alert keeps a series per domain and
	// per identifier set.
	if !hasScope(series, "example.com") || !hasScope(series, "set-a") {
		t.Errorf("the bounded families must keep publishing every scope they are given, got %v", series)
	}
}

// blockedSeries returns every currently-exported {limit,scope} pair of the blocked gauge.
func blockedSeries(t *testing.T) []string {
	t.Helper()
	ch := make(chan prometheus.Metric, 64)
	go func() {
		metrics.RateLimitBlocked.Collect(ch)
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

// A paused identifier must be visible as BLOCKED, and must NOT come with a token count.
//
// wecert_ratelimit_remaining_tokens is documented as an upper bound on what may still be spent, and
// this bucket is filled by the CA's own validators: nothing here spends against it, so any number
// computed locally would be the limit's bare capacity (1,152) published as if it were an estimate.
// The blocked gauge is the series that carries the fact, and it has to carry it -- a pause is
// cleared in the CA's self-service portal rather than by waiting, so a missing series would read as
// healthy to anyone watching the dashboard, which is the failure mode the per-identifier scope work
// already fixed once for the budgets.
func TestAPauseIsPublishedAsBlockedWithoutACount(t *testing.T) {
	metrics.RateLimitRemaining.Reset()
	metrics.RateLimitBlocked.Reset()

	_, m, _, _ := newAPITestHarness(t, []string{"paused.example.com"})
	fixed := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return fixed })
	limit := ratelimit.ConsecutiveAuthzFailuresPerIdentifier
	if _, ok := m.quota.NoteDeadline(limit, "paused.example.com", fixed.Add(limit.Refill),
		"identifier pause floor"); !ok {
		t.Fatal("the fixture must record the pause deadline")
	}

	// The scope list for the identifier family comes from the store, so the pause bucket alone is
	// enough for the series to exist -- no failure budget was ever spent for this name.
	m.PublishQuota(map[string][]string{
		"registered-domain":    {"example.com"},
		"exact-identifier-set": {"paused.example.com"},
	})

	want := limit.Name + "|paused.example.com"
	for _, s := range quotaSeries(t) {
		if s == want {
			t.Errorf("series %q publishes a token count for a bucket this program never spends "+
				"against; the only number available is the limit's capacity, which is not an estimate", s)
		}
	}
	var found bool
	for _, s := range blockedSeries(t) {
		if s == want {
			found = true
		}
	}
	if !found {
		t.Errorf("a paused identifier has to be exported as blocked; the CA clears the pause only in "+
			"its self-service portal, so an absent series says 'nothing to see'. Blocked series: %v",
			blockedSeries(t))
	}
}
