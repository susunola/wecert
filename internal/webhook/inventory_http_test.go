package webhook

// The inventory is the read-only surface an operator looks at when something is wrong, so the
// interesting behaviour is what it does with facts that are missing, stale or contradictory:
// a desired document that names a certificate the store has never seen, a probe answer that
// survived a restart, a state database that cannot be read at all, and a CA rate limit that has
// to be mapped back onto the certificate rows it blocks. These tests drive that through the
// real http.Handler the package mounts, and through the assembly itself where the mapping is
// the thing under test.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/group"
	"github.com/susunola/wecert/internal/inventory"
	"github.com/susunola/wecert/internal/probe"
	"github.com/susunola/wecert/internal/ratelimit"
	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
)

// inventoryCapabilityFake is the whole optional capability surface the assembly probes for: the
// desired state and the cached quota reports the real reconciler exposes, on top of the probe
// and binding facts daemonFake already models. Keeping them on one fake lets a test say "this
// daemon knows all of it" and assert that the page says so, and lets another say "it knows none
// of it" without the assembly inventing the difference.
type inventoryCapabilityFake struct {
	*daemonFake
	last   *spec.Result
	quotas []ratelimit.QuotaReport
}

func (f *inventoryCapabilityFake) LastResult() *spec.Result { return f.last }

func (f *inventoryCapabilityFake) QuotaStatus() []ratelimit.QuotaReport { return f.quotas }

// countInventoryRows counts the rows a name produced. More than one row for one name is the
// symptom this helper exists to catch: the desired document and the store are merged by name,
// and a missed de-duplication renders the same certificate twice with two different statuses.
func countInventoryRows(snap inventory.Snapshot, name string) int {
	n := 0
	for _, row := range snap.Certificates {
		if row.Name == name {
			n++
		}
	}
	return n
}

// TestInventoryEndpointsRejectNonGET checks the method guard on both halves of the read-only
// surface. Neither route may be driven with a write verb -- one assembles the snapshot, the
// other renders the console page -- and the Allow header is what tells an automated caller how
// to fix itself.
func TestInventoryEndpointsRejectNonGET(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t, &fakeReconciler{names: []string{"example-com"}})

	for _, path := range []string{"/api/inventory", "/status"} {
		w := do(t, s, http.MethodPost, path, `{}`, bearer())
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s = %d, want 405", path, w.Code)
			continue
		}
		if allow := w.Header().Get("Allow"); allow != http.MethodGet {
			t.Errorf("POST %s: Allow = %q, want GET", path, allow)
		}
		var body map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Errorf("POST %s: body %s is not the usual error object: %v", path, w.Body.String(), err)
			continue
		}
		if body["error"] != "use GET" {
			t.Errorf("POST %s: error = %q, want \"use GET\"", path, body["error"])
		}
	}
}

// errRenderStalled stands in for the write error a browser that navigates away mid-page
// produces.
var errRenderStalled = errors.New("the connection went away mid-render")

// renderFailWriter is a ResponseWriter whose first write fails, the way a real one does when
// the client is gone. It records the statuses the handler asks for so a test can tell a handler
// that accepts the failure from one that tries to report an error into a response that has
// already started.
type renderFailWriter struct {
	header http.Header
	status []int
	writes int
}

func (w *renderFailWriter) Header() http.Header { return w.header }

func (w *renderFailWriter) WriteHeader(code int) { w.status = append(w.status, code) }

func (w *renderFailWriter) Write([]byte) (int, error) {
	if len(w.status) == 0 {
		w.status = append(w.status, http.StatusOK)
	}
	w.writes++
	return 0, errRenderStalled
}

// TestInventoryPageSurvivesARenderFailure covers the console page when the template cannot be
// written out. A client that disconnects mid-render is ordinary, and the handler must neither
// panic nor try to append an error status to a response that already started: the failure
// belongs in the log, where a broken template or a failing client is visible.
func TestInventoryPageSurvivesARenderFailure(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	s, err := New(&fakeReconciler{names: []string{"example-com"}}, store, testToken,
		context.Background(), slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	fw := &renderFailWriter{header: http.Header{}}
	s.Handler().ServeHTTP(fw, req)

	if fw.writes == 0 {
		t.Fatal("the handler never attempted to render the page")
	}
	if len(fw.status) != 1 || fw.status[0] != http.StatusOK {
		t.Errorf("statuses = %v, want exactly the 200 the render started with: an error status must not be appended to a partial page", fw.status)
	}
	if ct := fw.header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want the page's own type, set before the first byte", ct)
	}
	if cache := fw.header.Get("Cache-Control"); cache != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store: a stale console page hides the current state", cache)
	}
	if !strings.Contains(logs.String(), "failed to render the inventory page") {
		t.Errorf("the render failure must be logged, got:\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), errRenderStalled.Error()) {
		t.Errorf("the cause must travel with the warning, got:\n%s", logs.String())
	}
}

// TestInventoryAddsTheDesiredDocumentWithoutDuplicateRows covers the merge of the desired state
// into the rows. A certificate the document names but the store has never seen must appear --
// that is the answer to "why is my domain not issued" -- carrying the document's domains and
// profile, while a name that appears in both sources must produce exactly one row, and an entry
// with no name must produce none at all.
func TestInventoryAddsTheDesiredDocumentWithoutDuplicateRows(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	rec := &inventoryCapabilityFake{
		daemonFake: &daemonFake{fakeReconciler: &fakeReconciler{names: []string{"shared", "from-store"}}},
		last: &spec.Result{
			Revision: "sha256:desired-1",
			Certificates: []config.Certificate{
				{Name: "from-document", Domains: []string{"from-document.example"}, Profile: "classic"},
				{Name: "shared", Domains: []string{"shared.example"}, KeyType: "rsa2048"},
				{Name: "", Domains: []string{"nameless.example"}},
			},
		},
	}
	s, store := newTestServer(t, rec)
	snap := inventorySnapshot(t, s, store,
		&state.CertState{Name: "shared", NotAfter: now.Add(60 * 24 * time.Hour)},
		&state.CertState{Name: "from-store", NotAfter: now.Add(60 * 24 * time.Hour)})

	if snap.Desired.Revision != "sha256:desired-1" {
		t.Errorf("desired revision = %q, want the document that was read", snap.Desired.Revision)
	}
	if snap.Desired.Frozen == nil || *snap.Desired.Frozen {
		t.Errorf("desired frozen = %v, want the document's own answer", snap.Desired.Frozen)
	}

	want := []string{"from-document", "from-store", "shared"}
	if len(snap.Certificates) != len(want) {
		t.Fatalf("rows = %+v, want one per distinct name", snap.Certificates)
	}
	for _, name := range want {
		if n := countInventoryRows(snap, name); n != 1 {
			t.Errorf("%q produced %d rows, want 1", name, n)
		}
	}
	if n := countInventoryRows(snap, ""); n != 0 {
		t.Error("a nameless entry in the desired document must not become a blank row")
	}

	row := rowNamed(t, snap, "from-document")
	if row.Status != inventory.StatusNotIssued {
		t.Errorf("status = %q, want not_issued for a certificate that is desired but has no state", row.Status)
	}
	if !slices.Equal(row.Domains, []string{"from-document.example"}) {
		t.Errorf("domains = %v, want the document's: the page cannot show what to bind without them", row.Domains)
	}
	if row.Profile != "classic" {
		t.Errorf("profile = %q, want the document's", row.Profile)
	}
}

// TestInventoryReportsPendingRevocationsAndLiveBindings covers the two row inputs that come
// from outside the state store: the operator's outstanding revocation requests, and the cached
// bind-resource enumeration. An outstanding revocation must be visible rather than reported as
// healthy -- it is the one status an operator has to act on -- and a certificate that has never
// been deployed must not pick up binding rows keyed by an empty id.
func TestInventoryReportsPendingRevocationsAndLiveBindings(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	rec := &inventoryCapabilityFake{daemonFake: &daemonFake{
		fakeReconciler: &fakeReconciler{names: []string{"bound", "store-only", "not-deployed"}},
		bindings: map[string]inventory.Bindings{
			"c1": {
				Count: 2, Complete: true, Freshness: inventory.FreshnessLive,
				ObservedAt: "2026-09-22T05:00:00Z",
				Items:      []inventory.BindingItem{{ResourceType: "clb", LoadBalancerID: "lb-1", Complete: true}},
			},
			// Keyed by the empty id on purpose: the assembly must skip a certificate with no
			// deployed id before it looks anything up.
			"": {Count: 9, Complete: true, Freshness: inventory.FreshnessLive, Items: []inventory.BindingItem{}},
		},
	}}
	s, store := newTestServer(t, rec)
	if err := store.AddRevokeRequest("bound", 4, "identity-1", now); err != nil {
		t.Fatal(err)
	}
	snap := inventorySnapshot(t, s, store,
		&state.CertState{Name: "bound", NotAfter: now.Add(60 * 24 * time.Hour), DeployedCertID: "c1", DeployConfirmed: true},
		&state.CertState{Name: "store-only", NotAfter: now.Add(60 * 24 * time.Hour), DeployedCertID: "c2", DeployConfirmed: true},
		&state.CertState{Name: "not-deployed", NotAfter: now.Add(60 * 24 * time.Hour)})

	bound := rowNamed(t, snap, "bound")
	if bound.Status != inventory.StatusRevokePending {
		t.Errorf("status = %q, want revoke_pending for an outstanding revocation", bound.Status)
	}
	if bound.Bindings.Count != 2 || bound.Bindings.Freshness != inventory.FreshnessLive ||
		bound.Bindings.ObservedAt != "2026-09-22T05:00:00Z" {
		t.Errorf("bindings = %+v, want the cached live enumeration with its observation time", bound.Bindings)
	}
	if len(bound.Bindings.Items) != 1 || bound.Bindings.Items[0].LoadBalancerID != "lb-1" {
		t.Errorf("binding items = %+v, want the enumerated listener", bound.Bindings.Items)
	}

	storeOnly := rowNamed(t, snap, "store-only")
	if storeOnly.Bindings.Freshness != inventory.FreshnessStore || storeOnly.Bindings.Count != 1 || storeOnly.Bindings.Complete {
		t.Errorf("bindings = %+v, want the store-side lower bound: one deployment, not an enumeration", storeOnly.Bindings)
	}

	notDeployed := rowNamed(t, snap, "not-deployed")
	if notDeployed.Bindings.Count != 0 || notDeployed.Bindings.Freshness != inventory.FreshnessStore {
		t.Errorf("bindings = %+v, want nothing borrowed for a certificate that was never deployed", notDeployed.Bindings)
	}
}

// blockedNames renders the blocking map for comparison.
func blockedNames(blocked map[string]bool) []string {
	out := make([]string, 0, len(blocked))
	for name, yes := range blocked {
		if yes {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// TestBlockedCertificatesMapsOnlyTheScopeTheCANamed is the test for "which row turns red".
//
// The CA names a limit and the scope it applied to; mapping that back onto certificate rows is
// an inference, so every published scope is pinned separately and the unmappable cases are
// pinned too. A row painted red on a guess sends the operator to the wrong console with more
// authority than the quota table, which reports the scope verbatim.
func TestBlockedCertificatesMapsOnlyTheScopeTheCANamed(t *testing.T) {
	t.Parallel()
	desired := &spec.Result{Certificates: []config.Certificate{
		{Name: "set", Domains: []string{"a.example", "b.example"}},
		{Name: "uk", Domains: []string{"www.example.co.uk"}},
		{Name: "broken", Domains: []string{"broken.example.com"}},
		{Name: "other", Domains: []string{"other.example"}},
	}}

	cases := []struct {
		why    string
		report ratelimit.QuotaReport
		want   []string
	}{
		{
			why:    "an account-wide order refusal belongs to no single name, so every row is blocked",
			report: ratelimit.QuotaReport{Limit: "new-orders", Scope: "account", Blocked: true},
			want:   []string{"broken", "other", "set", "uk"},
		},
		{
			why:    "an exact-identifier-set block follows the order-independent domain key",
			report: ratelimit.QuotaReport{Limit: "certs-per-exact-identifier-set", Scope: desired.Certificates[0].DomainKey(), Blocked: true},
			want:   []string{"set"},
		},
		{
			why:    "a registered-domain block follows the registrable domain the CA named",
			report: ratelimit.QuotaReport{Limit: "certs-per-registered-domain", Scope: group.RegisteredDomain("www.example.co.uk"), Blocked: true},
			want:   []string{"uk"},
		},
		{
			why:    "an authorization-failure block follows the identifier, case-insensitively",
			report: ratelimit.QuotaReport{Limit: "authz-failures-per-identifier", Scope: "BROKEN.example.COM", Blocked: true},
			want:   []string{"broken"},
		},
		{
			why:    "the CA-spent consecutive-failure pause blocks the identifier it names too",
			report: ratelimit.QuotaReport{Limit: "consecutive-authz-failures-per-identifier", Scope: "broken.example.com", Blocked: true},
			want:   []string{"broken"},
		},
		{
			why:    "a report that is not blocked blocks nothing, whatever it says about the remainder",
			report: ratelimit.QuotaReport{Limit: "new-orders", Blocked: false, Remaining: 0},
		},
		{
			why:    "an exact-identifier-set scope that matches no certificate blocks nothing",
			report: ratelimit.QuotaReport{Limit: "certs-per-exact-identifier-set", Scope: config.DomainKey([]string{"z.example"}), Blocked: true},
		},
		{
			why:    "a registered-domain scope that matches no certificate blocks nothing",
			report: ratelimit.QuotaReport{Limit: "certs-per-registered-domain", Scope: "elsewhere.example", Blocked: true},
		},
		{
			why:    "an identifier scope that matches no certificate blocks nothing",
			report: ratelimit.QuotaReport{Limit: "authz-failures-per-identifier", Scope: "fine.example", Blocked: true},
		},
		{
			why:    "a limit this build does not know is not turned into a blocked row",
			report: ratelimit.QuotaReport{Limit: "future-limit", Scope: "a.example", Blocked: true},
		},
	}

	for _, tc := range cases {
		got := blockedNames(blockedCertificates(desired, []ratelimit.QuotaReport{tc.report}))
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: blocked %v, want %v", tc.why, got, tc.want)
		}
	}

	// Without a desired state there is nothing to attribute a scope to, and without reports
	// there is nothing to attribute: both must stay nil rather than blocking on an absence.
	if got := blockedCertificates(nil, []ratelimit.QuotaReport{{Limit: "new-orders", Blocked: true}}); got != nil {
		t.Errorf("blocked = %v with no desired state, want nothing", got)
	}
	if got := blockedCertificates(desired, nil); got != nil {
		t.Errorf("blocked = %v with no reports, want nothing", got)
	}
}

// TestQuotaViewsDropsLimitsItCannotDescribe covers the quota table's rows. The page may only
// publish limits this build has a capacity and refill rate for: printing a row with a zero
// capacity would read as "this limit is exhausted" for a limit nobody can describe, so an
// unknown name is dropped instead, and a bucket with no announced reset must not print year one.
func TestQuotaViewsDropsLimitsItCannotDescribe(t *testing.T) {
	t.Parallel()
	if got := quotaViews(nil); got != nil {
		t.Errorf("quotaViews(nil) = %v, want nothing published", got)
	}

	until := time.Date(2026, 9, 22, 5, 0, 0, 0, time.UTC)
	got := quotaViews([]ratelimit.QuotaReport{
		{Limit: "future-limit", Scope: "x", Blocked: true},
		{Limit: "new-orders", Scope: "account", Remaining: 3, BlockedUntil: until},
		{
			Limit: "consecutive-authz-failures-per-identifier", Scope: "broken.example.com",
			Blocked: true, SpentByCA: true, Unreadable: true,
		},
	})
	if len(got) != 2 {
		t.Fatalf("quota rows = %+v, want only the limits this build can describe", got)
	}

	orders := got[0]
	if orders.Limit != "new-orders" {
		t.Fatalf("first row = %+v, want the published limit", orders)
	}
	if orders.Capacity != ratelimit.NewOrdersPerAccount.Capacity ||
		orders.RefillSecs != int64(ratelimit.NewOrdersPerAccount.Refill.Seconds()) {
		t.Errorf("row = %+v, want the published capacity and refill of %s", orders, ratelimit.NewOrdersPerAccount)
	}
	if orders.Remaining != 3 {
		t.Errorf("remaining = %v, want the report's estimate", orders.Remaining)
	}
	if orders.BlockedUntil != "2026-09-22T05:00:00Z" {
		t.Errorf("blockedUntil = %q, want the reported instant in RFC3339", orders.BlockedUntil)
	}

	pause := got[1]
	if !pause.SpentByCA || !pause.Unreadable {
		t.Errorf("row = %+v, want the CA-spent bucket flagged as such and as unreadable", pause)
	}
	if pause.BlockedUntil != "" {
		t.Errorf("blockedUntil = %q, want it absent when the CA named no reset", pause.BlockedUntil)
	}
}

// TestInventoryPublishesQuotaRowsAndBlocksTheNamedCertificate ties the two together through
// the HTTP surface: the quota table carries the rows, and the certificate the CA named carries
// the rate_limited status. A certificate whose scope was not named must stay out of it.
func TestInventoryPublishesQuotaRowsAndBlocksTheNamedCertificate(t *testing.T) {
	t.Parallel()
	until := time.Date(2026, 9, 22, 5, 0, 0, 0, time.UTC)
	rec := &inventoryCapabilityFake{
		daemonFake: &daemonFake{fakeReconciler: &fakeReconciler{}},
		last: &spec.Result{Certificates: []config.Certificate{
			{Name: "uk", Domains: []string{"www.example.co.uk"}},
			{Name: "paused", Domains: []string{"broken.example.com"}},
			{Name: "fine", Domains: []string{"fine.example"}},
		}},
		quotas: []ratelimit.QuotaReport{
			{Limit: "certs-per-registered-domain", Scope: group.RegisteredDomain("www.example.co.uk"), Blocked: true, Remaining: 1, BlockedUntil: until},
			{Limit: "consecutive-authz-failures-per-identifier", Scope: "broken.example.com", Blocked: true, SpentByCA: true, Unreadable: true},
			{Limit: "future-limit", Scope: "x", Blocked: true},
		},
	}
	s, store := newTestServer(t, rec)
	snap := inventorySnapshot(t, s, store)

	if len(snap.Quotas) != 2 {
		t.Fatalf("quotas = %+v, want the two limits this build can describe", snap.Quotas)
	}
	byLimit := map[string]inventory.Quota{}
	for _, q := range snap.Quotas {
		byLimit[q.Limit] = q
	}
	registered, ok := byLimit["certs-per-registered-domain"]
	if !ok {
		t.Fatalf("quotas = %+v, want the blocked registered-domain bucket", snap.Quotas)
	}
	if registered.Capacity != ratelimit.CertsPerRegisteredDomain.Capacity || registered.BlockedUntil != "2026-09-22T05:00:00Z" {
		t.Errorf("row = %+v, want the published capacity and the reported reset", registered)
	}
	if pause := byLimit["consecutive-authz-failures-per-identifier"]; !pause.SpentByCA || !pause.Unreadable {
		t.Errorf("row = %+v, want the CA-spent pause reported as unreadable", pause)
	}
	if _, ok := byLimit["future-limit"]; ok {
		t.Errorf("quotas = %+v, want the unknown limit dropped rather than published empty", snap.Quotas)
	}

	if row := rowNamed(t, snap, "uk"); row.Status != inventory.StatusRateLimited {
		t.Errorf("uk status = %q, want rate_limited for the certificate the CA's scope names", row.Status)
	}
	if row := rowNamed(t, snap, "paused"); row.Status != inventory.StatusRateLimited {
		t.Errorf("paused status = %q, want rate_limited for the paused identifier", row.Status)
	}
	if row := rowNamed(t, snap, "fine"); row.Status == inventory.StatusRateLimited {
		t.Errorf("fine status = %q, want it untouched: no report named its scope", row.Status)
	}
}

// TestInventoryRendersWhenTheStateStoreIsUnreadable covers the failure the console exists for.
// When state.db cannot be read, every certificate lookup fails; the page must still render,
// with each certificate listed as unreadable and carrying the store's own error text -- a blank
// page or a 500 would leave the operator with no way to see which certificate broke.
func TestInventoryRendersWhenTheStateStoreIsUnreadable(t *testing.T) {
	t.Parallel()
	s, store := newTestServer(t, &fakeReconciler{names: []string{"example-com"}})
	// A closed store reads exactly like a corrupt or unreadable one from here.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	w := do(t, s, http.MethodGet, "/api/inventory", "", bearer())
	if w.Code != http.StatusOK {
		t.Fatalf("inventory = %d, want 200 (body %s)", w.Code, w.Body.String())
	}
	var snap inventory.Snapshot
	if err := json.Unmarshal(w.Body.Bytes(), &snap); err != nil {
		t.Fatalf("inventory json: %v", err)
	}
	row := rowNamed(t, snap, "example-com")
	if row.Status != inventory.StatusStateUnreadable {
		t.Errorf("status = %q, want state_unreadable", row.Status)
	}
	if row.Error == "" {
		t.Error("the store's error must travel on the row, or the operator cannot tell this from a missing certificate")
	}
	if len(row.Drift) != 1 || row.Drift[0] != inventory.DriftStateUnreadable {
		t.Errorf("drift = %v, want the state-unreadable drift", row.Drift)
	}
	if snap.Summary.Unreadable != 1 || snap.Summary.Certificates != 1 {
		t.Errorf("summary = %+v, want the unreadable row counted", snap.Summary)
	}

	page := do(t, s, http.MethodGet, "/status", "", bearer())
	if page.Code != http.StatusOK {
		t.Fatalf("console page = %d, want 200 (body %s)", page.Code, page.Body.String())
	}
	if !strings.Contains(page.Body.String(), "example-com") {
		t.Error("the page must still name the certificate it could not read")
	}
}

// TestInventoryKeepsTheExpiryTheProbeRead covers the durable probe evidence a restarted process
// falls back to. The expiry the probe read at the endpoint must survive on the row next to the
// expiry the state store knows: they are different facts, and a page that dropped the first
// could not show that the endpoint is serving a certificate older than the one on disk.
func TestInventoryKeepsTheExpiryTheProbeRead(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	served := now.Add(20 * 24 * time.Hour)
	stateExpiry := now.Add(80 * 24 * time.Hour)
	srv, store := newTestServer(t, &daemonFake{
		fakeReconciler: &fakeReconciler{names: []string{"example-com"}},
		probeEnabled:   true,
		answers:        map[string][]probe.Answer{},
	})
	if err := store.PutProbeSample(state.ProbeSample{
		CertName: "example-com", Host: "example.com", Match: true, Trusted: true,
		NotAfter: served, ObservedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	snap := inventorySnapshot(t, srv, store, &state.CertState{
		Name: "example-com", NotAfter: stateExpiry, DeployedCertID: "c1", DeployConfirmed: true,
	})
	row := rowNamed(t, snap, "example-com")
	if len(row.Probe.Hosts) != 1 {
		t.Fatalf("probe hosts = %+v, want the persisted sample", row.Probe.Hosts)
	}
	host := row.Probe.Hosts[0]
	if host.NotAfter == nil {
		t.Fatal("the expiry the probe read must survive the restart; without it the endpoint's own certificate is unknown again")
	}
	if !host.NotAfter.Equal(served) {
		t.Errorf("probe notAfter = %s, want the expiry the probe read (%s)", host.NotAfter, served)
	}
	if host.ObservedAt == nil || !host.ObservedAt.Equal(now) {
		t.Errorf("probe observedAt = %v, want the sample's observation time %s", host.ObservedAt, now)
	}
	if row.NotAfter != stateExpiry.Format(time.RFC3339) {
		t.Errorf("row notAfter = %q, want the state store's own expiry %s", row.NotAfter, stateExpiry.Format(time.RFC3339))
	}
}

// TestInventoryRendersWhenTheProbeEvidenceCannotBeRead covers the durable fallback when the
// store cannot answer it at all -- a missing table, which is what a state database written by
// a different build looks like. The certificate must stay on the page as unverified rather
// than disappearing or reading as healthy, the console must still render, and the read failure
// must reach the log, because nothing else in the response says the evidence was unavailable.
func TestInventoryRendersWhenTheProbeEvidenceCannotBeRead(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Second)
	var logs bytes.Buffer
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.PutCert(&state.CertState{
		Name: "example-com", NotAfter: now.Add(60 * 24 * time.Hour),
		DeployedCertID: "c1", DeployConfirmed: true,
	}); err != nil {
		t.Fatal(err)
	}
	s, err := New(&daemonFake{
		fakeReconciler: &fakeReconciler{names: []string{"example-com"}},
		probeEnabled:   true,
		answers:        map[string][]probe.Answer{},
	}, store, testToken, context.Background(), slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	// The write API cannot express "the evidence cannot be read"; this is the state package's
	// documented seam for injecting exactly that kind of fault.
	if err := store.ExecForTest("DROP TABLE probe_samples"); err != nil {
		t.Fatal(err)
	}

	w := do(t, s, http.MethodGet, "/api/inventory", "", bearer())
	if w.Code != http.StatusOK {
		t.Fatalf("inventory = %d, want 200: a store that cannot answer the probe fallback must not take the console down (body %s)", w.Code, w.Body.String())
	}
	var snap inventory.Snapshot
	if err := json.Unmarshal(w.Body.Bytes(), &snap); err != nil {
		t.Fatalf("inventory json: %v", err)
	}
	row := rowNamed(t, snap, "example-com")
	if row.Status != inventory.StatusProbeUnknown {
		t.Errorf("status = %q, want probe_unknown: no verdict was read, and that is not ok", row.Status)
	}
	if !row.Probe.Enabled {
		t.Error("probing is on; the read failure must not be reported as probing being off")
	}
	if len(row.Probe.Hosts) != 0 {
		t.Errorf("probe hosts = %+v, want none: nothing was read", row.Probe.Hosts)
	}
	if !strings.Contains(logs.String(), "failed to read persisted TLS probe evidence") {
		t.Errorf("the unreadable evidence must reach the log, got:\n%s", logs.String())
	}
}
