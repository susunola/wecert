package webhook

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/inventory"
	"github.com/susunola/wecert/internal/probe"
	"github.com/susunola/wecert/internal/state"
)

// daemonFake answers the optional inventory capabilities the real daemon provides:
// whether probing is on, what the last probes concluded, which resource types the
// deployment enumerates, and any cached bind-resource rows. The tests below pin both
// directions -- with the capability and without it -- because the defect this covers
// was a hardcoded "probing is on" meeting an always-empty sample list, which made
// every deployed certificate read as an unknown binding.
type daemonFake struct {
	*fakeReconciler
	probeEnabled  bool
	answers       map[string][]probe.Answer
	resourceTypes []string
	bindings      map[string]inventory.Bindings
}

func (d *daemonFake) ProbeEnabled() bool { return d.probeEnabled }

func (d *daemonFake) ProbeAnswers(name string) []probe.Answer { return d.answers[name] }

func (d *daemonFake) ResourceTypes() []string { return d.resourceTypes }

func (d *daemonFake) BindingSnapshot(certID string) (inventory.Bindings, bool) {
	b, ok := d.bindings[certID]
	return b, ok
}

func inventorySnapshot(t *testing.T, s *Server, store *state.Store, certs ...*state.CertState) inventory.Snapshot {
	t.Helper()
	for _, c := range certs {
		if err := store.PutCert(c); err != nil {
			t.Fatalf("put cert %s: %v", c.Name, err)
		}
	}
	w := do(t, s, http.MethodGet, "/api/inventory", "", bearer())
	if w.Code != http.StatusOK {
		t.Fatalf("inventory: got %d body %s", w.Code, w.Body.String())
	}
	var snap inventory.Snapshot
	if err := json.Unmarshal(w.Body.Bytes(), &snap); err != nil {
		t.Fatalf("inventory json: %v", err)
	}
	return snap
}

func rowNamed(t *testing.T, snap inventory.Snapshot, name string) inventory.Certificate {
	t.Helper()
	for _, row := range snap.Certificates {
		if row.Name == name {
			return row
		}
	}
	t.Fatalf("no row for %q in %+v", name, snap.Certificates)
	return inventory.Certificate{}
}

func TestInventoryCarriesTheProbeAnswersTheDaemonRecorded(t *testing.T) {
	now := time.Now().UTC()
	served := now.Add(40 * 24 * time.Hour)
	srv, store := newTestServer(t, &daemonFake{
		fakeReconciler: &fakeReconciler{names: []string{"example-com"}},
		probeEnabled:   true,
		resourceTypes:  []string{"clb"},
		answers: map[string][]probe.Answer{
			"example-com": {{
				Host: "example.com", Match: false, Trusted: true,
				NotAfter: served, ProblemKind: string(probe.ProblemNotAfter),
			}},
		},
	})
	snap := inventorySnapshot(t, srv, store, &state.CertState{
		Name: "example-com", NotAfter: now.Add(80 * 24 * time.Hour),
		DeployedCertID: "c1", DeployConfirmed: true,
	})
	row := rowNamed(t, snap, "example-com")
	if !row.Probe.Enabled || len(row.Probe.Hosts) != 1 {
		t.Fatalf("probe %+v: the answers the prober recorded must reach the page", row.Probe)
	}
	if row.Status != inventory.StatusProbeMismatch {
		t.Fatalf("status %q", row.Status)
	}
	if len(row.Drift) != 1 || row.Drift[0] != inventory.DriftServedNotAfter {
		t.Fatalf("drift %v", row.Drift)
	}
	if len(row.Bindings.ResourceTypes) != 1 || row.Bindings.ResourceTypes[0] != "clb" {
		t.Fatalf("resource types %v: an unstated scope reads as no scope", row.Bindings.ResourceTypes)
	}
}

func TestInventoryWithoutTheProbeCapabilityClaimsNothing(t *testing.T) {
	now := time.Now().UTC()
	srv, store := newTestServer(t, &fakeReconciler{names: []string{"example-com"}})
	snap := inventorySnapshot(t, srv, store, &state.CertState{
		Name: "example-com", NotAfter: now.Add(80 * 24 * time.Hour),
		DeployedCertID: "c1", DeployConfirmed: true,
	})
	row := rowNamed(t, snap, "example-com")
	if row.Probe.Enabled {
		t.Fatal("probing must not be reported as enabled when the daemon does not say it is")
	}
	if row.Status == inventory.StatusProbeUnknown || row.Status == inventory.StatusBindingUnknown {
		t.Fatalf("status %q: nothing was probed, and no probe is claimed", row.Status)
	}
}

func TestInventoryAppliesCachedBindingsBeforeTheStatus(t *testing.T) {
	now := time.Now().UTC()
	srv, store := newTestServer(t, &daemonFake{
		fakeReconciler: &fakeReconciler{names: []string{"example-com"}},
		bindings: map[string]inventory.Bindings{
			"c1": {
				Count: 0, Complete: false, Freshness: inventory.FreshnessCached,
				ObservedAt: "2026-09-22T05:00:00Z", Items: []inventory.BindingItem{},
			},
		},
	})
	snap := inventorySnapshot(t, srv, store, &state.CertState{
		Name: "example-com", NotAfter: now.Add(80 * 24 * time.Hour),
		DeployedCertID: "c1", DeployConfirmed: true,
	})
	row := rowNamed(t, snap, "example-com")
	if row.Status != inventory.StatusBindingUnknown {
		t.Fatalf("status %q: an incomplete live enumeration is not healthy", row.Status)
	}
	if snap.Summary.BindingUnknown != 1 {
		t.Fatalf("summary %+v: live rows must be part of the status, not painted on afterwards", snap.Summary)
	}
	if row.Bindings.ObservedAt != "2026-09-22T05:00:00Z" {
		t.Fatalf("observedAt %q", row.Bindings.ObservedAt)
	}
}

func TestInventoryRoutesAreMounted(t *testing.T) {
	s, _ := newTestServer(t, &fakeReconciler{names: []string{"example-com"}})

	if w := do(t, s, http.MethodGet, "/api/inventory", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated inventory: got %d", w.Code)
	}
	if w := do(t, s, http.MethodGet, "/status", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated page: got %d", w.Code)
	}

	w := do(t, s, http.MethodGet, "/api/inventory", "", bearer())
	if w.Code != http.StatusOK {
		t.Fatalf("inventory: got %d body %s", w.Code, w.Body.String())
	}
	var snap inventory.Snapshot
	if err := json.Unmarshal(w.Body.Bytes(), &snap); err != nil {
		t.Fatalf("inventory json: %v", err)
	}
	if len(snap.Certificates) != 1 || snap.Certificates[0].Name != "example-com" {
		t.Fatalf("certificates %+v", snap.Certificates)
	}
	if strings.Contains(w.Body.String(), "BEGIN CERTIFICATE") || strings.Contains(w.Body.String(), "PRIVATE") {
		t.Fatal("inventory payload must not contain PEM")
	}

	page := do(t, s, http.MethodGet, "/status", "", bearer())
	if page.Code != http.StatusOK {
		t.Fatalf("status page: got %d", page.Code)
	}
	if ct := page.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("content-type %q", ct)
	}
	if !strings.Contains(page.Body.String(), "example-com") {
		t.Fatalf("page missing cert name: %s", page.Body.String())
	}
}

func TestInventoryIncludesAccountUIN(t *testing.T) {
	s, _ := newTestServer(t, &fakeReconciler{names: []string{"example-com"}})
	s.SetAccountUIN("100012345678")

	w := do(t, s, http.MethodGet, "/api/inventory", "", bearer())
	if w.Code != http.StatusOK {
		t.Fatalf("inventory: got %d body %s", w.Code, w.Body.String())
	}
	var snap inventory.Snapshot
	if err := json.Unmarshal(w.Body.Bytes(), &snap); err != nil {
		t.Fatalf("inventory json: %v", err)
	}
	if len(snap.Certificates) != 1 || snap.Certificates[0].UIN != "100012345678" {
		t.Fatalf("uin %+v", snap.Certificates)
	}
	page := do(t, s, http.MethodGet, "/status", "", bearer())
	if !strings.Contains(page.Body.String(), "100012345678") {
		t.Fatalf("page missing uin: %s", page.Body.String())
	}
}
