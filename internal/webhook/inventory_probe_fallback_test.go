package webhook

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/inventory"
	"github.com/susunola/wecert/internal/probe"
	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
)

func TestInventoryProbeEvidenceEligibility(t *testing.T) {
	now := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name         string
		probeEnabled bool
		desired      *spec.Result
		confirmed    bool
		wantEnabled  bool
		wantEvidence bool
		wantStatus   string
	}{
		{name: "globally disabled", confirmed: true, wantStatus: inventory.StatusExpiring},
		{name: "deployment disabled", probeEnabled: true, confirmed: true,
			desired:    &spec.Result{Certificates: []config.Certificate{{Name: "example-com", Deploy: config.Deploy{Enabled: false}}}},
			wantStatus: inventory.StatusExpiring},
		{name: "enabled with desired context", probeEnabled: true, confirmed: true,
			desired:     &spec.Result{Certificates: []config.Certificate{{Name: "example-com", Deploy: config.Deploy{Enabled: true}}}},
			wantEnabled: true, wantEvidence: true, wantStatus: inventory.StatusProbeMismatch},
		{name: "enabled without desired context", probeEnabled: true, confirmed: true,
			wantEnabled: true, wantEvidence: true, wantStatus: inventory.StatusProbeMismatch},
		{name: "enabled without matching desired certificate", probeEnabled: true, confirmed: true, desired: &spec.Result{},
			wantEnabled: true, wantEvidence: true, wantStatus: inventory.StatusProbeMismatch},
		{name: "unconfirmed deployment", probeEnabled: true,
			wantEnabled: true, wantStatus: inventory.StatusWaitingManualBind},
	} {
		for _, source := range []string{"persisted", "memory"} {
			t.Run(tc.name+"/"+source, func(t *testing.T) {
				fake := &inventoryCapabilityFake{
					daemonFake: &daemonFake{fakeReconciler: &fakeReconciler{names: []string{"example-com"}}, probeEnabled: tc.probeEnabled},
					last:       tc.desired,
				}
				if source == "memory" {
					fake.answers = map[string][]probe.Answer{"example-com": {{Host: "example.com", ProblemKind: string(probe.ProblemNotAfter)}}}
				}
				srv, store := newTestServer(t, fake)
				srv.now = func() time.Time { return now }
				if err := store.PutProbeSample(state.ProbeSample{
					CertName: "example-com", Host: "example.com", ProblemKind: string(probe.ProblemNotAfter), ObservedAt: now.Add(-time.Hour),
				}); err != nil {
					t.Fatal(err)
				}
				snap := inventorySnapshot(t, srv, store, &state.CertState{
					Name: "example-com", NotAfter: now.Add(10 * 24 * time.Hour), DeployedCertID: "fixture-cert", DeployConfirmed: tc.confirmed,
				})
				row := rowNamed(t, snap, "example-com")
				if row.Status != tc.wantStatus {
					t.Errorf("status = %q, want %q", row.Status, tc.wantStatus)
				}
				if row.Probe.Enabled != tc.wantEnabled {
					t.Errorf("probe.enabled = %v, want %v", row.Probe.Enabled, tc.wantEnabled)
				}
				if tc.wantEvidence {
					if len(row.Probe.Hosts) != 1 || row.Probe.OK == nil || *row.Probe.OK {
						t.Errorf("enabled probe evidence missing: %+v", row.Probe)
					}
					if snap.Summary.ProbeMismatch != 1 {
						t.Errorf("summary lost the enabled mismatch: %+v", snap.Summary)
					}
				} else {
					if row.Probe.Hosts == nil || len(row.Probe.Hosts) != 0 || row.Probe.OK != nil {
						t.Errorf("ineligible probe must have no active verdict or hosts: %+v", row.Probe)
					}
					for _, drift := range row.Drift {
						if drift == inventory.DriftServedNotAfter {
							t.Errorf("ineligible probe evidence became drift: %v", row.Drift)
						}
					}
					if snap.Summary.ProbeMismatch != 0 || snap.Summary.ProbeUnreachable != 0 || snap.Summary.ProbeUnknown != 0 {
						t.Errorf("ineligible probes counted in summary: %+v", snap.Summary)
					}
				}
				stored, err := store.ListProbeSamples("example-com")
				if err != nil || len(stored) != 1 {
					t.Errorf("historical evidence must remain stored: samples=%v err=%v", stored, err)
				}
			})
		}
	}
}

// The console must read the durable probe evidence when the process has none of its own.
//
// Probe answers are held in the prober's memory, so a restart empties them; the last verdict per
// host is also written to probe_samples by the pass that read it, and this is the fallback that
// turns that row back into the answer a row displays. Without it every known endpoint shows
// probe_unknown after every restart until the next pass runs -- which is what the page used to do,
// and what "the prober's memory is the only source" reads as. The failure is silent in the other
// direction too: dropping the fallback does not break any other test, because an empty answer set
// is a perfectly valid "nothing read yet".
//
// The neighbouring test covers the fallback failing (an unreadable table must not take the console
// down). This one covers it succeeding, which is what a restart of a healthy daemon looks like.
func TestInventoryFallsBackToPersistedProbeEvidenceAfterARestart(t *testing.T) {
	now := time.Now()
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

	// What the pass before the restart observed, and what this process has: nothing.
	observedAt := now.Add(-3 * time.Minute).Truncate(time.Second)
	servedNotAfter := now.Add(45 * 24 * time.Hour).Truncate(time.Second)
	if err := store.PutProbeSample(state.ProbeSample{
		CertName: "example-com", Host: "example.com",
		Match: true, Trusted: true, NotAfter: servedNotAfter, ObservedAt: observedAt,
	}); err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	s, err := New(&daemonFake{
		fakeReconciler: &fakeReconciler{names: []string{"example-com"}},
		probeEnabled:   true,
		// A fresh process: the in-memory answers are empty, and that is not "unknown".
		answers: map[string][]probe.Answer{},
	}, store, testToken, context.Background(), slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}

	snap := inventorySnapshot(t, s, store)
	row := rowNamed(t, snap, "example-com")
	if row.Status == "probe_unknown" {
		t.Fatalf("status = %q with a persisted verdict in probe_samples: a restart must not erase "+
			"what the last pass observed", row.Status)
	}
	if !row.Probe.Enabled {
		t.Error("probing is enabled; the row must not claim it is off")
	}
	if len(row.Probe.Hosts) != 1 {
		t.Fatalf("probe hosts = %+v, want the one persisted host", row.Probe.Hosts)
	}
	host := row.Probe.Hosts[0]
	if host.Host != "example.com" || !host.Match || !host.Trusted {
		t.Errorf("host sample = %+v, want the persisted verdict (example.com, match, trusted)", host)
	}
	// The timestamps are the point of persisting it: they tell the reader how old the answer is.
	if host.ObservedAt == nil || !host.ObservedAt.Equal(observedAt) {
		t.Errorf("observedAt = %v, want the stored instant %s", host.ObservedAt, observedAt)
	}
	if host.NotAfter == nil || !host.NotAfter.Equal(servedNotAfter) {
		t.Errorf("notAfter = %v, want the certificate the probe read (%s)", host.NotAfter, servedNotAfter)
	}
}
