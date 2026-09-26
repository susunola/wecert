package webhook

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/probe"
	"github.com/susunola/wecert/internal/state"
)

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
