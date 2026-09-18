//go:build verifycount

package acme

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/state"
)

// The manager half of the orphan-teardown measurement.
//
// internal/reconcile's instrument counts only what the reconciler itself asks the store for (one
// ListCertNames plus one GetCert per orphan). The expensive half is CleanupOrphan, which is
// acme.Manager.discardOrder: register the recovered leases, list the authorizations, read the order,
// read the certificate, then a transaction. This measures that half against a real store with the
// real manager, at the shape the round-11 scale work used -- orphan rows whose orders and
// authorizations are long gone, which is what a certificate that left the desired state actually
// looks like.
//
// Run it with:
//
//	go test -tags verifycount -run TestMeasureManagerOrphanTeardownCost -v -count=1 ./internal/acme/
func TestMeasureManagerOrphanTeardownCost(t *testing.T) {
	const fleet = 2999

	store, err := state.OpenCounted(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	now := time.Now()
	for i := 0; i < fleet; i++ {
		name := "orphan-" + itoaInstrument(i)
		if err := store.PutCert(&state.CertState{
			Name: name, NotAfter: now.Add(48 * time.Hour),
			CertPEM: selfSignedCertPEM(t, now.Add(48*time.Hour), name+".invalid"),
		}); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}

	m := newManager(store, nil, &fakeSolver{}, fakeKeyAuth{}, deploy.Noop{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Warm-up: the first call also pays for any lazily-opened connection.
	_ = m.CleanupOrphan(context.Background(), "orphan-0")

	before := state.CountedStatements.Load()
	start := time.Now()
	for i := 0; i < fleet; i++ {
		if err := m.CleanupOrphan(context.Background(), "orphan-"+itoaInstrument(i)); err != nil {
			t.Fatalf("CleanupOrphan: %v", err)
		}
	}
	elapsed := time.Since(start)
	got := state.CountedStatements.Load() - before

	t.Logf("%d CleanupOrphan calls: %d statements (%.3f per orphan), %s (%.4f ms per orphan)",
		fleet, got, float64(got)/float64(fleet), elapsed.Round(time.Millisecond),
		float64(elapsed.Microseconds())/1000/float64(fleet))
	// The reconciler adds one statement per orphan on top (ListCertNames + GetCert in
	// tearDownOrphan); see internal/reconcile's TestMeasureOrphanTeardownCostPerPass.
	t.Logf("combined with the reconciler's own 1.000/orphan, the per-pass cost is about %.3f statements per orphan",
		float64(got)/float64(fleet)+1)
}

// itoaInstrument is strconv.Itoa without the import, so the instrument's imports stay minimal.
func itoaInstrument(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
