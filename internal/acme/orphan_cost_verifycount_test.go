//go:build verifycount

package acme

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/metrics"
	"github.com/susunola/wecert/internal/probe"
	"github.com/susunola/wecert/internal/reconcile"
	"github.com/susunola/wecert/internal/spec"
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
	// One of those five statements is GetCert inside tearDownOrphan and one is the mark the
	// reconciler writes when the teardown finishes; the end-to-end pass is measured by
	// TestMeasureReconcilerOrphanSweepCostPerPass below.
	t.Logf("combined with the reconciler's own read, the FIRST pass costs about %.3f statements per "+
		"orphan; every later pass costs none of it (the teardown is marked done)",
		float64(got)/float64(fleet)+1)
}

// TestMeasureReconcilerOrphanSweepCostPerPass is the end-to-end instrument: the real reconciler
// driving the real manager over a real state store, which is the shape the round-11 driver used and
// the source of the number in docs/backlog.md item 4b.
//
// The claim under measurement: 2,999 orphan rows cost 6.000 SQL statements EACH on every pass --
// five inside Manager.CleanupOrphan plus the GetCert in tearDownOrphan, on top of the sweep's own
// list query -- i.e. about 17,994 statements per pass, identical on every pass, forever, because the
// rows are kept by design. The fix is a durable mark: pass 1 does the work and writes it, and every
// later pass reports the same orphans for one statement.
//
// Reverting the skip in reconcile.publishOrphans turns this red: pass 2 goes back to the pass-1
// count, which is what the assertion below is for.
//
//	go test -tags verifycount -run TestMeasureReconcilerOrphanSweepCostPerPass -v -count=1 ./internal/acme/
func TestMeasureReconcilerOrphanSweepCostPerPass(t *testing.T) {
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

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := newManager(store, nil, &fakeSolver{}, fakeKeyAuth{}, deploy.Noop{}, log)

	// The desired state is empty, so every row is an orphan.
	cfg := &config.Config{}
	cfg.Probe.MaxHostsPerCert = 3
	r := reconcile.New(cfg, spec.NewStatic(nil), store, m, nil, log)
	r.SetProber(probe.NewRunner(probe.Options{}, 0, log))

	// Pass 1 is the one that has work to do: every orphan is unmarked, so it is torn down and
	// marked. Its count is also what EVERY pass cost before the mark existed.
	before := state.CountedStatements.Load()
	start := time.Now()
	rep := r.RunDetailed(context.Background())
	first := state.CountedStatements.Load() - before
	firstWall := time.Since(start)

	before = state.CountedStatements.Load()
	start = time.Now()
	rep2 := r.RunDetailed(context.Background())
	second := state.CountedStatements.Load() - before
	secondWall := time.Since(start)

	t.Logf("pass 1 (every orphan unmarked: what every pass used to cost): %d statements, %s "+
		"(attempted=%d, orphans=%d)", first, firstWall.Round(time.Millisecond), rep.Attempted, fleet)
	t.Logf("pass 2 (steady state): %d statements, %s (attempted=%d)",
		second, secondWall.Round(time.Millisecond), rep2.Attempted)
	t.Logf("per orphan per pass: %.3f statements before, %.3f after",
		float64(first)/float64(fleet), float64(second)/float64(fleet))

	// The rows are still there -- that is the design -- so the second pass must still have noticed
	// them (the gauge is what says so), and it must not have paid for them again.
	if got := testutil.ToFloat64(metrics.OrphanedCertificates); got != fleet {
		t.Errorf("the sweep must still report every orphan: gauge = %v, want %d", got, fleet)
	}
	if second >= first/10 {
		t.Errorf("the second pass cost %d statements against the first pass's %d: the orphan teardown "+
			"is still being repeated for every row on every pass", second, first)
	}
	// One sweep query plus the pass's own fixed epilogue (ReapRetired, the revocation read). The
	// bound is loose enough not to trip over one extra bookkeeping statement and tight enough that
	// a single orphan teardown in the pass breaks it.
	const steadyBudget = 16
	if second > steadyBudget {
		t.Errorf("the steady-state pass cost %d statements, want <= %d: something is still "+
			"proportional to the orphan count", second, steadyBudget)
	}
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
