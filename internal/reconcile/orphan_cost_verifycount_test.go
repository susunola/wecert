//go:build verifycount

package reconcile

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/probe"
	"github.com/susunola/wecert/internal/state"
)

// This file is a measuring instrument for the orphan-teardown cost, not a behavioural test. It is
// deliberately excluded from the default run: `go test` skips it, and it is invoked by name when
// someone needs the number.
//
// The claim under measurement (docs/backlog.md item 4b, from the round-11 scale work): certificates
// that left the desired state keep their row by design, and every pass tore each one down again --
// 2,999 orphans at 2,999 CleanupOrphan calls and 6.000 SQL statements per orphan PER PASS,
// identical on every pass. This instrument counts the reconciler's own half of that (the sweep, the
// per-orphan GetCert and the mark); the manager's five statements and the end-to-end pass are
// measured in internal/acme (orphan_cost_verifycount_test.go), which drives this same reconciler
// with the real Manager.
//
// The statement counter lives in internal/state (OpenCounted): it installs a counting driver
// connector in place of the plain sql.Open, so what is counted is every statement SQLite is asked
// to execute, through the store's own single-connection pool.

const orphanTeardownFleet = 2999

// TestMeasureOrphanTeardownCostPerPass is the instrument. Run it explicitly:
//
//	go test -tags verifycount -run TestMeasureOrphanTeardownCostPerPass -v -count=1 ./internal/reconcile/
//
// It also guards the fix: the assertions are per pass, not cumulative. Pass 1 must tear every orphan
// down (that half has to keep working), and pass 2 -- over rows that are still there, because that
// is the design -- must not call CleanupOrphan again. Deleting the skip in publishOrphans puts pass
// 2 back at pass 1's statement count and fails both of them.
func TestMeasureOrphanTeardownCostPerPass(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("a measurement, not a test")
	}

	store, err := state.OpenCounted(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	// Build the fleet: one issued certificate per orphan (a real SAN and a real expiry, because the
	// teardown reads both), none of them in the desired state.
	now := time.Now()
	build := time.Now()
	for i := 0; i < orphanTeardownFleet; i++ {
		name := "orphan-" + itoa(i)
		if err := store.PutCert(&state.CertState{
			Name:     name,
			NotAfter: now.Add(48 * time.Hour),
			CertPEM:  selfSignedCertPEM(t, "orphan-"+itoa(i)+".invalid"),
		}); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	t.Logf("seeded %d orphan rows in %s", orphanTeardownFleet, time.Since(build).Round(time.Millisecond))

	prov := &mutableProvider{} // desired state is empty: every row is an orphan
	cfg := &config.Config{}
	cfg.Probe.MaxHostsPerCert = 3
	mgr := &fakeManager{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := New(cfg, prov, store, mgr, nil, log)
	r.SetProber(probe.NewRunner(probe.Options{}, 0, log))

	// Pass 1 is the pass that has work to do: every orphan is unmarked, so it is torn down, its
	// probe hosts are reclaimed and the mark is written. Pass 2 is the steady state: the same rows
	// are still there (that is the design), so they are still reported, but nothing about them is
	// touched again.
	before := state.CountedStatements.Load()
	start := time.Now()
	rep := r.RunDetailed(context.Background())
	first := state.CountedStatements.Load() - before
	firstWall := time.Since(start)
	firstCleaned := len(mgr.orphanCleaned())

	before = state.CountedStatements.Load()
	start = time.Now()
	rep2 := r.RunDetailed(context.Background())
	second := state.CountedStatements.Load() - before
	secondWall := time.Since(start)
	secondCleaned := len(mgr.orphanCleaned()) - firstCleaned

	t.Logf("pass 1: %d statements, %s (attempted=%d, cleanupOrphan calls=%d)",
		first, firstWall.Round(time.Millisecond), rep.Attempted, firstCleaned)
	t.Logf("pass 2: %d statements, %s (attempted=%d, cleanupOrphan calls=%d)",
		second, secondWall.Round(time.Millisecond), rep2.Attempted, secondCleaned)
	t.Logf("steady state: %.3f statements per orphan per pass; %.4f ms per orphan",
		float64(second)/float64(orphanTeardownFleet), float64(secondWall.Microseconds())/1000/float64(orphanTeardownFleet))

	// Every orphan is visited exactly once -- by the pass that has something to do. (publishOrphans
	// holds each name's claim across its teardown, so a name can only be visited twice here if two
	// rounds overlapped; this harness runs one at a time.)
	if firstCleaned != orphanTeardownFleet {
		t.Errorf("pass 1 must tear down every orphan: %d CleanupOrphan calls, want %d",
			firstCleaned, orphanTeardownFleet)
	}
	// The fix, and the assertion that goes red without it: the mark is what stops the second pass
	// from repeating the teardown of rows that are still there by design.
	if secondCleaned != 0 {
		t.Errorf("pass 2 must not tear down the orphans it already tore down: %d CleanupOrphan calls "+
			"(--> the durable orphan-clean mark is not being honoured)", secondCleaned)
	}
	// And the number that mark exists for: the steady-state pass is the sweep query plus the pass's
	// own fixed epilogue, not one statement per orphan.
	const steadyBudget = 16
	if second > steadyBudget {
		t.Errorf("the steady-state pass cost %d statements, want <= %d: something is still "+
			"proportional to the orphan count", second, steadyBudget)
	}
	// The reconciler's own database cost per pass, isolated from the manager's (five statements per
	// CleanupOrphan call, measured in internal/acme).
	t.Logf("reconciler-visible: %.3f statements per orphan on the first pass, %.3f on every later one "+
		"(the manager's own SQL is measured in internal/acme, where the real CleanupOrphan lives)",
		float64(first)/float64(orphanTeardownFleet), float64(second)/float64(orphanTeardownFleet))
}

// TestOrphanTeardownCostScalesWithTheFleet is the small control: same shape, one orphan and ten, so
// a reader can see the marginal statement count per orphan rather than a single aggregate.
func TestOrphanTeardownCostScalesWithTheFleet(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 1, 10} {
		store, err := state.OpenCounted(filepath.Join(t.TempDir(), "state.db"))
		if err != nil {
			t.Fatalf("open state store: %v", err)
		}
		now := time.Now()
		for i := 0; i < n; i++ {
			if err := store.PutCert(&state.CertState{
				Name: "orphan-" + itoa(i), NotAfter: now.Add(48 * time.Hour),
				CertPEM: selfSignedCertPEM(t, "orphan-"+itoa(i)+".invalid"),
			}); err != nil {
				t.Fatal(err)
			}
		}
		prov := &mutableProvider{}
		cfg := &config.Config{}
		mgr := &fakeManager{}
		log := slog.New(slog.NewTextHandler(io.Discard, nil))
		r := New(cfg, prov, store, mgr, nil, log)

		// Both passes are reported: the first is the one that pays per orphan, the second is the
		// steady state. The marginal per-orphan cost is the difference across fleet sizes in
		// column one, and the point of the fix is that column two stays flat at one statement.
		before := state.CountedStatements.Load()
		_ = r.RunDetailed(context.Background())
		first := state.CountedStatements.Load() - before
		before = state.CountedStatements.Load()
		_ = r.RunDetailed(context.Background())
		second := state.CountedStatements.Load() - before
		t.Logf("%5d orphans: %6d statements on the first pass, %3d on the steady-state pass",
			n, first, second)
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// itoa avoids pulling strconv into the instrument's imports.
func itoa(i int) string {
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
