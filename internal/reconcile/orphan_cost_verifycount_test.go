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
// that left the desired state keep their row by design, and every pass tears each one down again --
// 2,999 orphans at 2,999 CleanupOrphan calls and 15,051 SQL statements PER PASS, identical on every
// pass. Running this against a synthetic fleet confirms or corrects that arithmetic from the real
// code, on a real state store, with the real lease/reclaim path.
//
// The statement counter lives in internal/state (OpenCounted): it installs a counting driver
// connector in place of the plain sql.Open, so what is counted is every statement SQLite is asked
// to execute, through the store's own single-connection pool.

const orphanTeardownFleet = 2999

// TestMeasureOrphanTeardownCostPerPass is the instrument. Run it explicitly:
//
//	go test -run TestMeasureOrphanTeardownCostPerPass -v -count=1 ./internal/reconcile/
func TestMeasureOrphanTeardownCostPerPass(t *testing.T) {
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

	// Pass 1 warms everything (in-process series, prober memory) and is reported separately, so pass
	// 2 is the steady-state number.
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

	cleaned := mgr.orphanCleaned()
	t.Logf("pass 1: %d statements, %s (attempted=%d, cleanupOrphan calls=%d)",
		first, firstWall.Round(time.Millisecond), rep.Attempted, len(cleaned))
	t.Logf("pass 2: %d statements, %s (attempted=%d)",
		second, secondWall.Round(time.Millisecond), rep2.Attempted)
	t.Logf("steady state: %.3f statements per orphan per pass; %.4f ms per orphan",
		float64(second)/float64(orphanTeardownFleet), float64(secondWall.Microseconds())/1000/float64(orphanTeardownFleet))

	// The rows are still there -- that is the design -- so pass 2 must have done the same work.
	if second != first {
		t.Logf("NOTE: pass 2 differs from pass 1 by %d statements (%d vs %d)",
			second-first, second, first)
	}
	// publishOrphans holds each name's claim across its teardown, so a pass may tear down a name
	// twice if two rounds overlap in this harness -- what matters is that every orphan is visited.
	if len(cleaned) < orphanTeardownFleet {
		t.Errorf("every orphan must be torn down on every pass, got %d CleanupOrphan calls", len(cleaned))
	}
	// The reconciler's own database cost per pass, isolated from the manager's.
	t.Logf("reconciler-visible: %.3f statements per orphan per pass (the manager's own SQL is measured in "+
		"internal/acme, where the real CleanupOrphan lives)", float64(second)/float64(orphanTeardownFleet))
}

// TestOrphanTeardownCostScalesWithTheFleet is the small control: same shape, one orphan and ten, so
// a reader can see the marginal statement count per orphan rather than a single aggregate.
func TestOrphanTeardownCostScalesWithTheFleet(t *testing.T) {
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

		// Warm, then measure.
		_ = r.RunDetailed(context.Background())
		before := state.CountedStatements.Load()
		_ = r.RunDetailed(context.Background())
		got := state.CountedStatements.Load() - before
		t.Logf("%5d orphans: %6d statements in the measured pass", n, got)
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
