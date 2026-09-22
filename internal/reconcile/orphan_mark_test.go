package reconcile

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/metrics"
	"github.com/susunola/wecert/internal/state"
)

// The orphan teardown used to run on EVERY pass, for every certificate that had ever left the
// desired state, because the row is deliberately kept (it is what preserves the history of a name
// that comes back). Measured at 2,999 orphans that was 6.000 statements per orphan per pass --
// 17,994 per pass, identical on every pass, forever (docs/backlog.md item 4b).
//
// The fix is a durable mark on the row, set when the teardown has actually finished and cleared when
// the name is desired again. These are its behaviour tests: the teardown runs once and the later
// passes still REPORT the orphan (the journal signal and the gauge must not regress) while issuing
// no SQL for it; a name that comes back and leaves again is torn down again; and a teardown that
// failed, or left a row behind, is not marked -- so it is retried instead of being silently dropped.
//
// The statement counts themselves are measured under `-tags verifycount` (orphan_cost_verifycount_test.go);
// what is asserted here is what the counts are made of.

// orphanMarkHarness is a reconciler over a real store, with a desired state the test can edit
// between passes and a log the test can read back.
type orphanMarkHarness struct {
	r     *Reconciler
	store *state.Store
	prov  *mutableProvider
	mgr   *fakeManager
	logs  *bytes.Buffer
}

func newOrphanMarkHarness(t *testing.T) *orphanMarkHarness {
	t.Helper()

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("opening the state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	prov := &mutableProvider{}
	mgr := &fakeManager{}
	logs := &bytes.Buffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// The config's certificate list is what enforce mode would fall back to; the provider is what a
	// pass actually resolves, so the test drives the document through prov.set.
	cfg := &config.Config{}
	r := New(cfg, prov, store, mgr, nil, log)
	return &orphanMarkHarness{r: r, store: store, prov: prov, mgr: mgr, logs: logs}
}

// seedOrphan puts a certificate row in the store that is not in the desired state -- the only thing
// an orphan IS, once the desired state does not name it.
func (h *orphanMarkHarness) seedOrphan(t *testing.T, name string) {
	t.Helper()
	if err := h.store.PutCert(&state.CertState{
		Name: name, NotAfter: time.Now().Add(10 * 24 * time.Hour),
	}); err != nil {
		t.Fatalf("PutCert(%s): %v", name, err)
	}
}

// pass runs one whole pass and returns how many CleanupOrphan calls it made.
func (h *orphanMarkHarness) pass(t *testing.T) int {
	t.Helper()
	before := len(h.mgr.orphanCleaned())
	h.r.RunDetailed(context.Background())
	return len(h.mgr.orphanCleaned()) - before
}

func (h *orphanMarkHarness) mark(t *testing.T, name string) time.Time {
	t.Helper()
	st, err := h.store.GetCert(name)
	if err != nil {
		t.Fatalf("GetCert(%s): %v", name, err)
	}
	if st == nil {
		t.Fatalf("certificate %s vanished from the state store", name)
	}
	return st.OrphanCleanedAt
}

// orphanLines counts the orphan report lines this pass wrote, split by level.
func (h *orphanMarkHarness) orphanLines() (errs, debug int) {
	for _, line := range strings.Split(strings.TrimSpace(h.logs.String()), "\n") {
		switch {
		case strings.Contains(line, "more certificates are no longer"):
			// The summary; its wording contains the per-orphan sentence too.
		case strings.Contains(line, "level=ERROR") && strings.Contains(line, "no longer in the desired state"):
			errs++
		case strings.Contains(line, "level=DEBUG") && strings.Contains(line, "no longer in the desired state"):
			debug++
		}
	}
	return errs, debug
}

func TestAnOrphanIsTornDownOnceAndThenOnlyReported(t *testing.T) {
	const name = "left-behind"
	h := newOrphanMarkHarness(t)
	h.seedOrphan(t, name)

	if got := h.pass(t); got != 1 {
		t.Fatalf("the first pass must tear the orphan down: %d CleanupOrphan calls, want 1", got)
	}
	if h.mark(t, name).IsZero() {
		t.Fatal("a finished teardown must be recorded on the row, or the next pass repeats it")
	}

	// Two more passes over the same rows -- still present, which is the design.
	for i := 0; i < 2; i++ {
		if got := h.pass(t); got != 0 {
			t.Fatalf("pass %d tore the orphan down again: %d CleanupOrphan calls, want 0 -- the "+
				"orphan-clean mark is not being honoured", i+2, got)
		}
	}

	// ...and it is still reported. The whole point of the mark is to stop the SQL, not the signal:
	// nothing else will ever mention that this certificate stopped being renewed.
	if errs, _ := h.orphanLines(); errs != 3 {
		t.Errorf("every pass must still report the orphan at ERROR: got %d lines for 3 passes", errs)
	}
	if got := testutil.ToFloat64(metrics.OrphanedCertificates); got != 1 {
		t.Errorf("wecert_orphaned_certificates = %v, want 1: an already-cleaned orphan is still an orphan", got)
	}
}

// The bound on the orphan lines has to survive the fix: a deployment whose whole document was
// dropped is exactly the case with thousands of marked rows, so the SECOND and later passes are now
// the ones that must not flood the journal.
func TestTheBoundedOrphanLogStillHoldsOnceTheOrphansAreMarked(t *testing.T) {
	const orphans = orphanLogLimit + 5
	h := newOrphanMarkHarness(t)
	for i := 0; i < orphans; i++ {
		h.seedOrphan(t, fmt.Sprintf("forgotten-%03d", i))
	}

	// Pass 1 is the one that tears them down.
	if got := h.pass(t); got != orphans {
		t.Fatalf("pass 1 must tear every orphan down, got %d CleanupOrphan calls, want %d",
			got, orphans)
	}

	// Pass 2 tears nothing down, and its journal must read exactly like pass 1's: the bound is per
	// pass, and what it bounds has to keep being written.
	h.logs.Reset()
	if got := h.pass(t); got != 0 {
		t.Fatalf("pass 2 must not tear anything down, got %d CleanupOrphan calls", got)
	}
	errs, debug := h.orphanLines()
	if errs != orphanLogLimit {
		t.Errorf("ERROR orphan lines = %d, want %d (the bound)", errs, orphanLogLimit)
	}
	if debug != orphans-orphanLogLimit {
		t.Errorf("the orphans past the bound must still be nameable at Debug: got %d, want %d",
			debug, orphans-orphanLogLimit)
	}
	if got := testutil.ToFloat64(metrics.OrphanedCertificates); got != orphans {
		t.Errorf("OrphanedCertificates = %v, want %d -- the gauge counts rows, not teardowns", got, orphans)
	}
	// And the summary that carries the count past the bound.
	if !strings.Contains(h.logs.String(), "more certificates are no longer in the desired state than "+
		"are listed above") {
		t.Error("the counted summary line must still be written once the teardown is marked as done")
	}
}

func TestAnOrphanThatComesBackAndLeavesIsTornDownAgain(t *testing.T) {
	const name = "returns"
	h := newOrphanMarkHarness(t)
	h.seedOrphan(t, name)

	if got := h.pass(t); got != 1 {
		t.Fatalf("the first pass must tear the orphan down, got %d CleanupOrphan calls", got)
	}
	if h.mark(t, name).IsZero() {
		t.Fatal("the teardown must be marked as finished")
	}

	// Back in the desired state.
	h.prov.set(config.Certificate{Name: name})
	if got := h.pass(t); got != 0 {
		t.Fatalf("a desired certificate is not an orphan: %d CleanupOrphan calls", got)
	}
	if got := h.mark(t, name); !got.IsZero() {
		t.Errorf("the mark must be cleared when the name comes back, still set to %s: it would "+
			"outlive the condition it describes and the next departure would be skipped", got)
	}

	// And it leaves again.
	h.prov.set()
	if got := h.pass(t); got != 1 {
		t.Fatalf("a certificate that left again must be torn down again, got %d CleanupOrphan calls",
			got)
	}
	if h.mark(t, name).IsZero() {
		t.Error("the second teardown must be marked as finished too")
	}
	if cleaned := h.mgr.orphanCleaned(); len(cleaned) != 2 {
		t.Errorf("want exactly two teardowns (one per departure), got %v", cleaned)
	}
}

// The webhook path reconciles a name WITHOUT running a whole pass, so the orphan sweep never sees
// that the name came back. If only publishOrphans cleared the mark, a name restored and triggered by
// hand would keep a stale mark: the next departure would be skipped, leaving behind the order, the
// TXT records and the metric series the pass that restored it wrote.
func TestANamedPassClearsTheOrphanMarkToo(t *testing.T) {
	const name = "webhooked"
	h := newOrphanMarkHarness(t)
	h.seedOrphan(t, name)

	if got := h.pass(t); got != 1 {
		t.Fatalf("the first pass must tear the orphan down, got %d CleanupOrphan calls", got)
	}

	h.prov.set(config.Certificate{Name: name})
	if err := h.r.RunCert(context.Background(), name); err != nil {
		t.Fatalf("RunCert: %v", err)
	}
	if got := h.mark(t, name); !got.IsZero() {
		t.Fatalf("a named pass over a desired certificate must clear the mark, still set to %s", got)
	}

	h.prov.set()
	if got := h.pass(t); got != 1 {
		t.Errorf("after the hand-restored name leaves again, the teardown must run again, got %d "+
			"CleanupOrphan calls", got)
	}
}

// The clear in publish covers a pass that reaches the certificate. The clear in publishOrphans
// covers the passes that do not: the sweep runs before the convergence loop, and the loop skips a
// name another pass is already holding. Without it, a certificate restored while a webhook-triggered
// pass was mid-flight would keep its stale mark, and the next departure would be skipped.
func TestAPassClearsTheMarkOfACertificateAnotherPassIsHolding(t *testing.T) {
	const name = "held-by-another-pass"
	h := newOrphanMarkHarness(t)
	h.seedOrphan(t, name)

	if got := h.pass(t); got != 1 {
		t.Fatalf("the first pass must tear the orphan down, got %d CleanupOrphan calls", got)
	}
	if h.mark(t, name).IsZero() {
		t.Fatal("the teardown must be marked as finished")
	}

	// The name is desired again, and a pass for it is already running, so this pass's loop will
	// skip it and never reach publish.
	h.prov.set(config.Certificate{Name: name})
	if !h.r.acquire(name) {
		t.Fatal("claiming the name for the simulation should succeed")
	}
	rep := h.r.RunDetailed(context.Background())
	h.r.release(name)
	if len(rep.Skipped) != 1 || rep.Skipped[0] != name {
		t.Fatalf("the pass should have skipped the held certificate, got %+v", rep.Skipped)
	}

	if got := h.mark(t, name); !got.IsZero() {
		t.Errorf("the sweep must clear the mark of a certificate that is back in the desired state even "+
			"when its own pass is in flight, still set to %s: the next departure would be skipped", got)
	}
}

func TestAFailedOrphanTeardownIsNotMarkedAndIsRetried(t *testing.T) {
	const name = "stubborn"
	h := newOrphanMarkHarness(t)
	h.seedOrphan(t, name)
	h.mgr.orphanFailWith = map[string]error{name: errors.New("cannot delete the TXT record: timeout")}

	if got := h.pass(t); got != 1 {
		t.Fatalf("the first pass must attempt the teardown, got %d CleanupOrphan calls", got)
	}
	if got := h.mark(t, name); !got.IsZero() {
		t.Fatalf("a FAILED teardown must not be marked as finished, mark = %s: the order and the TXT "+
			"records it could not reclaim would never be retried", got)
	}

	if got := h.pass(t); got != 1 {
		t.Fatalf("an unmarked orphan must be retried on the next pass, got %d CleanupOrphan calls", got)
	}

	// Once it succeeds, the mark goes on and the retries stop.
	h.mgr.orphanFailWith = nil
	if got := h.pass(t); got != 1 {
		t.Fatalf("the retry that succeeds must be the one that marks, got %d CleanupOrphan calls", got)
	}
	if h.mark(t, name).IsZero() {
		t.Fatal("the successful teardown must be marked")
	}
	if got := h.pass(t); got != 0 {
		t.Errorf("once marked, the teardown must stop: %d CleanupOrphan calls", got)
	}
}

// The mark must not be written over residue. Manager.CleanupOrphan deliberately keeps an
// authorization row when the TXT record could not be located, or when the challenge is still inside
// its propagation window and the record may yet appear -- the row carries the only clue for finding
// that record again. Marking the name anyway would stop the sweep from ever retrying it, stranding
// a stale _acme-challenge value that poisons every other certificate sharing the TXT name.
func TestALeftoverAuthorizationRowKeepsTheTeardownRetried(t *testing.T) {
	const name = "leaky-order"
	h := newOrphanMarkHarness(t)
	h.seedOrphan(t, name)

	// What a half-finished cleanup leaves behind.
	if err := h.store.PutAuthorization(&state.Authorization{
		CertName: name, AuthzURL: "https://acme.example/authz/1", Identifier: "example.com",
		ChallengeToken: "tok", TxtName: "_acme-challenge.example.com.", TxtValue: "v",
		Presented: true,
	}); err != nil {
		t.Fatalf("PutAuthorization: %v", err)
	}

	// The fake manager tears nothing down, so the row stays: exactly the shape of a teardown that
	// returned without reclaiming the record.
	if got := h.pass(t); got != 1 {
		t.Fatalf("the first pass must attempt the teardown, got %d CleanupOrphan calls", got)
	}
	if got := h.mark(t, name); !got.IsZero() {
		t.Fatalf("a teardown that left an authorization row behind must not be marked, mark = %s", got)
	}
	if got := h.pass(t); got != 1 {
		t.Fatalf("the name must be retried while the row is there, got %d CleanupOrphan calls", got)
	}

	// The record is reclaimed and its row goes away; now the teardown is finished.
	if err := h.store.DeleteAuthorization(name, "https://acme.example/authz/1"); err != nil {
		t.Fatalf("DeleteAuthorization: %v", err)
	}
	if got := h.pass(t); got != 1 {
		t.Fatalf("the last attempt must run, got %d CleanupOrphan calls", got)
	}
	if h.mark(t, name).IsZero() {
		t.Fatal("with the residue gone the teardown is finished and must be marked")
	}
	if got := h.pass(t); got != 0 {
		t.Errorf("once marked, the teardown must stop: %d CleanupOrphan calls", got)
	}
}
