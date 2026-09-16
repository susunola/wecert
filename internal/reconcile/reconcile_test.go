package reconcile

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/metrics"
	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
)

// fakeManager isolates the convergence loop's orchestration logic for testing.
type fakeManager struct {
	calls    []string
	failWith map[string]error

	reaped int

	// onReconcile fires on every Reconcile, so tests can cancel and so on.
	onReconcile func(name string)

	reapBefore chan struct{}
}

func (f *fakeManager) Reconcile(_ context.Context, c *config.Certificate) error {
	f.calls = append(f.calls, c.Name)
	if f.onReconcile != nil {
		f.onReconcile(c.Name)
	}
	return f.failWith[c.Name]
}

func (f *fakeManager) ReapRetired(_ context.Context) {
	if f.reapBefore != nil {
		<-f.reapBefore
	}
	f.reaped++
}

func newTestReconciler(t *testing.T, names []string, mgr CertManager) (*Reconciler, *state.Store) {
	t.Helper()

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("failed to open the state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := &config.Config{}
	for _, n := range names {
		cfg.Certificates = append(cfg.Certificates, config.Certificate{Name: n})
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(cfg, spec.NewStatic(cfg.Certificates), store, mgr, nil, log), store
}

// fakeNotifier records notifications, to verify "the result event really went out".
type fakeNotifier struct {
	events chan struct {
		cert string
		err  error
	}
}

func newFakeNotifier() *fakeNotifier {
	return &fakeNotifier{events: make(chan struct {
		cert string
		err  error
	}, 16)}
}

func (f *fakeNotifier) Renewal(_ context.Context, certName string, err error) {
	f.events <- struct {
		cert string
		err  error
	}{certName, err}
}

func TestNotifierReceivesRenewalResult(t *testing.T) {
	const name = "notify-ok"
	mgr := &fakeManager{}
	notifier := newFakeNotifier()

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	cfg := &config.Config{Certificates: []config.Certificate{{Name: name}}}
	r := New(cfg, spec.NewStatic(cfg.Certificates), store, mgr, notifier,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.RunOnce(context.Background())

	select {
	case ev := <-notifier.events:
		if ev.cert != name || ev.err != nil {
			t.Errorf("wrong notification content: cert=%q err=%v", ev.cert, ev.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no renewal notification received")
	}
}

func TestNotifierReceivesFailure(t *testing.T) {
	const name = "notify-fail"
	mgr := &fakeManager{failWith: map[string]error{name: errors.New("boom")}}
	notifier := newFakeNotifier()

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	cfg := &config.Config{Certificates: []config.Certificate{{Name: name}}}
	r := New(cfg, spec.NewStatic(cfg.Certificates), store, mgr, notifier,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.RunOnce(context.Background())

	select {
	case ev := <-notifier.events:
		if ev.err == nil {
			t.Error("failures should be notified too, with the error attached")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no failure notification received")
	}
}

// ── Event triggering ────────────────────────────────────────────────────────────

func TestRunCertUnknownName(t *testing.T) {
	mgr := &fakeManager{}
	r, _ := newTestReconciler(t, []string{"a"}, mgr)

	if err := r.RunCert(context.Background(), "nope"); err == nil {
		t.Fatal("an unknown certificate name should error")
	}
	if len(mgr.calls) != 0 {
		t.Errorf("an unknown name should trigger nothing, got %v", mgr.calls)
	}
}

func TestRunCertProcessesOnlyThatCert(t *testing.T) {
	mgr := &fakeManager{}
	r, _ := newTestReconciler(t, []string{"a", "b", "c"}, mgr)

	if err := r.RunCert(context.Background(), "b"); err != nil {
		t.Fatalf("RunCert failed: %v", err)
	}
	if len(mgr.calls) != 1 || mgr.calls[0] != "b" {
		t.Errorf("only b should be processed, got %v", mgr.calls)
	}
}

// This is why the whole concurrency gate exists: the timer and an
// event-triggered convergence landing on one certificate together means two
// orders that run into "5 certificates per exact set of identifiers / 7 days".
func TestConcurrentRunCertIsRejected(t *testing.T) {
	const name = "busy"
	release := make(chan struct{})
	entered := make(chan struct{}, 1)

	mgr := &fakeManager{onReconcile: func(string) {
		entered <- struct{}{}
		<-release
	}}
	r, _ := newTestReconciler(t, []string{name}, mgr)

	go func() { _ = r.RunCert(context.Background(), name) }()
	<-entered // wait until the first pass is really inside

	err := r.RunCert(context.Background(), name)
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("concurrent processing of one certificate should return ErrAlreadyRunning, got %v", err)
	}

	close(release)
}

// StartCert must claim the slot **synchronously**: otherwise, right after the
// caller gets "accepted", the same certificate could already have been started
// again elsewhere.
func TestStartCertReservesSlotSynchronously(t *testing.T) {
	const name = "async"
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	done := make(chan struct{})

	mgr := &fakeManager{onReconcile: func(string) {
		entered <- struct{}{}
		<-release
		close(done)
	}}
	r, _ := newTestReconciler(t, []string{name}, mgr)

	if err := r.StartCert(context.Background(), name); err != nil {
		t.Fatalf("StartCert failed: %v", err)
	}
	// Start again immediately; it must be refused — the background pass is still
	// running.
	if err := r.StartCert(context.Background(), name); !errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("should immediately report already running, got %v", err)
	}

	<-entered
	close(release)
	<-done
}

func TestStartAllSkipsBusyCerts(t *testing.T) {
	const busy = "busy-one"
	release := make(chan struct{})
	entered := make(chan struct{}, 1)

	mgr := &fakeManager{onReconcile: func(n string) {
		if n == busy {
			entered <- struct{}{}
			<-release
		}
	}}
	r, _ := newTestReconciler(t, []string{busy, "other"}, mgr)

	if err := r.StartCert(context.Background(), busy); err != nil {
		t.Fatal(err)
	}
	<-entered

	skipped := r.StartAll(context.Background())
	found := false
	for _, n := range skipped {
		if n == busy {
			found = true
		}
	}
	if !found {
		t.Errorf("StartAll should report %q as skipped, got %v", busy, skipped)
	}
	close(release)
}

func TestRunAllSkipsBusyCerts(t *testing.T) {
	const busy = "busy-runall"
	release := make(chan struct{})
	entered := make(chan struct{}, 1)

	mgr := &fakeManager{onReconcile: func(n string) {
		if n == busy {
			entered <- struct{}{}
			<-release
		}
	}}
	r, _ := newTestReconciler(t, []string{busy, "free"}, mgr)

	go func() { _ = r.RunCert(context.Background(), busy) }()
	<-entered

	skipped := r.RunAll(context.Background())
	if len(skipped) != 1 || skipped[0] != busy {
		t.Errorf("RunAll should skip %q, got %v", busy, skipped)
	}
	close(release)
}

func TestCertNamesPreservesConfigOrder(t *testing.T) {
	mgr := &fakeManager{}
	r, _ := newTestReconciler(t, []string{"z", "a", "m"}, mgr)

	// CertNames reads the cache of the last resolution, so resolve once first.
	// At startup main calls Prime to do the same: read-only endpoints must be able
	// to answer "which certificates exist" before the first convergence, or they
	// return an empty list — and an empty list is read as "the desired state is
	// empty".
	r.Prime(context.Background())

	got := r.CertNames()
	want := []string{"z", "a", "m"}
	if len(got) != len(want) {
		t.Fatalf("CertNames = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("CertNames order should match the config: %v vs %v", got, want)
		}
	}
}

// This is the entire reason RunOnce exists: one exploding certificate must not
// stall the others' renewals. The most dangerous thing in automation is that
// coupling — one mistyped domain and no certificate on the site renews.
func TestRunOnceContinuesAfterOneCertFails(t *testing.T) {
	mgr := &fakeManager{failWith: map[string]error{
		"b": errors.New("boom"),
	}}
	r, _ := newTestReconciler(t, []string{"a", "b", "c"}, mgr)

	r.RunOnce(context.Background())

	if len(mgr.calls) != 3 {
		t.Fatalf("all three certificates should be processed, only got %v", mgr.calls)
	}
	want := []string{"a", "b", "c"}
	for i := range want {
		if mgr.calls[i] != want[i] {
			t.Errorf("processing order should be %v, got %v", want, mgr.calls)
			break
		}
	}
}

func TestRunOnceReapsRetiredCerts(t *testing.T) {
	mgr := &fakeManager{}
	r, _ := newTestReconciler(t, []string{"only"}, mgr)

	r.RunOnce(context.Background())

	if mgr.reaped != 1 {
		t.Errorf("every pass should reap retired certificates once, got %d", mgr.reaped)
	}
}

// After a stop signal, no further certificates should be processed.
func TestRunOnceStopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := &fakeManager{onReconcile: func(string) { cancel() }}
	r, _ := newTestReconciler(t, []string{"a", "b", "c"}, mgr)

	r.RunOnce(ctx)

	if len(mgr.calls) != 1 {
		t.Errorf("after cancellation it should stop at the first, processed %v", mgr.calls)
	}
}

func TestPublishExportsNotAfter(t *testing.T) {
	mgr := &fakeManager{}
	r, store := newTestReconciler(t, []string{"pub-notafter"}, mgr)

	notAfter := time.Now().Add(60 * 24 * time.Hour).Truncate(time.Second)
	if err := store.PutCert(&state.CertState{Name: "pub-notafter", NotAfter: notAfter}); err != nil {
		t.Fatal(err)
	}

	r.RunOnce(context.Background())

	got := testutil.ToFloat64(metrics.CertNotAfter.WithLabelValues("pub-notafter"))
	if int64(got) != notAfter.Unix() {
		t.Errorf("CertNotAfter = %d, want %d", int64(got), notAfter.Unix())
	}
}

// The first upload still needs a manual bind, and "deployed" must not go green
// before then — or the expiry alert will think everything is fine.
func TestPublishDeployedRequiresConfirmation(t *testing.T) {
	const name = "pub-deployed"
	mgr := &fakeManager{}
	r, store := newTestReconciler(t, []string{name}, mgr)

	// Uploaded only, binding not yet confirmed
	if err := store.PutCert(&state.CertState{
		Name: name, NotAfter: time.Now().Add(24 * time.Hour), DeployedCertID: "ap-uploaded",
	}); err != nil {
		t.Fatal(err)
	}
	r.RunOnce(context.Background())
	if got := testutil.ToFloat64(metrics.CertDeployed.WithLabelValues(name)); got != 0 {
		t.Errorf("CertDeployed should be 0 when the binding is unconfirmed, got %v", got)
	}

	// Only after confirmation should it go green
	if err := store.PutCert(&state.CertState{
		Name: name, NotAfter: time.Now().Add(24 * time.Hour),
		DeployedCertID: "ap-uploaded", DeployConfirmed: true,
	}); err != nil {
		t.Fatal(err)
	}
	r.RunOnce(context.Background())
	if got := testutil.ToFloat64(metrics.CertDeployed.WithLabelValues(name)); got != 1 {
		t.Errorf("CertDeployed should be 1 after confirmation, got %v", got)
	}
}

// A certificate missing from the state store must not panic or write any
// metric.
func TestPublishMissingCertIsNoop(t *testing.T) {
	const name = "pub-missing"
	mgr := &fakeManager{}
	r, _ := newTestReconciler(t, []string{name}, mgr)

	r.RunOnce(context.Background())

	// The point is no panic. The metric should be at its default 0 here.
	if got := testutil.ToFloat64(metrics.CertConsecutiveFailures.WithLabelValues(name)); got != 0 {
		t.Errorf("a missing certificate's failure count should be 0, got %v", got)
	}
}

func TestRunOnceCountsFailuresInMetrics(t *testing.T) {
	const name = "pub-failcount"
	mgr := &fakeManager{failWith: map[string]error{name: errors.New("boom")}}
	r, store := newTestReconciler(t, []string{name}, mgr)

	if err := store.PutCert(&state.CertState{Name: name, ConsecutiveFailures: 3}); err != nil {
		t.Fatal(err)
	}

	r.RunOnce(context.Background())

	if got := testutil.ToFloat64(metrics.CertConsecutiveFailures.WithLabelValues(name)); got != 3 {
		t.Errorf("the consecutive failure count should surface as 3, got %v", got)
	}
}

// ── Failure semantics of the desired-state source ──────────────────────────────────────────────────

// failingProvider simulates "the source cannot be read".
type failingProvider struct{ err error }

func (f failingProvider) Desired(context.Context) ([]config.Certificate, error) {
	return nil, f.err
}

// An unreadable source must **never** be treated as an empty desired state.
//
// This is the one place in the design that can cause a disaster: once an empty
// result is taken as the desired state, wecert strips domains from every
// certificate and the live endpoints fail handshakes immediately — far worse
// than "nothing was issued this pass". The correct reaction is to skip the
// whole pass.
//
// This invariant is guarded both on the onboarding side (three-state
// semantics) and here: a contract boundary cannot assume the upstream got it
// right.
func TestUnreadableSourceSkipsThePassEntirely(t *testing.T) {
	mgr := &fakeManager{}

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	cfg := &config.Config{}
	r := New(cfg, failingProvider{err: errors.New("dns api is down")}, store, mgr, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	before := testutil.ToFloat64(metrics.DesiredStateErrors)
	r.RunOnce(context.Background())

	if len(mgr.calls) != 0 {
		t.Errorf("an unreadable source should process no certificates, processed %v", mgr.calls)
	}
	if got := testutil.ToFloat64(metrics.DesiredStateErrors); got != before+1 {
		t.Errorf("DesiredStateErrors should increment by one, got %v -> %v", before, got)
	}
	// CertNames must not become an empty list either: an empty list is read as
	// "the desired state is empty".
	if got := r.CertNames(); got != nil {
		t.Errorf("with no successful resolution CertNames should be nil, got %v", got)
	}
}

// Certificates in the state store but gone from the desired state are never
// renewed and quietly expire. This alert is that failure path's only safety
// net: the deletion path already has a grace period and reference checks, but
// if something still slips through, it should at least be visible before
// expiry.
func TestOrphanedCertificatesAreReported(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	cfg := &config.Config{Certificates: []config.Certificate{{Name: "kept"}}}
	if err := store.PutCert(&state.CertState{
		Name: "forgotten", NotAfter: time.Now().Add(10 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	r := New(cfg, spec.NewStatic(cfg.Certificates), store, &fakeManager{}, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.RunOnce(context.Background())

	if got := testutil.ToFloat64(metrics.OrphanedCertificates); got != 1 {
		t.Errorf("should report 1 orphaned certificate, got %v", got)
	}
}
