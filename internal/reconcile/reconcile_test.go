package reconcile

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/metrics"
	"github.com/susunola/wecert/internal/probe"
	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
)

// fakeManager isolates the convergence loop's orchestration logic for testing.
type fakeManager struct {
	// Reconcile runs concurrently for a full webhook trigger (one goroutine per
	// certificate, bounded), so the recording has to be guarded.
	mu       sync.Mutex
	calls    []string
	failWith map[string]error

	// panicWith makes Reconcile panic for the named certificates, to prove a
	// panic inside the manager is recovered rather than process-fatal.
	panicWith map[string]string

	// cleaned records every CleanupOrphan call, in call order.
	cleaned []string

	reaped int

	// onReconcile fires on every Reconcile, so tests can cancel and so on.
	onReconcile func(name string)

	reapBefore chan struct{}
}

func (f *fakeManager) Reconcile(_ context.Context, c *config.Certificate) error {
	f.mu.Lock()
	f.calls = append(f.calls, c.Name)
	panicMsg := f.panicWith[c.Name]
	f.mu.Unlock()

	if panicMsg != "" {
		panic(panicMsg)
	}
	if f.onReconcile != nil {
		f.onReconcile(c.Name)
	}
	return f.failWith[c.Name]
}

// reconciled returns the names Reconcile was called with.
func (f *fakeManager) reconciled() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// orphanCleaned returns the names CleanupOrphan was called with.
func (f *fakeManager) orphanCleaned() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.cleaned...)
}

func (f *fakeManager) CleanupOrphan(_ context.Context, certName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cleaned = append(f.cleaned, certName)
	return nil
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

	_, skipped, err := r.StartAll(context.Background())
	if err != nil {
		t.Fatalf("StartAll failed: %v", err)
	}
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

// ── a full trigger must resolve once and stay bounded ──────────────────────

// countingProvider counts Desired calls.
type countingProvider struct {
	inner spec.Provider
	calls atomic.Int64
}

func (c *countingProvider) Desired(ctx context.Context) ([]config.Certificate, error) {
	c.calls.Add(1)
	return c.inner.Desired(ctx)
}

// StartAll used to resolve the desired state once itself and then once more inside
// every StartCert: N+1 file reads, YAML decodes, full validations and document
// hashes, plus an O(n^2) Find over a slice it was already holding.
func TestStartAllResolvesTheDesiredStateOnce(t *testing.T) {
	const n = 12

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("opening the state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := &config.Config{}
	for i := 0; i < n; i++ {
		cfg.Certificates = append(cfg.Certificates, config.Certificate{Name: fmt.Sprintf("c-%02d", i)})
	}

	done := make(chan struct{}, n)
	mgr := &fakeManager{onReconcile: func(string) { done <- struct{}{} }}
	prov := &countingProvider{inner: spec.NewStatic(cfg.Certificates)}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := New(cfg, prov, store, mgr, nil, log)

	_, skipped, err := r.StartAll(context.Background())
	if err != nil {
		t.Fatalf("StartAll failed: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("nothing should be skipped, got %v", skipped)
	}

	// Wait for every pass to finish so nothing is still reading the provider.
	for i := 0; i < n; i++ {
		<-done
	}

	if got := prov.calls.Load(); got != 1 {
		t.Errorf("the desired state was read %d times for one full trigger; want exactly 1", got)
	}
	if got := len(mgr.reconciled()); got != n {
		t.Errorf("every certificate must still be reconciled, got %d of %d", got, n)
	}
}

// A full trigger used to start one goroutine per certificate, so a large state
// fired that many concurrent ACME orders, DNS writes and cloud calls from a single
// HTTP request. The timer path walks the same certificates strictly one at a time.
func TestFullTriggerBoundsConcurrentReconciles(t *testing.T) {
	const n = 40

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("opening the state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := &config.Config{}
	for i := 0; i < n; i++ {
		cfg.Certificates = append(cfg.Certificates, config.Certificate{Name: fmt.Sprintf("c-%02d", i)})
	}

	var inFlight, peak atomic.Int64
	release := make(chan struct{})
	mgr := &fakeManager{onReconcile: func(string) {
		cur := inFlight.Add(1)
		for {
			old := peak.Load()
			if cur <= old || peak.CompareAndSwap(old, cur) {
				break
			}
		}
		<-release
		inFlight.Add(-1)
	}}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := New(cfg, spec.NewStatic(cfg.Certificates), store, mgr, nil, log)

	if _, _, err := r.StartAll(context.Background()); err != nil {
		t.Fatalf("StartAll failed: %v", err)
	}

	// Long enough for every goroutine that can hold a slot to take one and block.
	time.Sleep(200 * time.Millisecond)

	if got := peak.Load(); got > maxConcurrentStarts {
		t.Errorf("%d certificates reconciled concurrently; the bound is %d", got, maxConcurrentStarts)
	}
	if got := peak.Load(); got == 0 {
		t.Error("no reconcile started at all")
	}

	close(release)
}

// mutableProvider lets a test change the desired state between passes.
type mutableProvider struct {
	mu    sync.Mutex
	certs []config.Certificate
}

func (m *mutableProvider) Desired(context.Context) ([]config.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]config.Certificate(nil), m.certs...), nil
}

func (m *mutableProvider) set(certs ...config.Certificate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certs = certs
}

// hasCertSeries reports whether the not_after gauge currently exports this cert.
//
// ToFloat64 cannot answer this: reading a deleted label set creates a fresh child, so
// it returns 0 either way.
func hasCertSeries(t *testing.T, name string) bool {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gathering metrics: %v", err)
	}
	for _, f := range families {
		if f.GetName() != "wecert_certificate_not_after_timestamp_seconds" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "cert" && l.GetValue() == name {
					return true
				}
			}
		}
	}
	return false
}

// A per-certificate gauge is only ever written for names in the *current* desired
// state, so nothing revisits one that leaves it: the series stays exported at its
// last value forever. A not_after frozen at its last value then trips the documented
// expiry rule -- (not_after - now) < 21 days -- permanently, for a certificate that
// no longer exists, and the vecs grow without bound as domains churn.
func TestRemovedCertificateSeriesAreReclaimed(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("opening the state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	prov := &mutableProvider{}
	prov.set(config.Certificate{Name: "gone"}, config.Certificate{Name: "kept"})

	cfg := &config.Config{}
	cfg.Certificates = []config.Certificate{{Name: "gone"}, {Name: "kept"}}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := New(cfg, prov, store, &fakeManager{}, nil, log)

	// State rows are what publish() reads; without them it returns early.
	for _, n := range []string{"gone", "kept"} {
		if err := store.PutCert(&state.CertState{Name: n, NotAfter: time.Now().Add(48 * time.Hour)}); err != nil {
			t.Fatalf("PutCert: %v", err)
		}
	}

	r.RunAll(context.Background())
	if !hasCertSeries(t, "gone") || !hasCertSeries(t, "kept") {
		t.Fatal("both certificates should be exported after the first pass")
	}

	// The declaration disappears.
	prov.set(config.Certificate{Name: "kept"})
	cfg.Certificates = []config.Certificate{{Name: "kept"}}
	r.RunAll(context.Background())

	if hasCertSeries(t, "gone") {
		t.Error("the removed certificate's series must be reclaimed, or its frozen " +
			"not_after keeps firing the expiry alert forever")
	}
	if !hasCertSeries(t, "kept") {
		t.Error("the remaining certificate must stay exported")
	}
}

// RunCert asks for one specific certificate, so its caller must hear the pass's
// own failure -- reporting success while the pass errored makes a targeted
// trigger look healthy when it was not. RunAll deliberately stays
// fire-and-forget: one failing certificate must not stall the others.
func TestRunCertPropagatesTheReconcileError(t *testing.T) {
	boom := errors.New("boom")
	mgr := &fakeManager{failWith: map[string]error{"b": boom}}
	r, _ := newTestReconciler(t, []string{"a", "b"}, mgr)

	if err := r.RunCert(context.Background(), "b"); !errors.Is(err, boom) {
		t.Errorf("RunCert must propagate the pass's error, got %v", err)
	}
	if err := r.RunCert(context.Background(), "a"); err != nil {
		t.Errorf("a successful pass must return nil, got %v", err)
	}
}

// StartAll used to report nothing when the desired state was unreadable: the
// webhook then answered 202 with every certificate "accepted" (from the last
// good cache) while not a single pass had started -- a convergence that will
// never happen, reported as scheduled.
func TestStartAllFailsWhenDesiredStateIsUnreadable(t *testing.T) {
	mgr := &fakeManager{}

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	cfg := &config.Config{}
	r := New(cfg, failingProvider{err: errors.New("document service is down")}, store, mgr, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	accepted, skipped, err := r.StartAll(context.Background())
	if !errors.Is(err, ErrDesiredStateUnavailable) {
		t.Errorf("StartAll must report ErrDesiredStateUnavailable, got %v", err)
	}
	if len(accepted) != 0 || len(skipped) != 0 {
		t.Errorf("nothing may be reported accepted or skipped, got accepted=%v skipped=%v", accepted, skipped)
	}
	if len(mgr.reconciled()) != 0 {
		t.Errorf("an unreadable source should start nothing, started %v", mgr.reconciled())
	}
}

// The accepted list must come from the same resolution the starts were made
// from, and together with skipped it must partition the desired state -- a name
// in both, or in neither, means the trigger report lies about what happened.
func TestStartAllAcceptedAndSkippedPartitionTheDesiredState(t *testing.T) {
	const busy = "busy-partition"
	release := make(chan struct{})
	entered := make(chan struct{}, 1)

	mgr := &fakeManager{onReconcile: func(n string) {
		if n == busy {
			entered <- struct{}{}
			<-release
		}
	}}
	r, _ := newTestReconciler(t, []string{busy, "free-a", "free-b"}, mgr)

	if err := r.StartCert(context.Background(), busy); err != nil {
		t.Fatal(err)
	}
	<-entered

	accepted, skipped, err := r.StartAll(context.Background())
	if err != nil {
		t.Fatalf("StartAll failed: %v", err)
	}
	if len(skipped) != 1 || skipped[0] != busy {
		t.Errorf("skipped should be exactly [%q], got %v", busy, skipped)
	}
	if len(accepted) != 2 {
		t.Fatalf("the two free certificates should be accepted, got %v", accepted)
	}
	for _, n := range accepted {
		if n == busy {
			t.Errorf("the busy certificate must not be both accepted and skipped: %v / %v", accepted, skipped)
		}
	}
	close(release)
}

// A panic inside the manager used to be process-fatal from a webhook-started
// goroutine: one bad certificate took down every certificate's renewals. The
// pass must surface as an error to its caller and the fleet must carry on.
func TestReconcileOneRecoversPanics(t *testing.T) {
	const bad = "panic-cert"
	mgr := &fakeManager{panicWith: map[string]string{bad: "nil pointer in the order flow"}}
	r, _ := newTestReconciler(t, []string{"a", bad, "c"}, mgr)

	beforePanics := testutil.ToFloat64(metrics.ReconcilePanics.WithLabelValues(bad))

	// RunCert surfaces the failure to its caller as an error, not as a crash.
	if err := r.RunCert(context.Background(), bad); err == nil {
		t.Fatal("a panicking pass must be reported as an error")
	}

	if got := testutil.ToFloat64(metrics.ReconcilePanics.WithLabelValues(bad)); got != beforePanics+1 {
		t.Errorf("ReconcilePanics should increment by one, got %v -> %v", beforePanics, got)
	}

	// And a full pass must still reach the certificates after the panicking one.
	r.RunAll(context.Background())
	calls := mgr.reconciled()
	seen := map[string]bool{}
	for _, n := range calls {
		seen[n] = true
	}
	if !seen["a"] || !seen["c"] {
		t.Errorf("the other certificates must still be processed after a panic, got %v", calls)
	}
}

// selfSignedCertPEM issues a throwaway certificate so the orphan path can
// recover probe hosts from its SANs -- the desired state no longer carries the
// domains, the last issued certificate does.
func selfSignedCertPEM(t *testing.T, dnsNames ...string) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("issuing the test certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// hasProbeSeries reports whether the probe_match gauge currently exports this host.
func hasProbeSeries(t *testing.T, host string) bool {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gathering metrics: %v", err)
	}
	for _, f := range families {
		if f.GetName() != "wecert_certificate_probe_match" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "host" && l.GetValue() == host {
					return true
				}
			}
		}
	}
	return false
}

// A certificate removed from the desired state mid-order used to leak its
// challenge leases and TXT rows forever (poisoning every other certificate
// sharing the TXT name), and its probe series plus the prober's transition
// memory stayed behind for good. The orphan path must tear all of it down.
func TestOrphanCleanupIsWired(t *testing.T) {
	const (
		gone = "orphan-wired"
		kept = "kept-wired"
		host = "orphan.invalid"
	)

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("opening the state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	prov := &mutableProvider{}
	prov.set(config.Certificate{Name: kept})

	cfg := &config.Config{}
	cfg.Certificates = []config.Certificate{{Name: kept}}
	cfg.Probe.MaxHostsPerCert = 3

	mgr := &fakeManager{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := New(cfg, prov, store, mgr, nil, log)
	prober := probe.NewRunner(probe.Options{}, 0, log)
	r.SetProber(prober)

	// The dropped certificate: issued once (so it has SANs to reclaim probes for),
	// with an in-flight order whose cleanup must be requested.
	if err := store.PutCert(&state.CertState{
		Name: gone, NotAfter: time.Now().Add(48 * time.Hour),
		CertPEM: selfSignedCertPEM(t, host),
	}); err != nil {
		t.Fatalf("PutCert: %v", err)
	}
	if err := store.PutOrder(&state.Order{
		CertName: gone, OrderURL: "https://acme.example/order/orphan", Status: "pending",
	}); err != nil {
		t.Fatalf("PutOrder: %v", err)
	}

	// Simulate that the host was probed while the certificate was still managed:
	// an exported series and a remembered transition state.
	metrics.CertificateProbeMatch.WithLabelValues(host).Set(1)
	prober.Check(context.Background(), host, probe.Expectation{})
	if prober.LastState(host) == "" {
		t.Fatal("the prober should remember the host before the drop")
	}

	r.RunAll(context.Background())

	if cleaned := mgr.orphanCleaned(); len(cleaned) != 1 || cleaned[0] != gone {
		t.Errorf("CleanupOrphan should be called exactly once, for %q, got %v", gone, cleaned)
	}
	if hasProbeSeries(t, host) {
		t.Error("the dropped host's probe series must be reclaimed")
	}
	if got := prober.LastState(host); got != "" {
		t.Errorf("the prober must forget the dropped host, still remembers %q", got)
	}
}

// recordLogHandler captures log messages so a test can assert a specific line
// went out.
type recordLogHandler struct {
	mu   sync.Mutex
	msgs []string
}

func (h *recordLogHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordLogHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.msgs = append(h.msgs, r.Message)
	return nil
}

func (h *recordLogHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordLogHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordLogHandler) contains(sub string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, m := range h.msgs {
		if strings.Contains(m, sub) {
			return true
		}
	}
	return false
}

// A pass parked on a start slot when shutdown arrives is dropped without
// running, even though the caller was told "accepted". That must leave a trace
// -- silently, the 202 is indistinguishable from a pass that started and failed.
func TestParkedStartLogsAtShutdown(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, maxConcurrentStarts)
	mgr := &fakeManager{onReconcile: func(string) {
		entered <- struct{}{}
		<-release
	}}
	defer close(release)

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	cfg := &config.Config{}
	for i := 0; i < maxConcurrentStarts; i++ {
		cfg.Certificates = append(cfg.Certificates, config.Certificate{Name: fmt.Sprintf("filler-%02d", i)})
	}
	cfg.Certificates = append(cfg.Certificates, config.Certificate{Name: "parked"})

	handler := &recordLogHandler{}
	log := slog.New(handler)
	r := New(cfg, spec.NewStatic(cfg.Certificates), store, mgr, nil, log)

	// Occupy every start slot with a blocked pass, but leave "parked" out.
	if err := r.StartCert(context.Background(), "filler-00"); err != nil {
		t.Fatal(err)
	}
	<-entered
	for i := 1; i < maxConcurrentStarts; i++ {
		if err := r.StartCert(context.Background(), fmt.Sprintf("filler-%02d", i)); err != nil {
			t.Fatal(err)
		}
		<-entered
	}

	// With all slots held, this pass can only park; cancelling the context is
	// the shutdown signal.
	ctx, cancel := context.WithCancel(context.Background())
	if err := r.StartCert(ctx, "parked"); err != nil {
		t.Fatal(err)
	}
	cancel()

	deadline := time.Now().Add(2 * time.Second)
	for !handler.contains("shutdown while waiting for a start slot") {
		if time.Now().After(deadline) {
			t.Fatal("the parked pass must log that it will not run")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A panic inside one certificate's pass must be contained, not fatal.
//
// StartAll is the shape that matters: each certificate runs on its own goroutine, and an
// unrecovered panic there takes down the whole daemon -- every other certificate stops
// being renewed because one of them hit a nil map. The panic must also be counted, since
// wecert_reconcile_panics_total is documented as "any nonzero value is a bug".
func TestPanicInOneCertificateIsContainedAndCounted(t *testing.T) {
	mgr := &fakeManager{onReconcile: func(name string) {
		if name == "boom" {
			panic("simulated nil map write")
		}
	}}
	r, _ := newTestReconciler(t, []string{"boom", "ok"}, mgr)

	before := testutil.ToFloat64(metrics.ReconcilePanics.WithLabelValues("boom"))

	r.StartAll(context.Background())

	deadline := time.Now().Add(5 * time.Second)
	for {
		if len(mgr.reconciled()) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the other certificate never ran; the panic aborted the pass set: %v", mgr.reconciled())
		}
		time.Sleep(10 * time.Millisecond)
	}

	if got := testutil.ToFloat64(metrics.ReconcilePanics.WithLabelValues("boom")) - before; got != 1 {
		t.Errorf("the panic must be counted exactly once, got %v", got)
	}
}

// The probe is best-effort evidence, so a panic in it must not reach the process either.
// It runs one goroutine per host, where a panic is unrecoverable by the parent.
func TestPanicInTheProbeIsContained(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	cfg := &config.Config{
		Probe: config.Probe{MaxHostsPerCert: 1},
		Certificates: []config.Certificate{{
			Name:    "probed",
			Domains: []string{"probed.example.com"},
			Deploy:  config.Deploy{Enabled: true},
		}},
	}
	if err := store.PutCert(&state.CertState{
		Name:            "probed",
		DeployConfirmed: true,
		NotAfter:        time.Now().Add(30 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	r := New(cfg, spec.NewStatic(cfg.Certificates), store, &fakeManager{}, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.prober = panickingProber{}

	if err := r.RunCert(context.Background(), "probed"); err != nil {
		t.Fatalf("RunCert: %v", err)
	}
}

type panickingProber struct{}

func (panickingProber) Check(context.Context, string, probe.Expectation) probe.Verdict {
	panic("simulated parsing bug")
}

func (panickingProber) Forget(string) {}
