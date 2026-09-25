package reconcile

import (
	"bytes"
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
	"github.com/susunola/wecert/internal/ratelimit"
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

	// panicReap and panicQuota make the pass-level epilogue steps panic, to prove a panic
	// there is contained rather than process-fatal: the epilogue runs outside reconcileOne's
	// recover, and the quota publication on a background goroutine, where a panic kills the
	// process.
	panicReap  bool
	panicQuota bool

	// cleaned records every CleanupOrphan call, in call order.
	cleaned []string

	// orphanFailWith makes CleanupOrphan fail for the named certificates, which is how a teardown
	// that could not reclaim its order or its TXT records is simulated: the name must then stay
	// unmarked and be retried on the next pass.
	orphanFailWith map[string]error

	reaped int

	// quotaScopes records every PublishQuota call.
	quotaScopes []map[string][]string

	// pendingRevocations drives PendingRevocations, and revocationRetries counts the
	// retry calls, so a test can assert the gate is honoured. pendingRevocationsErr makes the
	// read fail, to prove a failed read is not published as "nothing outstanding".
	pendingRevocations    int
	pendingRevocationsErr error
	revocationRetries     int

	// onReconcile fires on every Reconcile, so tests can cancel and so on.
	onReconcile func(name string)

	reapBefore chan struct{}

	// orphanEntered is signalled on every CleanupOrphan, and orphanRelease makes it block until
	// closed. Together they hold the orphan teardown open so a test can observe what may happen
	// while it runs.
	orphanEntered chan struct{}
	orphanRelease chan struct{}
}

func (f *fakeManager) QuotaStatus(map[string][]string) []ratelimit.QuotaReport { return nil }

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

// PendingRevocations reports the scripted outstanding count, so a test can assert the gate is
// honoured and that the published gauge follows it.
//
// With pendingRevocationsErr set it returns a zero count and the error, which is what
// acme.Manager does. That pairing is the trap the caller has to survive: the count is unusable, and
// publishing it would read as "nothing outstanding".
func (f *fakeManager) PendingRevocations() (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pendingRevocationsErr != nil {
		return 0, f.pendingRevocationsErr
	}
	return f.pendingRevocations, nil
}

func (f *fakeManager) RetryPendingRevocations(context.Context) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revocationRetries++
}

func (f *fakeManager) PublishQuota(scopes map[string][]string) {
	if f.panicQuota {
		panic("simulated quota publication bug")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.quotaScopes = append(f.quotaScopes, scopes)
}

// publishedQuota returns the scopes of every PublishQuota call so far.
func (f *fakeManager) publishedQuota() []map[string][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string][]string(nil), f.quotaScopes...)
}

func (f *fakeManager) CleanupOrphan(_ context.Context, certName string) error {
	f.mu.Lock()
	f.cleaned = append(f.cleaned, certName)
	entered, release := f.orphanEntered, f.orphanRelease
	failWith := f.orphanFailWith[certName]
	f.mu.Unlock()

	// Blocking happens outside the mutex: a test holds this call open while it reads the
	// reconciler's own state, and holding the fake's lock would deadlock that read.
	if entered != nil {
		entered <- struct{}{}
	}
	if release != nil {
		<-release
	}
	return failWith
}

func (f *fakeManager) ReapRetired(_ context.Context) {
	if f.panicReap {
		panic("simulated epilogue bug")
	}
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
	t.Parallel()
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
	r.RunDetailed(context.Background())

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
	t.Parallel()
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
	r.RunDetailed(context.Background())

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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

func TestAPassSkipsBusyCerts(t *testing.T) {
	t.Parallel()
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

	skipped := r.RunDetailed(context.Background()).Skipped
	if len(skipped) != 1 || skipped[0] != busy {
		t.Errorf("a pass should skip %q, got %v", busy, skipped)
	}
	close(release)
}

func TestCertNamesPreservesConfigOrder(t *testing.T) {
	t.Parallel()
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

// This is the entire reason a pass does not abort: one exploding certificate must not
// stall the others' renewals. The most dangerous thing in automation is that
// coupling — one mistyped domain and no certificate on the site renews.
func TestAPassContinuesAfterOneCertFails(t *testing.T) {
	t.Parallel()
	mgr := &fakeManager{failWith: map[string]error{
		"b": errors.New("boom"),
	}}
	r, _ := newTestReconciler(t, []string{"a", "b", "c"}, mgr)

	r.RunDetailed(context.Background())

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

func TestAPassReapsRetiredCerts(t *testing.T) {
	t.Parallel()
	mgr := &fakeManager{}
	r, _ := newTestReconciler(t, []string{"only"}, mgr)

	r.RunDetailed(context.Background())

	if mgr.reaped != 1 {
		t.Errorf("every pass should reap retired certificates once, got %d", mgr.reaped)
	}
}

// After a stop signal, no further certificates should be processed.
func TestAPassStopsOnContextCancel(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := &fakeManager{onReconcile: func(string) { cancel() }}
	r, _ := newTestReconciler(t, []string{"a", "b", "c"}, mgr)

	r.RunDetailed(ctx)

	if len(mgr.calls) != 1 {
		t.Errorf("after cancellation it should stop at the first, processed %v", mgr.calls)
	}
}

func TestPublishExportsNotAfter(t *testing.T) {
	t.Parallel()
	mgr := &fakeManager{}
	r, store := newTestReconciler(t, []string{"pub-notafter"}, mgr)

	notAfter := time.Now().Add(60 * 24 * time.Hour).Truncate(time.Second)
	if err := store.PutCert(&state.CertState{Name: "pub-notafter", NotAfter: notAfter}); err != nil {
		t.Fatal(err)
	}

	r.RunDetailed(context.Background())

	got := testutil.ToFloat64(metrics.CertNotAfter.WithLabelValues("pub-notafter", "classic"))
	if int64(got) != notAfter.Unix() {
		t.Errorf("CertNotAfter = %d, want %d", int64(got), notAfter.Unix())
	}
}

// The first upload still needs a manual bind, and "deployed" must not go green
// before then — or the expiry alert will think everything is fine.
func TestPublishDeployedRequiresConfirmation(t *testing.T) {
	t.Parallel()
	const name = "pub-deployed"
	mgr := &fakeManager{}
	r, store := newTestReconciler(t, []string{name}, mgr)

	// Uploaded only, binding not yet confirmed
	if err := store.PutCert(&state.CertState{
		Name: name, NotAfter: time.Now().Add(24 * time.Hour), DeployedCertID: "ap-uploaded",
	}); err != nil {
		t.Fatal(err)
	}
	r.RunDetailed(context.Background())
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
	r.RunDetailed(context.Background())
	if got := testutil.ToFloat64(metrics.CertDeployed.WithLabelValues(name)); got != 1 {
		t.Errorf("CertDeployed should be 1 after confirmation, got %v", got)
	}
}

// A certificate missing from the state store must not panic or write any
// metric.
func TestPublishMissingCertIsNoop(t *testing.T) {
	t.Parallel()
	const name = "pub-missing"
	mgr := &fakeManager{}
	r, _ := newTestReconciler(t, []string{name}, mgr)

	r.RunDetailed(context.Background())

	// The point is no panic. The metric should be at its default 0 here.
	if got := testutil.ToFloat64(metrics.CertConsecutiveFailures.WithLabelValues(name)); got != 0 {
		t.Errorf("a missing certificate's failure count should be 0, got %v", got)
	}
}

func TestAPassCountsFailuresInMetrics(t *testing.T) {
	t.Parallel()
	const name = "pub-failcount"
	mgr := &fakeManager{failWith: map[string]error{name: errors.New("boom")}}
	r, store := newTestReconciler(t, []string{name}, mgr)

	if err := store.PutCert(&state.CertState{Name: name, ConsecutiveFailures: 3}); err != nil {
		t.Fatal(err)
	}

	r.RunDetailed(context.Background())

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
	t.Parallel()
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
	r.RunDetailed(context.Background())

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
	t.Parallel()
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
	r.RunDetailed(context.Background())

	if got := testutil.ToFloat64(metrics.OrphanedCertificates); got != 1 {
		t.Errorf("should report 1 orphaned certificate, got %v", got)
	}
}

// A deployment with hundreds of orphans must not write hundreds of ERROR lines per pass.
//
// The orphan state is persistent by design (the row is kept so a re-added name resumes its history),
// so the per-orphan line repeated on every pass: measured at 500 orphans that is 500 ERROR lines per
// pass and 12,000 per day from one deployment, which is how a journal stops being read. The first few
// keep their own line; the rest are counted, and every one of them is still reachable at Debug.
func TestHundredsOfOrphansDoNotFloodTheJournal(t *testing.T) {
	t.Parallel()
	const orphans = orphanLogLimit + 5

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	cfg := &config.Config{Certificates: []config.Certificate{{Name: "kept"}}}
	for i := 0; i < orphans; i++ {
		if err := store.PutCert(&state.CertState{
			Name:     fmt.Sprintf("forgotten-%03d", i),
			NotAfter: time.Now().Add(10 * 24 * time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}

	var logs bytes.Buffer
	r := New(cfg, spec.NewStatic(cfg.Certificates), store, &fakeManager{}, nil,
		slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	r.RunDetailed(context.Background())

	if got := testutil.ToFloat64(metrics.OrphanedCertificates); got != orphans {
		t.Errorf("OrphanedCertificates = %v, want %d -- the count is what tells the operator the scale",
			got, orphans)
	}

	// At Error: the first orphanLogLimit lines plus one summary. Everything else is Debug.
	var errorLines, detailLines, summaries int
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		switch {
		// The summary first: its wording contains the per-orphan sentence as well.
		case strings.Contains(line, "more certificates are no longer"):
			summaries++
		case strings.Contains(line, "level=ERROR") && strings.Contains(line, "no longer in the desired state"):
			errorLines++
		case strings.Contains(line, "level=DEBUG") && strings.Contains(line, "no longer in the desired state"):
			detailLines++
		}
	}
	if errorLines != orphanLogLimit {
		t.Errorf("ERROR orphan lines = %d, want %d (the bound)", errorLines, orphanLogLimit)
	}
	if summaries != 1 {
		t.Errorf("expected exactly one summary line, got %d", summaries)
	}
	if detailLines != orphans-orphanLogLimit {
		t.Errorf("the orphans past the bound must still be nameable at Debug: got %d, want %d",
			detailLines, orphans-orphanLogLimit)
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
	t.Parallel()
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

// A full trigger must publish the quota gauges once, not once per certificate.
//
// publishQuota costs two store reads per scope, and the scope map is derived from the desired state
// (one entry per registered domain, per identifier set and, before round 11, per identifier). Calling
// it from each certificate's pass made the trigger quadratic in the fleet: the round-11 scale work
// measured 500 certificates of 20 names at 11,001,500 SQL statements and 84.4 s, against 23,003
// statements and 0.234 s for the same fleet's scheduled pass. The last pass of a batch publishes for
// the whole batch, so the numbers still include every spend the batch made.
func TestAFullTriggerPublishesQuotaOnce(t *testing.T) {
	t.Parallel()
	const n = 12

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("opening the state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := &config.Config{}
	for i := 0; i < n; i++ {
		cfg.Certificates = append(cfg.Certificates, config.Certificate{
			Name:    fmt.Sprintf("c-%02d", i),
			Domains: []string{fmt.Sprintf("c-%02d.example.com", i)},
		})
	}

	done := make(chan struct{}, n)
	mgr := &fakeManager{onReconcile: func(string) { done <- struct{}{} }}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := New(cfg, spec.NewStatic(cfg.Certificates), store, mgr, nil, log)

	if _, _, err := r.StartAll(context.Background()); err != nil {
		t.Fatalf("StartAll: %v", err)
	}
	for i := 0; i < n; i++ {
		<-done
	}

	// The publish happens in a deferred call in the last pass's goroutine, after onReconcile fires
	// for every certificate, so wait for the claims to be released as well.
	for i := 0; i < 500; i++ {
		if r.quotaPasses.Load() == 0 && !r.anyPassInFlight() {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	published := mgr.publishedQuota()
	if len(published) != 1 {
		t.Errorf("published the quota gauges %d times for one full trigger of %d certificates; "+
			"once per trigger is what keeps it linear in the fleet", len(published), n)
	}
}

// A full trigger used to start one goroutine per certificate, so a large state
// fired that many concurrent ACME orders, DNS writes and cloud calls from a single
// HTTP request. The timer path walks the same certificates strictly one at a time.
func TestFullTriggerBoundsConcurrentReconciles(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

	_ = r.RunDetailed(context.Background())
	if !hasCertSeries(t, "gone") || !hasCertSeries(t, "kept") {
		t.Fatal("both certificates should be exported after the first pass")
	}

	// The declaration disappears.
	prov.set(config.Certificate{Name: "kept"})
	cfg.Certificates = []config.Certificate{{Name: "kept"}}
	_ = r.RunDetailed(context.Background())

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
// trigger look healthy when it was not. A pass deliberately stays
// fire-and-forget: one failing certificate must not stall the others.
func TestRunCertPropagatesTheReconcileError(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	const bad = "panic-cert"
	mgr := &fakeManager{panicWith: map[string]string{bad: "nil pointer in the order flow"}}
	r, _ := newTestReconciler(t, []string{"a", bad, "c"}, mgr)

	beforePanics := testutil.ToFloat64(metrics.ReconcilePanics.WithLabelValues(bad))
	beforeErrors := testutil.ToFloat64(metrics.ReconcileTotal.WithLabelValues(bad, "error"))

	// RunCert surfaces the failure to its caller as an error, not as a crash.
	if err := r.RunCert(context.Background(), bad); err == nil {
		t.Fatal("a panicking pass must be reported as an error")
	}

	if got := testutil.ToFloat64(metrics.ReconcilePanics.WithLabelValues(bad)); got != beforePanics+1 {
		t.Errorf("ReconcilePanics should increment by one, got %v -> %v", beforePanics, got)
	}
	// The panic skipped the normal accounting, so the recover path must record the
	// failed pass itself -- reconcile_total must not under-report the worst passes.
	if got := testutil.ToFloat64(metrics.ReconcileTotal.WithLabelValues(bad, "error")); got != beforeErrors+1 {
		t.Errorf("ReconcileTotal{error} should increment by one on a panic, got %v -> %v", beforeErrors, got)
	}

	// And a full pass must still reach the certificates after the panicking one.
	_ = r.RunDetailed(context.Background())
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
	t.Parallel()
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
	cfg.Probe.MaxHostsPerCert = intPtr(3)

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

	_ = r.RunDetailed(context.Background())

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
	mu     sync.Mutex
	msgs   []string
	levels []slog.Level
}

func (h *recordLogHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordLogHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.msgs = append(h.msgs, r.Message)
	h.levels = append(h.levels, r.Level)
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

// containsAtLevel answers "was this said, and was it said loudly enough": a message
// an operator must not miss has to be logged at a level that survives the default
// verbosity, so the level is part of the assertion.
func (h *recordLogHandler) containsAtLevel(sub string, lvl slog.Level) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i, m := range h.msgs {
		if h.levels[i] == lvl && strings.Contains(m, sub) {
			return true
		}
	}
	return false
}

// A pass parked on a start slot when shutdown arrives is dropped without
// running, even though the caller was told "accepted". That must leave a trace
// -- silently, the 202 is indistinguishable from a pass that started and failed.
func TestParkedStartLogsAtShutdown(t *testing.T) {
	t.Parallel()
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
	for !handler.containsAtLevel("shutdown while waiting for a start slot", slog.LevelWarn) {
		if time.Now().After(deadline) {
			t.Fatal("the parked pass must log at Warn that it will not run: the caller was told " +
				"\"accepted\", so a trace buried at Debug leaves the 202 indistinguishable from a " +
				"pass that started and failed silently")
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
	t.Parallel()
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
	t.Parallel()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	cfg := &config.Config{
		Probe: config.Probe{MaxHostsPerCert: intPtr(1)},
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

// An orphan must not be torn down while its own pass is still running.
//
// Removing a certificate from the desired state while it is being issued is exactly when
// this matters: the running pass may be parked in WaitAll for minutes waiting on DNS
// propagation, holding challenge leases and an order URL. The teardown deletes the
// authorization rows and fires delete-all at the challenge TXT name, so doing it underneath
// the running pass makes that pass fail with a propagation error (or, if it already called
// AcceptChallenge, sends the CA to validate a vanished record and books an identifier
// failure that feeds the failure fallback), and the deleted order URL means its retry
// re-orders into the "5 certificates per exact set of identifiers / 7 days" limit.
//
// The claim is held here directly rather than by racing a real pass, so the assertion is
// deterministic: publishOrphans runs at the top of a pass, before the loop that claims.
func TestOrphanTeardownSkipsACertificateWithAPassInFlight(t *testing.T) {
	t.Parallel()
	const (
		gone = "in-flight-cert"
		kept = "kept-cert"
	)

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("opening the state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if err := store.PutCert(&state.CertState{
		Name: gone, NotAfter: time.Now().Add(48 * time.Hour),
	}); err != nil {
		t.Fatalf("PutCert: %v", err)
	}
	if err := store.PutOrder(&state.Order{
		CertName: gone, OrderURL: "https://acme.example/order/inflight", Status: "pending",
	}); err != nil {
		t.Fatalf("PutOrder: %v", err)
	}

	prov := &mutableProvider{}
	prov.set(config.Certificate{Name: kept})
	cfg := &config.Config{}
	cfg.Certificates = []config.Certificate{{Name: kept}}

	mgr := &fakeManager{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := New(cfg, prov, store, mgr, nil, log)

	// The pass for `gone` is in flight and has not released its claim.
	if !r.acquire(gone) {
		t.Fatal("acquiring the claim should succeed on a fresh reconciler")
	}

	_ = r.RunDetailed(context.Background())

	if cleaned := mgr.orphanCleaned(); len(cleaned) != 0 {
		t.Errorf("the orphan teardown ran for a certificate with a pass in flight (%v); "+
			"that deletes the TXT records and order the running pass is waiting on", cleaned)
	}
	// Deferred is not invisible: the certificate IS in the store and NOT in the desired
	// state, so the gauge must count it even while its teardown waits -- otherwise the
	// one signal for "this will expire unrenewed" reads 0 during exactly that window.
	if got := testutil.ToFloat64(metrics.OrphanedCertificates); got != 1 {
		t.Errorf("an orphan whose teardown is deferred must still be counted, got %v", got)
	}

	// Once the pass releases, the next round must reap it -- skipping must not mean losing.
	r.release(gone)
	_ = r.RunDetailed(context.Background())

	if cleaned := mgr.orphanCleaned(); len(cleaned) != 1 || cleaned[0] != gone {
		t.Errorf("after the claim is released the orphan must be reaped exactly once, got %v", cleaned)
	}
}

// A pass skipped for backoff must not be reported as a success, and must not notify.
//
// Manager.Reconcile returns state.ErrBackoff when the certificate is inside the retry
// window an earlier failure scheduled. That is neither a success nor a failure, and
// reporting it as either misleads the operator: result="ok" hid a certificate stuck in
// backoff behind a healthy-looking counter, and the documented notification contract is
// "every renewal ATTEMPT emits" -- a skip is the absence of an attempt, so emitting
// result:"ok" for it asserts a renewal that never ran.
func TestBackoffSkippedPassIsNotReportedAsSuccess(t *testing.T) {
	t.Parallel()
	const name = "backing-off"

	mgr := &fakeManager{failWith: map[string]error{name: state.ErrBackoff}}
	notifier := newFakeNotifier()

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	cfg := &config.Config{Certificates: []config.Certificate{{Name: name}}}
	r := New(cfg, spec.NewStatic(cfg.Certificates), store, mgr, notifier,
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Read the counters before the pass and assert the delta: these live in the process-global
	// registry, so an absolute expectation only holds on the first run of the test binary and
	// `go test -count=2` fails with "got 2". The delta is also the stronger statement -- it says
	// this pass counted exactly once, which "the counter reads 1" cannot distinguish from "an
	// earlier run already counted it".
	before := reconcileCounts(t, name)

	_ = r.RunDetailed(context.Background())

	// No notification: nothing was attempted.
	select {
	case ev := <-notifier.events:
		t.Errorf("a backoff skip must not emit a renewal notification, got cert=%q err=%v", ev.cert, ev.err)
	case <-time.After(200 * time.Millisecond):
	}

	after := reconcileCounts(t, name)
	if after["ok"] != before["ok"] {
		t.Errorf("a skipped pass must not be counted as ok, went from %v to %v -- a certificate in "+
			"failure backoff looked healthy on the counter an operator watches",
			before["ok"], after["ok"])
	}
	if after["skipped"] != before["skipped"]+1 {
		t.Errorf("a skipped pass must be counted as skipped exactly once, went from %v to %v",
			before["skipped"], after["skipped"])
	}
	if after["error"] != before["error"] {
		t.Errorf("a backoff skip is not a failure; error count went from %v to %v",
			before["error"], after["error"])
	}
}

// A pass in which every certificate is inside its backoff window must be reported as trouble.
//
// This is the classification Trouble() depends on, and the reason the guard it used to have could
// never fire: an ErrBackoff pass increments Backoff and does NOT append to Skipped, so a one-shot run
// exited 0 with a green journal for a certificate parked for up to six hours. Asserting it here as
// well as on Trouble() itself keeps the two halves -- what the pass records, and what the exit code
// reads -- from drifting apart again.
func TestAPassInBackoffIsRecordedAsTrouble(t *testing.T) {
	t.Parallel()
	names := []string{"backing-off-one", "backing-off-two"}

	mgr := &fakeManager{failWith: map[string]error{
		names[0]: state.ErrBackoff,
		names[1]: state.ErrBackoff,
	}}
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	certs := make([]config.Certificate, 0, len(names))
	for _, n := range names {
		certs = append(certs, config.Certificate{Name: n})
	}
	cfg := &config.Config{Certificates: certs}
	r := New(cfg, spec.NewStatic(certs), store, mgr, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	rep := r.RunDetailed(context.Background())
	if rep.Backoff != len(names) {
		t.Errorf("Backoff = %d, want %d: this is the count the exit code reads", rep.Backoff, len(names))
	}
	if len(rep.Skipped) != 0 {
		t.Errorf("a backoff skip is not an in-flight skip; Skipped = %v", rep.Skipped)
	}
	if rep.Attempted != 0 {
		t.Errorf("nothing was attempted, got %d", rep.Attempted)
	}
	if !rep.Trouble() {
		t.Error("a pass that attempted nothing because every certificate is in its retry window is " +
			"not a healthy pass: the timer would exit 0 while nothing is being renewed")
	}
}

// reconcileCounts reads the three result counters for one certificate.
func reconcileCounts(t *testing.T, name string) map[string]float64 {
	t.Helper()
	out := make(map[string]float64, 3)
	for _, result := range []string{"ok", "error", "skipped"} {
		out[result] = counterValue(t, "wecert_reconcile_total",
			map[string]string{"cert": name, "result": result})
	}
	return out
}

// The control: a genuine failure still counts as an error and still notifies, so the fix
// cannot be satisfied by never notifying or never counting.
func TestGenuineFailureStillCountsAndNotifies(t *testing.T) {
	t.Parallel()
	const name = "really-failing"

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

	before := reconcileCounts(t, name)

	_ = r.RunDetailed(context.Background())

	select {
	case ev := <-notifier.events:
		if ev.err == nil {
			t.Error("a failed pass must carry its error into the notification")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a genuine failure must still notify")
	}
	if after := reconcileCounts(t, name); after["error"] != before["error"]+1 {
		t.Errorf("a genuine failure must count as error exactly once, went from %v to %v",
			before["error"], after["error"])
	}
}

// counterValue reads one counter out of the default registry.
func counterValue(t *testing.T, metric string, labels map[string]string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() != metric {
			continue
		}
		for _, m := range f.GetMetric() {
			got := map[string]string{}
			for _, lp := range m.GetLabel() {
				got[lp.GetName()] = lp.GetValue()
			}
			match := true
			for k, v := range labels {
				if got[k] != v {
					match = false
					break
				}
			}
			if match {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// Outstanding revocations must be retried on every pass, and the gate must be honoured.
//
// Revocation is unbounded in time: a request recorded because a key leaked has to keep being
// attempted until the CA accepts it, across restarts and CA outages. The gate exists because
// this runs on every pass and almost every deployment has nothing outstanding.
func TestOutstandingRevocationsAreRetriedEachPass(t *testing.T) {
	t.Parallel()
	prov := &mutableProvider{}
	prov.set(config.Certificate{Name: "kept"})

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := &config.Config{Certificates: []config.Certificate{{Name: "kept"}}}
	mgr := &fakeManager{}
	r := New(cfg, prov, store, mgr, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Nothing outstanding: the pass must not even ask the manager to retry, and the gauge must say
	// so -- an operator reading wecert_revocation_pending at rest has to see 0, not nothing at all.
	_ = r.RunDetailed(context.Background())
	if mgr.revocationRetries != 0 {
		t.Errorf("with nothing outstanding the pass must skip the retry entirely, got %d calls",
			mgr.revocationRetries)
	}
	if got := testutil.ToFloat64(metrics.RevocationPending); got != 0 {
		t.Errorf("with nothing outstanding wecert_revocation_pending must read 0, got %v", got)
	}

	// Something outstanding: every pass retries it, so a CA that was briefly unavailable does
	// not leave a compromised certificate alive.
	mgr.mu.Lock()
	mgr.pendingRevocations = 1
	mgr.mu.Unlock()

	_ = r.RunDetailed(context.Background())
	if mgr.revocationRetries != 1 {
		t.Errorf("an outstanding revocation must be retried on the pass, got %d calls",
			mgr.revocationRetries)
	}
	if got := testutil.ToFloat64(metrics.RevocationPending); got != 1 {
		t.Errorf("an outstanding revocation must be visible as wecert_revocation_pending=1, got %v",
			got)
	}

	_ = r.RunDetailed(context.Background())
	if mgr.revocationRetries != 2 {
		t.Errorf("it must be retried on every pass until it succeeds, got %d calls",
			mgr.revocationRetries)
	}

	// The CA accepts it, so the next pass reports 0 -- and the retry stops being called.
	mgr.mu.Lock()
	mgr.pendingRevocations = 0
	mgr.mu.Unlock()

	_ = r.RunDetailed(context.Background())
	if mgr.revocationRetries != 2 {
		t.Errorf("an accepted revocation must not be retried again, got %d calls",
			mgr.revocationRetries)
	}
	if got := testutil.ToFloat64(metrics.RevocationPending); got != 0 {
		t.Errorf("an accepted revocation must clear the gauge, got %v", got)
	}

	// A store that cannot be read must leave the last known value alone and be counted. Folding
	// this error into a 0 would publish a confident all-clear on the one metric that says a
	// certificate which should no longer be trusted still is.
	mgr.mu.Lock()
	mgr.pendingRevocations = 2
	mgr.mu.Unlock()
	_ = r.RunDetailed(context.Background())
	if got := testutil.ToFloat64(metrics.RevocationPending); got != 2 {
		t.Fatalf("setup: the gauge must track the count before the failure, got %v", got)
	}

	beforeErrCount := testutil.ToFloat64(metrics.RevocationQueryErrors)
	beforeRetries := mgr.revocationRetries
	mgr.mu.Lock()
	mgr.pendingRevocationsErr = errors.New("state.db is unreadable")
	mgr.mu.Unlock()

	_ = r.RunDetailed(context.Background())
	if got := testutil.ToFloat64(metrics.RevocationPending); got != 2 {
		t.Errorf("a failed read must leave wecert_revocation_pending stale, not rewrite it to %v",
			got)
	}
	if got := testutil.ToFloat64(metrics.RevocationQueryErrors); got != beforeErrCount+1 {
		t.Errorf("a failed read must be counted, want %v errors, got %v", beforeErrCount+1, got)
	}
	if mgr.revocationRetries != beforeRetries {
		t.Errorf("a failed read must not start a retry against a store that just failed, "+
			"want %d calls, got %d", beforeRetries, mgr.revocationRetries)
	}
}

// "Is this daemon converging at all?" has to be answerable from outside the process, and it has to
// be answerable in a way that a wedged pass cannot fake.
func TestOnlyAFullPassStampsLastReconcile(t *testing.T) {
	t.Parallel()
	mgr := &fakeManager{}
	r, _ := newTestReconciler(t, []string{"one"}, mgr)

	// 0 before any pass. The alert reads that as "nothing has finished since startup" -- which is
	// true, and is the right answer for a daemon that has been up for a week without completing one.
	metrics.LastReconcile.Set(0)

	started := time.Now().Add(-time.Second).Unix()
	_ = r.RunDetailed(context.Background())
	if got := testutil.ToFloat64(metrics.LastReconcile); got < float64(started) {
		t.Errorf("a completed pass must stamp wecert_last_reconcile_timestamp_seconds with the time "+
			"it finished; got %v, which is not after the pass started", got)
	}

	// The webhook path reconciles named certificates without running a pass. If it stamped this
	// gauge, an API caller could keep a dead timer loop looking alive.
	metrics.LastReconcile.Set(0)
	if err := r.StartCert(context.Background(), "one"); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(metrics.LastReconcile); got != 0 {
		t.Errorf("StartCert must not stamp the pass timestamp, got %v", got)
	}

	if _, _, err := r.StartAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(metrics.LastReconcile); got != 0 {
		t.Errorf("StartAll must not stamp the pass timestamp, got %v", got)
	}
}

// A webhook-triggered pass must publish the rate-limit gauges when it finishes.
//
// Publishing lived only at the end of RunDetailed, so the webhook path -- which spends quota and
// records the CA's Retry-After exactly like a scheduled pass -- never refreshed either gauge. A
// deadline shorter than the polling interval (an hour by default) was then never visible as
// blocked, which is the whole window it describes: WecertRateLimitBlocked could not fire for it.
// The publish also has to come *after* the pass, or the spend it just made is not in the number.
func TestAWebhookTriggeredPassPublishesQuotaWhenItFinishes(t *testing.T) {
	t.Parallel()
	started := make(chan struct{}, 4)
	hold := make(chan struct{})
	mgr := &fakeManager{onReconcile: func(string) {
		started <- struct{}{}
		<-hold
	}}
	r, _ := newTestReconciler(t, []string{"webhook-a"}, mgr)

	if _, _, err := r.StartAll(context.Background()); err != nil {
		t.Fatalf("StartAll failed: %v", err)
	}
	<-started

	// The pass is in flight (blocked inside Reconcile), so nothing has been spent or decided yet.
	if n := len(mgr.publishedQuota()); n != 0 {
		t.Errorf("the gauges must be published when the pass finishes, not before it runs; got %d "+
			"call(s) while the pass was still in flight", n)
	}

	close(hold)

	deadline := time.Now().Add(5 * time.Second)
	for len(mgr.publishedQuota()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("a webhook-triggered pass must publish the rate-limit gauges; otherwise a quota " +
				"spend and the CA's deadline stay invisible until the next scheduled round, which " +
				"an hour away is too late for a deadline that is shorter than that")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The orphan teardown must hold the claim while it runs, not just look at it.
//
// The check that protects an in-flight pass from having its TXT records and order deleted
// underneath it used to read the claim and release the lock immediately, so a webhook-triggered
// pass could claim the name in the gap before CleanupOrphan ran -- the exact destructive
// interleaving the check exists to prevent. It is reachable: the desired state is resolved twice
// (once by the pass that sees the name as an orphan, once by the webhook after the declaration was
// restored), and a document revision can land in between.
func TestTheOrphanTeardownHoldsTheClaimWhileItRuns(t *testing.T) {
	t.Parallel()
	const orphan = "orphan-cert"
	entered := make(chan struct{}, 1)
	release := make(chan struct{})

	mgr := &fakeManager{orphanEntered: entered, orphanRelease: release}
	r, store := newTestReconciler(t, []string{"kept"}, mgr)

	// In the store but not in the desired state: an orphan.
	if err := store.PutCert(&state.CertState{Name: orphan}); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		r.RunDetailed(context.Background())
	}()
	<-entered

	// The teardown is inside CleanupOrphan. Anything that wants to claim this name now has to be
	// refused -- that is what startCert asks, and a "yes" here means the pass would run against a
	// name whose order and TXT records are being deleted.
	if r.acquire(orphan) {
		r.release(orphan)
		t.Error("the teardown must hold the claim for its whole duration: a pass that claims the " +
			"name now has its order and TXT records deleted underneath it, fails with a propagation " +
			"error, and re-orders into the exact-set quota")
	}

	close(release)
	<-done

	// And the claim is released when the teardown ends, so the name is not wedged against every
	// later pass.
	if !r.acquire(orphan) {
		t.Error("the teardown must release the claim when it finishes")
	} else {
		r.release(orphan)
	}
}

// A panicking pass must still notify.
//
// The panic recover sits in a defer, so the notifier call at the end of reconcileOne is
// unreachable while the stack unwinds: the pass was counted as an error and logged, but the
// operator's channel heard nothing -- and a panic is precisely the failure that must not go quiet.
func TestAPanickingPassStillNotifies(t *testing.T) {
	t.Parallel()
	const name = "boom"
	mgr := &fakeManager{onReconcile: func(n string) {
		if n == name {
			panic("simulated nil map write")
		}
	}}
	notifier := newFakeNotifier()

	cfg := &config.Config{Certificates: []config.Certificate{{Name: name}}}
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	r := New(cfg, spec.NewStatic(cfg.Certificates), store, mgr, notifier,
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	if err := r.RunCert(context.Background(), name); err == nil {
		t.Fatal("the pass must report the panic as a failure")
	}

	select {
	case ev := <-notifier.events:
		if ev.cert != name {
			t.Errorf("notification was for %q, want %q", ev.cert, name)
		}
		if ev.err == nil {
			t.Error("the notified result must be the failure, not a success")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a panicking pass emitted no notification: the recover unwinds past the notifier, " +
			"so the one failure an operator must hear about is the one that goes quiet")
	}
}

// Shutdown must wait for a webhook-triggered pass.
//
// The accepted pass writes the promotion, the resume anchor and the failure counter, and the caller
// closes the state store as soon as it returns. Nothing used to wait for them: on SIGTERM the
// daemon returned and the deferred Close() closed SQLite under a pass still mid-renewal, so its
// epilogue failed -- and the worst case is named in the code itself: an exit between an upload
// returning an id and PutOrder recording it leaves a cloud certificate in neither table, billed and
// never reclaimed.
func TestDrainWaitsForABackgroundPass(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	entered := make(chan struct{}, 1)

	mgr := &fakeManager{onReconcile: func(string) {
		entered <- struct{}{}
		<-release
	}}
	r, _ := newTestReconciler(t, []string{"a"}, mgr)

	if err := r.StartCert(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
	<-entered

	drained := make(chan error, 1)
	go func() { drained <- r.Drain(context.Background()) }()

	select {
	case <-drained:
		close(release)
		t.Fatal("Drain returned while a pass was still running: the store would be closed under it")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	select {
	case err := <-drained:
		if err != nil {
			t.Errorf("Drain reported %v after the pass finished", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Drain never returned after the pass finished")
	}
}

// A pass that cannot be interrupted must not hang shutdown forever.
//
// lego's low-level API is context-free, so a pass inside a CA call cannot be cancelled; the caller
// bounds the wait and says what a timeout means.
func TestDrainIsBounded(t *testing.T) {
	t.Parallel()
	hold := make(chan struct{})
	entered := make(chan struct{}, 1)
	defer close(hold)

	mgr := &fakeManager{onReconcile: func(string) {
		entered <- struct{}{}
		<-hold
	}}
	r, _ := newTestReconciler(t, []string{"a"}, mgr)

	if err := r.StartCert(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
	<-entered

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := r.Drain(ctx); err == nil {
		t.Error("a pass that cannot finish must be reported, so the operator knows the store is " +
			"about to be closed under it")
	}
}

// A pass may not be admitted once Drain has been called.
//
// Drain's contract is that the state store is safe to close when it returns, and a pass admitted
// afterwards breaks it in two ways: it writes its promotion, resume anchor and failure counter into
// a database that is already closed, and registering it is a sync.WaitGroup misuse (an Add that
// starts from a zero counter concurrent with Wait), which Go answers with the process-fatal
// "sync: WaitGroup is reused before previous Wait has returned". The webhook's HTTP shutdown is
// asynchronous, so a trigger arriving during shutdown reaches exactly this path.
func TestAPassStartedAfterDrainIsRefused(t *testing.T) {
	t.Parallel()
	mgr := &fakeManager{}
	r, _ := newTestReconciler(t, []string{"a", "b"}, mgr)

	if err := r.Drain(context.Background()); err != nil {
		t.Fatalf("Drain with no pass in flight: %v", err)
	}

	if err := r.StartCert(context.Background(), "a"); !errors.Is(err, ErrShuttingDown) {
		t.Errorf("StartCert after Drain must be refused with ErrShuttingDown, got %v", err)
	}
	if _, _, err := r.StartAll(context.Background()); !errors.Is(err, ErrShuttingDown) {
		t.Errorf("StartAll after Drain must be refused with ErrShuttingDown, got %v", err)
	}
	if _, _, _, err := r.StartNamed(context.Background(), []string{"a", "b"}); !errors.Is(err, ErrShuttingDown) {
		t.Errorf("StartNamed after Drain must be refused with ErrShuttingDown, got %v", err)
	}

	// A refusal, not a pass that runs anyway. (No goroutine was started, so reading the record
	// without the mutex is safe.)
	if len(mgr.calls) != 0 {
		t.Errorf("no pass may run after Drain returned, these did: %v", mgr.calls)
	}
}

// A refused trigger must not be reported as "already running".
//
// The webhook maps a start error to the "skipped" bucket, which means "already running" -- so
// answering ErrAlreadyRunning for a shutdown would tell the caller to poll for a pass that will
// never happen.
func TestAShutdownRefusalIsNotReportedAsAlreadyRunning(t *testing.T) {
	t.Parallel()
	mgr := &fakeManager{}
	r, _ := newTestReconciler(t, []string{"a"}, mgr)
	if err := r.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}

	started, running, unknown, err := r.StartNamed(context.Background(), []string{"a"})
	if !errors.Is(err, ErrShuttingDown) {
		t.Fatalf("want ErrShuttingDown, got %v", err)
	}
	if len(started) != 0 || len(running) != 0 || len(unknown) != 0 {
		t.Errorf("a refused trigger must report nothing but the error, got started=%v running=%v unknown=%v",
			started, running, unknown)
	}
}

// Registering a pass and entering Drain must not race.
//
// This is the window bgMu exists for: startCert's registration (bg.Add) running concurrently with
// Drain's bg.Wait. Without the lock this test fails with the process-fatal "sync: WaitGroup is
// reused before previous Wait has returned" panic, and -race reports the Add/Wait pair as a data
// race. Each iteration builds its own reconciler because draining is terminal by design.
func TestStartingAPassDoesNotRaceWithDrain(t *testing.T) {
	t.Parallel()
	for i := 0; i < 40; i++ {
		mgr := &fakeManager{}
		r, _ := newTestReconciler(t, []string{"a", "b", "c", "d"}, mgr)

		begin := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-begin
			_, _, _ = r.StartAll(context.Background())
		}()
		go func() {
			defer wg.Done()
			<-begin
			_ = r.Drain(context.Background())
		}()
		close(begin)
		wg.Wait()

		// Whatever the interleaving, nothing may be left running once Drain returns: a pass
		// admitted before the transition is waited for, and one attempted after it is refused.
		if err := r.Drain(context.Background()); err != nil {
			t.Fatalf("iteration %d: Drain after the race reported %v", i, err)
		}
	}
}

// A probe floor the desired state cannot satisfy must be reported, not silently ignored.
//
// In enforce mode config.normalize sees an empty certificate list -- the document is the only source
// of certificates -- so its probe.minValidFor check never runs. The floor then fails every probe of
// a shortlived certificate, which pins wecert_certificate_probe_match at 0 and fires the critical
// "not serving the deployed certificate" alert with a diagnosis that blames the rebind or SNI. The
// pass must say what the real cause is. It must not refuse to renew: the document may change between
// passes, and a monitoring misconfiguration is not a reason to stop issuing.
func TestAProbeFloorTheDocumentCannotSatisfyIsReported(t *testing.T) {
	t.Parallel()
	mgr := &fakeManager{}
	provider := &mutableProvider{}
	provider.set(config.Certificate{
		Name: "short", Profile: config.ProfileShortLived, Domains: []string{"short.example.com"},
	})

	var logs bytes.Buffer
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := &config.Config{}
	cfg.Probe.MinValidDur = 168 * time.Hour
	r := New(cfg, provider, store, mgr, nil, slog.New(slog.NewTextHandler(&logs, nil)))

	// A certificate with no stored state is attempted, which is what makes this a pass rather
	// than an empty sweep; the manager is a fake, so nothing else is needed.
	r.RunDetailed(context.Background())

	if got := logs.String(); !strings.Contains(got, "probe's minimum remaining validity") ||
		!strings.Contains(got, "short") {
		t.Errorf("the pass must report the unsatisfiable probe floor and name the certificate, got:\n%s", got)
	}
	if len(mgr.calls) == 0 {
		t.Error("a probe-setting mismatch must not stop the certificate from being renewed")
	}
}

// The gauges must cover every managed scope, not one representative per limit family.
//
// Publishing only the first certificate's first domain left the per-domain families with a single
// series: the alert that compares against them could not fire for any other domain, and for a fleet
// laid out one certificate per domain that is every domain but one. Each family gets every scope
// the resolved desired state actually spends against, deduplicated (a wildcard and its apex share a
// registered domain; a multi-name certificate appears once).
func TestQuotaPublishingCoversEveryManagedScope(t *testing.T) {
	t.Parallel()
	mgr := &fakeManager{}
	r, _ := newTestReconciler(t, []string{"a-example-com", "b-example-com"}, mgr)

	// newTestReconciler builds certificates with no domains, so give them real ones through the
	// provider the pass resolves.
	spec := spec.NewStatic([]config.Certificate{
		{Name: "a-example-com", Domains: []string{"a.example.com", "*.a.example.com"}},
		{Name: "b-example-com", Domains: []string{"b.example.com", "other.test"}},
	})
	r = New(r.cfg, spec, r.store, mgr, nil, r.log)

	r.RunDetailed(context.Background())

	published := mgr.publishedQuota()
	if len(published) == 0 {
		t.Fatal("a pass must publish the rate-limit gauges")
	}
	got := published[len(published)-1]

	inList := func(list []string, want string) bool {
		for _, got := range list {
			if got == want {
				return true
			}
		}
		return false
	}
	for _, want := range []string{"a.example.com", "b.example.com", "other.test"} {
		if !inList(got["identifier"], want) {
			t.Errorf("identifier scope %q is missing from %v; its series does not exist, so the "+
				"exhaustion alert cannot fire for it", want, got["identifier"])
		}
	}
	for _, want := range []string{"example.com", "other.test"} {
		if !inList(got["registered-domain"], want) {
			t.Errorf("registered-domain scope %q is missing from %v", want, got["registered-domain"])
		}
	}
	if n := len(got["registered-domain"]); n != 2 {
		t.Errorf("the registered domains are deduplicated (a wildcard shares its apex's), got %d: %v",
			n, got["registered-domain"])
	}
	if n := len(got["exact-identifier-set"]); n != 2 {
		t.Errorf("one identifier set per certificate, got %d: %v", n, got["exact-identifier-set"])
	}
}

// A one-shot run reads Trouble() as its exit code, so "nothing ran and nothing is
// running" must not read as clean. A certificate inside its retry backoff lands in
// Backoff -- not in Skipped (no pass was in flight; the manager deliberately did not
// run one) -- so a pass in which every certificate sat inside its window used to
// report Attempted == 0 with empty Skipped and exit 0 over a fleet making no progress.
func TestTroubleTreatsAFullyBackedOffPassAsTrouble(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		rep  RunReport
		want bool
	}{
		{"clean pass", RunReport{Attempted: 2, Succeeded: 2}, false},
		{"nothing managed", RunReport{}, false},
		{"failures", RunReport{Attempted: 1, Failed: 1}, true},
		{"unreadable desired state", RunReport{DesiredStateUnreadable: true}, true},
		{"all skipped", RunReport{Skipped: []string{"a"}}, true},
		{"all backed off", RunReport{Backoff: 2}, true},
		{"backoff beside real attempts is not trouble", RunReport{Attempted: 1, Succeeded: 1, Backoff: 3}, false},
	} {
		if got := tc.rep.Trouble(); got != tc.want {
			t.Errorf("%s: Trouble() = %v, want %v", tc.name, got, tc.want)
		}
	}

	// The integration that produces the shape: the only certificate is inside its
	// retry window, so the pass backs off instead of attempting.
	mgr := &fakeManager{failWith: map[string]error{"stuck": state.ErrBackoff}}
	r, _ := newTestReconciler(t, []string{"stuck"}, mgr)

	rep := r.RunDetailed(context.Background())
	if rep.Attempted != 0 || rep.Backoff != 1 {
		t.Fatalf("a backed-off pass must report Attempted=0 Backoff=1, got %+v", rep)
	}
	if !rep.Trouble() {
		t.Error("a pass in which the only certificate is backing off must read as trouble -- " +
			"a one-shot run exits 0 on !Trouble, over a fleet making no progress")
	}
}

// panicNotifier panics on every call, to prove the notification path cannot take a
// finished pass down with it.
type panicNotifier struct{ calls atomic.Int64 }

func (p *panicNotifier) Renewal(context.Context, string, error) {
	p.calls.Add(1)
	panic("the notification POST exploded")
}

// A notifier that panics on the NORMAL path used to escape into reconcileOne's own
// recover: a pass that had already succeeded was rewritten to a reported failure and
// the recover block then fired a second, contradictory notification.
func TestAPanickingNotifierDoesNotRewriteASuccessfulPass(t *testing.T) {
	t.Parallel()
	const name = "notify-panics"
	mgr := &fakeManager{}
	notifier := &panicNotifier{}

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	handler := &recordLogHandler{}
	cfg := &config.Config{Certificates: []config.Certificate{{Name: name}}}
	r := New(cfg, spec.NewStatic(cfg.Certificates), store, mgr, notifier, slog.New(handler))

	before := reconcileCounts(t, name)

	if err := r.RunCert(context.Background(), name); err != nil {
		t.Errorf("the pass succeeded; the notifier's panic must not rewrite that, got %v", err)
	}
	if got := notifier.calls.Load(); got != 1 {
		t.Errorf("the notifier must be called exactly once -- a second call would be the "+
			"recover block contradicting the first, got %d", got)
	}
	if !handler.contains("renewal notification itself panicked") {
		t.Error("the swallowed panic must be logged with its stack, not vanish")
	}
	after := reconcileCounts(t, name)
	if after["ok"] != before["ok"]+1 {
		t.Errorf("the pass must count as ok exactly once, went from %v to %v", before["ok"], after["ok"])
	}
	if after["error"] != before["error"] {
		t.Errorf("a notifier panic must not count as a pass error, went from %v to %v",
			before["error"], after["error"])
	}
}

// hasNotAfterSeries reports whether the not_after gauge exports this exact
// cert+profile combination (ToFloat64 cannot answer this: reading a deleted child
// recreates it).
func hasNotAfterSeries(t *testing.T, cert, profile string) bool {
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
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["cert"] == cert && labels["profile"] == profile {
				return true
			}
		}
	}
	return false
}

// A certificate whose profile changed between passes must not keep the old profile's
// not_after series: nothing ever writes it again, so it freezes at its last value and
// the per-profile expiry alert keeps comparing a stale timestamp.
func TestPublishDropsTheSeriesOfAPreviousProfile(t *testing.T) {
	t.Parallel()
	const name = "profile-switch-cert"

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	prov := &mutableProvider{}
	prov.set(config.Certificate{Name: name})
	cfg := &config.Config{Certificates: []config.Certificate{{Name: name}}}
	r := New(cfg, prov, store, &fakeManager{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	notAfter := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	if err := store.PutCert(&state.CertState{Name: name, NotAfter: notAfter}); err != nil {
		t.Fatal(err)
	}

	r.publish(&config.Certificate{Name: name}) // no profile -> classic
	if !hasNotAfterSeries(t, name, config.ProfileClassic) {
		t.Fatal("setup: the classic profile series should be exported")
	}

	// The document switches the certificate to the shortlived profile.
	r.publish(&config.Certificate{Name: name, Profile: config.ProfileShortLived})

	if hasNotAfterSeries(t, name, config.ProfileClassic) {
		t.Error("the previous profile's series must be dropped, or it freezes at its last " +
			"value and the per-profile expiry alert compares a stale timestamp forever")
	}
	if !hasNotAfterSeries(t, name, config.ProfileShortLived) {
		t.Error("the current profile's series must be published")
	}
	if v, ok := gaugeValue(t, "wecert_certificate_not_after_timestamp_seconds", name); !ok || int64(v) != notAfter.Unix() {
		t.Errorf("the remaining series must carry the real expiry, got %v (present=%v)", v, ok)
	}
}

// signalOnResolveProvider closes ch on its first Desired call, so a test can observe
// that the caller passed the entry checks and is about to walk the names.
type signalOnResolveProvider struct {
	inner spec.Provider
	once  sync.Once
	ch    chan struct{}
}

func (p *signalOnResolveProvider) Desired(ctx context.Context) ([]config.Certificate, error) {
	p.once.Do(func() { close(p.ch) })
	return p.inner.Desired(ctx)
}

// When Drain begins mid-walk, StartNamed must still hand back the names it already
// accepted: those passes were registered and Drain waits for them, so reporting them as
// refused would tell the caller to give up on passes that are in fact running.
func TestStartNamedReturnsTheAcceptedPrefixWhenShutdownBeginsMidWalk(t *testing.T) {
	t.Parallel()
	certs := []config.Certificate{{Name: "a"}, {Name: "b"}}

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	mgr := &fakeManager{}
	prov := &signalOnResolveProvider{inner: spec.NewStatic(certs), ch: make(chan struct{})}
	cfg := &config.Config{Certificates: certs}
	r := New(cfg, prov, store, mgr, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	type outcome struct {
		started, running, unknown []string
		err                       error
	}
	out := make(chan outcome, 1)

	// Holding the claim mutex parks the walk inside the first startCert: after the
	// pass was registered with the drain group, before its goroutine launches.
	r.mu.Lock()
	go func() {
		started, running, unknown, err := r.StartNamed(context.Background(), []string{"a", "b"})
		out <- outcome{started, running, unknown, err}
	}()

	<-prov.ch                          // the walk has resolved and is heading into the first start
	time.Sleep(100 * time.Millisecond) // let it reach the parked claim

	drained := make(chan error, 1)
	go func() { drained <- r.Drain(context.Background()) }()

	deadline := time.Now().Add(2 * time.Second)
	for !r.drainingNow() {
		if time.Now().After(deadline) {
			r.mu.Unlock()
			t.Fatal("Drain never began")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Draining is set, so the second name can no longer be admitted; release the walk.
	r.mu.Unlock()

	got := <-out
	if !errors.Is(got.err, ErrShuttingDown) {
		t.Fatalf("want ErrShuttingDown, got %v", got.err)
	}
	if len(got.started) != 1 || got.started[0] != "a" {
		t.Errorf("the accepted prefix must come back with the error, got started=%v", got.started)
	}
	if len(got.running) != 0 || len(got.unknown) != 0 {
		t.Errorf("no other bucket may be filled, got running=%v unknown=%v", got.running, got.unknown)
	}

	// "a" was reported accepted, so its pass must really run and Drain must wait for it.
	if err := <-drained; err != nil {
		t.Errorf("Drain must wait for the accepted pass and then return clean, got %v", err)
	}
	if calls := mgr.reconciled(); len(calls) != 1 || calls[0] != "a" {
		t.Errorf("the accepted pass must have run (Drain waited for it), reconciled=%v", calls)
	}
}

// A panic in the work that runs AFTER the pass's answer has been decided must not change that
// answer.
//
// publish and probeCert are best-effort -- publish only mirrors state into Prometheus, and
// probeCert's own contract is "failing to reach a conclusion does not affect this pass". But
// they ran bare, so a panic in either unwound into reconcileOne's recover, which set err: a
// certificate that had just been renewed was reported as a FAILED pass (metrics said ok, the
// report said Failed) and `-once` exited non-zero for a certificate that was fine. That is a
// false alarm on the one channel whose whole point is to be believed.
func TestAPanicAfterASuccessfulPassDoesNotFailThePass(t *testing.T) {
	t.Parallel()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	const name = "renewed"
	if err := store.PutCert(&state.CertState{
		Name: name, DeployConfirmed: true, NotAfter: time.Now().Add(30 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{Certificates: []config.Certificate{{Name: name}}}
	r := New(cfg, spec.NewStatic(cfg.Certificates), store, &fakeManager{}, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	// publish reads the store unconditionally; a nil one panics the moment it is called, which
	// is exactly the "panic in the post-pass work" shape under test.
	r.store = nil

	before := testutil.ToFloat64(metrics.ReconcilePanics.WithLabelValues(name))

	if err := r.RunCert(context.Background(), name); err != nil {
		t.Errorf("a panic in the metric mirror must not fail a pass that renewed its certificate, "+
			"got err=%v", err)
	}

	if got := testutil.ToFloat64(metrics.ReconcilePanics.WithLabelValues(name)) - before; got != 1 {
		t.Errorf("the panic must still be counted (any nonzero wecert_reconcile_panics_total is a "+
			"bug), got %v", got)
	}
}

// SetProber used to write r.prober with no synchronization while convergence
// goroutines read it. The "must be called before the first convergence" contract has
// no enforcement; a late call is otherwise a data race under -race and a torn read
// without it.
func TestSetProberIsSafeAgainstConcurrentReads(t *testing.T) {
	t.Parallel()
	r := &Reconciler{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			_ = r.getProber()
		}
	}()
	r.SetProber(nil)
	r.SetProber(nil)
	<-done
}

// anyPassInFlight reports whether any certificate currently holds a convergence claim.
//
// A test helper: production code only ever asks this question with the probe record held
// (reclaimStaleProbeSeries snapshots the claim set under mu), so the standalone form lives
// here rather than as dead production code.
func (r *Reconciler) anyPassInFlight() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.running) > 0
}

// A panic in a pass-level epilogue step must be contained, not process-fatal.
//
// The epilogue (reaping retired certificates, the revocation retry, the probe-series sweep,
// the quota publication) runs outside reconcileOne's recover, and RunDetailed's caller -- the
// timer loop -- has no recover either. A panicking step is logged with its stack and the
// remaining steps still run; one bad step must not stop the rest of the bookkeeping any more
// than one bad certificate may stall the others.
func TestAPanickingPassEpilogueStepIsContained(t *testing.T) {
	mgr := &fakeManager{panicReap: true, pendingRevocations: 1}

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	handler := &recordLogHandler{}
	cfg := &config.Config{Certificates: []config.Certificate{{Name: "a"}}}
	r := New(cfg, spec.NewStatic(cfg.Certificates), store, mgr, nil, slog.New(handler))

	rep := r.RunDetailed(context.Background())
	if rep.Attempted != 1 || rep.Succeeded != 1 {
		t.Errorf("an epilogue panic must not change the pass's own answer, got %+v", rep)
	}
	if mgr.revocationRetries != 1 {
		t.Error("the step after the panicking one must still run")
	}
	if !handler.contains("panic in a pass epilogue step") {
		t.Error("the contained panic must be logged with its stack, not vanish")
	}
}

// The unreadable-source branch has its own epilogue -- retired certificates are still reaped
// and revocations still retried -- and it is outside reconcileOne's recover too.
func TestAPanickingEpilogueStepWithAnUnreadableSourceIsContained(t *testing.T) {
	mgr := &fakeManager{panicReap: true, pendingRevocations: 1}

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	handler := &recordLogHandler{}
	cfg := &config.Config{}
	r := New(cfg, failingProvider{err: errors.New("document service is down")}, store, mgr, nil,
		slog.New(handler))

	rep := r.RunDetailed(context.Background())
	if !rep.DesiredStateUnreadable {
		t.Error("the pass must still report the unreadable desired state")
	}
	if mgr.revocationRetries != 1 {
		t.Error("the step after the panicking one must still run")
	}
	if !handler.contains("panic in a pass epilogue step") {
		t.Error("the contained panic must be logged, not vanish")
	}
}

// The webhook path's quota publication runs deferred on the pass's background goroutine,
// past reconcileOne's recover: a panic there used to take the whole daemon down.
func TestAPanickingQuotaPublicationOnTheWebhookPathIsContained(t *testing.T) {
	mgr := &fakeManager{panicQuota: true}

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	handler := &recordLogHandler{}
	cfg := &config.Config{Certificates: []config.Certificate{{Name: "a"}}}
	r := New(cfg, spec.NewStatic(cfg.Certificates), store, mgr, nil, slog.New(handler))

	if err := r.StartCert(context.Background(), "a"); err != nil {
		t.Fatalf("StartCert: %v", err)
	}

	// The deferred publication runs before the claim is released (LIFO), so once no pass is
	// in flight and the quota counter is back at zero, the panicking publish has happened.
	deadline := time.Now().Add(5 * time.Second)
	for r.quotaPasses.Load() != 0 || r.anyPassInFlight() {
		if time.Now().After(deadline) {
			t.Fatal("the pass never finished")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !handler.contains("panic in a pass epilogue step") {
		t.Error("the contained panic must be logged with its stack, not vanish")
	}
	if calls := mgr.reconciled(); len(calls) != 1 || calls[0] != "a" {
		t.Errorf("the pass itself is unaffected by the epilogue panic, reconciled=%v", calls)
	}
}

// When Drain begins mid-walk, StartAll must hand back the names it already accepted, exactly
// like StartNamed: those passes were registered and Drain waits for them, so discarding the
// prefix reports a pass that is running as one that was refused.
func TestStartAllReturnsTheAcceptedPrefixWhenShutdownBeginsMidWalk(t *testing.T) {
	certs := []config.Certificate{{Name: "a"}, {Name: "b"}}

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	mgr := &fakeManager{}
	prov := &signalOnResolveProvider{inner: spec.NewStatic(certs), ch: make(chan struct{})}
	cfg := &config.Config{Certificates: certs}
	r := New(cfg, prov, store, mgr, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	type outcome struct {
		accepted, skipped []string
		err               error
	}
	out := make(chan outcome, 1)

	// Holding the claim mutex parks the walk inside the first startCert: after the pass was
	// registered with the drain group, before its goroutine launches.
	r.mu.Lock()
	go func() {
		accepted, skipped, err := r.StartAll(context.Background())
		out <- outcome{accepted, skipped, err}
	}()

	<-prov.ch                          // the walk has resolved and is heading into the first start
	time.Sleep(100 * time.Millisecond) // let it reach the parked claim

	drained := make(chan error, 1)
	go func() { drained <- r.Drain(context.Background()) }()

	deadline := time.Now().Add(2 * time.Second)
	for !r.drainingNow() {
		if time.Now().After(deadline) {
			r.mu.Unlock()
			t.Fatal("Drain never began")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Draining is set, so the second certificate can no longer be admitted; release the walk.
	r.mu.Unlock()

	got := <-out
	if !errors.Is(got.err, ErrShuttingDown) {
		t.Fatalf("want ErrShuttingDown, got %v", got.err)
	}
	if len(got.accepted) != 1 || got.accepted[0] != "a" {
		t.Errorf("the accepted prefix must come back with the error, got accepted=%v", got.accepted)
	}
	if len(got.skipped) != 0 {
		t.Errorf("nothing may be reported skipped, got skipped=%v", got.skipped)
	}

	// "a" was reported accepted, so its pass must really run and Drain must wait for it.
	if err := <-drained; err != nil {
		t.Errorf("Drain must wait for the accepted pass and then return clean, got %v", err)
	}
	if calls := mgr.reconciled(); len(calls) != 1 || calls[0] != "a" {
		t.Errorf("the accepted pass must have run (Drain waited for it), reconciled=%v", calls)
	}
}
