package ratelimit

import (
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// fakeStore is an in-memory bucketStore.
type fakeStore struct {
	mu      sync.Mutex
	rows    map[string]*BucketRecord
	getErr  error
	putErr  error
	putSeen int
}

func newFakeStore() *fakeStore { return &fakeStore{rows: map[string]*BucketRecord{}} }

func key(limit, scope string) string { return limit + "\x00" + scope }

// UpdateRateBucket mirrors the real store: the whole read-modify-write happens under one lock, so
// two callers cannot both read the same token count. Get and Put stay individually atomic, which
// is exactly why a tracker doing Get...Put loses updates.
func (f *fakeStore) UpdateRateBucket(limit, scope string, fn func(*BucketRecord) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.getErr != nil {
		return f.getErr
	}
	rec := &BucketRecord{LimitName: limit, ScopeID: scope}
	if r, ok := f.rows[key(limit, scope)]; ok {
		cp := *r
		rec = &cp
	}
	if err := fn(rec); err != nil {
		return err
	}
	if f.putErr != nil {
		return f.putErr
	}
	cp := *rec
	f.rows[key(limit, scope)] = &cp
	f.putSeen++
	return nil
}

func (f *fakeStore) GetRateBucket(limit, scope string) (*BucketRecord, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if r, ok := f.rows[key(limit, scope)]; ok {
		cp := *r
		return &cp, nil
	}
	// A missing row is "never recorded", which the tracker must treat as a full bucket.
	return &BucketRecord{LimitName: limit, ScopeID: scope}, nil
}

func (f *fakeStore) PutRateBucket(r *BucketRecord) error {
	if f.putErr != nil {
		return f.putErr
	}
	f.putSeen++
	cp := *r
	f.rows[key(r.LimitName, r.ScopeID)] = &cp
	return nil
}

func testTracker(t *testing.T, st bucketStore, now time.Time) *Tracker {
	t.Helper()
	return NewTracker(st, slog.New(slog.NewTextHandler(io.Discard, nil)), func() time.Time { return now })
}

func TestTrackerAccumulatesSpendAcrossRestarts(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	store := newFakeStore()

	// A fresh process must see what the previous one spent: that is the whole reason the
	// bucket is persisted rather than kept in memory.
	for i := 0; i < 3; i++ {
		testTracker(t, store, now).Spend(NewOrdersPerAccount, "", 1)
	}

	// A brand-new tracker (a restart) reads the same bucket.
	left, ok := testTracker(t, store, now).Remaining(NewOrdersPerAccount, "")
	if !ok {
		t.Fatal("remaining should be readable")
	}
	if want := NewOrdersPerAccount.Capacity - 3; left != want {
		t.Errorf("after 3 orders across restarts: %v left, want %v", left, want)
	}
}

func TestTrackerRemainingIsFullBeforeAnythingIsSpent(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	left, ok := testTracker(t, newFakeStore(), now).Remaining(NewOrdersPerAccount, "")
	if !ok {
		t.Fatal("remaining should be readable")
	}
	if left != NewOrdersPerAccount.Capacity {
		t.Errorf("an unspent limit must read full, got %v", left)
	}
}

func TestTrackerNotesTheCAsOwnDeadline(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	store := newFakeStore()
	tr := testTracker(t, store, now)

	msg := "acme: error: 429 :: urn:ietf:params:acme:error:rateLimited :: " +
		"too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, " +
		"retry after 2026-09-23 04:00:00 UTC"

	at, ok := tr.NoteRetryAfter(CertsPerExactIdentifierSet, "a.example.com|b.example.com", msg)
	if !ok {
		t.Fatal("the documented message must yield a deadline")
	}
	want := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)
	if !at.Equal(want) {
		t.Errorf("deadline = %s, want %s", at, want)
	}

	// The deadline governs the estimate: the local count cannot see other accounts spending
	// the same global bucket, so it must not report quota that the CA has already refused.
	if left, ok := tr.Remaining(CertsPerExactIdentifierSet, "a.example.com|b.example.com"); !ok || left != 0 {
		t.Errorf("a reported deadline must read as 0 remaining, got %v (ok=%v)", left, ok)
	}

	// And it must be visible as a deadline, with the limit named.
	got, reason, blocked := tr.BlockedUntil(CertsPerExactIdentifierSet, "a.example.com|b.example.com")
	if !blocked || !got.Equal(want) || reason != CertsPerExactIdentifierSet.Name {
		t.Errorf("blocked = %v until %s (%s), want until %s", blocked, got, reason, want)
	}

	// A different scope is unaffected: the deadline belongs to the bucket that was exhausted.
	if _, _, blocked := tr.BlockedUntil(CertsPerExactIdentifierSet, "other.example.com"); blocked {
		t.Error("a deadline must not leak to another scope")
	}
}

func TestTrackerDeadlineDoesNotEraseTheEstimate(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	store := newFakeStore()
	tr := testTracker(t, store, now)

	tr.Spend(NewOrdersPerAccount, "", 5)
	at := now.Add(time.Hour)
	if err := store.PutRateBucket(&BucketRecord{
		LimitName: NewOrdersPerAccount.Name, Tokens: NewOrdersPerAccount.Capacity - 5, ObservedAt: now,
		ResetAt: at, ResetReason: NewOrdersPerAccount.Name,
	}); err != nil {
		t.Fatal(err)
	}

	// A later spend must not wipe the deadline: the two facts have different lifetimes and
	// the deadline is the stronger one.
	tr.Spend(NewOrdersPerAccount, "", 1)
	rec := store.rows[key(NewOrdersPerAccount.Name, "")]
	if !rec.ResetAt.Equal(at) {
		t.Errorf("the CA-reported deadline was erased by a spend: %s, want %s", rec.ResetAt, at)
	}
}

func TestTrackerAccountingFailuresAreNotFatal(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

	// A store that cannot read or write must not make Spend panic or block a renewal:
	// accounting is not allowed to be the reason issuance fails.
	broken := &fakeStore{rows: map[string]*BucketRecord{}, getErr: errors.New("disk full")}
	testTracker(t, broken, now).Spend(NewOrdersPerAccount, "", 1)

	brokenPut := &fakeStore{rows: map[string]*BucketRecord{}, putErr: errors.New("disk full")}
	testTracker(t, brokenPut, now).Spend(NewOrdersPerAccount, "", 1)

	if _, ok := testTracker(t, broken, now).Remaining(NewOrdersPerAccount, ""); ok {
		t.Error("an unreadable bucket must report not-ok rather than a made-up number")
	}
}

func TestNilTrackerIsInert(t *testing.T) {
	// Callers that have no store (diagnostics binaries, tests) must not need special cases.
	var tr *Tracker
	tr.Spend(NewOrdersPerAccount, "", 1)
	if _, ok := tr.Remaining(NewOrdersPerAccount, ""); ok {
		t.Error("a nil tracker must not report a value")
	}
	if at, ok := tr.NoteRetryAfter(NewOrdersPerAccount, "", "retry after 2026-01-01 00:00:00 UTC"); ok {
		t.Errorf("a nil tracker must not record, got %s", at)
	}
}

func TestSummarizeSkipsLimitsWithoutAScope(t *testing.T) {
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	tr := testTracker(t, newFakeStore(), now)
	tr.Spend(NewOrdersPerAccount, "", 2)

	// Only the account scope is supplied, so the per-domain limits are reported as unknown
	// rather than as full -- claiming "50 left" for a domain we know nothing about would be
	// the same class of lie as exporting 0 for a missing expiry.
	lines := tr.Summarize(nil)
	if len(lines) != 1 {
		t.Fatalf("expected only the account-wide limit, got %v", lines)
	}

	lines = tr.Summarize(map[string]string{"registered-domain": "example.com"})
	if len(lines) != 2 {
		t.Fatalf("expected the account-wide limit plus the supplied scope, got %v", lines)
	}
}

// Concurrent spends on one bucket must all count.
//
// The manager reconciles one goroutine per certificate and every one of them spends on the SAME
// account-scoped bucket. A read-modify-write through Get then Put loses updates in exactly that
// shape -- the certificate path hit the same bug ("a run of 50 concurrent GetCert/++/PutCert
// cycles landed as 3") and fixed it with UpdateCert -- and the local estimate is what keeps the
// fleet under the CA's limits, including the one with no override path.
func TestConcurrentSpendsOnOneBucketAllCount(t *testing.T) {
	store := newFakeStore()
	tr := testTracker(t, store, time.Now())

	const spenders = 32
	var wg sync.WaitGroup
	for i := 0; i < spenders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr.Spend(NewOrdersPerAccount, "", 1)
		}()
	}
	wg.Wait()

	rec, err := store.GetRateBucket(NewOrdersPerAccount.Name, "")
	if err != nil {
		t.Fatal(err)
	}
	want := NewOrdersPerAccount.Capacity - spenders
	if rec.Tokens != want {
		t.Errorf("after %d concurrent spends the bucket holds %v tokens, want %v: %d spend(s) were "+
			"lost to a read-modify-write race, so the estimate is optimistic about a limit that "+
			"blocks every certificate on the account",
			spenders, rec.Tokens, want, int(want-rec.Tokens))
	}
}
