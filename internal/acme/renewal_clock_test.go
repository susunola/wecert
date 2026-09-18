package acme

import (
	"context"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"

	"github.com/susunola/wecert/internal/state"
)

// Renewal time boundaries, driven by the clock seam instead of by editing the state database.
//
// The recorded position (docs/lifecycle-acceptance.md section 7, docs/test-plan.md sections 6 and
// 10) is that renewal boundaries were "always triggered by editing the state DB, never by moving
// the clock" -- moving the system clock would distort TLS, the journal and every Retry-After at
// once. What the corpus does have is a manager-level clock seam (SetNow) and tests for one backward
// step (TestABackwardClockStepDoesNotSilenceTheBindingCheck). These cases ask what that seam can
// cover and cover it:
//
//  1. a certificate whose renewal window opens BETWEEN passes (the DB needs no edit at all: the
//     window is a function of the clock, and that is the whole point);
//  2. a clock that steps BACKWARDS between passes -- the renewal instant must not move with it, and
//     must not be treated as "not yet due" for a negative elapsed time;
//  3. a clock that steps FORWARD past notAfter -- the certificate is expired, and the pass must
//     still renew rather than wedge.
//
// What none of this covers, and what still needs a real clock: anything where the process must keep
// running while wall time passes (TLS session lifetimes, the journal's own timestamps, a CA's
// Retry-After arriving as an HTTP-date, the six-hour ARI polling floor actually elapsing). The seam
// moves one function's answer; it does not move time.

// placedOrders counts orders the fake CA was asked to create.
func placedOrders(fake *fakeAPI) int {
	n := 0
	for _, call := range fake.calls {
		if len(call) >= 8 && call[:8] == "NewOrder" {
			n++
		}
	}
	return n
}

// A renewal window that opens between two passes is a pure clock function: no state edit.
func TestTheRenewalWindowOpensBetweenPasses(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})

	// Well outside the 30-day window of the classic profile: notAfter - renewBefore is 40 days out.
	base := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	notAfter := base.Add(70 * 24 * time.Hour)
	m.SetNow(func() time.Time { return base })
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: notAfter,
		CertPEM: selfSignedCertPEM(t, notAfter, "example.com"),
	}); err != nil {
		t.Fatal(err)
	}
	st, err := store.GetCert(cert.Name)
	if err != nil || st == nil {
		t.Fatalf("GetCert: %v %+v", err, st)
	}
	renewAt, _, ariErr := m.renewalDecision(context.Background(), cert, st)
	if ariErr != nil {
		t.Fatalf("renewalDecision: %v", ariErr)
	}
	if !renewAt.After(base) {
		t.Fatalf("fixture: the window must not be open yet, renewAt=%s now=%s", renewAt, base)
	}

	// Pass 1, one second before the window opens: no order.
	m.SetNow(func() time.Time { return renewAt.Add(-time.Second) })
	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile before the window: %v", err)
	}
	if got := placedOrders(fake); got != 0 {
		t.Fatalf("an order placed %s before the window opened (%d orders)", time.Second, got)
	}

	// Pass 2, one second after -- same state row, no DB edit, only the clock.
	fake.orders = []legoacme.ExtendedOrder{terminalOrder(
		"https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/1")}
	m.SetNow(func() time.Time { return renewAt.Add(time.Second) })
	_ = m.Reconcile(context.Background(), cert)
	if got := placedOrders(fake); got != 1 {
		t.Fatalf("the window is open at %s (renewAt=%s), so exactly one order belongs here, got %d",
			renewAt.Add(time.Second), renewAt, got)
	}
}

// A backward clock step must not postpone a renewal that is already due.
//
// This is the time-based half of the same class as TestABackwardClockStepDoesNotSilenceTheBindingCheck:
// that one pins the binding-lookup interval, this one pins the renewal instant. The saved window is
// absolute (it is stored as an instant), so stepping the clock back one hour must leave renewAt
// where it was -- and once the clock reaches it again the renewal must happen on that same pass,
// not one hour later.
func TestABackwardClockStepDoesNotPostponeARenewalThatIsDue(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})

	base := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	notAfter := base.Add(10 * 24 * time.Hour) // inside the 30-day window
	m.SetNow(func() time.Time { return base })
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: notAfter,
		CertPEM: selfSignedCertPEM(t, notAfter, "example.com"),
	}); err != nil {
		t.Fatal(err)
	}
	st, err := store.GetCert(cert.Name)
	if err != nil || st == nil {
		t.Fatalf("GetCert: %v %+v", err, st)
	}
	dueAt, _, ariErr := m.renewalDecision(context.Background(), cert, st)
	if ariErr != nil {
		t.Fatalf("renewalDecision: %v", ariErr)
	}
	if dueAt.After(base) {
		t.Fatalf("fixture: the renewal is already due, got renewAt=%s now=%s", dueAt, base)
	}

	// The clock steps back an hour. The renewal is still due (the instant did not move), and a
	// negative elapsed time must not read as "recently decided".
	m.SetNow(func() time.Time { return base.Add(-time.Hour) })
	fake.orders = []legoacme.ExtendedOrder{terminalOrder(
		"https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/1")}
	_ = m.Reconcile(context.Background(), cert)
	if got := placedOrders(fake); got != 1 {
		t.Fatalf("a backward clock step must not postpone a due renewal, got %d orders", got)
	}
}

// A clock that jumps past notAfter must still renew rather than wedge.
//
// An expired certificate is the end state of every failure this program has: a renewal that could
// not complete for the length of the window leaves a row whose notAfter is in the past. RFC 9773
// section 4.3 forbids asking ARI about an expired certificate, so the decision has to fall back to
// the deterministic schedule and STILL be due -- and the row must not be treated as "decided
// already" because a future-dated instant was stored before the clock jumped.
func TestAClockStepPastNotAfterStillRenews(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})

	base := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	notAfter := base.Add(10 * 24 * time.Hour)
	m.SetNow(func() time.Time { return base })
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: notAfter,
		CertPEM: selfSignedCertPEM(t, notAfter, "example.com"),
		// An ARI lookup was done and stored before the clock jumped, so the expiry path has to
		// overrule it rather than being throttled by it.
		ARICertID:    "ari-id",
		ARICheckedAt: base.Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	// The clock jumps a month forward: the certificate has been expired for three weeks.
	m.SetNow(func() time.Time { return notAfter.Add(21 * 24 * time.Hour) })
	fake.orders = []legoacme.ExtendedOrder{terminalOrder(
		"https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/1")}
	_ = m.Reconcile(context.Background(), cert)

	if got := placedOrders(fake); got != 1 {
		t.Fatalf("an expired certificate is overdue for renewal, so exactly one order belongs here, got %d", got)
	}
	if fake.renewalInfoHits != 0 {
		t.Errorf("an expired certificate must not be the subject of a renewalInfo request, got %d",
			fake.renewalInfoHits)
	}
}
