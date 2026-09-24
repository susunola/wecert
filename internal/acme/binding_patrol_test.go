package acme

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/deploy"
)

type countingPatroller struct {
	deploy.Deployer
	calls atomic.Int32
}

func (c *countingPatroller) PatrolBindings(_ context.Context, _ []deploy.KnownCert) ([]deploy.PatrolFinding, error) {
	c.calls.Add(1)
	return []deploy.PatrolFinding{{Kind: deploy.PatrolDrift, CertName: "www", CertID: "id"}}, nil
}

// The account-wide patrol is throttled: a second call inside the window does not
// hit the API again (the wrap-up runs every pass; this must not).
func TestPatrolBindingsIsThrottled(t *testing.T) {
	p := &countingPatroller{}
	m, store := newTestManager(t, &fakeSolver{}, fakeKeyAuth{})
	m.deployer = p
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return now })
	_ = store

	counts, err := m.PatrolBindings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if counts[string(deploy.PatrolDrift)] != 1 {
		t.Fatalf("counts = %v", counts)
	}
	if p.calls.Load() != 1 {
		t.Fatalf("first call should hit the API, got %d", p.calls.Load())
	}
	if _, err := m.PatrolBindings(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p.calls.Load() != 1 {
		t.Fatalf("second call inside the window must not hit the API, got %d", p.calls.Load())
	}
	// Past the window it runs again.
	m.SetNow(func() time.Time { return now.Add(bindingPatrolEvery + time.Minute) })
	if _, err := m.PatrolBindings(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p.calls.Load() != 2 {
		t.Fatalf("call past the window must hit the API, got %d", p.calls.Load())
	}
}
