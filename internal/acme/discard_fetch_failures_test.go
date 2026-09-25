package acme

import (
	"context"
	"testing"

	"github.com/susunola/wecert/internal/state"
)

// The fetch-failure counter is keyed by order URL, and a discarded order's URL is dead for
// good -- so discarding must forget the count. Otherwise every discarded URL stranded its
// entry for the rest of the process (a slow leak), and the entry kept claiming "this URL has
// been failing" for an order that no longer exists.
func TestDiscardOrderForgetsTheFetchFailures(t *testing.T) {
	store, m, _, cert := newAPITestHarness(t, []string{"example.com"})

	const orderURL = "https://ca.test/order/dead"
	if err := store.PutOrder(&state.Order{
		CertName: cert.Name, OrderURL: orderURL, Status: "pending",
	}); err != nil {
		t.Fatal(err)
	}
	// Two fetch failures, below the discard threshold, so the entry is still live.
	m.noteOrderFetchFailure(orderURL)
	m.noteOrderFetchFailure(orderURL)

	if err := m.discardOrder(context.Background(), cert.Name); err != nil {
		t.Fatalf("discardOrder: %v", err)
	}

	m.orderFetchMu.Lock()
	_, stuck := m.orderFetchFails[orderURL]
	m.orderFetchMu.Unlock()
	if stuck {
		t.Errorf("the discarded order's fetch failures must be forgotten; the counter still holds %q", orderURL)
	}
	if o, err := store.GetOrder(cert.Name); err != nil || o != nil {
		t.Fatalf("the order itself must be gone (order=%+v err=%v)", o, err)
	}
}
