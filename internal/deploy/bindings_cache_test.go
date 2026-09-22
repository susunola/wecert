package deploy

import (
	"fmt"
	"testing"
	"time"
)

// The cache is keyed by certID and certificates rotate. Without a ceiling, a long-lived
// daemon keeps one BindingSnapshot (with its Items slice) per certificate it has ever
// seen. The write path sweeps expired entries and then evicts the oldest until it fits.
func TestBindingMemoIsBounded(t *testing.T) {
	t.Cleanup(func() {
		bindingMemoStore.mu.Lock()
		bindingMemoStore.byID = map[string]cachedBindings{}
		bindingMemoStore.mu.Unlock()
	})
	bindingMemoStore.mu.Lock()
	bindingMemoStore.byID = map[string]cachedBindings{}
	bindingMemoStore.mu.Unlock()

	for i := 0; i < bindingMemoMaxEntries+100; i++ {
		rememberBindings(fmt.Sprintf("cert-%04d", i), BindingSnapshot{})
	}

	bindingMemoStore.mu.Lock()
	n := len(bindingMemoStore.byID)
	bindingMemoStore.mu.Unlock()
	if n > bindingMemoMaxEntries {
		t.Errorf("the memo grew to %d entries, want at most %d", n, bindingMemoMaxEntries)
	}
}

// A parse older than the TTL is a miss, not a stale answer about a certificate whose
// bindings may have been deleted out-of-band.
func TestBindingMemoExpires(t *testing.T) {
	t.Cleanup(func() {
		bindingMemoStore.mu.Lock()
		bindingMemoStore.byID = map[string]cachedBindings{}
		bindingMemoStore.mu.Unlock()
	})

	rememberBindings("cert-1", BindingSnapshot{})
	bindingMemoStore.mu.Lock()
	hit := bindingMemoStore.byID["cert-1"]
	hit.at = time.Now().Add(-bindingMemoTTL - time.Minute)
	bindingMemoStore.byID["cert-1"] = hit
	bindingMemoStore.mu.Unlock()

	if _, _, ok := LookupCachedBindings("cert-1"); ok {
		t.Error("an entry past its TTL must be a miss")
	}
	bindingMemoStore.mu.Lock()
	_, still := bindingMemoStore.byID["cert-1"]
	bindingMemoStore.mu.Unlock()
	if still {
		t.Error("the expired entry must be dropped on lookup, not just ignored")
	}
}

// ForgetBindings drops the snapshot of a certificate that has been deleted.
func TestForgetBindings(t *testing.T) {
	t.Cleanup(func() {
		bindingMemoStore.mu.Lock()
		bindingMemoStore.byID = map[string]cachedBindings{}
		bindingMemoStore.mu.Unlock()
	})

	rememberBindings("cert-1", BindingSnapshot{})
	ForgetBindings("cert-1")
	if _, _, ok := LookupCachedBindings("cert-1"); ok {
		t.Error("ForgetBindings must drop the entry")
	}
}

func TestLookupCachedBindingsRoundTrip(t *testing.T) {
	before := time.Now()
	rememberBindings("cYk-cache", BindingSnapshot{
		Count: 1, Complete: true,
		Items: []BindingRow{{ResourceType: "clb", LoadBalancerID: "lb-x", ListenerID: "lbl-y", Complete: true}},
	})
	after := time.Now()

	snap, at, ok := LookupCachedBindings("cYk-cache")
	if !ok || snap.Count != 1 || snap.Items[0].LoadBalancerID != "lb-x" {
		t.Fatalf("%v %+v", ok, snap)
	}
	// The returned time must be the observation instant of the remember call,
	// not the lookup instant and not the zero time.
	if at.IsZero() {
		t.Fatal("a cache hit must carry its observation time")
	}
	if at.Before(before) || at.After(after) {
		t.Fatalf("observation time %s outside [%s, %s]", at, before, after)
	}
}

func TestLookupCachedBindingsMissHasZeroTime(t *testing.T) {
	if _, at, ok := LookupCachedBindings("missing"); ok || !at.IsZero() {
		t.Fatalf("miss must return the zero time: %v %s", ok, at)
	}
	if _, at, ok := LookupCachedBindings(""); ok || !at.IsZero() {
		t.Fatalf("empty id must return the zero time: %v %s", ok, at)
	}
}
