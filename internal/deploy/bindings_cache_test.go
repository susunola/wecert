package deploy

import (
	"testing"
	"time"
)

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
