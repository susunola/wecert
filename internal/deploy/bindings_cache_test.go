package deploy

import "testing"

func TestLookupCachedBindingsRoundTrip(t *testing.T) {
	rememberBindings("cYk-cache", BindingSnapshot{
		Count: 1, Complete: true,
		Items: []BindingRow{{ResourceType: "clb", LoadBalancerID: "lb-x", ListenerID: "lbl-y", Complete: true}},
	})
	snap, ok := LookupCachedBindings("cYk-cache")
	if !ok || snap.Count != 1 || snap.Items[0].LoadBalancerID != "lb-x" {
		t.Fatalf("%v %+v", ok, snap)
	}
	if _, ok := LookupCachedBindings("missing"); ok {
		t.Fatal("missing id must not hit")
	}
}
