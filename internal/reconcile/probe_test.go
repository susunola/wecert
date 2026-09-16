package reconcile

import (
	"reflect"
	"testing"
)

// A wildcard has no address of its own to dial.
//
// Take the first N in declaration order, not randomly or lexicographically:
// declaration order puts the registered domain first, and that is usually the
// name most worth verifying.
func TestProbeHostsSkipsWildcardsInOrder(t *testing.T) {
	got := probeHosts([]string{"example.com", "*.example.com", "www.example.com", "api.example.com"}, 3)
	want := []string{"example.com", "www.example.com", "api.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("probeHosts = %v, want %v", got, want)
	}
}

// Not exhaustive: a 25-name certificate would mean 25 handshakes per pass,
// with diminishing returns and linear cost.
func TestProbeHostsRespectsTheCap(t *testing.T) {
	domains := []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com"}
	got := probeHosts(domains, 2)
	if len(got) != 2 || got[0] != "a.example.com" || got[1] != "b.example.com" {
		t.Errorf("probeHosts = %v, want the first two", got)
	}
}

// A certificate of nothing but wildcards has no dialable names — that should
// not error, there is simply nothing to verify.
func TestProbeHostsReturnsNothingForAWildcardOnlyCert(t *testing.T) {
	if got := probeHosts([]string{"*.example.com", "*.api.example.com"}, 3); len(got) != 0 {
		t.Errorf("wildcards should not be dialed, got %v", got)
	}
}

// A cap of 0 means "off", to pause probing temporarily during an
// investigation.
func TestProbeHostsHandlesAZeroCap(t *testing.T) {
	if got := probeHosts([]string{"example.com"}, 0); got != nil {
		t.Errorf("with a cap of 0 nothing should be dialed, got %v", got)
	}
}
