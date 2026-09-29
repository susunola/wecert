package acme

import (
	"strings"
	"testing"
)

// A wedged provider call keeps legoResolverMu until it really returns (lego's
// dns01.recursiveNameservers is package-level and is re-read during the call).
// The next acquirer must fail fast as "busy" instead of queueing behind it.
func TestLegoResolverSlotFailsFastWhenHeld(t *testing.T) {
	legoResolverMu.Lock()
	defer legoResolverMu.Unlock()
	err := acquireLegoResolver()
	if err == nil {
		t.Fatal("a held resolver slot must not be acquired")
	}
	if !strings.Contains(err.Error(), "busy") {
		t.Errorf("the error must say the provider is busy, got: %v", err)
	}
}
