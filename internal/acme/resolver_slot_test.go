package acme

import (
	"strings"
	"testing"
	"time"
)

// A wedged provider call used to keep legoResolverMu inside the bounded helper
// goroutine: the caller timed out, but every later Present/CleanUp queued on the
// package mutex. The slot must fail fast as "busy" instead.
func TestLegoResolverSlotFailsFastWhenHeld(t *testing.T) {
	legoResolverMu.Lock()
	defer legoResolverMu.Unlock()
	start := time.Now()
	err := acquireLegoResolver(50 * time.Millisecond)
	if err == nil {
		t.Fatal("a held resolver slot must not be acquired")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("acquire took %s, want a fast busy answer", time.Since(start))
	}
	if !strings.Contains(err.Error(), "busy") {
		t.Errorf("the error must say the provider is busy, got: %v", err)
	}
}
