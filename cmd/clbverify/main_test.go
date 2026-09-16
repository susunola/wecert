package main

import (
	"strings"
	"testing"
)

// The empty-listener failure must fit how the query was made: an unfiltered query that
// comes back empty means the CLB has no listeners, but a filtered one means *that
// listener* matched nothing (deleted, or a typo) -- blaming the CLB then sends the
// operator debugging the wrong object.
func TestNoListenersError(t *testing.T) {
	plain := noListenersError("lb-abc", "")
	if !strings.Contains(plain.Error(), "CLB lb-abc has no listeners") {
		t.Errorf("unfiltered wording = %q, want the CLB blamed", plain)
	}

	filtered := noListenersError("lb-abc", "lbl-xyz")
	if !strings.Contains(filtered.Error(), "lbl-xyz") || !strings.Contains(filtered.Error(), "deleted") {
		t.Errorf("filtered wording = %q, want the listener ID named with the deleted/typo hint", filtered)
	}
	if strings.Contains(filtered.Error(), "has no listeners") {
		t.Errorf("filtered wording = %q, must not claim the whole CLB is empty", filtered)
	}
}
