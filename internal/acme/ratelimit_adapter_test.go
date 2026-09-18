package acme

import (
	"reflect"
	"testing"

	"github.com/susunola/wecert/internal/ratelimit"
	"github.com/susunola/wecert/internal/state"
)

// The adapter translates between state.RateBucket and ratelimit.BucketRecord with named field
// literals, which still compile when either side gains a field -- and silently drop it on the
// floor. The translation is only faithful while the two field sets are identical, so pin the
// sets themselves: name and count, both directions.
func TestRateBucketAdapterStructsStayFieldForFieldIdentical(t *testing.T) {
	fieldSet := func(v any) map[string]bool {
		typ := reflect.TypeOf(v)
		out := make(map[string]bool, typ.NumField())
		for i := 0; i < typ.NumField(); i++ {
			out[typ.Field(i).Name] = true
		}
		return out
	}
	fromStore := fieldSet(state.RateBucket{})
	fromTracker := fieldSet(ratelimit.BucketRecord{})

	if len(fromStore) != len(fromTracker) {
		t.Errorf("state.RateBucket has %d fields, ratelimit.BucketRecord has %d: rateBucketAdapter "+
			"copies field by field, so the difference is silently dropped at the boundary",
			len(fromStore), len(fromTracker))
	}
	for name := range fromStore {
		if !fromTracker[name] {
			t.Errorf("state.RateBucket.%s has no counterpart in ratelimit.BucketRecord; "+
				"rateBucketAdapter would drop it in both directions", name)
		}
	}
	for name := range fromTracker {
		if !fromStore[name] {
			t.Errorf("ratelimit.BucketRecord.%s has no counterpart in state.RateBucket; "+
				"rateBucketAdapter would drop it in both directions", name)
		}
	}
}
