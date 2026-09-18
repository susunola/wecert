package state

import (
	"strings"
	"testing"
	"time"
)

// A nil bucket is an error, matching PutAuthorization.
//
// Silently accepting nil made a caller's bug -- a record that was never built -- indistinguishable
// from a write that landed, and the accounting this table exists for (see the RateBucket comment)
// only works if every reported write really happened.
func TestPutRateBucketRefusesANilBucket(t *testing.T) {
	s := openTestStore(t)

	err := s.PutRateBucket(nil)
	if err == nil {
		t.Fatal("a nil bucket must be refused: accepting it silently reports a write that never " +
			"happened, and rate-limit accounting built on that is optimistic exactly where it " +
			"must not be")
	}
	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("the error must say what was wrong, got: %v", err)
	}
}

// A real bucket still round-trips: the refusal above must not get in the way of the actual write.
func TestPutRateBucketRoundTrips(t *testing.T) {
	s := openTestStore(t)
	observed := time.Now().Truncate(time.Second)

	if err := s.PutRateBucket(&RateBucket{
		LimitName: "new-orders", ScopeID: "acct", Tokens: 3.5, ObservedAt: observed,
	}); err != nil {
		t.Fatalf("PutRateBucket: %v", err)
	}

	got, err := s.GetRateBucket("new-orders", "acct")
	if err != nil {
		t.Fatal(err)
	}
	if got.Tokens != 3.5 || !got.ObservedAt.Equal(observed) {
		t.Errorf("round trip = %+v, want tokens 3.5 observed at %v", got, observed)
	}
}
