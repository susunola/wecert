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

// fn may spend and annotate, but the bucket's identity is not its to move: writing the mutated
// key back would silently INSERT a second row (the conflict target no longer matches the row that
// was read), leaving the real bucket unspent and the local estimate optimistic.
func TestUpdateRateBucketRefusesARetargetedKey(t *testing.T) {
	s := openTestStore(t)
	observed := time.Now().Truncate(time.Second)

	if err := s.PutRateBucket(&RateBucket{
		LimitName: "new-orders", ScopeID: "acct", Tokens: 3.5, ObservedAt: observed,
	}); err != nil {
		t.Fatalf("PutRateBucket: %v", err)
	}

	err := s.UpdateRateBucket("new-orders", "acct", func(b *RateBucket) error {
		b.Tokens = 2
		b.LimitName = "certificates" // a bug, not a spend
		return nil
	})
	if err == nil {
		t.Fatal("fn moving the bucket's key must be refused, not written as a new row")
	}
	if !strings.Contains(err.Error(), "identity") {
		t.Errorf("the refusal should say what fn did wrong, got: %v", err)
	}

	// The real bucket is untouched, and no second row appeared under the mutated key.
	got, err := s.GetRateBucket("new-orders", "acct")
	if err != nil {
		t.Fatal(err)
	}
	if got.Tokens != 3.5 {
		t.Errorf("the refused update must not have landed, tokens = %v want 3.5", got.Tokens)
	}
	scopes, err := s.ListRateBucketScopes("certificates")
	if err != nil {
		t.Fatal(err)
	}
	if len(scopes) != 0 {
		t.Errorf("the mutated key must not exist as a row, got %v", scopes)
	}
}
