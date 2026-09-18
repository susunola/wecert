package state

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// A recorded attempt lands on the request it names: the counter moves and the reason is kept.
func TestRecordRevokeAttemptCountsTheAttemptAndRemembersWhy(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()

	if err := s.AddRevokeRequest("example-com", 1, "identity-1", now); err != nil {
		t.Fatalf("AddRevokeRequest: %v", err)
	}
	if err := s.RecordRevokeAttempt("example-com", errors.New("ca returned 503"), now); err != nil {
		t.Fatalf("RecordRevokeAttempt: %v", err)
	}

	req, err := s.GetRevokeRequest("example-com")
	if err != nil {
		t.Fatal(err)
	}
	if req == nil {
		t.Fatal("the request itself must be untouched by recording an attempt against it")
	}
	if req.Attempts != 1 {
		t.Errorf("attempts = %d, want 1", req.Attempts)
	}
	if !strings.Contains(req.LastError, "ca returned 503") {
		t.Errorf("the failure reason must be kept, got %q", req.LastError)
	}
}

// An attempt recorded against a name with no outstanding request is an error, not a silent
// success.
//
// An UPDATE that matches no row still "succeeds" as far as SQLite is concerned, so without the
// RowsAffected check the caller believed an attempt was tracked when there was no request to
// track it against -- and the operator's pending-revocation view stayed empty while the caller
// thought otherwise.
func TestRecordRevokeAttemptWithoutARequestIsAnError(t *testing.T) {
	s := openTestStore(t)

	err := s.RecordRevokeAttempt("no-such-cert", errors.New("ca returned 503"), time.Now())
	if err == nil {
		t.Fatal("recording an attempt against a name with no request must be refused: the update " +
			"matched nothing, and reporting success claims the attempt was tracked when it was not")
	}
	if !strings.Contains(err.Error(), "no-such-cert") {
		t.Errorf("the error must name the certificate, got: %v", err)
	}

	reqs, err := s.ListRevokeRequests()
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 0 {
		t.Errorf("a refused attempt must not conjure a request row, got %+v", reqs)
	}
}
