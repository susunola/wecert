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

// Re-asking for a revocation whose target certificate CHANGED (a renewal replaced the material
// under the same name, and the operator asked again) is a new decision: the attempts and the error
// on file describe tries at revoking the OLD material and say nothing about this one.
func TestReRequestingRevokeForDifferentMaterialResetsTheAttemptLedger(t *testing.T) {
	s := openTestStore(t)
	now := time.Now()

	if err := s.AddRevokeRequest("example-com", 1, "identity-1", now); err != nil {
		t.Fatalf("AddRevokeRequest: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := s.RecordRevokeAttempt("example-com", errors.New("ca returned 503"), now); err != nil {
			t.Fatalf("RecordRevokeAttempt: %v", err)
		}
	}

	// Asking again for the SAME certificate keeps the ledger: it is the same decision restated.
	if err := s.AddRevokeRequest("example-com", 1, "identity-1", now.Add(time.Minute)); err != nil {
		t.Fatalf("AddRevokeRequest (same identity): %v", err)
	}
	req, err := s.GetRevokeRequest("example-com")
	if err != nil {
		t.Fatal(err)
	}
	if req.Attempts != 3 || req.LastError == "" || req.LastAttemptAt.IsZero() {
		t.Errorf("re-asking for the same certificate must keep the attempt ledger, got %+v", req)
	}

	// Asking for DIFFERENT material resets it -- and keeps the original RequestedAt, because
	// "how long has a request for this name been outstanding" is still the number an operator
	// needs.
	if err := s.AddRevokeRequest("example-com", 4, "identity-2", now.Add(2*time.Minute)); err != nil {
		t.Fatalf("AddRevokeRequest (new identity): %v", err)
	}
	req, err = s.GetRevokeRequest("example-com")
	if err != nil {
		t.Fatal(err)
	}
	if req.CertIdentity != "identity-2" || req.Reason != 4 {
		t.Errorf("the refresh must retarget the request, got %+v", req)
	}
	if req.Attempts != 0 || req.LastError != "" || !req.LastAttemptAt.IsZero() {
		t.Errorf("a request for different material must not inherit the old certificate's "+
			"failures, got %+v", req)
	}
	if !req.RequestedAt.Equal(now.Truncate(time.Second)) {
		t.Errorf("RequestedAt must survive every refresh, got %v want %v",
			req.RequestedAt, now.Truncate(time.Second))
	}
}
