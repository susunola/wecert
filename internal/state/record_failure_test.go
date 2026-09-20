package state

import (
	"testing"
	"time"
)

// The failure path may be holding a CertState synthesised from a failed read, so
// recording a failure must never overwrite the certificate currently in service.
// This is the regression test for "a failed renewal wiped the private key out of
// the state database": only the three bookkeeping columns may move.
func TestRecordFailureKeepsCertificateMaterial(t *testing.T) {
	s := openTestStore(t)

	notAfter := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	full := &CertState{
		Name:           "example-com",
		NotAfter:       notAfter,
		CertURL:        "https://acme-v02.api.letsencrypt.org/acme/cert/123",
		CertPEM:        []byte("fullchain"),
		KeyPEM:         []byte("privkey"),
		IssuedAt:       time.Now().Truncate(time.Second),
		ARICertID:      "abc.def",
		DeployedCertID: "TencentCertId123",
	}
	if err := s.PutCert(full); err != nil {
		t.Fatalf("PutCert failed: %v", err)
	}

	nextAttempt := time.Now().Add(5 * time.Minute).Truncate(time.Second)
	if err := s.RecordFailure("example-com", "acme: rate limited", 4, nextAttempt); err != nil {
		t.Fatalf("RecordFailure failed: %v", err)
	}

	got, err := s.GetCert("example-com")
	if err != nil {
		t.Fatalf("GetCert failed: %v", err)
	}
	if got.ConsecutiveFailures != 4 {
		t.Errorf("ConsecutiveFailures = %d, want 4", got.ConsecutiveFailures)
	}
	if got.LastError != "acme: rate limited" {
		t.Errorf("LastError = %q, want %q", got.LastError, "acme: rate limited")
	}
	if !got.NextAttemptAt.Equal(nextAttempt) {
		t.Errorf("NextAttemptAt = %s, want %s", got.NextAttemptAt, nextAttempt)
	}

	// Everything RecordFailure must not touch.
	if string(got.CertPEM) != "fullchain" || string(got.KeyPEM) != "privkey" {
		t.Errorf("cert/key material was overwritten: %q / %q", got.CertPEM, got.KeyPEM)
	}
	if !got.NotAfter.Equal(notAfter) {
		t.Errorf("NotAfter = %s, want %s", got.NotAfter, notAfter)
	}
	if got.CertURL != full.CertURL {
		t.Errorf("CertURL = %q, want %q", got.CertURL, full.CertURL)
	}
	if got.ARICertID != "abc.def" {
		t.Errorf("ARICertID = %q, want abc.def", got.ARICertID)
	}
	if got.DeployedCertID != "TencentCertId123" {
		t.Errorf("DeployedCertID = %q, want TencentCertId123", got.DeployedCertID)
	}
}

// A certificate that fails on its very first issuance has no row yet; recording
// the failure must create one so the backoff survives a restart, with the
// certificate material columns left empty.
func TestRecordFailureInsertsAMissingRow(t *testing.T) {
	s := openTestStore(t)

	nextAttempt := time.Now().Add(2 * time.Minute).Truncate(time.Second)
	if err := s.RecordFailure("fresh", "dns: propagation timeout", 1, nextAttempt); err != nil {
		t.Fatalf("RecordFailure failed: %v", err)
	}

	got, err := s.GetCert("fresh")
	if err != nil {
		t.Fatalf("GetCert failed: %v", err)
	}
	if got == nil {
		t.Fatal("the failure row was not created")
	}
	if got.ConsecutiveFailures != 1 {
		t.Errorf("ConsecutiveFailures = %d, want 1", got.ConsecutiveFailures)
	}
	if got.LastError != "dns: propagation timeout" {
		t.Errorf("LastError = %q", got.LastError)
	}
	if !got.NextAttemptAt.Equal(nextAttempt) {
		t.Errorf("NextAttemptAt = %s, want %s", got.NextAttemptAt, nextAttempt)
	}
	if len(got.CertPEM) != 0 || len(got.KeyPEM) != 0 {
		t.Errorf("a failure-only row must carry no cert material, got %q / %q", got.CertPEM, got.KeyPEM)
	}
	if !got.NotAfter.IsZero() {
		t.Errorf("NotAfter should be zero on a failure-only row, got %s", got.NotAfter)
	}
}

// Recording the same failure twice is what a retried pass does: the second call
// must land the same state, not a second row or a doubled count.
func TestRecordFailureIsIdempotent(t *testing.T) {
	s := openTestStore(t)

	nextAttempt := time.Now().Add(5 * time.Minute).Truncate(time.Second)
	for i := 0; i < 3; i++ {
		if err := s.RecordFailure("example-com", "acme: rate limited", 4, nextAttempt); err != nil {
			t.Fatalf("RecordFailure call %d failed: %v", i, err)
		}
	}

	got, err := s.GetCert("example-com")
	if err != nil {
		t.Fatal(err)
	}
	if got.ConsecutiveFailures != 4 || got.LastError != "acme: rate limited" ||
		!got.NextAttemptAt.Equal(nextAttempt) {
		t.Errorf("repeated identical RecordFailure calls drifted: %+v", got)
	}

	names, err := s.ListCertNames()
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "example-com" {
		t.Errorf("want exactly one row, got %v", names)
	}
}

// A failure recorded for a row that could not be read carries a lower bound ("at least one
// failure: this one"), so it must not erase the count and the backoff already on disk.
//
// Regression: RecordFailure overwrote both columns. A certificate that had failed eight times
// straight -- and so earned a 6-hour backoff and was one failure away from the failure fallback
// (ConsecutiveFailures >= 5) -- went back to 1 the moment one pass could not read its row. The
// backoff collapsed to the base window and the fallback, which needs the count to reach its
// threshold, could never fire for it: the certificate that most needed degrading was the one
// that never could. And an unreadable row is precisely the condition this path exists for.
func TestRecordFailureNeverLowersTheCountOrTheBackoff(t *testing.T) {
	s := openTestStore(t)
	// Eight failures straight: the row carries the 6-hour backoff they earned.
	earned := time.Now().Add(6 * time.Hour).Truncate(time.Second)
	if err := s.PutCert(&CertState{Name: "example-com", ConsecutiveFailures: 8, NextAttemptAt: earned}); err != nil {
		t.Fatalf("PutCert failed: %v", err)
	}
	stored, err := s.GetCert("example-com")
	if err != nil {
		t.Fatalf("GetCert failed: %v", err)
	}
	storedBackoff := stored.NextAttemptAt
	if storedBackoff.IsZero() {
		t.Fatal("the fixture needs a backoff on disk; without one there is nothing to preserve")
	}

	// What recordFailureUnreadable sends when the row cannot be read: count 1, base window.
	lower := time.Now().Add(time.Minute).Truncate(time.Second)
	if err := s.RecordFailure("example-com", "state: read failed", 1, lower); err != nil {
		t.Fatalf("RecordFailure failed: %v", err)
	}

	got, err := s.GetCert("example-com")
	if err != nil {
		t.Fatalf("GetCert failed: %v", err)
	}
	if got.ConsecutiveFailures != 8 {
		t.Errorf("ConsecutiveFailures = %d, want 8: a lower bound must not lower the stored count",
			got.ConsecutiveFailures)
	}
	if !got.NextAttemptAt.Equal(storedBackoff) {
		t.Errorf("NextAttemptAt = %s, want the stored %s: a shorter window must not replace it",
			got.NextAttemptAt, storedBackoff)
	}
	// The error itself is this pass's news, so it is overwritten whatever the counters did.
	if got.LastError != "state: read failed" {
		t.Errorf("LastError = %q, want the newest error", got.LastError)
	}

	// A genuinely worse failure still raises both.
	higher := time.Now().Add(6 * time.Hour).Truncate(time.Second)
	if err := s.RecordFailure("example-com", "state: read failed again", 9, higher); err != nil {
		t.Fatalf("RecordFailure failed: %v", err)
	}
	got, err = s.GetCert("example-com")
	if err != nil {
		t.Fatalf("GetCert failed: %v", err)
	}
	if got.ConsecutiveFailures != 9 || !got.NextAttemptAt.Equal(higher) {
		t.Errorf("ConsecutiveFailures = %d and NextAttemptAt = %s, want 9 and %s: MAX must still "+
			"let the counters grow", got.ConsecutiveFailures, got.NextAttemptAt, higher)
	}
}

// A recovered pass clears the counters, so merging with MAX cannot strand a stale backoff
// after the certificate is healthy again.
func TestRecordFailureDoesNotSurviveARecovery(t *testing.T) {
	s := openTestStore(t)
	if err := s.PutCert(&CertState{Name: "example-com", ConsecutiveFailures: 3}); err != nil {
		t.Fatalf("PutCert failed: %v", err)
	}
	if err := s.RecordFailure("example-com", "state: read failed", 1, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("RecordFailure failed: %v", err)
	}

	// The success path is a whole-row upsert that carries the cleared counters.
	if err := s.PutCert(&CertState{Name: "example-com", ConsecutiveFailures: 0, NextAttemptAt: time.Time{}}); err != nil {
		t.Fatalf("PutCert failed: %v", err)
	}
	got, err := s.GetCert("example-com")
	if err != nil {
		t.Fatalf("GetCert failed: %v", err)
	}
	if got.ConsecutiveFailures != 0 || !got.NextAttemptAt.IsZero() {
		t.Errorf("after a recovery: ConsecutiveFailures = %d, NextAttemptAt = %s, want both clear",
			got.ConsecutiveFailures, got.NextAttemptAt)
	}
}
