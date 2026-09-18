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
