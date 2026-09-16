package acme

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/state"
)

// A revocation the CA does not accept must survive as a durable request.
//
// Revocation is unbounded in time: a leaked private key does not stop being leaked because the
// CA returned a 503. If this only attempted the revoke and reported the failure, the operator
// would be left believing the certificate was revoked when it was not -- the most dangerous way
// for this particular action to be wrong.
func TestFailedRevocationIsRecordedAndRetried(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return fixed })

	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: fixed.Add(30 * 24 * time.Hour),
		CertPEM: selfSignedCertPEM(t, fixed.Add(30*24*time.Hour), "example.com"),
	}); err != nil {
		t.Fatal(err)
	}

	// The CA is unreachable for now.
	fake.revokeErr = errors.New("acme: error: 503 :: service unavailable")

	err := m.RequestRevocation(context.Background(), cert.Name, RevocationReasons["keyCompromise"])
	if err == nil {
		t.Fatal("a failed revocation must be reported, not silently reported as done")
	}

	// The decision is recorded, so the daemon can finish the job.
	req, err := store.GetRevokeRequest(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if req == nil {
		t.Fatal("a revocation that failed must leave a durable request; otherwise the operator " +
			"believes a compromised certificate was revoked when it was not")
	}
	if req.Reason != RevocationReasons["keyCompromise"] {
		t.Errorf("the operator's reason must be preserved, got %d", req.Reason)
	}
	if req.Attempts == 0 {
		t.Error("the failed attempt must be counted, so 'has this been failing for a week' is answerable")
	}
	if !m.HasPendingRevocations() {
		t.Error("the pass gate must see the outstanding request")
	}

	// The CA comes back, and the next pass finishes it.
	fake.revokeErr = nil
	m.RetryPendingRevocations(context.Background())

	if len(fake.revoked) != 2 {
		t.Fatalf("expected two revoke attempts (the failed one and the retry), got %d", len(fake.revoked))
	}
	if fake.revoked[1].Reason != RevocationReasons["keyCompromise"] {
		t.Errorf("the retry must carry the operator's reason, got %d", fake.revoked[1].Reason)
	}
	req, err = store.GetRevokeRequest(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if req != nil {
		t.Errorf("an accepted revocation must clear the request, still have %+v", req)
	}
	if m.HasPendingRevocations() {
		t.Error("nothing should be pending after the CA accepted")
	}
}

// The certificate sent to the CA must be the DER of the stored leaf, not the PEM bundle.
//
// The protocol field is base64url(DER); sending PEM text would be a malformed request, and
// sending the whole bundle would revoke the wrong element -- it is the leaf that is revoked.
func TestRevocationSendsTheStoredLeaf(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return fixed })

	leaf := selfSignedCertPEM(t, fixed.Add(30*24*time.Hour), "example.com")
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: fixed.Add(30 * 24 * time.Hour), CertPEM: leaf,
	}); err != nil {
		t.Fatal(err)
	}

	if err := m.RequestRevocation(context.Background(), cert.Name, 0); err != nil {
		t.Fatalf("RequestRevocation: %v", err)
	}
	if len(fake.revoked) != 1 {
		t.Fatalf("expected one revoke call, got %d", len(fake.revoked))
	}
	der, err := leafDER(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if fake.revoked[0].DERLen != len(der) {
		t.Errorf("sent %d bytes of DER, want the stored leaf's %d -- sending the PEM bundle "+
			"would be a malformed request", fake.revoked[0].DERLen, len(der))
	}
	// Reason 0 must be omitted rather than sent explicitly: the CA then omits the CRL entry
	// extension, which is the difference between "unspecified" and "reason=0".
	if fake.revoked[0].Reason != 0 {
		t.Errorf("reason 0 must be passed through as unspecified, got %d", fake.revoked[0].Reason)
	}
}

// Revoking a certificate wecert has no material for must say so rather than silently succeed.
//
// Without the stored PEM there is nothing to revoke with. Reporting success would be a lie
// about a security action; the error names the way out instead.
func TestRevocationWithoutStoredMaterialIsRefused(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})

	// A row with no certificate material: uploaded or planned, never issued.
	if err := store.PutCert(&state.CertState{Name: cert.Name}); err != nil {
		t.Fatal(err)
	}

	err := m.RequestRevocation(context.Background(), cert.Name, 1)
	if err == nil {
		t.Fatal("there is nothing to revoke without the stored certificate")
	}
	if len(fake.revoked) != 0 {
		t.Error("no revoke call belongs here")
	}
	// And the message has to point somewhere useful.
	if got := err.Error(); !contains(got, "revoke it at the CA") {
		t.Errorf("the error should say what to do instead, got %q", got)
	}
}

// An unknown certificate must not create a request that can never complete.
func TestRevocationOfAnUnknownCertificateIsRefused(t *testing.T) {
	_, m, fake, _ := newAPITestHarness(t, []string{"example.com"})

	if err := m.RequestRevocation(context.Background(), "no-such-cert", 1); err == nil {
		t.Fatal("revoking an unknown certificate must be refused")
	}
	if len(fake.revoked) != 0 {
		t.Error("no revoke call belongs here")
	}
}

// An unknown reason code must be refused up front, not sent and rejected by the CA.
func TestRevocationRejectsAnUnknownReason(t *testing.T) {
	store, m, _, cert := newAPITestHarness(t, []string{"example.com"})
	_ = store.PutCert(&state.CertState{Name: cert.Name, CertPEM: selfSignedCertPEM(t, time.Now().Add(time.Hour), "example.com")})

	if err := m.RequestRevocation(context.Background(), cert.Name, 99); err == nil {
		t.Fatal("an unknown RFC 5280 reason code must be refused before contacting the CA")
	}
}

// The pass gate must not query when nothing is outstanding: this runs on every pass.
func TestPendingRevocationsGate(t *testing.T) {
	store, m, _, cert := newAPITestHarness(t, []string{"example.com"})
	if m.HasPendingRevocations() {
		t.Fatal("a fresh store has nothing pending")
	}
	if err := store.AddRevokeRequest(cert.Name, 1, time.Now()); err != nil {
		t.Fatal(err)
	}
	if !m.HasPendingRevocations() {
		t.Error("a recorded request must be visible to the pass gate")
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 || indexOfStr(haystack, needle) >= 0)
}

func indexOfStr(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
