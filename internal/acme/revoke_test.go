package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/ratelimit"
	"github.com/susunola/wecert/internal/state"

	legoacme "github.com/go-acme/lego/v4/acme"
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

	// This error is the "it is recorded, the CA has not accepted yet" kind, so a caller may tell
	// the operator the request is queued and will be retried.
	if errors.Is(err, ErrRevocationNotRecorded) {
		t.Errorf("the request WAS recorded, so this must not be reported as \"nothing was recorded\": %v", err)
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
	if n, err := m.PendingRevocations(); err != nil || n != 1 {
		t.Errorf("the pass gate must see the outstanding request, got (%d, %v)", n, err)
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
	if n, err := m.PendingRevocations(); err != nil || n != 0 {
		t.Errorf("nothing should be pending after the CA accepted, got (%d, %v)", n, err)
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
	// Nothing reached the store, so no later pass will retry this: the CLI has to be able to tell
	// that apart from the recorded case, or it tells an operator acting on a key compromise that
	// the revocation is queued.
	if !errors.Is(err, ErrRevocationNotRecorded) {
		t.Errorf("this failure recorded nothing, so it must match ErrRevocationNotRecorded: %v", err)
	}
}

// An unknown certificate must not create a request that can never complete.
func TestRevocationOfAnUnknownCertificateIsRefused(t *testing.T) {
	_, m, fake, _ := newAPITestHarness(t, []string{"example.com"})

	if err := m.RequestRevocation(context.Background(), "no-such-cert", 1); err == nil {
		t.Fatal("revoking an unknown certificate must be refused")
	} else if !errors.Is(err, ErrRevocationNotRecorded) {
		t.Errorf("an unknown certificate records nothing, so it must match ErrRevocationNotRecorded: %v", err)
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
	} else if !errors.Is(err, ErrRevocationNotRecorded) {
		t.Errorf("a rejected reason records nothing, so it must match ErrRevocationNotRecorded: %v", err)
	}
}

// PendingRevocations is both the retry gate and the source of wecert_revocation_pending, so it has
// to count exactly -- and it has to refuse to answer at all when the store cannot be read.
func TestPendingRevocationsCountsAndRefusesToGuess(t *testing.T) {
	store, m, _, cert := newAPITestHarness(t, []string{"example.com"})
	if n, err := m.PendingRevocations(); err != nil || n != 0 {
		t.Fatalf("a fresh store has nothing pending, got (%d, %v)", n, err)
	}
	if err := store.AddRevokeRequest(cert.Name, 1, "", time.Now()); err != nil {
		t.Fatal(err)
	}
	if n, err := m.PendingRevocations(); err != nil || n != 1 {
		t.Errorf("a recorded request must be visible to the pass gate, got (%d, %v)", n, err)
	}

	// Zero is a meaningful answer here, so an unreadable store must not be able to produce it.
	// The reconciler publishes this count as wecert_revocation_pending, where 0 is the all-clear
	// that says no certificate is waiting to stop being trusted.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	n, err := m.PendingRevocations()
	if err == nil {
		t.Errorf("an unreadable store must report an error rather than a count; got %d with no "+
			"error, which the reconciler would publish as an all-clear", n)
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

// "Already revoked" is the desired state, so the request must be cleared, not retried forever.
//
// ClearRevokeRequest only runs on success, so an alreadyRevoked answer left the row outstanding:
// wecert_revocation_pending stayed >= 1 and the critical WecertRevocationPending alert never
// cleared, every pass re-attempted the revocation, and `wecert -revoke` kept telling the operator
// that a certificate the CA had already revoked "will be retried". The code's own comment called
// that retry harmless; it is not.
func TestAlreadyRevokedIsTerminalAndClearsTheRequest(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return fixed })

	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: fixed.Add(30 * 24 * time.Hour),
		CertPEM: selfSignedCertPEM(t, fixed.Add(30*24*time.Hour), "example.com"),
	}); err != nil {
		t.Fatal(err)
	}
	// The CA answers with the registered problem type, as lego hands it back.
	fake.revokeErr = &legoacme.ProblemDetails{
		Type:   "urn:ietf:params:acme:error:alreadyRevoked",
		Detail: "Certificate already revoked",
	}

	if err := m.RequestRevocation(context.Background(), cert.Name, RevocationReasons["keyCompromise"]); err != nil {
		t.Fatalf("an already-revoked certificate is the desired state, not a failure to report: %v", err)
	}
	req, err := store.GetRevokeRequest(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if req != nil {
		t.Errorf("the request row must be cleared, or the pending gauge and its CRITICAL alert stay "+
			"up forever and every pass retries: %+v", req)
	}

	// A plain failure is still retryable: the row stays and the error surfaces.
	fake.revokeErr = errors.New("acme: error: 503 :: service unavailable")
	if err := m.RequestRevocation(context.Background(), cert.Name, RevocationReasons["keyCompromise"]); err == nil {
		t.Fatal("a transport failure must still be reported")
	}
	if again, err := store.GetRevokeRequest(cert.Name); err != nil || again == nil {
		t.Errorf("a retryable failure must leave the request outstanding (req=%+v err=%v)", again, err)
	}
}

// certPEMWithSerial issues a self-signed certificate with a chosen serial, so a test can hold two
// certificates for one name that are tellable apart -- which is the whole question a revocation
// request outliving a renewal turns on. The shared helper always uses serial 1.
func certPEMWithSerial(t *testing.T, serial int64, dnsNames ...string) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "test"},
		DNSNames:              dnsNames,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(30 * 24 * time.Hour),
		AuthorityKeyId:        []byte{0x01, 0x02, 0x03},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("issue test certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// leafIdentity is certIdentity of the stored PEM, for assertions.
func leafIdentity(t *testing.T, certPEM []byte) string {
	t.Helper()
	leaf, err := leafCertificate(certPEM)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return certIdentity(leaf)
}

// A revocation that outlives a renewal must revoke the certificate it was asked about.
//
// The request is durable, so its retry can land after a renewal has replaced the material stored
// under the name -- and reconcile retries revocations AFTER the certificate loop, so the same pass
// can install a new certificate and then revoke it. The retry used to read the current
// certificates.cert_pem, which is now the new certificate: it revoked that, cleared the row as a
// success, and left the compromised certificate valid -- the exact opposite of what the operator
// asked for, on the one action where being wrong is unrecoverable.
func TestARetryThatOutlivesARenewalRevokesTheArchivedCertificate(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return fixed })

	oldCert := certPEMWithSerial(t, 1001, "example.com")
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: fixed.Add(30 * 24 * time.Hour), CertPEM: oldCert,
	}); err != nil {
		t.Fatal(err)
	}

	// The operator asks while the compromised certificate is the one stored, and the CA is down,
	// so the request stays outstanding.
	fake.revokeErr = errors.New("acme: error: 503 :: service unavailable")
	if err := m.RequestRevocation(context.Background(), cert.Name, RevocationReasons["keyCompromise"]); err == nil {
		t.Fatal("the CA refused the revocation, so this must report a failure")
	}
	req, err := store.GetRevokeRequest(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if req == nil {
		t.Fatal("the request must be recorded")
	}
	if req.CertIdentity != leafIdentity(t, oldCert) {
		t.Fatalf("the request must record which certificate it is about: got %q, want the stored "+
			"leaf's identity %q", req.CertIdentity, leafIdentity(t, oldCert))
	}

	// A renewal happens: the new certificate is stored, and the old one is archived (this is what
	// the deploy path does with the material it takes out of service).
	newCert := certPEMWithSerial(t, 2002, "example.com")
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: fixed.Add(90 * 24 * time.Hour), CertPEM: newCert,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddRetiredCert("cloud-cert-1", cert.Name, oldCert, nil); err != nil {
		t.Fatal(err)
	}

	// The CA comes back. The retry belongs to the old certificate.
	fake.revokeErr = nil
	m.RetryPendingRevocations(context.Background())

	if len(fake.revoked) != 2 {
		t.Fatalf("expected the failed attempt and its retry, got %d calls", len(fake.revoked))
	}
	wantDER, err := leafDER(oldCert)
	if err != nil {
		t.Fatal(err)
	}
	wrongDER, err := leafDER(newCert)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fake.revoked[1].DER, wantDER) {
		t.Errorf("the retry revoked the wrong certificate: it sent %d bytes, and the certificate "+
			"asked about is %d bytes (the newly issued one is %d). Revoking the live certificate "+
			"leaves the compromised one valid and destroys coverage that was fine",
			len(fake.revoked[1].DER), len(wantDER), len(wrongDER))
	}
	if again, err := store.GetRevokeRequest(cert.Name); err != nil || again != nil {
		t.Errorf("the CA accepted the revocation of the certificate asked about, so the request is "+
			"done (req=%+v err=%v)", again, err)
	}
	if n, err := m.PendingRevocations(); err != nil || n != 0 {
		t.Errorf("nothing should be pending afterwards, got (%d, %v)", n, err)
	}
}

// When the archived copy is gone the retry must not fall back to the live certificate.
//
// Retention reclaims retired material, so "the certificate asked about is not here any more" is a
// real outcome. The one thing that must not happen then is revoking the replacement: it is valid,
// it is serving traffic, and the compromised certificate would stay valid. The request stays
// outstanding instead, which is what keeps wecert_revocation_pending and its alert up.
func TestAReplacementIsNeverRevokedInPlaceOfTheRequestedCertificate(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return fixed })

	oldCert := certPEMWithSerial(t, 1001, "example.com")
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: fixed.Add(30 * 24 * time.Hour), CertPEM: oldCert,
	}); err != nil {
		t.Fatal(err)
	}
	fake.revokeErr = errors.New("acme: error: 503 :: service unavailable")
	if err := m.RequestRevocation(context.Background(), cert.Name, RevocationReasons["keyCompromise"]); err == nil {
		t.Fatal("the CA refused the revocation, so this must report a failure")
	}

	// A renewal, and the retired row holds no material (the orphan path records exactly this: a
	// certificate wecert uploaded and never held a copy of).
	newCert := certPEMWithSerial(t, 2002, "example.com")
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: fixed.Add(90 * 24 * time.Hour), CertPEM: newCert,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddRetiredCert("cloud-cert-1", cert.Name, nil, nil); err != nil {
		t.Fatal(err)
	}

	fake.revokeErr = nil
	m.RetryPendingRevocations(context.Background())

	if len(fake.revoked) != 1 {
		t.Fatalf("only the first, failed attempt belongs here: the replacement certificate must "+
			"never be sent in place of the one asked about, got %d calls", len(fake.revoked))
	}
	req, err := store.GetRevokeRequest(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if req == nil {
		t.Fatal("the request must stay outstanding: the certificate asked about has not been revoked")
	}
	if req.Attempts < 2 {
		t.Errorf("the failed retry must be counted, got %d attempts", req.Attempts)
	}
	if !contains(req.LastError, "revoked at the CA") {
		t.Errorf("the operator has to be told what is left to do, got last_error %q", req.LastError)
	}
}

// A request recorded before identities were stored must still be honoured.
//
// Empty means "unknown", not "mismatch". Refusing on unknown would strand every request written by
// an older build: the row could never be cleared, wecert_revocation_pending would stay up for a
// certificate that may well have been revoked, and the operator's only way out would be editing
// the database.
func TestARequestWithoutAnIdentityRevokesTheStoredCertificate(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return fixed })

	stored := certPEMWithSerial(t, 1001, "example.com")
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: fixed.Add(30 * 24 * time.Hour), CertPEM: stored,
	}); err != nil {
		t.Fatal(err)
	}
	// As an older build wrote it: no identity column at all.
	if err := store.AddRevokeRequest(cert.Name, RevocationReasons["superseded"], "", fixed); err != nil {
		t.Fatal(err)
	}

	m.RetryPendingRevocations(context.Background())

	if len(fake.revoked) != 1 {
		t.Fatalf("expected one revoke call, got %d", len(fake.revoked))
	}
	wantDER, err := leafDER(stored)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fake.revoked[0].DER, wantDER) {
		t.Error("a request with no recorded identity revokes the material stored under the name")
	}
	if req, err := store.GetRevokeRequest(cert.Name); err != nil || req != nil {
		t.Errorf("the CA accepted it, so the request is done (req=%+v err=%v)", req, err)
	}
}

// Asking again after a renewal is a decision about the certificate stored now.
//
// The identity has to travel with the reason on that refresh, otherwise the second request would
// silently keep pointing at a certificate the operator is no longer asking about -- and a name
// whose certificate is replaced twice would never get its current one revoked.
func TestAskingAgainAfterARenewalTargetsTheCertificateStoredNow(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return fixed })

	oldCert := certPEMWithSerial(t, 1001, "example.com")
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: fixed.Add(30 * 24 * time.Hour), CertPEM: oldCert,
	}); err != nil {
		t.Fatal(err)
	}
	fake.revokeErr = errors.New("acme: error: 503 :: service unavailable")
	if err := m.RequestRevocation(context.Background(), cert.Name, RevocationReasons["keyCompromise"]); err == nil {
		t.Fatal("the CA refused the revocation, so this must report a failure")
	}

	newCert := certPEMWithSerial(t, 2002, "example.com")
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: fixed.Add(90 * 24 * time.Hour), CertPEM: newCert,
	}); err != nil {
		t.Fatal(err)
	}

	// The operator asks again, now about the certificate that is stored.
	fake.revokeErr = nil
	if err := m.RequestRevocation(context.Background(), cert.Name, RevocationReasons["superseded"]); err != nil {
		t.Fatalf("RequestRevocation: %v", err)
	}

	if len(fake.revoked) != 2 {
		t.Fatalf("expected the failed attempt and the new request, got %d calls", len(fake.revoked))
	}
	wantDER, err := leafDER(newCert)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fake.revoked[1].DER, wantDER) {
		t.Error("the second request is about the certificate stored now, and that is the one it must revoke")
	}
	if req, err := store.GetRevokeRequest(cert.Name); err != nil || req != nil {
		t.Errorf("the CA accepted it, so the request is done (req=%+v err=%v)", req, err)
	}
}

// A request can also be honoured from the archive when no material is stored at all.
//
// The name does not always keep its certificate row: an onboarding or re-plan pass can rewrite it
// with no material, and a request recorded while the certificate was stored must not become
// unanswerable because of that. The archive still holds what the operator asked about, so that is
// what is sent -- and with no identity recorded there is nothing to look for, which is the one case
// that keeps the old refusal.
func TestARequestIsHonouredFromTheArchiveWhenNothingIsStored(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return fixed })

	stored := certPEMWithSerial(t, 1001, "example.com")
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: fixed.Add(30 * 24 * time.Hour), CertPEM: stored,
	}); err != nil {
		t.Fatal(err)
	}
	fake.revokeErr = errors.New("acme: error: 503 :: service unavailable")
	if err := m.RequestRevocation(context.Background(), cert.Name, RevocationReasons["keyCompromise"]); err == nil {
		t.Fatal("the CA refused the revocation, so this must report a failure")
	}

	// The row loses its material, and the certificate moves to the archive.
	if err := store.PutCert(&state.CertState{Name: cert.Name}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddRetiredCert("cloud-cert-1", cert.Name, stored, nil); err != nil {
		t.Fatal(err)
	}

	fake.revokeErr = nil
	m.RetryPendingRevocations(context.Background())

	if len(fake.revoked) != 2 {
		t.Fatalf("the retry belongs here and must send the archived certificate, got %d calls",
			len(fake.revoked))
	}
	wantDER, err := leafDER(stored)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fake.revoked[1].DER, wantDER) {
		t.Error("the archived copy of the certificate asked about is what must be revoked")
	}
	if req, err := store.GetRevokeRequest(cert.Name); err != nil || req != nil {
		t.Errorf("the CA accepted it, so the request is done (req=%+v err=%v)", req, err)
	}

	// With no identity and nothing stored there is still nothing to send, and saying so is the
	// only honest answer: the request stays outstanding rather than being cleared as a success.
	if err := store.AddRevokeRequest(cert.Name, RevocationReasons["superseded"], "", fixed); err != nil {
		t.Fatal(err)
	}
	m.RetryPendingRevocations(context.Background())
	if len(fake.revoked) != 2 {
		t.Error("there is no certificate to send, so no revoke call belongs here")
	}
	if req, err := store.GetRevokeRequest(cert.Name); err != nil || req == nil {
		t.Errorf("a request that could not be honoured must stay outstanding (req=%+v err=%v)", req, err)
	}
}

// A failed ARI decision must schedule the retry, not just stop the round.
//
// The guard that refuses to renew when the decision itself failed was returning the bare error.
// The write that failed is the one carrying ARICheckedAt, and that column is the ONLY thing
// throttling the ARI call: with the store broken, every pass re-queried renewalInfo for every
// certificate -- the exact loop renewalDecision's default branch exists to avoid. recordFailure
// adds the backoff it could not persist, which is what a broken state store still costs.
func TestAFailedARIDecisionSchedulesItsOwnBackoff(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return fixed })

	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: fixed.Add(30 * 24 * time.Hour),
		CertPEM: selfSignedCertPEM(t, fixed.Add(30*24*time.Hour), "example.com"),
		// An ARI check is due, and the store dies while ARI is answering -- so the write that
		// records ARICheckedAt is the one that fails.
		ARICertID: "aki.serial",
	}); err != nil {
		t.Fatal(err)
	}
	fake.beforeCall = func(call string) {
		if call == "GetRenewalInfo" {
			_ = store.Close()
		}
	}

	if err := m.Reconcile(context.Background(), cert); err == nil {
		t.Fatal("the decision could not be made, so the pass must report a failure")
	}
	if _, ok := m.transientBackoffFor(cert.Name); !ok {
		t.Error("a failed ARI decision must schedule a retry: without one, every pass re-queries the " +
			"CA's renewalInfo for every certificate until the state store recovers")
	}
}

// A cancelled pass is not a business failure, and must not cost a backoff window.
//
// This is the other half of the same guard: the ARI decision returns the context error when the
// pass is shutting down, and recording that as a failure would lock the certificate out of the
// next window for a stop signal. recordFailure filters it; a bare return trivially "passed" this,
// which is why the fix has to keep it.
func TestACancelledPassDoesNotSetABackoff(t *testing.T) {
	store, m, _, cert := newAPITestHarness(t, []string{"example.com"})
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return fixed })

	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: fixed.Add(30 * 24 * time.Hour),
		CertPEM: selfSignedCertPEM(t, fixed.Add(30*24*time.Hour), "example.com"),
	}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := m.Reconcile(ctx, cert)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("a stopped pass must report the cancellation, got %v", err)
	}
	if _, ok := m.transientBackoffFor(cert.Name); ok {
		t.Error("a stop signal must not schedule a business backoff: after a restart the certificate " +
			"would be locked out of the window it should have been renewed in")
	}
}

// The new-order spend must follow the attempt that actually created the order.
//
// A renewal whose `replaces` the CA refuses is retried without it, and the retry is what creates
// the order. Accounting ran on the first call alone, so that order was never counted: the
// published lower bound (which gates the fleet against "300 new orders per account per 3 hours")
// was optimistic by one, in the one flow that places orders in bursts -- every renewal that hits a
// CA which will not honour the stored ARI certID.
func TestTheNewOrderSpendFollowsTheAttemptThatCreatedTheOrder(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"a.example.com"})
	now := m.now()

	// The ARI window is in the past and was checked just now, so renewal is due and the order
	// carries the stored certID as `replaces`.
	if err := store.PutCert(&state.CertState{
		Name:           cert.Name,
		NotAfter:       now.Add(20 * 24 * time.Hour),
		ARICertID:      "YWJj.ZGVm",
		ARIWindowStart: now.Add(-2 * time.Hour),
		ARIWindowEnd:   now.Add(-time.Hour),
		ARICheckedAt:   now,
	}); err != nil {
		t.Fatal(err)
	}

	// The first attempt is refused and the retry succeeds. The order sequence converges, so the
	// pass does not sit in the state machine's polling loop.
	fake.newOrderErr = errors.New("ACME error: replaces is not honoured for this order")
	fake.orders = []legoacme.ExtendedOrder{
		{
			Order:    legoacme.Order{Status: "pending", Finalize: "https://ca.test/finalize/1"},
			Location: "https://ca.test/order/1",
		},
		terminalOrder("https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/1"),
	}

	_ = m.Reconcile(context.Background(), cert)

	if got := len(fake.newOrderReplaces); got != 2 {
		t.Fatalf("expected the refused replaces attempt and the retry, got %d NewOrder call(s): %v",
			got, fake.newOrderReplaces)
	}
	if fake.newOrderReplaces[1] != "" {
		t.Fatalf("the retry must drop replaces, got %q", fake.newOrderReplaces[1])
	}

	bucket, err := store.GetRateBucket(ratelimit.NewOrdersPerAccount.Name, "")
	if err != nil {
		t.Fatal(err)
	}
	if want := ratelimit.NewOrdersPerAccount.Capacity - 1; bucket.Tokens != want {
		t.Errorf("the order the retry created must be counted: tokens=%v want %v. An order that is "+
			"not counted makes the published lower bound -- the number an operator trusts against "+
			"the account's 300-per-3-hours limit -- read higher than the real usage",
			bucket.Tokens, want)
	}
}

// A rate-limit refusal from the replaces retry must not be dropped.
//
// The first attempt is refused for a `replaces` reason, which carries no deadline; the retry is
// then refused by the rate limiter, which does. Reading only the first error threw that deadline
// away -- the one signal that says every certificate on the account has to wait, not just this one.
func TestARateLimitRefusalFromTheRetryStillSetsTheDeadline(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"a.example.com"})
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return fixed })

	if err := store.PutCert(&state.CertState{
		Name:           cert.Name,
		NotAfter:       fixed.Add(20 * 24 * time.Hour),
		ARICertID:      "YWJj.ZGVm",
		ARIWindowStart: fixed.Add(-2 * time.Hour),
		ARIWindowEnd:   fixed.Add(-time.Hour),
		ARICheckedAt:   fixed,
	}); err != nil {
		t.Fatal(err)
	}

	fake.newOrderErr = errors.New("ACME error: the requested replaces certificate was not issued by this account")
	calls := 0
	fake.beforeCall = func(call string) {
		if call != "NewOrder" {
			return
		}
		calls++
		if calls == 2 {
			// orderErr is sticky, so this refusal is what the retry sees.
			fake.orderErr = errors.New("acme: error: 429 :: urn:ietf:params:acme:error:rateLimited :: " +
				"too many new orders recently, retry after 2026-09-16 15:00:00 UTC")
		}
	}

	_ = m.Reconcile(context.Background(), cert)

	at, reason, blocked := m.quota.BlockedUntil(ratelimit.NewOrdersPerAccount, "")
	if !blocked {
		t.Fatal("the retry's rate-limit refusal names the instant the CA will listen again; dropping " +
			"it leaves every certificate retrying into a closed door")
	}
	if want := time.Date(2026, 9, 16, 15, 0, 0, 0, time.UTC); !at.Equal(want) {
		t.Errorf("deadline = %s, want %s", at, want)
	}
	if reason != ratelimit.NewOrdersPerAccount.Name {
		t.Errorf("the deadline must name the limit, got %q", reason)
	}
}

// A refusal must be booked against the limit the CA actually refused.
//
// Every newOrder refusal was recorded against new-orders, whatever the CA said. A refusal for
// "this exact set of identifiers" then marked the wrong series blocked while the exact-set series
// -- the limit with NO override path, and the one whose alert is `< 5` -- kept reading optimistic:
// the estimate was wrong in the direction that leads to an order the CA will reject.
func TestARefusalIsBookedAgainstTheLimitItNames(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"a.example.com"})
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return fixed })
	cert.Domains = []string{"a.example.com"}

	cases := []struct {
		name     string
		message  string
		limit    ratelimit.Limit
		scope    string
		unmarked ratelimit.Limit
	}{
		{
			name: "exact identifier set",
			message: "acme: error: 429 :: urn:ietf:params:acme:error:rateLimited :: too many certificates " +
				"already issued for this exact set of identifiers, retry after 2026-09-16 15:00:00 UTC: see " +
				"https://letsencrypt.org/docs/rate-limits/#certificates-per-exact-set-of-identifiers",
			limit: ratelimit.CertsPerExactIdentifierSet,
			scope: cert.DomainKey(),
			// The account-wide order budget is untouched by this refusal and must not be marked.
			unmarked: ratelimit.NewOrdersPerAccount,
		},
		{
			name: "registered domain",
			message: "acme: error: 429 :: urn:ietf:params:acme:error:rateLimited :: too many certificates " +
				"already issued for this registered domain, retry after 2026-09-16 15:00:00 UTC",
			limit:    ratelimit.CertsPerRegisteredDomain,
			scope:    "example.com",
			unmarked: ratelimit.NewOrdersPerAccount,
		},
		{
			name: "new orders",
			message: "acme: error: 429 :: urn:ietf:params:acme:error:rateLimited :: too many new orders " +
				"recently, retry after 2026-09-16 15:00:00 UTC",
			limit:    ratelimit.NewOrdersPerAccount,
			scope:    "",
			unmarked: ratelimit.CertsPerExactIdentifierSet,
		},
	}

	want := time.Date(2026, 9, 16, 15, 0, 0, 0, time.UTC)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Re-seed the row: the previous case left a retry deadline behind, and a pass inside a
			// backoff window never reaches the order at all.
			// NotAfter inside the renewal window (renewBefore is 30 days for classic) and no ARI,
			// so the pass places an order; and a fresh row, so the previous case's retry deadline
			// does not send this pass into its backoff window.
			expiry := fixed.Add(10 * 24 * time.Hour)
			if err := store.PutCert(&state.CertState{
				Name:     cert.Name,
				NotAfter: expiry,
				CertPEM:  selfSignedCertPEM(t, expiry, "a.example.com"),
			}); err != nil {
				t.Fatal(err)
			}
			fake.orders = []legoacme.ExtendedOrder{terminalOrder(
				"https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/1")}
			fake.newOrderErr = errors.New(tc.message)

			if err := m.Reconcile(context.Background(), cert); err == nil {
				t.Fatal("a rate-limited order must be reported as a failure")
			}

			at, reason, blocked := m.quota.BlockedUntil(tc.limit, tc.scope)
			if !blocked {
				t.Fatalf("the refusal names the %s limit; that deadline must gate it", tc.limit.Name)
			}
			if !at.Equal(want) {
				t.Errorf("deadline = %s, want %s", at, want)
			}
			if reason != tc.limit.Name {
				t.Errorf("the deadline must name the limit, got %q", reason)
			}
			if _, _, other := m.quota.BlockedUntil(tc.unmarked, ""); other {
				t.Errorf("%s was marked blocked by a refusal that does not name it", tc.unmarked.Name)
			}

			// Clear the bucket so the next case starts clean.
			if err := store.UpdateRateBucket(tc.limit.Name, tc.scope, func(rec *state.RateBucket) error {
				rec.ResetAt = time.Time{}
				rec.ResetReason = ""
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
