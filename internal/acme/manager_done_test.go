package acme

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"

	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/state"
)

func TestLocalOnlyRenewalClearsDeploymentStateWithoutRetiringLiveCloudCert(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	cert.Deploy.Enabled = false

	// The ID of the certificate that is being left behind is the only local record that
	// it exists, and nothing else in the system will mention it again. Capture the log so
	// "it was dropped" cannot regress into "it vanished".
	var logs bytes.Buffer
	m.log = slog.New(slog.NewTextHandler(&logs, nil))

	oldExpiry, newExpiry := time.Now().Add(24*time.Hour), time.Now().Add(90*24*time.Hour)
	st := &state.CertState{Name: cert.Name, NotAfter: oldExpiry, CertURL: "https://ca.test/old", CertPEM: selfSignedCertPEM(t, oldExpiry, "example.com"), KeyPEM: []byte("old-key"), DeployedCertID: "cloud-old", DeployConfirmed: true}
	if err := store.PutCert(st); err != nil {
		t.Fatal(err)
	}
	key, err := GenerateKey(cert.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := MarshalPrivateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutOrder(&state.Order{CertName: cert.Name, KeyPEM: keyPEM}); err != nil {
		t.Fatal(err)
	}
	fake.certNotAfter = newExpiry
	fake.orders = []legoacme.ExtendedOrder{{Order: legoacme.Order{Status: "valid", Certificate: "https://ca.test/new"}, Location: "https://ca.test/order/new"}}
	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if got.DeployedCertID != "" || got.DeployConfirmed {
		t.Fatalf("local-only renewal must not inherit cloud deployment state: %+v", got)
	}
	retired, err := store.ListRetiredCertsBefore(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(retired) != 0 {
		t.Fatalf("the old cloud certificate may still be bound, so local-only renewal must not retire it: %+v", retired)
	}
	if !strings.Contains(logs.String(), "cloud-old") {
		t.Errorf("the ID of the certificate that is left behind must be logged, got:\n%s", logs.String())
	}
}

// A certificate that belongs to a different key must never replace a working one.
//
// It covers exactly the right names and lives exactly as long, so VerifyCoverage and the
// notAfter check both wave it through -- and what gets deployed is a certificate that
// cannot complete a single handshake. That is "the renewal succeeded and HTTPS is down",
// the worst possible pair of symptoms.
func TestDownloadRefusesACertificateForADifferentKey(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})

	fake.orders = []legoacme.ExtendedOrder{
		{
			Order: legoacme.Order{
				Status:   "pending",
				Finalize: "https://ca.test/finalize/9",
				// Already valid, so the flow goes straight to the download.
				Authorizations: []string{},
			},
			Location: "https://ca.test/order/9",
		},
		terminalOrder("https://ca.test/order/9", "https://ca.test/finalize/9", "https://ca.test/cert/9"),
	}

	// Same names, same lifetime, some other key: selfSignedCertPEM generates its own.
	fake.certPEM = selfSignedCertPEM(t, time.Now().Add(90*24*time.Hour), cert.Domains...)

	err := m.Reconcile(context.Background(), cert)
	if err == nil {
		t.Fatal("a certificate for a different key must fail the pass, not be deployed")
	}
	if !strings.Contains(err.Error(), "does not belong to the private key") {
		t.Errorf("the failure must name the real cause, got: %v", err)
	}

	// Nothing may have been promoted to the live certificate.
	st, gerr := store.GetCert(cert.Name)
	if gerr != nil {
		t.Fatal(gerr)
	}
	if st != nil && len(st.CertPEM) != 0 {
		t.Error("the mismatched certificate must not be stored as the live one")
	}
}

func TestReapRetiredKeepsQueueWhenCloudDeploymentIsDisabled(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AddRetiredCert("cloud-old", "example-com"); err != nil {
		t.Fatal(err)
	}
	m := newManager(store, nil, &fakeSolver{}, fakeKeyAuth{}, deploy.Noop{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.now = func() time.Time { return time.Now().Add(8 * 24 * time.Hour) }
	m.ReapRetired(context.Background())
	retired, err := store.ListRetiredCertsBefore(time.Now().Add(24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(retired) != 1 || retired[0].CertID != "cloud-old" {
		t.Fatalf("Noop must not erase an undeleted cloud certificate from the queue: %+v", retired)
	}
}

// A domain-set change must not carry ARI's `replaces`.
//
// Let's Encrypt answers `malformed: Could not validate ARI 'replaces' field: identifiers
// in this order do not match any identifiers in the certificate being replaced` when the
// two identifier sets do not overlap, and that error comes back from newOrder -- so no
// order is created, and every later round sends the same value and is refused the same
// way. A certificate moved to a wholly different domain set would then never issue again.
//
// Found by running the lifecycle acceptance case against real Let's Encrypt staging.
func TestDriftReissueSendsNoReplaces(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"new.example.com"})

	// The live certificate covers something else entirely, and its ARI certID is known:
	// that is exactly the value the old code would have sent.
	notAfter := time.Now().Add(80 * 24 * time.Hour)
	if err := store.PutCert(&state.CertState{
		Name:      cert.Name,
		NotAfter:  notAfter,
		CertPEM:   selfSignedCertPEM(t, notAfter, "old.example.com"),
		KeyPEM:    []byte("old-key"),
		ARICertID: "oldAki.oldSerial",
	}); err != nil {
		t.Fatal(err)
	}

	// Already valid, so the pass goes straight to the download.
	fake.orders = []legoacme.ExtendedOrder{
		terminalOrder("https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/1"),
	}

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if len(fake.newOrderReplaces) != 1 {
		t.Fatalf("expected exactly one order attempt, got %v", fake.newOrderReplaces)
	}
	if got := fake.newOrderReplaces[0]; got != "" {
		t.Errorf("a changed identifier set must not send replaces (got %q): the CA rejects "+
			"it outright, and because no order is created the failure repeats forever", got)
	}
}

// A refused `replaces` is retried once without it, on the renewal path too.
//
// Losing the rate-limit exemption costs one quota slot; failing to renew costs the
// certificate. This is the guard that makes the second outcome impossible.
func TestRefusedReplacesIsRetriedWithoutIt(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})

	// Due for renewal through the ARI window, so `replaces` is non-empty.
	notAfter := time.Now().Add(20 * 24 * time.Hour)
	if err := store.PutCert(&state.CertState{
		Name:           cert.Name,
		NotAfter:       notAfter,
		CertPEM:        selfSignedCertPEM(t, notAfter, "example.com"),
		KeyPEM:         []byte("old-key"),
		ARICertID:      "oldAki.oldSerial",
		ARIWindowStart: time.Now().Add(-2 * time.Hour),
		ARIWindowEnd:   time.Now().Add(-time.Hour),
		ARICheckedAt:   time.Now(), // fresh, so the window above is not refetched
	}); err != nil {
		t.Fatal(err)
	}

	fake.orders = []legoacme.ExtendedOrder{
		terminalOrder("https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/1"),
	}
	fake.newOrderErr = errors.New("acme: error: 400 :: urn:ietf:params:acme:error:malformed :: " +
		"Could not validate ARI 'replaces' field :: identifiers in this order do not match " +
		"any identifiers in the certificate being replaced")

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("the pass must recover by dropping replaces, got: %v", err)
	}

	want := []string{"oldAki.oldSerial", ""}
	if len(fake.newOrderReplaces) != len(want) {
		t.Fatalf("expected a retry without replaces, got attempts %v", fake.newOrderReplaces)
	}
	for i := range want {
		if fake.newOrderReplaces[i] != want[i] {
			t.Errorf("attempt %d sent replaces=%q, want %q", i, fake.newOrderReplaces[i], want[i])
		}
	}
}
