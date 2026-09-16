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

	"github.com/susunola/wecert/internal/config"
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
	if err := store.AddRetiredCert("cloud-old", "example-com", nil, nil); err != nil {
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

// A renewal must archive the OUTGOING certificate's material, so the rollback the retired
// row promises is actually possible.
//
// The row used to keep only a CertId. The private key was overwritten in the certificates
// row at the moment of renewal, so once the retention period expired and the reaper deleted
// the cloud copy, there was nothing left to re-upload: the rollback window was really "how
// long Tencent Cloud still has it", and the comment claiming otherwise was aspirational.
func TestRenewalArchivesTheOutgoingCertificateMaterial(t *testing.T) {
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")
	saved := challengeLeases
	challengeLeases = newTXTLeases()
	t.Cleanup(func() { challengeLeases = saved })

	// Built inline rather than through newAPITestHarness: that harness hardcodes
	// deploy.Noop, and this test is specifically about what a real rebind records.
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	fake := &fakeAPI{}
	certs := []config.Certificate{{
		Name:    "site-example-com",
		Domains: []string{"a.example.com"},
		Profile: config.ProfileClassic,
		KeyType: config.KeyTypeECDSAP256,
		Deploy:  config.Deploy{Enabled: true},
	}}
	if err := config.NormalizeCertificates(certs); err != nil {
		t.Fatal(err)
	}
	cert := &certs[0]

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := newManager(store, fake, &fakeSolver{}, fakeKeyAuth{}, &recordingDeployer{id: "cloud-new"}, log)

	fake.orderDomains = func() []string { return cert.Domains }
	fake.orderKeyPEM = func() []byte {
		o, err := store.GetOrder(cert.Name)
		if err != nil || o == nil {
			return nil
		}
		return o.KeyPEM
	}

	// A live, deployed certificate whose material must survive the renewal. The fake issues
	// against the key this order generated, so the key-match gate is satisfied.
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return fixed }

	oldCertPEM := []byte("-----BEGIN CERTIFICATE-----\nOUTGOING\n-----END CERTIFICATE-----\n")
	oldKeyPEM := []byte("-----BEGIN PRIVATE KEY-----\nOUTGOING-KEY\n-----END PRIVATE KEY-----\n")
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: fixed.Add(48 * time.Hour),
		CertURL: "https://acme.test/cert/old", CertPEM: oldCertPEM, KeyPEM: oldKeyPEM,
		DeployedCertID: "cloud-old", DeployConfirmed: true,
	}); err != nil {
		t.Fatal(err)
	}

	scriptDNS01Order(fake, cert.Domains)
	fake.certNotAfter = fixed.Add(90 * 24 * time.Hour)

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	retired, err := store.ListRetiredCertsBefore(fixed.Add(24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(retired) != 1 {
		t.Fatalf("expected the outgoing certificate on the reclaim list, got %+v", retired)
	}
	if retired[0].CertID != "cloud-old" {
		t.Errorf("reclaim list holds %q, want cloud-old", retired[0].CertID)
	}
	if string(retired[0].CertPEM) != string(oldCertPEM) {
		t.Errorf("the outgoing certificate's PEM was not archived:\n got %q\nwant %q",
			retired[0].CertPEM, oldCertPEM)
	}
	if string(retired[0].KeyPEM) != string(oldKeyPEM) {
		t.Errorf("the outgoing certificate's private key was not archived, so it can never be "+
			"re-uploaded after the cloud copy is reclaimed:\n got %q\nwant %q",
			retired[0].KeyPEM, oldKeyPEM)
	}

	// And the live row must hold the NEW material, not the archived one.
	st, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if string(st.KeyPEM) == string(oldKeyPEM) {
		t.Error("the archive overwrote the live certificate's key instead of recording the outgoing one")
	}
	if st.DeployedCertID != "cloud-new" {
		t.Errorf("live DeployedCertID = %q, want cloud-new", st.DeployedCertID)
	}
}

// recordingDeployer reports a configurable new CertId and records what it was asked to do.
type recordingDeployer struct {
	id string
}

func (d *recordingDeployer) Deploy(_ context.Context, _ string, oldID string, _, _ []byte) (string, error) {
	if d.id == "" {
		return oldID, nil
	}
	return d.id, nil
}
func (d *recordingDeployer) Delete(context.Context, string) error          { return nil }
func (d *recordingDeployer) Bindings(context.Context, string) (int, error) { return 0, nil }

// A drift reissue must still succeed even when the identifier sets share nothing.
//
// This is where the "never send replaces on a changed set" rule came from, found by running
// the lifecycle acceptance case against real Let's Encrypt staging: with two wholly disjoint
// sets the CA refuses `replaces`, that refusal comes back from newOrder, and -- before
// issue() learned to retry -- no order was created and every later round was refused
// identically, so a certificate moved to a different domain set never issued again.
//
// The refusal is the NO-overlap case, not "any change". Let's Encrypt's published rule is
// that an ARI order is exempt when it includes AT LEAST ONE identifier matching the
// certificate it replaces, and an ordinary config change keeps most of the set -- so the
// blanket "never send it" gave up a real exemption to avoid a case the retry now handles.
// The safety property to pin is therefore not "no replaces" but "a disjoint set can never
// wedge the renewal": the order is still created, on the retry.
func TestDriftReissueSurvivesADisjointIdentifierSet(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"new.example.com"})

	// The live certificate covers something else entirely, and its ARI certID is known.
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

	fake.orders = []legoacme.ExtendedOrder{
		terminalOrder("https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/1"),
	}
	// The CA behaves as Let's Encrypt does for a disjoint set: it refuses the replaces and
	// the order is never created.
	fake.beforeCall = func(call string) {
		if call != "NewOrder" {
			return
		}
		fake.mu.Lock()
		defer fake.mu.Unlock()
		if len(fake.newOrderReplaces) > 0 && fake.newOrderReplaces[len(fake.newOrderReplaces)-1] != "" {
			fake.newOrderErr = errors.New("acme: error: 400 :: urn:ietf:params:acme:error:malformed :: " +
				"Could not validate ARI 'replaces' field :: identifiers in this order do not match " +
				"any identifiers in the certificate being replaced")
		}
	}

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("a disjoint identifier set must never wedge the renewal; got %v", err)
	}

	// Two attempts: the exempting one, then the retry that gets the order created.
	if len(fake.newOrderReplaces) != 2 {
		t.Fatalf("expected the replaces attempt plus one retry, got %v", fake.newOrderReplaces)
	}
	if fake.newOrderReplaces[0] != "oldAki.oldSerial" {
		t.Errorf("the first attempt should try to keep the ARI exemption, sent %q", fake.newOrderReplaces[0])
	}
	if fake.newOrderReplaces[1] != "" {
		t.Errorf("the retry must drop replaces, sent %q", fake.newOrderReplaces[1])
	}
}

// A config change that KEEPS most of the set must keep `replaces`, because Let's Encrypt
// exempts an ARI order sharing at least one identifier. Dropping it there spends one of the
// 50-certificates-per-registered-domain-per-7-days allowance for nothing.
func TestDriftReissueWithAnOverlappingSetKeepsTheExemption(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t,
		[]string{"a.example.com", "b.example.com", "c.example.com"})

	// Live certificate covers two of the three configured names.
	notAfter := time.Now().Add(80 * 24 * time.Hour)
	if err := store.PutCert(&state.CertState{
		Name:      cert.Name,
		NotAfter:  notAfter,
		CertPEM:   selfSignedCertPEM(t, notAfter, "a.example.com", "b.example.com"),
		KeyPEM:    []byte("old-key"),
		ARICertID: "oldAki.oldSerial",
	}); err != nil {
		t.Fatal(err)
	}

	fake.orders = []legoacme.ExtendedOrder{
		terminalOrder("https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/1"),
	}

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if len(fake.newOrderReplaces) != 1 {
		t.Fatalf("expected exactly one order attempt, got %v", fake.newOrderReplaces)
	}
	if got := fake.newOrderReplaces[0]; got != "oldAki.oldSerial" {
		t.Errorf("an overlapping identifier set qualifies for the ARI exemption, so replaces must be "+
			"sent (got %q); dropping it consumes the 50-per-registered-domain quota for nothing", got)
	}
}

func TestRefusedReplacesIsRetriedWithoutIt(t *testing.T) {
	// Every wording a real CA uses to refuse a `replaces` field. Only the last one contains
	// the literal string "replaces", which is what the original guard matched on -- so the
	// first three used to fall through to a permanent failure and the certificate NEVER
	// renewed. Boulder reports the first two, Pebble the third (an ACME server is free to
	// word its errors however it likes, so message matching cannot be made correct).
	wordings := []struct {
		name string
		msg  string
	}{
		{"boulder-ari-certid", "acme: error: 400 :: urn:ietf:params:acme:error:malformed :: parsing ARI CertID failed"},
		{"boulder-account", "acme: error: 403 :: urn:ietf:params:acme:error:unauthorized :: " +
			"requester account did not request the certificate being replaced by this order"},
		{"pebble-no-order", "acme: error: 404 :: urn:ietf:params:acme:error:malformed :: " +
			"could not find an order for the given certificate"},
		{"le-no-overlap", "acme: error: 400 :: urn:ietf:params:acme:error:malformed :: " +
			"Could not validate ARI 'replaces' field :: identifiers in this order do not match " +
			"any identifiers in the certificate being replaced"},
	}

	for _, w := range wordings {
		t.Run(w.name, func(t *testing.T) {
			store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})

			// Due for renewal through the ARI window, so `replaces` is non-empty.
			notAfter := m.now().Add(20 * 24 * time.Hour)
			if err := store.PutCert(&state.CertState{
				Name:           cert.Name,
				NotAfter:       notAfter,
				CertPEM:        selfSignedCertPEM(t, notAfter, "example.com"),
				KeyPEM:         []byte("old-key"),
				ARICertID:      "oldAki.oldSerial",
				ARIWindowStart: m.now().Add(-2 * time.Hour),
				ARIWindowEnd:   m.now().Add(-time.Hour),
				ARICheckedAt:   m.now(), // fresh, so the window above is not refetched
			}); err != nil {
				t.Fatal(err)
			}

			fake.orders = []legoacme.ExtendedOrder{
				terminalOrder("https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/1"),
			}
			fake.newOrderErr = errors.New(w.msg)

			if err := m.Reconcile(context.Background(), cert); err != nil {
				t.Fatalf("the pass must recover by dropping replaces (this error wording is the CA's "+
					"choice, so it cannot be the thing that decides whether a renewal happens), got: %v", err)
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
		})
	}
}

// A failure with NO replaces set must not be retried: there is nothing to drop, and retrying
// would double the order rate for an error that will repeat identically.
func TestOrderFailureWithoutReplacesIsNotRetried(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})

	// No certificate state at all: first issuance, so replaces is empty.
	_ = store
	fake.orders = []legoacme.ExtendedOrder{
		terminalOrder("https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/1"),
	}
	fake.newOrderErr = errors.New("acme: error: 500 :: server internal error")

	if err := m.Reconcile(context.Background(), cert); err == nil {
		t.Fatal("a genuine order-creation failure must be reported, not hidden")
	}
	if len(fake.newOrderReplaces) != 1 {
		t.Errorf("an error with no replaces to drop must not be retried, got %d attempts",
			len(fake.newOrderReplaces))
	}
}
