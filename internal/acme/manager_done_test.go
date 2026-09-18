package acme

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"
	_ "modernc.org/sqlite"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/group"
	"github.com/susunola/wecert/internal/ratelimit"
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

	// The bound has to come from the store's own clock, not from the manager's injected one:
	// AddRetiredCert stamps retired_at with time.Now(), so a bound derived from fixed made this
	// test pass only until the wall clock reached fixed+24h -- at which point it failed for a
	// reason that had nothing to do with the behaviour under test. The assertion is about the
	// archived material, not about when it was archived.
	retired, err := store.ListRetiredCertsBefore(time.Now().Add(time.Hour))
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
func (d *recordingDeployer) Delete(context.Context, string) error                { return nil }
func (d *recordingDeployer) Bindings(context.Context, string) (int, bool, error) { return 0, true, nil }

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

// A failure to RECORD a created order must still schedule a backoff.
//
// This was a bare `return err`, the worst of both worlds: the order exists at the CA but not
// in the state store, so the next pass has no order URL to resume and creates ANOTHER one --
// and because recordFailure never ran, no backoff was scheduled either. The order rate then
// follows the pass rate instead of the backoff: at a 1-minute interval that is 1440 orders a
// day against "300 new orders per account per 3 hours", and hitting that ceiling blocks every
// certificate on the account, not just this one.
func TestFailedOrderPersistSchedulesABackoff(t *testing.T) {
	// Opened here rather than through newAPITestHarness so the path is known: the test needs a
	// second connection to install the trigger.
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	store, err := state.Open(path)
	if err != nil {
		t.Fatalf("open state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	certs := []config.Certificate{{
		Name: "example-com", Domains: []string{"example.com"},
		Profile: config.ProfileClassic, KeyType: config.KeyTypeECDSAP256,
		Deploy: config.Deploy{Enabled: false},
	}}
	if err := config.NormalizeCertificates(certs); err != nil {
		t.Fatalf("normalize certificate: %v", err)
	}
	cert := &certs[0]

	fake := &fakeAPI{}
	m := newManager(store, fake, &fakeSolver{}, fakeKeyAuth{}, deploy.Noop{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	now := fixed
	m.now = func() time.Time { return now }

	// Block only order INSERTs, so the certificate row (where the backoff lives) still writes.
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open second connection: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`CREATE TRIGGER block_order_insert BEFORE INSERT ON orders
		BEGIN SELECT RAISE(FAIL, 'order insert blocked by test'); END;`); err != nil {
		t.Fatalf("block order inserts: %v", err)
	}

	fake.orders = []legoacme.ExtendedOrder{
		terminalOrder("https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/1"),
	}

	// First issuance, so the pass goes straight to issue().
	if err := m.Reconcile(context.Background(), cert); err == nil {
		t.Fatal("failing to record the order must be reported")
	}
	if len(fake.newOrderReplaces) != 1 {
		t.Fatalf("expected one order attempt, got %d", len(fake.newOrderReplaces))
	}

	st, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if st == nil || st.NextAttemptAt.IsZero() {
		t.Fatal("a failed order-record must schedule a retry; without one the next pass runs " +
			"immediately and creates another order, so the rate follows the pass rate")
	}
	if st.ConsecutiveFailures == 0 {
		t.Error("the failure must be counted")
	}

	// And the scheduled window must actually hold the next pass off.
	if err := m.Reconcile(context.Background(), cert); !errors.Is(err, state.ErrBackoff) {
		t.Errorf("the next pass must wait for the backoff, got %v", err)
	}
	if len(fake.newOrderReplaces) != 1 {
		t.Errorf("the backoff window must prevent a second order, got %d attempts",
			len(fake.newOrderReplaces))
	}
}

// An order URL that can never be fetched again must not block renewal until it expires.
//
// The order branch keeps advancing a persisted order instead of creating a new one, and
// renewal is only decided AFTER that branch -- so an order whose URL is permanently gone
// stalls every later renewal for the order's whole TTL (7 days by default). Reachable without
// anything exotic: accounts are keyed by ACME directory while orders are not, so pointing
// wecert at staging and back leaves orders naming a directory that no longer serves them.
// Observed before the fix: a certificate 5 days from expiry sat through 24 passes and 24
// GetOrder failures, fell to 21 hours left, and issued only once the order expired.
func TestDeadOrderURLIsDiscardedInsteadOfBlockingRenewal(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	now := fixed
	m.now = func() time.Time { return now }

	// A live certificate well inside its renewal window, with a persisted order whose URL
	// the CA will never serve again.
	notAfter := fixed.Add(5 * 24 * time.Hour)
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: notAfter,
		CertPEM: selfSignedCertPEM(t, notAfter, "example.com"),
		KeyPEM:  []byte("live-key"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutOrder(&state.Order{
		CertName: cert.Name, OrderURL: "https://ca.test/order/gone",
		FinalizeURL: "https://ca.test/finalize/gone", Status: "pending",
		Identifiers: cert.DomainKey(),
		ExpiresAt:   fixed.Add(7 * 24 * time.Hour), // a week away
	}); err != nil {
		t.Fatal(err)
	}

	// Every GetOrder fails; the fake is only consulted once the order row is gone.
	fake.orderErr = nil
	fake.getOrderErr = errors.New("acme: error: 404 :: urn:ietf:params:acme:error:malformed :: no order found")

	var discarded bool
	for i := 0; i < maxOrderFetchFailures+2; i++ {
		_ = m.Reconcile(context.Background(), cert)
		o, err := store.GetOrder(cert.Name)
		if err != nil {
			t.Fatal(err)
		}
		if o == nil {
			discarded = true
			t.Logf("order discarded after %d attempt(s)", i+1)
			break
		}
		// Clear the backoff so the next attempt is not simply skipped.
		st, err := store.GetCert(cert.Name)
		if err != nil {
			t.Fatal(err)
		}
		if st != nil {
			st.NextAttemptAt = time.Time{}
			if err := store.PutCert(st); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !discarded {
		t.Fatalf("an order that cannot be fetched must be discarded after %d consecutive failures, "+
			"otherwise renewal waits for the order to expire (%s away)",
			maxOrderFetchFailures, time.Until(fixed.Add(7*24*time.Hour)).Round(time.Hour))
	}
}

// A name whose authorization just failed must not be ordered again inside the failure window.
//
// The certificate backoff starts at a minute and doubles, so the first hour of a persistently
// failing name costs six attempts (1+2+4+8+16+32 minutes) against "5 authorization failures
// per identifier per hour". That budget belongs to the IDENTIFIER, not the certificate, so N
// certificates sharing the name attack the same five -- at ten certificates, sixty failures in
// the first hour, of which at most five could have produced a different answer. Past the limit
// every further order for that name is rejected outright, so the extra attempts bought nothing
// while the consecutive-failure counter (which feeds an account pause requiring manual portal
// action) kept climbing.
func TestIdentifierCooldownSuppressesFurtherOrders(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"broken.example.com"})
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	now := fixed
	m.now = func() time.Time { return now }

	fake.orders = []legoacme.ExtendedOrder{
		terminalOrder("https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/1"),
	}

	// Everything except the identifier cooldown must be permissive, or this test would pass
	// for the wrong reason. Two things have to be re-armed before each pass: the certificate
	// backoff (cleared) and the renewal window. A successful issuance replaces the live
	// certificate with a fresh 90-day one, which is NOT due for renewal -- so the expiry is
	// reset too, leaving the cooldown as the only thing that can stop an order.
	dueForRenewal := func(t *testing.T) {
		t.Helper()
		if err := store.PutCert(&state.CertState{
			Name: cert.Name, NotAfter: fixed.Add(20 * 24 * time.Hour),
			CertPEM: selfSignedCertAt(t, fixed.Add(-70*24*time.Hour),
				fixed.Add(20*24*time.Hour), "broken.example.com"),
			KeyPEM: []byte("live-key"),
		}); err != nil {
			t.Fatal(err)
		}
		if err := store.DeleteOrder(cert.Name); err != nil {
			t.Fatal(err)
		}
	}

	// Pass 1: due for renewal, no cooldown, so an order is placed.
	dueForRenewal(t)
	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(fake.newOrderReplaces) != 1 {
		t.Fatalf("expected one order, got %d", len(fake.newOrderReplaces))
	}

	// The CA reports the name's authorization as failed, starting its cooldown.
	m.noteIdentifierFailure("broken.example.com")

	// Pass 2: renewal is due and the backoff is clear, so only the cooldown can stop it.
	dueForRenewal(t)
	_ = m.Reconcile(context.Background(), cert)
	if n := len(fake.newOrderReplaces); n != 1 {
		t.Errorf("an identifier inside its failure cooldown must not be ordered again, got %d orders "+
			"in total; retrying inside the window cannot succeed and spends the budget every other "+
			"certificate for this name depends on", n)
	}

	// Pass 3, past the window: a cooldown is a delay, not a blacklist. A permanent one would
	// turn a transient DNS problem into an outage.
	now = fixed.Add(identifierCooldownFor + time.Minute)
	dueForRenewal(t)
	_ = m.Reconcile(context.Background(), cert)
	if n := len(fake.newOrderReplaces); n != 2 {
		t.Errorf("after the cooldown expires the name must be retried, got %d orders in total", n)
	}
}

// The quota accounting must count what this program actually spends.
//
// Let's Encrypt documents its limits and their token-bucket refill rates but has NO endpoint to
// query the remaining allowance -- the only way to answer "do 40 more issuances fit in this
// week's 50?" is to account for what was spent. Before this, the answer was unavailable from
// anywhere, and the first signal was an error after the quota was already gone.
func TestPlacingAnOrderSpendsAccountQuota(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return fixed })

	before, ok := m.quota.Remaining(ratelimit.NewOrdersPerAccount, "")
	if !ok {
		t.Fatal("the account limit must be readable")
	}

	fake.orders = []legoacme.ExtendedOrder{
		terminalOrder("https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/1"),
	}
	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	after, ok := m.quota.Remaining(ratelimit.NewOrdersPerAccount, "")
	if !ok {
		t.Fatal("the account limit must be readable after an order")
	}
	if after != before-1 {
		t.Errorf("one order must spend exactly one token: before=%v after=%v", before, after)
	}

	// The quota must survive a restart, since the bucket is persisted: a fresh Manager over the
	// same store sees the spend rather than a full bucket.
	fresh := newManager(store, fake, &fakeSolver{}, fakeKeyAuth{}, deploy.Noop{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	fresh.SetNow(func() time.Time { return fixed })
	restarted, ok := fresh.quota.Remaining(ratelimit.NewOrdersPerAccount, "")
	if !ok {
		t.Fatal("the account limit must be readable from a fresh manager")
	}
	if restarted != after {
		t.Errorf("a restart must not forget the spend: %v, want %v", restarted, after)
	}
}

// A CA-reported deadline must be recorded, and must be visible to an operator.
//
// The message shape is the one Let's Encrypt documents, and the instant inside it is
// authoritative: it accounts for every other account spending the same global bucket, which
// the local estimate cannot see.
func TestRateLimitErrorRecordsTheCAsDeadline(t *testing.T) {
	_, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return fixed })

	fake.newOrderErr = errors.New("acme: error: 429 :: urn:ietf:params:acme:error:rateLimited :: " +
		"too many new orders recently, retry after 2026-09-16 15:00:00 UTC")

	if err := m.Reconcile(context.Background(), cert); err == nil {
		t.Fatal("a rate-limited order must be reported as a failure")
	}

	at, reason, blocked := m.quota.BlockedUntil(ratelimit.NewOrdersPerAccount, "")
	if !blocked {
		t.Fatal("the CA reported when it will accept requests again; that deadline must be recorded")
	}
	want := time.Date(2026, 9, 16, 15, 0, 0, 0, time.UTC)
	if !at.Equal(want) {
		t.Errorf("deadline = %s, want %s", at, want)
	}
	if reason != ratelimit.NewOrdersPerAccount.Name {
		t.Errorf("the deadline must name the limit, got %q", reason)
	}

	// And it must appear in the report an operator or metric reader sees.
	var found bool
	for _, rep := range m.QuotaStatus(nil) {
		if rep.Limit == ratelimit.NewOrdersPerAccount.Name {
			found = true
			if !rep.Blocked || !rep.BlockedUntil.Equal(want) {
				t.Errorf("the report must carry the deadline, got %+v", rep)
			}
		}
	}
	if !found {
		t.Error("the account limit must be in the quota report")
	}
}

// unverifiedDeployer is what the Tencent Cloud deployer looks like when the one-click switch
// is reported as done but the asynchronous bind-resource enumeration does not answer in time:
// it returns the uploaded certificate's ID together with a wrapped ErrSwitchUnverified.
type unverifiedDeployer struct{ id string }

func (d *unverifiedDeployer) Deploy(context.Context, string, string, []byte, []byte) (string, error) {
	return d.id, fmt.Errorf("UpdateCertificateInstance: %w: the enumeration did not answer",
		deploy.ErrSwitchUnverified)
}
func (d *unverifiedDeployer) Delete(context.Context, string) error { return nil }
func (d *unverifiedDeployer) Bindings(context.Context, string) (int, bool, error) {
	return 0, false, nil
}

// A switch the cloud reports as done but wecert could not confirm must be RECORDED, not
// retried forever.
//
// Observed on a real shared account: the deploy record reported success=1 on three
// consecutive passes, each pass then failed on the enumeration timeout, and the state kept
// the old certificate with not_after at 0 -- because the old certificate has no bindings
// left, every round re-ran the same switch and nothing ever converged. The honest outcome is
// "deployed, but not confirmed": the certificate is promoted so the next round is a cheap
// binding probe instead of another deploy, and DeployConfirmed stays false so the deployed
// metric does not claim a confirmation that never happened.
func TestUnverifiedSwitchIsRecordedAsDeployedButUnconfirmed(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	cert.Deploy.Enabled = true
	m.deployer = &unverifiedDeployer{id: "cloud-new"}

	oldExpiry, newExpiry := time.Now().Add(24*time.Hour), time.Now().Add(90*24*time.Hour)
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: oldExpiry,
		CertURL: "https://ca.test/old", CertPEM: selfSignedCertPEM(t, oldExpiry, "example.com"),
		KeyPEM: []byte("old-key"), DeployedCertID: "cloud-old", DeployConfirmed: true,
	}); err != nil {
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
	fake.orders = []legoacme.ExtendedOrder{{
		Order:    legoacme.Order{Status: "valid", Certificate: "https://ca.test/new"},
		Location: "https://ca.test/order/new",
	}}

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("an unconfirmed switch is not a failed renewal; failing here never converges: %v", err)
	}

	got, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if got.DeployedCertID != "cloud-new" {
		t.Errorf("DeployedCertID = %q, want cloud-new: the certificate that is serving traffic must be "+
			"recorded, otherwise every later round re-runs the same switch", got.DeployedCertID)
	}
	if got.DeployConfirmed {
		t.Error("the binding was never confirmed, so DeployConfirmed must stay false and the deployed " +
			"metric must keep saying so until the next pass's probe confirms it")
	}
	if got.ConsecutiveFailures != 0 {
		t.Errorf("this is not a failure, so it must not enter backoff: ConsecutiveFailures = %d",
			got.ConsecutiveFailures)
	}
	if o, err := store.GetOrder(cert.Name); err != nil {
		t.Fatal(err)
	} else if o != nil {
		t.Errorf("the order must be finished, or the next round resumes it and deploys again: %+v", o)
	}
	retired, err := store.ListRetiredCertsBefore(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(retired) != 1 || retired[0].CertID != "cloud-old" {
		t.Errorf("the outgoing certificate belongs on the reclaim list (the cloud refuses to delete a "+
			"certificate that is still bound), got %+v", retired)
	}

	// And the loop closes: the state this leaves behind is exactly what the cheap binding probe
	// acts on, so the next pass settles the question instead of repeating the switch.
	m.deployer = &fakeDeployer{bindings: 2}
	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("the confirming pass must not fail: %v", err)
	}
	confirmed, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if !confirmed.DeployConfirmed {
		t.Error("the next pass found the certificate bound, so the deployment must become confirmed " +
			"without another deploy")
	}
}

// A renewal that resumes an already-uploaded certificate must not queue that certificate for
// reclaim.
//
// The reclaim guard asks "is the order's uploaded id the one now in service?", and on this path
// the honest answer is the id this pass is about to promote. It used to read
// certificates.deployed_cert_id instead, which at that moment still names the OUTGOING
// certificate -- the promotion is staged on a copy until the epilogue transaction commits -- so
// the comparison could never match and the certificate that was about to serve traffic was
// written to the reclaim list by the very transaction that promoted it. ReapRetired would then
// delete it once the retention window passed, with only the cloud's own IsCheckResource standing
// in the way.
func TestAResumedCertificateIsNotQueuedForReclaim(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	fake := &fakeAPI{}
	certs := []config.Certificate{{
		Name: "site-example-com", Domains: []string{"a.example.com"},
		Profile: config.ProfileClassic, KeyType: config.KeyTypeECDSAP256,
		Deploy: config.Deploy{Enabled: true},
	}}
	if err := config.NormalizeCertificates(certs); err != nil {
		t.Fatal(err)
	}
	cert := &certs[0]

	m := newManager(store, fake, &fakeSolver{}, fakeKeyAuth{}, &recordingDeployer{id: "cloud-new"},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	fake.orderDomains = func() []string { return cert.Domains }
	fake.orderKeyPEM = func() []byte {
		o, err := store.GetOrder(cert.Name)
		if err != nil || o == nil {
			return nil
		}
		return o.KeyPEM
	}

	now := time.Now()
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: now.Add(24 * time.Hour),
		CertURL: "https://acme.test/cert/old", CertPEM: selfSignedCertPEM(t, now.Add(24*time.Hour), "a.example.com"),
		KeyPEM: []byte("old-key"), DeployedCertID: "cloud-old", DeployConfirmed: true,
	}); err != nil {
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
	// An earlier pass uploaded this certificate and then failed before the rebind could finish,
	// so the order carries the resume anchor and this pass deploys exactly that id.
	if err := store.PutOrder(&state.Order{
		CertName: cert.Name, KeyPEM: keyPEM, DeploymentCertID: "cloud-new",
	}); err != nil {
		t.Fatal(err)
	}

	scriptDNS01Order(fake, cert.Domains)
	fake.certNotAfter = now.Add(90 * 24 * time.Hour)
	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if got.DeployedCertID != "cloud-new" {
		t.Fatalf("DeployedCertID = %q, want cloud-new", got.DeployedCertID)
	}
	retired, err := store.ListRetiredCertsBefore(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(retired) != 1 || retired[0].CertID != "cloud-old" {
		t.Fatalf("the reclaim list must hold the outgoing certificate and nothing else, got %+v", retired)
	}
}

// When the epilogue transaction fails, the order must still carry the certificate it uploaded.
//
// That ID is the resume anchor: it is what lets the next pass call ResumeDeploy instead of
// uploading a second copy of the same certificate, and it is the only local record of a cloud
// object that nothing else in the state store mentions. Clearing it was a durable write outside
// the transaction ("best-effort: a successful issuance must not fail because a bookkeeping write
// did"), so a rollback left the order without it -- and, because the reclaim guard reads the
// order back, a *successful* write of that clear was also what made the guard compare against the
// outgoing certificate. The delete inside the transaction removes the row and the ID together.
func TestAFailedEpilogueKeepsTheOrdersResumeAnchor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	fake := &fakeAPI{}
	dep := &stagedDeployer{uploadID: "cloud-new"}
	certs := []config.Certificate{{
		Name: "site-example-com", Domains: []string{"a.example.com"},
		Profile: config.ProfileClassic, KeyType: config.KeyTypeECDSAP256,
		Deploy: config.Deploy{Enabled: true},
	}}
	if err := config.NormalizeCertificates(certs); err != nil {
		t.Fatal(err)
	}
	cert := &certs[0]

	m := newManager(store, fake, &fakeSolver{}, fakeKeyAuth{}, dep,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	fake.orderDomains = func() []string { return cert.Domains }
	fake.orderKeyPEM = func() []byte {
		o, err := store.GetOrder(cert.Name)
		if err != nil || o == nil {
			return nil
		}
		return o.KeyPEM
	}

	now := time.Now()
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: now.Add(24 * time.Hour),
		CertURL: "https://acme.test/cert/old", CertPEM: selfSignedCertPEM(t, now.Add(24*time.Hour), "a.example.com"),
		KeyPEM: []byte("old-key"), DeployedCertID: "cloud-old", DeployConfirmed: true,
	}); err != nil {
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

	scriptDNS01Order(fake, cert.Domains)
	fake.certNotAfter = now.Add(90 * 24 * time.Hour)

	// Fail the last statement of the epilogue, so everything before it has already run.
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`CREATE TRIGGER block_order_delete BEFORE DELETE ON orders
		BEGIN SELECT RAISE(FAIL, 'orders blocked by test'); END;`); err != nil {
		t.Fatal(err)
	}

	if err := m.Reconcile(context.Background(), cert); err == nil {
		t.Fatal("the epilogue failed, so the pass must be reported as failed")
	}

	o, err := store.GetOrder(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if o == nil {
		t.Fatal("the order must survive a rolled-back epilogue")
	}
	if o.DeploymentCertID != "cloud-new" {
		t.Errorf("the rolled-back epilogue lost the resume anchor (DeploymentCertID=%q, want cloud-new): "+
			"the next pass uploads a second copy of a certificate that is already in the cloud, and the "+
			"first copy is recorded nowhere", o.DeploymentCertID)
	}
	if got, err := store.GetCert(cert.Name); err != nil {
		t.Fatal(err)
	} else if got.DeployedCertID != "cloud-old" || got.CertURL != "https://acme.test/cert/old" {
		t.Errorf("the promotion committed despite the failed transaction: %+v", got)
	}
	if retired, _ := store.ListRetiredCertsBefore(time.Now().Add(time.Hour)); len(retired) != 0 {
		t.Errorf("a rolled-back epilogue left reclaim records: %+v", retired)
	}
}

// A failed discardOrder must schedule a retry, not return the bare error.
//
// discardOrder is what reclaims TXT records through authoritative DNS probes, and its failures are
// state-store failures. Returning the error without recordFailure skips the backoff entirely, so
// the next pass re-runs those probes at the pass rate and nothing escalates or records why. The
// sibling call site in manager_flow.go already says exactly this; the other three did not.
func TestAFailedDiscardSchedulesARetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	fake := &fakeAPI{}
	m := newManager(store, fake, &fakeSolver{}, fakeKeyAuth{}, deploy.Noop{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	certs := []config.Certificate{{
		Name: "site-example-com", Domains: []string{"a.example.com"},
		Profile: config.ProfileClassic, KeyType: config.KeyTypeECDSAP256,
	}}
	if err := config.NormalizeCertificates(certs); err != nil {
		t.Fatal(err)
	}
	cert := &certs[0]

	now := time.Now()
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: now.Add(24 * time.Hour),
		CertURL: "https://acme.test/cert/old", CertPEM: selfSignedCertPEM(t, now.Add(24*time.Hour), "a.example.com"),
		KeyPEM: []byte("old-key"), DeployedCertID: "cloud-old", DeployConfirmed: true,
	}); err != nil {
		t.Fatal(err)
	}
	// An order the CA has already expired: the pass discards it before doing anything else.
	if err := store.PutOrder(&state.Order{
		CertName: cert.Name, OrderURL: "https://acme.test/order/expired",
		FinalizeURL: "https://acme.test/finalize/expired", Status: "pending",
		KeyPEM: []byte("old-key"), Identifiers: cert.DomainKey(),
		ExpiresAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`CREATE TRIGGER block_order_delete BEFORE DELETE ON orders
		BEGIN SELECT RAISE(FAIL, 'orders blocked by test'); END;`); err != nil {
		t.Fatal(err)
	}

	if err := m.Reconcile(context.Background(), cert); err == nil {
		t.Fatal("the store refused the delete, so the pass must be reported as failed")
	}

	got, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if got.ConsecutiveFailures == 0 || got.NextAttemptAt.IsZero() {
		t.Errorf("a failed discard recorded no failure (failures=%d nextAttempt=%v): the next pass then "+
			"retries at the pass rate instead of a backoff, re-running the TXT reclaim probes each time",
			got.ConsecutiveFailures, got.NextAttemptAt)
	}
}

// An issuance spends the two per-certificate budgets, so the gauges that publish them mean
// something.
//
// Only the account-wide order limit was ever spent, while all four limits were published as
// `wecert_ratelimit_remaining_tokens`. Remaining on a bucket nobody writes returns Capacity by
// design, so three of those gauges were pinned at "full" forever and the alert on
// certs-per-exact-identifier-set -- the limit Let's Encrypt offers no override for -- could never
// fire. The spend happens where the certificate exists at the CA, not after the deploy: a deploy
// failure of ours does not give that budget back.
func TestAnIssuanceSpendsTheCertificateBudgets(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"a.example.com"})
	cert.Deploy.Enabled = false

	fixed := time.Now()
	m.now = func() time.Time { return fixed }
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: fixed.Add(24 * time.Hour),
		CertURL: "https://ca.test/cert/old", CertPEM: selfSignedCertPEM(t, fixed.Add(24*time.Hour), "a.example.com"),
		KeyPEM: []byte("old-key"),
	}); err != nil {
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
	fake.certNotAfter = fixed.Add(90 * 24 * time.Hour)
	fake.orders = []legoacme.ExtendedOrder{{
		Order:    legoacme.Order{Status: "valid", Certificate: "https://ca.test/new"},
		Location: "https://ca.test/order/new",
	}}

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	for _, tc := range []struct {
		limit ratelimit.Limit
		scope string
	}{
		{ratelimit.CertsPerExactIdentifierSet, cert.DomainKey()},
		{ratelimit.CertsPerRegisteredDomain, group.RegisteredDomain("a.example.com")},
	} {
		bucket, err := store.GetRateBucket(tc.limit.Name, tc.scope)
		if err != nil {
			t.Fatal(err)
		}
		if want := tc.limit.Capacity - 1; bucket.Tokens != want {
			t.Errorf("%s/%s was not spent: tokens=%v want %v (an unspent bucket reads as full, so the "+
				"published gauge and its alert are meaningless)", tc.limit.Name, tc.scope, bucket.Tokens, want)
		}
	}
}

// A Retry-After shorter than our own floor must be honoured.
//
// The checks ran in sequence with the fixed six-hour floor first, so a server asking for an hour
// was silently extended to six: the floor had already answered false. The adjacent comment claimed
// the opposite, and RFC 9773 makes Retry-After the time to come back, not a lower bound on our own
// polling interval.
func TestAShortRetryAfterShortensTheARICheckInterval(t *testing.T) {
	store, m, _, _ := newAPITestHarness(t, []string{"example.com"})
	_ = store
	checked := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

	st := &state.CertState{Name: "site", ARICheckedAt: checked, ARIRetryAfter: time.Hour}
	if m.ariCheckDue(st, checked.Add(30*time.Minute)) {
		t.Error("the server asked for an hour and only 30 minutes have passed: not due")
	}
	if !m.ariCheckDue(st, checked.Add(90*time.Minute)) {
		t.Error("the server asked for an hour and 90 minutes have passed: the check is due, but the " +
			"fixed six-hour floor made it wait until six")
	}

	// No Retry-After: the six-hour floor still applies, so renewalInfo is not polled for free.
	st = &state.CertState{Name: "site", ARICheckedAt: checked}
	if m.ariCheckDue(st, checked.Add(2*time.Hour)) {
		t.Error("without a Retry-After the floor must still hold the check back")
	}
	if !m.ariCheckDue(st, checked.Add(7*time.Hour)) {
		t.Error("past the floor the check is due again")
	}

	// A server asking for longer than our ceiling is clamped to the RFC's reasonableness bound.
	st = &state.CertState{Name: "site", ARICheckedAt: checked, ARIRetryAfter: 72 * time.Hour}
	if !m.ariCheckDue(st, checked.Add(25*time.Hour)) {
		t.Error("a 72h Retry-After is clamped to 24h, so at 25h the check is due again")
	}
	if m.ariCheckDue(st, checked.Add(23*time.Hour)) {
		t.Error("23h is still inside the clamped 24h window")
	}
}

// A failed bookkeeping write on the deploy path must cost a backoff, not a bare retry.
//
// The upload has already happened, so the id being persisted is the only local record of a cloud
// object (the resume anchor, or the reclaim list for a failed deploy). Returning the bare store
// error skipped recordFailure, so nothing escalated and the next pass ran at the pass rate --
// uploading another copy each time.
func TestAFailedDeployBookkeepingSchedulesARetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	fake := &fakeAPI{}
	dep := &stagedDeployer{uploadID: "cloud-new", rebindErr: errors.New("tencent: try later")}
	certs := []config.Certificate{{
		Name: "site-example-com", Domains: []string{"a.example.com"},
		Profile: config.ProfileClassic, KeyType: config.KeyTypeECDSAP256,
		Deploy: config.Deploy{Enabled: true},
	}}
	if err := config.NormalizeCertificates(certs); err != nil {
		t.Fatal(err)
	}
	cert := &certs[0]

	m := newManager(store, fake, &fakeSolver{}, fakeKeyAuth{}, dep,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	fake.orderDomains = func() []string { return cert.Domains }
	fake.orderKeyPEM = func() []byte {
		o, err := store.GetOrder(cert.Name)
		if err != nil || o == nil {
			return nil
		}
		return o.KeyPEM
	}

	now := time.Now()
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: now.Add(24 * time.Hour),
		CertURL: "https://acme.test/cert/old", CertPEM: selfSignedCertPEM(t, now.Add(24*time.Hour), "a.example.com"),
		KeyPEM: []byte("old-key"), DeployedCertID: "cloud-old", DeployConfirmed: true,
	}); err != nil {
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
	scriptDNS01Order(fake, cert.Domains)
	fake.certNotAfter = now.Add(90 * 24 * time.Hour)

	// Block the order write: the upload succeeds, the anchor cannot be recorded.
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	// Only the ANCHOR write is blocked: every other order update (advancing the order, recording the
	// certificate URL) must succeed, or the pass dies earlier and never reaches the deploy.
	if _, err := db.Exec(`CREATE TRIGGER block_anchor_update BEFORE UPDATE ON orders
		WHEN NEW.deployment_cert_id != OLD.deployment_cert_id
		BEGIN SELECT RAISE(FAIL, 'the anchor write is blocked by test'); END;`); err != nil {
		t.Fatal(err)
	}

	if err := m.Reconcile(context.Background(), cert); err == nil {
		t.Fatal("the store refused the anchor write, so the pass must be reported as failed")
	}
	got, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if got.ConsecutiveFailures == 0 || got.NextAttemptAt.IsZero() {
		t.Errorf("a failed deploy bookkeeping write recorded no failure (failures=%d nextAttempt=%v): "+
			"the next pass then re-uploads at the pass rate instead of backing off",
			got.ConsecutiveFailures, got.NextAttemptAt)
	}
	if dep.uploads == 0 {
		t.Error("this test needs the upload to have happened, or it is not testing the bookkeeping")
	}
}

// A timeout from inside a call is a business failure; only a stopped pass is not.
//
// The old filter was `errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)`,
// and net/http wraps its own request deadline in *url.Error, whose Unwrap is
// context.DeadlineExceeded. So the commonest CA-side failure there is -- a request that timed out --
// was filed as "pass cancelled": no consecutive_failures, no last_error, no backoff, and on a first
// issuance not even a certificate row for the next pass to find. The rule the code states is about
// the PASS being stopped, so the pass context is what decides.
func TestAnInnerTimeoutIsRecordedAsAFailure(t *testing.T) {
	store, m, _, cert := newAPITestHarness(t, []string{"example.com"})
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.SetNow(func() time.Time { return fixed })

	st := &state.CertState{Name: cert.Name, NotAfter: fixed.Add(30 * 24 * time.Hour)}
	if err := store.PutCert(st); err != nil {
		t.Fatal(err)
	}

	// The shape an http.Client timeout produces: a *url.Error wrapping the context error.
	inner := &url.Error{Op: "Post", URL: "https://acme-v02.api.letsencrypt.org/order",
		Err: context.DeadlineExceeded}
	if !errors.Is(inner, context.DeadlineExceeded) {
		t.Fatal("the fixture must wrap the sentinel, or this test proves nothing")
	}

	if err := m.recordFailure(context.Background(), st, inner); err == nil {
		t.Fatal("the failure has to be reported")
	}
	after, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if after.ConsecutiveFailures == 0 {
		t.Error("a request that timed out is a failure: without the counter the fallback trigger and " +
			"the pre-expiry degradation never see it")
	}
	if after.NextAttemptAt.IsZero() {
		t.Error("a timed-out request must schedule a retry; retrying at the pass rate hammers the CA " +
			"and burns the per-identifier failure budget")
	}
	if after.LastError == "" {
		t.Error("the operator has to be able to read what happened")
	}

	// The same error on a stopped pass is still not a failure.
	stopped, cancel := context.WithCancel(context.Background())
	cancel()
	before := after.ConsecutiveFailures
	if err := m.recordFailure(stopped, after, inner); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a stopped pass reports the error unchanged, got %v", err)
	}
	again, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if again.ConsecutiveFailures != before {
		t.Errorf("a stop signal must not count as a failure: %d -> %d", before, again.ConsecutiveFailures)
	}
}
