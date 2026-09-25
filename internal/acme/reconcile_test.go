package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	legoapi "github.com/go-acme/lego/v4/acme/api"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/state"
)

// fakeACME starts a minimal ACME directory (over TLS).
//
// It only implements enough to construct an api.Core and make NewOrder fail -- the point is
// not to emulate a CA but to make Reconcile's **decision path** observable: did it actually
// try to create an order.
type fakeACME struct {
	srv       *httptest.Server
	newOrders atomic.Int64

	// omitAccountLocation makes /new-account answer without a Location header, which is how a
	// registration response that carries no kid looks. Only the account tests set it.
	omitAccountLocation atomic.Bool

	// newAccounts counts newAccount calls; registrations holds the account key each one was
	// signed with. Registration is the one request a test can tie to a specific key, because
	// its JWS carries the account JWK rather than a kid (see registrationJWK).
	newAccounts atomic.Int64

	regMu         sync.Mutex
	registrations []*ecdsa.PublicKey
}

func newFakeACME(t *testing.T) *fakeACME {
	t.Helper()
	f := &fakeACME{}
	mux := http.NewServeMux()

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		// lego forces https (sender.newHTTPSOnly checks req.URL.Scheme), so the fake server
		// must speak TLS; srv.Client() comes with the test CA.
		base := "https://" + r.Host
		writeJSON(w, map[string]any{
			"newNonce":   base + "/new-nonce",
			"newAccount": base + "/new-account",
			"newOrder":   base + "/new-order",
			"revokeCert": base + "/revoke-cert",
			"keyChange":  base + "/key-change",
			// renewalInfo is deliberately omitted: GetRenewalInfo returns ErrNoARI, so the
			// renewal decision falls back to time-based logic and makes no extra requests.
		})
	})
	mux.HandleFunc("/new-nonce", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/new-order", func(w http.ResponseWriter, _ *http.Request) {
		f.newOrders.Add(1)
		// Fail explicitly so recordFailure runs to completion.
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{
			"type":   "urn:ietf:params:acme:error:malformed",
			"detail": "the fake test server does not accept order creation",
		})
	})
	mux.HandleFunc("/new-account", func(w http.ResponseWriter, r *http.Request) {
		f.newAccounts.Add(1)
		if key := registrationJWK(r); key != nil {
			f.regMu.Lock()
			f.registrations = append(f.registrations, key)
			f.regMu.Unlock()
		}
		if !f.omitAccountLocation.Load() {
			w.Header().Set("Location", "https://"+r.Host+"/acct/1")
		}
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]any{"status": "valid"})
	})

	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// registrationJWK decodes the public key a newAccount request was signed with.
//
// Registration is the one ACME request that cannot carry a kid -- the account does not exist
// yet -- so the JWS protected header carries the account key itself as a JWK, which is how a
// test proves WHICH key a registration used.
func registrationJWK(r *http.Request) *ecdsa.PublicKey {
	var body struct {
		Protected string `json:"protected"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(body.Protected)
	if err != nil {
		return nil
	}
	var protected struct {
		JWK struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"jwk"`
	}
	if err := json.Unmarshal(raw, &protected); err != nil || protected.JWK.Kty != "EC" {
		return nil
	}
	x, err := base64.RawURLEncoding.DecodeString(protected.JWK.X)
	if err != nil {
		return nil
	}
	y, err := base64.RawURLEncoding.DecodeString(protected.JWK.Y)
	if err != nil {
		return nil
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
}

// registeredKeys returns the account keys of every newAccount call so far, in order.
func (f *fakeACME) registeredKeys() []*ecdsa.PublicKey {
	f.regMu.Lock()
	defer f.regMu.Unlock()
	return append([]*ecdsa.PublicKey(nil), f.registrations...)
}

// selfSignedCertPEM builds a self-signed certificate with the given SANs, used to fill CertState.CertPEM.
func selfSignedCertPEM(t *testing.T, notAfter time.Time, dnsNames ...string) []byte {
	t.Helper()
	return selfSignedCertAt(t, time.Now().Add(-time.Hour), notAfter, dnsNames...)
}

// selfSignedCertAt is selfSignedCertPEM with an explicit NotBefore, for tests that must
// distinguish "issued after the live certificate" from "expires later than it" -- the two
// are not the same thing once a profile can get shorter.
func selfSignedCertAt(t *testing.T, notBefore, notAfter time.Time, dnsNames ...string) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		DNSNames:              dnsNames,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		AuthorityKeyId:        []byte{0x01, 0x02, 0x03},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("issue test certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// newReconcileHarness sets up "certificate already issued, still mid-lifetime".
func newReconcileHarness(t *testing.T, domains []string, certSANs []string) (*Manager, *state.Store, *fakeACME, *config.Certificate) {
	t.Helper()

	fake := newFakeACME(t)
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	httpClient := fake.srv.Client()
	// The account kid and private key are arbitrary: this test only cares whether an order was tried.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	core, err := legoapi.New(httpClient, "wecert-test", fake.srv.URL+"/directory", "kid-1", key)
	if err != nil {
		t.Fatalf("build api.Core: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	solver := &fakeSolver{}
	m := newManager(store, NewAPI(core), solver, fakeKeyAuth{}, deploy.Noop{}, log)

	// 90-day validity, freshly issued: still far from classic's 30-day renewal window.
	notAfter := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	certPEM := selfSignedCertPEM(t, notAfter, certSANs...)

	if err := store.PutCert(&state.CertState{
		Name:      "many-sans",
		NotAfter:  notAfter,
		CertPEM:   certPEM,
		KeyPEM:    []byte("irrelevant"),
		IssuedAt:  time.Now(),
		CertURL:   "https://acme.example/cert/old",
		ARICertID: "", // disable ARI so the decision falls back to time alone, avoiding extra requests
	}); err != nil {
		t.Fatalf("PutCert: %v", err)
	}

	domainsCopy := append([]string(nil), domains...)
	return m, store, fake, &config.Certificate{
		Name:           "many-sans",
		Domains:        domainsCopy,
		Profile:        config.ProfileClassic,
		KeyType:        config.KeyTypeECDSAP256,
		RenewBeforeDur: 30 * 24 * time.Hour,
		Deploy:         config.Deploy{Enabled: false},
	}
}

// The most important one: when the domain sets match, **do nothing**.
//
// This also verifies the other direction -- drift detection must not fire falsely and push a
// healthy certificate into reissuance: if this is wrong, every reconcile creates an order and
// hits "5 certs per exact set of identifiers / 7 days" within days.
func TestReconcileSkipsWhenDomainsMatch(t *testing.T) {
	domains := []string{"a.example.com", "b.example.com", "c.example.com"}
	m, _, fake, cert := newReconcileHarness(t, domains, domains)

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("domains match and no renewal window reached: no error expected, got %v", err)
	}
	if n := fake.newOrders.Load(); n != 0 {
		t.Errorf("no order should be created, but %d were -- this exhausts the rate-limit quota within days", n)
	}
}

// Set equality that ignores order and case must not be misread as drift.
func TestReconcileIgnoresDomainOrderAndCase(t *testing.T) {
	m, _, fake, cert := newReconcileHarness(t,
		[]string{"B.Example.com", "a.example.com"},
		[]string{"a.example.com", "b.example.com"},
	)

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("equivalent sets: no error expected, got %v", err)
	}
	if n := fake.newOrders.Load(); n != 0 {
		t.Errorf("equivalent sets were judged as drift and created %d orders", n)
	}
}

// Key regression: **adding a domain** to a live certificate must trigger reissuance right away,
// not wait for the renewal window 30 days out.
//
// "An order was actually attempted" is how we prove the decision path was taken -- real
// issuance needs a real ACME server and is out of scope for unit tests.
func TestReconcileReissuesImmediatelyWhenDomainAdded(t *testing.T) {
	live := []string{"a.example.com", "b.example.com"}
	m, store, fake, cert := newReconcileHarness(t, append(live, "new.example.com"), live)

	err := m.Reconcile(context.Background(), cert)
	if err == nil {
		t.Fatal("adding a domain must reissue immediately (the fake server rejects orders, so this must fail)")
	}
	if !strings.Contains(err.Error(), "create order") {
		t.Errorf("the error should come from order creation, proving issuance was really entered: %v", err)
	}
	if n := fake.newOrders.Load(); n != 1 {
		t.Errorf("should attempt to create exactly 1 order, got %d", n)
	}

	// The failure must be persisted and a backoff scheduled, otherwise every round re-hits the CA.
	st, gerr := store.GetCert("many-sans")
	if gerr != nil {
		t.Fatal(gerr)
	}
	if st.ConsecutiveFailures != 1 {
		t.Errorf("ConsecutiveFailures = %d, want 1", st.ConsecutiveFailures)
	}
	if st.NextAttemptAt.IsZero() {
		t.Error("the next attempt time (backoff) should be scheduled")
	}
}

// The reverse: **removing** a domain from the config must trigger reissuance too.
// Checking only for missing names would miss it, leaving a SAN the certificate should no longer have.
func TestReconcileReissuesImmediatelyWhenDomainRemoved(t *testing.T) {
	m, _, fake, cert := newReconcileHarness(t,
		[]string{"a.example.com"},
		[]string{"a.example.com", "b.example.com"},
	)

	if err := m.Reconcile(context.Background(), cert); err == nil {
		t.Fatal("removing a domain from the config should reissue immediately")
	}
	if n := fake.newOrders.Load(); n != 1 {
		t.Errorf("should attempt to create 1 order, got %d", n)
	}
}

// When a non-expired order exists and it matches the current config, keep advancing it
// instead of creating a new one -- the core invariant that avoids rate-limit hits.
func TestReconcileResumesMatchingOrderInsteadOfCreatingNew(t *testing.T) {
	domains := []string{"a.example.com", "b.example.com"}
	m, store, fake, cert := newReconcileHarness(t, domains, domains)

	if err := store.PutOrder(&state.Order{
		CertName:    "many-sans",
		OrderURL:    fake.srv.URL + "/order/1",
		FinalizeURL: fake.srv.URL + "/finalize/1",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		Status:      "pending",
		Identifiers: cert.DomainKey(),
	}); err != nil {
		t.Fatal(err)
	}

	// advance will look up the order; the fake server has no such endpoint -> error.
	// The point is that NewOrder must not happen even once.
	_ = m.Reconcile(context.Background(), cert)

	if n := fake.newOrders.Load(); n != 0 {
		t.Errorf("must not create a new order while a matching in-flight order exists, created %d", n)
	}
}

// Once the config changes, an in-flight order must be discarded -- otherwise we keep advancing
// an order whose finalize is bound to be rejected until it expires 7 days later.
//
// The setup mirrors the real thing: the live certificate still carries the **old** domain set,
// the config has already changed, and the in-flight order was created for the old set too.
// A single reconcile should both "discard the old order" and "reissue for the new domains".
func TestReconcileDiscardsStaleOrderAndReissues(t *testing.T) {
	oldDomains := []string{"a.example.com", "b.example.com"}
	newDomains := []string{"a.example.com", "b.example.com", "c.example.com"}

	// The live certificate holds the old set, the config holds the new one.
	m, store, fake, cert := newReconcileHarness(t, newDomains, oldDomains)

	// The in-flight order was created for the old set too.
	if err := store.PutOrder(&state.Order{
		CertName:    "many-sans",
		OrderURL:    fake.srv.URL + "/order/stale",
		FinalizeURL: fake.srv.URL + "/finalize/stale",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		Status:      "ready",
		Identifiers: config.DomainKey(oldDomains),
	}); err != nil {
		t.Fatal(err)
	}

	_ = m.Reconcile(context.Background(), cert)

	o, err := store.GetOrder("many-sans")
	if err != nil {
		t.Fatal(err)
	}
	if o != nil {
		t.Errorf("the old order should be discarded after the domain change, but it is still there: %+v", o)
	}
	if n := fake.newOrders.Load(); n != 1 {
		t.Errorf("after discarding the old order, a new one should be created for the new domains, created %d", n)
	}
}

// The converse: when the order does not match the config but the live certificate **already**
// does, discarding the order is enough -- do not reissue along the way, otherwise every
// reconcile pointlessly burns one order from the rate-limit quota.
func TestReconcileDiscardStaleOrderDoesNotForceReissue(t *testing.T) {
	domains := []string{"a.example.com", "b.example.com"}
	// The live certificate already carries exactly the set the config asks for.
	m, store, fake, cert := newReconcileHarness(t, domains, domains)

	// The in-flight order was created for a different (earlier) set.
	if err := store.PutOrder(&state.Order{
		CertName:    "many-sans",
		OrderURL:    fake.srv.URL + "/order/stale",
		FinalizeURL: fake.srv.URL + "/finalize/stale",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		Status:      "ready",
		Identifiers: config.DomainKey([]string{"a.example.com"}),
	}); err != nil {
		t.Fatal(err)
	}

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile should not return an error: %v", err)
	}

	if o, _ := store.GetOrder("many-sans"); o != nil {
		t.Errorf("the order for the stale set should be discarded: %+v", o)
	}
	if n := fake.newOrders.Load(); n != 0 {
		t.Errorf("certificate already matches the config and no renewal window was reached: created %d orders", n)
	}
}

// A cancelled context must never turn into an order.
//
// renewalDecision's error exits return a zero renewAt, and the zero time reads as "long
// overdue": without the guard, cancelling the shutdown context mid-round made Reconcile
// log the ARI error and then place a **real** new order -- spending exact-set rate-limit
// quota as the process was going down. The round must stop with the error instead.
func TestReconcileCancelledContextDoesNotPlaceOrder(t *testing.T) {
	domains := []string{"a.example.com", "b.example.com"}
	m, store, fake, cert := newReconcileHarness(t, domains, domains)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := m.Reconcile(ctx, cert)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled round must return the context error, got %v", err)
	}
	if n := fake.newOrders.Load(); n != 0 {
		t.Errorf("a cancelled round placed %d orders -- the zero renewAt was misread as 'overdue'", n)
	}

	// A cancellation is not a business failure: no backoff may be recorded either.
	st, gerr := store.GetCert("many-sans")
	if gerr != nil {
		t.Fatal(gerr)
	}
	if st.ConsecutiveFailures != 0 {
		t.Errorf("ConsecutiveFailures = %d, want 0 for a cancelled round", st.ConsecutiveFailures)
	}
}
