package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/state"
)

// fakeAPI records every ACME call and returns pre-scripted responses.
//
// It is the real payoff of narrowing Manager's dependency on *api.Core to an interface.
// The order state machine's correctness is entirely about **call order and arguments**:
//
//   - the order URL must be on disk before we contact the CA
//   - a renewal order must carry replaces, or we get no ARI rate-limit exemption
//   - the CSR must be DER, and must be submitted to the finalize URL
//
// None of the three errors out; they just quietly burn quota or no-op the rebind --
// exactly what most needs asserting, and in a test that needs no network.
//
// Previously the only way to cover these was a fake ACME HTTP server: it runs the whole
// flow, but cannot answer "what did it actually do first".
type fakeAPI struct {
	mu    sync.Mutex
	calls []string

	// beforeCall runs **before** each call, to assert "what the state store looks like now".
	//
	// Crash safety can only be verified this way: it asserts a **moment**, not a final outcome.
	// "the order ended up on disk" and "the order was on disk before contacting the CA" are
	// different; only the latter blocks a re-order when the process is killed mid-propagation.
	beforeCall func(call string)

	// orders is the script GetOrder returns in turn; once exhausted it keeps returning the
	// last one, so the polling loop converges instead of spinning.
	orders   []legoacme.ExtendedOrder
	orderIdx int

	// orderErr, when a beforeCall hook sets it, makes NewOrder fail. It models a CA that
	// refuses an order outright (an invalid authorization), which is a different failure
	// from a scripted order that later turns out invalid.
	orderErr error

	// authzByURL overrides GetAuthorization per authorization URL. URLs left out keep the
	// default "everything is valid" answer, so only the tests that need a failing -- or a
	// wildcard -- authorization have to populate it.
	authzByURL map[string]legoacme.Authorization

	// authzSeq is like authzByURL but scripts a progression: each GetAuthorization call
	// returns the next entry, and once exhausted keeps returning the last one, so the
	// polling loop converges ("pending" first, "valid" once validation lands).
	authzSeq    map[string][]legoacme.Authorization
	authzSeqIdx map[string]int

	// authzHits counts GetAuthorization per URL, so a test can tell "polled again"
	// from "polled once".
	authzHits map[string]int

	// certPEM overrides the certificate GetCertificate returns. Left nil, the fake issues
	// one for the CSR the flow actually finalized, the way a real CA does -- which also
	// means every flow test exercises "does the leaf belong to the order's key" instead of
	// only the one test dedicated to it.
	// newOrderReplaces records the ReplacesCertID of every NewOrder attempt, so a test can
	// assert not only what was sent but that it was retried without it.
	newOrderReplaces []string

	// revoked records RevokeCertificate calls, and revokeErr makes the next ones fail.
	revoked   []revokedCall
	revokeErr error

	// getOrderErr, when set, makes every GetOrder fail. It models an order URL that the CA
	// will never serve again (a purged order, or a different ACME directory).
	getOrderErr error

	// newOrderErr, when set, is returned by the next NewOrder call and then cleared. It
	// scripts "the CA refused this order" without making the fake stateful.
	newOrderErr error

	certPEM []byte
	certErr error

	// certNotAfter and certDomains shape an issued certificate. An unset certNotAfter means
	// 90 days; an empty certDomains means "the names the order was placed for".
	//
	// certNotAfterFn is the dynamic form, for tests whose clock moves: a renewal has to
	// come back with a certificate that is newer than the one already deployed, and a
	// pinned notAfter cannot express that once the live certificate was issued by an
	// earlier pass of the same test.
	certNotAfter   time.Time
	certNotAfterFn func() time.Time
	// certNotBefore overrides the issued certificate's NotBefore (default: an hour ago). A
	// test that must tell "issued later" apart from "expires later" sets it explicitly.
	certNotBefore time.Time
	certDomains   []string

	// orderKeyPEM lets the fake read the private key the flow generated for its order, so a
	// pass that resumes an order finalized in an earlier process still gets a usable
	// certificate back. Without it, the fake would have no public key to issue for when no
	// CSR was submitted in this process.
	orderKeyPEM func() []byte

	// orderDomains is what the certificate is being issued for, used when the fake has to
	// issue without a CSR. An empty result falls back to the domains NewOrder was called
	// with.
	orderDomains func() []string

	// Arguments captured from the calls.
	newOrderDomains []string
	newOrderOpts    *api.OrderOptions
	finalizeURL     string
	finalizeCSR     []byte
	accepted        []string
	// certBundle records the *argument* GetCertificate was called with. Setting it
	// unconditionally would make the "must ask for fullchain" assertion a tautology:
	// download could pass bundle=false and the suite would stay green, while the CLB
	// received a leaf with no intermediates.
	certBundle      bool
	renewalInfoHits int
}

func (f *fakeAPI) enter(call string) {
	f.mu.Lock()
	f.calls = append(f.calls, call)
	f.mu.Unlock()
	if f.beforeCall != nil {
		f.beforeCall(call)
	}
}

func (f *fakeAPI) callLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeAPI) NewOrder(domains []string, opts *api.OrderOptions) (legoacme.ExtendedOrder, error) {
	// Record the arguments BEFORE enter(), so a beforeCall hook observes the same
	// identifier set this call is ordering. Hooks that emulate a CA rejecting a
	// particular name need exactly that; a hook that only asserts "which call came
	// first" is unaffected either way.
	f.mu.Lock()
	f.newOrderDomains = append([]string(nil), domains...)
	f.newOrderOpts = opts
	replaces := ""
	if opts != nil {
		replaces = opts.ReplacesCertID
	}
	f.newOrderReplaces = append(f.newOrderReplaces, replaces)
	f.orderErr = nil
	f.mu.Unlock()

	f.enter("NewOrder")

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.newOrderErr != nil {
		err := f.newOrderErr
		f.newOrderErr = nil
		return legoacme.ExtendedOrder{}, err
	}
	if f.orderErr != nil {
		return legoacme.ExtendedOrder{}, f.orderErr
	}
	if len(f.orders) == 0 {
		return legoacme.ExtendedOrder{}, errors.New("fakeAPI: NewOrder has no scripted orders")
	}
	return f.orders[0], nil
}

func (f *fakeAPI) GetOrder(string) (legoacme.ExtendedOrder, error) {
	f.enter("GetOrder")
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getOrderErr != nil {
		return legoacme.ExtendedOrder{}, f.getOrderErr
	}
	if len(f.orders) == 0 {
		return legoacme.ExtendedOrder{}, errors.New("fakeAPI: GetOrder has no scripted orders")
	}
	o := f.orders[f.orderIdx]
	if f.orderIdx < len(f.orders)-1 {
		f.orderIdx++
	}
	return o, nil
}

func (f *fakeAPI) UpdateOrderForCSR(finalizeURL string, csr []byte) (legoacme.ExtendedOrder, error) {
	f.enter("UpdateOrderForCSR")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finalizeURL = finalizeURL
	f.finalizeCSR = append([]byte(nil), csr...)
	if len(f.orders) == 0 {
		return legoacme.ExtendedOrder{}, errors.New("fakeAPI: UpdateOrderForCSR has no scripted orders")
	}
	return f.orders[len(f.orders)-1], nil
}

func (f *fakeAPI) GetAuthorization(authzURL string) (legoacme.Authorization, error) {
	f.enter("GetAuthorization")
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.authzHits == nil {
		f.authzHits = make(map[string]int)
	}
	f.authzHits[authzURL]++
	if seq, ok := f.authzSeq[authzURL]; ok {
		if f.authzSeqIdx == nil {
			f.authzSeqIdx = make(map[string]int)
		}
		i := f.authzSeqIdx[authzURL]
		if i >= len(seq) {
			i = len(seq) - 1
		}
		f.authzSeqIdx[authzURL] = i + 1
		return seq[i], nil
	}
	if a, ok := f.authzByURL[authzURL]; ok {
		return a, nil
	}
	return legoacme.Authorization{Status: "valid", Identifier: legoacme.Identifier{Value: "a.example.com"}}, nil
}

// authorizationHits returns a copy of the per-URL GetAuthorization counts.
func (f *fakeAPI) authorizationHits() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]int, len(f.authzHits))
	for k, v := range f.authzHits {
		out[k] = v
	}
	return out
}

func (f *fakeAPI) AcceptChallenge(challengeURL string) error {
	f.enter("AcceptChallenge")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accepted = append(f.accepted, challengeURL)
	return nil
}

func (f *fakeAPI) GetCertificate(_ string, bundle bool) ([]byte, []byte, error) {
	f.enter("GetCertificate")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.certBundle = bundle
	if f.certErr != nil {
		return nil, nil, f.certErr
	}
	if f.certPEM != nil {
		return f.certPEM, []byte("key"), nil
	}
	return f.issueForCSR(), []byte("key"), nil
}

// issueForCSR signs a certificate for the key this order was placed with, the way a real CA
// does. The public key comes from the CSR when the flow finalized in this process, and from
// the order on disk otherwise.
//
// It must not be some other key: VerifyKeyMatch rejects anything else, so a fake that
// invented its own key would fail every flow test for the wrong reason.
func (f *fakeAPI) issueForCSR() []byte {
	var csr *x509.CertificateRequest
	if len(f.finalizeCSR) > 0 {
		parsed, err := x509.ParseCertificateRequest(f.finalizeCSR)
		if err != nil {
			return nil
		}
		csr = parsed
	}

	pub := crypto.PublicKey(nil)
	names := f.certDomains
	switch {
	case csr != nil:
		pub = csr.PublicKey
		if len(names) == 0 {
			names = csr.DNSNames
		}
	case f.orderKeyPEM != nil:
		key, err := ParsePrivateKeyPEM(f.orderKeyPEM())
		if err != nil {
			return nil
		}
		pub = key.Public()
	}
	if pub == nil {
		return nil
	}
	if len(names) == 0 {
		names = f.newOrderDomains
	}
	if len(names) == 0 && f.orderDomains != nil {
		names = f.orderDomains()
	}

	notAfter := f.certNotAfter
	if f.certNotAfterFn != nil {
		notAfter = f.certNotAfterFn()
	}
	if notAfter.IsZero() {
		notAfter = time.Now().Add(90 * 24 * time.Hour)
	}
	// tls.X509KeyPair-style self-signature: the fake CA is its own issuer, and nothing in
	// the download path verifies the chain (the network probe does that separately).
	notBefore := time.Now().Add(-time.Hour)
	if !f.certNotBefore.IsZero() {
		notBefore = f.certNotBefore
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     names,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		// A real CA always sets the Authority Key Identifier, and CertID needs it: without
		// one the ARI certID cannot be built and the next renewal loses its rate-limit
		// exemption.
		AuthorityKeyId:        []byte{0x01, 0x02, 0x03},
		BasicConstraintsValid: true,
	}
	// The signer is a throwaway: the issued certificate's *public* key is the CSR's, which
	// is all the download path looks at. Nothing here verifies the chain -- the network
	// probe covers that separately, against its own certificates.
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// GetRenewalInfo errors by default: ARI is optional, and an unscripted ARI call usually
// means the test's throttling is wrong. Failing loudly is easier to debug than an empty response.
// revoked records every RevokeCertificate call, so a test can assert that a revocation was
// attempted, with which reason, and how many times.
func (f *fakeAPI) RevokeCertificate(der []byte, reason int) error {
	f.enter("RevokeCertificate")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, revokedCall{Reason: reason, DERLen: len(der)})
	if f.revokeErr != nil {
		return f.revokeErr
	}
	return nil
}

type revokedCall struct {
	Reason int
	DERLen int
}

func (f *fakeAPI) GetRenewalInfo(string) (*http.Response, error) {
	f.enter("GetRenewalInfo")
	f.mu.Lock()
	f.renewalInfoHits++
	f.mu.Unlock()
	return nil, errors.New("fakeAPI: ARI is not scripted")
}

func (f *fakeAPI) GetKeyAuthorization(token string) (string, error) {
	return "keyauth(" + token + ")", nil
}

// ---------- scaffolding ----------

// terminalOrder returns an order that is "already issued".
//
// Every test scripts a converging order sequence: if the fake GetOrder kept returning
// pending, the state machine would dutifully poll until the 2-minute timeout -- making
// the package's tests unusably slow, and hiding what the test actually wants to assert.
func terminalOrder(location, finalize, certURL string) legoacme.ExtendedOrder {
	return legoacme.ExtendedOrder{
		Order:    legoacme.Order{Status: "valid", Finalize: finalize, Certificate: certURL},
		Location: location,
	}
}

func newAPITestHarness(t *testing.T, domains []string) (*state.Store, *Manager, *fakeAPI, *config.Certificate) {
	t.Helper()

	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	fake := &fakeAPI{}
	m := newManager(store, fake, &fakeSolver{}, fakeKeyAuth{}, deploy.Noop{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	certs := []config.Certificate{{
		Name:    "site-example-com",
		Domains: domains,
		Profile: config.ProfileClassic,
		KeyType: config.KeyTypeECDSAP256,
		Deploy:  config.Deploy{Enabled: false},
	}}
	if err := config.NormalizeCertificates(certs); err != nil {
		t.Fatalf("normalize certificate: %v", err)
	}
	// The certificate the fake returns has to belong to the key the order was placed with,
	// and that key is generated inside the flow -- so the fake reads it back from the store.
	fake.orderKeyPEM = func() []byte {
		o, err := store.GetOrder(certs[0].Name)
		if err != nil || o == nil {
			return nil
		}
		return o.KeyPEM
	}
	fake.orderDomains = func() []string { return certs[0].Domains }
	return store, m, fake, &certs[0]
}

// ---------- invariant 1: the order URL is on disk before we contact the CA ----------

// This is the entire basis of crash safety.
//
// If the order URL is not on disk, a process killed during those minutes of DNS
// propagation places a new order whose identifier set is exactly the same as the
// previous one -- walking straight into "5 certificates per exact set of identifiers / 7 days",
// with no override to appeal for.
func TestOrderURLIsOnDiskBeforeTheNextACMECall(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"a.example.com"})

	fake.orders = []legoacme.ExtendedOrder{
		{
			Order:    legoacme.Order{Status: "pending", Finalize: "https://ca.test/finalize/1"},
			Location: "https://ca.test/order/1",
		},
		terminalOrder("https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/1"),
	}

	var checked bool
	fake.beforeCall = func(call string) {
		// The call after NewOrder is the state machine reading the order; by then the write must be on disk.
		if call != "GetOrder" || checked {
			return
		}
		checked = true

		o, err := store.GetOrder(cert.Name)
		if err != nil {
			t.Fatalf("read order: %v", err)
		}
		if o == nil {
			t.Fatal("the order URL must be on disk before we contact the CA: a kill here makes the restart" +
				" place another order for the same identifier set and hit the unrecoverable 7-day limit")
		}
		if o.OrderURL != "https://ca.test/order/1" {
			t.Fatalf("persisted order URL = %q, want https://ca.test/order/1", o.OrderURL)
		}
		// The finalize URL must be persisted alongside it: this is the only time we get it.
		if o.FinalizeURL != "https://ca.test/finalize/1" {
			t.Fatalf("persisted finalize URL = %q", o.FinalizeURL)
		}
		// The identifier set must be recorded too, or a later config change goes unnoticed.
		if o.Identifiers != cert.DomainKey() {
			t.Fatalf("persisted identifier fingerprint = %q, want %q", o.Identifiers, cert.DomainKey())
		}
	}

	_ = m.Reconcile(context.Background(), cert)

	if !checked {
		t.Fatalf("GetOrder was never called on the fake; this test verified nothing (calls: %v)", fake.callLog())
	}
}

// ---------- invariant 2: a renewal must carry replaces ----------

// An order without replaces gets no ARI rate-limit exemption -- and it does not error,
// it just makes this issuance genuinely consume "50 per registered domain / 7 days".
// Silent failures like this are exactly why the fake needs to assert call arguments.
func TestRenewalCarriesTheReplacesCertID(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"a.example.com"})

	now := m.now()
	const certID = "YWJj.ZGVm"

	// The whole ARI window is in the past, so renewal is due now.
	// ARICheckedAt is set to "just checked", which throttles the ARI fetch step,
	// so this test only cares about what the order was placed with.
	if err := store.PutCert(&state.CertState{
		Name:           cert.Name,
		NotAfter:       now.Add(20 * 24 * time.Hour),
		ARICertID:      certID,
		ARIWindowStart: now.Add(-2 * time.Hour),
		ARIWindowEnd:   now.Add(-time.Hour),
		ARICheckedAt:   now,
	}); err != nil {
		t.Fatal(err)
	}

	fake.orders = []legoacme.ExtendedOrder{
		{
			Order:    legoacme.Order{Status: "pending", Finalize: "https://ca.test/finalize/2"},
			Location: "https://ca.test/order/2",
		},
		terminalOrder("https://ca.test/order/2", "https://ca.test/finalize/2", "https://ca.test/cert/2"),
	}

	_ = m.Reconcile(context.Background(), cert)

	if fake.newOrderOpts == nil {
		t.Fatalf("expected a renewal order, call sequence: %v", fake.callLog())
	}
	if fake.newOrderOpts.ReplacesCertID != certID {
		t.Errorf("the order must carry replaces=%q (the precondition for the ARI exemption), got %q",
			certID, fake.newOrderOpts.ReplacesCertID)
	}
	if fake.newOrderOpts.Profile != config.ProfileClassic {
		t.Errorf("the profile should be passed through to the CA, got %q", fake.newOrderOpts.Profile)
	}
	if fake.renewalInfoHits != 0 {
		t.Errorf("ARICheckedAt was just set, so ARI must not be refetched; got %d fetches", fake.renewalInfoHits)
	}
}

// ---------- invariant 3: the CSR is DER and goes to the finalize URL ----------

// Both of these have bitten us:
//
//   - pass PEM and asn1 says "tags don't match"
//   - submit to the order URL and you get "POST-as-GET requests must have an empty payload"
//
// lego happens to name that parameter orderURL, which makes the latter especially easy to hit.
func TestCSRIsDERAndGoesToTheFinalizeURL(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"a.example.com", "b.example.com"})

	key, err := GenerateKey(cert.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := MarshalPrivateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}

	const orderURL = "https://ca.test/order/9"
	const finalizeURL = "https://ca.test/finalize/9"
	const certURL = "https://ca.test/cert/9"

	if err := store.PutOrder(&state.Order{
		CertName:    cert.Name,
		OrderURL:    orderURL,
		FinalizeURL: finalizeURL,
		Status:      "ready",
		KeyPEM:      keyPEM,
		Identifiers: cert.DomainKey(),
	}); err != nil {
		t.Fatal(err)
	}

	// Status ready means go straight to finalize; no challenge needs pushing.
	fake.orders = []legoacme.ExtendedOrder{
		{Order: legoacme.Order{Status: "ready", Finalize: finalizeURL}, Location: orderURL},
		{Order: legoacme.Order{Status: "valid", Finalize: finalizeURL, Certificate: certURL}, Location: orderURL},
	}

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if fake.finalizeURL != finalizeURL {
		t.Errorf("the CSR must go to finalize URL %q, went to %q (LE reads an order URL as POST-as-GET)",
			finalizeURL, fake.finalizeURL)
	}

	// DER, not PEM: PEM makes the CA report asn1 "tags don't match".
	if len(fake.finalizeCSR) == 0 {
		t.Fatal("no CSR was captured")
	}
	req, err := x509.ParseCertificateRequest(fake.finalizeCSR)
	if err != nil {
		t.Fatalf("the submitted CSR is not DER (PEM yields asn1 tags don't match): %v", err)
	}
	if err := req.CheckSignature(); err != nil {
		t.Errorf("CSR signature check: %v", err)
	}
	if got := len(req.DNSNames); got != len(cert.Domains) {
		t.Errorf("CSR has %d names, want %d: %v", got, len(cert.Domains), req.DNSNames)
	}

	if !fake.certBundle {
		t.Error("the certificate download must ask for fullchain (bundle=true); that is the format CLB needs")
	}

	// Finally the certificate must actually reach the state store, or this whole round was for nothing.
	st, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if st == nil || st.NotAfter.IsZero() {
		t.Fatalf("certificate was not persisted: %+v", st)
	}
	if st.ARICertID == "" {
		t.Error("the ARI certID must be derived from the certificate; the next renewal depends on that exemption")
	}
}

// The state machine must not call AcceptChallenge again on an already-valid authorization.
//
// Re-notifying does not error, but it is a wasted round trip every round; more important,
// an implementation that re-pushes the challenge every round hides real progress problems.
func TestChallengesAreAcceptedOncePerAuthorization(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"a.example.com"})

	key, err := GenerateKey(cert.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := MarshalPrivateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}

	if err := store.PutOrder(&state.Order{
		CertName:    cert.Name,
		OrderURL:    "https://ca.test/order/3",
		FinalizeURL: "https://ca.test/finalize/3",
		Status:      "pending",
		KeyPEM:      keyPEM,
		Identifiers: cert.DomainKey(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutAuthorization(&state.Authorization{
		CertName:       cert.Name,
		AuthzURL:       "https://ca.test/authz/1",
		Identifier:     "a.example.com",
		Status:         "valid",
		ChallengeURL:   "https://ca.test/chall/1",
		ChallengeToken: "tok-1",
	}); err != nil {
		t.Fatal(err)
	}

	// The order sits at pending while the authorization is already valid: no challenge should be pushed.
	fake.orders = []legoacme.ExtendedOrder{
		{
			Order:    legoacme.Order{Status: "pending", Finalize: "https://ca.test/finalize/3"},
			Location: "https://ca.test/order/3",
		},
		terminalOrder("https://ca.test/order/3", "https://ca.test/finalize/3", "https://ca.test/cert/3"),
	}

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if len(fake.accepted) != 0 {
		t.Errorf("the authorization is already valid, so no challenge should be pushed; got %v", fake.accepted)
	}

	// Half this test's value is confirming the call sequence really is the steps we think it is.
	t.Logf("call sequence: %v", fake.callLog())
}

func TestAwaitAuthorizationInvalidRecordsIdentifierFailure(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"bad.example.com"})
	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return fixed }
	fake.authzByURL = map[string]legoacme.Authorization{
		"https://ca.test/authz/bad": {Status: "invalid", Identifier: legoacme.Identifier{Value: "bad.example.com"}, Challenges: []legoacme.Challenge{{Type: "dns-01", Error: &legoacme.ProblemDetails{Detail: "NXDOMAIN"}}}},
	}
	err := m.awaitAuthorizations(context.Background(), []*state.Authorization{{CertName: cert.Name, AuthzURL: "https://ca.test/authz/bad", Identifier: "bad.example.com"}})
	if err == nil {
		t.Fatal("invalid authorization must fail")
	}
	got, err := store.ListIdentifierFailures(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Identifier != "bad.example.com" || got[0].Failures != 1 {
		t.Fatalf("invalid authorization must enter the fallback ledger, got %+v", got)
	}
}

// ── every persistOrder call site must honour its error ─────────────────────

// persistOrder returns its write error so a failed write aborts the step instead
// of being logged and forgotten: crash recovery would otherwise resume from stale
// state, which is the invariant the whole package is built around. There are three
// call sites, and Go does not warn about a dropped return value -- so this pins the
// one in advance(), which the contract change originally missed.
func TestAdvanceAbortsWhenTheOrderCannotBePersisted(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"a.example.com"})

	fake.orders = []legoacme.ExtendedOrder{{
		Order:    legoacme.Order{Status: "pending", Finalize: "https://ca.test/finalize/1"},
		Location: "https://ca.test/order/1",
	}}

	o := &state.Order{CertName: cert.Name, OrderURL: "https://ca.test/order/1", Status: "pending"}
	st := &state.CertState{Name: cert.Name}

	// Closing the store makes every write fail, which is the situation the error
	// return exists for. recordFailure joins its own write error onto this one, so
	// the original message has to survive into what the caller sees.
	if err := store.Close(); err != nil {
		t.Fatalf("closing the store: %v", err)
	}

	err := m.advance(context.Background(), cert, st, o, round{})
	if err == nil {
		t.Fatal("a failed order write must abort the step; discarding it means recovery resumes from stale state")
	}
	if !strings.Contains(err.Error(), "order state") {
		t.Errorf("want the error to name the failed order write, got: %v", err)
	}
}

// ── the authorization wait loop must not re-poll what already concluded ─────

// awaitAuthorizations used to fetch and re-persist *every* authorization on every
// poll round. For a 25-name certificate that takes its whole 3-minute budget that
// is ~1500 CA round trips and ~1500 upserts, of which only the first 25 ever carry
// new information -- and each upsert is its own WAL commit.
func TestAwaitAuthorizationsStopsPollingConcludedAuthorizations(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"a.example.com", "b.example.com", "c.example.com"})

	const (
		aURL = "https://ca.test/authz/a"
		bURL = "https://ca.test/authz/b"
		cURL = "https://ca.test/authz/c"
	)
	fake.orders = []legoacme.ExtendedOrder{{
		Order: legoacme.Order{
			Status:         "pending",
			Finalize:       "https://ca.test/finalize/1",
			Authorizations: []string{aURL, bURL, cURL},
		},
		Location: "https://ca.test/order/1",
	}}
	fake.authzByURL = map[string]legoacme.Authorization{
		aURL: {Status: "valid", Identifier: legoacme.Identifier{Value: "a.example.com"}},
		bURL: {Status: "valid", Identifier: legoacme.Identifier{Value: "b.example.com"}},
		// Never concludes, so the loop keeps polling until its budget is gone.
		cURL: {Status: "pending", Identifier: legoacme.Identifier{Value: "c.example.com"}},
	}

	// A short budget with a very short interval gives many rounds and no real waiting.
	m.authzWait = 200 * time.Millisecond
	m.pollInterval = time.Millisecond

	var authzs []*state.Authorization
	for _, u := range []string{aURL, bURL, cURL} {
		a := &state.Authorization{CertName: cert.Name, AuthzURL: u, Status: "pending"}
		if err := store.PutAuthorization(a); err != nil {
			t.Fatalf("PutAuthorization: %v", err)
		}
		authzs = append(authzs, a)
	}

	if err := m.awaitAuthorizations(context.Background(), authzs); err == nil {
		t.Fatal("an authorization that never concludes must exhaust the budget and error")
	}

	hits := fake.authorizationHits()
	if hits[aURL] != 1 || hits[bURL] != 1 {
		t.Errorf("a concluded authorization must be polled exactly once, got a=%d b=%d",
			hits[aURL], hits[bURL])
	}
	if hits[cURL] < 2 {
		t.Errorf("the pending authorization must keep being polled, got %d", hits[cURL])
	}
}

// ── a processing order goes straight to "wait for valid, download" ──────────

// A "processing" order means the CSR is already with the CA (a previous pass submitted it
// and died before seeing the result). Falling into the pending branch re-solves challenges
// that no longer exist and then waits for "ready" -- a state a processing order never
// revisits -- until orderWaitTimeout, recording a spurious ConsecutiveFailures on an order
// that was on track the whole time.
func TestAdvanceProcessingOrderWaitsForValidAndDownloads(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"a.example.com"})

	key, err := GenerateKey(cert.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := MarshalPrivateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}

	const orderURL = "https://ca.test/order/7"
	const finalizeURL = "https://ca.test/finalize/7"
	const certURL = "https://ca.test/cert/7"
	if err := store.PutOrder(&state.Order{
		CertName: cert.Name, OrderURL: orderURL, FinalizeURL: finalizeURL,
		Status: "processing", KeyPEM: keyPEM, Identifiers: cert.DomainKey(),
	}); err != nil {
		t.Fatal(err)
	}

	fake.orders = []legoacme.ExtendedOrder{
		{
			Order: legoacme.Order{
				Status:   "processing",
				Finalize: finalizeURL,
				// The authorizations exist but are none of this pass's business any more:
				// the pending branch would re-fetch and re-solve them, the processing
				// branch must not touch them at all.
				Authorizations: []string{"https://ca.test/authz/done"},
			},
			Location: orderURL,
		},
		terminalOrder(orderURL, finalizeURL, certURL),
	}

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// No challenges may be re-solved and the CSR must not be re-submitted.
	if hits := fake.authorizationHits(); len(hits) != 0 {
		t.Errorf("a processing order must not touch authorizations, got %v", hits)
	}
	if len(fake.accepted) != 0 {
		t.Errorf("a processing order must not re-push challenges, got %v", fake.accepted)
	}
	if fake.finalizeURL != "" {
		t.Errorf("the CSR was already submitted by the previous pass; resubmitting went to %q", fake.finalizeURL)
	}

	st, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if st.NotAfter.IsZero() {
		t.Error("the certificate was not persisted; the processing order was not seen through to download")
	}
	if st.ConsecutiveFailures != 0 {
		t.Errorf("ConsecutiveFailures = %d, want 0: waiting out a healthy processing order is not a failure", st.ConsecutiveFailures)
	}
}

// ── idempotent Present: an interrupted pass must not duplicate the TXT ──────

// seedInterruptedPass builds "order pending + authorization row with a challenge token but
// Presented=false" -- exactly what a crash (or a failed persist) between the DNS write and
// the state update leaves behind. The DNS write itself already happened; what the next
// round does about it is what these tests pin down.
func seedInterruptedPass(t *testing.T, store *state.Store, cert *config.Certificate, authzURL string) {
	t.Helper()
	seedInterruptedPassWithToken(t, store, cert, authzURL, "tok-1")
}

func seedInterruptedPassWithToken(t *testing.T, store *state.Store, cert *config.Certificate, authzURL, token string) {
	t.Helper()

	key, err := GenerateKey(cert.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := MarshalPrivateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutOrder(&state.Order{
		CertName: cert.Name, OrderURL: "https://ca.test/order/8", FinalizeURL: "https://ca.test/finalize/8",
		Status: "pending", KeyPEM: keyPEM, Identifiers: cert.DomainKey(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutAuthorization(&state.Authorization{
		CertName: cert.Name, AuthzURL: authzURL, Identifier: "example.com",
		Status: "pending", ChallengeURL: "https://ca.test/chall/1", ChallengeToken: token,
		Presented: false,
	}); err != nil {
		t.Fatal(err)
	}
}

func scriptPendingThenValid(fake *fakeAPI, authzURL string) {
	pending := legoacme.Authorization{
		Status:     "pending",
		Identifier: legoacme.Identifier{Value: "example.com"},
		Challenges: []legoacme.Challenge{{Type: "dns-01", URL: "https://ca.test/chall/1", Token: "tok-1"}},
	}
	valid := pending
	valid.Status = "valid"
	fake.authzSeq = map[string][]legoacme.Authorization{authzURL: {pending, valid}}
	fake.orders = []legoacme.ExtendedOrder{
		{
			Order: legoacme.Order{
				Status:         "pending",
				Finalize:       "https://ca.test/finalize/8",
				Authorizations: []string{authzURL},
			},
			Location: "https://ca.test/order/8",
		},
		terminalOrder("https://ca.test/order/8", "https://ca.test/finalize/8", "https://ca.test/cert/8"),
	}
}

// The record from the interrupted pass is still up: adopt it, do not write a duplicate.
func TestSolveChallengesAdoptsTXTFromInterruptedPass(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	solver := &fakeSolver{lookupFound: true}
	m.dns = solver

	const authzURL = "https://ca.test/authz/1"
	seedInterruptedPass(t, store, cert, authzURL)
	scriptPendingThenValid(fake, authzURL)

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	solver.mu.Lock()
	presented := append([]string(nil), solver.presented...)
	lookups := append([]string(nil), solver.lookups...)
	solver.mu.Unlock()

	if len(presented) != 0 {
		t.Errorf("the old record is already up, so Present must not run -- that duplicates the TXT; got %v", presented)
	}
	if len(lookups) == 0 || lookups[0] != "example.com" {
		t.Errorf("the adoption path must probe for the old record first, got lookups %v", lookups)
	}
}

// The token stored in the row can be stale: an earlier pass recorded the challenge it was
// solving, and the CA later handed out a different challenge for the same authorization.
// If the row keeps the old token it no longer hashes to its own TxtValue, and cleanup then
// derives a value that was never registered -- CleanUp reads that as "another challenge is
// still live at this name" and the provider's delete-all never fires again for the name,
// stranding every later TXT record there.
func TestSolveChallengesRefreshesAStaleChallengeToken(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	solver := &fakeSolver{lookupFound: false}
	m.dns = solver

	const authzURL = "https://ca.test/authz/1"
	// The interrupted pass was solving "tok-stale"; the live challenge now carries "tok-1".
	seedInterruptedPassWithToken(t, store, cert, authzURL, "tok-stale")
	scriptPendingThenValid(fake, authzURL)

	// solveChallenges rather than Reconcile: a successful Reconcile ends by discarding the
	// order, which deletes the authorization rows.
	order := legoacme.ExtendedOrder{
		Order: legoacme.Order{
			Status:         "pending",
			Finalize:       "https://ca.test/finalize/8",
			Authorizations: []string{authzURL},
		},
		Location: "https://ca.test/order/8",
	}
	ok, err := m.solveChallenges(context.Background(), cert, &state.CertState{Name: cert.Name}, order)
	if err != nil || !ok {
		t.Fatalf("solveChallenges = %v, %v", ok, err)
	}

	rows, err := store.ListAuthorizations(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one authorization row, got %d", len(rows))
	}
	// The row has to describe the challenge this pass actually solved, so its token and
	// its value agree.
	if rows[0].ChallengeToken != "tok-1" {
		t.Errorf("the row must carry the live challenge token, got %q", rows[0].ChallengeToken)
	}
	if rows[0].TxtValue != "txt-tok-1" {
		t.Errorf("TxtValue must be the value written for the live token, got %q", rows[0].TxtValue)
	}
}

// A store failure while solving a challenge must still count as a failure.
//
// Four PutAuthorization calls inside solveChallenges used to `return false, err` directly, which
// skips recordFailure: ConsecutiveFailures stays 0, NextAttemptAt stays unset, LastError stays
// empty. Nothing then backs off and nothing escalates -- a persistent write failure (a full disk, or
// SQLITE_BUSY while another process holds the write lock) is retried on every single pass forever,
// and the certificate's own metrics keep reporting a healthy zero failures. The invariant is written
// down in advance(): returning early "would skip backoff entirely".
func TestStoreFailureWhileSolvingCountsAsAPassFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := state.Open(path)
	if err != nil {
		t.Fatalf("open state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	fake := &fakeAPI{}
	m := newManager(store, fake, &fakeSolver{lookupFound: false}, fakeKeyAuth{}, deploy.Noop{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	cert := &config.Certificate{Name: "site-example-com", Domains: []string{"example.com"}}
	if err := config.NormalizeCertificates([]config.Certificate{*cert}); err != nil {
		t.Fatal(err)
	}
	cert = &config.Certificate{Name: "site-example-com", Domains: []string{"example.com"}, Profile: config.ProfileClassic, KeyType: config.KeyTypeECDSAP256}

	const authzURL = "https://ca.test/authz/1"
	seedInterruptedPassWithToken(t, store, cert, authzURL, "tok-1")
	scriptPendingThenValid(fake, authzURL)

	// Fail the write the solver has to make, through a second connection: a BEFORE UPDATE trigger
	// leaves every other statement working, which is exactly the "one write is broken" case.
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open second connection: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`CREATE TRIGGER block_authz_update BEFORE UPDATE ON authorizations
		BEGIN SELECT RAISE(FAIL, 'authorization update blocked by test'); END;`); err != nil {
		t.Fatalf("block authorization updates: %v", err)
	}

	st := &state.CertState{Name: cert.Name}
	order := legoacme.ExtendedOrder{
		Order: legoacme.Order{
			Status:         "pending",
			Finalize:       "https://ca.test/finalize/8",
			Authorizations: []string{authzURL},
		},
		Location: "https://ca.test/order/8",
	}

	if ok, err := m.solveChallenges(context.Background(), cert, st, order); err == nil || ok {
		t.Fatalf("with the store refusing the write this pass cannot have succeeded: ok=%v err=%v", ok, err)
	}

	after, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if after == nil {
		t.Fatal("no certificate row was written for a pass that failed on a store error, so the " +
			"failure is not recorded at all: no counter, no backoff, no LastError")
	}
	if after.ConsecutiveFailures == 0 {
		t.Error("a pass that failed on a store error left ConsecutiveFailures at 0, so nothing backs " +
			"off and nothing escalates: the same write is retried on every pass forever")
	}
	if after.NextAttemptAt.IsZero() {
		t.Error("no backoff was scheduled for a pass that failed on a store error")
	}
}

// A refreshed challenge must actually be accepted.
//
// ChallengeSent belongs to the challenge it was set for. When the CA hands back a different one for
// the same authorization, the old "already sent" flag is about a challenge that no longer exists --
// and phase 3 skips any row whose flag is set, so the new TXT would be written, never announced, and
// the order would sit pending until it expired (up to the 7-day order TTL) with nothing counting it.
func TestSolveChallengesAcceptsARefreshedChallenge(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	solver := &fakeSolver{lookupFound: false}
	m.dns = solver

	const authzURL = "https://ca.test/authz/1"
	seedInterruptedPassWithToken(t, store, cert, authzURL, "tok-stale")

	// The earlier pass had announced the challenge it held then, so the row says so.
	rows, err := store.ListAuthorizations(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one authorization row, got %d", len(rows))
	}
	rows[0].ChallengeSent = true
	if err := store.PutAuthorization(rows[0]); err != nil {
		t.Fatal(err)
	}

	// The live challenge now carries a different token, which is what the CA is waiting for.
	scriptPendingThenValid(fake, authzURL)

	order := legoacme.ExtendedOrder{
		Order: legoacme.Order{
			Status:         "pending",
			Finalize:       "https://ca.test/finalize/8",
			Authorizations: []string{authzURL},
		},
		Location: "https://ca.test/order/8",
	}
	ok, err := m.solveChallenges(context.Background(), cert, &state.CertState{Name: cert.Name}, order)
	if err != nil || !ok {
		t.Fatalf("solveChallenges = %v, %v", ok, err)
	}

	if len(fake.accepted) == 0 {
		t.Error("the row was pointing at a challenge the CA has never been told about, so it must be " +
			"announced; accepting nothing leaves the order pending until it expires")
	}
}

// The probe finds nothing (the write really never happened): write the record. Also pins
// the computed challenge name: production stores the bare apex as the identifier, and the
// TXT name must come out as _acme-challenge.example.com.
func TestSolveChallengesPresentsWhenProbeMisses(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	solver := &fakeSolver{lookupFound: false}
	m.dns = solver

	const authzURL = "https://ca.test/authz/1"
	seedInterruptedPass(t, store, cert, authzURL)
	scriptPendingThenValid(fake, authzURL)

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	solver.mu.Lock()
	presented := append([]string(nil), solver.presented...)
	records := append([]DNSRecord(nil), solver.records...)
	solver.mu.Unlock()

	if len(presented) != 1 || presented[0] != "example.com|tok-1" {
		t.Errorf("a probe miss must write the record exactly once, got %v", presented)
	}
	if len(records) != 1 || records[0].FQDN != "_acme-challenge.example.com." {
		t.Errorf("the computed challenge name must be _acme-challenge.example.com., got %+v", records)
	}
}

// ── an invalid order must back off even when discarding it fails ───────────

// advance's invalid branch used to return the discard error early, before recordFailure.
// A transient store error (exactly when discardOrder fails) then made the next round
// place a fresh order immediately, bypassing the backoff -- burning exact-set quota,
// which the backoff exists to prevent.
func TestAdvanceInvalidOrderBacksOffEvenWhenDiscardFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := state.Open(path)
	if err != nil {
		t.Fatalf("open state store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	fake := &fakeAPI{}
	m := newManager(store, fake, &fakeSolver{}, fakeKeyAuth{}, deploy.Noop{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	cert := &config.Certificate{Name: "c", Domains: []string{"a.example.com"}}

	// Make only DeleteOrder fail, through a second connection: a BEFORE DELETE trigger
	// leaves every other write (persistOrder's upsert, recordFailure's PutCert) working,
	// which is exactly the "transient store error mid-step" this test is about.
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open second connection: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`CREATE TRIGGER block_order_delete BEFORE DELETE ON orders
		BEGIN SELECT RAISE(FAIL, 'order delete blocked by test'); END;`); err != nil {
		t.Fatalf("block order deletes: %v", err)
	}

	fake.orders = []legoacme.ExtendedOrder{{
		Order:    legoacme.Order{Status: "invalid"},
		Location: "https://ca.test/order/1",
	}}

	o := &state.Order{CertName: cert.Name, OrderURL: "https://ca.test/order/1", Status: "pending"}
	st := &state.CertState{Name: cert.Name}

	err = m.advance(context.Background(), cert, st, o, round{})
	if err == nil {
		t.Fatal("an invalid order must fail the pass")
	}
	if !strings.Contains(err.Error(), "order became invalid") {
		t.Errorf("the order failure must survive into the returned error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "order delete blocked") {
		t.Errorf("the discard failure must be joined into the returned error, got: %v", err)
	}

	// The whole point: the failure was recorded, so the next round backs off instead of
	// immediately placing a fresh order.
	if st.ConsecutiveFailures != 1 {
		t.Errorf("ConsecutiveFailures = %d, want 1: a transient discard error must not skip the backoff",
			st.ConsecutiveFailures)
	}
	if st.NextAttemptAt.IsZero() {
		t.Error("NextAttemptAt is unset: the next round would place a fresh order immediately")
	}
}

// ── a resumed TXT that never propagates is re-presented next round ─────────

// A row resumed as Presented=true is never re-written by the pass -- but its record may
// have been deleted out of band (DNS console, account cleanup). WaitAll is the only
// remaining check, and when it fails the row must go back to Presented=false: otherwise
// every round burns the whole propagation budget waiting for a record that will never
// appear, until the order expires.
func TestSolveChallengesMarksResumedTXTUnpresentedWhenPropagationFails(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	solver := &fakeSolver{waitErr: errors.New("TXT propagation not confirmed: waited 5m")}
	m.dns = solver

	const authzURL = "https://ca.test/authz/1"
	seedInterruptedPass(t, store, cert, authzURL)
	// Upgrade the row to "an earlier pass wrote the record and marked it" -- the resume
	// shape this test is about.
	if err := store.PutAuthorization(&state.Authorization{
		CertName: cert.Name, AuthzURL: authzURL, Identifier: "example.com",
		Status: "pending", ChallengeURL: "https://ca.test/chall/1", ChallengeToken: "tok-1",
		TxtName: "_acme-challenge.example.com.", TxtValue: "txt-tok-1", Presented: true,
	}); err != nil {
		t.Fatal(err)
	}
	scriptPendingThenValid(fake, authzURL)

	if err := m.Reconcile(context.Background(), cert); err == nil {
		t.Fatal("a failed propagation wait must fail the round")
	}

	solver.mu.Lock()
	presented := append([]string(nil), solver.presented...)
	solver.mu.Unlock()
	if len(presented) != 0 {
		t.Errorf("a resumed row is not re-written in the same round, got presents %v", presented)
	}

	as, err := store.ListAuthorizations(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(as) != 1 {
		t.Fatalf("want 1 authorization row, got %d", len(as))
	}
	if as[0].Presented {
		t.Error("the resumed row must go back to Presented=false, so the next round probes and re-presents it")
	}
}

// A failure while recording a completed renewal must leave nothing half-recorded.
//
// The epilogue promotes the new certificate, retires what the order uploaded, clears the fallback
// and identifier ledgers, and discards the order -- and it runs after the certificate is already
// live in the cloud, where nothing rolls back. Committed one statement at a time, a failure in the
// middle used to leave states no later pass repairs:
//
//   - promoted but not retired: the certificate that was serving is in no table, so ReapRetired
//     never sees it, nothing deletes it from the cloud, and it holds uploaded-certificate quota
//     forever -- the quota whose exhaustion stops renewal;
//   - retired but not promoted: the certificate still bound to the listener is scheduled for
//     deletion.
//
// So this test does two things: it proves the transaction leaves the state exactly as it was, and
// it proves the next pass finishes the job once the store works again -- because "nothing
// half-recorded" is only useful if the work is still there to do.
func TestAFailedRenewalEpilogueLeavesNothingHalfRecorded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	fake := &fakeAPI{}
	m := newManager(store, fake, &fakeSolver{}, fakeKeyAuth{}, deploy.Noop{},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	cert := &config.Certificate{
		Name: "epilogue-atomic", Domains: []string{"a.example.com"},
		Profile: config.ProfileClassic, KeyType: config.KeyTypeECDSAP256,
	}
	if err := config.NormalizeCertificates([]config.Certificate{*cert}); err != nil {
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

	const orderURL = "https://ca.test/order/atomic"
	const finalizeURL = "https://ca.test/finalize/atomic"
	const certURL = "https://ca.test/cert/atomic"

	// The live certificate, and an order that uploaded a DIFFERENT one whose rebind never
	// completed -- the orphan that has to reach the reclaim list in the same transaction.
	before := selfSignedCertPEM(t, time.Now().Add(24*time.Hour), "a.example.com")
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, CertURL: "https://ca.test/cert/old", CertPEM: before,
		KeyPEM: keyPEM, NotAfter: time.Now().Add(24 * time.Hour), DeployedCertID: "ap-live",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutOrder(&state.Order{
		CertName: cert.Name, OrderURL: orderURL, FinalizeURL: finalizeURL, Status: "ready",
		KeyPEM: keyPEM, Identifiers: cert.DomainKey(), DeploymentCertID: "ap-orphan",
	}); err != nil {
		t.Fatal(err)
	}

	fake.orders = []legoacme.ExtendedOrder{
		{Order: legoacme.Order{Status: "ready", Finalize: finalizeURL}, Location: orderURL},
		{Order: legoacme.Order{Status: "valid", Finalize: finalizeURL, Certificate: certURL}, Location: orderURL},
	}

	// Two more things the same transaction clears, and which nothing else in the failure path
	// touches: they are how this test can tell a rollback from "the failure handler happened to
	// write the old certificate back". A fallback record for a name that this issuance covers, and
	// an identifier-failure ledger entry, both of which a successful full-set renewal retires.
	if err := store.PutFallback(&state.Fallback{
		CertName: cert.Name, Dropped: []string{"a.example.com"}, Since: time.Now(), Reason: "test",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordIdentifierFailure(cert.Name, "a.example.com", "test", time.Now()); err != nil {
		t.Fatal(err)
	}

	// Fail the LAST statement of the epilogue, the order delete.
	//
	// The position matters for what this test can prove. Every other write in the transaction --
	// the promotion, the reclaim record, both clears -- has already run by then, so if the
	// transaction did not roll back they would all be visible: the certificate promoted, the
	// fallback record gone, the ledger cleared. Failing the first statement instead would let the
	// failure handler's own rewrite of the certificate row hide the difference.
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`CREATE TRIGGER block_order_delete BEFORE DELETE ON orders
		BEGIN SELECT RAISE(FAIL, 'orders blocked by test'); END;`); err != nil {
		t.Fatal(err)
	}

	err = m.Reconcile(context.Background(), cert)
	if err == nil {
		t.Fatal("the epilogue failed, so the pass must be reported as failed rather than as success")
	}
	// The message has to be true about what happened: the certificate IS live in the cloud.
	for _, want := range []string{"issued and deployed", "state.db"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the failure must say %q so the operator knows the cloud does not roll back, got %q",
				want, err)
		}
	}

	// Nothing from the transaction may be visible.
	after, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if after.CertURL != "https://ca.test/cert/old" || string(after.CertPEM) != string(before) {
		t.Errorf("the certificate was promoted by a transaction that failed: certUrl=%q", after.CertURL)
	}
	if retired, _ := store.ListRetiredCertsBefore(time.Now().Add(time.Hour)); len(retired) != 0 {
		t.Errorf("a failed transaction left reclaim records: %+v", retired)
	}
	if o, _ := store.GetOrder(cert.Name); o == nil {
		t.Error("the order was discarded by a transaction that failed, so the next pass has nothing " +
			"to finish and the uploaded certificate is only recoverable from the cloud")
	}
	if after.ConsecutiveFailures == 0 || after.NextAttemptAt.IsZero() {
		t.Error("a failed epilogue must be recorded as a failure with backoff, not silently retried " +
			"on every pass")
	}
	// The clears are part of the same unit of work, so they must not have happened either. This is
	// also what makes the assertion decisive: the failure handler rewrites the certificate row from
	// the in-memory state, so the row alone cannot distinguish a rollback from a repair.
	if fb, err := store.GetFallback(cert.Name); err != nil || fb == nil {
		t.Errorf("a failed epilogue cleared the fallback record (fb=%+v err=%v); the next pass then "+
			"re-orders the full name set that the record exists to hold back", fb, err)
	}
	if fails, err := store.ListIdentifierFailures(cert.Name); err != nil || len(fails) == 0 {
		t.Errorf("a failed epilogue cleared the identifier failure ledger (fails=%d err=%v), so a "+
			"name that has been failing is retried as if it were healthy", len(fails), err)
	}

	// And with the store working again, the next pass completes the renewal -- which is the point
	// of leaving nothing half-recorded.
	//
	// The clock has to move first: the failed pass recorded a failure, and the backoff that comes
	// with it is the reason a store outage does not turn into a retry on every pass.
	if _, err := db.Exec(`DROP TRIGGER block_order_delete`); err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	m.SetNow(func() time.Time { return base.Add(2 * time.Hour) })
	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("the pass after the store recovered: %v", err)
	}
	done, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if done.CertURL != certURL {
		t.Errorf("the recovered pass did not promote the new certificate: certUrl=%q", done.CertURL)
	}
	retired, _ := store.ListRetiredCertsBefore(time.Now().Add(time.Hour))
	if len(retired) != 1 || retired[0].CertID != "ap-orphan" {
		t.Errorf("the recovered pass did not record the uploaded orphan for reclaim: %+v", retired)
	}
	if o, _ := store.GetOrder(cert.Name); o != nil {
		t.Errorf("the recovered pass left the order in flight: %+v", o)
	}
}
