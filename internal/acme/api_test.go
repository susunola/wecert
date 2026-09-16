package acme

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
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

	// authzByURL overrides GetAuthorization per authorization URL. URLs left out keep the
	// default "everything is valid" answer, so only the tests that need a failing -- or a
	// wildcard -- authorization have to populate it.
	authzByURL map[string]legoacme.Authorization

	// authzHits counts GetAuthorization per URL, so a test can tell "polled again"
	// from "polled once".
	authzHits map[string]int

	certPEM []byte
	certErr error

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
	f.enter("NewOrder")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.newOrderDomains = append([]string(nil), domains...)
	f.newOrderOpts = opts
	if len(f.orders) == 0 {
		return legoacme.ExtendedOrder{}, errors.New("fakeAPI: NewOrder has no scripted orders")
	}
	return f.orders[0], nil
}

func (f *fakeAPI) GetOrder(string) (legoacme.ExtendedOrder, error) {
	f.enter("GetOrder")
	f.mu.Lock()
	defer f.mu.Unlock()
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
	return f.certPEM, []byte("key"), f.certErr
}

// GetRenewalInfo errors by default: ARI is optional, and an unscripted ARI call usually
// means the test's throttling is wrong. Failing loudly is easier to debug than an empty response.
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
	fake.certPEM = selfSignedCertPEM(t, time.Now().Add(90*24*time.Hour), cert.Domains...)

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
	fake.certPEM = selfSignedCertPEM(t, time.Now().Add(90*24*time.Hour), cert.Domains...)

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
	fake.certPEM = selfSignedCertPEM(t, time.Now().Add(90*24*time.Hour), cert.Domains...)

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
	fake.certPEM = selfSignedCertPEM(t, time.Now().Add(90*24*time.Hour), cert.Domains...)

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

	err := m.advance(context.Background(), cert, st, o)
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
