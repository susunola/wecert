// Multi-SAN tests where a wildcard and its apex are part of the same certificate.
//
// Two harness traps cost real time here and are worth recording, because both produce a
// test that passes while asserting nothing about DNS-01:
//
//   - A scripted order must start PENDING. terminalOrder builds a "valid" order, which
//     sends advance() straight to download; no challenge is ever solved.
//   - A scripted order must carry its Authorizations list. loadAuthorizations iterates it,
//     so an empty slice means solveChallenges sees no pending work, reports success, and
//     the flow finalizes without writing or accepting anything. The fake's default
//     authorization is "valid", which hides the omission further.
//
// And one about the certificate under test: config.NormalizeCertificates fills in the
// parsed fields (RenewBeforeDur among them) on the slice it is handed, so the certificate
// must be the normalized copy. Keeping the original leaves RenewBeforeDur at zero, every
// renewal window reads as "not yet due", and Reconcile returns without a single API call.
package acme

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/state"
)

// faithfulSolver mirrors the real DNSSolver's two load-bearing computations:
//
//   - the challenge FQDN and TXT value come from dns01.GetChallengeInfo, so a wildcard
//     authorization and its apex land on the SAME TXT name -- the property the whole
//     "write everything, validate everything, then clean up together" design rests on.
//     fakeSolver derives the name by string concatenation, which cannot express that.
//   - CleanUp follows lego's provider semantics: it deletes every TXT at the name. It is
//     gated by the same challengeLeases registry the real solver uses.
type faithfulSolver struct {
	mu sync.Mutex
	// writes is every Present call: identifier -> (fqdn, value).
	writes []solverWrite
	// waitAllRecords is the record list handed to WaitAll, after the manager's dedup.
	waitAllRecords []DNSRecord
	waitAllCalls   int
	// cleanups is every provider-level CleanUp that actually ran, keyed by FQDN. The
	// registry defers this to the last leaver.
	cleanups []string
	// records is the simulated DNS state: fqdn -> set of values.
	records map[string]map[string]bool
}

type solverWrite struct {
	identifier string
	fqdn       string
	value      string
}

func newFaithfulSolver() *faithfulSolver {
	return &faithfulSolver{records: map[string]map[string]bool{}}
}

func (s *faithfulSolver) Present(_ context.Context, domain, token, keyAuth string) (DNSRecord, error) {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	rec := DNSRecord{FQDN: info.EffectiveFQDN, Value: info.Value}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes = append(s.writes, solverWrite{identifier: domain, fqdn: rec.FQDN, value: rec.Value})
	if s.records[rec.FQDN] == nil {
		s.records[rec.FQDN] = map[string]bool{}
	}
	s.records[rec.FQDN][rec.Value] = true
	return rec, nil
}

// PropagationTimeout is the window the reclaim probe uses as its floor for trusting a denial.
func (s *faithfulSolver) PropagationTimeout() time.Duration { return 5 * time.Minute }

func (s *faithfulSolver) WaitAll(_ context.Context, records []DNSRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.waitAllCalls++
	s.waitAllRecords = append([]DNSRecord(nil), records...)
	return nil
}

func (s *faithfulSolver) CleanUp(_ context.Context, domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	s.mu.Lock()
	defer s.mu.Unlock()
	// lego's provider deletes every TXT at the name, so simulating the delete-all here is
	// what makes the "did we strand a sibling" assertion meaningful.
	delete(s.records, info.EffectiveFQDN)
	s.cleanups = append(s.cleanups, info.EffectiveFQDN)
	return nil
}

func (s *faithfulSolver) LookupTXT(_ context.Context, domain, keyAuth string) (DNSRecord, bool, error) {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	s.mu.Lock()
	defer s.mu.Unlock()
	values := s.records[info.EffectiveFQDN]
	return DNSRecord{FQDN: info.EffectiveFQDN, Value: info.Value}, values[info.Value], nil
}

func (s *faithfulSolver) snapshot() (writes []solverWrite, waitAll []DNSRecord, calls int, cleanups []string, records map[string]map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := map[string]map[string]bool{}
	for k, v := range s.records {
		cp[k] = map[string]bool{}
		for val := range v {
			cp[k][val] = true
		}
	}
	return append([]solverWrite(nil), s.writes...), append([]DNSRecord(nil), s.waitAllRecords...),
		s.waitAllCalls, append([]string(nil), s.cleanups...), cp
}

// wildcardHarness builds a multi-SAN certificate whose SAN set is the shape this scenario
// is about: the apex, its wildcard, and several concrete names (some covered by the
// wildcard, some not).
func wildcardHarness(t *testing.T) (*state.Store, *Manager, *fakeAPI, *faithfulSolver, *config.Certificate) {
	t.Helper()

	store, err := state.Open(t.TempDir() + "/state.db")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	solver := newFaithfulSolver()
	fake := &fakeAPI{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := newManager(store, fake, solver, fakeKeyAuth{}, deploy.Noop{}, log)

	certs := []config.Certificate{{
		Name:    "site-example-com",
		Domains: []string{"example.com", "*.example.com", "www.example.com", "api.example.com", "deep.sub.example.com"},
		Profile: config.ProfileClassic,
		KeyType: config.KeyTypeECDSAP256,
	}}
	// NormalizeCertificates fills in the parsed fields (RenewBeforeDur among them) on the
	// slice it is given, so the certificate under test must be the normalized copy. Keeping
	// the un-normalized one leaves RenewBeforeDur at zero, every renewal window is then
	// "not yet due", and Reconcile returns without a single API call -- a test that looks
	// like it exercised the flow while asserting nothing.
	if err := config.NormalizeCertificates(certs); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	cert := &certs[0]
	fake.orderDomains = func() []string { return cert.Domains }
	fake.orderKeyPEM = func() []byte {
		o, err := store.GetOrder(cert.Name)
		if err != nil || o == nil {
			return nil
		}
		return o.KeyPEM
	}
	return store, m, fake, solver, cert
}

// scriptDNS01Order scripts an order that actually drives the DNS-01 challenges.
//
// Both halves are load-bearing and both are easy to get wrong when writing a test:
//
//   - the order must start PENDING. A terminal "valid" order sends advance() straight to
//     download and never touches a challenge, so a test can look like it exercises the
//     DNS path while writing nothing to DNS.
//   - the order must carry its Authorizations list. Without it loadAuthorizations iterates
//     an empty slice, solveChallenges sees no pending work and reports success, and the
//     flow finalizes without a single AcceptChallenge. The fake's default authorization is
//     "valid", which hides that too.
//
// Each identifier gets a pending -> valid sequence, so the first look writes DNS and the
// poll after AcceptChallenge sees it through.
func scriptDNS01Order(fake *fakeAPI, identifiers []string) {
	authzURLs := make([]string, 0, len(identifiers))
	fake.authzSeq = map[string][]legoacme.Authorization{}
	fake.authzByURL = map[string]legoacme.Authorization{}

	for i, id := range identifiers {
		// RFC 8555 §7.1.3: a wildcard authorization carries the BARE identifier plus
		// wildcard=true. This mirrors the real CA, and it is the reason the apex and its
		// wildcard end up on one TXT name.
		value, wildcard := id, false
		if strings.HasPrefix(id, "*.") {
			value, wildcard = strings.TrimPrefix(id, "*."), true
		}

		url := fmt.Sprintf("https://ca.test/authz/%d", i)
		authzURLs = append(authzURLs, url)
		fake.authzSeq[url] = []legoacme.Authorization{
			{
				Status:     "pending",
				Identifier: legoacme.Identifier{Value: value},
				Wildcard:   wildcard,
				Challenges: []legoacme.Challenge{{
					Type: "dns-01", Token: fmt.Sprintf("tok-%d", i), URL: fmt.Sprintf("https://ca.test/chall/%d", i),
				}},
			},
			{Status: "valid", Identifier: legoacme.Identifier{Value: value}, Wildcard: wildcard},
		}
	}

	fake.orders = []legoacme.ExtendedOrder{
		{
			Order:    legoacme.Order{Status: "pending", Finalize: "https://ca.test/finalize/1", Authorizations: authzURLs},
			Location: "https://ca.test/order/1",
		},
		{
			Order:    legoacme.Order{Status: "ready", Finalize: "https://ca.test/finalize/1", Authorizations: authzURLs},
			Location: "https://ca.test/order/1",
		},
		terminalOrder("https://ca.test/order/1", "https://ca.test/finalize/1", "https://ca.test/cert/1"),
	}
}

// The invariant the whole DNS-01 design is built around, exercised end to end on a
// multi-SAN certificate: the apex and its wildcard must both write the SAME TXT name with
// two DIFFERENT values, and both must be present at the same time.
//
// This is what "write everything, validate everything, only then clean up together"
// exists for. An implementation that writes, validates and deletes one authorization at a
// time cannot pass: the second write lands on the name the first one just cleared.
func TestMultiSANWildcardAndApexShareOneTXTName(t *testing.T) {
	// GetChallengeInfo chases CNAMEs over the network otherwise.
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")
	saved := challengeLeases
	challengeLeases = newTXTLeases()
	t.Cleanup(func() { challengeLeases = saved })

	store, m, fake, solver, cert := wildcardHarness(t)
	scriptDNS01Order(fake, cert.Domains)

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	writes, waitAll, waitCalls, cleanups, records := solver.snapshot()

	// 1. One write per identifier: five SANs, five authorizations.
	if len(writes) != len(cert.Domains) {
		t.Fatalf("expected one Present per identifier (%d), got %d: %+v", len(cert.Domains), len(writes), writes)
	}

	// 2. Both the apex and the wildcard present the BARE identifier (RFC 8555 §7.1.3), so
	//    their two authorizations resolve to one challenge name while carrying two
	//    distinct tokens -- hence two distinct TXT values that must coexist on that name.
	//    An implementation that writes, validates and deletes one authorization at a time
	//    cannot satisfy this: the second write lands on the name the first just cleared.
	const shared = "_acme-challenge.example.com."
	var values []string
	for _, w := range writes {
		if w.identifier == "example.com" {
			if w.fqdn != shared {
				t.Errorf("identifier example.com produced %s, want %s", w.fqdn, shared)
			}
			values = append(values, w.value)
		}
	}
	if len(values) != 2 {
		t.Fatalf("expected two authorizations on the bare identifier (apex + wildcard), got %d: %+v", len(values), writes)
	}
	if values[0] == values[1] {
		t.Errorf("the two authorizations carry different tokens, so their TXT values must differ; both were %s", values[0])
	}

	// 3. Every concrete name gets its own challenge name, and the wildcard SAN adds no
	//    challenge name of its own beyond the shared one.
	names := map[string]int{}
	for _, w := range writes {
		names[w.fqdn]++
	}
	if names[shared] != 2 {
		t.Errorf("expected exactly two authorizations on the shared name, got %d", names[shared])
	}
	for _, want := range []string{
		"_acme-challenge.www.example.com.",
		"_acme-challenge.api.example.com.",
		"_acme-challenge.deep.sub.example.com.",
	} {
		if names[want] != 1 {
			t.Errorf("expected exactly one authorization on %s, got %d", want, names[want])
		}
	}
	if len(names) != 4 {
		t.Errorf("five SANs must produce four challenge names (apex and wildcard share one), got %v", names)
	}

	// 4. Prop­agation is confirmed for the shared name before the CA is told to validate.
	if waitCalls == 0 {
		t.Fatal("WaitAll was never called, so propagation was never confirmed")
	}
	confirmed := map[string]bool{}
	for _, r := range waitAll {
		confirmed[r.FQDN] = true
	}
	if !confirmed["_acme-challenge.example.com."] {
		t.Errorf("the shared name was not confirmed before validation; WaitAll saw %v", waitAll)
	}

	// 5. Every challenge was accepted, and cleanup ran last and left DNS empty.
	fake.mu.Lock()
	accepted := append([]string(nil), fake.accepted...)
	fake.mu.Unlock()
	if len(accepted) != len(cert.Domains) {
		t.Errorf("expected AcceptChallenge for all %d authorizations, got %d", len(cert.Domains), len(accepted))
	}
	if len(cleanups) == 0 {
		t.Error("cleanup never ran, so the TXT records would be left in DNS")
	}
	if len(records) != 0 {
		t.Errorf("TXT records were left behind after cleanup: %v", records)
	}

	// 6. And the certificate is live with the full SAN set.
	st, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if st.NotAfter.IsZero() {
		t.Error("the certificate was not recorded as live")
	}
	leaf, err := ParseLeaf(st.CertPEM)
	if err != nil {
		t.Fatalf("parse live certificate: %v", err)
	}
	if err := VerifyCoverage(leaf, cert.Domains); err != nil {
		t.Errorf("the issued certificate does not cover every SAN: %v", err)
	}
}

// A multi-SAN certificate where ONE concrete name never validates must degrade to exactly
// that name's removal -- the wildcard and the apex are different authorizations that share
// a TXT name, and the fallback works by literal identifier, so getting this wrong drops
// coverage that works while keeping the name that does not.
func TestMultiSANFallbackDropsOnlyTheBrokenName(t *testing.T) {
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")
	saved := challengeLeases
	challengeLeases = newTXTLeases()
	t.Cleanup(func() { challengeLeases = saved })

	store, m, fake, solver, cert := wildcardHarness(t)

	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return fixed }
	m.SetFallbackPolicy(fallbackPolicy())

	// A live full-set certificate, inside the pre-expiry window.
	liveNotAfter := fixed.Add(48 * time.Hour)
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: liveNotAfter, CertURL: "https://ca.test/cert/live",
		ConsecutiveFailures: 5,
	}); err != nil {
		t.Fatal(err)
	}
	// Only api.example.com is broken, and it is a CONCRETE name -- not the wildcard, not
	// the apex. The wildcard's own failure is booked against "*.example.com", which is a
	// separate ledger entry from the apex's.
	for i := 0; i < 5; i++ {
		if err := store.RecordIdentifierFailure(cert.Name, "api.example.com", "dns says no", fixed); err != nil {
			t.Fatal(err)
		}
	}

	scriptDNS01Order(fake, cert.Domains)
	fake.certNotAfter = fixed.Add(90 * 24 * time.Hour)

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// What did we actually order for?
	fake.mu.Lock()
	ordered := append([]string(nil), fake.newOrderDomains...)
	fake.mu.Unlock()

	want := []string{"example.com", "*.example.com", "www.example.com", "deep.sub.example.com"}
	if len(ordered) != len(want) {
		t.Fatalf("ordered %v, want %v (only api.example.com should have been dropped)", ordered, want)
	}
	for _, w := range want {
		found := false
		for _, got := range ordered {
			if got == w {
				found = true
			}
		}
		if !found {
			t.Errorf("the fallback dropped %s, which is not the broken identifier; ordered %v", w, ordered)
		}
	}
	for _, got := range ordered {
		if got == "api.example.com" {
			t.Error("the broken identifier is still in the ordered set")
		}
	}

	// The live certificate must cover the kept set, and the ledger must survive so the
	// next pass does not immediately re-order the broken full set.
	st, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ParseLeaf(st.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCoverage(leaf, ordered); err != nil {
		t.Errorf("the degraded certificate does not cover the kept set: %v", err)
	}
	if st.ConsecutiveFailures == 0 {
		t.Error("consecutive_failures was reset by the degraded issuance")
	}
	failures, err := store.ListIdentifierFailures(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) == 0 {
		t.Error("the identifier ledger was cleared, so the next pass cannot tell api.example.com is broken")
	}

	// The wildcard's records were on the shared name; cleanup of a partial set must still
	// leave DNS clean.
	_, _, _, _, records := solver.snapshot()
	if len(records) != 0 {
		t.Errorf("TXT records left behind after the degraded round: %v", records)
	}
}

// When a wildcard and its apex both go through a fallback round, the shared TXT name must
// not be cleaned up while the other value is still needed. This is the "last leaver" rule
// seen from the multi-SAN angle.
func TestCleanupKeepsTheSharedNameWhileTheWildcardIsStillLive(t *testing.T) {
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")
	saved := challengeLeases
	challengeLeases = newTXTLeases()
	t.Cleanup(func() { challengeLeases = saved })

	provider := &recordingProvider{}
	solver := &DNSSolver{
		newProvider: func(context.Context) (challenge.Provider, error) { return provider, nil },
		log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	m, store := newTestManager(t, solver, fakeKeyAuth{})

	// The apex authorization is being cleaned up; the wildcard's value is still live at the
	// same name.
	apexKeyAuth := "keyauth(tok-apex)"
	wildcardKeyAuth := "keyauth(tok-wildcard)"
	apex := dns01.GetChallengeInfo("example.com", apexKeyAuth)
	wildcard := dns01.GetChallengeInfo("example.com", wildcardKeyAuth)
	if apex.EffectiveFQDN != wildcard.EffectiveFQDN {
		t.Fatalf("precondition: apex and wildcard must share a challenge name, got %s and %s",
			apex.EffectiveFQDN, wildcard.EffectiveFQDN)
	}

	rows := []*state.Authorization{
		{
			CertName: "site-example-com", AuthzURL: "https://acme.example/authz/apex",
			Identifier: "example.com", TxtName: apex.EffectiveFQDN, TxtValue: apex.Value,
			ChallengeToken: "tok-apex", Presented: true,
		},
	}
	seedOrderWithAuthzs(t, store, "site-example-com", rows)

	// Register the wildcard's value the way WaitAll would have.
	challengeLeases.add(wildcard.EffectiveFQDN, wildcard.Value)

	m.cleanup(context.Background(), "site-example-com", rows)

	if len(provider.cleanups) != 0 {
		t.Fatalf("cleanup deleted every TXT at %s while the wildcard's value was still live: %v",
			apex.EffectiveFQDN, provider.cleanups)
	}
	if rows[0].Presented {
		t.Error("the apex row handled its own value, so it must be marked not-presented")
	}

	// The wildcard leaves last; now the delete-all is allowed and clears the name.
	if err := solver.CleanUp(context.Background(), "example.com", "tok-wildcard", wildcardKeyAuth); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	if len(provider.cleanups) != 1 {
		t.Errorf("the last leaver must run exactly one delete-all, got %v", provider.cleanups)
	}
}

// A wildcard authorization's failure must be booked on the wildcard, not on the apex, or
// the fallback drops the healthy apex and keeps the name that cannot issue.
//
// Coverage note, verified by mutation rather than assumed: this is NOT a guard for the
// fallback fix. It passes on the pre-fix commit, because that bug never touched the ledger
// key. Its value is narrower and worth stating plainly -- it drives the multi-SAN case
// (three concrete names plus a wildcard) rather than the two-name fixture the dedicated
// unit test uses, so it catches an implementation that keys on the shared challenge name
// instead of the identifier. Mutating the fallback to key on the challenge name makes this
// test AND TestWildcardFailureIsBookedAgainstTheWildcardNotTheApex fail. The
// "*.example.com" ledger key itself is already covered there.
func TestMultiSANWildcardFailureDoesNotDropTheApex(t *testing.T) {
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")
	saved := challengeLeases
	challengeLeases = newTXTLeases()
	t.Cleanup(func() { challengeLeases = saved })

	store, m, fake, _, cert := wildcardHarness(t)

	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return fixed }
	m.SetFallbackPolicy(fallbackPolicy())

	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: fixed.Add(48 * time.Hour), CertURL: "https://ca.test/cert/live",
		ConsecutiveFailures: 5,
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := store.RecordIdentifierFailure(cert.Name, "*.example.com", "wildcard dns is broken", fixed); err != nil {
			t.Fatal(err)
		}
	}

	scriptDNS01Order(fake, cert.Domains)
	fake.certNotAfter = fixed.Add(90 * 24 * time.Hour)

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	fake.mu.Lock()
	ordered := append([]string(nil), fake.newOrderDomains...)
	fake.mu.Unlock()

	if !containsStr(ordered, "example.com") {
		t.Errorf("the apex is healthy and must stay in the certificate; ordered %v", ordered)
	}
	if containsStr(ordered, "*.example.com") {
		t.Errorf("the wildcard is the broken identifier and must be dropped; ordered %v", ordered)
	}
	// The concrete names are also unrelated to the wildcard's failure and must survive.
	for _, keep := range []string{"www.example.com", "api.example.com", "deep.sub.example.com"} {
		if !containsStr(ordered, keep) {
			t.Errorf("%s is unrelated to the wildcard failure and must stay; ordered %v", keep, ordered)
		}
	}

	// The ledger entry must be keyed on the wildcard, so the fallback can find it again.
	failures, err := store.ListIdentifierFailures(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 1 || failures[0].Identifier != "*.example.com" {
		t.Errorf("the ledger must key the failure on the wildcard, got %+v", failures)
	}
}

func containsStr(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// The mirror image of the previous case: the APEX authorization is the one that never
// validates while the wildcard is fine.
//
// The two authorizations share a challenge name, so a fallback that keys on the TXT name
// instead of the authorization's identifier cannot tell them apart and would drop the
// wrong one -- losing the bare domain while keeping *.example.com, which is the more
// surprising half to keep and the more surprising half to lose.
func TestMultiSANFallbackCanDropTheApexAndKeepTheWildcard(t *testing.T) {
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")
	saved := challengeLeases
	challengeLeases = newTXTLeases()
	t.Cleanup(func() { challengeLeases = saved })

	store, m, fake, _, cert := wildcardHarness(t)

	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return fixed }
	m.SetFallbackPolicy(fallbackPolicy())

	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: fixed.Add(48 * time.Hour), CertURL: "https://ca.test/cert/live",
		ConsecutiveFailures: 5,
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := store.RecordIdentifierFailure(cert.Name, "example.com", "apex dns is broken", fixed); err != nil {
			t.Fatal(err)
		}
	}

	scriptDNS01Order(fake, cert.Domains)
	fake.certNotAfter = fixed.Add(90 * 24 * time.Hour)

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	fake.mu.Lock()
	ordered := append([]string(nil), fake.newOrderDomains...)
	fake.mu.Unlock()

	if containsStr(ordered, "example.com") {
		t.Errorf("the apex is the broken identifier and must be dropped; ordered %v", ordered)
	}
	if !containsStr(ordered, "*.example.com") {
		t.Errorf("the wildcard is healthy and shares only the TXT name, not the failure; ordered %v", ordered)
	}
	// The concrete names are independent and must survive.
	for _, keep := range []string{"www.example.com", "api.example.com", "deep.sub.example.com"} {
		if !containsStr(ordered, keep) {
			t.Errorf("%s is unrelated to the apex failure and must stay; ordered %v", keep, ordered)
		}
	}
}

// A degraded round must not strand a wildcard's TXT value.
//
// The subset order re-writes the wildcard's record to the name shared with its apex, and
// that is a different authorization from the dropped one. If cleanup treated the name as
// one unit it would either delete a value the subset still needs or leave a value behind --
// a DNSPod record slowly consuming the account's quota.
//
// Scope note: this runs ONE pass, so it says nothing about what the next pass decides.
// That is deliberate and is covered elsewhere: TestFallbackStaysStickyAfterIssuingTheDegradedSubset
// asserts the failures and ledger survive the degraded issuance. Mutation-checked -- this
// test passes even with the pre-fix "reset everything on success" behaviour restored,
// because the reset happens on a pass it never runs.
func TestMultiSANDegradedRoundCleansUpAfterItself(t *testing.T) {
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")
	saved := challengeLeases
	challengeLeases = newTXTLeases()
	t.Cleanup(func() { challengeLeases = saved })

	store, m, fake, solver, cert := wildcardHarness(t)

	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return fixed }
	m.SetFallbackPolicy(fallbackPolicy())

	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: fixed.Add(48 * time.Hour), CertURL: "https://ca.test/cert/live",
		ConsecutiveFailures: 5,
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := store.RecordIdentifierFailure(cert.Name, "api.example.com", "dns says no", fixed); err != nil {
			t.Fatal(err)
		}
	}

	scriptDNS01Order(fake, cert.Domains)
	fake.certNotAfter = fixed.Add(90 * 24 * time.Hour)

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	writes, _, _, cleanups, records := solver.snapshot()

	// The subset still contains the apex and the wildcard, so the shared name was written
	// and must have been cleaned.
	const shared = "_acme-challenge.example.com."
	sharedWrites := 0
	for _, w := range writes {
		if w.fqdn == shared {
			sharedWrites++
		}
	}
	if sharedWrites != 2 {
		t.Errorf("the kept set still has both the apex and the wildcard, so the shared name must be written twice; got %d (%+v)",
			sharedWrites, writes)
	}
	if len(records) != 0 {
		t.Errorf("a degraded round stranded TXT records: %v", records)
	}
	if len(cleanups) == 0 {
		t.Error("no provider cleanup ran, so the shared name was never cleared")
	}

	// Every authorization row must be accounted for: none left presented (which would make
	// the next round try to clean up records that are already gone).
	rows, err := store.ListPresentedAuthorizations()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("authorization rows are still marked presented after cleanup: %+v", rows)
	}
}
