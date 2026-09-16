package state

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("opening state db: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// This is the single most important invariant in the system: an order and its private
// key must survive a process restart fully intact.
// Losing the order URL means re-ordering, walking straight into
// "5 certificates per exact set of identifiers / 7 days".
func TestOrderRoundTripPreservesKey(t *testing.T) {
	s := openTestStore(t)

	keyPEM := []byte("-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n")
	expires := time.Now().Add(7 * 24 * time.Hour).Truncate(time.Second)
	want := &Order{
		CertName:    "example-com",
		OrderURL:    "https://acme-v02.api.letsencrypt.org/acme/order/1/2",
		FinalizeURL: "https://acme-v02.api.letsencrypt.org/acme/finalize/1/2",
		CertURL:     "",
		ExpiresAt:   expires,
		Status:      "pending",
		KeyPEM:      keyPEM,
	}
	if err := s.PutOrder(want); err != nil {
		t.Fatalf("PutOrder failed: %v", err)
	}

	got, err := s.GetOrder("example-com")
	if err != nil {
		t.Fatalf("GetOrder failed: %v", err)
	}
	if got == nil {
		t.Fatal("GetOrder returned nil, the order was lost")
	}

	if got.OrderURL != want.OrderURL {
		t.Errorf("OrderURL = %q, want %q", got.OrderURL, want.OrderURL)
	}
	if got.FinalizeURL != want.FinalizeURL {
		t.Errorf("FinalizeURL = %q, want %q", got.FinalizeURL, want.FinalizeURL)
	}
	if got.Status != "pending" {
		t.Errorf("Status = %q, want pending", got.Status)
	}
	if !got.ExpiresAt.Equal(expires) {
		t.Errorf("ExpiresAt = %s, want %s", got.ExpiresAt, expires)
	}
	if string(got.KeyPEM) != string(keyPEM) {
		t.Errorf("KeyPEM was not restored verbatim: %q", got.KeyPEM)
	}
}

func TestOrderUpsertKeepsSingleRow(t *testing.T) {
	s := openTestStore(t)

	o := &Order{CertName: "c", OrderURL: "url-1", Status: "pending"}
	if err := s.PutOrder(o); err != nil {
		t.Fatal(err)
	}
	// Writing the same certificate again must overwrite, not leave two orders behind.
	o.OrderURL = "url-2"
	o.Status = "ready"
	if err := s.PutOrder(o); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetOrder("c")
	if err != nil {
		t.Fatal(err)
	}
	if got.OrderURL != "url-2" || got.Status != "ready" {
		t.Errorf("order was not overwritten by the upsert: %+v", got)
	}
}

func TestGetMissingReturnsNil(t *testing.T) {
	s := openTestStore(t)

	if o, err := s.GetOrder("nope"); err != nil || o != nil {
		t.Errorf("GetOrder on a missing certificate should return (nil, nil), got (%v, %v)", o, err)
	}
	if c, err := s.GetCert("nope"); err != nil || c != nil {
		t.Errorf("GetCert on a missing certificate should return (nil, nil), got (%v, %v)", c, err)
	}
	if a, err := s.GetAccount("nope"); err != nil || a != nil {
		t.Errorf("GetAccount on a missing directory should return (nil, nil), got (%v, %v)", a, err)
	}
}

func TestCertStateRoundTrip(t *testing.T) {
	s := openTestStore(t)

	notAfter := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	windowStart := time.Now().Add(60 * 24 * time.Hour).Truncate(time.Second)
	windowEnd := windowStart.Add(48 * time.Hour)

	want := &CertState{
		Name:                "example-com",
		NotAfter:            notAfter,
		CertURL:             "https://acme-v02.api.letsencrypt.org/acme/cert/123",
		CertPEM:             []byte("fullchain"),
		KeyPEM:              []byte("privkey"),
		IssuedAt:            time.Now().Truncate(time.Second),
		ARICertID:           "abc.def",
		ARIWindowStart:      windowStart,
		ARIWindowEnd:        windowEnd,
		ARICheckedAt:        time.Now().Truncate(time.Second),
		ARIRetryAfter:       6 * time.Hour,
		ConsecutiveFailures: 3,
		LastError:           "boom",
		DeployedCertID:      "TencentCertId123",
	}
	if err := s.PutCert(want); err != nil {
		t.Fatalf("PutCert failed: %v", err)
	}

	got, err := s.GetCert("example-com")
	if err != nil {
		t.Fatalf("GetCert failed: %v", err)
	}

	if !got.NotAfter.Equal(notAfter) {
		t.Errorf("NotAfter = %s, want %s", got.NotAfter, notAfter)
	}
	if got.ARICertID != want.ARICertID {
		t.Errorf("ARICertID = %q, want %q", got.ARICertID, want.ARICertID)
	}
	if !got.ARIWindowStart.Equal(windowStart) || !got.ARIWindowEnd.Equal(windowEnd) {
		t.Errorf("ARI window was not restored: %s - %s", got.ARIWindowStart, got.ARIWindowEnd)
	}
	if got.ARIRetryAfter != 6*time.Hour {
		t.Errorf("ARIRetryAfter = %v, want 6h", got.ARIRetryAfter)
	}
	if got.ConsecutiveFailures != 3 {
		t.Errorf("ConsecutiveFailures = %d, want 3", got.ConsecutiveFailures)
	}
	if got.DeployedCertID != "TencentCertId123" {
		t.Errorf("DeployedCertID = %q", got.DeployedCertID)
	}
	if string(got.CertPEM) != "fullchain" || string(got.KeyPEM) != "privkey" {
		t.Errorf("cert/key was not restored: %q / %q", got.CertPEM, got.KeyPEM)
	}
}

// Zero times must round-trip verbatim, otherwise "not issued yet" is misread as
// "issued back in 1970".
func TestZeroTimesRoundTrip(t *testing.T) {
	s := openTestStore(t)

	if err := s.PutCert(&CertState{Name: "fresh"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCert("fresh")
	if err != nil {
		t.Fatal(err)
	}
	if !got.NotAfter.IsZero() {
		t.Errorf("NotAfter should be zero, got %s", got.NotAfter)
	}
	if !got.ARIWindowStart.IsZero() || !got.ARICheckedAt.IsZero() {
		t.Error("ARI time fields should be zero")
	}
	if !got.NextAttemptAt.IsZero() {
		t.Errorf("NextAttemptAt should be zero, got %s", got.NextAttemptAt)
	}
}

func TestAuthorizationRoundTrip(t *testing.T) {
	s := openTestStore(t)

	// wildcard and apex land on the same TXT name, so the two authorizations must be
	// storable independently of each other.
	for _, a := range []*Authorization{
		{CertName: "c", AuthzURL: "authz-1", Identifier: "example.com",
			TxtName: "_acme-challenge.example.com.", TxtValue: "value-1", Presented: true},
		{CertName: "c", AuthzURL: "authz-2", Identifier: "*.example.com",
			TxtName: "_acme-challenge.example.com.", TxtValue: "value-2", Presented: true},
	} {
		if err := s.PutAuthorization(a); err != nil {
			t.Fatalf("PutAuthorization failed: %v", err)
		}
	}

	got, err := s.ListAuthorizations("c")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 authorizations, got %d", len(got))
	}

	values := map[string]string{}
	for _, a := range got {
		if a.TxtName != "_acme-challenge.example.com." {
			t.Errorf("TxtName = %q", a.TxtName)
		}
		if !a.Presented {
			t.Errorf("Presented for %s should be true", a.Identifier)
		}
		values[a.Identifier] = a.TxtValue
	}
	if values["example.com"] != "value-1" || values["*.example.com"] != "value-2" {
		t.Errorf("the two TXT records sharing one name were not kept distinct: %v", values)
	}

	if err := s.DeleteAuthorizations("c"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListAuthorizations("c"); len(got) != 0 {
		t.Errorf("want empty after delete, got %d rows", len(got))
	}
}

// The lease recovery path re-registers every presented row across all certificates, so the
// listing has to be exhaustive and has to scan the columns in the right order -- it is a
// hand-written SELECT with an explicit column list, which is exactly where a silent
// mis-scan hides.
func TestListPresentedAuthorizationsIsExhaustiveAndReadsEveryColumn(t *testing.T) {
	s := openTestStore(t)

	rows := []*Authorization{
		{CertName: "a", AuthzURL: "authz-1", Identifier: "one.example.com", Status: "pending",
			ChallengeURL: "https://ca.test/chall/1", ChallengeToken: "tok-1",
			TxtName: "_acme-challenge.one.example.com.", TxtValue: "value-1",
			Presented: true, ChallengeSent: true},
		{CertName: "b", AuthzURL: "authz-2", Identifier: "two.example.com", Status: "pending",
			ChallengeURL: "https://ca.test/chall/2", ChallengeToken: "tok-2",
			TxtName: "_acme-challenge.two.example.com.", TxtValue: "value-2",
			Presented: true},
		// Not presented: it is not in DNS, so it must not be re-registered as a lease.
		{CertName: "c", AuthzURL: "authz-3", Identifier: "three.example.com",
			TxtName: "_acme-challenge.three.example.com.", TxtValue: "value-3"},
	}
	for _, a := range rows {
		if err := s.PutAuthorization(a); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.ListPresentedAuthorizations()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want the 2 presented rows, got %d: %+v", len(got), got)
	}

	byValue := map[string]*Authorization{}
	for _, a := range got {
		byValue[a.TxtValue] = a
	}
	first := byValue["value-1"]
	if first == nil {
		t.Fatalf("every presented row must be listed, got %+v", byValue)
	}
	if first.CertName != "a" || first.AuthzURL != "authz-1" || first.Identifier != "one.example.com" ||
		first.Status != "pending" || first.ChallengeURL != "https://ca.test/chall/1" ||
		first.ChallengeToken != "tok-1" || first.TxtName != "_acme-challenge.one.example.com." ||
		!first.Presented || !first.ChallengeSent {
		t.Errorf("columns are mis-scanned or missing: %+v", first)
	}
}

func TestRetiredCerts(t *testing.T) {
	s := openTestStore(t)

	if err := s.AddRetiredCert("old-1", "example-com"); err != nil {
		t.Fatal(err)
	}
	// Adding twice should be ignored rather than erroring (idempotent).
	if err := s.AddRetiredCert("old-1", "example-com"); err != nil {
		t.Fatalf("adding a retired cert twice should be idempotent: %v", err)
	}

	// Only certs past the retention window should be reclaimed.
	if got, err := s.ListRetiredCertsBefore(time.Now().Add(-7 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	} else if len(got) != 0 {
		t.Errorf("a just-retired cert should not appear in the reclamation list, got %d rows", len(got))
	}

	got, err := s.ListRetiredCertsBefore(time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].CertID != "old-1" {
		t.Fatalf("want 1 retired cert reclaimed, got %+v", got)
	}

	if err := s.DeleteRetiredCert("old-1"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListRetiredCertsBefore(time.Now().Add(time.Minute)); len(got) != 0 {
		t.Errorf("want empty after reclamation, got %d rows", len(got))
	}
}

// Data must still be there after the state db is reopened -- the physical basis for
// "restart without re-ordering".
func TestStatePersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")

	s1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.PutOrder(&Order{CertName: "c", OrderURL: "persisted-url", KeyPEM: []byte("k")}); err != nil {
		t.Fatal(err)
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()

	got, err := s2.GetOrder("c")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.OrderURL != "persisted-url" {
		t.Fatalf("order lost after reopen: %+v", got)
	}
}

// last_error holds upstream text verbatim: lego embeds the entire non-JSON ACME
// error body in its errors, and the CVM metadata path echoes response bodies. It
// must be bounded where it is persisted rather than in each producer, or a hostile
// or merely verbose endpoint controls how much text lands in the database -- and
// /hook/status serves that text, while notifyURL posts it off-host.
func TestPutCertBoundsLastError(t *testing.T) {
	s := openTestStore(t)

	st := &CertState{Name: "c", LastError: strings.Repeat("x", 64*1024)}
	if err := s.PutCert(st); err != nil {
		t.Fatalf("PutCert failed: %v", err)
	}

	got, err := s.GetCert("c")
	if err != nil {
		t.Fatalf("GetCert failed: %v", err)
	}
	if len(got.LastError) > maxLastErrorBytes+len("...") {
		t.Fatalf("last_error was stored unbounded: %d bytes", len(got.LastError))
	}
	if !strings.HasSuffix(got.LastError, "...") {
		t.Errorf("truncation should be visible, got the tail %q", got.LastError[max(0, len(got.LastError)-8):])
	}

	// A short message must survive untouched: truncation must not mangle the
	// ordinary case, which is what an operator actually reads.
	st.LastError = "acme: rate limited"
	if err := s.PutCert(st); err != nil {
		t.Fatalf("PutCert failed: %v", err)
	}
	got, err = s.GetCert("c")
	if err != nil {
		t.Fatalf("GetCert failed: %v", err)
	}
	if got.LastError != "acme: rate limited" {
		t.Errorf("a short last_error must round-trip unchanged, got %q", got.LastError)
	}
}

// The 0600 pre-create is part of the security contract (private keys live in
// this file), so its failure must come back wrapped -- not swallowed, leaving
// the sql.Open below to fail with a message that points at SQLite instead of
// the real permission problem.
func TestOpenReturnsThePrecreateError(t *testing.T) {
	dir := t.TempDir()
	ro := filepath.Join(dir, "ro")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })

	// OpenUnlocked because the exclusive lock file lives in the same directory
	// and would fail even earlier, masking the branch under test.
	_, err := OpenUnlocked(filepath.Join(ro, "state.db"))
	if err == nil {
		t.Fatal("opening a state database in an unwritable directory must fail")
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("the pre-create error must be wrapped, not swallowed, got %v", err)
	}
	if !strings.Contains(err.Error(), "state.db") {
		t.Errorf("the error must name the state file, got %v", err)
	}
}
