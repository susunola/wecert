package inventory

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
)

// selfSignedPEM builds a certificate in the shape the inventory parses.
//
// Generated rather than pasted as a fixture on purpose: the serial the page shows has to come out
// of the DER of the certificate that is actually stored, and a hard-coded PEM would keep passing
// after the parse path stopped reading it.
func selfSignedPEM(t *testing.T, serial *big.Int, names ...string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Unix(1790000000, 0),
		NotAfter:     time.Unix(1893456000, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestStatusTokens(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	notAfterOK := now.Add(80 * 24 * time.Hour)
	notAfterSoon := now.Add(10 * 24 * time.Hour)

	tests := []struct {
		name   string
		in     Input
		status string
		drift  []string
	}{
		{
			name: "frozen desired state wins",
			in: Input{
				Now: now,
				Desired: &spec.Result{
					Frozen: true, FreezeReason: "source unread",
					Certificates: []config.Certificate{{Name: "a", Domains: []string{"a.example"}}},
				},
				Certs: map[string]*state.CertState{
					"a": {Name: "a", NotAfter: notAfterOK, DeployedCertID: "c1", DeployConfirmed: true},
				},
			},
			status: StatusFrozen, drift: []string{DriftDesiredFrozen},
		},
		{
			name: "rate limited",
			in: Input{
				Now: now, Names: []string{"a"}, RateLimited: map[string]bool{"a": true},
				Certs: map[string]*state.CertState{
					"a": {Name: "a", NotAfter: notAfterOK, DeployedCertID: "c1", DeployConfirmed: true},
				},
			},
			status: StatusRateLimited,
		},
		{
			name: "revoke pending",
			in: Input{
				Now: now, Names: []string{"a"}, RevokePending: map[string]bool{"a": true},
				Certs: map[string]*state.CertState{
					"a": {Name: "a", NotAfter: notAfterOK, DeployedCertID: "c1", DeployConfirmed: true},
				},
			},
			status: StatusRevokePending,
		},
		{
			name: "waiting for the one-time console bind",
			in: Input{
				Now: now, Names: []string{"a"},
				Certs: map[string]*state.CertState{
					"a": {Name: "a", NotAfter: notAfterOK, DeployedCertID: "c1"},
				},
			},
			status: StatusWaitingManualBind,
			drift:  []string{DriftWaitingManualBind, DriftIssuedNotConfirmed},
		},
		{
			name: "probe mismatch",
			in: Input{
				Now: now, Names: []string{"a"}, ProbeEnabled: true,
				Certs: map[string]*state.CertState{
					"a": {Name: "a", NotAfter: notAfterOK, DeployedCertID: "c1", DeployConfirmed: true},
				},
				Probes: map[string][]HostSample{"a": {{Host: "a.example", Match: false, ProblemKind: "not_after"}}},
			},
			status: StatusProbeMismatch, drift: []string{DriftServedNotAfter},
		},
		{
			name: "confirmed but never probed is unverified, not ok",
			in: Input{
				Now: now, Names: []string{"a"}, ProbeEnabled: true,
				Certs: map[string]*state.CertState{
					"a": {Name: "a", NotAfter: notAfterOK, DeployedCertID: "c1", DeployConfirmed: true},
				},
			},
			// Not binding_unknown: the bindings are known here, the served
			// certificate has simply not been read yet. Saying "binding unknown" sent
			// operators to the load-balancer console for a probe that had not run.
			status: StatusProbeUnknown,
		},
		{
			name: "a host that cannot be dialled is not a probe mismatch",
			in: Input{
				Now: now, Names: []string{"a"}, ProbeEnabled: true,
				Certs: map[string]*state.CertState{
					"a": {Name: "a", NotAfter: notAfterOK, DeployedCertID: "c1", DeployConfirmed: true},
				},
				Probes: map[string][]HostSample{"a": {{Host: "a.example", Match: false, ProblemKind: "unreachable"}}},
			},
			status: StatusProbeUnreachable,
		},
		{
			name: "an untrusted chain is drift even though the names match",
			in: Input{
				Now: now, Names: []string{"a"}, ProbeEnabled: true,
				Certs: map[string]*state.CertState{
					"a": {Name: "a", NotAfter: notAfterOK, DeployedCertID: "c1", DeployConfirmed: true},
				},
				Probes: map[string][]HostSample{"a": {{Host: "a.example", Match: false, ProblemKind: "untrusted", NotAfter: &notAfterOK}}},
			},
			status: StatusProbeMismatch, drift: []string{DriftServedUntrusted},
		},
		{
			name: "a mismatch with no reported kind invents no drift token",
			in: Input{
				Now: now, Names: []string{"a"}, ProbeEnabled: true,
				Certs: map[string]*state.CertState{
					"a": {Name: "a", NotAfter: notAfterOK, DeployedCertID: "c1", DeployConfirmed: true},
				},
				Probes: map[string][]HostSample{"a": {{Host: "a.example", Match: false}}},
			},
			status: StatusProbeMismatch,
		},
		{
			name: "consecutive failures",
			in: Input{
				Now: now, Names: []string{"a"},
				Certs: map[string]*state.CertState{
					"a": {Name: "a", NotAfter: notAfterOK, DeployConfirmed: true, ConsecutiveFailures: 3, LastError: "dns"},
				},
			},
			status: StatusFailing, drift: []string{DriftConsecutiveFailures},
		},
		{
			name: "inside the default renew window",
			in: Input{
				Now: now, Names: []string{"a"},
				Certs: map[string]*state.CertState{
					"a": {Name: "a", NotAfter: notAfterSoon, DeployConfirmed: true},
				},
			},
			status: StatusExpiring,
		},
		{
			name: "ok when probe is off and the cert is confirmed",
			in: Input{
				Now: now, Names: []string{"a"}, ProbeEnabled: false,
				Certs: map[string]*state.CertState{
					"a": {Name: "a", NotAfter: notAfterOK, DeployedCertID: "c1", DeployConfirmed: true},
				},
			},
			status: StatusOK,
		},
		{
			name: "ok when every sample matches",
			in: Input{
				Now: now, Names: []string{"a"}, ProbeEnabled: true,
				Certs: map[string]*state.CertState{
					"a": {Name: "a", NotAfter: notAfterOK, DeployedCertID: "c1", DeployConfirmed: true},
				},
				Probes: map[string][]HostSample{"a": {{Host: "a.example", Match: true, Trusted: true, NotAfter: &notAfterOK}}},
			},
			status: StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snap := Assemble(tt.in)
			if len(snap.Certificates) != 1 {
				t.Fatalf("got %d rows", len(snap.Certificates))
			}
			row := snap.Certificates[0]
			if row.Status != tt.status {
				t.Fatalf("status: got %q want %q", row.Status, tt.status)
			}
			if !equalStrings(row.Drift, tt.drift) {
				t.Fatalf("drift: got %v want %v", row.Drift, tt.drift)
			}
			if row.Bindings.Items == nil {
				t.Fatal("bindings.items must serialize as [] not null")
			}
		})
	}
}

func TestWaitingManualBindUsesStoreBindings(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	snap := Assemble(Input{
		Now: now, Names: []string{"example-com"}, ResourceTypes: []string{"clb"},
		Certs: map[string]*state.CertState{
			"example-com": {Name: "example-com", NotAfter: now.Add(89 * 24 * time.Hour), DeployedCertID: "cYk1"},
		},
	})
	row := snap.Certificates[0]
	if row.Status != StatusWaitingManualBind {
		t.Fatalf("status %q", row.Status)
	}
	if row.Bindings.Freshness != FreshnessStore || row.Bindings.Count != 0 || row.Bindings.Complete {
		// An uploaded certificate that the cloud has not confirmed is a lower bound of
		// zero, not "bound nowhere": the manual console bind may already exist and this
		// program cannot see it yet.
		t.Fatalf("bindings %+v", row.Bindings)
	}
	if row.DaysLeft == nil || *row.DaysLeft != 89 {
		t.Fatalf("daysLeft %+v", row.DaysLeft)
	}
	if snap.Summary.WaitingManualBind != 1 {
		t.Fatalf("summary %+v", snap.Summary)
	}
}

func TestEmptyInventorySerializesAsEmptySlice(t *testing.T) {
	t.Parallel()
	snap := Assemble(Input{Now: time.Unix(0, 0).UTC()})
	if snap.Certificates == nil || len(snap.Certificates) != 0 {
		t.Fatalf("%v", snap.Certificates)
	}
}

func TestSortPutsTroubleFirstThenDaysLeft(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	snap := Assemble(Input{
		Now: now, Names: []string{"ok-far", "wait", "ok-near"}, ProbeEnabled: false,
		Certs: map[string]*state.CertState{
			"wait":    {Name: "wait", NotAfter: now.Add(40 * 24 * time.Hour), DeployedCertID: "c1"},
			"ok-near": {Name: "ok-near", NotAfter: now.Add(20 * 24 * time.Hour), DeployConfirmed: true},
			"ok-far":  {Name: "ok-far", NotAfter: now.Add(80 * 24 * time.Hour), DeployConfirmed: true},
		},
	})
	if snap.Certificates[0].Name != "wait" {
		t.Fatalf("first %q", snap.Certificates[0].Name)
	}
	if snap.Certificates[1].Name != "ok-near" || snap.Certificates[1].Status != StatusExpiring {
		t.Fatalf("second %+v", snap.Certificates[1])
	}
}

func TestAssembleCopiesUIN(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	snap := Assemble(Input{
		Now: now, Names: []string{"a", "b"}, UIN: "100012345678",
		Desired: &spec.Result{
			Certificates: []config.Certificate{
				{Name: "a", Domains: []string{"a.example"}},
				{Name: "b", Domains: []string{"b.example"}, UIN: "100098765432"},
			},
		},
	})
	if len(snap.Certificates) != 2 {
		t.Fatalf("got %d rows", len(snap.Certificates))
	}
	byName := map[string]Certificate{}
	for _, c := range snap.Certificates {
		byName[c.Name] = c
	}
	if byName["a"].UIN != "100012345678" {
		t.Fatalf("a uin: got %q", byName["a"].UIN)
	}
	if byName["b"].UIN != "100098765432" {
		t.Fatalf("cert-level uin must win: got %q", byName["b"].UIN)
	}
}

// The Tencent Cloud SSL console identifies a certificate by its remark, not by anything
// wecert-side, so every row has to carry the remark it was uploaded under
// ("wecert/<name>"). Without it an operator can see a name in this page and a different
// string in the console and has no way to tell that they are the same certificate.
func TestAssembleCarriesTheUploadAlias(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	snap := Assemble(Input{
		Now: now, Names: []string{"joontest-xyz"},
		Desired: &spec.Result{
			Certificates: []config.Certificate{
				{Name: "joontest-xyz", Domains: []string{"joontest.xyz"}},
			},
		},
		Certs: map[string]*state.CertState{
			"joontest-xyz": {
				Name: "joontest-xyz", NotAfter: now.Add(80 * 24 * time.Hour),
				DeployedCertID: "b9PFzILI", DeployConfirmed: true,
			},
		},
	})
	if len(snap.Certificates) != 1 {
		t.Fatalf("got %d rows", len(snap.Certificates))
	}
	row := snap.Certificates[0]
	if row.Alias != "wecert/joontest-xyz" {
		t.Fatalf("alias = %q, want wecert/joontest-xyz (the remark the uploader writes)", row.Alias)
	}
	if row.DeployedCertID != "b9PFzILI" {
		t.Fatalf("deployedCertId = %q", row.DeployedCertID)
	}
}

// A row has to state the certificate's own identity, not only what wecert and the cloud call it.
//
// The wecert name and the cloud certificate id both stop existing the moment a customer changes
// DNS provider, cloud account, or deployment target; the serial number is on the certificate
// itself, and it is what a browser, an auditor, or a CA support ticket will ask for. The previous
// certificate and the rollback window travel with it for the same reason: "which certificate did
// this name serve before" is a question asked exactly when something is wrong with the current one.
func TestAssembleCarriesTheCertificateIdentity(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	swappedAt := time.Unix(1790000000, 0).UTC()
	retiredAt := time.Unix(1790003600, 0).UTC()
	serial := new(big.Int).SetBytes([]byte{0x04, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0xa7})

	snap := Assemble(Input{
		Now: now, Names: []string{"joontest-xyz"},
		Desired: &spec.Result{
			Certificates: []config.Certificate{
				{Name: "joontest-xyz", Domains: []string{"joontest.xyz", "renew-test.joontest.xyz"}},
			},
		},
		Certs: map[string]*state.CertState{
			"joontest-xyz": {
				Name:            "joontest-xyz",
				NotAfter:        now.Add(80 * 24 * time.Hour),
				CertURL:         "https://acme-v02.api.letsencrypt.org/acme/cert/04a1b2c3d4e5f6a7",
				CertPEM:         selfSignedPEM(t, serial, "joontest.xyz", "renew-test.joontest.xyz"),
				ARICertID:       "YWtp.04a1b2c3d4e5f6a7",
				IssuedAt:        now.Add(-time.Hour),
				DeployedCertID:  "b9PFzILI",
				DeployConfirmed: true,
				PreviousCertID:  "b9Previous",
				SwappedAt:       swappedAt,
			},
		},
		Retired: map[string][]RetiredRef{
			"joontest-xyz": {
				{CertID: "b9Previous", RetiredAt: retiredAt.Format(time.RFC3339)},
				// The orphan path records an upload with no material and no usable time; it still
				// has to appear, because the cloud certificate it names counts against the quota.
				{CertID: "b9Orphan"},
			},
		},
	})
	if len(snap.Certificates) != 1 {
		t.Fatalf("got %d rows", len(snap.Certificates))
	}
	row := snap.Certificates[0]

	if row.Serial != "4A1B2C3D4E5F6A7" {
		t.Errorf("serial = %q, want the certificate's own serial in upper-case hex", row.Serial)
	}
	if row.ACMECertURL != "https://acme-v02.api.letsencrypt.org/acme/cert/04a1b2c3d4e5f6a7" {
		t.Errorf("acmeCertUrl = %q", row.ACMECertURL)
	}
	if row.ARICertID != "YWtp.04a1b2c3d4e5f6a7" {
		t.Errorf("ariCertId = %q", row.ARICertID)
	}
	if row.Previous == nil {
		t.Fatal("previous is missing: the row must say which certificate this name served before")
	}
	if row.Previous.CertID != "b9Previous" || row.Previous.SwappedAt != swappedAt.Format(time.RFC3339) {
		t.Errorf("previous = %+v, want b9Previous at %s", row.Previous, swappedAt.Format(time.RFC3339))
	}
	if len(row.Retired) != 2 {
		t.Fatalf("retired = %+v, want both rows inside the rollback window", row.Retired)
	}
	if row.Retired[0].CertID != "b9Previous" || row.Retired[0].RetiredAt != retiredAt.Format(time.RFC3339) {
		t.Errorf("retired[0] = %+v", row.Retired[0])
	}
	if row.Retired[1].CertID != "b9Orphan" || row.Retired[1].RetiredAt != "" {
		t.Errorf("retired[1] = %+v, want the material-less orphan row with no time", row.Retired[1])
	}
}

// A certificate that predates the swap columns states no previous certificate rather than an
// invented one, and its serial still comes from the material it holds.
func TestAssembleWithoutASwapRecord(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	snap := Assemble(Input{
		Now: now, Names: []string{"first-bind"},
		Desired: &spec.Result{
			Certificates: []config.Certificate{{Name: "first-bind", Domains: []string{"first.example"}}},
		},
		Certs: map[string]*state.CertState{
			"first-bind": {
				Name: "first-bind", NotAfter: now.Add(80 * 24 * time.Hour),
				CertPEM:        selfSignedPEM(t, big.NewInt(0x1234), "first.example"),
				DeployedCertID: "b9First", DeployConfirmed: true,
			},
		},
	})
	if len(snap.Certificates) != 1 {
		t.Fatalf("got %d rows", len(snap.Certificates))
	}
	row := snap.Certificates[0]
	if row.Previous != nil {
		t.Errorf("previous = %+v, want none for a name that has never been swapped", row.Previous)
	}
	if row.Serial != "1234" {
		t.Errorf("serial = %q, want 1234", row.Serial)
	}
	if len(row.Retired) != 0 {
		t.Errorf("retired = %+v, want empty", row.Retired)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestACertificateThatWasNeverIssuedIsNotHealthy(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	snap := Assemble(Input{
		Now: now, Names: []string{"never"},
		Desired: &spec.Result{Certificates: []config.Certificate{
			{Name: "never", Domains: []string{"never.example"}},
		}},
	})
	row := snap.Certificates[0]
	if row.Status != StatusNotIssued {
		t.Fatalf("status %q: a certificate with no state row is not healthy", row.Status)
	}
	if row.Bindings.Complete {
		t.Fatalf("bindings %+v: nothing was enumerated, so the count is not the whole set", row.Bindings)
	}
	if row.DaysLeft != nil || row.NotAfter != "" {
		t.Fatalf("expiry invented for a certificate that does not exist: %v %q", row.DaysLeft, row.NotAfter)
	}
	if snap.Summary.NotIssued != 1 {
		t.Fatalf("summary %+v", snap.Summary)
	}
}

func TestAStateRowThatCouldNotBeReadIsNotABindingProblem(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	snap := Assemble(Input{
		Now: now, Names: []string{"a"},
		CertErrors: map[string]string{"a": "sql: database is closed"},
	})
	row := snap.Certificates[0]
	if row.Status != StatusStateUnreadable {
		t.Fatalf("status %q", row.Status)
	}
	if !equalStrings(row.Drift, []string{DriftStateUnreadable}) {
		t.Fatalf("drift %v", row.Drift)
	}
	if row.Error != "sql: database is closed" {
		t.Fatalf("error %q", row.Error)
	}
	if row.Bindings.Complete {
		t.Fatalf("bindings %+v", row.Bindings)
	}
	if snap.Summary.Unreadable != 1 {
		t.Fatalf("summary %+v", snap.Summary)
	}
}

func TestAnIssuedCertificateThatWasNeverUploadedIsPendingDeploy(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	in := Input{
		Now: now, Names: []string{"a"},
		Desired: &spec.Result{Certificates: []config.Certificate{
			{Name: "a", Domains: []string{"a.example"}, Deploy: config.Deploy{Enabled: true}},
		}},
		Certs: map[string]*state.CertState{"a": {Name: "a", NotAfter: now.Add(80 * 24 * time.Hour)}},
	}
	if got := Assemble(in).Certificates[0].Status; got != StatusPendingDeploy {
		t.Fatalf("status %q", got)
	}
	// A certificate whose deployment is switched off never waits for an upload, so
	// the same row is healthy there.
	in.ProbeEnabled = false
	in.Desired = &spec.Result{Certificates: []config.Certificate{
		{Name: "a", Domains: []string{"a.example"}, Deploy: config.Deploy{Enabled: false}},
	}}
	if got := Assemble(in).Certificates[0].Status; got != StatusOK {
		t.Fatalf("deploy disabled: status %q", got)
	}
}

func TestALiveEnumerationThatCameBackIncompleteIsBindingUnknown(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	snap := Assemble(Input{
		Now: now, Names: []string{"a"}, ProbeEnabled: false,
		Certs: map[string]*state.CertState{
			"a": {Name: "a", NotAfter: now.Add(80 * 24 * time.Hour), DeployedCertID: "c1", DeployConfirmed: true},
		},
		LiveBindings: map[string]Bindings{"a": {
			Count: 0, Complete: false, Freshness: FreshnessCached,
			ObservedAt: "2026-09-22T05:00:00Z", Items: []BindingItem{},
		}},
	})
	row := snap.Certificates[0]
	if row.Status != StatusBindingUnknown {
		t.Fatalf("status %q: an incomplete enumeration with no binding is binding_unknown, not healthy", row.Status)
	}
	if snap.Summary.BindingUnknown != 1 {
		t.Fatalf("summary %+v: the live rows must be part of the status, not painted on after it", snap.Summary)
	}
	if row.Bindings.ObservedAt != "2026-09-22T05:00:00Z" {
		t.Fatalf("observedAt %q: stale rows must carry when they were observed", row.Bindings.ObservedAt)
	}
	if !equalStrings(row.Drift, []string{DriftBindingIncomplete}) {
		t.Fatalf("drift %v", row.Drift)
	}
}

func TestALiveEnumerationThatAnsweredZeroIsNotUnknown(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	snap := Assemble(Input{
		Now: now, Names: []string{"a"}, ProbeEnabled: false,
		Certs: map[string]*state.CertState{
			"a": {Name: "a", NotAfter: now.Add(80 * 24 * time.Hour), DeployedCertID: "c1", DeployConfirmed: true},
		},
		LiveBindings: map[string]Bindings{"a": {
			Count: 0, Complete: true, Freshness: FreshnessCached, Items: []BindingItem{},
		}},
	})
	row := snap.Certificates[0]
	if row.Status != StatusOK || snap.Summary.BindingUnknown != 0 {
		t.Fatalf("status %q summary %+v: an answered zero is an answer", row.Status, snap.Summary)
	}
	if row.Bindings.Freshness != FreshnessCached {
		t.Fatalf("freshness %q", row.Bindings.Freshness)
	}
}

func TestConfirmedStoreBindingsAreALowerBound(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	snap := Assemble(Input{
		Now: now, Names: []string{"a"}, ProbeEnabled: false,
		Certs: map[string]*state.CertState{
			"a": {Name: "a", NotAfter: now.Add(80 * 24 * time.Hour), DeployedCertID: "c1", DeployConfirmed: true},
		},
	})
	b := snap.Certificates[0].Bindings
	if b.Count != 1 || b.Complete {
		t.Fatalf("bindings %+v: the store sees what this program deployed, which is a lower bound", b)
	}
	if b.Freshness != FreshnessStore {
		t.Fatalf("freshness %q", b.Freshness)
	}
}

func TestAnUnreadDesiredStateDoesNotClaimNotFrozen(t *testing.T) {
	t.Parallel()
	snap := Assemble(Input{Now: time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC), Names: []string{"a"}})
	if snap.Desired.Frozen != nil {
		t.Fatalf("frozen %v: the document was never read, so false is an invented answer", *snap.Desired.Frozen)
	}
}

func TestRegionsAreTheObservedBindingRegions(t *testing.T) {
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	in := Input{
		Now: now, Names: []string{"bound", "unseen"}, ProbeEnabled: false,
		Certs: map[string]*state.CertState{
			"bound":  {Name: "bound", NotAfter: now.Add(80 * 24 * time.Hour), DeployedCertID: "c1", DeployConfirmed: true},
			"unseen": {Name: "unseen", NotAfter: now.Add(80 * 24 * time.Hour), DeployedCertID: "c2", DeployConfirmed: true},
		},
		LiveBindings: map[string]Bindings{
			"bound": {
				Count: 3, Complete: true, Freshness: FreshnessCached, Items: []BindingItem{
					{Region: "ap-singapore", LoadBalancerID: "lb-2"},
					{Region: "ap-guangzhou", LoadBalancerID: "lb-1"},
					{Region: "ap-guangzhou", LoadBalancerID: "lb-3"},
				},
			},
		},
	}
	rows := map[string]Certificate{}
	for _, row := range Assemble(in).Certificates {
		rows[row.Name] = row
	}
	if got := rows["bound"].Regions; !equalStrings(got, []string{"ap-guangzhou", "ap-singapore"}) {
		t.Fatalf("regions %v, want the distinct observed regions in sorted order", got)
	}
	if got := rows["unseen"].Regions; got != nil {
		// The store cannot enumerate bindings, so a region nobody observed must stay
		// absent rather than become a guess or a zero.
		t.Fatalf("regions %v, want unknown for a certificate with no live rows", got)
	}
	if got := rows["bound"].Bindings.Items; len(got) != 3 {
		t.Fatalf("items %v", got)
	}
}
