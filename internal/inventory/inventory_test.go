package inventory

import (
	"testing"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
)

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
