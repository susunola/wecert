package inventory

import (
	"testing"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
)

func TestStatusTokens(t *testing.T) {
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
			name: "confirmed but never probed is unknown, not ok",
			in: Input{
				Now: now, Names: []string{"a"}, ProbeEnabled: true,
				Certs: map[string]*state.CertState{
					"a": {Name: "a", NotAfter: notAfterOK, DeployedCertID: "c1", DeployConfirmed: true},
				},
			},
			status: StatusBindingUnknown,
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
				Probes: map[string][]HostSample{"a": {{Host: "a.example", Match: true, Trusted: true, NotAfter: notAfterOK}}},
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
	if row.Bindings.Freshness != FreshnessStore || row.Bindings.Count != 0 || !row.Bindings.Complete {
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
	snap := Assemble(Input{Now: time.Unix(0, 0).UTC()})
	if snap.Certificates == nil || len(snap.Certificates) != 0 {
		t.Fatalf("%v", snap.Certificates)
	}
}

func TestSortPutsTroubleFirstThenDaysLeft(t *testing.T) {
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
