package inventory

import (
	"testing"
	"time"

	"github.com/susunola/wecert/internal/state"
)

func TestApplyLiveBindingsNamesTheCLB(t *testing.T) {
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	snap := Assemble(Input{
		Now: now, Names: []string{"example-com"}, ProbeEnabled: false,
		Certs: map[string]*state.CertState{
			"example-com": {Name: "example-com", NotAfter: now.Add(80 * 24 * time.Hour), DeployedCertID: "cYk1", DeployConfirmed: true},
		},
	})
	row := snap.Certificates[0]
	ApplyLiveBindings(&row, Bindings{
		Count: 1, Complete: true, Freshness: FreshnessCached,
		Items: []BindingItem{{
			ResourceType: "clb", Region: "ap-guangzhou",
			LoadBalancerID: "lb-aaaa", ListenerID: "lbl-bbbb",
			Protocol: "HTTPS", SNIDomain: "www.example.com", Role: "primary", Complete: true,
		}},
	})
	if row.Bindings.Items[0].LoadBalancerID != "lb-aaaa" {
		t.Fatalf("%+v", row.Bindings)
	}
	if row.Bindings.Freshness != FreshnessCached {
		t.Fatalf("freshness %q", row.Bindings.Freshness)
	}
}

func TestApplyLiveBindingsIncompleteAddsDrift(t *testing.T) {
	row := Certificate{Name: "a"}
	ApplyLiveBindings(&row, Bindings{Complete: false, Items: []BindingItem{}})
	if len(row.Drift) != 1 || row.Drift[0] != DriftBindingIncomplete {
		t.Fatalf("%v", row.Drift)
	}
}
