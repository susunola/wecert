package inventory

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
)

// TestWritePreviewPage writes the inventory page with representative data.
//
// Skipped unless WECERT_PREVIEW names a file:
//
//	WECERT_PREVIEW=/tmp/inventory.html go test ./internal/inventory -run TestWritePreviewPage
//
// The page is otherwise only reachable through a running daemon's token-protected
// /status, which makes a layout change hard to look at. This calls the same
// WritePage the handler calls, so what it writes is what the daemon serves.
func TestWritePreviewPage(t *testing.T) {
	out := os.Getenv("WECERT_PREVIEW")
	if out == "" {
		t.Skip("set WECERT_PREVIEW=<file> to write a demo page")
	}
	now := time.Date(2026, 9, 22, 16, 30, 0, 0, time.UTC)
	d := func(days int) time.Time { return now.Add(time.Duration(days) * 24 * time.Hour) }
	ptr := func(t time.Time) *time.Time { return &t }
	sample := func(host string, match, trusted bool, served time.Time, kind string) HostSample {
		s := HostSample{Host: host, Match: match, Trusted: trusted, ProblemKind: kind}
		if !served.IsZero() {
			s.NotAfter = ptr(served)
		}
		return s
	}
	clb := func(region, lb, listener, sni, role string) BindingItem {
		return BindingItem{ResourceType: "clb", Region: region, LoadBalancerID: lb,
			ListenerID: listener, Protocol: "HTTPS", Port: 443, SNIDomain: sni, Role: role, Complete: true}
	}

	rows := []struct {
		name, uin string
		domains   []string
		notAfter  int
		issued    int
		certID    string
		confirmed bool
		failures  int
		lastErr   string
	}{
		{name: "shop-checkout", uin: "100098765432", domains: []string{"shop.example.com", "pay.example.com"}, notAfter: 89, issued: -1, certID: "cYk1A2b3C4d5"},
		{name: "cdn-static", uin: "100055501234", domains: []string{"static.example.com", "img.example.com", "*.cdn.example.com"}, notAfter: 11, issued: -80, certID: "cYk9Z8y7X6w5", confirmed: true},
		{name: "api-gateway", uin: "100012345678", domains: []string{"api.example.com"}, notAfter: 64, issued: -26, certID: "cYk4D5e6F7g8", confirmed: true},
		{name: "legacy-portal", uin: "100012345678", domains: []string{"portal.example.com"}, notAfter: 52, issued: -38, certID: "cYk7H8i9J0k1", confirmed: true},
		{name: "mail-relay", uin: "100012345678", domains: []string{"mail.example.com"}, notAfter: 41, issued: -49, certID: "cYk2L3m4N5o6", confirmed: true,
			failures: 3, lastErr: "dns-01: the TXT record was not visible on all authoritative nameservers after 240s"},
		{name: "wildcard-edge", uin: "100055501234", domains: []string{"*.edge.example.com", "edge.example.com"}, notAfter: 77, issued: -13, certID: "cYk6P7q8R9s0", confirmed: true},
		{name: "bulk-import", uin: "100098765432", domains: []string{"import.example.com"}},
		{name: "partner-sso", uin: "100098765432", domains: []string{"sso.partner-example.com"}, notAfter: 70, issued: -20, certID: "cYk3T4u5V6w7", confirmed: true},
		{name: "reporting-api", uin: "100012345678", domains: []string{"reporting.example.com"}, notAfter: 58, issued: -32, certID: "cYk5B6c7D8e9", confirmed: true},
		{name: "legacy-cdn", uin: "100055501234", domains: []string{"legacy-cdn.example.com"}, notAfter: 44, issued: -46, certID: "cYk8F9g0H1i2", confirmed: true},
	}
	// Enough accounts that the picker has to scroll: an installation with a few
	// hundred is the case the account control exists for.
	for i := 1; i <= 30; i++ {
		rows = append(rows, struct {
			name, uin string
			domains   []string
			notAfter  int
			issued    int
			certID    string
			confirmed bool
			failures  int
			lastErr   string
		}{
			name: fmt.Sprintf("svc-%02d", i), uin: fmt.Sprintf("1000%08d", i),
			domains:  []string{fmt.Sprintf("svc-%02d.example.com", i)},
			notAfter: 30 + i, issued: -20, certID: fmt.Sprintf("cYkfiller%02d", i), confirmed: true,
		})
	}

	certs := make([]config.Certificate, 0, len(rows))
	certState := map[string]*state.CertState{}
	names := make([]string, 0, len(rows))
	for _, r := range rows {
		certs = append(certs, config.Certificate{
			Name: r.name, Domains: r.domains, Profile: "classic", KeyType: "ecdsa-p256",
			UIN: r.uin, Deploy: config.Deploy{Enabled: true},
		})
		names = append(names, r.name)
		if r.notAfter != 0 || r.certID != "" {
			certState[r.name] = &state.CertState{
				Name: r.name, NotAfter: d(r.notAfter), IssuedAt: d(r.issued),
				DeployedCertID: r.certID, DeployConfirmed: r.confirmed,
				ConsecutiveFailures: r.failures, LastError: r.lastErr,
			}
		}
	}
	desired := &spec.Result{Revision: "rev-2026-09-22.3", GeneratedAt: now.Add(-37 * time.Minute), Certificates: certs}

	snap := Assemble(Input{
		Now: now, Desired: desired, Names: names,
		ProbeEnabled: true, ResourceTypes: []string{"clb"},
		Certs: certState,
		Probes: map[string][]HostSample{
			"shop-checkout": {sample("shop.example.com", true, true, d(89), "")},
			"cdn-static":    {sample("static.example.com", true, true, d(11), ""), sample("img.example.com", true, true, d(11), "")},
			"api-gateway":   {sample("api.example.com", false, true, d(64), "names_missing")},
			"mail-relay":    {sample("mail.example.com", true, true, d(41), "")},
			"wildcard-edge": {sample("edge.example.com", true, true, d(77), "")},
			"legacy-portal": {sample("portal.example.com", false, false, time.Time{}, "unreachable")},
			"partner-sso":   {sample("sso.partner-example.com", false, false, d(70), "untrusted")},
		},
		LiveBindings: map[string]Bindings{
			"wildcard-edge": {ResourceTypes: []string{"clb"}, Count: 2, Complete: true, Freshness: FreshnessCached,
				ObservedAt: now.Add(-6 * time.Minute).Format(time.RFC3339),
				Items: []BindingItem{
					clb("ap-guangzhou", "lb-8f3k2m1p", "lbl-3k9d2s", "edge.example.com", "primary"),
					clb("ap-singapore", "lb-2w7x4y9z", "lbl-8h2k5v", "*.edge.example.com", "ext"),
				}},
			"shop-checkout": {ResourceTypes: []string{"clb"}, Count: 1, Complete: false, Freshness: FreshnessCached,
				ObservedAt: now.Add(-19 * time.Minute).Format(time.RFC3339),
				Items:      []BindingItem{clb("ap-guangzhou", "lb-6t2n8q4r", "lbl-1p7m3c", "shop.example.com", "primary")}},
			"legacy-cdn": {ResourceTypes: []string{"clb"}, Count: 0, Complete: false, Freshness: FreshnessCached,
				ObservedAt: now.Add(-52 * time.Minute).Format(time.RFC3339), Items: []BindingItem{}},
		},
	})

	f, err := os.Create(out)
	if err != nil {
		t.Fatalf("create %s: %v", out, err)
	}
	defer f.Close()
	if err := WritePage(f, snap); err != nil {
		t.Fatalf("write page: %v", err)
	}
	t.Logf("wrote %s (%d certificates, %d accounts)", out, snap.Summary.Certificates, len(uniqueUINs(snap)))
}

func uniqueUINs(snap Snapshot) map[string]bool {
	seen := map[string]bool{}
	for _, c := range snap.Certificates {
		seen[c.UIN] = true
	}
	return seen
}
