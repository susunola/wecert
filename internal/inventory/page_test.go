package inventory

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestWritePageGroupsByUIN(t *testing.T) {
	now := time.Date(2026, 9, 22, 7, 45, 0, 0, time.UTC)
	d := 12
	snap := Snapshot{
		Time:    now.UTC().Format(time.RFC3339),
		Summary: Summary{Certificates: 2, Expiring: 1},
		Certificates: []Certificate{
			{Name: "cdn-static", UIN: "100055501234", Status: StatusExpiring, Domains: []string{"static.example.com"}, DaysLeft: &d},
			{Name: "shop-example", UIN: "100098765432", Status: StatusFailing, Domains: []string{"shop.example.com"}, LastError: "DNS-01 timeout"},
		},
	}
	var buf bytes.Buffer
	if err := WritePage(&buf, snap); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	if strings.Contains(html, "https://") && strings.Contains(html, "fonts.") {
		t.Fatal("page must not load an external font")
	}
	for _, want := range []string{
		"cdn-static",
		"shop-example",
		"100055501234",
		"100098765432",
		`data-uin="100055501234"`,
		`data-filter="attention"`,
		"DNS-01 timeout",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("page missing %q", want)
		}
	}
	if strings.Contains(html, "BEGIN CERTIFICATE") {
		t.Fatal("page must not contain PEM")
	}
}

func TestWritePageHidesUINChipsWhenUnset(t *testing.T) {
	snap := Snapshot{
		Certificates: []Certificate{
			{Name: "only", Status: StatusOK, Domains: []string{"only.example"}},
		},
	}
	var buf bytes.Buffer
	if err := WritePage(&buf, snap); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), `id="uins"`) {
		t.Fatal("UIN chips should stay hidden when no certificate has a uin")
	}
}
