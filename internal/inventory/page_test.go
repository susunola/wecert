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

func TestWritePageShowsTheReasonsBehindTheNewStatuses(t *testing.T) {
	frozen := true
	snap := Snapshot{
		Time:    time.Date(2026, 9, 22, 8, 0, 0, 0, time.UTC).Format(time.RFC3339),
		Desired: DesiredView{Revision: "rev-9", Frozen: &frozen, FreezeReason: "desired source unread"},
		Summary: Summary{Certificates: 2, NotIssued: 1},
		Certificates: []Certificate{
			{Name: "never", Status: StatusNotIssued, Domains: []string{"never.example"}},
			{Name: "bound", Status: StatusOK, Domains: []string{"bound.example"},
				Bindings: Bindings{Count: 1, Freshness: FreshnessStore, Items: []BindingItem{}}},
		},
	}
	var buf bytes.Buffer
	if err := WritePage(&buf, snap); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	for _, want := range []string{
		"frozen · desired source unread",
		"Not issued",
		// A store-side count is a lower bound and must not read as the whole set.
		"≥1",
		// not_issued is something to look at, so the Attention filter keeps it.
		`data-status="not_issued"`,
		`data-attention="1"`,
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("page missing %q", want)
		}
	}
}

func TestWritePageSaysWhenTheDesiredStateWasNeverRead(t *testing.T) {
	snap := Snapshot{Certificates: []Certificate{{Name: "a", Status: StatusOK}}}
	var buf bytes.Buffer
	if err := WritePage(&buf, snap); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	if !strings.Contains(html, "desired state not read") {
		t.Fatal("a revision that was never read must not render as an empty one")
	}
	if strings.Contains(html, "frozen ·") {
		t.Fatal("an unread document is not a frozen one")
	}
}
