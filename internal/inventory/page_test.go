package inventory

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestWritePageGroupsByUIN(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	snap := Snapshot{Certificates: []Certificate{{Name: "a", Status: StatusOK}}}
	var buf bytes.Buffer
	if err := WritePage(&buf, snap); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	// The header renders this as a labelled pair ("Desired state" / "not read"),
	// which is the same claim the sentence made: the document was never read, so no
	// revision exists to show.
	if !strings.Contains(html, "desired state") || !strings.Contains(html, ">not read<") {
		t.Fatal("a revision that was never read must not render as an empty one")
	}
	if strings.Contains(html, "frozen ·") {
		t.Fatal("an unread document is not a frozen one")
	}
}

func TestWritePageOffersEveryAccountInOneControl(t *testing.T) {
	t.Parallel()
	// An installation can carry hundreds of accounts. They belong in one picker,
	// not in a row of chips that grows with the fleet.
	certs := make([]Certificate, 0, 250)
	for i := 1; i <= 250; i++ {
		certs = append(certs, Certificate{
			Name: fmt.Sprintf("svc-%03d", i), UIN: fmt.Sprintf("1000%08d", i),
			Status: StatusOK, Domains: []string{fmt.Sprintf("svc-%03d.example.com", i)},
		})
	}
	snap := Snapshot{Certificates: certs, Summary: Summary{Certificates: len(certs)}}
	var buf bytes.Buffer
	if err := WritePage(&buf, snap); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	if got := strings.Count(html, `role="option"`); got != len(certs)+1 {
		t.Fatalf("account picker has %d options, want %d (every account plus the all-accounts entry)", got, len(certs)+1)
	}
	if strings.Contains(html, `class="chip`) {
		t.Fatal("accounts must not be rendered as a chip row")
	}
	if !strings.Contains(html, `aria-haspopup="listbox"`) {
		t.Fatal("the account control must be a listbox popup, so it can be opened and filtered")
	}
}
