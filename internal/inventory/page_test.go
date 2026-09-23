package inventory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

func renderPage(t *testing.T, snap Snapshot) (string, *html.Node) {
	t.Helper()
	var buf bytes.Buffer
	if err := WritePage(&buf, snap); err != nil {
		t.Fatal(err)
	}
	doc, err := html.Parse(strings.NewReader(buf.String()))
	if err != nil {
		t.Fatal(err)
	}
	return buf.String(), doc
}

func walkPage(n *html.Node, visit func(*html.Node)) {
	visit(n)
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		walkPage(child, visit)
	}
}

func pageSnapshot(t *testing.T, doc *html.Node) Snapshot {
	t.Helper()
	var data string
	walkPage(doc, func(n *html.Node) {
		for _, a := range n.Attr {
			if a.Key == "id" && a.Val == "inventory-data" && n.FirstChild != nil {
				data = n.FirstChild.Data
			}
		}
	})
	var snap Snapshot
	if err := json.Unmarshal([]byte(data), &snap); err != nil {
		t.Fatalf("embedded snapshot is not JSON: %v", err)
	}
	return snap
}

func TestWritePagePreservesInventoryEvidence(t *testing.T) {
	t.Parallel()
	frozen, failed, days := true, false, 12
	snap := Snapshot{
		Time:    "2026-09-22T16:30:00Z",
		Desired: DesiredView{Revision: "rev-9", Frozen: &frozen, FreezeReason: "source unavailable"},
		Certificates: []Certificate{{
			Name: "cdn-static", UIN: "100055501234", Status: StatusProbeMismatch,
			Domains: []string{"static.example.com"}, DaysLeft: &days,
			Regions:   []string{"ap-guangzhou", "ap-singapore"},
			Bindings:  Bindings{Count: 1, Complete: false, Freshness: FreshnessStore},
			Probe:     ProbeView{Enabled: true, OK: &failed, Hosts: []HostSample{{Host: "static.example.com", ProblemKind: "untrusted"}}},
			LastError: "DNS-01 timeout", Drift: []string{DriftServedUntrusted},
			ARI: &ARIView{WindowStart: "2026-09-23T00:00:00Z", WindowEnd: "2026-09-24T00:00:00Z"},
		}},
	}
	_, doc := renderPage(t, snap)
	if got := pageSnapshot(t, doc); !reflect.DeepEqual(got, snap) {
		t.Fatalf("page lost inventory evidence: got %+v, want %+v", got, snap)
	}
}

func TestWritePagePreservesUnknownRatherThanInventingHealthyValues(t *testing.T) {
	t.Parallel()
	_, doc := renderPage(t, Snapshot{Certificates: []Certificate{{Name: "unreadable", Status: StatusStateUnreadable}}})
	got := pageSnapshot(t, doc)
	if got.Desired.Frozen != nil || got.Certificates[0].DaysLeft != nil || got.Certificates[0].Probe.OK != nil {
		t.Fatal("unknown freeze, expiry and probe results must remain absent")
	}
	if got.Certificates[0].Bindings.Complete || got.Certificates[0].Probe.Enabled {
		t.Fatal("the renderer must not invent complete bindings or enabled probing")
	}
}

func TestWritePageEscapesUntrustedValuesInDataAndAccountOptions(t *testing.T) {
	t.Parallel()
	attack := `</script><img src=x onerror="alert(1)"><script>alert(2)</script>`
	snap := Snapshot{Desired: DesiredView{Revision: attack}, Certificates: []Certificate{{Name: attack, UIN: attack, Domains: []string{attack}, LastError: attack}}}
	page, doc := renderPage(t, snap)
	if strings.Contains(page, attack) {
		t.Fatal("untrusted text escaped its HTML or JSON context")
	}
	if got := pageSnapshot(t, doc); !reflect.DeepEqual(got, snap) {
		t.Fatal("escaping must preserve the text for safe client-side display")
	}
	scripts := 0
	walkPage(doc, func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			scripts++
		}
		for _, a := range n.Attr {
			if strings.HasPrefix(a.Key, "on") {
				t.Fatalf("injected event handler %s", a.Key)
			}
		}
	})
	if scripts != 3 {
		t.Fatalf("got %d script elements, want only the direct-open redirect, JSON data, and embedded app", scripts)
	}
}

func TestWritePageOffersEveryAccountInOneNativeControl(t *testing.T) {
	t.Parallel()
	certs := make([]Certificate, 250)
	for i := range certs {
		certs[i] = Certificate{Name: fmt.Sprintf("svc-%03d", i), UIN: fmt.Sprintf("1000%08d", i), Status: StatusOK}
	}
	certs = append(certs, certs[0]) // Multiple certificates do not duplicate an account.
	_, doc := renderPage(t, Snapshot{Certificates: certs})
	options := 0
	walkPage(doc, func(n *html.Node) {
		for _, a := range n.Attr {
			if a.Key == "id" && a.Val == "account" {
				if n.Data != "select" {
					t.Fatal("account selection must use one native control")
				}
				walkPage(n, func(option *html.Node) {
					if option.Type == html.ElementNode && option.Data == "option" {
						options++
					}
				})
			}
		}
	})
	if options != 251 {
		t.Fatalf("got %d options, want 250 accounts plus All accounts", options)
	}
}

func TestWritePageEmbedsAssetsAndHasNoWriteControls(t *testing.T) {
	t.Parallel()
	_, doc := renderPage(t, Snapshot{})
	walkPage(doc, func(n *html.Node) {
		if n.Type != html.ElementNode {
			return
		}
		if n.Data == "form" {
			t.Fatal("the inventory must not expose a mutation form")
		}
		for _, a := range n.Attr {
			if a.Key == "src" && (n.Data == "script" || n.Data == "img") && !strings.HasPrefix(a.Val, "data:") {
				t.Fatalf("asset requires a second request: %s", a.Val)
			}
			if n.Data == "link" && a.Key == "href" && !strings.HasPrefix(a.Val, "data:") {
				t.Fatalf("external stylesheet or icon: %s", a.Val)
			}
		}
	})
}

// Optional browser fixture for empty/unknown/error states and hostile strings.
func TestWriteConsoleEdgePreview(t *testing.T) {
	out := os.Getenv("WECERT_EDGE_PREVIEW")
	if out == "" {
		t.Skip("set WECERT_EDGE_PREVIEW to inspect edge states in a browser")
	}
	frozen, failed, days := true, false, -2
	attack := `</script><img src=x onerror="alert(1)">`
	snap := Snapshot{Time: "2026-09-22T16:30:00Z", Desired: DesiredView{Frozen: &frozen, FreezeReason: attack}}
	for _, status := range []string{StatusFrozen, StatusRateLimited, StatusRevokePending, StatusStateUnreadable, StatusNotIssued, StatusWaitingManualBind, StatusPendingDeploy, StatusProbeMismatch, StatusProbeUnreachable, StatusBindingUnknown, StatusProbeUnknown, StatusFailing, StatusExpiring, StatusOK} {
		snap.Certificates = append(snap.Certificates, Certificate{Name: status, Status: status})
	}
	snap.Certificates = append(snap.Certificates, Certificate{
		Name: attack, UIN: "unknown-account", Status: StatusProbeMismatch,
		Domains: []string{attack}, DaysLeft: &days, LastError: attack, Error: attack,
		NotAfter: "2026-09-20T16:30:00Z", NextAttemptAt: "2026-09-23T16:30:00Z", ConsecutiveFailures: 3,
		Bindings: Bindings{Complete: true, Count: 0, Freshness: FreshnessCached},
		Probe: ProbeView{Enabled: true, OK: &failed, Hosts: []HostSample{
			{Host: "unreachable.example.com", ProblemKind: "unreachable"},
			{Host: "wrong.example.com", ProblemKind: "names_missing"},
		}},
		ARI: &ARIView{WindowStart: "2026-09-18T16:30:00Z", WindowEnd: "2026-09-19T16:30:00Z"},
	})
	var buf bytes.Buffer
	if err := WritePage(&buf, snap); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
}
