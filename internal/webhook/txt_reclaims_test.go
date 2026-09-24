package webhook

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/acme"
)

type fakeTXTQueue struct {
	rows []*acme.TXTReclaimStuck
	err  error
}

func (f *fakeTXTQueue) ListStuckTXTReclaims() ([]*acme.TXTReclaimStuck, error) {
	return f.rows, f.err
}

func TestTXTReclaimsViewIsReadOnlyAndListsTheQueue(t *testing.T) {
	rec := &fakeReconciler{names: []string{"a"}}
	s, _ := newTestServer(t, rec)
	// Mount requires the lister on rec; use a server whose rec also implements it.
	s2, _ := newTestServer(t, &struct {
		*fakeReconciler
		*fakeTXTQueue
	}{&fakeReconciler{names: []string{"a"}}, &fakeTXTQueue{rows: []*acme.TXTReclaimStuck{{
		CertName: "www", Identifier: "www.example.com",
		TxtName: "_acme-challenge.www.example.com.", TxtValue: "v",
		Attempts: 3, LastError: "ns unreachable",
		StuckSince: time.Now().Add(-time.Hour),
	}}}})
	_ = s

	// GET with auth
	w := do(t, s2, http.MethodGet, "/diagnostics/txt-reclaims", "", bearer())
	if w.Code != http.StatusOK {
		t.Fatalf("GET = %d, body %s", w.Code, w.Body.String())
	}
	var body struct {
		ReadOnly bool `json:"readOnly"`
		Count    int  `json:"count"`
		Items    []struct {
			TxtName string `json:"txtName"`
		} `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.ReadOnly || body.Count != 1 || body.Items[0].TxtName != "_acme-challenge.www.example.com." {
		t.Fatalf("unexpected body %+v", body)
	}

	// POST is refused: this is a view, not a write path.
	if w := do(t, s2, http.MethodPost, "/diagnostics/txt-reclaims", "", bearer()); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST = %d, want 405", w.Code)
	}
	// Auth still required.
	if w := do(t, s2, http.MethodGet, "/diagnostics/txt-reclaims", "", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("no auth = %d, want 401", w.Code)
	}
}
