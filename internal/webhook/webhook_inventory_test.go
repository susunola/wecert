package webhook

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/susunola/wecert/internal/inventory"
)

func TestInventoryRoutesAreMounted(t *testing.T) {
	s, _ := newTestServer(t, &fakeReconciler{names: []string{"example-com"}})

	if w := do(t, s, http.MethodGet, "/api/inventory", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated inventory: got %d", w.Code)
	}
	if w := do(t, s, http.MethodGet, "/status", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated page: got %d", w.Code)
	}

	w := do(t, s, http.MethodGet, "/api/inventory", "", bearer())
	if w.Code != http.StatusOK {
		t.Fatalf("inventory: got %d body %s", w.Code, w.Body.String())
	}
	var snap inventory.Snapshot
	if err := json.Unmarshal(w.Body.Bytes(), &snap); err != nil {
		t.Fatalf("inventory json: %v", err)
	}
	if len(snap.Certificates) != 1 || snap.Certificates[0].Name != "example-com" {
		t.Fatalf("certificates %+v", snap.Certificates)
	}
	if strings.Contains(w.Body.String(), "BEGIN CERTIFICATE") || strings.Contains(w.Body.String(), "PRIVATE") {
		t.Fatal("inventory payload must not contain PEM")
	}

	page := do(t, s, http.MethodGet, "/status", "", bearer())
	if page.Code != http.StatusOK {
		t.Fatalf("status page: got %d", page.Code)
	}
	if ct := page.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("content-type %q", ct)
	}
	if !strings.Contains(page.Body.String(), "example-com") {
		t.Fatalf("page missing cert name: %s", page.Body.String())
	}
}
