package webhook

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
)

type diagnosticReader struct {
	result *spec.Result
	calls  int
}

func (d *diagnosticReader) Prime(context.Context)                   { d.calls++ }
func (d *diagnosticReader) LastResult() *spec.Result                { return d.result }
func (d *diagnosticReader) CertNames() []string                     { return nil }
func (d *diagnosticReader) StartCert(context.Context, string) error { return nil }
func (d *diagnosticReader) StartNamed(context.Context, []string) ([]string, []string, []string, error) {
	return nil, nil, nil, nil
}
func (d *diagnosticReader) StartAll(context.Context) ([]string, []string, error) {
	return nil, nil, nil
}

func TestDesiredDiagnosticIsAuthenticatedReadOnly(t *testing.T) {
	d := &diagnosticReader{result: &spec.Result{Revision: "r1", Certificates: []config.Certificate{{Name: "example"}}}}
	// New refuses a nil store: the status and inventory routes are mounted on every
	// server and dereference it, so even a test that only exercises /diagnostics needs
	// a real one.
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	s, err := New(d, store, "0123456789abcdef", context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/diagnostics/desired-state", nil)
	req.Header.Set("Authorization", "Bearer 0123456789abcdef")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if d.calls != 1 {
		t.Fatalf("Prime calls = %d, want 1", d.calls)
	}
}
