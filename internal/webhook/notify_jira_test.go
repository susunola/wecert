package webhook

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/susunola/wecert/internal/config"
)

// Search-before-create: an open issue for the same certificate is commented on,
// not duplicated.
func TestJiraReusesAnOpenIssueForTheSameCertificate(t *testing.T) {
	var mu sync.Mutex
	var created, commented int
	var lastLabels []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/search"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issues": []map[string]string{{"key": "OPS-1"}},
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/comment"):
			commented++
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/issue"):
			created++
			var body struct {
				Fields struct {
					Labels []string `json:"labels"`
				} `json:"fields"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			lastLabels = body.Fields.Labels
			_ = json.NewEncoder(w).Encode(map[string]string{"key": "OPS-2"})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	n := NewNotifierJira(srv.URL, "", config.NotifyFormatJira, "", JiraTarget{
		BaseURL: srv.URL, ProjectKey: "OPS", IssueType: "Bug",
		Email: "ops@example.com", APIToken: "token",
		ReuseOpenIssue: true,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	ev := RenewalEvent{Event: "renewal", Cert: "www", Result: "error", Error: "boom", Timestamp: "2026-09-24T00:00:00Z"}
	if err := n.deliverJira(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if created != 0 || commented != 1 {
		t.Fatalf("created=%d commented=%d, want 0/1", created, commented)
	}
	_ = lastLabels

	// No open issue -> create with wecert labels.
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/search"):
			_ = json.NewEncoder(w).Encode(map[string]any{"issues": []any{}})
		case strings.HasSuffix(r.URL.Path, "/issue"):
			created++
			var body struct {
				Fields struct {
					Labels  []string `json:"labels"`
					Summary string   `json:"summary"`
				} `json:"fields"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			lastLabels = body.Fields.Labels
			_ = json.NewEncoder(w).Encode(map[string]string{"key": "OPS-3"})
		}
	})
	if err := n.deliverJira(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if created != 1 {
		t.Fatalf("created=%d, want 1", created)
	}
	joined := strings.Join(lastLabels, ",")
	if !strings.Contains(joined, "wecert") || !strings.Contains(joined, "wecert-cert-www") {
		t.Errorf("labels = %v, want wecert and wecert-cert-www", lastLabels)
	}
}

// Success renewals do not open tickets.
func TestJiraSkipsSuccessfulRenewals(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	n := NewNotifierJira(srv.URL, "", config.NotifyFormatJira, "", JiraTarget{
		BaseURL: srv.URL, ProjectKey: "OPS", IssueType: "Bug",
		Email: "ops@example.com", APIToken: "token",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := n.deliverJira(context.Background(), RenewalEvent{Cert: "www", Result: "ok"}); err != nil {
		t.Fatal(err)
	}
	if hits != 0 {
		t.Errorf("success hit the API %d times, want 0", hits)
	}
}

func TestJiraLabelSanitizesCertificateName(t *testing.T) {
	if got := jiraLabel("*.Example.COM"); got != "example.com" {
		t.Errorf("jiraLabel = %q", got)
	}
	if got := jiraLabel("has space/and*star"); got != "has-space-and-star" {
		t.Errorf("jiraLabel = %q", got)
	}
}
