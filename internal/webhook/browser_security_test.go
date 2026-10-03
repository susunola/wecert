package webhook

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSessionRejectsOversizedUnauthenticatedBody(t *testing.T) {
	s := &Server{token: "valid", now: time.Now, limiter: newAuthLimiter()}
	req := httptest.NewRequest(http.MethodPost, "/api/session", strings.NewReader(`{"token":"`+strings.Repeat("x", 2<<20)+`"}`))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d, want 413", w.Code)
	}
}

func TestBrowserMutationRequiresSameOrigin(t *testing.T) {
	for _, tc := range []struct {
		name, origin, site string
		want               int
	}{
		{"sibling subdomain", "https://evil.example.com", "same-site", 403},
		{"cross site", "https://evil.invalid", "cross-site", 403},
		{"origin fallback", "https://evil.example.com", "", 403},
		{"same origin", "https://console.example.com", "same-origin", 200},
		{"same origin fallback", "https://console.example.com", "", 200},
		{"API client", "", "", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			s := &Server{adminToken: "valid", now: time.Now, limiter: newAuthLimiter(), ops: AdminOps{UnbindCertificate: func(context.Context, string) (any, error) { called = true; return "ok", nil }}}
			req := httptest.NewRequest(http.MethodPost, "https://console.example.com/admin/certificates/test/unbind", nil)
			req.Header.Set("Origin", tc.origin)
			req.Header.Set("Sec-Fetch-Site", tc.site)
			if tc.name == "API client" {
				req.Header.Set("Authorization", "Bearer valid")
			} else {
				req.AddCookie(&http.Cookie{Name: cookieAdmin, Value: "valid"})
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, req)
			if w.Code != tc.want || called != (tc.want == 200) {
				t.Fatalf("status=%d called=%v, want %d", w.Code, called, tc.want)
			}
		})
	}
}
