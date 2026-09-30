package webhook

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNotificationAdminAuthentication(t *testing.T) {
	calls := 0
	server := adminServer(t, AdminOps{Notifications: func(context.Context, string, map[string]any) (any, error) {
		calls++
		return map[string]bool{"saved": true}, nil
	}})
	for _, test := range []struct {
		token, body string
		status      int
	}{{testToken, `{}`, 401}, {adminTok, `broken`, 400}, {adminTok, `{}`, 200}} {
		req := httptest.NewRequest(http.MethodPut, "/admin/notifications", strings.NewReader(test.body))
		req.Header.Set("Authorization", "Bearer "+test.token)
		res := httptest.NewRecorder()
		server.Handler().ServeHTTP(res, req)
		if res.Code != test.status {
			t.Fatalf("status %d expected %d", res.Code, test.status)
		}
	}
	if calls != 1 {
		t.Fatalf("unexpected callbacks: %d", calls)
	}
}
