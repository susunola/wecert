package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/reconcile"
	"github.com/susunola/wecert/internal/state"
)

const testToken = "0123456789abcdef0123456789abcdef"

// fakeReconciler 记录被触发的内容，并按预设返回错误。
type fakeReconciler struct {
	names   []string
	started []string
	failFor map[string]error
}

func (f *fakeReconciler) CertNames() []string { return f.names }

func (f *fakeReconciler) StartCert(_ context.Context, name string) error {
	f.started = append(f.started, name)
	return f.failFor[name]
}

func (f *fakeReconciler) StartAll(_ context.Context) []string {
	var skipped []string
	for _, n := range f.names {
		if err := f.StartCert(context.Background(), n); err != nil {
			skipped = append(skipped, n)
		}
	}
	return skipped
}

func newTestServer(t *testing.T, rec Reconciler) (*Server, *state.Store) {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("打开状态库失败: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(rec, store, testToken, context.Background(), log), store
}

func do(t *testing.T, s *Server, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func bearer() map[string]string {
	return map[string]string{"Authorization": "Bearer " + testToken}
}

// ── 鉴权 ────────────────────────────────────────────────────────────────────

// 这个端点会触发真实签发、消耗速率限制配额，裸奔不可接受。
func TestAuthIsRequired(t *testing.T) {
	rec := &fakeReconciler{names: []string{"a"}}
	s, _ := newTestServer(t, rec)

	for _, tc := range []struct {
		name    string
		headers map[string]string
	}{
		{"无任何头", nil},
		{"空 token", map[string]string{"Authorization": "Bearer "}},
		{"错 token", map[string]string{"Authorization": "Bearer wrongwrongwrong"}},
		{"前缀对但值错", map[string]string{"Authorization": "Bearer " + testToken[:len(testToken)-1] + "X"}},
		{"X-Wecert-Token 错", map[string]string{"X-Wecert-Token": "nope"}},
	} {
		w := do(t, s, http.MethodPost, "/hook/reconcile", "", tc.headers)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: 应返回 401，实际 %d", tc.name, w.Code)
		}
	}
	if len(rec.started) != 0 {
		t.Errorf("鉴权失败时不该触发任何处理，实际 %v", rec.started)
	}
}

func TestAuthAcceptsBothHeaderForms(t *testing.T) {
	for name, headers := range map[string]map[string]string{
		"Bearer": bearer(),
		"X-Wecert-Token": {
			"X-Wecert-Token": testToken,
		},
	} {
		rec := &fakeReconciler{names: []string{"a"}}
		s, _ := newTestServer(t, rec)

		w := do(t, s, http.MethodPost, "/hook/reconcile", `{"cert":"a"}`, headers)
		if w.Code != http.StatusAccepted {
			t.Errorf("%s: 应返回 202，实际 %d", name, w.Code)
		}
	}
}

// 健康检查不能要鉴权，否则探活没法用。
func TestHealthzNeedsNoAuth(t *testing.T) {
	s, _ := newTestServer(t, &fakeReconciler{})

	w := do(t, s, http.MethodGet, "/healthz", "", nil)
	if w.Code != http.StatusOK {
		t.Errorf("healthz 应返回 200，实际 %d", w.Code)
	}
}

// ── 触发 ────────────────────────────────────────────────────────────────────

func TestTriggerAllWhenBodyEmpty(t *testing.T) {
	rec := &fakeReconciler{names: []string{"a", "b"}}
	s, _ := newTestServer(t, rec)

	w := do(t, s, http.MethodPost, "/hook/reconcile", "", bearer())
	if w.Code != http.StatusAccepted {
		t.Fatalf("应返回 202，实际 %d", w.Code)
	}

	var resp reconcileResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if len(resp.Accepted) != 2 {
		t.Errorf("应受理两张证书，实际 %v", resp.Accepted)
	}
}

func TestTriggerSingleCert(t *testing.T) {
	rec := &fakeReconciler{names: []string{"a", "b", "c"}}
	s, _ := newTestServer(t, rec)

	w := do(t, s, http.MethodPost, "/hook/reconcile", `{"cert":"b"}`, bearer())
	if w.Code != http.StatusAccepted {
		t.Fatalf("应返回 202，实际 %d", w.Code)
	}
	if len(rec.started) != 1 || rec.started[0] != "b" {
		t.Errorf("只应触发 b，实际 %v", rec.started)
	}
}

func TestTriggerMultipleCerts(t *testing.T) {
	rec := &fakeReconciler{names: []string{"a", "b", "c"}}
	s, _ := newTestServer(t, rec)

	do(t, s, http.MethodPost, "/hook/reconcile", `{"certs":["a","c"]}`, bearer())

	if len(rec.started) != 2 {
		t.Fatalf("应触发两张，实际 %v", rec.started)
	}
}

func TestTriggerUnknownCertIsReportedNotFatal(t *testing.T) {
	rec := &fakeReconciler{names: []string{"a"}}
	s, _ := newTestServer(t, rec)

	w := do(t, s, http.MethodPost, "/hook/reconcile", `{"cert":"nope"}`, bearer())
	if w.Code != http.StatusAccepted {
		t.Fatalf("未知名字不该让整个请求失败，实际 %d", w.Code)
	}

	var resp reconcileResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Unknown) != 1 || resp.Unknown[0] != "nope" {
		t.Errorf("应把未知名字报在 unknown 里，实际 %+v", resp)
	}
}

// 已在处理中的证书要如实报成 skipped，而不是假装受理了 ——
// 调用方据此判断"这次触发到底有没有真的起作用"。
func TestTriggerBusyCertIsSkipped(t *testing.T) {
	rec := &fakeReconciler{
		names:   []string{"busy"},
		failFor: map[string]error{"busy": reconcile.ErrAlreadyRunning},
	}
	s, _ := newTestServer(t, rec)

	w := do(t, s, http.MethodPost, "/hook/reconcile", `{"cert":"busy"}`, bearer())

	var resp reconcileResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Skipped) != 1 || resp.Skipped[0] != "busy" {
		t.Errorf("应报成 skipped，实际 %+v", resp)
	}
	if len(resp.Accepted) != 0 {
		t.Errorf("不该报成 accepted，实际 %+v", resp)
	}
}

func TestTriggerRejectsBothForms(t *testing.T) {
	s, _ := newTestServer(t, &fakeReconciler{names: []string{"a"}})

	w := do(t, s, http.MethodPost, "/hook/reconcile", `{"cert":"a","certs":["a"]}`, bearer())
	if w.Code != http.StatusBadRequest {
		t.Errorf("同时给 cert 和 certs 应返回 400，实际 %d", w.Code)
	}
}

func TestTriggerRejectsBadJSON(t *testing.T) {
	s, _ := newTestServer(t, &fakeReconciler{names: []string{"a"}})

	w := do(t, s, http.MethodPost, "/hook/reconcile", `{not json`, bearer())
	if w.Code != http.StatusBadRequest {
		t.Errorf("坏 JSON 应返回 400，实际 %d", w.Code)
	}
}

func TestTriggerRejectsGET(t *testing.T) {
	s, _ := newTestServer(t, &fakeReconciler{names: []string{"a"}})

	w := do(t, s, http.MethodGet, "/hook/reconcile", "", bearer())
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET 应返回 405，实际 %d", w.Code)
	}
	if allow := w.Header().Get("Allow"); allow != "POST" {
		t.Errorf("应带 Allow: POST，实际 %q", allow)
	}
}

// ── 状态 ────────────────────────────────────────────────────────────────────

func TestStatusReportsCertificates(t *testing.T) {
	rec := &fakeReconciler{names: []string{"cert-a", "cert-b"}}
	s, store := newTestServer(t, rec)

	notAfter := time.Now().Add(60 * 24 * time.Hour).Truncate(time.Second)
	if err := store.PutCert(&state.CertState{
		Name: "cert-a", NotAfter: notAfter,
		DeployedCertID: "ap123", DeployConfirmed: true,
	}); err != nil {
		t.Fatal(err)
	}

	w := do(t, s, http.MethodGet, "/hook/status", "", bearer())
	if w.Code != http.StatusOK {
		t.Fatalf("应返回 200，实际 %d", w.Code)
	}

	var out struct {
		Certificates []certStatus `json:"certificates"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(out.Certificates) != 2 {
		t.Fatalf("应返回两张证书，实际 %d", len(out.Certificates))
	}

	a := out.Certificates[0]
	if a.Name != "cert-a" || !a.Deployed || !a.DeployConfirmed {
		t.Errorf("cert-a 状态不对: %+v", a)
	}
	if a.DaysLeft == nil || *a.DaysLeft < 58 || *a.DaysLeft > 60 {
		t.Errorf("DaysLeft 不合理: %v", a.DaysLeft)
	}

	// 状态库缺失的证书也要出现，只是没有时间信息。
	if out.Certificates[1].Name != "cert-b" || out.Certificates[1].NotAfter != "" {
		t.Errorf("cert-b 应罗列但无 notAfter: %+v", out.Certificates[1])
	}
}

func TestStatusRequiresAuth(t *testing.T) {
	s, _ := newTestServer(t, &fakeReconciler{names: []string{"a"}})

	w := do(t, s, http.MethodGet, "/hook/status", "", nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("状态端点也应鉴权，实际 %d", w.Code)
	}
}

// ── 出站通知 ────────────────────────────────────────────────────────────────

func TestNotifierPostsEvent(t *testing.T) {
	got := make(chan RenewalEvent, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev RenewalEvent
		_ = json.NewDecoder(r.Body).Decode(&ev)
		got <- ev
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewNotifier(srv.URL, slog.New(slog.NewTextHandler(io.Discard, nil)))
	n.Renewal(context.Background(), "my-cert", nil)

	select {
	case ev := <-got:
		if ev.Event != "renewal" || ev.Cert != "my-cert" || ev.Result != "ok" {
			t.Errorf("事件内容不对: %+v", ev)
		}
		if ev.Timestamp == "" {
			t.Error("事件应带时间戳")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("没有收到通知")
	}
}

func TestNotifierReportsErrorResult(t *testing.T) {
	got := make(chan RenewalEvent, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev RenewalEvent
		_ = json.NewDecoder(r.Body).Decode(&ev)
		got <- ev
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewNotifier(srv.URL, slog.New(slog.NewTextHandler(io.Discard, nil)))
	n.Renewal(context.Background(), "c", errors.New("boom"))

	select {
	case ev := <-got:
		if ev.Result != "error" || !strings.Contains(ev.Error, "boom") {
			t.Errorf("失败事件内容不对: %+v", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("没有收到通知")
	}
}

// 通知目标挂掉不能影响收敛：Renewal 必须立刻返回（它是异步的）。
func TestNotifierDoesNotBlockOnDeadEndpoint(t *testing.T) {
	n := NewNotifier("http://127.0.0.1:1/nowhere", slog.New(slog.NewTextHandler(io.Discard, nil)))

	start := time.Now()
	n.Renewal(context.Background(), "c", nil)
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("Renewal 应当立刻返回，实际耗时 %v", elapsed)
	}
}

func TestNewNotifierDisabledWhenURLEmpty(t *testing.T) {
	if n := NewNotifier("", slog.New(slog.NewTextHandler(io.Discard, nil))); n != nil {
		t.Error("url 为空时应返回 nil")
	}
}
