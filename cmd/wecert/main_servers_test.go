package main

// Tests for the two HTTP listeners main.go starts.
//
// Both are started by a function that binds the port synchronously and returns an error on
// failure, and both decisions are load-bearing: /metrics is the only expiry alerting channel
// this system has, and the webhook is the only entrance to the event-driven path. "Occupied
// port, one log line, carry on" therefore looks perfectly healthy from the outside while every
// signal is lost -- which is why run() turns either failure into a non-zero exit, and why the
// webhook construction path has to hand the port back when it refuses the configuration.
//
// The listeners are exercised through real loopback sockets, allocated by the OS and never
// dialled outside 127.0.0.1, so no test here depends on an external service.

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/metrics"
	"github.com/susunola/wecert/internal/state"
)

// serverStore opens the state database the listeners need, in the test's own directory.
func serverStore(t *testing.T) *state.Store {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// httpGet issues a loopback request with a short timeout, so a listener that never answers
// fails the test instead of hanging the package.
func httpGet(t *testing.T, url string, headers map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build the request: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read the response body: %v", err)
	}
	return resp.StatusCode, string(body)
}

// The metrics server must actually serve, and must stop when the process context is cancelled.
//
// The interesting half is the shutdown: run() returns while the listener's goroutine is still
// holding the socket, and a listener that ignored ctx.Done() would keep the port bound after
// the process decided to exit -- which is what makes an immediate restart fail with "address
// already in use" and sends the operator looking for a phantom instance.
func TestStartMetricsServerServesAndStopsWithTheContext(t *testing.T) {
	addr := freeAddress(t)
	ctx, cancel := context.WithCancel(context.Background())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := startMetricsServer(ctx, addr, log); err != nil {
		t.Fatalf("startMetricsServer on a free port: %v", err)
	}

	if code, body := httpGet(t, "http://"+addr+"/healthz", nil); code != http.StatusOK || strings.TrimSpace(body) != "ok" {
		t.Errorf("GET /healthz = %d %q, want 200 ok: the health endpoint is what systemd and every "+
			"watchdog probe", code, body)
	}
	if code, body := httpGet(t, "http://"+addr+"/metrics", nil); code != http.StatusOK {
		t.Errorf("GET /metrics = %d, want 200: expiry alerting is driven by this endpoint", code)
	} else if !strings.Contains(body, "wecert_") {
		t.Error("the metrics handler must serve this program's collectors, not an empty registry")
	}

	cancel()
	// Shutdown is asynchronous, so wait for the port rather than assuming it is free the
	// instant the context is cancelled.
	deadline := time.Now().Add(5 * time.Second)
	for {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			_ = ln.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the metrics listener still holds %s after shutdown: %v", addr, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A port that is already taken must be an error, and the message must say what to do about it.
//
// The failure this prevents is silent: the process looks healthy, /metrics never answers, and
// certificates slide toward expiry with nobody being paged. The hint about running the daemon
// and the timer at once is the actual cause in the field, so it is pinned here.
func TestStartMetricsServerReportsAnOccupiedPort(t *testing.T) {
	addr := occupiedAddress(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	err := startMetricsServer(context.Background(), addr, log)
	if err == nil {
		t.Fatal("a port that cannot be bound must fail, not degrade to a log line")
	}
	for _, want := range []string{"metrics port", addr, "already in use"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error must carry %q so the operator knows which port and why, got: %v", want, err)
		}
	}
}

// webhookReconciler is the smallest webhook.Reconciler: the server's read-only routes call
// CertNames, and the trigger routes are not touched by these tests.
type webhookReconciler struct{ names []string }

func (r webhookReconciler) CertNames() []string { return r.names }

func (r webhookReconciler) StartCert(context.Context, string) error { return nil }

func (r webhookReconciler) StartNamed(context.Context, []string) ([]string, []string, []string, error) {
	return nil, nil, nil, nil
}

func (r webhookReconciler) StartAll(context.Context) ([]string, []string, error) {
	return nil, nil, nil
}

// An empty webhook.listen means disabled, and that must not be an error: the timer-only
// deployment is a supported shape, and the configuration layer has already refused every
// contradictory combination (a token with no address is rejected there).
func TestStartWebhookServerIsOffWithoutAListenAddress(t *testing.T) {
	log, buf := quietLog()
	api, err := startWebhookServer(context.Background(), &config.Config{}, webhookReconciler{}, serverStore(t), log)
	if err != nil {
		t.Fatalf("webhook.listen is empty, which means disabled and not failure: %v", err)
	}
	if api != nil {
		t.Error("no listener may be started when there is no address")
	}
	if !strings.Contains(buf.String(), "webhook disabled") {
		t.Errorf("the operator has to be able to tell the timer-only deployment from a broken "+
			"webhook, got:\n%s", buf.String())
	}
}

// The endpoint must serve, and it must be authenticated.
//
// Without the token comparison the trigger endpoint is an unauthenticated "place a real order
// now" button, and every call spends CA rate limit -- so the 401 half of this test is the
// security property, not a nicety.
func TestStartWebhookServerServesTheTriggerEndpointBehindItsToken(t *testing.T) {
	addr := freeAddress(t)
	const token = "0123456789abcdef0123456789abcdef"
	cfg := &config.Config{
		StatePath: filepath.Join(t.TempDir(), "state.db"),
		Webhook:   config.Webhook{Listen: addr, Token: token},
	}
	cfg.Tencent.UIN = "100012345678"
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	api, err := startWebhookServer(ctx, cfg, webhookReconciler{names: []string{"example-com"}}, serverStore(t), log)
	if err != nil {
		t.Fatalf("startWebhookServer: %v", err)
	}
	if api == nil {
		t.Fatal("a configured webhook must return the server, or nothing can rotate its token on reload")
	}

	// The metrics server binds the same way; this one must not become a second way in.
	if code, _ := httpGet(t, "http://"+addr+"/hook/status", nil); code != http.StatusUnauthorized {
		t.Errorf("GET /hook/status without a token = %d, want 401 in place of an anonymous trigger", code)
	}

	code, body := httpGet(t, "http://"+addr+"/hook/status", map[string]string{"Authorization": "Bearer " + token})
	if code != http.StatusOK {
		t.Fatalf("GET /hook/status with the configured token = %d, want 200", code)
	}
	if !strings.Contains(body, "example-com") {
		t.Errorf("the status endpoint must report the reconciler's certificates, got: %s", body)
	}
}

// A webhook the constructor refuses must not leave its port bound.
//
// The situation is ordinary: an operator edits webhook.token to something the constructor
// rejects, restarts, and fixes it. If the refused start keeps the socket, the corrected run
// fails with "address already in use" and points at an instance that is not running -- so the
// fix for one mistake looks like a second, unrelated one. The port is proven free by binding it
// again, which is the only honest check.
func TestStartWebhookServerReleasesThePortWhenTheConfigIsRefused(t *testing.T) {
	addr := freeAddress(t)
	cfg := &config.Config{
		StatePath: filepath.Join(t.TempDir(), "state.db"),
		// A listen address with no token: webhook.NewWithAdmin refuses it, and config.Load would
		// have too -- this is the same refusal, from the layer that must not leak the port.
		Webhook: config.Webhook{Listen: addr, Token: ""},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	_, err := startWebhookServer(context.Background(), cfg, webhookReconciler{}, serverStore(t), log)
	if err == nil {
		t.Fatal("a webhook with no token must be refused: the endpoint triggers real issuance")
	}
	if !strings.Contains(err.Error(), "has been released") {
		t.Errorf("the error must say the port was handed back, got: %v", err)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("the port %s is still bound after the refused start: %v", addr, err)
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
}

// The webhook server must also stop when the process context is cancelled, for the same reason
// the metrics server does -- a bound port left behind turns the next start into a phantom.
func TestStartWebhookServerStopsWithTheContext(t *testing.T) {
	addr := freeAddress(t)
	cfg := &config.Config{
		StatePath: filepath.Join(t.TempDir(), "state.db"),
		Webhook:   config.Webhook{Listen: addr, Token: "0123456789abcdef0123456789abcdef"},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	ctx, cancel := context.WithCancel(context.Background())
	if _, err := startWebhookServer(ctx, cfg, webhookReconciler{}, serverStore(t), log); err != nil {
		t.Fatalf("startWebhookServer: %v", err)
	}
	cancel()

	deadline := time.Now().Add(5 * time.Second)
	for {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			_ = ln.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the webhook listener still holds %s after shutdown: %v", addr, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The metrics of this process are shared with the whole package: reading one here proves
	// the test file did not perturb them, and gives the metric registry a reason to be imported
	// alongside the server it describes.
	if got := testutil.ToFloat64(metrics.BackupRemoteErrors.WithLabelValues("unused-server-test", "s3")); got != 0 {
		t.Errorf("an unrelated counter started at %v, want 0", got)
	}
}
