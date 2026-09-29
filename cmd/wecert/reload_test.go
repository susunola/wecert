package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/inventory"
	"github.com/susunola/wecert/internal/ratelimit"
	"github.com/susunola/wecert/internal/reconcile"
	"github.com/susunola/wecert/internal/spec"
	"github.com/susunola/wecert/internal/state"
	"github.com/susunola/wecert/internal/webhook"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
)

func TestRuntimeControllerImplementsBindingReader(t *testing.T) {
	if _, ok := any((*runtimeController)(nil)).(webhook.BindingReader); !ok {
		t.Fatal("runtimeController must expose cached bindings to the webhook")
	}
}

func TestRuntimeControllerBindingSnapshotConcurrentSwap(t *testing.T) {
	controller := newRuntimeController(nil, &reconcile.Reconciler{}, nil, nil)
	reader, ok := any(controller).(webhook.BindingReader)
	if !ok {
		t.Fatal("runtimeController must implement webhook.BindingReader")
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 1000; i++ {
			controller.mu.Lock()
			controller.rec = &reconcile.Reconciler{}
			controller.mu.Unlock()
		}
	}()
	close(start)
	for i := 0; i < 1000; i++ {
		if _, hit := reader.BindingSnapshot(""); hit {
			t.Error("an empty certificate ID must miss the binding cache")
		}
	}
	wg.Wait()
}

type bindingFixtureTransport func(*http.Request) (*http.Response, error)

func (f bindingFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type inventoryOnlyManager struct{ reconcile.CertManager }

func (inventoryOnlyManager) QuotaStatus(map[string][]string) []ratelimit.QuotaReport { return nil }

func TestRuntimeControllerInventoryUsesCachedBindings(t *testing.T) {
	// The SDK transport is process-global, so this test must not run in parallel.
	// It returns fixtures only: no request can reach a cloud endpoint.
	const certID = "runtime-controller-binding-fixture"
	oldClient := common.DefaultHttpClient
	t.Cleanup(func() {
		common.DefaultHttpClient = oldClient
		deploy.ForgetBindings(certID)
	})
	deploy.ForgetBindings(certID)
	calls := 0
	common.DefaultHttpClient = &http.Client{Transport: bindingFixtureTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		var body string
		switch r.Header.Get("X-TC-Action") {
		case "CreateCertificateBindResourceSyncTask":
			body = `{"Response":{"CertTaskIds":[{"CertId":"` + certID + `","TaskId":"fixture-task"}]}}`
		case "DescribeCertificateBindResourceTaskResult":
			body = `{"Response":{"SyncTaskBindResourceResult":[{"TaskId":"fixture-task","Status":1,"BindResourceResult":[{"BindResourceRegionResult":[{"TotalCount":1}]}]}]}}`
		case "DescribeCertificateBindResourceTaskDetail":
			body = `{"Response":{"Status":1,"CLB":[{"Region":"ap-singapore","TotalCount":1,"InstanceList":[{"LoadBalancerId":"lb-fixture","Listeners":[{"ListenerId":"lbl-fixture","Protocol":"HTTPS","Certificate":{"CertId":"` + certID + `"},"Rules":[{"Domain":"example.com","Certificate":{"CertId":"` + certID + `"}}]}]}]}]}}`
		default:
			return nil, fmt.Errorf("unexpected SDK action %q", r.Header.Get("X-TC-Action"))
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}
	log, _ := quietLog()
	cfg := &config.Config{
		Tencent: config.Tencent{
			CredentialMode: config.CredentialStatic, SecretID: "fixture-id", SecretKey: "fixture-key",
			// The detail cache remains CLB-only even when deployment targets more types.
			ResourceTypes: []string{"clb", "cdn"}, Regions: []string{"ap-singapore"},
		},
		Certificates: []config.Certificate{{Name: "example-com", Domains: []string{"example.com"}, Deploy: config.Deploy{Enabled: true}}},
	}
	d, err := deploy.NewTencentCLB(cfg.Tencent, log)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if count, complete, err := d.Bindings(ctx, certID); err != nil || count != 1 || !complete {
		t.Fatalf("seed cached binding: count=%d complete=%v err=%v", count, complete, err)
	}
	if calls != 3 {
		t.Fatalf("fixture SDK requests = %d, want 3", calls)
	}
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.PutCert(&state.CertState{
		Name: "example-com", NotAfter: time.Now().Add(80 * 24 * time.Hour),
		DeployedCertID: certID, DeployConfirmed: true,
	}); err != nil {
		t.Fatal(err)
	}
	rec := reconcile.New(cfg, spec.NewStatic(cfg.Certificates), store, inventoryOnlyManager{}, nil, log)
	controller := newRuntimeController(cfg, rec, nil, store)
	controller.Prime(ctx)
	want, hit := rec.BindingSnapshot(certID)
	if !hit || want.Count != 1 || !want.Complete || len(want.Items) != 1 || want.ObservedAt == "" {
		t.Fatalf("fixture was not cached: %+v hit=%v", want, hit)
	}
	server, err := webhook.New(controller, store, "fixture-token", ctx, log)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/inventory", nil)
	request.Header.Set("Authorization", "Bearer fixture-token")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("inventory: %d %s", response.Code, response.Body.String())
	}
	var snap inventory.Snapshot
	if err := json.Unmarshal(response.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if len(snap.Certificates) != 1 {
		t.Fatalf("inventory rows = %+v", snap.Certificates)
	}
	if !reflect.DeepEqual(want.ResourceTypes, []string{"clb"}) {
		t.Errorf("cached scope must explicitly describe the CLB-only observation, got %v", want.ResourceTypes)
	}
	row := snap.Certificates[0]
	if !reflect.DeepEqual(row.Bindings, want) {
		t.Errorf("bindings through runtimeController = %+v, want %+v", row.Bindings, want)
	}
	if !reflect.DeepEqual(row.Regions, []string{"ap-singapore"}) || row.Status != inventory.StatusOK {
		t.Errorf("cached binding inventory row = %+v", row)
	}
	if calls != 3 {
		t.Errorf("inventory performed SDK requests: got %d total, want only the 3 fixture-seeding requests", calls)
	}
}

func TestReloadImmutableRejectsResourceIdentityChanges(t *testing.T) {
	base := &config.Config{}
	base.StatePath = "/var/lib/wecert/state.db"
	base.ACME.Directory = "https://acme.example/directory"
	base.Metrics.Listen = "127.0.0.1:9800"
	base.Webhook.Listen = "127.0.0.1:9801"

	cases := []struct {
		name string
		edit func(*config.Config)
		want string
	}{
		{"state", func(c *config.Config) { c.StatePath = "/other/state.db" }, "statePath"},
		{"directory", func(c *config.Config) { c.ACME.Directory = "https://other/directory" }, "acme.directory"},
		{"metrics", func(c *config.Config) { c.Metrics.Listen = "127.0.0.1:9900" }, "metrics.listen"},
		{"webhook", func(c *config.Config) { c.Webhook.Listen = "127.0.0.1:9901" }, "webhook.listen"},
		{"stateEncryption", func(c *config.Config) { c.StateEncryption.KeyFile = "/other/master.key" }, "stateEncryption"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			next := *base
			tc.edit(&next)
			err := reloadImmutable(base, &next)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("reloadImmutable() = %v, want error mentioning %q", err, tc.want)
			}
		})
	}
	if err := reloadImmutable(base, base); err != nil {
		t.Fatalf("identical config should reload: %v", err)
	}
}
