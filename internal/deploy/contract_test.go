package deploy

import (
	"context"
	"io"
	"log/slog"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"

	"github.com/susunola/wecert/internal/config"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// stubSSLClient swaps the package-level client constructor and restores it afterwards.
func stubSSLClient(t *testing.T, fake sslAPI) {
	t.Helper()
	orig := newSSLClient
	newSSLClient = func(common.CredentialIface) (sslAPI, error) { return fake, nil }
	t.Cleanup(func() { newSSLClient = orig })
}

// ── constructing the deployer ────────────────────────────────────────────────────────

// NewTencentCLB must carry the configured regions and resource types through to the request
// builder. Omitting them means the one-click update silently targets nothing: CLB is
// regional, so a missing region list updates not one instance.
func TestNewTencentCLBCarriesRegionsAndTypes(t *testing.T) {
	cfg := config.Tencent{
		CredentialMode: config.CredentialStatic, SecretID: "id", SecretKey: "key",
		Regions: []string{"ap-guangzhou", "ap-shanghai"}, ResourceTypes: []string{"clb"},
	}
	d, err := NewTencentCLB(cfg, quietLog())
	if err != nil {
		t.Fatalf("NewTencentCLB: %v", err)
	}
	if !reflect.DeepEqual(d.regions, cfg.Regions) {
		t.Errorf("regions = %v, want %v", d.regions, cfg.Regions)
	}
	if !reflect.DeepEqual(d.types, cfg.ResourceTypes) {
		t.Errorf("resource types = %v, want %v", d.types, cfg.ResourceTypes)
	}
	// The credential must resolve for the configured mode.
	if _, err := d.credential(context.Background()); err != nil {
		t.Errorf("the configured static credential must resolve: %v", err)
	}
}

// An unusable credential configuration must fail at construction rather than at the first
// API call, where it would surface as an opaque authentication error mid-renewal.
func TestNewTencentCLBRejectsAnUnusableCredentialConfig(t *testing.T) {
	// Static mode with nothing anywhere, and an unknown mode, are both decidable now.
	for _, mode := range []string{config.CredentialStatic, "instance-profile"} {
		if _, err := NewTencentCLB(config.Tencent{CredentialMode: mode}, quietLog()); err == nil {
			t.Errorf("credentialMode=%q must be refused at construction", mode)
		}
	}

	// cvm-role is deliberately NOT decidable here. Constructing the source only records the
	// role name; the metadata fetch happens per credential so a temporary token is never
	// stale. The failure therefore belongs to the first credential request, not construction
	// -- see TestCredentialSourceCVMRoleRequiresARoleName.
	d, err := NewTencentCLB(config.Tencent{CredentialMode: config.CredentialCVMRole}, quietLog())
	if err != nil {
		t.Fatalf("cvm-role without a role name must construct and fail on use: %v", err)
	}
	if _, err := d.credential(context.Background()); err == nil {
		t.Error("requesting a cvm-role credential without a role name must fail")
	}
}

// The lazy deployer exists so an enforce-mode process whose document enables no deployment
// never needs static credentials at all. Construction must therefore resolve nothing.
func TestLazyTencentCLBResolvesNothingAtConstruction(t *testing.T) {
	cfg := config.Tencent{CredentialMode: config.CredentialStatic} // deliberately unusable
	d := NewLazyTencentCLB(cfg, quietLog())
	if d == nil {
		t.Fatal("NewLazyTencentCLB returned nil")
	}
	if d.inner != nil {
		t.Error("no client may be built at construction time")
	}
}

// The first operation builds the client; a failure must be reported then, not at construction.
func TestLazyTencentCLBReportsAnUnusableCredentialOnFirstUse(t *testing.T) {
	cfg := config.Tencent{CredentialMode: config.CredentialStatic}
	d := NewLazyTencentCLB(cfg, quietLog())

	if _, err := d.Bindings(context.Background(), "cert-1"); err == nil {
		t.Fatal("first use with an unusable credential config must fail")
	}
	if _, err := d.Deploy(context.Background(), "c", "old", []byte("pem"), []byte("key")); err == nil {
		t.Fatal("Deploy with an unusable credential config must fail")
	}
	if err := d.Delete(context.Background(), "cert-1"); err == nil {
		t.Fatal("Delete with an unusable credential config must fail")
	}
}

// All three operations must go through one shared inner deployer: rebuilding it per call
// would re-read credentials and re-dial the endpoint on every use.
// The lazy wrapper's contract is "no work until something is needed, then work" -- not "one
// SSL client for the process".
//
// TencentCLB.client() builds a fresh SDK client per operation on purpose: it resolves a
// credential each time, so a temporary CVM-role token can never be stale. What the wrapper
// guarantees is that CONSTRUCTION resolves nothing (an enforce-mode deployment whose document
// enables no deploy needs no credentials at all) and that the first operation is where the
// credential is validated and the inner deployer is built once and kept.
func TestLazyTencentCLBDefersWorkUntilFirstUse(t *testing.T) {
	var mu sync.Mutex
	var constructions int
	fake := &fakeSSLAPI{
		uploadFn: func(context.Context, *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error) {
			return &ssl.UploadCertificateResponse{
				Response: &ssl.UploadCertificateResponseParams{CertificateId: common.StringPtr("new-id")},
			}, nil
		},
		createTaskFn: func(context.Context, *ssl.CreateCertificateBindResourceSyncTaskRequest) (*ssl.CreateCertificateBindResourceSyncTaskResponse, error) {
			return &ssl.CreateCertificateBindResourceSyncTaskResponse{
				Response: &ssl.CreateCertificateBindResourceSyncTaskResponseParams{},
			}, nil
		},
	}
	orig := newSSLClient
	newSSLClient = func(common.CredentialIface) (sslAPI, error) {
		mu.Lock()
		constructions++
		mu.Unlock()
		return fake, nil
	}
	t.Cleanup(func() { newSSLClient = orig })

	cfg := config.Tencent{
		CredentialMode: config.CredentialStatic, SecretID: "id", SecretKey: "key",
		Regions: []string{"ap-guangzhou"}, ResourceTypes: []string{"clb"},
	}
	d := NewLazyTencentCLB(cfg, quietLog())

	// Construction: no credential resolution, no SDK client, no inner deployer.
	if d.inner != nil {
		t.Error("constructing the lazy wrapper must not build the inner deployer")
	}
	mu.Lock()
	before := constructions
	mu.Unlock()
	if before != 0 {
		t.Fatalf("constructing the wrapper already built %d SDK client(s)", before)
	}

	// First use: the work happens now.
	if _, err := d.Deploy(context.Background(), "c", "", []byte("pem"), []byte("key")); err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	if d.inner == nil {
		t.Fatal("the first operation must build and keep the inner deployer")
	}
	mu.Lock()
	afterFirst := constructions
	mu.Unlock()
	if afterFirst == 0 {
		t.Error("the first operation must have resolved a credential and built a client")
	}

	// A later operation reuses the memoised inner deployer. It may build its own SDK client
	// again -- that is the per-operation credential refresh -- but it must not rebuild the
	// TencentCLB.
	inner := d.inner
	if _, err := d.Bindings(context.Background(), "cert-1"); err != nil {
		t.Fatalf("Bindings: %v", err)
	}
	if d.inner != inner {
		t.Error("the inner deployer was rebuilt instead of reused")
	}
}

// ── request field mapping ────────────────────────────────────────────────────────────

// Every field the API needs must actually be set. A missing ResourceTypeRegions is the
// quiet one: the request succeeds and updates nothing, because CLB is regional.
func TestUpdateInstanceSetsEveryRequiredField(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)

	var got *ssl.UpdateCertificateInstanceRequest
	fake := &fakeSSLAPI{
		updateFn: func(_ context.Context, req *ssl.UpdateCertificateInstanceRequest) (*ssl.UpdateCertificateInstanceResponse, error) {
			got = req
			return updateResp(42, 1), nil
		},
		detailFn: func(context.Context, *ssl.DescribeHostUpdateRecordDetailRequest) (*ssl.DescribeHostUpdateRecordDetailResponse, error) {
			return detailResp(1, 0, 0), nil
		},
	}
	d := newTestDeployer(clock.now)
	d.regions = []string{"ap-guangzhou", "ap-shanghai"}
	d.types = []string{"clb"}

	if err := d.updateInstance(context.Background(), fake, "old-id", "new-id"); err != nil {
		t.Fatalf("updateInstance: %v", err)
	}
	if got == nil {
		t.Fatal("UpdateCertificateInstance was never called")
	}
	if derefStr(got.OldCertificateId) != "old-id" {
		t.Errorf("OldCertificateId = %q, want old-id", derefStr(got.OldCertificateId))
	}
	if derefStr(got.CertificateId) != "new-id" {
		t.Errorf("CertificateId = %q, want new-id", derefStr(got.CertificateId))
	}
	if len(got.ResourceTypes) != 1 || derefStr(got.ResourceTypes[0]) != "clb" {
		t.Errorf("ResourceTypes = %v, want [clb]", got.ResourceTypes)
	}
	// The per-type region list is what makes the update reach regional resources.
	if len(got.ResourceTypesRegions) != 1 {
		t.Fatalf("ResourceTypesRegions = %v, want one entry per resource type", got.ResourceTypesRegions)
	}
	rt := got.ResourceTypesRegions[0]
	if derefStr(rt.ResourceType) != "clb" {
		t.Errorf("ResourceTypesRegions[0].ResourceType = %q, want clb", derefStr(rt.ResourceType))
	}
	if len(rt.Regions) != 2 {
		t.Errorf("ResourceTypesRegions[0].Regions = %v, want both regions", rt.Regions)
	}
	// Without this the old certificate keeps firing expiry alerts after a successful renewal.
	if got.ExpiringNotificationSwitch == nil || *got.ExpiringNotificationSwitch != 1 {
		t.Errorf("ExpiringNotificationSwitch = %v, want 1", got.ExpiringNotificationSwitch)
	}
}

// The upload must set the type, the alias that makes leftovers findable and reclaimable, and
// Repeatable so a retry of the same material does not fail on the fingerprint check.
func TestUploadSetsEveryDocumentedField(t *testing.T) {
	var got *ssl.UploadCertificateRequest
	fake := &fakeSSLAPI{
		uploadFn: func(_ context.Context, req *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error) {
			got = req
			return &ssl.UploadCertificateResponse{
				Response: &ssl.UploadCertificateResponseParams{CertificateId: common.StringPtr("cert-1")},
			}, nil
		},
	}
	d := newTestDeployer(time.Now)

	const certPEM = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n"
	const keyPEM = "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n"
	id, err := d.upload(context.Background(), fake, "my-cert", []byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if id != "cert-1" {
		t.Errorf("id = %q, want cert-1", id)
	}
	if derefStr(got.CertificateType) != "SVR" {
		t.Errorf("CertificateType = %q, want SVR", derefStr(got.CertificateType))
	}
	if derefStr(got.Alias) != "wecert/my-cert" {
		t.Errorf("Alias = %q, want wecert/my-cert (preflight and the reaper select on this prefix)", derefStr(got.Alias))
	}
	if got.Repeatable == nil || !*got.Repeatable {
		t.Error("Repeatable must be true, otherwise a single upload retry fails on the fingerprint")
	}
	if derefStr(got.CertificatePublicKey) != certPEM {
		t.Error("the certificate PEM must be passed through unchanged")
	}
	if derefStr(got.CertificatePrivateKey) != keyPEM {
		t.Error("the key PEM must be passed through unchanged")
	}
}

// An upload that returns no CertificateId must fail: without an ID there is nothing to record
// and the certificate would leak in the account with no local trace.
func TestUploadFailsWithoutACertificateID(t *testing.T) {
	fake := &fakeSSLAPI{
		uploadFn: func(context.Context, *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error) {
			return &ssl.UploadCertificateResponse{Response: &ssl.UploadCertificateResponseParams{}}, nil
		},
	}
	d := newTestDeployer(time.Now)
	if _, err := d.upload(context.Background(), fake, "c", []byte("pem"), []byte("key")); err == nil {
		t.Fatal("an upload without a CertificateId must fail")
	}
}

// ── Bindings ─────────────────────────────────────────────────────────────────────────

// An empty CertId means "never uploaded", so asking the API about it is pointless.
func TestBindingsWithAnEmptyIDDoesNotCallTheAPI(t *testing.T) {
	stubSSLClient(t, &fakeSSLAPI{}) // every method panics if called
	d := newTestDeployer(time.Now)

	n, err := d.Bindings(context.Background(), "")
	if err != nil {
		t.Fatalf("Bindings(\"\") must not fail: %v", err)
	}
	if n != 0 {
		t.Errorf("Bindings(\"\") = %d, want 0", n)
	}
}

// A task that never appears for this certificate means "not bound", not an error: the first
// issuance uploads without binding, and that is a normal state to report as 0.
func TestBindingsReturnsZeroWhenNoTaskIsCreated(t *testing.T) {
	stubSSLClient(t, &fakeSSLAPI{
		createTaskFn: func(context.Context, *ssl.CreateCertificateBindResourceSyncTaskRequest) (*ssl.CreateCertificateBindResourceSyncTaskResponse, error) {
			return &ssl.CreateCertificateBindResourceSyncTaskResponse{
				Response: &ssl.CreateCertificateBindResourceSyncTaskResponseParams{},
			}, nil
		},
	})
	d := newTestDeployer(time.Now)

	n, err := d.Bindings(context.Background(), "cert-1")
	if err != nil {
		t.Fatalf("Bindings: %v", err)
	}
	if n != 0 {
		t.Errorf("no task means no known binding, got %d", n)
	}
}

// The enumeration is asynchronous, so Bindings must poll until the task reports done rather
// than reading the first (empty) result as "zero bindings" -- which would judge a perfectly
// well-bound certificate as unbound.
func TestBindingsPollsUntilTheTaskCompletes(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)

	var polls int
	stubSSLClient(t, &fakeSSLAPI{
		createTaskFn: stubCreateTask("cert-1", "task-1"),
		taskResultFn: func(context.Context, *ssl.DescribeCertificateBindResourceTaskResultRequest) (*ssl.DescribeCertificateBindResourceTaskResultResponse, error) {
			polls++
			if polls < 3 {
				// Task exists but has no result yet: the shape that used to read as zero.
				return &ssl.DescribeCertificateBindResourceTaskResultResponse{
					Response: &ssl.DescribeCertificateBindResourceTaskResultResponseParams{
						SyncTaskBindResourceResult: []*ssl.SyncTaskBindResourceResult{{
							TaskId: common.StringPtr("task-1"),
							Status: common.Uint64Ptr(0),
						}},
					},
				}, nil
			}
			return bindingsResp("task-1", 2), nil
		},
	})
	d := newTestDeployer(clock.now)

	n, err := d.Bindings(context.Background(), "cert-1")
	if err != nil {
		t.Fatalf("Bindings: %v", err)
	}
	if n != 2 {
		t.Errorf("Bindings = %d, want 2", n)
	}
	if polls < 3 {
		t.Errorf("Bindings returned after %d poll(s) without waiting for the result", polls)
	}
}

// A task that reports an explicit error must surface it rather than spin until the deadline.
func TestBindingsReportsATaskError(t *testing.T) {
	stubSSLClient(t, &fakeSSLAPI{
		createTaskFn: stubCreateTask("cert-1", "task-1"),
		taskResultFn: func(context.Context, *ssl.DescribeCertificateBindResourceTaskResultRequest) (*ssl.DescribeCertificateBindResourceTaskResultResponse, error) {
			return &ssl.DescribeCertificateBindResourceTaskResultResponse{
				Response: &ssl.DescribeCertificateBindResourceTaskResultResponseParams{
					SyncTaskBindResourceResult: []*ssl.SyncTaskBindResourceResult{{
						TaskId: common.StringPtr("task-1"),
						Error:  &ssl.Error{Message: common.StringPtr("certificate not found")},
					}},
				},
			}, nil
		},
	})
	d := newTestDeployer(time.Now)

	_, err := d.Bindings(context.Background(), "cert-1")
	if err == nil {
		t.Fatal("an explicit task error must be reported")
	}
	if !strings.Contains(err.Error(), "certificate not found") {
		t.Errorf("the server's message must survive, got: %v", err)
	}
}

// ── the "which response fields does the code never read" check ───────────────────────

// This is the mechanical version of the review that found three P1s in this file.
//
// Every one of them had the same shape: a response arrived, the code read the fields it
// expected and ignored the rest, and an ignored field was carrying the answer ("the delete
// was accepted but not performed", "a task was already in progress", "the rebind partly
// failed"). Reading the code cannot rule that out; walking the response type can.
//
// The list below is the reviewed set of deliberately-unread fields. A NEW unread field on any
// of these response types fails this test, which is the point: it forces the question "what
// does this field tell us, and are we ignoring it on purpose?" to be answered explicitly.
func TestResponseTypesHaveNoUnreviewedUnreadFields(t *testing.T) {
	unread := map[string][]string{
		"UploadCertificateResponseParams": {
			// Tencent returns the parsed certificate metadata; wecert only needs the ID
			// because everything else is re-derived from the downloaded fullchain.
			"Status", "RequestId", "InsertTime", "CertificateExtra", "Tags",
		},
		"UpdateCertificateInstanceResponseParams": {
			// UpdateSyncProgress IS read (progressBoundCount). The rest is echoed request
			// context.
			"RequestId",
		},
		"DescribeHostUpdateRecordDetailResponseParams": {
			// Only the four counters are the verdict. RecordDetailList is the per-resource
			// breakdown the console shows; the counters already say whether the rebind
			// finished, and the per-resource names add nothing wecert acts on.
			"TotalCount", "RecordDetailList", "RequestId",
		},
		"DeleteCertificateResponseParams": {
			// DeleteResult and TaskId are both read now; the delete task result is polled
			// through DescribeDeleteCertificatesTaskResult.
			"RequestId",
		},
		"DescribeDeleteCertificatesTaskResultResponseParams": {
			// DeleteTaskResult is read; RequestId is not needed.
			"RequestId",
		},
		"CreateCertificateBindResourceSyncTaskResponseParams": {
			// CertTaskIds is read; the rest describes the account.
			"TotalCount", "RequestId",
		},
		"DescribeCertificateBindResourceTaskResultResponseParams": {
			"RequestId",
		},
	}

	for typeName, allowed := range unread {
		for _, field := range unreadFieldsOf(t, typeName) {
			if !containsString(allowed, field) {
				t.Errorf("%s.%s is never read by internal/deploy.\n"+
					"    Every P1 found in this file had this shape: a response field carrying the\n"+
					"    answer (was the delete performed? was a task already running? did the rebind\n"+
					"    partly fail?) while the code read only the fields it expected. Either read it,\n"+
					"    or add it to this test's reviewed list with a reason.",
					typeName, field)
			}
		}
	}
}

// unreadFieldsOf reports the exported fields of a response params struct that no non-test
// source file in this package reads by name.
func unreadFieldsOf(t *testing.T, typeName string) []string {
	t.Helper()

	var typ reflect.Type
	for _, cand := range []reflect.Type{
		reflect.TypeOf(ssl.UploadCertificateResponseParams{}),
		reflect.TypeOf(ssl.UpdateCertificateInstanceResponseParams{}),
		reflect.TypeOf(ssl.DescribeHostUpdateRecordDetailResponseParams{}),
		reflect.TypeOf(ssl.DeleteCertificateResponseParams{}),
		reflect.TypeOf(ssl.DescribeDeleteCertificatesTaskResultResponseParams{}),
		reflect.TypeOf(ssl.CreateCertificateBindResourceSyncTaskResponseParams{}),
		reflect.TypeOf(ssl.DescribeCertificateBindResourceTaskResultResponseParams{}),
	} {
		if cand.Name() == typeName {
			typ = cand
			break
		}
	}
	if typ == nil {
		t.Fatalf("no response type named %s in the reviewed set: the SDK type was renamed or "+
			"replaced, so this check is no longer guarding anything", typeName)
	}

	src := packageSources(t)
	var out []string
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.PkgPath != "" { // unexported
			continue
		}
		// A field counts as read when its name appears in a non-test source file. This is a
		// syntactic check on purpose: it is cheap, it cannot be fooled by interface
		// indirection, and a false "read" is far less costly than a false "unread".
		if !strings.Contains(src, "."+f.Name) && !strings.Contains(src, "Get"+f.Name+"()") {
			out = append(out, f.Name)
		}
	}
	return out
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// packageSources is the concatenation of this package's non-test Go sources, so the
// unread-field check can look for field usage by name.
func packageSources(t *testing.T) string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	var b strings.Builder
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		data, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		b.Write(data)
		b.WriteByte('\n')
	}
	return b.String()
}

// The duplicate-certificate path must produce a usable ID, not an unexplained failure.
//
// The SDK documents that once the same certificate has been uploaded more than 5000 times the
// API ignores Repeatable=true and returns the existing copy's ID as RepeatCertId instead of
// creating another one. Reading only CertificateId turned that into "UploadCertificate
// returned no CertificateId" -- an error that names neither the cause nor what to do.
func TestUploadFallsBackToTheDuplicateCertificateID(t *testing.T) {
	fake := &fakeSSLAPI{
		uploadFn: func(context.Context, *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error) {
			return &ssl.UploadCertificateResponse{
				Response: &ssl.UploadCertificateResponseParams{
					// CertificateId deliberately absent: this is the >5000-copies shape.
					RepeatCertId: common.StringPtr("existing-id"),
				},
			}, nil
		},
	}
	d := newTestDeployer(time.Now)

	id, err := d.upload(context.Background(), fake, "my-cert", []byte("pem"), []byte("key"))
	if err != nil {
		t.Fatalf("a duplicate ID is a usable answer, not a failure: %v", err)
	}
	if id != "existing-id" {
		t.Errorf("id = %q, want existing-id", id)
	}
}
