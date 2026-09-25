package deploy

import (
	"context"
	"errors"
	tcerrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"

	"github.com/susunola/wecert/internal/tcerr"
)

// ── The sslAPI seam ─────────────────────────────────────────────────────────
//
// These tests exist because of the seam: *ssl.Client is a concrete SDK type, so the
// polling loops in updateInstance and waitDeployRecord used to be reachable only
// against the real cloud. fakeSSLAPI implements sslAPI with per-method closures, and
// package-level hooks (newSSLClient, waitBetweenPolls) plus the injectable now field
// make every branch of the polling logic deterministic to test.

// fakeSSLAPI implements sslAPI with a closure per method. A nil closure panics, which
// fails the test -- an unexpected call is exactly what a test should catch.
type fakeSSLAPI struct {
	uploadFn     func(context.Context, *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error)
	updateFn     func(context.Context, *ssl.UpdateCertificateInstanceRequest) (*ssl.UpdateCertificateInstanceResponse, error)
	detailFn     func(context.Context, *ssl.DescribeHostUpdateRecordDetailRequest) (*ssl.DescribeHostUpdateRecordDetailResponse, error)
	deleteFn     func(context.Context, *ssl.DeleteCertificateRequest) (*ssl.DeleteCertificateResponse, error)
	deleteTaskFn func(context.Context, *ssl.DescribeDeleteCertificatesTaskResultRequest) (*ssl.DescribeDeleteCertificatesTaskResultResponse, error)
	createTaskFn func(context.Context, *ssl.CreateCertificateBindResourceSyncTaskRequest) (*ssl.CreateCertificateBindResourceSyncTaskResponse, error)
	taskResultFn func(context.Context, *ssl.DescribeCertificateBindResourceTaskResultRequest) (*ssl.DescribeCertificateBindResourceTaskResultResponse, error)
	listCertsFn  func(context.Context, *ssl.DescribeCertificatesRequest) (*ssl.DescribeCertificatesResponse, error)
}

func (f *fakeSSLAPI) UploadCertificateWithContext(ctx context.Context, req *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error) {
	if f.uploadFn == nil {
		panic("unexpected UploadCertificate call")
	}
	return f.uploadFn(ctx, req)
}

func (f *fakeSSLAPI) UpdateCertificateInstanceWithContext(ctx context.Context, req *ssl.UpdateCertificateInstanceRequest) (*ssl.UpdateCertificateInstanceResponse, error) {
	if f.updateFn == nil {
		panic("unexpected UpdateCertificateInstance call")
	}
	return f.updateFn(ctx, req)
}

func (f *fakeSSLAPI) DescribeHostUpdateRecordDetailWithContext(ctx context.Context, req *ssl.DescribeHostUpdateRecordDetailRequest) (*ssl.DescribeHostUpdateRecordDetailResponse, error) {
	if f.detailFn == nil {
		panic("unexpected DescribeHostUpdateRecordDetail call")
	}
	return f.detailFn(ctx, req)
}

func (f *fakeSSLAPI) DeleteCertificateWithContext(ctx context.Context, req *ssl.DeleteCertificateRequest) (*ssl.DeleteCertificateResponse, error) {
	if f.deleteFn == nil {
		panic("unexpected DeleteCertificate call")
	}
	return f.deleteFn(ctx, req)
}

func (f *fakeSSLAPI) CreateCertificateBindResourceSyncTaskWithContext(ctx context.Context, req *ssl.CreateCertificateBindResourceSyncTaskRequest) (*ssl.CreateCertificateBindResourceSyncTaskResponse, error) {
	if f.createTaskFn == nil {
		panic("unexpected CreateCertificateBindResourceSyncTask call")
	}
	return f.createTaskFn(ctx, req)
}

func (f *fakeSSLAPI) DescribeCertificateBindResourceTaskResultWithContext(ctx context.Context, req *ssl.DescribeCertificateBindResourceTaskResultRequest) (*ssl.DescribeCertificateBindResourceTaskResultResponse, error) {
	if f.taskResultFn == nil {
		panic("unexpected DescribeCertificateBindResourceTaskResult call")
	}
	return f.taskResultFn(ctx, req)
}

func (f *fakeSSLAPI) DescribeCertificatesWithContext(ctx context.Context, req *ssl.DescribeCertificatesRequest) (*ssl.DescribeCertificatesResponse, error) {
	if f.listCertsFn == nil {
		panic("unexpected DescribeCertificates call")
	}
	return f.listCertsFn(ctx, req)
}

func (f *fakeSSLAPI) DescribeDeleteCertificatesTaskResultWithContext(ctx context.Context, req *ssl.DescribeDeleteCertificatesTaskResultRequest) (*ssl.DescribeDeleteCertificatesTaskResultResponse, error) {
	if f.deleteTaskFn == nil {
		panic("unexpected DescribeDeleteCertificatesTaskResult call")
	}
	return f.deleteTaskFn(ctx, req)
}

// fakeClock lets timeout tests advance time without real sleeping. Only the test
// goroutine touches it, so no locking is needed.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// stubSleeper swaps the package poll sleeper for one that advances the fake clock
// instantly, and restores it when the test ends.
func stubSleeper(t *testing.T, clock *fakeClock) {
	t.Helper()
	orig := waitBetweenPolls
	waitBetweenPolls = func(_ context.Context, d time.Duration) error {
		clock.advance(d)
		return nil
	}
	t.Cleanup(func() { waitBetweenPolls = orig })
}

func newTestDeployer(now func() time.Time) *TencentCLB {
	return &TencentCLB{
		credential: func(context.Context) (common.CredentialIface, error) {
			return common.NewCredential("test-id", "test-key"), nil
		},
		regions: []string{"ap-guangzhou"},
		types:   []string{"clb"},
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:     now,
	}
}

// updateResp builds an UpdateCertificateInstance response whose progress list *is*
// populated -- with a total of `bound`, which may be 0. That is the server answering
// "this many resources", so 0 really does mean "none bound".
func updateResp(recordID uint64, bound int64) *ssl.UpdateCertificateInstanceResponse {
	resp := &ssl.UpdateCertificateInstanceResponse{
		Response: &ssl.UpdateCertificateInstanceResponseParams{
			DeployRecordId: common.Uint64Ptr(recordID),
			UpdateSyncProgress: []*ssl.UpdateSyncProgress{{
				ResourceType: common.StringPtr("clb"),
				UpdateSyncProgressRegions: []*ssl.UpdateSyncProgressRegion{{
					Region:     common.StringPtr("ap-guangzhou"),
					TotalCount: common.Int64Ptr(bound),
				}},
			}},
		},
	}
	return resp
}

// updateRespNoProgress builds the response that caused a production incident: the task
// was created (a real DeployRecordId) but the per-region progress was still absent.
//
// An empty progress list is a **missing** answer, not the answer "zero" -- the API
// populates it separately from creating the task. It must not be read as "nothing is
// bound", because the rebind it just started may well be switching the listener.
func updateRespNoProgress(recordID uint64) *ssl.UpdateCertificateInstanceResponse {
	return &ssl.UpdateCertificateInstanceResponse{
		Response: &ssl.UpdateCertificateInstanceResponseParams{
			DeployRecordId: common.Uint64Ptr(recordID),
		},
	}
}

// updateRespPartialProgress builds the half-answered variant: the task was created and
// one region already carries a TotalCount, but the other region's is still null. That
// is no more an answer than no progress at all -- the task may be switching the null
// region right now, so the populated region's count (even zero) must not be read as
// the whole truth.
func updateRespPartialProgress(recordID uint64, bound int64) *ssl.UpdateCertificateInstanceResponse {
	return &ssl.UpdateCertificateInstanceResponse{
		Response: &ssl.UpdateCertificateInstanceResponseParams{
			DeployRecordId: common.Uint64Ptr(recordID),
			UpdateSyncProgress: []*ssl.UpdateSyncProgress{{
				ResourceType: common.StringPtr("clb"),
				UpdateSyncProgressRegions: []*ssl.UpdateSyncProgressRegion{{
					Region:     common.StringPtr("ap-guangzhou"),
					TotalCount: common.Int64Ptr(bound),
				}, {
					Region:     common.StringPtr("ap-shanghai"),
					TotalCount: nil,
				}},
			}},
		},
	}
}

func detailResp(success, failed, running int64) *ssl.DescribeHostUpdateRecordDetailResponse {
	return detailRespPending(success, failed, running, 0)
}

func detailRespPending(success, failed, running, pending int64) *ssl.DescribeHostUpdateRecordDetailResponse {
	return &ssl.DescribeHostUpdateRecordDetailResponse{
		Response: &ssl.DescribeHostUpdateRecordDetailResponseParams{
			SuccessTotalCount: common.Int64Ptr(success),
			FailedTotalCount:  common.Int64Ptr(failed),
			RunningTotalCount: common.Int64Ptr(running),
			PendingTotalCount: common.Int64Ptr(pending),
		},
	}
}

// detailRespUninstrumented is what the record detail looks like before the server
// instruments the task: the response exists, but every counter field is still null.
// Null is not zero -- this must read as "no answer yet", never as "nothing bound".
func detailRespUninstrumented() *ssl.DescribeHostUpdateRecordDetailResponse {
	return &ssl.DescribeHostUpdateRecordDetailResponse{
		Response: &ssl.DescribeHostUpdateRecordDetailResponseParams{},
	}
}

// ── updateInstance ──────────────────────────────────────────────────────────

// DeployRecordId == 0 means "task still being created" and must be retried until a
// real ID shows up; only then does the wait for the record begin, with that ID.
func TestUpdateInstancePollsUntilRecordCreated(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)
	d := newTestDeployer(clock.now)

	var updateCalls int
	fake := &fakeSSLAPI{
		updateFn: func(_ context.Context, req *ssl.UpdateCertificateInstanceRequest) (*ssl.UpdateCertificateInstanceResponse, error) {
			updateCalls++
			if got := derefStr(req.OldCertificateId); got != "old-id" {
				t.Errorf("OldCertificateId = %q, want old-id", got)
			}
			if got := derefStr(req.CertificateId); got != "new-id" {
				t.Errorf("CertificateId = %q, want new-id", got)
			}
			if updateCalls < 3 {
				return updateResp(0, 0), nil // still being created
			}
			return updateResp(42, 1), nil
		},
		detailFn: func(_ context.Context, req *ssl.DescribeHostUpdateRecordDetailRequest) (*ssl.DescribeHostUpdateRecordDetailResponse, error) {
			if got := derefStr(req.DeployRecordId); got != "42" {
				t.Errorf("waited on DeployRecordId %q, want the 42 returned by the create call", got)
			}
			return detailResp(1, 0, 0), nil
		},
	}

	if err := d.updateInstance(context.Background(), fake, "old-id", "new-id"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updateCalls != 3 {
		t.Errorf("UpdateCertificateInstance calls = %d, want 3 (two DeployRecordId=0 retries, then a created task)", updateCalls)
	}
}

// A task that never gets created within the 2-minute window must fail instead of
// polling forever.
func TestUpdateInstanceCreationTimeout(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)
	d := newTestDeployer(clock.now)

	var calls int
	fake := &fakeSSLAPI{
		updateFn: func(context.Context, *ssl.UpdateCertificateInstanceRequest) (*ssl.UpdateCertificateInstanceResponse, error) {
			calls++
			return updateResp(0, 0), nil // never created
		},
	}

	err := d.updateInstance(context.Background(), fake, "old-id", "new-id")
	if err == nil || !strings.Contains(err.Error(), "not created within 2m") {
		t.Fatalf("err = %v, want the 2-minute creation timeout", err)
	}
	if calls < 2 {
		t.Errorf("calls = %d, want polling to have repeated before timing out", calls)
	}
}

// An API error during the creation poll must abort immediately (it is not one of the
// "retryable" conditions) and keep the wrapped cause for errors.Is.
func TestUpdateInstanceAPIError(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)
	d := newTestDeployer(clock.now)

	sentinel := errors.New("sdk transport boom")
	var calls int
	fake := &fakeSSLAPI{
		updateFn: func(context.Context, *ssl.UpdateCertificateInstanceRequest) (*ssl.UpdateCertificateInstanceResponse, error) {
			calls++
			if calls == 1 {
				return updateResp(0, 0), nil
			}
			return nil, sentinel
		},
	}

	err := d.updateInstance(context.Background(), fake, "old-id", "new-id")
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want it to wrap the API error", err)
	}
	if !strings.Contains(err.Error(), "UpdateCertificateInstance") {
		t.Errorf("err = %v, want the failing operation named", err)
	}
	if calls != 2 {
		t.Errorf("calls = %d, want the loop to stop at the first API error", calls)
	}
}

// A created task that covers zero bound resources means the old certificate was never
// really bound; reporting success here would be the silent "renewed but not deployed"
// failure, so it must be an explicit error.
func TestUpdateInstanceRefusesZeroBound(t *testing.T) {
	d := newTestDeployer(time.Now)
	fake := &fakeSSLAPI{
		updateFn: func(context.Context, *ssl.UpdateCertificateInstanceRequest) (*ssl.UpdateCertificateInstanceResponse, error) {
			return updateResp(42, 0), nil // task created, but nothing bound
		},
		// detailFn deliberately unset: the wait must never start.
	}

	err := d.updateInstance(context.Background(), fake, "old-id", "new-id")
	if err == nil || !strings.Contains(err.Error(), "no resource bound to the old certificate") {
		t.Fatalf("err = %v, want the zero-bound refusal", err)
	}
}

// ── waitDeployRecord ────────────────────────────────────────────────────────

// failed > 0 with nothing left running means the one-click update finished badly and
// must be reported as a failure, naming both counts.
func TestWaitDeployRecordFailedCountsAsFailure(t *testing.T) {
	d := newTestDeployer(time.Now)
	fake := &fakeSSLAPI{
		detailFn: func(context.Context, *ssl.DescribeHostUpdateRecordDetailRequest) (*ssl.DescribeHostUpdateRecordDetailResponse, error) {
			return detailResp(1, 2, 0), nil
		},
	}

	err := d.waitDeployRecord(context.Background(), fake, 7, "old-id")
	if err == nil {
		t.Fatal("failed=2 must not be treated as success")
	}
	if !strings.Contains(err.Error(), "2 resources failed") || !strings.Contains(err.Error(), "1 succeeded") {
		t.Errorf("err = %v, want both the failed and succeeded counts named", err)
	}
}

// running == 0 with only successes means the update really took effect.
func TestWaitDeployRecordSuccess(t *testing.T) {
	d := newTestDeployer(time.Now)
	var calls int
	fake := &fakeSSLAPI{
		detailFn: func(_ context.Context, req *ssl.DescribeHostUpdateRecordDetailRequest) (*ssl.DescribeHostUpdateRecordDetailResponse, error) {
			calls++
			if got := derefStr(req.DeployRecordId); got != "7" {
				t.Errorf("DeployRecordId = %q, want 7", got)
			}
			return detailResp(3, 0, 0), nil
		},
	}

	if err := d.waitDeployRecord(context.Background(), fake, 7, "old-id"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want a finished record to be detected on the first query", calls)
	}
}

// A query error is transient (the task is still out there), so it must be logged and
// retried rather than aborting the wait.
func TestWaitDeployRecordRetriesQueryErrors(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)
	d := newTestDeployer(clock.now)

	var calls int
	fake := &fakeSSLAPI{
		detailFn: func(context.Context, *ssl.DescribeHostUpdateRecordDetailRequest) (*ssl.DescribeHostUpdateRecordDetailResponse, error) {
			calls++
			if calls == 1 {
				return nil, errors.New("throttled")
			}
			return detailResp(1, 0, 0), nil
		},
	}

	if err := d.waitDeployRecord(context.Background(), fake, 7, "old-id"); err != nil {
		t.Fatalf("a single query error must be retried, got: %v", err)
	}
	if calls != 2 {
		t.Errorf("calls = %d, want one retry after the query error", calls)
	}
}

// A task still running past the 3-minute deadline must fail with the last observed
// counters, not wait forever.
func TestWaitDeployRecordTimeout(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)
	d := newTestDeployer(clock.now)

	var calls int
	fake := &fakeSSLAPI{
		detailFn: func(context.Context, *ssl.DescribeHostUpdateRecordDetailRequest) (*ssl.DescribeHostUpdateRecordDetailResponse, error) {
			calls++
			return detailResp(0, 0, 1), nil // still running
		},
	}

	err := d.waitDeployRecord(context.Background(), fake, 7, "old-id")
	if err == nil || !strings.Contains(err.Error(), "did not finish within 3m") {
		t.Fatalf("err = %v, want the 3-minute wait timeout", err)
	}
	if !strings.Contains(err.Error(), "running=1") {
		t.Errorf("err = %v, want the last observed counters in the message", err)
	}
	if calls < 2 {
		t.Errorf("calls = %d, want polling to have repeated before timing out", calls)
	}
}

// ── Deploy through the newSSLClient factory ─────────────────────────────────

// The whole point of the factory seam: when the one-click update fails, Deploy must
// still hand back the already-uploaded new certificate ID -- dropping it would strand
// the certificate as a cloud orphan (see the note in Deploy).
func TestDeployReturnsNewIDWhenUpdateFails(t *testing.T) {
	orig := newSSLClient
	t.Cleanup(func() { newSSLClient = orig })

	sentinel := errors.New("update failed")
	fake := &fakeSSLAPI{
		uploadFn: func(_ context.Context, req *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error) {
			if got := derefStr(req.Alias); got != "wecert/my-cert" {
				t.Errorf("Alias = %q, want wecert/my-cert", got)
			}
			return &ssl.UploadCertificateResponse{
				Response: &ssl.UploadCertificateResponseParams{
					CertificateId: common.StringPtr("new-id"),
				},
			}, nil
		},
		updateFn: func(context.Context, *ssl.UpdateCertificateInstanceRequest) (*ssl.UpdateCertificateInstanceResponse, error) {
			return nil, sentinel
		},
		// Deploy now asks whether the new certificate is already bound before believing
		// the failure. Nothing is, so the error must propagate unchanged.
		createTaskFn: stubCreateTask("new-id", "task-1"),
		taskResultFn: func(context.Context, *ssl.DescribeCertificateBindResourceTaskResultRequest) (*ssl.DescribeCertificateBindResourceTaskResultResponse, error) {
			return bindingsResp("task-1", 0), nil
		},
	}

	var gotCred common.CredentialIface
	newSSLClient = func(cred common.CredentialIface) (sslAPI, error) {
		gotCred = cred
		return fake, nil
	}

	d := newTestDeployer(time.Now)
	newID, err := d.Deploy(context.Background(), "my-cert", "old-id", []byte("pem"), []byte("key"))
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want it to wrap the update failure", err)
	}
	if newID != "new-id" {
		t.Errorf("newID = %q, want the uploaded ID even on failure, otherwise the certificate becomes a cloud orphan", newID)
	}
	if gotCred == nil || gotCred.GetSecretId() != "test-id" {
		t.Errorf("the factory was not given the resolved credential: %v", gotCred)
	}
}

// First issuance has no old certificate, so there is nothing to one-click update:
// upload only, and UpdateCertificateInstance must not be called at all.
func TestDeployFirstIssuanceSkipsUpdate(t *testing.T) {
	orig := newSSLClient
	t.Cleanup(func() { newSSLClient = orig })

	fake := &fakeSSLAPI{
		uploadFn: func(context.Context, *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error) {
			return &ssl.UploadCertificateResponse{
				Response: &ssl.UploadCertificateResponseParams{
					CertificateId: common.StringPtr("new-id"),
				},
			}, nil
		},
		// updateFn deliberately unset: any update call panics and fails the test.
	}
	newSSLClient = func(common.CredentialIface) (sslAPI, error) { return fake, nil }

	d := newTestDeployer(time.Now)
	newID, err := d.Deploy(context.Background(), "my-cert", "", []byte("pem"), []byte("key"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if newID != "new-id" {
		t.Errorf("newID = %q, want new-id", newID)
	}
}

// ── the production incident: absent progress detail is not "nothing bound" ──

// updateInstance used to fail whenever UpdateSyncProgress was absent, reading "the
// server has not answered yet" as "nothing is bound". Observed live: the rebind task
// was created (recordId=14822), the creation response carried no per-region progress,
// wecert recorded a failure -- and Tencent Cloud finished switching the listener 47
// seconds later.
//
// The damage is not self-correcting. wecert keeps the old certificate as its anchor,
// that certificate has no bindings left because the switch *did* happen, so every later
// round uploads another certificate, fails identically and records another orphan --
// while the certificate actually serving traffic sits in retired_certificates, held back
// only by the cloud-side resource check.
func TestUpdateInstanceWithNoProgressDetailWaitsForTheTask(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)
	d := newTestDeployer(clock.now)

	var detailCalls int
	fake := &fakeSSLAPI{
		updateFn: func(context.Context, *ssl.UpdateCertificateInstanceRequest) (*ssl.UpdateCertificateInstanceResponse, error) {
			return updateRespNoProgress(14822), nil
		},
		detailFn: func(context.Context, *ssl.DescribeHostUpdateRecordDetailRequest) (*ssl.DescribeHostUpdateRecordDetailResponse, error) {
			detailCalls++
			// Nothing is reported for the first couple of polls, then the switch lands:
			// exactly how the real task behaved.
			if detailCalls < 3 {
				return detailRespPending(0, 0, 0, 0), nil
			}
			return detailResp(1, 0, 0), nil
		},
	}

	if err := d.updateInstance(context.Background(), fake, "old-id", "new-id"); err != nil {
		t.Fatalf("a rebind whose task succeeds must not be reported as failed: %v", err)
	}
	if detailCalls < 3 {
		t.Errorf("the wait should have polled until the record settled, got %d calls", detailCalls)
	}
}

// The half-answered variant of the incident above: one region already carries a
// TotalCount of zero while another region's is still null. Reading the populated half
// as the whole answer would fire "nothing is bound" while the task may be switching
// the null region, so a partially populated progress must defer to the async record
// exactly like a fully absent one.
func TestUpdateInstanceWithPartialProgressDetailWaitsForTheTask(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)
	d := newTestDeployer(clock.now)

	var detailCalls int
	fake := &fakeSSLAPI{
		updateFn: func(context.Context, *ssl.UpdateCertificateInstanceRequest) (*ssl.UpdateCertificateInstanceResponse, error) {
			return updateRespPartialProgress(14822, 0), nil
		},
		detailFn: func(context.Context, *ssl.DescribeHostUpdateRecordDetailRequest) (*ssl.DescribeHostUpdateRecordDetailResponse, error) {
			detailCalls++
			return detailResp(1, 0, 0), nil
		},
	}

	if err := d.updateInstance(context.Background(), fake, "old-id", "new-id"); err != nil {
		t.Fatalf("a partially populated progress must not fail the rebind as unbound: %v", err)
	}
	if detailCalls != 1 {
		t.Errorf("detailCalls = %d, want the decision deferred to the deploy record", detailCalls)
	}
}

// The record detail has the same async-population hazard as the sync progress: until
// the server instruments the task, every counter field is null. Null read as zero past
// the grace period would fire the no-binding verdict against a task that simply has
// not been measured yet, so uninstrumented answers must keep the wait going even after
// the grace expires.
func TestWaitDeployRecordWaitsForUninstrumentedCounters(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)
	d := newTestDeployer(clock.now)

	var calls int
	fake := &fakeSSLAPI{
		detailFn: func(context.Context, *ssl.DescribeHostUpdateRecordDetailRequest) (*ssl.DescribeHostUpdateRecordDetailResponse, error) {
			calls++
			// Four uninstrumented polls at 5s each put the clock well past the 15s
			// grace -- past the point where populated zeros would be a verdict.
			if calls < 5 {
				return detailRespUninstrumented(), nil
			}
			return detailResp(1, 0, 0), nil
		},
	}

	if err := d.waitDeployRecord(context.Background(), fake, 7, "old-id"); err != nil {
		t.Fatalf("uninstrumented counters past the grace period are not a verdict, got: %v", err)
	}
	if calls != 5 {
		t.Errorf("calls = %d, want the wait to continue until the task is instrumented and settles", calls)
	}
}

// A task whose record is never instrumented at all must end at the deadline with the
// timeout error, not with the no-binding diagnosis -- the server never answered, so
// "no resource bound" is a claim nobody made.
func TestWaitDeployRecordUninstrumentedUntilDeadlineIsNotANoBindingVerdict(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)
	d := newTestDeployer(clock.now)

	fake := &fakeSSLAPI{
		detailFn: func(context.Context, *ssl.DescribeHostUpdateRecordDetailRequest) (*ssl.DescribeHostUpdateRecordDetailResponse, error) {
			return detailRespUninstrumented(), nil
		},
	}

	err := d.waitDeployRecord(context.Background(), fake, 7, "old-id")
	if err == nil {
		t.Fatal("a task that never settles must not be treated as success")
	}
	if !strings.Contains(err.Error(), "did not finish within 3m") {
		t.Errorf("err = %v, want the deadline timeout", err)
	}
	if strings.Contains(err.Error(), "no resource bound to the old certificate") {
		t.Errorf("err = %v, the server never answered, so the no-binding diagnosis is wrong", err)
	}
}

// Queued-but-not-started resources count as unfinished. Resources are dispatched in
// batches, so "nothing is running" can be true while most of the task has not begun --
// and declaring success there retires the old certificate while listeners still serve it.
func TestWaitDeployRecordWaitsForPendingResources(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)
	d := newTestDeployer(clock.now)

	var calls int
	fake := &fakeSSLAPI{
		detailFn: func(context.Context, *ssl.DescribeHostUpdateRecordDetailRequest) (*ssl.DescribeHostUpdateRecordDetailResponse, error) {
			calls++
			if calls == 1 {
				// One resource done, three still queued, none running.
				return detailRespPending(1, 0, 0, 3), nil
			}
			return detailResp(4, 0, 0), nil
		},
	}

	if err := d.waitDeployRecord(context.Background(), fake, 7, "old-id"); err != nil {
		t.Fatalf("waitDeployRecord: %v", err)
	}
	if calls < 2 {
		t.Errorf("pending resources must keep the wait going, got %d poll(s)", calls)
	}
}

// A task that reports nothing at all for the whole budget is the genuine "no resource
// was bound to the old certificate" case. It is diagnosed at the deadline rather than
// from the creation-time response, because an all-zero record is also what a task looks
// like before the server has populated it -- and failing on that is what broke a rebind
// that was in fact succeeding.
func TestWaitDeployRecordDiagnosesAnEmptyTaskAfterTheGracePeriod(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)
	d := newTestDeployer(clock.now)

	fake := &fakeSSLAPI{
		detailFn: func(context.Context, *ssl.DescribeHostUpdateRecordDetailRequest) (*ssl.DescribeHostUpdateRecordDetailResponse, error) {
			return detailRespPending(0, 0, 0, 0), nil
		},
	}

	err := d.waitDeployRecord(context.Background(), fake, 7, "old-id")
	if err == nil {
		t.Fatal("a task that never reports anything must not be treated as success")
	}
	// The verdict now comes from the shared noResourceBoundError, so this path carries the
	// same wording -- and the same SNI hint -- as the sync-response path.
	if !strings.Contains(err.Error(), "no resource bound to the old certificate") {
		t.Errorf("err = %v, want the no-binding diagnosis", err)
	}
}

// The deadline branch reports the last *successful* answer, not whatever the final poll
// returned. When the last polls all errored, reading per-iteration counters would leave
// zeros there and misdiagnose a task that showed progress as "no resource bound" -- the
// one error message that sends the operator off checking a listener that is fine.
func TestWaitDeployRecordDeadlineUsesLastKnownCounters(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)
	d := newTestDeployer(clock.now)

	var calls int
	fake := &fakeSSLAPI{
		detailFn: func(context.Context, *ssl.DescribeHostUpdateRecordDetailRequest) (*ssl.DescribeHostUpdateRecordDetailResponse, error) {
			calls++
			if calls == 1 {
				// Progress is seen once, then every poll errors until the deadline.
				return detailResp(0, 0, 1), nil
			}
			return nil, errors.New("throttled")
		},
	}

	err := d.waitDeployRecord(context.Background(), fake, 7, "old-id")
	if err == nil {
		t.Fatal("a task that never finishes must not be treated as success")
	}
	if strings.Contains(err.Error(), "no resource bound to the old certificate") {
		t.Errorf("err = %v, progress was seen before the errors, so the no-binding diagnosis is wrong", err)
	}
	if !strings.Contains(err.Error(), "did not finish within 3m") || !strings.Contains(err.Error(), "running=1") {
		t.Errorf("err = %v, want the timeout with the last known counters", err)
	}
}

// ── recovery: a switch that happened but was not recorded ───────────────────

// bindingsFor builds cert-aware stubs for the two bind-resource calls.
//
// The cert awareness is not decoration. bindingsWith is called for two *different*
// certificates on the recovery path -- the new one and the old one -- and a stub that
// answers both with the same response cannot tell the wedge ("the new certificate is
// bound, the old one is not") from a partial failure ("the new certificate is bound and so
// is the old one"). The earlier version of these tests answered any certificate ID with a
// single cert's task, and the old-certificate lookup then found no task at all and read as
// zero bindings -- so the two cases were indistinguishable in the fixtures, which is
// exactly the distinction the production check exists to make.
func bindingsFor(t *testing.T, byCert map[string]uint64) (
	func(context.Context, *ssl.CreateCertificateBindResourceSyncTaskRequest) (*ssl.CreateCertificateBindResourceSyncTaskResponse, error),
	func(context.Context, *ssl.DescribeCertificateBindResourceTaskResultRequest) (*ssl.DescribeCertificateBindResourceTaskResultResponse, error),
) {
	t.Helper()
	taskByCert := make(map[string]string, len(byCert))
	totalByTask := make(map[string]uint64, len(byCert))
	for certID, total := range byCert {
		taskID := "task-" + certID
		taskByCert[certID] = taskID
		totalByTask[taskID] = total
	}
	create := func(_ context.Context, req *ssl.CreateCertificateBindResourceSyncTaskRequest) (*ssl.CreateCertificateBindResourceSyncTaskResponse, error) {
		out := &ssl.CreateCertificateBindResourceSyncTaskResponse{
			Response: &ssl.CreateCertificateBindResourceSyncTaskResponseParams{},
		}
		for _, id := range req.CertificateIds {
			if id == nil {
				continue
			}
			taskID, ok := taskByCert[*id]
			if !ok {
				continue
			}
			out.Response.CertTaskIds = append(out.Response.CertTaskIds, &ssl.CertTaskId{
				CertId: common.StringPtr(*id),
				TaskId: common.StringPtr(taskID),
			})
		}
		return out, nil
	}
	result := func(_ context.Context, req *ssl.DescribeCertificateBindResourceTaskResultRequest) (*ssl.DescribeCertificateBindResourceTaskResultResponse, error) {
		if len(req.TaskIds) == 0 || req.TaskIds[0] == nil {
			t.Errorf("the result query carried no task id")
			return bindingsResp("", 0), nil
		}
		taskID := *req.TaskIds[0]
		total, ok := totalByTask[taskID]
		if !ok {
			t.Errorf("the result query asked about an unknown task %q", taskID)
		}
		return bindingsResp(taskID, total), nil
	}
	return create, result
}

func stubCreateTask(certID, taskID string) func(context.Context, *ssl.CreateCertificateBindResourceSyncTaskRequest) (*ssl.CreateCertificateBindResourceSyncTaskResponse, error) {
	return func(context.Context, *ssl.CreateCertificateBindResourceSyncTaskRequest) (*ssl.CreateCertificateBindResourceSyncTaskResponse, error) {
		return &ssl.CreateCertificateBindResourceSyncTaskResponse{
			Response: &ssl.CreateCertificateBindResourceSyncTaskResponseParams{
				CertTaskIds: []*ssl.CertTaskId{{
					CertId: common.StringPtr(certID),
					TaskId: common.StringPtr(taskID),
				}},
			},
		}, nil
	}
}

// bindingsResp reports a finished enumeration totaling `total` resources. The result list
// must be non-empty even for zero: countBindings keeps waiting on an empty one.
func bindingsResp(taskID string, total uint64) *ssl.DescribeCertificateBindResourceTaskResultResponse {
	return &ssl.DescribeCertificateBindResourceTaskResultResponse{
		Response: &ssl.DescribeCertificateBindResourceTaskResultResponseParams{
			SyncTaskBindResourceResult: []*ssl.SyncTaskBindResourceResult{{
				TaskId: common.StringPtr(taskID),
				Status: common.Uint64Ptr(1),
				BindResourceResult: []*ssl.BindResourceResult{{
					ResourceType: common.StringPtr("clb"),
					BindResourceRegionResult: []*ssl.BindResourceRegionResult{{
						Region:     common.StringPtr("ap-guangzhou"),
						TotalCount: common.Uint64Ptr(total),
						Error:      common.StringPtr(""),
					}},
				}},
			}},
		},
	}
}

// A rebind that succeeded without being recorded leaves a wedge that no fix to the
// "nothing to switch" check can clear on its own: the old certificate has no bindings
// left, so every later round fails that check no matter how many certificates are
// uploaded, and the certificate actually serving traffic sits in the reclamation list.
//
// Asking about the *new* certificate settles it: if anything is bound to it, the switch
// is done.
func TestDeployTreatsAnAlreadyBoundNewCertificateAsSuccess(t *testing.T) {
	orig := newSSLClient
	t.Cleanup(func() { newSSLClient = orig })

	createTask, taskResult := bindingsFor(t, map[string]uint64{"new-id": 3, "old-id": 0})
	fake := &fakeSSLAPI{
		uploadFn: func(context.Context, *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error) {
			return &ssl.UploadCertificateResponse{
				Response: &ssl.UploadCertificateResponseParams{CertificateId: common.StringPtr("new-id")},
			}, nil
		},
		updateFn: func(context.Context, *ssl.UpdateCertificateInstanceRequest) (*ssl.UpdateCertificateInstanceResponse, error) {
			// The old certificate has no bindings left, which is the wedge.
			return updateResp(42, 0), nil
		},
		createTaskFn: createTask,
		taskResultFn: taskResult,
	}

	newSSLClient = func(common.CredentialIface) (sslAPI, error) { return fake, nil }

	d := newTestDeployer(time.Now)
	id, err := d.Deploy(context.Background(), "my-cert", "old-id", []byte("cert"), []byte("key"))
	if err != nil {
		t.Fatalf("a new certificate that is already bound means the switch happened; got %v", err)
	}
	if id != "new-id" {
		t.Errorf("Deploy returned %q, want new-id", id)
	}
}

// When the one-click update settles having switched only SOME listeners, that is a
// partial failure, not a success.
//
// The recovery path asks "is anything bound to the new certificate?" before believing a
// failure. That question cannot tell a half-done switch from a clean one: the listeners
// that did migrate make the answer "yes", so Deploy used to return success, the state
// anchored on the new CertId, and the listeners still serving the old certificate were
// never revisited -- they would run to expiry in production.
func TestDeployDoesNotReportPartialRebindAsSuccess(t *testing.T) {
	orig := newSSLClient
	t.Cleanup(func() { newSSLClient = orig })

	var updateCalls int
	// The listener that did switch is enough to make "is the new cert bound?" say yes, but
	// the listener still on the old certificate makes the old anchor non-zero -- which is
	// exactly what separates this from the wedge case above.
	createTask, taskResult := bindingsFor(t, map[string]uint64{"new-id": 1, "old-id": 2})
	fake := &fakeSSLAPI{
		uploadFn: func(context.Context, *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error) {
			return &ssl.UploadCertificateResponse{
				Response: &ssl.UploadCertificateResponseParams{CertificateId: common.StringPtr("new-id")},
			}, nil
		},
		updateFn: func(context.Context, *ssl.UpdateCertificateInstanceRequest) (*ssl.UpdateCertificateInstanceResponse, error) {
			updateCalls++
			// One listener is bound to the old certificate, so the task exists.
			return updateResp(42, 1), nil
		},
		// ...but it settles having switched one and failed two.
		detailFn: func(context.Context, *ssl.DescribeHostUpdateRecordDetailRequest) (*ssl.DescribeHostUpdateRecordDetailResponse, error) {
			return detailResp(1, 2, 0), nil
		},
		createTaskFn: createTask,
		taskResultFn: taskResult,
	}

	newSSLClient = func(common.CredentialIface) (sslAPI, error) { return fake, nil }

	d := newTestDeployer(time.Now)
	id, err := d.Deploy(context.Background(), "my-cert", "old-id", []byte("cert"), []byte("key"))
	if err == nil {
		t.Fatal("2 of 3 resources failed to rebind, but Deploy reported success: the state would " +
			"anchor on the new certificate and those listeners would never be updated again")
	}
	if id != "new-id" {
		t.Errorf("the uploaded id must still be returned for reclamation, got %q", id)
	}
	if updateCalls == 0 {
		t.Error("the update was never attempted")
	}
}

// The check must not turn a genuine failure into success: when nothing is bound to the
// new certificate either, the error stands.
func TestDeployKeepsTheErrorWhenNothingIsBoundToEitherCertificate(t *testing.T) {
	orig := newSSLClient
	t.Cleanup(func() { newSSLClient = orig })

	fake := &fakeSSLAPI{
		uploadFn: func(context.Context, *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error) {
			return &ssl.UploadCertificateResponse{
				Response: &ssl.UploadCertificateResponseParams{CertificateId: common.StringPtr("new-id")},
			}, nil
		},
		updateFn: func(context.Context, *ssl.UpdateCertificateInstanceRequest) (*ssl.UpdateCertificateInstanceResponse, error) {
			return updateResp(42, 0), nil
		},
		createTaskFn: stubCreateTask("new-id", "task-1"),
		taskResultFn: func(context.Context, *ssl.DescribeCertificateBindResourceTaskResultRequest) (*ssl.DescribeCertificateBindResourceTaskResultResponse, error) {
			return bindingsResp("task-1", 0), nil
		},
	}

	newSSLClient = func(common.CredentialIface) (sslAPI, error) { return fake, nil }

	d := newTestDeployer(time.Now)
	id, err := d.Deploy(context.Background(), "my-cert", "old-id", []byte("cert"), []byte("key"))
	if err == nil {
		t.Fatal("nothing is bound to either certificate; the failure must stand")
	}
	if id != "new-id" {
		t.Errorf("the uploaded id must still be returned for reclamation, got %q", id)
	}
}

// ── Delete ──────────────────────────────────────────────────────────────────

func derefBool(p *bool) bool { return p != nil && *p }

func deleteResp(result bool, taskID string) *ssl.DeleteCertificateResponse {
	params := &ssl.DeleteCertificateResponseParams{DeleteResult: common.BoolPtr(result)}
	if taskID != "" {
		params.TaskId = common.StringPtr(taskID)
	}
	return &ssl.DeleteCertificateResponse{Response: params}
}

func deleteTaskResp(taskID string, status uint64, errMsg string) *ssl.DescribeDeleteCertificatesTaskResultResponse {
	r := &ssl.DeleteTaskResult{
		TaskId: common.StringPtr(taskID),
		Status: common.Uint64Ptr(status),
	}
	if errMsg != "" {
		r.Error = common.StringPtr(errMsg)
	}
	return &ssl.DescribeDeleteCertificatesTaskResultResponse{
		Response: &ssl.DescribeDeleteCertificatesTaskResultResponseParams{DeleteTaskResult: []*ssl.DeleteTaskResult{r}},
	}
}

// IsCheckResource=true makes DeleteCertificate asynchronous: the SDK documents that the
// call returns a task ID and that DescribeDeleteCertificatesTaskResult is what says
// whether the delete happened. Treating "accepted" as "deleted" made ReapRetired drop
// its reclaim record, leaking the certificate in the cloud account forever -- and status
// 4 ("a cloud resource still references it") is exactly the answer that must keep it.
func TestDeleteWaitsForTheAsyncTask(t *testing.T) {
	orig := newSSLClient
	t.Cleanup(func() { newSSLClient = orig })
	// The poll interval is real seconds; drive it with the fake clock so this test does
	// not spend two of them asleep.
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)

	var polls int
	fake := &fakeSSLAPI{
		deleteFn: func(_ context.Context, req *ssl.DeleteCertificateRequest) (*ssl.DeleteCertificateResponse, error) {
			if !derefBool(req.IsCheckResource) {
				t.Error("IsCheckResource must stay true: the server-side reference check is the last guard " +
					"between a bookkeeping cleanup and an HTTPS outage")
			}
			return deleteResp(true, "del-task-1"), nil
		},
		deleteTaskFn: func(_ context.Context, req *ssl.DescribeDeleteCertificatesTaskResultRequest) (*ssl.DescribeDeleteCertificatesTaskResultResponse, error) {
			polls++
			if got := derefStr(req.TaskIds[0]); got != "del-task-1" {
				t.Errorf("polled task %q, want del-task-1", got)
			}
			if polls < 3 {
				return deleteTaskResp("del-task-1", 0, ""), nil // still running
			}
			return deleteTaskResp("del-task-1", 1, ""), nil
		},
	}

	newSSLClient = func(common.CredentialIface) (sslAPI, error) { return fake, nil }

	d := newTestDeployer(time.Now)
	if err := d.Delete(context.Background(), "cert-1"); err != nil {
		t.Fatalf("a successful delete task must be reported as success, got %v", err)
	}
	if polls < 3 {
		t.Errorf("Delete returned after %d poll(s) without waiting for the task to finish", polls)
	}
}

// DeleteResult=false is what the live API returns whenever IsCheckResource is on -- for a refusal
// AND for a deletion that succeeds -- so it must NOT short-circuit the task poll.
//
// The round-11 verification pass found this against the real account: a bound certificate gave
// DeleteResult=false with task status 4, and the same call after unbinding gave DeleteResult=false
// with task status 1 and the certificate was really gone. Every test in this file used
// DeleteResult=true, so the fake encoded an API that does not exist, and the product reported "the
// API refused the delete" for a certificate it had already deleted -- keeping the
// retired_certificates row and warning again on every pass.
func TestDeleteWithFalseResultStillPollsTheTask(t *testing.T) {
	orig := newSSLClient
	t.Cleanup(func() { newSSLClient = orig })

	var polls int
	fake := &fakeSSLAPI{
		deleteFn: func(context.Context, *ssl.DeleteCertificateRequest) (*ssl.DeleteCertificateResponse, error) {
			return deleteResp(false, "del-task-1"), nil
		},
		deleteTaskFn: func(context.Context, *ssl.DescribeDeleteCertificatesTaskResultRequest) (*ssl.DescribeDeleteCertificatesTaskResultResponse, error) {
			polls++
			return deleteTaskResp("del-task-1", 1, ""), nil
		},
	}
	newSSLClient = func(common.CredentialIface) (sslAPI, error) { return fake, nil }

	d := newTestDeployer(time.Now)
	if err := d.Delete(context.Background(), "cert-1"); err != nil {
		t.Fatalf("DeleteResult=false with a successful task is a DELETED certificate, not a refusal: %v", err)
	}
	if polls == 0 {
		t.Error("the task must be polled: with IsCheckResource on, DeleteResult=false is not the answer")
	}
}

// The same flag with task status 4 is the real refusal, and it names the status.
func TestDeleteWithFalseResultAndStatusFourIsTheRefusal(t *testing.T) {
	orig := newSSLClient
	t.Cleanup(func() { newSSLClient = orig })

	fake := &fakeSSLAPI{
		deleteFn: func(context.Context, *ssl.DeleteCertificateRequest) (*ssl.DeleteCertificateResponse, error) {
			return deleteResp(false, "del-task-1"), nil
		},
		deleteTaskFn: func(context.Context, *ssl.DescribeDeleteCertificatesTaskResultRequest) (*ssl.DescribeDeleteCertificatesTaskResultResponse, error) {
			return deleteTaskResp("del-task-1", 4, "There are unbound cloud resources: clb, that cannot be deleted."), nil
		},
	}
	newSSLClient = func(common.CredentialIface) (sslAPI, error) { return fake, nil }

	d := newTestDeployer(time.Now)
	err := d.Delete(context.Background(), "cert-1")
	if err == nil {
		t.Fatal("status 4 must be reported as a refusal so the reclaim row is kept and retried")
	}
	if !strings.Contains(err.Error(), "status 4") {
		t.Errorf("the error should name status 4, got %v", err)
	}
}

// With no task ID the flag IS the whole answer, and false means refused.
func TestDeleteWithFalseResultAndNoTaskIsARefusal(t *testing.T) {
	orig := newSSLClient
	t.Cleanup(func() { newSSLClient = orig })

	fake := &fakeSSLAPI{
		deleteFn: func(context.Context, *ssl.DeleteCertificateRequest) (*ssl.DeleteCertificateResponse, error) {
			return deleteResp(false, ""), nil
		},
		deleteTaskFn: func(context.Context, *ssl.DescribeDeleteCertificatesTaskResultRequest) (*ssl.DescribeDeleteCertificatesTaskResultResponse, error) {
			t.Error("there is no task to poll")
			return nil, nil
		},
	}
	newSSLClient = func(common.CredentialIface) (sslAPI, error) { return fake, nil }

	d := newTestDeployer(time.Now)
	if err := d.Delete(context.Background(), "cert-1"); err == nil {
		t.Error("a synchronous DeleteResult=false is a refusal")
	}
}

// Status 4 is the server refusing because a resource still references the certificate.
// That must surface as an error so ReapRetired keeps its reclaim record and retries.
func TestDeleteReportsAResourceStillBound(t *testing.T) {
	orig := newSSLClient
	t.Cleanup(func() { newSSLClient = orig })

	fake := &fakeSSLAPI{
		deleteFn: func(context.Context, *ssl.DeleteCertificateRequest) (*ssl.DeleteCertificateResponse, error) {
			return deleteResp(true, "del-task-1"), nil
		},
		deleteTaskFn: func(context.Context, *ssl.DescribeDeleteCertificatesTaskResultRequest) (*ssl.DescribeDeleteCertificatesTaskResultResponse, error) {
			return deleteTaskResp("del-task-1", 4, "certificate is still bound to a cloud resource"), nil
		},
	}

	newSSLClient = func(common.CredentialIface) (sslAPI, error) { return fake, nil }

	d := newTestDeployer(time.Now)
	err := d.Delete(context.Background(), "cert-1")
	if err == nil {
		t.Fatal("a delete refused because a resource still references the certificate must not report success")
	}
	if !strings.Contains(err.Error(), "status 4") {
		t.Errorf("the error should name the status so the operator can look it up, got %v", err)
	}
}

// A synchronous answer (no task ID) is complete on its own, so it must not start polling.
func TestDeleteWithoutATaskDoesNotPoll(t *testing.T) {
	orig := newSSLClient
	t.Cleanup(func() { newSSLClient = orig })

	fake := &fakeSSLAPI{
		deleteFn: func(context.Context, *ssl.DeleteCertificateRequest) (*ssl.DeleteCertificateResponse, error) {
			return deleteResp(true, ""), nil
		},
		deleteTaskFn: func(context.Context, *ssl.DescribeDeleteCertificatesTaskResultRequest) (*ssl.DescribeDeleteCertificatesTaskResultResponse, error) {
			t.Error("there is no task to poll")
			return nil, nil
		},
	}

	newSSLClient = func(common.CredentialIface) (sslAPI, error) { return fake, nil }

	d := newTestDeployer(time.Now)
	if err := d.Delete(context.Background(), "cert-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

// DeleteResult=false is the API refusing outright.
func TestDeleteHonoursAnExplicitFalseResult(t *testing.T) {
	orig := newSSLClient
	t.Cleanup(func() { newSSLClient = orig })

	fake := &fakeSSLAPI{
		deleteFn: func(context.Context, *ssl.DeleteCertificateRequest) (*ssl.DeleteCertificateResponse, error) {
			return deleteResp(false, ""), nil
		},
	}

	newSSLClient = func(common.CredentialIface) (sslAPI, error) { return fake, nil }

	d := newTestDeployer(time.Now)
	if err := d.Delete(context.Background(), "cert-1"); err == nil {
		t.Fatal("DeleteResult=false must be reported as a failure")
	}
}

// DeployStatus == 0 means "a task is already in progress, this request created nothing,
// and the returned DeployRecordId is that task's". The SDK says so explicitly.
//
// Adopting it blindly is how a switch for a *different* certificate gets reported as this
// one's success: waitDeployRecord returns nil when that task completes, and Deploy then
// hands back newID while the cloud is serving whatever that task switched to. The answer
// that settles it is "is THIS certificate bound?".
func TestUpdateInstanceVerifiesAnAdoptedTask(t *testing.T) {
	orig := newSSLClient
	t.Cleanup(func() { newSSLClient = orig })

	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)

	fake := &fakeSSLAPI{
		uploadFn: func(context.Context, *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error) {
			return &ssl.UploadCertificateResponse{
				Response: &ssl.UploadCertificateResponseParams{CertificateId: common.StringPtr("new-id")},
			}, nil
		},
		updateFn: func(context.Context, *ssl.UpdateCertificateInstanceRequest) (*ssl.UpdateCertificateInstanceResponse, error) {
			// A pre-existing task, not ours.
			return updateRespWithStatus(42, 1, 0), nil
		},
		// That task is for a different switch and finishes successfully right away.
		detailFn: func(context.Context, *ssl.DescribeHostUpdateRecordDetailRequest) (*ssl.DescribeHostUpdateRecordDetailResponse, error) {
			return detailResp(1, 0, 0), nil
		},
		createTaskFn: stubCreateTask("new-id", "task-1"),
		// And this certificate is bound to nothing.
		taskResultFn: func(context.Context, *ssl.DescribeCertificateBindResourceTaskResultRequest) (*ssl.DescribeCertificateBindResourceTaskResultResponse, error) {
			return bindingsResp("task-1", 0), nil
		},
	}
	newSSLClient = func(common.CredentialIface) (sslAPI, error) { return fake, nil }

	d := newTestDeployer(clock.now)
	if _, err := d.Deploy(context.Background(), "my-cert", "old-id", []byte("cert"), []byte("key")); err == nil {
		t.Fatal("the in-progress task belonged to another switch and this certificate is bound to nothing; " +
			"reporting success would record a deploy that never happened")
	}
}

// The same adopted task, but this time it really did bind our certificate, so the answer
// is success.
func TestUpdateInstanceAcceptsAnAdoptedTaskThatBoundUs(t *testing.T) {
	orig := newSSLClient
	t.Cleanup(func() { newSSLClient = orig })

	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)

	fake := &fakeSSLAPI{
		uploadFn: func(context.Context, *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error) {
			return &ssl.UploadCertificateResponse{
				Response: &ssl.UploadCertificateResponseParams{CertificateId: common.StringPtr("new-id")},
			}, nil
		},
		updateFn: func(context.Context, *ssl.UpdateCertificateInstanceRequest) (*ssl.UpdateCertificateInstanceResponse, error) {
			return updateRespWithStatus(42, 1, 0), nil
		},
		detailFn: func(context.Context, *ssl.DescribeHostUpdateRecordDetailRequest) (*ssl.DescribeHostUpdateRecordDetailResponse, error) {
			return detailResp(1, 0, 0), nil
		},
		createTaskFn: stubCreateTask("new-id", "task-1"),
		taskResultFn: func(context.Context, *ssl.DescribeCertificateBindResourceTaskResultRequest) (*ssl.DescribeCertificateBindResourceTaskResultResponse, error) {
			return bindingsResp("task-1", 2), nil
		},
	}
	newSSLClient = func(common.CredentialIface) (sslAPI, error) { return fake, nil }

	d := newTestDeployer(clock.now)
	id, err := d.Deploy(context.Background(), "my-cert", "old-id", []byte("cert"), []byte("key"))
	if err != nil {
		t.Fatalf("the adopted task did bind this certificate, so this is a success: %v", err)
	}
	if id != "new-id" {
		t.Errorf("id = %q, want new-id", id)
	}
}

// updateRespWithStatus is updateResp plus an explicit DeployStatus, so a test can say
// "this request created the task" (1) or "a task was already running" (0).
func updateRespWithStatus(recordID uint64, bound, status int64) *ssl.UpdateCertificateInstanceResponse {
	resp := updateResp(recordID, bound)
	resp.Response.DeployStatus = common.Int64Ptr(status)
	return resp
}

// An enumeration that never answers is not the same answer as "nothing is bound".
//
// The deploy record -- the authoritative account of the switch -- already reported it done,
// and the enumeration is an asynchronous server-side cache whose latency belongs to the
// server. Treating that timeout as a failed deploy is what put a real account into a loop
// where every round re-ran the same switch, hit the same timeout, and never recorded the
// certificate that was serving traffic. The caller gets a distinguishable answer instead, so
// it can record the certificate as deployed-but-unconfirmed and let the cheap binding probe
// settle it on the next pass.
func TestAdoptedTaskWhoseEnumerationNeverAnswersIsUnverifiedNotFailed(t *testing.T) {
	orig := newSSLClient
	t.Cleanup(func() { newSSLClient = orig })

	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)

	fake := &fakeSSLAPI{
		uploadFn: func(context.Context, *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error) {
			return &ssl.UploadCertificateResponse{
				Response: &ssl.UploadCertificateResponseParams{CertificateId: common.StringPtr("new-id")},
			}, nil
		},
		updateFn: func(context.Context, *ssl.UpdateCertificateInstanceRequest) (*ssl.UpdateCertificateInstanceResponse, error) {
			// A task is already in progress and this is its record.
			return updateRespWithStatus(42, 1, 0), nil
		},
		detailFn: func(context.Context, *ssl.DescribeHostUpdateRecordDetailRequest) (*ssl.DescribeHostUpdateRecordDetailResponse, error) {
			return detailResp(1, 0, 0), nil
		},
		createTaskFn: stubCreateTask("new-id", "task-1"),
		// The task never reaches Status=1, so the polling loop runs out its budget.
		taskResultFn: func(context.Context, *ssl.DescribeCertificateBindResourceTaskResultRequest) (*ssl.DescribeCertificateBindResourceTaskResultResponse, error) {
			return &ssl.DescribeCertificateBindResourceTaskResultResponse{
				Response: &ssl.DescribeCertificateBindResourceTaskResultResponseParams{
					SyncTaskBindResourceResult: []*ssl.SyncTaskBindResourceResult{{
						TaskId: common.StringPtr("task-1"),
						Status: common.Uint64Ptr(0),
					}},
				},
			}, nil
		},
	}
	newSSLClient = func(common.CredentialIface) (sslAPI, error) { return fake, nil }

	d := newTestDeployer(clock.now)
	id, err := d.Deploy(context.Background(), "my-cert", "old-id", []byte("cert"), []byte("key"))
	if !errors.Is(err, ErrSwitchUnverified) {
		t.Fatalf("an enumeration that never answers must be reported as unverified, so the caller "+
			"can record the certificate and re-check later; got err = %v", err)
	}
	// The uploaded certificate must still be identified: without the ID the caller has
	// nothing to record and the certificate leaks in the cloud account.
	if id != "new-id" {
		t.Errorf("id = %q, want new-id even on the unverified path", id)
	}
}

// Nothing bound to either certificate is not a failed switch: it is a pending first bind.
//
// deploy.enabled starts with one upload plus a manual bind, and a renewal can arrive before a human
// does that. The cloud then answers FailedOperation.CertificateDeployInstanceEmpty, which is also
// what a genuinely broken switch looks like -- so the decision has to come from the bindings
// enumeration, and both answers must be COMPLETE: a partial enumeration reports 0 for a certificate
// that is bound in a region the read could not reach, and reading that as "nothing is bound" skips
// a switch that was needed, leaving a listener on a certificate that is about to expire.
func TestDeployReportsAPendingFirstBindInsteadOfAFailure(t *testing.T) {
	orig := newSSLClient
	t.Cleanup(func() { newSSLClient = orig })

	createTask, taskResult := bindingsFor(t, map[string]uint64{"new-id": 0, "old-id": 0})
	fake := &fakeSSLAPI{
		uploadFn: func(context.Context, *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error) {
			return &ssl.UploadCertificateResponse{
				Response: &ssl.UploadCertificateResponseParams{CertificateId: common.StringPtr("new-id")},
			}, nil
		},
		updateFn: func(context.Context, *ssl.UpdateCertificateInstanceRequest) (*ssl.UpdateCertificateInstanceResponse, error) {
			// What the real API answers when no resource holds the old certificate.
			return nil, errors.New("UpdateCertificateInstance: [TencentCloudSDKError] " +
				"Code=FailedOperation.CertificateDeployInstanceEmpty, Message=no usable instance was found")
		},
		createTaskFn: createTask,
		taskResultFn: taskResult,
	}
	newSSLClient = func(common.CredentialIface) (sslAPI, error) { return fake, nil }

	d := newTestDeployer(time.Now)
	id, err := d.Deploy(context.Background(), "my-cert", "old-id", []byte("cert"), []byte("key"))
	if !errors.Is(err, ErrNothingBoundYet) {
		t.Fatalf("nothing is bound anywhere, so this is a pending first bind, not a failure: %v", err)
	}
	if id != "new-id" {
		t.Errorf("the uploaded certificate's id must still be reported for the caller to record, got %q", id)
	}

	// A partial enumeration must not be read as "nothing is bound".
	createTask, taskResult = bindingsFor(t, map[string]uint64{"new-id": 0, "old-id": 0})
	// Make the old certificate's answer incomplete: one region's enumeration fails.
	partialResultFn := func(ctx context.Context, req *ssl.DescribeCertificateBindResourceTaskResultRequest) (*ssl.DescribeCertificateBindResourceTaskResultResponse, error) {
		resp, err := taskResult(ctx, req)
		if err != nil || resp == nil || resp.Response == nil {
			return resp, err
		}
		// One region's enumeration failed, so the answer is a lower bound.
		for _, task := range resp.Response.SyncTaskBindResourceResult {
			if task == nil {
				continue
			}
			for _, res := range task.BindResourceResult {
				if res == nil {
					continue
				}
				for _, region := range res.BindResourceRegionResult {
					if region != nil {
						region.Error = common.StringPtr("region ap-shanghai did not answer")
					}
				}
			}
		}
		return resp, nil
	}
	fake.createTaskFn, fake.taskResultFn = createTask, partialResultFn

	_, err = d.Deploy(context.Background(), "my-cert", "old-id", []byte("cert"), []byte("key"))
	if errors.Is(err, ErrNothingBoundYet) {
		t.Error("an incomplete enumeration reports zero for a certificate that may be bound where the " +
			"read did not reach: that must not be read as \"nothing is bound\", or a needed switch is skipped")
	}
}

// A call cut short by a shutdown must carry the shutdown's sentinel.
//
// The SDK builds a fresh *TencentCloudSDKError from the transport error's string and does not wrap
// it, so `errors.Is(err, context.Canceled)` is false for a cancelled call. Upstream, recordFailure
// uses exactly that test to decide "a stopped process is not a business failure" -- without the
// sentinel, a stop signal costs the certificate a failure counter, a backoff and a last_error it
// must then serve out after the restart.
func TestACancelledSDKCallCarriesTheContextError(t *testing.T) {
	// The shape the SDK produces, verbatim from common@v1.3.180's netretry path.
	sdkErr := tcerrors.NewTencentCloudSDKError("ClientError.NetworkError",
		"Post \"https://ssl.tencentcloudapi.com\": context canceled", "req-1")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := sdkCallError(ctx, "UploadCertificate", sdkErr)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("a cancelled call must unwrap to context.Canceled, got %v", err)
	}
	if !strings.Contains(err.Error(), "UploadCertificate") {
		t.Errorf("the call has to stay identifiable, got %v", err)
	}

	// A live context means the SDK error is a real failure, and it must keep its own identity so
	// the caller can classify it (a throttle is retried, a permission error is not).
	err = sdkCallError(context.Background(), "UploadCertificate", sdkErr)
	if !errors.Is(err, sdkErr) {
		t.Errorf("a failure on a live context must keep the SDK error, got %v", err)
	}
	if errors.Is(err, context.Canceled) {
		t.Error("a live context must not manufacture a cancellation")
	}

	// A deadline that has expired is the same story as a cancellation: the context is the reason.
	expired, cancelExpired := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancelExpired()
	time.Sleep(time.Millisecond)
	if err := sdkCallError(expired, "UploadCertificate", sdkErr); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("an expired deadline must unwrap to context.DeadlineExceeded, got %v", err)
	}
}

// ── waitDeleteTask ──────────────────────────────────────────────────────────

// A failed QUERY of the delete task is not a failed task -- the answer was never read.
// waitDeployRecord has always retried these within its deadline; the delete path used
// to give up on the first one, abandoning a task that may well have succeeded.
func TestWaitDeleteTaskRetriesQueryErrors(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)
	d := newTestDeployer(clock.now)

	var calls int
	fake := &fakeSSLAPI{
		deleteTaskFn: func(context.Context, *ssl.DescribeDeleteCertificatesTaskResultRequest) (*ssl.DescribeDeleteCertificatesTaskResultResponse, error) {
			calls++
			if calls == 1 {
				return nil, errors.New("throttled")
			}
			return deleteTaskResp("del-task-1", 1, ""), nil
		},
	}

	if err := d.waitDeleteTask(context.Background(), fake, "del-task-1", "cert-1"); err != nil {
		t.Fatalf("a single query error must be retried, got: %v", err)
	}
	if calls != 2 {
		t.Errorf("calls = %d, want one retry after the query error", calls)
	}
}

// Retrying is bounded by the task deadline, not endless: queries that keep failing end
// in the same "did not finish" timeout a running task gets, which keeps the reclaim
// record so the next round tries again.
func TestWaitDeleteTaskTimesOutWhenQueriesKeepFailing(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)
	d := newTestDeployer(clock.now)

	var calls int
	fake := &fakeSSLAPI{
		deleteTaskFn: func(context.Context, *ssl.DescribeDeleteCertificatesTaskResultRequest) (*ssl.DescribeDeleteCertificatesTaskResultResponse, error) {
			calls++
			return nil, errors.New("throttled")
		},
	}

	err := d.waitDeleteTask(context.Background(), fake, "del-task-1", "cert-1")
	if err == nil || !strings.Contains(err.Error(), "did not finish within") {
		t.Fatalf("err = %v, want the delete-task timeout", err)
	}
	if calls < 2 {
		t.Errorf("calls = %d, want polling to have repeated before timing out", calls)
	}
}

// A caller cancellation must still interrupt the wait even when the query errors are
// what made the loop spin: the retry must not swallow the shutdown signal.
func TestWaitDeleteTaskStopsOnCancellationDespiteQueryErrors(t *testing.T) {
	// No stubSleeper here: the stub ignores ctx, and honoring ctx is exactly what is
	// under test. The cancelled context makes the one real waitBetweenPolls return
	// immediately.
	d := newTestDeployer(time.Now)

	fake := &fakeSSLAPI{
		deleteTaskFn: func(context.Context, *ssl.DescribeDeleteCertificatesTaskResultRequest) (*ssl.DescribeDeleteCertificatesTaskResultResponse, error) {
			return nil, errors.New("throttled")
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := d.waitDeleteTask(ctx, fake, "del-task-1", "cert-1")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("a cancelled wait must surface the cancellation, got %v", err)
	}
}

// ── A query error that retrying cannot fix ──────────────────────────────────────
//
// The polling loops treat a failed query as "the answer is not ready yet", which is right for a
// hiccup and wrong for an error the server will repeat verbatim: a dead key or a missing
// permission then burns the whole three-minute budget and surfaces as "did not finish within
// 3m", sending the operator to look for a slow task instead of a revoked credential.

func permanentSDKError(code string) error {
	return &tcerrors.TencentCloudSDKError{Code: code, Message: "the secret id is disabled"}
}

// A permanent query error ends the wait on the first poll, and the code survives.
func TestWaitDeployRecordStopsOnAPermanentQueryError(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)
	d := newTestDeployer(clock.now)

	var polls int
	api := &fakeSSLAPI{detailFn: func(context.Context, *ssl.DescribeHostUpdateRecordDetailRequest) (*ssl.DescribeHostUpdateRecordDetailResponse, error) {
		polls++
		return nil, permanentSDKError("AuthFailure.SignatureFailure")
	}}

	err := d.waitDeployRecord(context.Background(), api, 42, "old-cert-id")
	if err == nil {
		t.Fatal("a permanent query error must fail the wait")
	}
	if polls != 1 {
		t.Errorf("polled %d times, want 1: retrying an error that cannot be fixed only delays the report", polls)
	}
	if !strings.Contains(err.Error(), "AuthFailure.SignatureFailure") {
		t.Errorf("the error must carry the API code, got %v", err)
	}
	if strings.Contains(err.Error(), "did not finish within") {
		t.Errorf("the failure must not be reported as a timeout, got %v", err)
	}
}

// The same loop still waits out a transient error, and says why when it gives up.
func TestWaitDeployRecordRetriesATransientQueryError(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)
	d := newTestDeployer(clock.now)

	var polls int
	api := &fakeSSLAPI{detailFn: func(context.Context, *ssl.DescribeHostUpdateRecordDetailRequest) (*ssl.DescribeHostUpdateRecordDetailResponse, error) {
		polls++
		return nil, permanentSDKError("InternalError")
	}}

	err := d.waitDeployRecord(context.Background(), api, 42, "old-cert-id")
	if err == nil {
		t.Fatal("an error that never clears must still fail the wait")
	}
	if polls < 2 {
		t.Errorf("polled %d times, want the loop to retry a transient error", polls)
	}
	// The reason is the point: without it this reads as a slow task.
	if !strings.Contains(err.Error(), "InternalError") {
		t.Errorf("the timeout must carry the last query error, got %v", err)
	}
}

// The delete-task loop follows the same rule.
func TestWaitDeleteTaskStopsOnAPermanentQueryError(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)
	d := newTestDeployer(clock.now)

	var polls int
	api := &fakeSSLAPI{deleteTaskFn: func(context.Context, *ssl.DescribeDeleteCertificatesTaskResultRequest) (*ssl.DescribeDeleteCertificatesTaskResultResponse, error) {
		polls++
		return nil, permanentSDKError("AuthFailure.UnauthorizedOperation")
	}}

	err := d.waitDeleteTask(context.Background(), api, "task-1", "cert-1")
	if err == nil {
		t.Fatal("a permanent query error must fail the wait")
	}
	if polls != 1 {
		t.Errorf("polled %d times, want 1", polls)
	}
	if !strings.Contains(err.Error(), "AuthFailure") {
		t.Errorf("the error must carry the API code, got %v", err)
	}
}

// The enumeration loop must not abandon a switch that already succeeded: one unreachable
// query used to fail the whole call, so the repair path skipped its fix and the
// pending-first-bind check answered false for a certificate whose rebind had in fact gone
// through.
func TestBindingsWithRetriesATransientQueryError(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)
	d := newTestDeployer(clock.now)

	taskID := "task-9"
	api := &fakeSSLAPI{
		createTaskFn: func(context.Context, *ssl.CreateCertificateBindResourceSyncTaskRequest) (*ssl.CreateCertificateBindResourceSyncTaskResponse, error) {
			return &ssl.CreateCertificateBindResourceSyncTaskResponse{
				Response: &ssl.CreateCertificateBindResourceSyncTaskResponseParams{
					CertTaskIds: []*ssl.CertTaskId{{CertId: common.StringPtr("cert-1"), TaskId: common.StringPtr(taskID)}},
				},
			}, nil
		},
		taskResultFn: func(context.Context, *ssl.DescribeCertificateBindResourceTaskResultRequest) (*ssl.DescribeCertificateBindResourceTaskResultResponse, error) {
			return nil, permanentSDKError("InternalError")
		},
	}

	// The answer is a timeout carrying the reason, not "no bindings" and not a bare failure.
	_, err := d.bindingsWith(context.Background(), api, "cert-1", false)
	if err == nil {
		t.Fatal("an error that never clears must still be reported")
	}
	if !strings.Contains(err.Error(), "InternalError") {
		t.Errorf("the failure must carry the last query error, got %v", err)
	}
}

// An expired deadline must keep BOTH identities: the context's (so "a stopped process is not a
// business failure" can still see it) and the API's own (so a throttle is still classifiable).
//
// The two used to be mutually exclusive. Reporting only the context turned
// `RequestLimitExceeded` into "context deadline exceeded", and the caller -- which backs off
// three times as long when it sees a throttle -- retried at the usual rate into a limit it had
// just hit. Reporting only the API error hid that the call never finished.
func TestADeadlineKeepsBothTheContextAndTheAPIError(t *testing.T) {
	sdkErr := permanentSDKError("RequestLimitExceeded")
	expired, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)

	err := sdkCallError(expired, "UploadCertificate", sdkErr)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("the deadline must stay visible: errors.Is(context.DeadlineExceeded) = false, got %v", err)
	}
	if !errors.Is(err, sdkErr) {
		t.Errorf("the API error must stay classifiable: errors.Is(sdkErr) = false, got %v", err)
	}
	// And the throttle must survive the wrapping, because that is the whole point: this is the
	// signal that makes the caller back off longer instead of retrying into the same limit.
	if !tcerr.IsThrottled(err) {
		t.Errorf("a throttled call that hit its deadline must still be classified as throttled, got %v", err)
	}
}

// ── reclaiming a certificate that is already gone ─────────────────────────────

// Deleting a certificate that no longer exists must be a success, not an error.
//
// The certificate can be removed out of band (console, another tool), and then the goal
// state of the reclaim -- "the certificate does not occupy a quota slot" -- is already
// reached. The SDK documents FailedOperation.CertificateNotFound for DeleteCertificate.
// Reporting it as a failure kept the retired_certificates row forever and warned on every
// pass about a certificate that no longer existed.
func TestDeleteTreatsAnAlreadyGoneCertificateAsReclaimed(t *testing.T) {
	orig := newSSLClient
	t.Cleanup(func() { newSSLClient = orig })

	fake := &fakeSSLAPI{
		deleteFn: func(context.Context, *ssl.DeleteCertificateRequest) (*ssl.DeleteCertificateResponse, error) {
			return nil, tcerrors.NewTencentCloudSDKError(
				"FailedOperation.CertificateNotFound", "certificate not found", "req-1")
		},
		// deleteTaskFn deliberately unset: there is no task to poll.
	}
	newSSLClient = func(common.CredentialIface) (sslAPI, error) { return fake, nil }

	d := newTestDeployer(time.Now)
	if err := d.Delete(context.Background(), "cert-1"); err != nil {
		t.Errorf("deleting a certificate that is already gone is the reclaim's goal state: %v", err)
	}
}

// The control: any other failure of the delete call must still surface, or the reaper would
// drop reclaim records for certificates that do still exist.
func TestDeleteStillReportsOtherFailures(t *testing.T) {
	orig := newSSLClient
	t.Cleanup(func() { newSSLClient = orig })

	fake := &fakeSSLAPI{
		deleteFn: func(context.Context, *ssl.DeleteCertificateRequest) (*ssl.DeleteCertificateResponse, error) {
			return nil, tcerrors.NewTencentCloudSDKError(
				"AuthFailure.SignatureFailure", "the secret id is disabled", "req-1")
		},
	}
	newSSLClient = func(common.CredentialIface) (sslAPI, error) { return fake, nil }

	d := newTestDeployer(time.Now)
	if err := d.Delete(context.Background(), "cert-1"); err == nil {
		t.Error(`a delete failure that is not "already gone" must keep the reclaim record`)
	}
}

// ── the timeout wording says what actually happened ───────────────────────────

// "Every poll failed" is wrong the moment one poll succeeded -- the common timeout shape is
// a slow task with some failed queries. The message must count the failed polls instead,
// the same way waitDeployRecord does.
func TestWaitDeleteTaskTimeoutCountsTheFailedPolls(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)
	d := newTestDeployer(clock.now)

	var calls int
	fake := &fakeSSLAPI{
		deleteTaskFn: func(context.Context, *ssl.DescribeDeleteCertificatesTaskResultRequest) (*ssl.DescribeDeleteCertificatesTaskResultResponse, error) {
			calls++
			if calls == 1 {
				// One poll answers "still running"; the rest fail until the deadline.
				return deleteTaskResp("del-task-1", 0, ""), nil
			}
			return nil, errors.New("throttled")
		},
	}

	err := d.waitDeleteTask(context.Background(), fake, "del-task-1", "cert-1")
	if err == nil {
		t.Fatal("a task that never finishes must fail")
	}
	if strings.Contains(err.Error(), "every poll failed") {
		t.Errorf(`one poll succeeded, so "every poll failed" is a misdiagnosis: %v`, err)
	}
	if !strings.Contains(err.Error(), "the last ") || !strings.Contains(err.Error(), " polls failed") {
		t.Errorf("the timeout must count the failed polls, got: %v", err)
	}
}

// The enumeration timeout follows the same rule.
func TestBindingsTimeoutCountsTheFailedPolls(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)
	d := newTestDeployer(clock.now)

	var calls int
	fake := &fakeSSLAPI{
		createTaskFn: stubCreateTask("cert-1", "task-1"),
		taskResultFn: func(context.Context, *ssl.DescribeCertificateBindResourceTaskResultRequest) (*ssl.DescribeCertificateBindResourceTaskResultResponse, error) {
			calls++
			if calls == 1 {
				// The task exists but is not done; the rest of the polls fail.
				return &ssl.DescribeCertificateBindResourceTaskResultResponse{
					Response: &ssl.DescribeCertificateBindResourceTaskResultResponseParams{
						SyncTaskBindResourceResult: []*ssl.SyncTaskBindResourceResult{{
							TaskId: common.StringPtr("task-1"),
							Status: common.Uint64Ptr(0),
						}},
					},
				}, nil
			}
			return nil, errors.New("throttled")
		},
	}

	_, err := d.bindingsWith(context.Background(), fake, "cert-1", false)
	if err == nil {
		t.Fatal("an enumeration that never finishes must fail")
	}
	if strings.Contains(err.Error(), "every poll failed") {
		t.Errorf(`one poll succeeded, so "every poll failed" is a misdiagnosis: %v`, err)
	}
	if !strings.Contains(err.Error(), "the last ") || !strings.Contains(err.Error(), " polls failed") {
		t.Errorf("the timeout must count the failed polls, got: %v", err)
	}
}
