package deploy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
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
	createTaskFn func(context.Context, *ssl.CreateCertificateBindResourceSyncTaskRequest) (*ssl.CreateCertificateBindResourceSyncTaskResponse, error)
	taskResultFn func(context.Context, *ssl.DescribeCertificateBindResourceTaskResultRequest) (*ssl.DescribeCertificateBindResourceTaskResultResponse, error)
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

// ── recovery: a switch that happened but was not recorded ───────────────────

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
		createTaskFn: stubCreateTask("new-id", "task-1"),
		taskResultFn: func(context.Context, *ssl.DescribeCertificateBindResourceTaskResultRequest) (*ssl.DescribeCertificateBindResourceTaskResultResponse, error) {
			return bindingsResp("task-1", 3), nil
		},
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
