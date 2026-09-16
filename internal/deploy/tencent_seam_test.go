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

// updateResp builds an UpdateCertificateInstance response. bound == 0 leaves the
// progress list empty, which is how the server reports "nothing was bound".
func updateResp(recordID uint64, bound int64) *ssl.UpdateCertificateInstanceResponse {
	resp := &ssl.UpdateCertificateInstanceResponse{
		Response: &ssl.UpdateCertificateInstanceResponseParams{
			DeployRecordId: common.Uint64Ptr(recordID),
		},
	}
	if bound > 0 {
		resp.Response.UpdateSyncProgress = []*ssl.UpdateSyncProgress{{
			ResourceType: common.StringPtr("clb"),
			UpdateSyncProgressRegions: []*ssl.UpdateSyncProgressRegion{{
				Region:     common.StringPtr("ap-guangzhou"),
				TotalCount: common.Int64Ptr(bound),
			}},
		}}
	}
	return resp
}

func detailResp(success, failed, running int64) *ssl.DescribeHostUpdateRecordDetailResponse {
	return &ssl.DescribeHostUpdateRecordDetailResponse{
		Response: &ssl.DescribeHostUpdateRecordDetailResponseParams{
			SuccessTotalCount: common.Int64Ptr(success),
			FailedTotalCount:  common.Int64Ptr(failed),
			RunningTotalCount: common.Int64Ptr(running),
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

	err := d.waitDeployRecord(context.Background(), fake, 7)
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

	if err := d.waitDeployRecord(context.Background(), fake, 7); err != nil {
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

	if err := d.waitDeployRecord(context.Background(), fake, 7); err != nil {
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

	err := d.waitDeployRecord(context.Background(), fake, 7)
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
