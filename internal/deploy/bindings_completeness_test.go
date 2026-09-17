package deploy

import (
	"context"
	"testing"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

// bindAnswer scripts one CreateCertificateBindResourceSyncTask + result pair for a certificate
// whose enumeration task is `taskID`: it is bound to `total` resources in one region, and that
// region answers unless `errored`.
//
// `errored` is the interesting shape. The SDK reports a region whose query failed by leaving
// TotalCount unset and filling in Error, so the region contributes nothing to the total -- which
// makes the total a lower bound rather than an answer, and made it indistinguishable from 0.
func bindAnswer(certID, taskID string, total uint64, errored bool) (*ssl.CreateCertificateBindResourceSyncTaskResponse, *ssl.DescribeCertificateBindResourceTaskResultResponse) {
	region := &ssl.BindResourceRegionResult{
		Region:     common.StringPtr("ap-guangzhou"),
		TotalCount: common.Uint64Ptr(total),
	}
	if errored {
		region = &ssl.BindResourceRegionResult{
			Region: common.StringPtr("ap-guangzhou"),
			Error:  common.StringPtr("query failed"),
		}
	}

	create := &ssl.CreateCertificateBindResourceSyncTaskResponse{
		Response: &ssl.CreateCertificateBindResourceSyncTaskResponseParams{
			CertTaskIds: []*ssl.CertTaskId{{CertId: common.StringPtr(certID), TaskId: common.StringPtr(taskID)}},
		},
	}
	result := &ssl.DescribeCertificateBindResourceTaskResultResponse{
		Response: &ssl.DescribeCertificateBindResourceTaskResultResponseParams{
			SyncTaskBindResourceResult: []*ssl.SyncTaskBindResourceResult{{
				TaskId: common.StringPtr(taskID),
				Status: common.Uint64Ptr(bindStatusDone),
				BindResourceResult: []*ssl.BindResourceResult{{
					ResourceType:             common.StringPtr("clb"),
					BindResourceRegionResult: []*ssl.BindResourceRegionResult{region},
				}},
			}},
		},
	}
	return create, result
}

// scriptedBindings returns a fakeSSLAPI that answers each certificate with its own enumeration task.
func scriptedBindings(
	cacheFlags *[]uint64,
	newCreate *ssl.CreateCertificateBindResourceSyncTaskResponse,
	newResult *ssl.DescribeCertificateBindResourceTaskResultResponse,
	oldCreate *ssl.CreateCertificateBindResourceSyncTaskResponse,
	oldResult *ssl.DescribeCertificateBindResourceTaskResultResponse,
) *fakeSSLAPI {
	return &fakeSSLAPI{
		// The switch fails, which is the condition the repair path exists for ("the rebind
		// succeeded but was not recorded", reported as an error by the API).
		updateFn: func(_ context.Context, _ *ssl.UpdateCertificateInstanceRequest) (*ssl.UpdateCertificateInstanceResponse, error) {
			return nil, errNothingToSwitch{}
		},
		createTaskFn: func(_ context.Context, req *ssl.CreateCertificateBindResourceSyncTaskRequest) (*ssl.CreateCertificateBindResourceSyncTaskResponse, error) {
			if cacheFlags != nil {
				*cacheFlags = append(*cacheFlags, derefU64(req.IsCache))
			}
			if len(req.CertificateIds) > 0 && derefStr(req.CertificateIds[0]) == "old-id" {
				return oldCreate, nil
			}
			return newCreate, nil
		},
		taskResultFn: func(_ context.Context, req *ssl.DescribeCertificateBindResourceTaskResultRequest) (*ssl.DescribeCertificateBindResourceTaskResultResponse, error) {
			if len(req.TaskIds) > 0 && derefStr(req.TaskIds[0]) == "task-old" {
				return oldResult, nil
			}
			return newResult, nil
		},
	}
}

// errNothingToSwitch stands in for the cloud's answer when there is nothing left to rebind.
type errNothingToSwitch struct{}

func (errNothingToSwitch) Error() string { return "The certificate has no resources to be updated" }

// The defect this pins: the repair path read "the old certificate is bound nowhere" out of an
// enumeration that had not covered every region, and reported a half-finished switch as done.
//
// The shape here is exactly the dangerous one. The switch failed with "nothing to switch", the new
// certificate is bound, and the old certificate's only region never answered -- so it may still be
// serving that region's listeners. Reading the failed region as "0 bindings left" turned that into
// success, and nothing would ever revisit those listeners.
func TestDeployUploadedDoesNotRepairOnAPartialOldCertificateAnswer(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)
	d := newTestDeployer(clock.now)

	newCreate, newResult := bindAnswer("new-id", "task-new", 1, false)
	oldCreate, oldResult := bindAnswer("old-id", "task-old", 0, true)
	fake := scriptedBindings(nil, newCreate, newResult, oldCreate, oldResult)

	if _, err := d.deployUploaded(context.Background(), fake, "c", "old-id", "new-id"); err == nil {
		t.Fatal("the old certificate's region never answered, so whether it is still bound is " +
			"unknown; reporting the switch as done on that answer is how listeners stay on the old " +
			"certificate with nothing left to revisit them")
	}
}

// The control: with every region answering, the new certificate bound and the old one genuinely
// bound nowhere, the repair must still fire. Without this, "never repair" would pass the test above
// and leave the historical wedge in place forever.
func TestDeployUploadedStillRepairsACompleteAnswer(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)
	d := newTestDeployer(clock.now)

	newCreate, newResult := bindAnswer("new-id", "task-new", 2, false)
	oldCreate, oldResult := bindAnswer("old-id", "task-old", 0, false)
	fake := scriptedBindings(nil, newCreate, newResult, oldCreate, oldResult)

	got, err := d.deployUploaded(context.Background(), fake, "c", "old-id", "new-id")
	if err != nil {
		t.Fatalf("a complete answer saying the new certificate is bound and the old one is not is "+
			"exactly what the repair exists for, got error: %v", err)
	}
	if got != "new-id" {
		t.Errorf("repaired ID = %q, want new-id", got)
	}
}

// The verification lookups must not trust the server-side cache.
//
// The SDK documents IsCache=1 as: if a completed task exists for this certificate within the last
// half hour, return the completed task's result closest to now *within that half hour*. That is
// acceptable for the periodic "has a human bound it yet" poll and wrong for a lookup that decides
// whether a switch took effect, because it can answer from before the switch.
//
// The assertion is made through the real call sites -- deployUploaded and Bindings -- rather than by
// calling bindingsWith with cached=false directly. A direct call only proves the parameter is
// honoured, which is what the first version of this test did: flipping the repair path back to the
// cache left it green.
func TestVerificationLookupsDoNotUseTheServerSideCache(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)
	d := newTestDeployer(clock.now)

	var cacheFlags []uint64
	newCreate, newResult := bindAnswer("new-id", "task-new", 2, false)
	oldCreate, oldResult := bindAnswer("old-id", "task-old", 0, false)
	fake := scriptedBindings(&cacheFlags, newCreate, newResult, oldCreate, oldResult)

	if _, err := d.deployUploaded(context.Background(), fake, "c", "old-id", "new-id"); err != nil {
		t.Fatalf("the repair path should have accepted a complete answer: %v", err)
	}
	if len(cacheFlags) == 0 {
		t.Fatal("the repair path queried nothing, so this test proves nothing")
	}
	for i, flag := range cacheFlags {
		if flag != 0 {
			t.Errorf("bind-resource query %d of %d used IsCache=%d: a cached answer can be up to half "+
				"an hour old, which cannot decide whether a switch took effect", i+1, len(cacheFlags), flag)
		}
	}

	// The periodic confirmation poll is the one place the cache is wanted; without it every
	// reconcile would force a full enumeration.
	// Bindings is the periodic entry point, so it goes through the client factory. Stub it: the
	// first version of this test called the real factory and made a real request to Tencent Cloud.
	cacheFlags = nil
	stubSSLClient(t, &fakeSSLAPI{
		createTaskFn: func(_ context.Context, req *ssl.CreateCertificateBindResourceSyncTaskRequest) (*ssl.CreateCertificateBindResourceSyncTaskResponse, error) {
			cacheFlags = append(cacheFlags, derefU64(req.IsCache))
			return newCreate, nil
		},
		taskResultFn: func(_ context.Context, _ *ssl.DescribeCertificateBindResourceTaskResultRequest) (*ssl.DescribeCertificateBindResourceTaskResultResponse, error) {
			return newResult, nil
		},
	})
	if _, _, err := d.Bindings(context.Background(), "new-id"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cacheFlags) != 1 || cacheFlags[0] != 1 {
		t.Errorf("the periodic poll used IsCache=%v, want 1 -- the cache exists to stop every "+
			"reconcile from forcing a full enumeration", cacheFlags)
	}
}

func derefU64(p *uint64) uint64 {
	if p == nil {
		return 0
	}
	return *p
}

// An answer with no task to read is the absence of an answer, not the answer zero.
func TestBindingCountWithoutATaskIsNotZero(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	stubSleeper(t, clock)
	d := newTestDeployer(clock.now)

	fake := &fakeSSLAPI{
		createTaskFn: func(_ context.Context, _ *ssl.CreateCertificateBindResourceSyncTaskRequest) (*ssl.CreateCertificateBindResourceSyncTaskResponse, error) {
			return &ssl.CreateCertificateBindResourceSyncTaskResponse{
				Response: &ssl.CreateCertificateBindResourceSyncTaskResponseParams{CertTaskIds: []*ssl.CertTaskId{}},
			}, nil
		},
	}

	n, err := d.bindingsWith(context.Background(), fake, "cert", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n.count != 0 || n.complete {
		t.Errorf("got %+v, want an incomplete zero: the API returned no task, which is the absence "+
			"of an answer rather than the answer zero", n)
	}
}

// An enumeration that counted no region must not be published as the authoritative number zero.
//
// The repair path reads `complete && count == 0` as "the old certificate is gone, so the switch
// happened" and reports the deploy as done; the certificate that is still serving traffic then
// goes on the reclaim list. The empty outer list is already refused for exactly that reason, and
// the same partial-population shape one level down -- a resource-type entry with no body, or with
// no region counted at all -- has to be refused too. The real API expresses a genuine zero as
// POPULATED entries (`{Region:"", TotalCount:0}`), never as a missing child list.
func TestAnUnpopulatedBindingEntryIsNotAnAuthoritativeZero(t *testing.T) {
	t.Run("nil resource-type entry", func(t *testing.T) {
		result := &ssl.DescribeCertificateBindResourceTaskResultResponse{
			Response: &ssl.DescribeCertificateBindResourceTaskResultResponseParams{
				SyncTaskBindResourceResult: []*ssl.SyncTaskBindResourceResult{{
					TaskId: common.StringPtr("task-1"),
					Status: common.Uint64Ptr(bindStatusDone),
					BindResourceResult: []*ssl.BindResourceResult{
						nil,
						{ResourceType: common.StringPtr("clb")},
					},
				}},
			},
		}
		n, _, err := countBindings(result, "task-1")
		if err != nil {
			t.Fatalf("countBindings: %v", err)
		}
		if n.complete {
			t.Error("an entry that counted nothing must leave the enumeration incomplete: a complete " +
				"zero means \"the old certificate is gone\" to the repair path, which then claims a " +
				"switch that may not have happened")
		}
	})

	t.Run("entry with no region", func(t *testing.T) {
		result := &ssl.DescribeCertificateBindResourceTaskResultResponse{
			Response: &ssl.DescribeCertificateBindResourceTaskResultResponseParams{
				SyncTaskBindResourceResult: []*ssl.SyncTaskBindResourceResult{{
					TaskId: common.StringPtr("task-1"),
					Status: common.Uint64Ptr(bindStatusDone),
					BindResourceResult: []*ssl.BindResourceResult{
						{ResourceType: common.StringPtr("clb"), BindResourceRegionResult: nil},
					},
				}},
			},
		}
		n, _, err := countBindings(result, "task-1")
		if err != nil {
			t.Fatalf("countBindings: %v", err)
		}
		if n.complete {
			t.Error("a resource-type entry with no counted region must leave the enumeration incomplete")
		}
	})
}
