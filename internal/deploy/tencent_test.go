package deploy

import (
	"testing"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

func TestProgressBoundCount(t *testing.T) {
	if n := progressBoundCount(nil); n != 0 {
		t.Errorf("nil progress = %d, want 0", n)
	}

	zero := []*ssl.UpdateSyncProgress{{
		ResourceType: common.StringPtr("clb"),
		UpdateSyncProgressRegions: []*ssl.UpdateSyncProgressRegion{{
			Region:     common.StringPtr("ap-guangzhou"),
			TotalCount: common.Int64Ptr(0),
		}},
	}}
	if n := progressBoundCount(zero); n != 0 {
		t.Errorf("zero total = %d, want 0", n)
	}

	bound := []*ssl.UpdateSyncProgress{{
		ResourceType: common.StringPtr("clb"),
		UpdateSyncProgressRegions: []*ssl.UpdateSyncProgressRegion{{
			Region:     common.StringPtr("ap-guangzhou"),
			TotalCount: common.Int64Ptr(2),
		}, {
			Region:     common.StringPtr("ap-shanghai"),
			TotalCount: common.Int64Ptr(1),
		}},
	}}
	if n := progressBoundCount(bound); n != 3 {
		t.Errorf("bound = %d, want 3", n)
	}
}

// ── Confirming bindings ─────────────────────────────────────────────────────
//
// I got this logic wrong in two places in my first version. Neither breaks the build;
// both just misjudge a well-bound certificate as "unbound" on a real machine (the
// deployed metric silently reports 0, for up to 90 days):
//
//   1. I guessed the meaning of Status backwards. Empirically Status == 1 on success, but
//      I wrote "Status != 0 means not ready yet" by intuition, so it waited for a result
//      that never arrived.
//   2. I returned as soon as the TaskId matched. The first query (before the server-side
//      cache exists) returns an object with a correct TaskId but an empty result list, and
//      that instant gets judged as "0 bindings".
//
// So both traps are pinned down here.

func bindResp(taskID string, status uint64, withResult bool) *ssl.DescribeCertificateBindResourceTaskResultResponse {
	r := &ssl.SyncTaskBindResourceResult{
		TaskId: common.StringPtr(taskID),
		Status: common.Uint64Ptr(status),
	}
	if withResult {
		r.BindResourceResult = []*ssl.BindResourceResult{{
			ResourceType: common.StringPtr("clb"),
			BindResourceRegionResult: []*ssl.BindResourceRegionResult{
				{Region: common.StringPtr("ap-guangzhou"), TotalCount: common.Uint64Ptr(2), Error: common.StringPtr("")},
				{Region: common.StringPtr("ap-shanghai"), TotalCount: common.Uint64Ptr(1), Error: common.StringPtr("")},
			},
		}}
	}
	return &ssl.DescribeCertificateBindResourceTaskResultResponse{
		Response: &ssl.DescribeCertificateBindResourceTaskResultResponseParams{
			SyncTaskBindResourceResult: []*ssl.SyncTaskBindResourceResult{r},
		},
	}
}

// Status == 1 with results populated -> done, totaling 3.
func TestCountBindingsDone(t *testing.T) {
	n, done, err := countBindings(bindResp("t1", bindStatusDone, true), "t1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !done {
		t.Fatal("Status=1 with results populated should be judged done")
	}
	if n != 3 {
		t.Errorf("count = %d, want 3", n)
	}
}

// This pins down the first trap: Status=1 means **done**, not "in progress".
func TestCountBindingsStatusOneMeansDone(t *testing.T) {
	_, done, _ := countBindings(bindResp("t1", 1, true), "t1")
	if !done {
		t.Error("Status=1 must be treated as done -- the reverse makes confirmation time out forever")
	}
}

// This pins down the second trap: when the TaskId matches but results are empty it must
// keep waiting, and must not report 0.
func TestCountBindingsEmptyResultIsNotDone(t *testing.T) {
	n, done, err := countBindings(bindResp("t1", bindStatusDone, false), "t1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if done {
		t.Error("an empty result list must keep waiting, otherwise a bound certificate is judged unbound")
	}
	if n != 0 {
		t.Errorf("count should be 0 when not done, got %d", n)
	}
}

// A not-yet-done status must likewise keep waiting.
func TestCountBindingsPendingIsNotDone(t *testing.T) {
	_, done, _ := countBindings(bindResp("t1", 0, true), "t1")
	if done {
		t.Error("Status=0 means not done yet, so it should keep waiting")
	}
}

// A mismatched TaskId must not take someone else's result as its own.
func TestCountBindingsIgnoresOtherTasks(t *testing.T) {
	_, done, _ := countBindings(bindResp("other", bindStatusDone, true), "t1")
	if done {
		t.Error("a mismatched TaskId should not be judged done")
	}
}

// A server-reported error must be surfaced rather than waiting idly until timeout.
func TestCountBindingsSurfacesTaskError(t *testing.T) {
	resp := bindResp("t1", 0, false)
	resp.Response.SyncTaskBindResourceResult[0].Error = &ssl.Error{Message: common.StringPtr("boom")}

	if _, _, err := countBindings(resp, "t1"); err == nil {
		t.Error("a failing task should return an error rather than keep waiting idly")
	}
}

// When a region's query fails, that region's number cannot be trusted and must not be
// added in.
func TestCountBindingsSkipsErroredRegion(t *testing.T) {
	resp := &ssl.DescribeCertificateBindResourceTaskResultResponse{
		Response: &ssl.DescribeCertificateBindResourceTaskResultResponseParams{
			SyncTaskBindResourceResult: []*ssl.SyncTaskBindResourceResult{{
				TaskId: common.StringPtr("t1"),
				Status: common.Uint64Ptr(bindStatusDone),
				BindResourceResult: []*ssl.BindResourceResult{{
					ResourceType: common.StringPtr("clb"),
					BindResourceRegionResult: []*ssl.BindResourceRegionResult{
						{Region: common.StringPtr("ap-guangzhou"), TotalCount: common.Uint64Ptr(2)},
						{Region: common.StringPtr("ap-shanghai"), TotalCount: common.Uint64Ptr(9), Error: common.StringPtr("query failed")},
					},
				}},
			}},
		},
	}

	n, done, err := countBindings(resp, "t1")
	if err != nil || !done {
		t.Fatalf("done=%v err=%v", done, err)
	}
	if n != 2 {
		t.Errorf("an errored region should not be counted, count = %d, want 2", n)
	}
}

func TestCountBindingsNilResponse(t *testing.T) {
	if _, done, _ := countBindings(nil, "t1"); done {
		t.Error("a nil response should not be judged done")
	}
}
