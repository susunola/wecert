package deploy

import (
	"strings"
	"testing"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

func TestProgressBoundCount(t *testing.T) {
	if n, ready := progressBoundCount(nil); n != 0 || ready {
		t.Errorf("nil progress = (%d, %v), want (0, false)", n, ready)
	}

	zero := []*ssl.UpdateSyncProgress{{
		ResourceType: common.StringPtr("clb"),
		UpdateSyncProgressRegions: []*ssl.UpdateSyncProgressRegion{{
			Region:     common.StringPtr("ap-guangzhou"),
			TotalCount: common.Int64Ptr(0),
		}},
	}}
	if n, ready := progressBoundCount(zero); n != 0 || !ready {
		t.Errorf("zero total = (%d, %v), want (0, true): an explicitly populated zero must be reported as ready", n, ready)
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
	if n, ready := progressBoundCount(bound); n != 3 || !ready {
		t.Errorf("bound = (%d, %v), want (3, true)", n, ready)
	}
}

// 钉住换绑误判的坑：UpdateCertificateInstance 任务创建成功、后台实际也会
// 正常完成，但同步响应里 UpdateSyncProgressRegions[].TotalCount 全为 null
// （服务端异步填充）。null 必须被视为"进度未就绪"，而不是"没有绑定资源"——
// 否则一次成功的换绑会被误报成失败，随后以旧证书为锚重试又会陷入
// bound=0 的死循环，每一轮还多漏一张孤儿证书。
func TestProgressBoundCountNullTotalCountIsNotReady(t *testing.T) {
	progress := []*ssl.UpdateSyncProgress{{
		ResourceType: common.StringPtr("clb"),
		UpdateSyncProgressRegions: []*ssl.UpdateSyncProgressRegion{{
			Region:     common.StringPtr("ap-singapore"),
			TotalCount: nil,
		}, {
			Region:     common.StringPtr("ap-tokyo"),
			TotalCount: nil,
		}},
	}}
	n, ready := progressBoundCount(progress)
	if n != 0 {
		t.Fatalf("count = %d, want 0", n)
	}
	if ready {
		t.Fatal("ready = true, want false: a null TotalCount means the progress has not been populated yet, not that no resource is bound")
	}
}

// 混合情形：任一 region 的 TotalCount 非 nil 即视为进度已填充。
func TestProgressBoundCountMixedNullAndValue(t *testing.T) {
	progress := []*ssl.UpdateSyncProgress{{
		ResourceType: common.StringPtr("clb"),
		UpdateSyncProgressRegions: []*ssl.UpdateSyncProgressRegion{{
			Region:     common.StringPtr("ap-singapore"),
			TotalCount: nil,
		}, {
			Region:     common.StringPtr("ap-tokyo"),
			TotalCount: common.Int64Ptr(1),
		}},
	}}
	if n, ready := progressBoundCount(progress); n != 1 || !ready {
		t.Fatalf("count = %d, ready = %v; want 1, true", n, ready)
	}
}

func TestNoResourceBoundErrorMentionsCertAndSNIHint(t *testing.T) {
	err := noResourceBoundError("aqOld", []string{"ap-singapore"})
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	for _, want := range []string{"aqOld", "ap-singapore", "multi_cert_info"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error message %q does not mention %q", msg, want)
		}
	}
}

// ── 确认绑定关系 ────────────────────────────────────────────────────────────
//
// 这段逻辑我第一版写错了两处，两处都不会导致编译失败、只会在真机上
// 把一张绑好的证书判成“未绑定”（deployed 指标静默报 0，最长 90 天）：
//
//   1. Status 的语义猜反了。实测成功时 Status == 1，我按直觉写成了
//      “Status != 0 就是还没好”，于是永远等不到结果。
//   2. 只看 TaskId 匹配就返回。首次查询（服务端缓存未建立）会返回一个
//      TaskId 正确、但结果列表为空的对象，那一刻会被判成“绑定数为 0”。
//
// 所以这里把两个坑都钉住。

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

// Status == 1 且结果已填充 → 完成，合计 3。
func TestCountBindingsDone(t *testing.T) {
	n, done, err := countBindings(bindResp("t1", bindStatusDone, true), "t1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !done {
		t.Fatal("Status=1 且结果已填充时应当判定为完成")
	}
	if n != 3 {
		t.Errorf("count = %d, want 3", n)
	}
}

// 这条钉住第一个坑：Status=1 是**完成**，不是“进行中”。
func TestCountBindingsStatusOneMeansDone(t *testing.T) {
	_, done, _ := countBindings(bindResp("t1", 1, true), "t1")
	if !done {
		t.Error("Status=1 必须被当成完成 —— 反过来的话确认会永远超时")
	}
}

// 这条钉住第二个坑：TaskId 匹配但结果为空时，必须继续等，不能报 0。
func TestCountBindingsEmptyResultIsNotDone(t *testing.T) {
	n, done, err := countBindings(bindResp("t1", bindStatusDone, false), "t1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if done {
		t.Error("结果列表为空时必须继续等，否则会把绑好的证书判成未绑定")
	}
	if n != 0 {
		t.Errorf("未完成时 count 应为 0，得到 %d", n)
	}
}

// 还没到完成状态时同样要继续等。
func TestCountBindingsPendingIsNotDone(t *testing.T) {
	_, done, _ := countBindings(bindResp("t1", 0, true), "t1")
	if done {
		t.Error("Status=0 表示还没完成，应当继续等")
	}
}

// TaskId 对不上时不能拿别人的结果当自己的。
func TestCountBindingsIgnoresOtherTasks(t *testing.T) {
	_, done, _ := countBindings(bindResp("other", bindStatusDone, true), "t1")
	if done {
		t.Error("TaskId 不匹配时不该判定为完成")
	}
}

// 服务端报错时要把错误抛出来，而不是空等到超时。
func TestCountBindingsSurfacesTaskError(t *testing.T) {
	resp := bindResp("t1", 0, false)
	resp.Response.SyncTaskBindResourceResult[0].Error = &ssl.Error{Message: common.StringPtr("boom")}

	if _, _, err := countBindings(resp, "t1"); err == nil {
		t.Error("任务报错时应当返回错误，而不是继续空等")
	}
}

// 某个地域查询异常时，那个地域的数字不可信，不能累加进去。
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
		t.Errorf("查询异常的地域不应计入，count = %d, want 2", n)
	}
}

func TestCountBindingsNilResponse(t *testing.T) {
	if _, done, _ := countBindings(nil, "t1"); done {
		t.Error("nil 响应不该判定为完成")
	}
}
