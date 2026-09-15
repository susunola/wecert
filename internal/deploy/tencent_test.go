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
