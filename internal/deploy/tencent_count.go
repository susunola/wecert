package deploy

import (
	"context"
	"errors"
	"fmt"

	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

type bindingCount struct {
	count    int
	complete bool
}

// ErrNothingBoundYet means the certificate was uploaded, but neither it nor the certificate it
// replaces is bound to any cloud resource.
var ErrNothingBoundYet = errors.New("the certificate is uploaded but nothing is bound to it yet")

func (d *TencentCLB) nothingBoundYet(ctx context.Context, client sslAPI, oldID, newID string) bool {
	newBindings, nerr := d.bindingsWith(ctx, client, newID, false)
	if nerr != nil || !newBindings.complete || newBindings.count > 0 {
		return false
	}
	oldBindings, oerr := d.bindingsWith(ctx, client, oldID, false)
	return oerr == nil && oldBindings.complete && oldBindings.count == 0
}

const bindStatusDone = 1

func countBindings(
	resp *ssl.DescribeCertificateBindResourceTaskResultResponse, taskID string,
) (count bindingCount, done bool, err error) {
	if resp == nil || resp.Response == nil {
		return bindingCount{}, false, nil
	}

	for _, r := range resp.Response.SyncTaskBindResourceResult {
		if r == nil || r.TaskId == nil || *r.TaskId != taskID {
			continue
		}
		if r.Error != nil && r.Error.Message != nil && *r.Error.Message != "" {
			return bindingCount{}, false, fmt.Errorf("bind-resource task %s failed: %s", taskID, *r.Error.Message)
		}
		if r.Status == nil || *r.Status != bindStatusDone || len(r.BindResourceResult) == 0 {
			// An empty result with Status=done is NOT "finished, nothing bound": the first
			// query (before the server-side cache exists) answers with a correct TaskId and
			// an empty list, and judging that as 0 bindings reports a bound certificate as
			// unbound. Keep waiting -- see TestCountBindingsEmptyResultIsNotDone.
			return bindingCount{}, false, nil
		}

		total := 0
		complete := true
		for _, res := range r.BindResourceResult {
			if res == nil {
				complete = false
				continue
			}
			if len(res.BindResourceRegionResult) == 0 {
				complete = false
			}
			for _, region := range res.BindResourceRegionResult {
				if region == nil || region.TotalCount == nil {
					complete = false
					continue
				}
				if region.Error != nil && *region.Error != "" {
					complete = false
					continue
				}
				total += int(*region.TotalCount)
			}
		}
		return bindingCount{count: total, complete: complete}, true, nil
	}

	return bindingCount{}, false, nil
}
