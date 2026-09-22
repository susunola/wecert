package deploy

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"

	"github.com/susunola/wecert/internal/tcerr"
)

func (d *TencentCLB) waitDeployRecord(ctx context.Context, client sslAPI, recordID uint64, oldID string) error {
	deadline := d.now().Add(3 * time.Minute)
	var success, failed, running, pending int64
	var lastQueryErr error
	var pollFailures int
	throttled := false
	graceUntil := d.now().Add(deployRecordGrace)
	for {
		s, f, r, p, instrumented, err := d.describeDeployRecord(ctx, client, recordID)
		if err != nil {
			if tcerr.IsPermanent(err) {
				return fmt.Errorf("cannot query one-click update task %d: %w", recordID, err)
			}
			pollFailures++
			lastQueryErr = err
			if tcerr.IsThrottled(err) {
				throttled = true
			}
			d.log.Warn("failed to query the deploy record; retrying shortly", "deployRecordId", recordID, "err", err)
		} else if !instrumented {
			d.log.Info("the deploy record carries no counters yet; waiting for the server to instrument the task",
				"deployRecordId", recordID)
		} else {
			success, failed, running, pending = s, f, r, p
			d.log.Info("one-click update progress",
				"deployRecordId", recordID,
				"success", success, "failed", failed, "running", running, "pending", pending)
			if running == 0 && pending == 0 && (success+failed) > 0 {
				if failed > 0 {
					return fmt.Errorf("one-click update finished with %d resources failed (%d succeeded)", failed, success)
				}
				return nil
			}
			if running == 0 && pending == 0 && success == 0 && failed == 0 && d.now().After(graceUntil) {
				return noResourceBoundError(oldID, d.regions)
			}
		}
		if d.now().After(deadline) {
			if lastQueryErr != nil {
				return fmt.Errorf("one-click update task %d did not finish within 3m (success=%d failed=%d running=%d pending=%d); the last %d polls failed, most recently: %w",
					recordID, success, failed, running, pending, pollFailures, lastQueryErr)
			}
			return fmt.Errorf("one-click update task %d did not finish within 3m (success=%d failed=%d running=%d pending=%d)",
				recordID, success, failed, running, pending)
		}
		if err := waitBetweenPolls(ctx, pollWait(5*time.Second, throttled)); err != nil {
			return err
		}
	}
}

func pollWait(base time.Duration, throttled bool) time.Duration {
	if throttled {
		return 3 * base
	}
	return base
}

func (d *TencentCLB) describeDeployRecord(ctx context.Context, client sslAPI, recordID uint64) (success, failed, running, pending int64, instrumented bool, err error) {
	req := ssl.NewDescribeHostUpdateRecordDetailRequest()
	req.DeployRecordId = common.StringPtr(strconv.FormatUint(recordID, 10))
	resp, err := client.DescribeHostUpdateRecordDetailWithContext(ctx, req)
	if err != nil {
		return 0, 0, 0, 0, false, sdkCallError(ctx, fmt.Sprintf("DescribeHostUpdateRecordDetail(%d)", recordID), err)
	}
	if resp.Response == nil {
		return 0, 0, 0, 0, false, errors.New("DescribeHostUpdateRecordDetail returned an empty response")
	}
	r := resp.Response
	if r.SuccessTotalCount == nil || r.FailedTotalCount == nil || r.RunningTotalCount == nil || r.PendingTotalCount == nil {
		return 0, 0, 0, 0, false, nil
	}
	return *r.SuccessTotalCount, *r.FailedTotalCount, *r.RunningTotalCount, *r.PendingTotalCount, true, nil
}

func (d *TencentCLB) resourceTypeRegions() []*ssl.ResourceTypeRegions {
	out := make([]*ssl.ResourceTypeRegions, 0, len(d.types))
	for _, t := range d.types {
		out = append(out, &ssl.ResourceTypeRegions{
			ResourceType: common.StringPtr(t),
			Regions:      toPtrSlice(d.regions),
		})
	}
	return out
}
