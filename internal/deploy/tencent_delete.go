package deploy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"

	"github.com/susunola/wecert/internal/tcerr"
)

func (d *TencentCLB) Delete(ctx context.Context, certID string) error {
	if certID == "" {
		return nil
	}
	client, err := d.client(ctx)
	if err != nil {
		return err
	}
	req := ssl.NewDeleteCertificateRequest()
	req.CertificateId = common.StringPtr(certID)
	req.IsCheckResource = common.BoolPtr(true)
	resp, err := client.DeleteCertificateWithContext(ctx, req)
	if err != nil {
		// "The certificate does not exist" is the goal state already reached, not a
		// failure: the certificate was deleted out of band (console, another tool) and
		// nothing remains to reclaim. Re-reporting it as an error would keep the
		// retired_certificates row alerting on every pass forever.
		if isCertificateNotFound(err) {
			d.log.Info("the certificate is already gone from the cloud account; the reclaim is complete",
				"certId", certID)
			return nil
		}
		return sdkCallError(ctx, "DeleteCertificate("+certID+")", err)
	}
	// The certificate is gone from the account (or the delete is in flight): its
	// cached BindingSnapshot is dead weight now. Doing this only on success would
	// keep the snapshot of a refused delete, which is still the right answer for a
	// later inventory lookup -- so drop it once the API has accepted the delete.
	defer ForgetBindings(certID)
	if resp.Response == nil {
		return fmt.Errorf("DeleteCertificate(%s): the API returned an empty response", certID)
	}
	if (resp.Response.DeleteResult != nil && !*resp.Response.DeleteResult) &&
		(resp.Response.TaskId == nil || *resp.Response.TaskId == "") {
		return fmt.Errorf("DeleteCertificate(%s): the API refused the delete", certID)
	}
	if resp.Response.TaskId == nil || *resp.Response.TaskId == "" {
		return nil
	}
	return d.waitDeleteTask(ctx, client, *resp.Response.TaskId, certID)
}

const (
	deleteTaskTimeout = 2 * time.Minute
	deleteTaskPoll    = 3 * time.Second
	deleteTaskRunning = 0
	deleteTaskSuccess = 1
)

func (d *TencentCLB) waitDeleteTask(ctx context.Context, client sslAPI, taskID, certID string) error {
	deadline := d.now().Add(deleteTaskTimeout)
	var lastQueryErr error
	var pollFailures int
	throttled := false
	for {
		req := ssl.NewDescribeDeleteCertificatesTaskResultRequest()
		req.TaskIds = []*string{common.StringPtr(taskID)}
		resp, err := client.DescribeDeleteCertificatesTaskResultWithContext(ctx, req)
		if err != nil {
			if tcerr.IsPermanent(err) {
				return fmt.Errorf("cannot query the delete task for %s (taskId=%s): %w", certID, taskID, err)
			}
			lastQueryErr = err
			pollFailures++
			if tcerr.IsThrottled(err) {
				throttled = true
			}
			d.log.Warn("failed to query the delete task's result; retrying shortly",
				"taskId", taskID, "err", err)
		} else {
			status, detail, found, err := deleteTaskStatus(resp, taskID)
			if err != nil {
				return err
			}
			if found && status != deleteTaskRunning {
				if status == deleteTaskSuccess {
					return nil
				}
				return fmt.Errorf("DeleteCertificate(%s) failed: task %s reported status %d%s",
					certID, taskID, status, detail)
			}
		}
		if d.now().After(deadline) {
			if lastQueryErr != nil {
				return fmt.Errorf(
					"the delete task for %s did not finish within %s (taskId=%s); the last %d polls failed, most recently: %w; "+
						"keeping it on the reclaim list to retry",
					certID, deleteTaskTimeout, taskID, pollFailures, lastQueryErr)
			}
			return fmt.Errorf("the delete task for %s did not finish within %s (taskId=%s); keeping it on the reclaim list to retry",
				certID, deleteTaskTimeout, taskID)
		}
		if err := waitBetweenPolls(ctx, pollWait(deleteTaskPoll, throttled)); err != nil {
			return err
		}
	}
}

// isCertificateNotFound reports whether err is the SSL service saying the certificate does
// not exist.
//
// The SDK documents FailedOperation.CertificateNotFound for DeleteCertificate, and that is
// the whole family: there is no bare FailedOperation.NotFound in this API's error list. The
// substring fallback covers an error that was already flattened to text somewhere above, the
// same convention tcerr's classifiers use.
func isCertificateNotFound(err error) bool {
	if err == nil {
		return false
	}
	return tcerr.Code(err) == "FailedOperation.CertificateNotFound" ||
		strings.Contains(err.Error(), "FailedOperation.CertificateNotFound")
}

func deleteTaskStatus(
	resp *ssl.DescribeDeleteCertificatesTaskResultResponse, taskID string,
) (status uint64, detail string, found bool, err error) {
	if resp == nil || resp.Response == nil {
		return 0, "", false, nil
	}
	for _, r := range resp.Response.DeleteTaskResult {
		if r == nil || r.TaskId == nil || *r.TaskId != taskID {
			continue
		}
		if r.Status == nil {
			return 0, "", false, nil
		}
		d := ""
		if r.Error != nil && *r.Error != "" {
			d = ": " + *r.Error
		}
		return *r.Status, d, true, nil
	}
	return 0, "", false, nil
}
