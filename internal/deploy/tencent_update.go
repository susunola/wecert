package deploy

import (
	"context"
	"fmt"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

func (d *TencentCLB) updateInstance(ctx context.Context, client sslAPI, oldID, newID string) error {
	req := ssl.NewUpdateCertificateInstanceRequest()
	req.OldCertificateId = common.StringPtr(oldID)
	req.CertificateId = common.StringPtr(newID)
	req.ResourceTypes = toPtrSlice(d.types)
	req.ResourceTypesRegions = d.resourceTypeRegions()
	req.ExpiringNotificationSwitch = common.Uint64Ptr(1)

	deadline := d.now().Add(2 * time.Minute)
	var recordID uint64
	for {
		resp, err := client.UpdateCertificateInstanceWithContext(ctx, req)
		if err != nil {
			return sdkCallError(ctx, "UpdateCertificateInstance", err)
		}
		if resp.Response != nil && resp.Response.DeployRecordId != nil && *resp.Response.DeployRecordId > 0 {
			recordID = *resp.Response.DeployRecordId
			progress := resp.Response.UpdateSyncProgress
			bound, progressReady := progressBoundCount(progress)

			if resp.Response.DeployStatus != nil && *resp.Response.DeployStatus == 0 {
				verifyStart := d.now()
				d.log.Warn("another update task is already in progress; waiting for it and then "+
					"verifying that this certificate is the one that got bound",
					"oldCertId", oldID, "newCertId", newID, "deployRecordId", recordID)
				if werr := d.waitDeployRecord(ctx, client, recordID, oldID); werr != nil {
					return werr
				}
				n, berr := d.bindingsWith(ctx, client, newID, false)
				if berr != nil {
					return fmt.Errorf("%w: the in-progress update task finished, but enumerating the bindings of %s failed: %v", ErrSwitchUnverified, newID, berr)
				}
				if n.count == 0 && !n.complete {
					return fmt.Errorf("%w: an update task was already in progress and finished, but the bind-resource enumeration for %s did not cover every region", ErrSwitchUnverified, newID)
				}
				if n.count == 0 {
					return fmt.Errorf("an update task was already in progress, and this certificate (%s) is not bound to any resource afterwards; the task belonged to a different switch, so this deploy did not happen", newID)
				}
				d.log.Info("verified the adopted update task",
					"oldCertId", oldID, "newCertId", newID, "deployRecordId", recordID,
					"boundResources", n.count, "took", d.now().Sub(verifyStart).Round(time.Second))
				return nil
			}

			d.log.Info("one-click update task created",
				"oldCertId", oldID, "newCertId", newID,
				"deployRecordId", recordID,
				"boundResources", bound,
				"progress", formatProgress(progress))

			if bound == 0 && progressReady {
				return noResourceBoundError(oldID, d.regions)
			}
			if bound == 0 && !progressReady {
				d.log.Warn("the sync progress carries no per-region count yet; "+
					"deferring to the async deploy record to decide whether anything was bound",
					"oldCertId", oldID, "newCertId", newID, "deployRecordId", recordID)
			}
			return d.waitDeployRecord(ctx, client, recordID, oldID)
		}
		if d.now().After(deadline) {
			return fmt.Errorf("the UpdateCertificateInstance task was not created within 2m (there may be one already running)")
		}
		if err := waitBetweenPolls(ctx, 3*time.Second); err != nil {
			return err
		}
	}
}
