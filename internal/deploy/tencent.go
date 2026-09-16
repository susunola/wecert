package deploy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"

	"github.com/susunola/wecert/internal/config"
)

// TencentCLB uses the Tencent Cloud SSL certificate service to one-click update a
// certificate onto its bound CLB resources.
type TencentCLB struct {
	credential CredentialFunc
	regions    []string
	types      []string
	log        *slog.Logger
	now        func() time.Time
}

// LazyTencentCLB creates the Tencent Cloud deployer only when an operation
// actually needs it. Desired-state documents can enable deployment after the
// process has started, while a document that keeps every certificate local
// should not require otherwise-unused static credentials at startup.
type LazyTencentCLB struct {
	cfg config.Tencent
	log *slog.Logger

	mu    sync.Mutex
	inner *TencentCLB
}

// NewLazyTencentCLB returns a deployer that defers credential validation and
// client construction until Deploy, Delete, or Bindings is first needed.
func NewLazyTencentCLB(cfg config.Tencent, log *slog.Logger) *LazyTencentCLB {
	return &LazyTencentCLB{cfg: cfg, log: log}
}

func (d *LazyTencentCLB) client() (*TencentCLB, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.inner != nil {
		return d.inner, nil
	}
	inner, err := NewTencentCLB(d.cfg, d.log)
	if err != nil {
		return nil, err
	}
	d.inner = inner
	return inner, nil
}

// Deploy implements Deployer.
func (d *LazyTencentCLB) Deploy(ctx context.Context, certName, oldID string, certPEM, keyPEM []byte) (string, error) {
	inner, err := d.client()
	if err != nil {
		return "", err
	}
	return inner.Deploy(ctx, certName, oldID, certPEM, keyPEM)
}

// Delete implements Deployer.
func (d *LazyTencentCLB) Delete(ctx context.Context, certID string) error {
	if certID == "" {
		return nil
	}
	inner, err := d.client()
	if err != nil {
		return err
	}
	return inner.Delete(ctx, certID)
}

// Bindings implements Deployer.
func (d *LazyTencentCLB) Bindings(ctx context.Context, certID string) (int, error) {
	if certID == "" {
		return 0, nil
	}
	inner, err := d.client()
	if err != nil {
		return 0, err
	}
	return inner.Bindings(ctx, certID)
}

// NewTencentCLB constructs the deployer.
func NewTencentCLB(cfg config.Tencent, log *slog.Logger) (*TencentCLB, error) {
	src, err := NewCredentialSource(cfg)
	if err != nil {
		return nil, err
	}
	return &TencentCLB{
		credential: src,
		regions:    cfg.Regions,
		types:      cfg.ResourceTypes,
		log:        log,
		now:        time.Now,
	}, nil
}

// client builds a client for the SSL certificate service.
func (d *TencentCLB) client(ctx context.Context) (*ssl.Client, error) {
	cred, err := d.credential(ctx)
	if err != nil {
		return nil, err
	}

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ssl.tencentcloudapi.com"
	// The upload request body can be hundreds of KB, so the default timeout is not enough.
	cpf.HttpProfile.ReqTimeout = 60

	// The SSL certificate service is global, so pass an empty Region.
	return ssl.NewClient(cred, "", cpf)
}

// Deploy uploads the new certificate and, when an old one exists, one-click updates every
// cloud resource bound to it.
func (d *TencentCLB) Deploy(ctx context.Context, certName, oldID string, certPEM, keyPEM []byte) (string, error) {
	client, err := d.client(ctx)
	if err != nil {
		return "", err
	}

	newID, err := d.upload(ctx, client, certName, certPEM, keyPEM)
	if err != nil {
		return "", err
	}

	// First issuance: there is no "old certificate -> cloud resource" binding on the Tencent
	// Cloud side to look up, so after upload a human has to bind it once in the CLB console.
	// Every renewal after that is fully automatic.
	if oldID == "" {
		return newID, nil
	}

	// Note: on error, still hand back the newID that was already uploaded successfully.
	// The caller must record it in the reclamation list, otherwise this certificate becomes a
	// cloud orphan that occupies the account's uploaded-certificate quota forever.
	if err := d.updateInstance(ctx, client, oldID, newID); err != nil {
		return newID, err
	}
	return newID, nil
}

func (d *TencentCLB) upload(ctx context.Context, client *ssl.Client, certName string, certPEM, keyPEM []byte) (string, error) {
	req := ssl.NewUploadCertificateRequest()
	req.CertificatePublicKey = common.StringPtr(string(certPEM))
	req.CertificatePrivateKey = common.StringPtr(string(keyPEM))
	req.CertificateType = common.StringPtr("SVR")
	req.Alias = common.StringPtr("wecert/" + certName)
	// Allow re-uploading a certificate with the same fingerprint: otherwise a single upload
	// retry fails outright.
	req.Repeatable = common.BoolPtr(true)

	resp, err := client.UploadCertificateWithContext(ctx, req)
	if err != nil {
		return "", fmt.Errorf("UploadCertificate: %w", err)
	}
	if resp.Response == nil || resp.Response.CertificateId == nil || *resp.Response.CertificateId == "" {
		return "", errors.New("UploadCertificate returned no CertificateId")
	}
	return *resp.Response.CertificateId, nil
}

// updateInstance calls UpdateCertificateInstance to do the one-click update.
//
// The API is asynchronous and has a rather unintuitive convention: DeployRecordId == 0
// means the task is still being created, so the request must be repeated until it is > 0
// before creation counts as successful.
// DeployStatus == 0 means "a task is already in progress", which is naturally idempotent.
func (d *TencentCLB) updateInstance(ctx context.Context, client *ssl.Client, oldID, newID string) error {
	req := ssl.NewUpdateCertificateInstanceRequest()
	req.OldCertificateId = common.StringPtr(oldID)
	req.CertificateId = common.StringPtr(newID)
	req.ResourceTypes = toPtrSlice(d.types)
	req.ResourceTypesRegions = d.resourceTypeRegions()
	// 1 = ignore the old certificate's expiry reminder. Without this, the old certificate
	// keeps firing expiry alerts even after a successful renewal.
	req.ExpiringNotificationSwitch = common.Uint64Ptr(1)

	deadline := d.now().Add(2 * time.Minute)
	// Mind the type: DeployRecordId in the UpdateCertificateInstance response is *uint64
	// (the SDK has several same-named fields elsewhere that are *int64 -- do not copy that).
	var recordID uint64
	for {
		resp, err := client.UpdateCertificateInstanceWithContext(ctx, req)
		if err != nil {
			return fmt.Errorf("UpdateCertificateInstance: %w", err)
		}
		if resp.Response != nil && resp.Response.DeployRecordId != nil && *resp.Response.DeployRecordId > 0 {
			recordID = *resp.Response.DeployRecordId
			// Log the server-reported progress verbatim.
			// bound is "how many resources this old certificate is actually bound to" --
			// the only authoritative basis for judging whether the one-click update took
			// effect, since CLB's DescribeListeners does not read certificate bindings back.
			bound := progressBoundCount(resp.Response.UpdateSyncProgress)
			d.log.Info("one-click update task created",
				"oldCertId", oldID, "newCertId", newID,
				"deployRecordId", recordID,
				"boundResources", bound,
				"progress", formatProgress(resp.Response.UpdateSyncProgress))
			if bound == 0 {
				return fmt.Errorf("UpdateCertificateInstance found no resource bound to the old certificate %s (regions=%v); refusing to mark the new certificate as deployed. Check that the CLB listener has it bound (an SNI listener must use multi_cert_info; the primary certificate_id is silently ignored)",
					oldID, d.regions)
			}
			return d.waitDeployRecord(ctx, client, recordID)
		}
		if d.now().After(deadline) {
			return fmt.Errorf("the UpdateCertificateInstance task was not created within 2m (there may be one already running)")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

// waitDeployRecord waits for the one-click update task to actually finish.
//
// UpdateCertificateInstance returning only means the task was created; the rebinding
// happens asynchronously in the background. Setting DeployConfirmed without waiting for it
// to finish writes the most insidious failure mode -- "the program thinks it succeeded
// while nothing actually took effect" -- into the state database.
func (d *TencentCLB) waitDeployRecord(ctx context.Context, client *ssl.Client, recordID uint64) error {
	deadline := d.now().Add(3 * time.Minute)
	for {
		success, failed, running, err := d.describeDeployRecord(ctx, client, recordID)
		if err != nil {
			d.log.Warn("failed to query the deploy record; retrying shortly", "deployRecordId", recordID, "err", err)
		} else {
			d.log.Info("one-click update progress",
				"deployRecordId", recordID,
				"success", success, "failed", failed, "running", running)
			if running == 0 && (success+failed) > 0 {
				if failed > 0 {
					return fmt.Errorf("one-click update finished with %d resources failed (%d succeeded)", failed, success)
				}
				return nil
			}
		}
		if d.now().After(deadline) {
			return fmt.Errorf("one-click update task %d did not finish within 3m (success=%d failed=%d running=%d)",
				recordID, success, failed, running)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// describeDeployRecord queries the resource-level detail of a deploy record once.
func (d *TencentCLB) describeDeployRecord(ctx context.Context, client *ssl.Client, recordID uint64) (success, failed, running int64, err error) {
	req := ssl.NewDescribeHostUpdateRecordDetailRequest()
	req.DeployRecordId = common.StringPtr(strconv.FormatUint(recordID, 10))
	resp, err := client.DescribeHostUpdateRecordDetailWithContext(ctx, req)
	if err != nil {
		return 0, 0, 0, err
	}
	if resp.Response == nil {
		return 0, 0, 0, errors.New("DescribeHostUpdateRecordDetail returned an empty response")
	}
	return derefI64(resp.Response.SuccessTotalCount),
		derefI64(resp.Response.FailedTotalCount),
		derefI64(resp.Response.RunningTotalCount),
		nil
}

// resourceTypeRegions expands the region list per resource type.
// Resources such as CLB are regional, so omitting regions means not one instance gets
// updated.
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

// Delete removes a retired certificate.
//
// This step is not optional: Tencent Cloud accounts have a quota on uploaded certificates,
// and long-running automation that never reclaims old certificates will eventually hit the
// quota and be unable to renew.
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
	// true = have the server still check associated resources: refuse the delete as long as
	// any cloud resource still references this certificate.
	// This is more conservative than "we track bindings ourselves and skip the check" -- the
	// cost of a failed delete is a held quota slot, while the cost of a mistaken delete is
	// production HTTPS going down. The two are not equivalent.
	// When the delete fails, ReapRetired logs a warning and retries next round.
	req.IsCheckResource = common.BoolPtr(true)

	if _, err := client.DeleteCertificateWithContext(ctx, req); err != nil {
		return fmt.Errorf("DeleteCertificate(%s): %w", certID, err)
	}
	return nil
}

func toPtrSlice(in []string) []*string {
	out := make([]*string, 0, len(in))
	for _, s := range in {
		out = append(out, common.StringPtr(s))
	}
	return out
}

// progressBoundCount counts how many resources this one-click update covers in total.
// Zero means "no resource bound to the old certificate was found", i.e. the certificate was
// never actually bound -- the failure mode most easily overlooked.
func progressBoundCount(progress []*ssl.UpdateSyncProgress) int64 {
	var n int64
	for _, p := range progress {
		for _, r := range p.UpdateSyncProgressRegions {
			n += derefI64(r.TotalCount)
		}
	}
	return n
}

// formatProgress summarizes UpdateCertificateInstance progress into a single line.
func formatProgress(progress []*ssl.UpdateSyncProgress) string {
	if len(progress) == 0 {
		return "(the server returned no progress detail)"
	}
	var parts []string
	for _, p := range progress {
		for _, r := range p.UpdateSyncProgressRegions {
			parts = append(parts,
				fmt.Sprintf("%s/%s total=%d status=%d",
					derefStr(p.ResourceType), derefStr(r.Region), derefI64(r.TotalCount), derefI64(r.Status)))
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("(%d resource types, but no per-region detail)", len(progress))
	}
	return strings.Join(parts, "; ")
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefI64(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

// Bindings queries how many cloud resources this certificate is currently bound to.
//
// This is read-only: CreateCertificateBindResourceSyncTask creates an enumeration task and
// the result is then fetched by TaskId. Deliberately not using UpdateCertificateInstance to
// "probe" the state, because that is a write operation and confirming a binding must not
// produce side effects.
//
// Why it is needed: first issuance only uploads and does not bind, so DeployConfirmed is
// false. After a human binds it in the console there used to be no path back to set it --
// the deployed metric would report "not deployed" for the whole certificate cycle (up to 90
// days for classic) even though the certificate was serving traffic the entire time.
func (d *TencentCLB) Bindings(ctx context.Context, certID string) (int, error) {
	if certID == "" {
		return 0, nil
	}

	client, err := d.client(ctx)
	if err != nil {
		return 0, err
	}

	createReq := ssl.NewCreateCertificateBindResourceSyncTaskRequest()
	createReq.CertificateIds = []*string{common.StringPtr(certID)}
	// IsCache=1: allow reusing the server-side cache, avoiding a full enumeration on every
	// reconcile.
	createReq.IsCache = common.Uint64Ptr(1)

	createResp, err := client.CreateCertificateBindResourceSyncTaskWithContext(ctx, createReq)
	if err != nil {
		return 0, fmt.Errorf("CreateCertificateBindResourceSyncTask: %w", err)
	}
	if createResp.Response == nil || len(createResp.Response.CertTaskIds) == 0 {
		return 0, nil
	}

	var taskID string
	for _, t := range createResp.Response.CertTaskIds {
		if t != nil && t.CertId != nil && *t.CertId == certID && t.TaskId != nil {
			taskID = *t.TaskId
			break
		}
	}
	if taskID == "" {
		return 0, nil
	}

	// Enumeration is asynchronous, so poll until there is a result. Keep the ceiling short:
	// this is only a confirmation action and not worth blocking reconciliation on for long.
	deadline := d.now().Add(30 * time.Second)
	for {
		queryReq := ssl.NewDescribeCertificateBindResourceTaskResultRequest()
		queryReq.TaskIds = []*string{common.StringPtr(taskID)}

		queryResp, err := client.DescribeCertificateBindResourceTaskResultWithContext(ctx, queryReq)
		if err != nil {
			return 0, fmt.Errorf("DescribeCertificateBindResourceTaskResult: %w", err)
		}

		n, done, err := countBindings(queryResp, taskID)
		if err != nil {
			return 0, err
		}
		if done {
			return n, nil
		}

		if d.now().After(deadline) {
			return 0, fmt.Errorf("the bind-resource enumeration did not finish within 30s (taskId=%s)", taskID)
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// bindStatusDone is the Status value when the enumeration task has completed.
//
// This value has no public documentation; it was determined empirically (see the
// countBindings comment below).
const bindStatusDone = 1

// countBindings counts the total number of bound resources out of the query result.
//
// A return value of done=false means the task has no result yet and the caller should keep
// waiting.
//
// On the meaning of Status: **empirically, Status == 1 means success**.
// I first wrote "Status != 0 means not ready yet" on intuition, and the confirmation then
// never saw a result -- this field's meaning cannot be guessed, so the empirical finding is
// recorded here.
//
// BindResourceResult must also be required to be non-empty: the first query (before the
// server-side cache exists) returns an object whose TaskId matches but whose result list is
// empty. Checking only TaskId would conclude "0 bindings" at that instant and judge a
// perfectly well-bound certificate as unbound.
func countBindings(
	resp *ssl.DescribeCertificateBindResourceTaskResultResponse, taskID string,
) (count int, done bool, err error) {
	if resp == nil || resp.Response == nil {
		return 0, false, nil
	}

	for _, r := range resp.Response.SyncTaskBindResourceResult {
		if r == nil || r.TaskId == nil || *r.TaskId != taskID {
			continue
		}

		// Do not keep waiting idly when the server reports an explicit error.
		if r.Error != nil && r.Error.Message != nil && *r.Error.Message != "" {
			return 0, false, fmt.Errorf("bind-resource task %s failed: %s", taskID, *r.Error.Message)
		}

		// Either not finished yet, or finished but the result list is not populated yet --
		// keep waiting in both cases.
		if r.Status == nil || *r.Status != bindStatusDone || len(r.BindResourceResult) == 0 {
			return 0, false, nil
		}

		total := 0
		for _, res := range r.BindResourceResult {
			if res == nil {
				continue
			}
			for _, region := range res.BindResourceRegionResult {
				if region == nil || region.TotalCount == nil {
					continue
				}
				// A non-empty Error means this region's query failed and its result cannot be
				// trusted -- better to treat that as "not found yet" than to mark the
				// certificate as deployed based on it.
				if region.Error != nil && *region.Error != "" {
					continue
				}
				total += int(*region.TotalCount)
			}
		}
		return total, true, nil
	}

	return 0, false, nil
}
