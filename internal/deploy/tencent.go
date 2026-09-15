package deploy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"

	"github.com/atom/wecert/internal/config"
)

// TencentCLB 通过腾讯云 SSL 证书服务把证书一键更新到绑定的 CLB 资源上。
type TencentCLB struct {
	credential CredentialFunc
	regions    []string
	types      []string
	log        *slog.Logger
	now        func() time.Time
}

// NewTencentCLB 构造部署器。
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

func (d *TencentCLB) client(ctx context.Context) (*ssl.Client, error) {
	cred, err := d.credential(ctx)
	if err != nil {
		return nil, err
	}

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ssl.tencentcloudapi.com"
	cpf.HttpProfile.ReqTimeout = 60
	return ssl.NewClient(cred, "", cpf)
}

// Deploy 上传新证书，并在存在旧证书时一键更新所有绑定了旧证书的云资源。
func (d *TencentCLB) Deploy(ctx context.Context, certName, oldID string, certPEM, keyPEM []byte) (string, error) {
	client, err := d.client(ctx)
	if err != nil {
		return "", err
	}

	newID, err := d.upload(ctx, client, certName, certPEM, keyPEM)
	if err != nil {
		return "", err
	}

	if oldID == "" {
		return newID, nil
	}

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
	req.Repeatable = common.BoolPtr(true)

	resp, err := client.UploadCertificateWithContext(ctx, req)
	if err != nil {
		return "", fmt.Errorf("UploadCertificate: %w", err)
	}
	if resp.Response == nil || resp.Response.CertificateId == nil || *resp.Response.CertificateId == "" {
		return "", errors.New("UploadCertificate 未返回 CertificateId")
	}
	return *resp.Response.CertificateId, nil
}

func (d *TencentCLB) updateInstance(ctx context.Context, client *ssl.Client, oldID, newID string) error {
	req := ssl.NewUpdateCertificateInstanceRequest()
	req.OldCertificateId = common.StringPtr(oldID)
	req.CertificateId = common.StringPtr(newID)
	req.ResourceTypes = toPtrSlice(d.types)
	req.ResourceTypesRegions = d.resourceTypeRegions()
	req.ExpiringNotificationSwitch = common.Uint64Ptr(1)

	deadline := d.now().Add(2 * time.Minute)
	var recordID int64
	for {
		resp, err := client.UpdateCertificateInstanceWithContext(ctx, req)
		if err != nil {
			return fmt.Errorf("UpdateCertificateInstance: %w", err)
		}
		if resp.Response != nil && resp.Response.DeployRecordId != nil && *resp.Response.DeployRecordId > 0 {
			recordID = *resp.Response.DeployRecordId
			bound := progressBoundCount(resp.Response.UpdateSyncProgress)
			d.log.Info("一键更新任务已创建",
				"oldCertId", oldID, "newCertId", newID,
				"deployRecordId", recordID,
				"boundResources", bound,
				"progress", formatProgress(resp.Response.UpdateSyncProgress))
			if bound == 0 {
				return fmt.Errorf("UpdateCertificateInstance 未找到任何绑定了旧证书 %s 的资源（regions=%v）；拒绝把新证书标为已部署。请确认 CLB 监听器已绑定该证书（SNI 监听器必须走 multi_cert_info，主 certificate_id 会被静默忽略）",
					oldID, d.regions)
			}
			return d.waitDeployRecord(ctx, client, recordID)
		}
		if d.now().After(deadline) {
			return fmt.Errorf("UpdateCertificateInstance 任务在 2m 内未创建成功（可能一直有进行中的任务）")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

func (d *TencentCLB) waitDeployRecord(ctx context.Context, client *ssl.Client, recordID int64) error {
	deadline := d.now().Add(3 * time.Minute)
	for {
		success, failed, running, err := d.describeDeployRecord(ctx, client, recordID)
		if err != nil {
			d.log.Warn("查询部署记录失败，稍后重试", "deployRecordId", recordID, "err", err)
		} else {
			d.log.Info("一键更新进度",
				"deployRecordId", recordID,
				"success", success, "failed", failed, "running", running)
			if running == 0 && (success+failed) > 0 {
				if failed > 0 {
					return fmt.Errorf("一键更新完成但有 %d 个资源失败（成功 %d）", failed, success)
				}
				return nil
			}
		}
		if d.now().After(deadline) {
			return fmt.Errorf("一键更新任务 %d 在 3m 内未完成（success=%d failed=%d running=%d）",
				recordID, success, failed, running)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func (d *TencentCLB) describeDeployRecord(ctx context.Context, client *ssl.Client, recordID int64) (success, failed, running int64, err error) {
	req := ssl.NewDescribeHostUpdateRecordDetailRequest()
	req.DeployRecordId = common.StringPtr(strconv.FormatInt(recordID, 10))
	resp, err := client.DescribeHostUpdateRecordDetailWithContext(ctx, req)
	if err != nil {
		return 0, 0, 0, err
	}
	if resp.Response == nil {
		return 0, 0, 0, errors.New("DescribeHostUpdateRecordDetail 空响应")
	}
	return derefI64(resp.Response.SuccessTotalCount),
		derefI64(resp.Response.FailedTotalCount),
		derefI64(resp.Response.RunningTotalCount),
		nil
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

func progressBoundCount(progress []*ssl.UpdateSyncProgress) int64 {
	var n int64
	for _, p := range progress {
		for _, r := range p.UpdateSyncProgressRegions {
			n += derefI64(r.TotalCount)
		}
	}
	return n
}

func formatProgress(progress []*ssl.UpdateSyncProgress) string {
	if len(progress) == 0 {
		return "(服务端未返回进度)"
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
		return fmt.Sprintf("(资源类型 %d 个，但无地域明细)", len(progress))
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
