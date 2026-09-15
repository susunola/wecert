package deploy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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
	// 上传证书的请求体可能几百 KB，默认超时不够用。
	cpf.HttpProfile.ReqTimeout = 60

	// SSL 证书服务是全局的，Region 传空。
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

	// 首次签发：腾讯云侧还没有"旧证书 → 云资源"的绑定关系可查，
	// 只能上传后由人工在 CLB 控制台绑定一次。之后每次续期都是全自动的。
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
	// 允许重复上传相同指纹的证书：否则重试一次上传就会直接失败。
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

// updateInstance 调 UpdateCertificateInstance 做一键更新。
//
// 这个 API 是异步的，而且有个不太直观的约定：DeployRecordId == 0
// 表示任务还在创建中，必须重复请求直到它 > 0 才算创建成功。
// DeployStatus == 0 则表示"已有一个进行中的任务"，这天然就是幂等的。
func (d *TencentCLB) updateInstance(ctx context.Context, client *ssl.Client, oldID, newID string) error {
	req := ssl.NewUpdateCertificateInstanceRequest()
	req.OldCertificateId = common.StringPtr(oldID)
	req.CertificateId = common.StringPtr(newID)
	req.ResourceTypes = toPtrSlice(d.types)
	req.ResourceTypesRegions = d.resourceTypeRegions()
	// 1 = 忽略旧证书的到期提醒。不加这条，续期成功后旧证书还会一直发到期告警。
	req.ExpiringNotificationSwitch = common.Uint64Ptr(1)

	deadline := d.now().Add(2 * time.Minute)
	for {
		resp, err := client.UpdateCertificateInstanceWithContext(ctx, req)
		if err != nil {
			return fmt.Errorf("UpdateCertificateInstance: %w", err)
		}
		if resp.Response != nil && resp.Response.DeployRecordId != nil && *resp.Response.DeployRecordId > 0 {
			// 把服务端报的进度原样打出来。
			// TotalCount 就是"这张旧证书实际绑了几个资源"——
			// 它是判断一键更新到底有没有生效的唯一权威依据，
			// 因为 CLB 的 DescribeListeners 并不回读证书绑定。
			d.log.Info("一键更新任务已创建",
				"oldCertId", oldID, "newCertId", newID,
				"deployRecordId", *resp.Response.DeployRecordId,
				"progress", formatProgress(resp.Response.UpdateSyncProgress))
			return nil
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

// resourceTypeRegions 按资源类型展开地域列表。
// CLB 等资源是分地域的，不传地域会一个实例都更新不到。
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

// Delete 删除一张已退役的证书。
//
// 这一步不是可选的：腾讯云账号下上传证书数量有配额，
// 长期运行的自动化如果不回收旧证书，早晚会撞上配额而无法续期。
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
	// 我们自己在状态库里管绑定关系，不需要服务端再检查一遍关联资源。
	req.IsCheckResource = common.BoolPtr(false)

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

// formatProgress 把 UpdateCertificateInstance 的进度摘要成一行。
// TotalCount 为 0 意味着"没找到任何绑定了旧证书的资源"，
// 也就是说证书其实没绑上 —— 这是最容易被忽略的失败形态。
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
