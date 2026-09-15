package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"

	"github.com/susunola/wecert/internal/config"
)

// cvmMetadataURL 是 CVM 实例元数据服务里读取 CAM 角色临时凭证的地址。
// 用角色而不是把 SecretId/SecretKey 写进配置文件，是为了让密钥不落盘。
const cvmMetadataURL = "http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/"

// CredentialFunc 每次都重新获取一份凭证。
// 不缓存是有意的：临时凭证会过期，而部署动作几十天才发生一次。
type CredentialFunc func(ctx context.Context) (common.CredentialIface, error)

// NewCredentialSource 按配置返回一个凭证来源。
// 证书部署和 dns.provider=tencentcloud 的 DNS-01 共用同一套凭证。
func NewCredentialSource(cfg config.Tencent) (CredentialFunc, error) {
	switch cfg.CredentialMode {
	case config.CredentialStatic:
		// 优先用配置里的值，其次回退到腾讯云官方约定的环境变量。
		// 走环境变量的意义在于：凭证不必落进配置文件，
		// 配置文件和 systemd unit 就可以放心提交、放心备份。
		id, key := cfg.SecretID, cfg.SecretKey
		if id == "" {
			id = os.Getenv(EnvSecretID)
		}
		if key == "" {
			key = os.Getenv(EnvSecretKey)
		}
		if id == "" || key == "" {
			return nil, fmt.Errorf(
				"credentialMode=static 但缺少凭证：请在配置里填 secretId/secretKey，"+
					"或设置环境变量 %s / %s", EnvSecretID, EnvSecretKey)
		}
		cred := common.NewCredential(id, key)
		return func(context.Context) (common.CredentialIface, error) { return cred, nil }, nil

	case config.CredentialCVMRole:
		return func(ctx context.Context) (common.CredentialIface, error) {
			return fetchCVMRoleCredential(ctx, cfg.RoleName)
		}, nil

	default:
		return nil, fmt.Errorf("未知的凭证模式 %q", cfg.CredentialMode)
	}
}

// 腾讯云 SDK 约定的环境变量名。
const (
	EnvSecretID  = "TENCENTCLOUD_SECRET_ID"
	EnvSecretKey = "TENCENTCLOUD_SECRET_KEY"
)

type cvmRoleCredential struct {
	TmpSecretID  string `json:"TmpSecretId"`
	TmpSecretKey string `json:"TmpSecretKey"`
	Token        string `json:"Token"`
	ExpiredTime  int64  `json:"ExpiredTime"`
	Code         string `json:"Code"`
}

// fetchCVMRoleCredential 每次部署都重新取一次临时凭证。
//
// 不做缓存是有意的：临时凭证通常 2 小时过期，而部署动作 45~90 天才发生一次，
// 缓存它只会换来"等真要用的时候才发现已经过期"这种最难排查的故障。
func fetchCVMRoleCredential(ctx context.Context, roleName string) (common.CredentialIface, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cvmMetadataURL+roleName, nil)
	if err != nil {
		return nil, fmt.Errorf("构造元数据请求: %w", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("访问 CVM 元数据服务: %w（若不在 CVM 上运行，请把 tencent.credentialMode 改为 static）", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("读取元数据响应: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("元数据服务返回 %d；请确认该 CVM 已绑定角色 %q（响应: %s）",
			resp.StatusCode, roleName, truncate(string(body), 256))
	}

	var mc cvmRoleCredential
	if err := json.Unmarshal(body, &mc); err != nil {
		return nil, fmt.Errorf("解析元数据凭证: %w", err)
	}
	if mc.TmpSecretID == "" || mc.TmpSecretKey == "" {
		return nil, fmt.Errorf("元数据服务未返回有效凭证 (Code=%q)", mc.Code)
	}

	return common.NewTokenCredential(mc.TmpSecretID, mc.TmpSecretKey, mc.Token), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
