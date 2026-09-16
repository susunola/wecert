package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"

	"github.com/susunola/wecert/internal/config"
)

// cvmMetadataURL is the address for reading CAM role temporary credentials from the CVM
// instance metadata service.
// Using a role instead of writing SecretId/SecretKey into the config file keeps the
// secrets off disk.
// It is a variable rather than a constant so tests can point it at an httptest server;
// production code never reassigns it.
var cvmMetadataURL = "http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/"

// CredentialFunc fetches a fresh credential every time.
// The lack of caching is deliberate: temporary credentials expire, and deployment only
// happens once every few dozen days.
type CredentialFunc func(ctx context.Context) (common.CredentialIface, error)

// NewCredentialSource returns a credential source according to config.
// Certificate deployment and DNS-01 with dns.provider=tencentcloud share the same
// credentials.
func NewCredentialSource(cfg config.Tencent) (CredentialFunc, error) {
	switch cfg.CredentialMode {
	case config.CredentialStatic:
		// Prefer values from the config, then fall back to Tencent Cloud's official
		// environment variables. The point of the environment is that the credentials
		// need not land in the config file, so that file can be committed and backed up
		// freely.
		//
		// It does *not* follow that they may go in the systemd unit: install.sh writes
		// the units 0644 root:root, so an inline Environment= line would make a
		// long-lived CAM key world-readable. Put them in an EnvironmentFile that is
		// 0600 root:wecert instead.
		id, key := cfg.SecretID, cfg.SecretKey
		if id == "" {
			id = os.Getenv(EnvSecretID)
		}
		if key == "" {
			key = os.Getenv(EnvSecretKey)
		}
		if id == "" || key == "" {
			return nil, fmt.Errorf(
				"credentialMode=static but no credentials: put secretId/secretKey in the config, "+
					"or set the environment variables %s / %s", EnvSecretID, EnvSecretKey)
		}
		cred := common.NewCredential(id, key)
		return func(context.Context) (common.CredentialIface, error) { return cred, nil }, nil

	case config.CredentialCVMRole:
		return func(ctx context.Context) (common.CredentialIface, error) {
			return fetchCVMRoleCredential(ctx, cfg.RoleName)
		}, nil

	default:
		return nil, fmt.Errorf("unknown credential mode %q", cfg.CredentialMode)
	}
}

// Environment variable names as agreed by the Tencent Cloud SDK.
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

// fetchCVMRoleCredential fetches a fresh temporary credential on every deploy.
//
// The lack of caching is deliberate: temporary credentials usually expire in 2 hours
// while a deploy happens only once every 45-90 days, so caching one buys nothing but the
// hardest kind of failure to diagnose -- "it turned out to be expired right when we
// finally needed it".
func fetchCVMRoleCredential(ctx context.Context, roleName string) (common.CredentialIface, error) {
	if roleName == "" {
		return nil, fmt.Errorf("credentialMode=cvm-role requires tencent.roleName")
	}
	// Escaped, not concatenated raw: the role name comes from the config, and an
	// unescaped "../" would let it reach other metadata paths.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cvmMetadataURL+url.PathEscape(roleName), nil)
	if err != nil {
		return nil, fmt.Errorf("build metadata request: %w", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reach the CVM metadata service: %w (if not running on a CVM, set tencent.credentialMode to static)", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("read the metadata response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// The body *is* included, bounded: on a 404 it is the only thing that says
		// "the role is not attached" rather than just "404", and that is the difference
		// between an actionable error and a round of guessing. It is safe to bound here
		// because state.PutCert also caps last_error at 512 bytes, which is where this
		// string ends up.
		return nil, fmt.Errorf("the metadata service returned %d; check that this CVM has role %q attached (response: %s)",
			resp.StatusCode, roleName, truncate(string(body), 256))
	}

	var mc cvmRoleCredential
	if err := json.Unmarshal(body, &mc); err != nil {
		return nil, fmt.Errorf("parse the metadata credentials: %w", err)
	}
	if mc.TmpSecretID == "" || mc.TmpSecretKey == "" {
		return nil, fmt.Errorf("the metadata service returned no usable credentials (Code=%q)", mc.Code)
	}

	return common.NewTokenCredential(mc.TmpSecretID, mc.TmpSecretKey, mc.Token), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
