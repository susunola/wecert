// Package config 定义 wecert 的声明式期望状态（spec）。
//
// 设计原则：YAML 里写的只是"我要什么"，不含任何运行时状态。
// 运行时状态（order URL、ARI 窗口、腾讯云 CertId 等）一律进 SQLite，
// 因为丢失它们会直接导致重复下单并撞上 Let's Encrypt 的速率限制。
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ACME profile 名。Max Names 上限随 profile 变化。
const (
	ProfileClassic    = "classic"
	ProfileTLSServer  = "tlsserver"
	ProfileShortLived = "shortlived"
)

// Let's Encrypt 目录 URL。
const (
	DirectoryStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
	DirectoryProduction = "https://acme-v02.api.letsencrypt.org/directory"
)

const (
	KeyTypeECDSAP256 = "ecdsa-p256"
	KeyTypeECDSAP384 = "ecdsa-p384"
	KeyTypeRSA2048   = "rsa2048"
	KeyTypeRSA4096   = "rsa4096"
)

const (
	CredentialStatic  = "static"
	CredentialCVMRole = "cvm-role"
)

// DNS-01 solver 的实现。两者的凭证体系完全不同，别搞混：
//
//   - dnspod       用 DNSPod 自有的 API Token（dnspod.cn 控制台 → 密钥管理），
//                  调 dnsapi.cn。它和腾讯云 CAM 的 SecretId/SecretKey 是两套东西。
//   - tencentcloud 用腾讯云 CAM 凭证（AK/SK 或 CVM 角色临时凭证），
//                  调 dnspod.tencentcloudapi.com。好处是能和证书部署共用同一套凭证，
//                  而且支持 SessionToken，可以走 role。
const (
	DNSProviderDNSPod       = "dnspod"
	DNSProviderTencentCloud = "tencentcloud"
)

// profileMaxNames 是各 profile 允许的最大 identifier 数量。
// classic 允许 100，但新的 tlsserver / shortlived 只有 25 —— 本地先拦，
// 免得把一个必然被 CA 拒绝的订单打出去（那会消耗 order 配额）。
var profileMaxNames = map[string]int{
	ProfileClassic:    100,
	ProfileTLSServer:  25,
	ProfileShortLived: 25,
}

// profileRenewBefore 是各 profile 的默认提前续期时长。
// 这只在 ARI 不可用时作为兜底；ARI 可用时以 suggestedWindow 为准。
var profileRenewBefore = map[string]time.Duration{
	ProfileClassic:    30 * 24 * time.Hour,
	ProfileTLSServer:  15 * 24 * time.Hour,
	ProfileShortLived: 48 * time.Hour,
}

// Config 是整份配置。
type Config struct {
	StatePath    string        `yaml:"statePath"`
	ACME         ACME          `yaml:"acme"`
	DNS          DNS           `yaml:"dns"`
	Tencent      Tencent       `yaml:"tencent"`
	Metrics      Metrics       `yaml:"metrics"`
	Certificates []Certificate `yaml:"certificates"`
}

// ACME 是 ACME 账号与目录配置。
type ACME struct {
	Directory string `yaml:"directory"`
	Email     string `yaml:"email"`
}

// DNS 是 DNS-01 solver 配置。
type DNS struct {
	Provider string `yaml:"provider"`

	// provider=dnspod 时必填。
	// 这是 DNSPod 自有的 API Token（形如 "12345,abcdef0123456789..."），
	// 不是腾讯云 CAM 的 SecretId/SecretKey。
	LoginToken string `yaml:"loginToken"`

	// TTL 是写入 _acme-challenge TXT 记录时用的值。
	//
	// 默认 600 而不是 60：DNSPod 免费套餐的 TTL 下限就是 600，
	// 写 60 会被 API 以 LimitExceeded.RecordTtlLimit 拒绝。
	// 付费套餐可以调低以加快传播和清理。
	TTL                int    `yaml:"ttl"`
	PropagationTimeout string `yaml:"propagationTimeout"`
	PollingInterval    string `yaml:"pollingInterval"`
	// 解析后的时长，由 normalize 填充。
	Propagation time.Duration `yaml:"-"`
	Polling     time.Duration `yaml:"-"`
}

// Tencent 是腾讯云凭证与部署目标配置。
type Tencent struct {
	CredentialMode string   `yaml:"credentialMode"`
	SecretID       string   `yaml:"secretId"`
	SecretKey      string   `yaml:"secretKey"`
	RoleName       string   `yaml:"roleName"`
	ResourceTypes  []string `yaml:"resourceTypes"`
	Regions        []string `yaml:"regions"`
}

// Metrics 是 Prometheus 暴露配置。
type Metrics struct {
	Listen string `yaml:"listen"`
}

// Certificate 是一张证书的期望状态。
type Certificate struct {
	Name        string   `yaml:"name"`
	Domains     []string `yaml:"domains"`
	Profile     string   `yaml:"profile"`
	KeyType     string   `yaml:"keyType"`
	RenewBefore string   `yaml:"renewBefore"`
	Deploy      Deploy   `yaml:"deploy"`

	// 解析后的时长，由 normalize 填充。
	RenewBeforeDur time.Duration `yaml:"-"`
}

// Deploy 描述签出来的证书要部署到哪里。
// 首次签发时腾讯云侧还没有绑定关系，需要人工绑一次；
// 之后每 90/45 天续期都由 UpdateCertificateInstance 自动换。
type Deploy struct {
	Enabled bool `yaml:"enabled"`
}

// MaxNames 返回该证书 profile 允许的最大域名数。
func (c *Certificate) MaxNames() int {
	if n, ok := profileMaxNames[c.Profile]; ok {
		return n
	}
	return 0
}

// Load 读取并校验配置文件。
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &Config{}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	// 未知字段直接报错，避免配置写错了却静默生效。
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) normalize() error {
	if c.StatePath == "" {
		return fmt.Errorf("statePath is required")
	}
	if c.ACME.Directory == "" {
		return fmt.Errorf("acme.directory is required")
	}
	if c.ACME.Email == "" {
		return fmt.Errorf("acme.email is required")
	}

	// DNS provider 必须显式选一个。默认 dnspod 会让人误以为
	// 腾讯云 AK/SK 就够了，然后在 DNS-01 阶段一头雾水地失败。
	switch c.DNS.Provider {
	case "":
		c.DNS.Provider = DNSProviderDNSPod
	case DNSProviderDNSPod, DNSProviderTencentCloud:
	default:
		return fmt.Errorf("dns.provider must be %q or %q, got %q",
			DNSProviderDNSPod, DNSProviderTencentCloud, c.DNS.Provider)
	}
	if c.DNS.Provider == DNSProviderDNSPod && c.DNS.LoginToken == "" {
		return fmt.Errorf("dns.provider=dnspod requires dns.loginToken " +
			"(DNSPod 自有 API Token，不是腾讯云 SecretId/SecretKey；" +
			"若想用腾讯云 CAM 凭证请设 dns.provider=tencentcloud)")
	}

	var err error
	if c.DNS.Propagation, err = parseDuration(c.DNS.PropagationTimeout, 5*time.Minute, "dns.propagationTimeout"); err != nil {
		return err
	}
	if c.DNS.Polling, err = parseDuration(c.DNS.PollingInterval, 5*time.Second, "dns.pollingInterval"); err != nil {
		return err
	}
	if c.DNS.TTL <= 0 {
		// 默认 600 而不是 60：DNSPod 免费套餐的 TTL 下限就是 600，
		// 写 60 会被 API 以 LimitExceeded.RecordTtlLimit 拒绝。
		// 付费套餐可以调低，但默认值必须对所有套餐都成立。
		c.DNS.TTL = 600
	}

	if c.Metrics.Listen == "" {
		c.Metrics.Listen = "127.0.0.1:9800"
	}

	switch c.Tencent.CredentialMode {
	case "":
		c.Tencent.CredentialMode = CredentialCVMRole
	case CredentialStatic, CredentialCVMRole:
	default:
		return fmt.Errorf("tencent.credentialMode must be %q or %q, got %q",
			CredentialStatic, CredentialCVMRole, c.Tencent.CredentialMode)
	}

	// credentialMode=static 时不再强制要求 secretId/secretKey 写在配置里：
	// 也允许走 TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY 环境变量，
	// 这样配置文件里就不必出现长期密钥。真正的校验在 deploy.NewCredentialSource。
	if c.Tencent.CredentialMode == CredentialCVMRole && c.Tencent.RoleName == "" {
		return fmt.Errorf("tencent.credentialMode=cvm-role requires roleName")
	}
	if len(c.Tencent.ResourceTypes) == 0 {
		c.Tencent.ResourceTypes = []string{"clb"}
	}
	if len(c.Tencent.Regions) == 0 {
		return fmt.Errorf("tencent.regions is required (CLB is regional; list every region you have CLBs in)")
	}

	if len(c.Certificates) == 0 {
		return fmt.Errorf("at least one certificate is required")
	}

	seen := map[string]bool{}
	for i := range c.Certificates {
		if err := c.Certificates[i].normalize(seen); err != nil {
			return err
		}
	}
	return nil
}

func (c *Certificate) normalize(seen map[string]bool) error {
	if c.Name == "" {
		return fmt.Errorf("certificates[].name is required")
	}
	if seen[c.Name] {
		return fmt.Errorf("certificate name %q is duplicated", c.Name)
	}
	seen[c.Name] = true

	if c.Profile == "" {
		c.Profile = ProfileClassic
	}
	maxNames, ok := profileMaxNames[c.Profile]
	if !ok {
		return fmt.Errorf("certificate %q: unknown profile %q (want %s/%s/%s)",
			c.Name, c.Profile, ProfileClassic, ProfileTLSServer, ProfileShortLived)
	}

	if c.KeyType == "" {
		c.KeyType = KeyTypeECDSAP256
	}
	switch c.KeyType {
	case KeyTypeECDSAP256, KeyTypeECDSAP384, KeyTypeRSA2048, KeyTypeRSA4096:
	default:
		return fmt.Errorf("certificate %q: unknown keyType %q", c.Name, c.KeyType)
	}

	if len(c.Domains) == 0 {
		return fmt.Errorf("certificate %q: domains is empty", c.Name)
	}
	if len(c.Domains) > maxNames {
		return fmt.Errorf(
			"certificate %q: %d domains exceeds the %s profile's max of %d identifiers; "+
				"split it into smaller certificates (and remember every name fails together)",
			c.Name, len(c.Domains), c.Profile, maxNames)
	}
	for _, d := range c.Domains {
		if err := validateDomain(d); err != nil {
			return fmt.Errorf("certificate %q: %w", c.Name, err)
		}
	}

	var err error
	c.RenewBeforeDur, err = parseDuration(c.RenewBefore, profileRenewBefore[c.Profile],
		fmt.Sprintf("certificate %q renewBefore", c.Name))
	if err != nil {
		return err
	}
	return nil
}

// validateDomain 挡住几种明知会被 CA 拒绝、或者覆盖范围容易被误解的写法。
func validateDomain(d string) error {
	if d == "" {
		return fmt.Errorf("empty domain")
	}
	if strings.HasSuffix(d, ".") {
		return fmt.Errorf("domain %q has a trailing dot", d)
	}
	if strings.Contains(d, "*") {
		// LE 只允许最左侧一个通配符标签。
		if !strings.HasPrefix(d, "*.") {
			return fmt.Errorf("domain %q: wildcard must be the leftmost label (e.g. *.example.com)", d)
		}
		if strings.Contains(d[2:], "*") {
			return fmt.Errorf("domain %q: *.*.example.com is not allowed by Let's Encrypt", d)
		}
	}
	return nil
}

func parseDuration(s string, def time.Duration, field string) (time.Duration, error) {
	if s == "" {
		if def == 0 {
			return 0, fmt.Errorf("%s is required", field)
		}
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", field, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive, got %s", field, s)
	}
	return d, nil
}
