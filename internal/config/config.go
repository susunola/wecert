// Package config 定义 wecert 的声明式期望状态（spec）。
//
// 设计原则：YAML 里写的只是"我要什么"，不含任何运行时状态。
// 运行时状态（order URL、ARI 窗口、腾讯云 CertId 等）一律进 SQLite，
// 因为丢失它们会直接导致重复下单并撞上 Let's Encrypt 的速率限制。
package config

import (
	"bytes"
	"fmt"
	"os"
	"sort"
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
// dnspod 用 DNSPod 自有的 API Token（dnspod.cn 控制台 → 密钥管理），调
// dnsapi.cn。它和腾讯云 CAM 的 SecretId/SecretKey 是两套东西。
//
// tencentcloud 用腾讯云 CAM 凭证（AK/SK 或 CVM 角色临时凭证），调
// dnspod.tencentcloudapi.com。好处是能和证书部署共用同一套凭证，而且支持
// SessionToken，可以走 role。
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
	Webhook      Webhook       `yaml:"webhook"`
	DesiredState DesiredState  `yaml:"desiredState"`
	Onboarding   Onboarding    `yaml:"onboarding"`
	Probe        Probe         `yaml:"probe"`
	Certificates []Certificate `yaml:"certificates"`
}

// Probe 配置网络侧的证书探测。
//
// 云 API 说"绑定成功"，和浏览器真的能拿到这张证书，是两件事：
// 前者走控制面，后者要拨一个真实的 TLS 连接。这个开关决定要不要后者。
//
// 默认开着，因为它能挡住一整类控制面看不出来的故障（换绑没生效、
// CLB 上另一张证书在赢 SNI），而且"探测没跑成"和"证书不对"是分开报的 ——
// 从这台机器拨不出去只会让 probe_errors 涨，不会让证书看起来是坏的。
type Probe struct {
	// Enabled 默认 true。
	Enabled *bool `yaml:"enabled"`

	// Port 默认 443。
	Port int `yaml:"port"`

	// Timeout 默认 10s。跨可用区握手慢到 3~5 秒是常态，
	// 设小了会频繁误报，而误报会训练人忽略告警。
	Timeout string `yaml:"timeout"`

	// MaxHostsPerCert 是每张证书最多探测几个名字。默认 3。
	//
	// 不做全量：一张 25 个名字的证书每轮拨 25 次握手，
	// 收益递减而成本线性增长。
	MaxHostsPerCert int `yaml:"maxHostsPerCert"`

	// MinValidFor 是"至少还要剩多久有效期"。留空表示不检查。
	//
	// 这个检查是冗余的 —— 到期告警本来就该基于 notAfter。
	// 但它的失败模式不同：它验的是"线上真的在服务一张没过期的证书"，
	// 而不是"我以为部署了一张没过期的证书"。
	MinValidFor string `yaml:"minValidFor"`

	// 解析后的时长，由 normalize 填充。
	TimeoutDur  time.Duration `yaml:"-"`
	MinValidDur time.Duration `yaml:"-"`
}

// ProbeEnabledOr 返回探测开关，未设置时用 def。
func (p *Probe) EnabledOr(def bool) bool {
	if p.Enabled == nil {
		return def
	}
	return *p.Enabled
}

func (p *Probe) normalize() error {
	var err error
	if p.TimeoutDur, err = parseDuration(p.Timeout, 10*time.Second, "probe.timeout"); err != nil {
		return err
	}

	// minValidFor 不能走 parseDuration：它把"默认值为 0"理解成"必填"，
	// 而这里留空恰恰是合法且有意义的 —— 表示不检查剩余有效期。
	if p.MinValidFor != "" {
		d, err := time.ParseDuration(p.MinValidFor)
		if err != nil {
			return fmt.Errorf("probe.minValidFor: %w", err)
		}
		if d <= 0 {
			return fmt.Errorf("probe.minValidFor must be positive, got %s", p.MinValidFor)
		}
		p.MinValidDur = d
	}
	if p.Port == 0 {
		p.Port = 443
	}
	if p.Port < 1 || p.Port > 65535 {
		return fmt.Errorf("probe.port must be between 1 and 65535, got %d", p.Port)
	}
	if p.MaxHostsPerCert == 0 {
		p.MaxHostsPerCert = 3
	}
	if p.MaxHostsPerCert < 0 {
		return fmt.Errorf("probe.maxHostsPerCert must not be negative, got %d", p.MaxHostsPerCert)
	}
	return nil
}

// Onboarding 配置期望状态的生成策略，供 wecert-onboard 使用。
//
// wecert 自己不读这一节 —— 这是刻意的：生成策略会反复调，而收敛必须稳。
// 放在配置里而不是写成常量，是因为这些数字只能从真实漂移数据里来：
// 先跑 observe 攒数据，再回来调它们。
type Onboarding struct {
	// Zones 限定枚举哪些 DNS zone。留空表示账号下所有 zone。
	Zones []string `yaml:"zones"`

	// RequireCLBRule 表示声明必须同时有 CLB 规则才生效（守卫 1）。默认 true。
	//
	// 用指针是因为 false 是有意义的值，而 Go 的零值分不出"没写"和"写了 false"。
	RequireCLBRule *bool `yaml:"requireCLBRule"`

	// Allowlist 限定允许签发证书的注册域。留空表示不限制。
	Allowlist []string `yaml:"allowlist"`

	// MaxNames 是单证书 SAN 上限，默认 25（与 tlsserver 对齐，
	// 将来切 profile 不用改架构）。
	MaxNames int `yaml:"maxNames"`

	Profile string `yaml:"profile"`
	KeyType string `yaml:"keyType"`
	Deploy  *bool  `yaml:"deploy"`

	// GracePeriod 是删除宽限期，默认 24h。
	GracePeriod string `yaml:"gracePeriod"`

	// Budget / BudgetWindow 是配额预算，默认 25 次 / 7 天。
	Budget       int    `yaml:"budget"`
	BudgetWindow string `yaml:"budgetWindow"`

	// DropThreshold 是骤变熔断阈值，默认 0.30。
	DropThreshold float64 `yaml:"dropThreshold"`

	StatePath  string `yaml:"statePath"`
	ReportPath string `yaml:"reportPath"`

	// 解析后的时长，由 normalize 填充。
	GraceDur  time.Duration `yaml:"-"`
	BudgetDur time.Duration `yaml:"-"`
}

// RequireCLBRuleOr 返回守卫开关，未设置时用 def。
func (o *Onboarding) RequireCLBRuleOr(def bool) bool {
	if o.RequireCLBRule == nil {
		return def
	}
	return *o.RequireCLBRule
}

// DeployOr 返回部署默认值，未设置时用 def。
func (o *Onboarding) DeployOr(def bool) bool {
	if o.Deploy == nil {
		return def
	}
	return *o.Deploy
}

func (o *Onboarding) normalize() error {
	var err error
	if o.GraceDur, err = parseDuration(o.GracePeriod, 24*time.Hour, "onboarding.gracePeriod"); err != nil {
		return err
	}
	if o.BudgetDur, err = parseDuration(o.BudgetWindow, 7*24*time.Hour, "onboarding.budgetWindow"); err != nil {
		return err
	}
	return nil
}

// DesiredState 的三种模式。
//
// 区别是**谁有最终解释权**，不是"读几个文件"。
const (
	// ModeStatic：配置里的 certificates 就是期望状态。历史行为，零风险。
	ModeStatic = "static"

	// ModeObserve：仍然按 certificates 收敛，但同时读文档并报告差异。
	//
	// 这是从 static 迁到 enforce 之间的必经阶段：它不签发任何东西，
	// 只回答"如果真的按文档来，会加什么、会删什么"。
	ModeObserve = "observe"

	// ModeEnforce：文档就是期望状态。
	ModeEnforce = "enforce"
)

// DesiredState 配置期望状态的来源。
//
// 为什么不把推断放进 wecert 自己：这个系统所有已知的坑（限速、误删、
// 状态漂移）都出在"判断"上，而判断逻辑必然会反复改；证书生命周期必须稳。
// 拆开之后，来源故障的失败模式是"期望状态不更新"（安全），
// 而不是"域名看起来消失了"（灾难）。
type DesiredState struct {
	// Mode 是 static / observe / enforce。
	Mode string `yaml:"mode"`

	// Path 是期望状态文档的路径。observe 与 enforce 必填。
	Path string `yaml:"path"`

	// MaxStaleness 是文档多久没被刷新就告警，默认 48h。
	//
	// 这是这套架构新引入的失败模式：onboarding 组件挂掉之后，wecert 会一直
	// 按旧文档正常续期，一切看起来都正常，但新域名再也不会进来。
	// 没有这个告警，那种状态能一直持续到有人想起来加域名为止。
	MaxStaleness string `yaml:"maxStaleness"`

	// 解析后的时长，由 normalize 填充。
	MaxStalenessDur time.Duration `yaml:"-"`
}

func (d *DesiredState) normalize(hasCertificates bool) error {
	if d.Mode == "" {
		d.Mode = ModeStatic
	}

	var err error
	if d.MaxStalenessDur, err = parseDuration(d.MaxStaleness, 48*time.Hour, "desiredState.maxStaleness"); err != nil {
		return err
	}

	switch d.Mode {
	case ModeStatic:
		if d.Path != "" {
			return fmt.Errorf("desiredState.path is set but desiredState.mode is %q: "+
				"an unused path is almost always a half-finished switch to observe/enforce, "+
				"so it is rejected instead of silently ignored", ModeStatic)
		}
	case ModeObserve, ModeEnforce:
		if d.Path == "" {
			return fmt.Errorf("desiredState.mode=%q requires desiredState.path", d.Mode)
		}
	default:
		return fmt.Errorf("desiredState.mode must be %q, %q or %q, got %q",
			ModeStatic, ModeObserve, ModeEnforce, d.Mode)
	}

	if d.Mode == ModeEnforce && hasCertificates {
		return fmt.Errorf("desiredState.mode=%q but certificates is not empty: "+
			"in enforce mode the document is the single source of truth, "+
			"and leaving a stale certificates block behind means editing it would silently do nothing", d.Mode)
	}
	return nil
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

// Webhook 让 wecert 可以被外部事件触发，而不是只靠定时轮询。
//
// 典型用法：域名新增后由 CI/事件总线调一次，不用等下一个整点。
type Webhook struct {
	// Listen 是触发端点的监听地址。留空表示不启用 webhook。
	Listen string `yaml:"listen"`

	// Token 是共享密钥，必填。
	//
	// 这个端点会触发真实签发、消耗 Let's Encrypt 的速率限制配额，
	// 所以绝不能裸奔。支持两种带法：
	//   Authorization: Bearer <token>
	//   X-Wecert-Token: <token>
	Token string `yaml:"token"`

	// NotifyURL 可选。设置后，每次续期尝试结束都会向它 POST 一条 JSON 事件。
	// 用来把"证书已续期"接进下游流程（比如触发一次配置重载）。
	NotifyURL string `yaml:"notifyURL"`
}

// WebhookTokenMinLen 是 token 的最小长度。
// 太短的 token 在这个端点上等于没有鉴权 —— 攻击者触发签发就能烧掉速率配额。
const WebhookTokenMinLen = 16

// Certificate 是一张证书的期望状态。
type Certificate struct {
	Name        string   `yaml:"name" json:"name"`
	Domains     []string `yaml:"domains" json:"domains"`
	Profile     string   `yaml:"profile" json:"profile"`
	KeyType     string   `yaml:"keyType" json:"keyType"`
	RenewBefore string   `yaml:"renewBefore,omitempty" json:"renewBefore,omitempty"`
	Deploy      Deploy   `yaml:"deploy" json:"deploy"`

	// 解析后的时长，由 normalize 填充。
	RenewBeforeDur time.Duration `yaml:"-" json:"-"`
}

// Deploy 描述签出来的证书要部署到哪里。
// 首次签发时腾讯云侧还没有绑定关系，需要人工绑一次；
// 之后每 90/45 天续期都由 UpdateCertificateInstance 自动换。
type Deploy struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
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
	dec := yaml.NewDecoder(bytes.NewReader(data))
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
			"(a DNSPod API token, not a Tencent Cloud SecretId/SecretKey;" +
			"to use Tencent Cloud CAM credentials instead, set dns.provider=tencentcloud)")
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

	if err := c.Webhook.normalize(); err != nil {
		return err
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

	if err := c.DesiredState.normalize(len(c.Certificates) > 0); err != nil {
		return err
	}
	if err := c.Onboarding.normalize(); err != nil {
		return err
	}
	if err := c.Probe.normalize(); err != nil {
		return err
	}

	// static 和 observe 都要用 certificates 收敛，所以非空是硬要求。
	// enforce 模式下 certificates 必须为空（上面已经拦过），文档才是唯一来源。
	if c.DesiredState.Mode != ModeEnforce && len(c.Certificates) == 0 {
		return fmt.Errorf("at least one certificate is required "+
			"(desiredState.mode=%q still converges on this list; "+
			"set desiredState.mode=%q to take the whole list from the desired-state document instead)",
			c.DesiredState.Mode, ModeEnforce)
	}

	return NormalizeCertificates(c.Certificates)
}

func (w *Webhook) normalize() error {
	// 留空 Listen 表示不启用，此时 Token 也不必设置。
	if w.Listen == "" {
		if w.Token != "" {
			return fmt.Errorf("webhook.token is set but webhook.listen is empty: " +
				"with no listen address there is no endpoint for the token to guard")
		}
		if w.NotifyURL != "" {
			// NotifyURL 独立于监听端点，允许单独使用。
			return nil
		}
		return nil
	}

	if w.Token == "" {
		return fmt.Errorf("webhook.listen is set but webhook.token is missing: " +
			"this endpoint triggers real issuance and consumes rate-limit quota, so it must be authenticated")
	}
	if len(w.Token) < WebhookTokenMinLen {
		return fmt.Errorf("webhook.token is too short (%d characters, minimum %d): "+
			"this endpoint can trigger real issuance, so a weak token is no better than none",
			len(w.Token), WebhookTokenMinLen)
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

	// 先把域名规范化（小写、去重、校验），再判上限。
	//
	// 顺序很重要：SAN 多的证书，domains 列表往往是从别处整段复制粘贴来的，
	// 重复和小写混用是常态。如果先判上限，一个 100 个域名 + 1 个手误重复的
	// 配置会被判成 101 超限而拒掉 —— 但它本该是合法的。
	normalized, err := normalizeDomains(c.Domains)
	if err != nil {
		return fmt.Errorf("certificate %q: %w", c.Name, err)
	}
	c.Domains = normalized

	if len(c.Domains) > maxNames {
		return fmt.Errorf(
			"certificate %q: %d domains exceeds the %s profile's max of %d identifiers; "+
				"split it into smaller certificates (and remember every name fails together)",
			c.Name, len(c.Domains), c.Profile, maxNames)
	}

	c.RenewBeforeDur, err = parseDuration(c.RenewBefore, profileRenewBefore[c.Profile],
		fmt.Sprintf("certificate %q renewBefore", c.Name))
	if err != nil {
		return err
	}
	return nil
}

// normalizeDomains 去空白、转小写、按集合去重，并逐个校验。
//
// 保留配置里的原始顺序是有意的：classic profile 会把第一个 dNSName 提升为 CN，
// 顺序一变证书的 Subject CN 就跟着变。
func normalizeDomains(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))

	for _, raw := range in {
		d := strings.ToLower(strings.TrimSpace(raw))
		if err := validateDomain(d); err != nil {
			return nil, err
		}
		if seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out, nil
}

// DomainKey 返回这张证书期望的域名集合指纹。
func (c *Certificate) DomainKey() string { return DomainKey(c.Domains) }

// DomainKey 把一组域名压成与顺序、大小写、重复无关的字符串。
//
// 用途是拿"配置里期望的集合"和"证书里实际的 SAN"做相等比较：
// 直接比 []string 会被顺序和大小写干扰，而这两者对证书语义毫无影响。
func DomainKey(domains []string) string {
	seen := make(map[string]bool, len(domains))
	cp := make([]string, 0, len(domains))
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		cp = append(cp, d)
	}
	sort.Strings(cp)
	return strings.Join(cp, ",")
}

// DiffDomains 返回 want 有而 have 没有的（missing），以及 have 有而 want 没有的（extra）。
//
// 两个方向都要看：只查 missing 会漏掉"配置里删了域名"这种情况，
// 而那种情况下证书里多出来的 SAN 同样是需要收敛的偏差。
func DiffDomains(want, have []string) (missing, extra []string) {
	inWant := make(map[string]bool, len(want))
	inHave := make(map[string]bool, len(have))
	for _, d := range want {
		inWant[strings.ToLower(strings.TrimSpace(d))] = true
	}
	for _, d := range have {
		inHave[strings.ToLower(strings.TrimSpace(d))] = true
	}
	for d := range inWant {
		if !inHave[d] {
			missing = append(missing, d)
		}
	}
	for d := range inHave {
		if !inWant[d] {
			extra = append(extra, d)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra
}

// validateDomain 挡住几种明知会被 CA 拒绝、或者覆盖范围容易被误解的写法。
//
// 为什么不交给 CA 报错：每个被拒的订单都要消耗一次订单配额，
// 而 SAN 多的证书一旦有个手误，代价是整张证书重来一遍。本地拦下更便宜。
// ValidateDomain 校验一个域名，允许最左侧一个通配符标签。
//
// 导出是为了让期望状态来源复用同一套规则：如果来源接受了 wecert 会拒掉的名字，
// 收敛就会卡在一个永远修不好的错误上，而报错点离真正的原因很远。
func ValidateDomain(d string) error { return validateDomain(d) }

// NormalizeCertificates 校验并规范化一组证书：补默认值、去重名字、校验域名与数量上限。
//
// 静态配置和期望状态文档都走这一个入口，避免两条路径的宽松程度不一致
// —— 那是"文档里能过、配置里过不了"这类诡异差异的来源。
func NormalizeCertificates(certs []Certificate) error {
	seen := make(map[string]bool, len(certs))
	for i := range certs {
		if err := certs[i].normalize(seen); err != nil {
			return err
		}
	}
	return nil
}

func validateDomain(d string) error {
	if d == "" {
		return fmt.Errorf("empty domain")
	}
	if strings.HasSuffix(d, ".") {
		return fmt.Errorf("domain %q has a trailing dot", d)
	}
	if len(d) > 253 {
		return fmt.Errorf("domain %q is longer than 253 characters", d)
	}
	if strings.ContainsAny(d, " \t\r\n/") {
		return fmt.Errorf("domain %q contains whitespace or a slash", d)
	}

	// 逐标签检查。空标签（a..example.com）、超长标签、非法字符都会被 CA 拒绝。
	for _, label := range strings.Split(d, ".") {
		if label == "*" {
			// 通配符标签本身合法，位置由下面单独校验。
			continue
		}
		if label == "" {
			return fmt.Errorf("domain %q has an empty label", d)
		}
		if len(label) > 63 {
			return fmt.Errorf("domain %q: label %q exceeds 63 characters", d, label)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("domain %q: label %q must not start or end with a hyphen", d, label)
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' {
				continue
			}
			return fmt.Errorf("domain %q: label %q contains an invalid character %q", d, label, string(ch))
		}
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
