// Package probe 从网络侧验证"这张证书真的在服务"。
//
// 云 API 说绑定成功，和浏览器真的能拿到这张证书，是两件事。
// 绑定确认走的是控制面，而这个包拨的是一个真实的 TLS 连接，
// 读回对端**实际出示**的证书。它是这套系统里唯一不信任控制面的证据。
//
// 为什么不用 Go 的默认校验、让握手直接失败：
// 那样我们只知道"失败了"，而不知道"它出示了什么"。
// 排障时最有用的信息恰恰是那张不该出现的证书 ——
// 是过期了、是别人的域名、还是压根就是自签的默认证书。
// 所以这里先完成握手把证书拿到手，再自己做判断。
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DefaultTimeout 是单次探测的默认超时。
//
// 10 秒是刻意偏大的：这个探测多半是从一台 CVM 拨到公网 VIP，
// 跨可用区时握手慢到 3~5 秒是常态。设成 3 秒会让它频繁误报，
// 而误报会训练人忽略告警 —— 那比不探测更糟。
const DefaultTimeout = 10 * time.Second

// Result 是一次成功探测的结果，也就是对端实际出示了什么。
type Result struct {
	// Host 是探测用的名字，也是握手里的 SNI。
	Host string `json:"host"`

	// RemoteAddr 是真正建立起连接的地址。
	RemoteAddr string `json:"remoteAddr"`

	// ResolvedIPs 是这个名字解析出来的全部地址。
	//
	// 单独留着是因为"证书不对"最常见的原因之一就是 DNS 指到了别的机器，
	// 而这个信息在失败摘要里最容易丢。
	ResolvedIPs []string `json:"resolvedIPs"`

	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	Serial    string    `json:"serial"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
	SANs      []string  `json:"sans"`

	// Trusted 表示这条链能否用系统根证书验通。
	//
	// 自签或内网 CA 会是 false —— 那不是错误，但必须能看见：
	// 一张 internal-ca 签的证书在 curl 里能过、在浏览器里会红。
	Trusted bool `json:"trusted"`

	// ChainError 是链验证失败的原因，Trusted 为 true 时为空。
	ChainError string `json:"chainError,omitempty"`

	// HandshakeMS 是握手耗时，用来把"证书不对"和"慢得离谱"分开。
	HandshakeMS int64 `json:"handshakeMs"`

	// cert 保留叶证书本体，供 VerifyHostname 使用。
	// 自己实现通配符匹配是这类代码里最经典的一类 bug，不值得重写一遍。
	cert *x509.Certificate
}

// Options 控制一次探测。
type Options struct {
	// Port 默认 443。
	Port int

	// Timeout 默认 DefaultTimeout。
	Timeout time.Duration
}

// Attempt is the TLS probe result for one resolved IP address.
//
// Exactly one of Result and Err is non-nil. Address is the dialled endpoint so
// a partially updated backend can be distinguished from an ordinary mismatch.
type Attempt struct {
	Address string
	Result  *Result
	Err     error
}

// Probe 拨 host:port，用 SNI=host 完成 TLS 握手，读回对端出示的叶证书。
//
// This is the simple API for the CLI and callers: it tries addresses in order
// and returns the first successful result. Use ProbeAll to verify every backend;
// Runner uses it so an updated node cannot hide a node still serving an old cert.
func Probe(ctx context.Context, host string, opts Options) (*Result, error) {
	host, ips, opts, err := prepareProbe(ctx, host, opts)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, ip := range ips {
		attempt := probeIP(ctx, host, ip, opts)
		if attempt.Result != nil {
			attempt.Result.ResolvedIPs = append([]string(nil), ips...)
			return attempt.Result, nil
		}
		if attempt.Err != nil {
			lastErr = attempt.Err
		}
	}
	return nil, fmt.Errorf("probe: none of the %d address(es) of %s completed a TLS handshake on port %d "+
		"(last error: %w)", len(ips), host, opts.Port, lastErr)
}

// ProbeAll dials every address resolved for host and preserves each result.
//
// opts.Timeout is the full per-address budget after DNS resolution, shared by
// TCP dial and TLS handshake. Limiting dial alone lets a faulty endpoint that
// accepts TCP but never sends TLS bytes block reconciliation indefinitely.
func ProbeAll(ctx context.Context, host string, opts Options) ([]Attempt, error) {
	host, ips, opts, err := prepareProbe(ctx, host, opts)
	if err != nil {
		return nil, err
	}
	attempts := probeIPs(ctx, host, ips, opts)
	for i := range attempts {
		if attempts[i].Result != nil {
			attempts[i].Result.ResolvedIPs = append([]string(nil), ips...)
		}
	}
	return attempts, nil
}

func prepareProbe(ctx context.Context, host string, opts Options) (string, []string, Options, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return "", nil, opts, errors.New("probe: empty host")
	}
	if strings.HasPrefix(host, "*.") {
		return "", nil, opts, fmt.Errorf("probe: %q is a wildcard, which has no address of its own to dial; "+
			"probe a concrete name that the same certificate covers", host)
	}
	if opts.Port == 0 {
		opts.Port = 443
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}

	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return "", nil, opts, fmt.Errorf("probe: resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return "", nil, opts, fmt.Errorf("probe: %s resolved to no address", host)
	}
	sort.Strings(ips)
	return host, ips, opts, nil
}

// probeIPs is ProbeAll's per-address work, separated so multi-address behavior
// can be tested without depending on local DNS ordering.
func probeIPs(ctx context.Context, host string, ips []string, opts Options) []Attempt {
	attempts := make([]Attempt, 0, len(ips))
	for _, ip := range ips {
		attempts = append(attempts, probeIP(ctx, host, ip, opts))
	}
	return attempts
}

func probeIP(ctx context.Context, host, ip string, opts Options) Attempt {

	// Do not use tls.DialWithDialer: dial and handshake must share the same
	// context so every address is bound by the full probe budget.
	dialer := &net.Dialer{Timeout: opts.Timeout}
	addr := net.JoinHostPort(ip, strconv.Itoa(opts.Port))

	// A DialContext timeout is not enough: after TCP connects, TLS can wait
	// forever for peer data. Every IP needs its own full budget.
	attemptCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	res, err := probeAddr(attemptCtx, dialer, addr, host)
	if err != nil {
		return Attempt{Address: addr, Err: err}
	}
	return Attempt{Address: addr, Result: res}
}

func probeAddr(ctx context.Context, dialer *net.Dialer, addr, sni string) (*Result, error) {
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	// HandshakeContext observes cancellation, but an I/O deadline also guards
	// against transports that are stuck below the TLS state machine. Clear it
	// after the handshake so the captured connection state can be inspected
	// without inheriting a stale deadline.
	if deadline, ok := ctx.Deadline(); ok {
		if err := raw.SetDeadline(deadline); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("set probe deadline for %s: %w", addr, err)
		}
	}

	cfg := &tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS12,

		// 这是本包存在的理由，不是疏忽。
		// 让 Go 在握手期因为链或名字不对而报错的话，我们拿不到那张证书；
		// 而"它到底出示了什么"正是要回答的问题。判断放在 Verify 里做。
		InsecureSkipVerify: true,
	}

	conn := tls.Client(raw, cfg)
	defer conn.Close()

	start := time.Now()
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS handshake with %s (SNI %s): %w", addr, sni, err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clear probe deadline for %s: %w", addr, err)
	}
	elapsed := time.Since(start)

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("%s completed a handshake without presenting a certificate", addr)
	}
	leaf := state.PeerCertificates[0]

	res := &Result{
		Host:        sni,
		RemoteAddr:  conn.RemoteAddr().String(),
		Subject:     leaf.Subject.String(),
		Issuer:      leaf.Issuer.String(),
		Serial:      leaf.SerialNumber.Text(16),
		NotBefore:   leaf.NotBefore,
		NotAfter:    leaf.NotAfter,
		SANs:        append([]string(nil), leaf.DNSNames...),
		HandshakeMS: elapsed.Milliseconds(),
		cert:        leaf,
	}

	// 链验证单独做，失败也不影响上面那些字段。
	// Roots 留 nil 让 x509 用系统根证书池。
	inter := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: sni, Intermediates: inter}); err != nil {
		res.ChainError = err.Error()
	} else {
		res.Trusted = true
	}

	return res, nil
}

// Expectation 是"这个地址应该表现出什么"。
type Expectation struct {
	// Domains 是部署下去的那张证书应该覆盖的全部域名（含通配符）。
	//
	// 非空时按集合比对，而不是"至少覆盖其中一个" ——
	// CLB 上挂着多张证书时，最危险的形态正是"名字能过、但服务的是另一张"。
	Domains []string

	// NotAfter 是状态库里记的到期时间。
	//
	// 非零时用来回答"对端出示的是不是我部署的那一张"，
	// 而不是弱化成"某张还没过期的证书"。这两者的差别就是
	// "换绑生效了"和"换绑根本没发生"。
	NotAfter time.Time

	// MinValidFor 是"至少还要剩多久有效期"。
	MinValidFor time.Duration

	// Now 可注入，便于测试。
	Now time.Time
}

// Verdict 是比对结论。
type Verdict struct {
	// OK 为真表示所有检查都过了。
	OK bool `json:"ok"`

	// Problems 是给人看的问题清单，每条都自成一个结论。
	Problems []string `json:"problems,omitempty"`
}

// Summary 返回一行摘要，用于日志和 CLI 输出。
func (v Verdict) Summary() string {
	if v.OK {
		return "ok"
	}
	return strings.Join(v.Problems, "; ")
}

// Verify 拿探测结果和期望比对。
//
// 四类问题分开报，不合并成一句"校验失败"：
// 方向完全不同 —— 名字不匹配要去看 DNS 和 CLB 规则，
// 是别的一张证书要去看换绑有没有生效，过期了要去看续期为什么没跑。
func (r *Result) Verify(e Expectation) Verdict {
	now := e.Now
	if now.IsZero() {
		now = time.Now()
	}

	var problems []string

	// 1. 这张证书覆盖我拨的那个名字吗？
	// 这是最根本的一条：不覆盖的话后面几条再对也没有意义。
	if r.cert == nil {
		problems = append(problems, "no certificate was captured")
	} else if err := r.cert.VerifyHostname(r.Host); err != nil {
		problems = append(problems, fmt.Sprintf("the served certificate does not cover %s "+
			"(it covers %s)", r.Host, formatSANs(r.SANs)))
	}

	// 2. 覆盖的面和部署下去的那张一致吗？
	if len(e.Domains) > 0 && r.cert != nil {
		missing, extra := diffDomains(e.Domains, r.SANs)
		if len(missing) > 0 {
			problems = append(problems, fmt.Sprintf(
				"the served certificate is missing names that were deployed: %s", strings.Join(missing, ", ")))
		}
		if len(extra) > 0 {
			problems = append(problems, fmt.Sprintf(
				"the served certificate has names that were not deployed: %s "+
					"(a different certificate is being served, or the deploy wrote something unexpected)",
				strings.Join(extra, ", ")))
		}
	}

	// 3. 是不是我部署的那一张？
	if !e.NotAfter.IsZero() && !r.NotAfter.Equal(e.NotAfter) {
		problems = append(problems, fmt.Sprintf(
			"the served certificate expires at %s but the deployed one expires at %s "+
				"(the rebind did not take effect, or another certificate is winning SNI)",
			r.NotAfter.UTC().Format(time.RFC3339), e.NotAfter.UTC().Format(time.RFC3339)))
	}

	// 4. 还剩多久？
	if e.MinValidFor > 0 {
		left := r.NotAfter.Sub(now)
		if left < e.MinValidFor {
			problems = append(problems, fmt.Sprintf(
				"the served certificate has %s left, less than the required %s",
				left.Round(time.Hour), e.MinValidFor))
		}
	}

	return Verdict{OK: len(problems) == 0, Problems: problems}
}

// formatSANs 把 SAN 列表压成一句可读的短语。
func formatSANs(sans []string) string {
	if len(sans) == 0 {
		return "no names at all"
	}
	if len(sans) > 4 {
		return strings.Join(sans[:4], ", ") + fmt.Sprintf(" and %d more", len(sans)-4)
	}
	return strings.Join(sans, ", ")
}

// diffDomains 比较"应该有的"和"实际有的"，忽略顺序、大小写和重复。
func diffDomains(want, got []string) (missing, extra []string) {
	w := normalizeSet(want)
	g := normalizeSet(got)

	for d := range w {
		if !g[d] {
			missing = append(missing, d)
		}
	}
	for d := range g {
		if !w[d] {
			extra = append(extra, d)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra
}

func normalizeSet(in []string) map[string]bool {
	out := make(map[string]bool, len(in))
	for _, d := range in {
		out[strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")] = true
	}
	return out
}

// DaysLeft 返回剩余天数，向上取整——"还有 0 天"这种说法没有意义。
func (r *Result) DaysLeft(now time.Time) int {
	if now.IsZero() {
		now = time.Now()
	}
	left := r.NotAfter.Sub(now)
	if left <= 0 {
		return 0
	}
	return int((left + 24*time.Hour - 1) / (24 * time.Hour))
}
