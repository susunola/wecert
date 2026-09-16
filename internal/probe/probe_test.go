package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// ── 测试脚手架 ──────────────────────────────────────────────────────────────

// makeCert 生成一张自签证书。
//
// 自签是有意的：这些测试关心的是"对端出示了什么"，而不是"这家 CA 可不可信"，
// 而且自签让 Trusted 必然是 false —— 正好把"链不可信"和"证书不对"
// 这两件事必须分开报给钉住。
func makeCert(t *testing.T, dnsNames []string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: dnsNames[0]},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	for _, n := range dnsNames {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发测试证书失败: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startServer 在 127.0.0.1 的一个随机端口上起 TLS 监听，返回端口。
func startServer(t *testing.T, cert tls.Certificate) int {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
			}(conn)
		}
	}()

	return ln.Addr().(*net.TCPAddr).Port
}

// probeLocalhost 探测本地那台测试服务器。
//
// 用 localhost 而不是 127.0.0.1：走的是完整的目标名字 + SNI 路径，
// 和真机上探测一个域名是同一条代码路径。它也可能解析出 ::1，
// 那正好顺带覆盖"多个地址逐个尝试"。
func probeLocalhost(t *testing.T, port int) *Result {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := Probe(ctx, "localhost", Options{Port: port})
	if err != nil {
		t.Fatalf("探测失败: %v", err)
	}
	return res
}

// ── 探测本身 ────────────────────────────────────────────────────────────────

func TestProbeReadsTheServedCertificate(t *testing.T) {
	notAfter := time.Now().Add(60 * 24 * time.Hour).Truncate(time.Second)
	port := startServer(t, makeCert(t, []string{"localhost", "www.example.com"},
		time.Now().Add(-time.Hour), notAfter))

	res := probeLocalhost(t, port)

	if res.Host != "localhost" {
		t.Errorf("Host = %q", res.Host)
	}
	if !res.NotAfter.Equal(notAfter.UTC()) && !res.NotAfter.Equal(notAfter) {
		t.Errorf("NotAfter = %v，期望 %v", res.NotAfter, notAfter)
	}
	if len(res.SANs) != 2 {
		t.Errorf("SANs = %v，期望两个名字", res.SANs)
	}
	if res.RemoteAddr == "" {
		t.Error("RemoteAddr 应当记录实际连上的地址")
	}
	if len(res.ResolvedIPs) == 0 {
		t.Error("ResolvedIPs 应当记录解析结果，证书不对时这是第一个要看的东西")
	}
	if res.Serial == "" {
		t.Error("Serial 不该为空")
	}
}

// 自签证书必须报成"链不可信"，而不是报成"证书不对"。
//
// 这两件事的排障方向完全相反：链不可信要去看 CA，
// 证书不对要去看 DNS 和 CLB 规则。混在一起会让人查错方向。
func TestProbeSeparatesTrustFromCorrectness(t *testing.T) {
	port := startServer(t, makeCert(t, []string{"localhost"},
		time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour)))

	res := probeLocalhost(t, port)

	if res.Trusted {
		t.Error("自签证书不该被报成可信")
	}
	if res.ChainError == "" {
		t.Error("不可信时必须说明原因")
	}

	// 但证书本身覆盖 localhost，所以校验应当通过。
	v := res.Verify(Expectation{})
	if !v.OK {
		t.Errorf("自签不该影响覆盖判断，实际: %s", v.Summary())
	}
}

func TestProbeReportsAWrongCertificate(t *testing.T) {
	// 服务的是别人的证书。
	port := startServer(t, makeCert(t, []string{"other.example"},
		time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour)))

	res := probeLocalhost(t, port)
	v := res.Verify(Expectation{})

	if v.OK {
		t.Fatal("名字不匹配时必须报错")
	}
	if !strings.Contains(v.Summary(), "does not cover localhost") {
		t.Errorf("应当指出不覆盖被拨的名字，实际: %s", v.Summary())
	}
	// 摘要里要能看见它到底覆盖了什么，否则还得再拨一次才知道。
	if !strings.Contains(v.Summary(), "other.example") {
		t.Errorf("应当报出实际覆盖的名字，实际: %s", v.Summary())
	}
}

// 这一条是"换绑到底生效了没有"的唯一硬证据。
//
// 名字对得上、面也对得上，但证书不是部署的那一张 ——
// 也就是 CLB 上还挂着旧证书。只检查"能不能握手"会完全漏掉它。
func TestProbeDetectsAStaleCertificate(t *testing.T) {
	servedNotAfter := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	port := startServer(t, makeCert(t, []string{"localhost"},
		time.Now().Add(-time.Hour), servedNotAfter))

	res := probeLocalhost(t, port)

	deployedNotAfter := servedNotAfter.Add(24 * time.Hour)
	v := res.Verify(Expectation{NotAfter: deployedNotAfter})

	if v.OK {
		t.Fatal("服务的是另一张证书时必须报错")
	}
	if !strings.Contains(v.Summary(), "the rebind did not take effect") {
		t.Errorf("应当指向换绑没生效，实际: %s", v.Summary())
	}
}

func TestProbeDetectsMissingAndExtraNames(t *testing.T) {
	port := startServer(t, makeCert(t, []string{"localhost", "old.example.com"},
		time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour)))

	res := probeLocalhost(t, port)

	v := res.Verify(Expectation{
		Domains: []string{"localhost", "new.example.com"},
	})

	if v.OK {
		t.Fatal("覆盖面不一致时必须报错")
	}
	if !strings.Contains(v.Summary(), "new.example.com") {
		t.Errorf("应当报出缺失的名字，实际: %s", v.Summary())
	}
	if !strings.Contains(v.Summary(), "old.example.com") {
		t.Errorf("应当报出多余的名字，实际: %s", v.Summary())
	}
}

// 比较必须对顺序、大小写、重复和末尾点不敏感 ——
// 否则每一次探测都会报一次假差异。
func TestProbeIgnoresOrderCaseAndDuplicates(t *testing.T) {
	port := startServer(t, makeCert(t, []string{"localhost", "WWW.Example.COM"},
		time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour)))

	res := probeLocalhost(t, port)

	v := res.Verify(Expectation{
		Domains: []string{"www.example.com.", "LOCALHOST", "localhost"},
	})
	if !v.OK {
		t.Errorf("顺序/大小写/重复不该影响判断，实际: %s", v.Summary())
	}
}

func TestProbeDetectsExpiry(t *testing.T) {
	port := startServer(t, makeCert(t, []string{"localhost"},
		time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)))

	res := probeLocalhost(t, port)

	v := res.Verify(Expectation{MinValidFor: 7 * 24 * time.Hour})
	if v.OK {
		t.Fatal("剩余有效期不足时必须报错")
	}
	if !strings.Contains(v.Summary(), "less than the required") {
		t.Errorf("实际: %s", v.Summary())
	}
}

// ── 输入校验 ────────────────────────────────────────────────────────────────

// 通配符没有自己的地址可拨。直接说清楚，而不是让 DNS 解析去报一个
// 看不懂的 "no such host"。
func TestProbeRejectsAWildcard(t *testing.T) {
	_, err := Probe(context.Background(), "*.example.com", Options{})
	if err == nil || !strings.Contains(err.Error(), "wildcard") {
		t.Fatalf("通配符应当被明确拒绝，实际: %v", err)
	}
}

func TestProbeRejectsAnEmptyHost(t *testing.T) {
	if _, err := Probe(context.Background(), "  ", Options{}); err == nil {
		t.Fatal("空名字应当被拒绝")
	}
}

// 收敛循环里探测不能被拖住：context 取消必须立刻返回。
func TestProbeHonorsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	if _, err := Probe(ctx, "localhost", Options{Port: 443}); err == nil {
		t.Fatal("已取消的 context 不该成功")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("应当立刻返回，实际用了 %v", elapsed)
	}
}

func TestProbeErrorsWhenNothingIsListening(t *testing.T) {
	// 端口 1 上几乎不可能有东西在听。
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := Probe(ctx, "localhost", Options{Port: 1, Timeout: 2 * time.Second})
	if err == nil {
		t.Fatal("没有监听时应当报错")
	}
	// 报错里要带上试过哪些地址，否则只知道"失败了"。
	if !strings.Contains(err.Error(), "localhost") {
		t.Errorf("错误信息应当能看出是哪个名字失败了，实际: %v", err)
	}
}

// A successful TCP connection does not mean TLS will complete. A broken endpoint
// can accept connections yet send no TLS bytes; timeout must include that handshake
// or the entire reconciliation pass can block until the process exits.
func TestProbeTimesOutAStalledTLSHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	start := time.Now()
	attempts := probeIPs(context.Background(), "localhost", []string{"127.0.0.1"},
		Options{Port: port, Timeout: 100 * time.Millisecond})
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("a stalled TLS handshake must obey timeout, took %v", elapsed)
	}
	if len(attempts) != 1 || attempts[0].Err == nil {
		t.Fatalf("stalled handshake should be recorded as a failure, got %+v", attempts)
	}

	select {
	case conn := <-accepted:
		_ = conn.Close()
	case <-time.After(time.Second):
		t.Fatal("test server did not receive the TCP connection")
	}
}

// Runner must verify every address. Treating an updated first node as success
// would hide the critical case where a later node still serves an old certificate.
func TestRunnerDetectsAMismatchOnAnyResolvedAddress(t *testing.T) {
	goodCert := makeCert(t, []string{"service.example"},
		time.Now().Add(-time.Hour), time.Now().Add(60*24*time.Hour))
	badCert := makeCert(t, []string{"old.example"},
		time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))

	resultFor := func(cert tls.Certificate, host string) *Result {
		t.Helper()
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		return &Result{
			Host:     host,
			NotAfter: leaf.NotAfter,
			SANs:     append([]string(nil), leaf.DNSNames...),
			cert:     leaf,
		}
	}

	r := NewRunner(Options{}, 0, nil)
	good := resultFor(goodCert, "service.example")
	bad := resultFor(badCert, "service.example")
	r.probeAll = func(context.Context, string, Options) ([]Attempt, error) {
		return []Attempt{
			{Address: "192.0.2.10:443", Result: good},
			{Address: "192.0.2.11:443", Result: bad},
		}, nil
	}

	v := r.Check(context.Background(), "service.example", Expectation{
		Domains:  []string{"service.example"},
		NotAfter: good.NotAfter,
	})
	if v.OK {
		t.Fatal("a reachable address serving the wrong certificate must fail")
	}
	if !strings.Contains(v.Summary(), "192.0.2.11:443") {
		t.Errorf("problem should name the stale address, got: %s", v.Summary())
	}
}
