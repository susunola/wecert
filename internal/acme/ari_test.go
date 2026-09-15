package acme

import (
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"testing"
	"time"
)

// RenewalTime 的确定性是硬性要求：如果每次调用都重新随机，
// 进程每重启一次续期时间就会往后推一点，最终推过有效期。
// 这个测试就是钉住这个性质。
func TestRenewalTimeIsDeterministic(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(48 * time.Hour)

	first := RenewalTime("example-com", start, end)
	for i := 0; i < 100; i++ {
		if got := RenewalTime("example-com", start, end); !got.Equal(first) {
			t.Fatalf("第 %d 次调用结果不一致: %s != %s", i, got, first)
		}
	}
}

func TestRenewalTimeStaysInsideWindow(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(48 * time.Hour)

	// 抖动有可能把它推出窗口，必须被夹回来。
	for _, name := range []string{"a", "b", "example-com", "api-example-com", "x.y.z"} {
		got := RenewalTime(name, start, end)
		if got.Before(start) || got.After(end) {
			t.Errorf("%s: %s 落在窗口 [%s, %s] 之外", name, got, start, end)
		}
	}
}

// 不同证书应当散在窗口的不同位置，否则几百张证书会在同一秒一起去敲 CA。
func TestRenewalTimeSpreadsAcrossNames(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(48 * time.Hour)

	seen := map[time.Time]bool{}
	distinct := 0
	const n = 50
	for i := 0; i < n; i++ {
		name := "cert-" + string(rune('a'+i%26)) + string(rune('0'+i/26))
		at := RenewalTime(name, start, end)
		if !seen[at] {
			seen[at] = true
			distinct++
		}
	}
	if distinct < n/2 {
		t.Errorf("50 个证书只散出了 %d 个不同的时刻，抖动不足", distinct)
	}
}

func TestRenewalTimeDegenerateWindow(t *testing.T) {
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	// end 不晚于 start 时应当原样返回 start，而不是 panic（除零）。
	if got := RenewalTime("x", start, start); !got.Equal(start) {
		t.Errorf("零宽窗口应返回 start，得到 %s", got)
	}
	if got := RenewalTime("x", start, start.Add(-time.Hour)); !got.Equal(start) {
		t.Errorf("非法窗口应返回 start，得到 %s", got)
	}
}

func TestDeterministicTimeWithinSpread(t *testing.T) {
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	spread := 6 * time.Hour

	for _, name := range []string{"a", "b", "example-com"} {
		at := DeterministicTime(name, base, spread)
		if at.Before(base) || at.After(base.Add(spread)) {
			t.Errorf("%s: %s 落在 [%s, %s] 之外", name, at, base, base.Add(spread))
		}
		if again := DeterministicTime(name, base, spread); !again.Equal(at) {
			t.Errorf("%s: 结果不确定 %s != %s", name, again, at)
		}
	}

	// spread 为 0 时应退化成 base。
	if got := DeterministicTime("a", base, 0); !got.Equal(base) {
		t.Errorf("spread=0 应返回 base，得到 %s", got)
	}
}

// CertID 必须严格按 RFC 9773 构造，否则 ARI 查不到，
// 也就拿不到"豁免全部速率限制"的待遇。
func TestCertIDFormat(t *testing.T) {
	aki := []byte{0x01, 0x02, 0x03, 0xff}
	serial := big.NewInt(0xdeadbeef)

	leaf := &x509.Certificate{AuthorityKeyId: aki, SerialNumber: serial}

	got, err := CertID(leaf)
	if err != nil {
		t.Fatalf("CertID 返回错误: %v", err)
	}

	want := base64.RawURLEncoding.EncodeToString(aki) + "." +
		base64.RawURLEncoding.EncodeToString(serial.Bytes())
	if got != want {
		t.Errorf("CertID = %q，期望 %q", got, want)
	}
}

func TestCertIDRequiresAKI(t *testing.T) {
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1)}
	if _, err := CertID(leaf); err == nil {
		t.Error("缺少 AKI 时应当报错，而不是返回一个查不到的 certID")
	}
}

// 部署前的最后一道闸门：签回来的证书必须覆盖申请的全部域名。
func TestVerifyCoverage(t *testing.T) {
	leaf := &x509.Certificate{DNSNames: []string{"example.com", "*.example.com"}}

	if err := VerifyCoverage(leaf, []string{"example.com", "*.example.com"}); err != nil {
		t.Errorf("完全覆盖时不应报错: %v", err)
	}
	// 大小写不应影响判断。
	if err := VerifyCoverage(leaf, []string{"EXAMPLE.COM"}); err != nil {
		t.Errorf("大小写不同不应报错: %v", err)
	}
	if err := VerifyCoverage(leaf, []string{"example.com", "other.com"}); err == nil {
		t.Error("缺少 other.com 时应当报错")
	}
}
