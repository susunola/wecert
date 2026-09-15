package acme

import (
	"fmt"
	"testing"

	"github.com/miekg/dns"
)

// txtResponse 造一个包含若干条 TXT 的应答。
func txtResponse(values ...string) *dns.Msg {
	m := new(dns.Msg)
	for _, v := range values {
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   "_acme-challenge.example.com.",
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
			},
			Txt: []string{v},
		})
	}
	return m
}

// probeRecords 必须把结果放回各自的下标上。
//
// 这是并发改造里唯一容易出错的地方：每个 goroutine 只写自己那一格，
// 一旦下标串了，就会出现"某几个域名的传播等待一直不通过、其余正常"
// 这种极难排查的现象 —— 而且 SAN 越多越容易撞上。
//
// 用空的 NS 列表来驱动：不产生网络请求，但完整跑一遍并发路径。
func TestProbeRecordsPreservesOrder(t *testing.T) {
	const n = 20 // 故意超过 maxProbeConcurrency，强制排队

	recs := make([]DNSRecord, 0, n)
	for i := 0; i < n; i++ {
		recs = append(recs, DNSRecord{
			FQDN:  fmt.Sprintf("_acme-challenge.host%02d.example.com.", i),
			Value: fmt.Sprintf("value-%02d", i),
		})
	}

	got := probeRecords(nil, recs)

	if len(got) != n {
		t.Fatalf("结果数量 = %d，期望 %d", len(got), n)
	}
	for i, res := range got {
		if res.record.FQDN != recs[i].FQDN || res.record.Value != recs[i].Value {
			t.Errorf("下标 %d 串了：得到 %s=%s，期望 %s=%s",
				i, res.record.FQDN, res.record.Value, recs[i].FQDN, recs[i].Value)
		}
		if res.ready {
			t.Errorf("下标 %d 在没有权威 NS 的情况下不应判为已就绪", i)
		}
		if res.summary == "" {
			t.Errorf("下标 %d 缺少诊断摘要", i)
		}
	}
}

func TestProbeRecordsEmpty(t *testing.T) {
	if got := probeRecords(nil, nil); len(got) != 0 {
		t.Errorf("空输入应返回空结果，得到 %d 条", len(got))
	}
}

// 单条记录时不应该因为并发池的边界处理而出错。
func TestProbeRecordsSingle(t *testing.T) {
	got := probeRecords(nil, []DNSRecord{{FQDN: "_acme-challenge.a.example.com.", Value: "v"}})
	if len(got) != 1 {
		t.Fatalf("结果数量 = %d", len(got))
	}
	if got[0].record.Value != "v" {
		t.Errorf("记录内容不匹配: %+v", got[0].record)
	}
}

// probeReady 的判定规则：没有任何可达 NS 否认，且至少 2 台确认。
// 这里直接验证判定逻辑本身（不依赖真实 DNS）。
func TestProbeReadyJudgement(t *testing.T) {
	// 无可达 NS：既不能确认也不能放行。
	ready, summary := probeReady(nil, "_acme-challenge.example.com.", "v")
	if ready {
		t.Error("一台 NS 都没探测到就放行，会让 CA 验证失败并消耗配额")
	}
	if summary == "" {
		t.Error("应当给出可读的摘要")
	}
}

// responseHasTXT 要能处理 TXT 被切成多个字符串片段的情况，
// 也要能在多个 TXT 记录中挑出匹配的那条（wildcard 与 apex 共存时就是这样）。
func TestResponseHasTXT(t *testing.T) {
	// 同名两条 TXT 是 wildcard + apex 的常态。
	if !responseHasTXT(txtResponse("other-value", "wanted-value"), "wanted-value") {
		t.Error("应当在多条 TXT 中找到匹配值")
	}
	if responseHasTXT(txtResponse("other-value"), "wanted-value") {
		t.Error("不存在的值不应被判定为命中")
	}

	// TXT 记录超过 255 字节时会被切成多个片段，必须先拼接再比较。
	// 不加这一步，长 key authorization 会被判成"没传播开"，然后白等到超时。
	segmented := &dns.Msg{}
	segmented.Answer = append(segmented.Answer, &dns.TXT{
		Hdr: dns.RR_Header{Name: "_acme-challenge.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET},
		Txt: []string{"wanted-", "value"},
	})
	if !responseHasTXT(segmented, "wanted-value") {
		t.Error("被切成多段的 TXT 应当在拼接后再比较")
	}

	if responseHasTXT(txtResponse(), "anything") {
		t.Error("空应答不应判定为命中")
	}
}
