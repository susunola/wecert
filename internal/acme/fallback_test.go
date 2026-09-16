package acme

import (
	"testing"
	"time"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/state"
)

// fallbackPolicy 是一份"开启、阈值调小"的策略，便于测试。
//
// BeforeExpiryDur / FailureWindowDur 在这里直接给：config.normalize 平时会
// 填它们，而 SetFallbackPolicy 收的是原样的结构体。
// fallbackPolicyPtr 返回策略的指针，便于在用例里传 nil 表示"没配置"。
func fallbackPolicyPtr() *config.FailureFallback {
	p := fallbackPolicy()
	return &p
}

func fallbackPolicy() config.FailureFallback {
	on := true
	return config.FailureFallback{
		Enabled:               &on,
		AfterFailures:         3,
		BeforeExpiryDur:       7 * 24 * time.Hour,
		MinIdentifierFailures: 2,
		FailureWindowDur:      24 * time.Hour,
		MinNames:              1,
	}
}

// fallbackFixture 搭一个"三张名字、快到期、连续失败"的现场。
func fallbackFixture(t *testing.T, policy *config.FailureFallback) (*state.Store, *Manager, *config.Certificate, time.Time) {
	t.Helper()

	store, m, _, cert := newAPITestHarness(t,
		[]string{"a.example.com", "b.example.com", "c.example.com"})

	fixed := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return fixed }

	if policy != nil {
		m.SetFallbackPolicy(*policy)
	}
	return store, m, cert, fixed
}

// 策略要显式开启，而且要显式把 Enabled 设成 true。
func TestFallbackIsOffByDefault(t *testing.T) {
	store, m, cert, now := fallbackFixture(t, nil)

	for i := 0; i < 10; i++ {
		if err := store.RecordIdentifierFailure(cert.Name, "b.example.com", "dns says no", now); err != nil {
			t.Fatal(err)
		}
	}

	st := &state.CertState{Name: cert.Name, NotAfter: now.Add(time.Hour), ConsecutiveFailures: 99}
	got := m.applyFallback(cert, st)

	if len(got.Domains) != 3 {
		t.Fatalf("策略没开启时不该摘任何名字，实际 %v", got.Domains)
	}
}

// 失败次数不够时不动。降级是一次主动放弃覆盖面的决定，
// 不能因为"这轮没签出来"就触发 —— 那几乎每张证书都会遇到。
func TestFallbackWaitsForEnoughConsecutiveFailures(t *testing.T) {
	store, m, cert, now := fallbackFixture(t, fallbackPolicyPtr())

	for i := 0; i < 5; i++ {
		if err := store.RecordIdentifierFailure(cert.Name, "b.example.com", "dns says no", now); err != nil {
			t.Fatal(err)
		}
	}

	st := &state.CertState{
		Name:                cert.Name,
		NotAfter:            now.Add(24 * time.Hour),
		ConsecutiveFailures: 2, // 阈值是 3
	}
	if got := m.applyFallback(cert, st); len(got.Domains) != 3 {
		t.Fatalf("失败次数不够时不该降级，实际 %v", got.Domains)
	}
}

// 也不能太早降级：用一张缺名字的证书换掉一张还完全有效的证书是净损失。
func TestFallbackWaitsForTheExpiryWindow(t *testing.T) {
	store, m, cert, now := fallbackFixture(t, fallbackPolicyPtr())

	for i := 0; i < 5; i++ {
		if err := store.RecordIdentifierFailure(cert.Name, "b.example.com", "dns says no", now); err != nil {
			t.Fatal(err)
		}
	}

	st := &state.CertState{
		Name:                cert.Name,
		NotAfter:            now.Add(30 * 24 * time.Hour), // 还在 7 天窗口之外
		ConsecutiveFailures: 9,
	}
	if got := m.applyFallback(cert, st); len(got.Domains) != 3 {
		t.Fatalf("还没进入到期窗口时不该降级，实际 %v", got.Domains)
	}
}

// 没有生效证书时没有"保住现有的"这个立论 —— 那不是部分可用，是只签一部分。
func TestFallbackRefusesWithoutALiveCertificate(t *testing.T) {
	store, m, cert, now := fallbackFixture(t, fallbackPolicyPtr())

	for i := 0; i < 5; i++ {
		if err := store.RecordIdentifierFailure(cert.Name, "b.example.com", "dns says no", now); err != nil {
			t.Fatal(err)
		}
	}

	st := &state.CertState{Name: cert.Name, ConsecutiveFailures: 9} // NotAfter 是零值
	if got := m.applyFallback(cert, st); len(got.Domains) != 3 {
		t.Fatalf("没有生效证书时不该降级，实际 %v", got.Domains)
	}
}

// 不知道是哪个名字坏的时候绝不能摘 —— 随机摘会把本来好的名字也一起牺牲掉，
// 那比不降级更糟。
func TestFallbackRefusesWithoutASpecificFailingIdentifier(t *testing.T) {
	_, m, cert, now := fallbackFixture(t, fallbackPolicyPtr())

	st := &state.CertState{
		Name:                cert.Name,
		NotAfter:            now.Add(24 * time.Hour),
		ConsecutiveFailures: 9,
	}
	if got := m.applyFallback(cert, st); len(got.Domains) != 3 {
		t.Fatalf("没有 identifier 级失败记录时不该降级，实际 %v", got.Domains)
	}
}

// 这是这个功能的核心：只摘掉反复失败的那几个名字，其余原样保留。
func TestFallbackDropsOnlyTheFailingIdentifiers(t *testing.T) {
	store, m, cert, now := fallbackFixture(t, fallbackPolicyPtr())

	// b 反复失败（3 次），a 只抖了一下（1 次，低于阈值 2）。
	for i := 0; i < 3; i++ {
		if err := store.RecordIdentifierFailure(cert.Name, "b.example.com", "dns says no", now); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.RecordIdentifierFailure(cert.Name, "a.example.com", "one blip", now); err != nil {
		t.Fatal(err)
	}

	st := &state.CertState{
		Name:                cert.Name,
		NotAfter:            now.Add(3 * 24 * time.Hour),
		ConsecutiveFailures: 4,
		ARICertID:           "YWJj.ZGVm",
	}

	got := m.applyFallback(cert, st)

	want := []string{"a.example.com", "c.example.com"}
	if len(got.Domains) != len(want) {
		t.Fatalf("域名集合 = %v，期望 %v", got.Domains, want)
	}
	for i := range want {
		if got.Domains[i] != want[i] {
			t.Fatalf("域名集合 = %v，期望 %v", got.Domains, want)
		}
	}

	// 原对象不能被改动：调用方拿的还是配置里那份。
	if len(cert.Domains) != 3 {
		t.Fatalf("不该就地修改调用方传进来的证书，实际 %v", cert.Domains)
	}

	// 降级状态必须落盘 —— 它是"现在有一张缺名字的证书在服务"的唯一记录。
	fb, err := store.GetFallback(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if fb == nil {
		t.Fatal("降级状态必须落盘，否则没人知道证书少了几个名字")
	}
	if len(fb.Dropped) != 1 || fb.Dropped[0] != "b.example.com" {
		t.Errorf("记录的被摘名字 = %v，期望 [b.example.com]", fb.Dropped)
	}
	if fb.Reason == "" {
		t.Error("降级必须带上原因")
	}
}

// 剩下的名字太少就拒绝降级：那是"全挂"换了个样子，
// 却会让人以为还有部分可用。
func TestFallbackRefusesWhenItWouldDropTooMany(t *testing.T) {
	store, m, cert, now := fallbackFixture(t, fallbackPolicyPtr())

	// a 和 b 都反复失败，只剩 c 一个 —— 而下限是 2。
	for _, id := range []string{"a.example.com", "b.example.com"} {
		for i := 0; i < 3; i++ {
			if err := store.RecordIdentifierFailure(cert.Name, id, "dns says no", now); err != nil {
				t.Fatal(err)
			}
		}
	}

	p := fallbackPolicy()
	p.MinNames = 2
	m.SetFallbackPolicy(p)

	st := &state.CertState{
		Name:                cert.Name,
		NotAfter:            now.Add(24 * time.Hour),
		ConsecutiveFailures: 9,
	}

	if got := m.applyFallback(cert, st); len(got.Domains) != 3 {
		t.Fatalf("剩下的名字少于下限时应当拒绝降级，实际 %v", got.Domains)
	}
	if fb, _ := store.GetFallback(cert.Name); fb != nil {
		t.Error("拒绝降级时不该留下降级记录")
	}
}

// 老失败记录不参与 —— 那正是自愈的入口。
//
// 被摘掉的名字永远不会再被尝试，所以它等不到一次"成功"来洗白自己；
// 唯一的出路就是记录老化。
func TestFallbackIgnoresStaleFailures(t *testing.T) {
	store, m, cert, now := fallbackFixture(t, fallbackPolicyPtr())

	stale := now.Add(-48 * time.Hour) // 窗口是 24h
	for i := 0; i < 5; i++ {
		if err := store.RecordIdentifierFailure(cert.Name, "b.example.com", "dns says no", stale); err != nil {
			t.Fatal(err)
		}
	}

	st := &state.CertState{
		Name:                cert.Name,
		NotAfter:            now.Add(24 * time.Hour),
		ConsecutiveFailures: 9,
	}
	if got := m.applyFallback(cert, st); len(got.Domains) != 3 {
		t.Fatalf("超过失败窗口的记录不该再参与降级，实际 %v", got.Domains)
	}
}

// 恢复之后要能自己走出去，并且把账本清掉。
func TestFallbackClearsItselfOnceTheNamesAreHealthy(t *testing.T) {
	store, m, cert, now := fallbackFixture(t, fallbackPolicyPtr())

	if err := store.PutFallback(&state.Fallback{
		CertName: cert.Name,
		Dropped:  []string{"b.example.com"},
		Since:    now.Add(-time.Hour),
		Reason:   "earlier",
	}); err != nil {
		t.Fatal(err)
	}

	// 这一轮没有任何 identifier 在失败 → 用全集。
	st := &state.CertState{
		Name:                cert.Name,
		NotAfter:            now.Add(24 * time.Hour),
		ConsecutiveFailures: 0,
	}
	if got := m.applyFallback(cert, st); len(got.Domains) != 3 {
		t.Fatalf("应当回到全集，实际 %v", got.Domains)
	}

	fb, err := store.GetFallback(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if fb != nil {
		t.Errorf("回到全集之后降级记录应当被清掉，实际 %+v", fb)
	}
}
