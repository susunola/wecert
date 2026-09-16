package state

import (
	"path/filepath"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("打开状态库失败: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestIdentifierFailureLedgerCounts(t *testing.T) {
	s := newStore(t)
	now := time.Now().Truncate(time.Second)

	for i := 0; i < 3; i++ {
		if err := s.RecordIdentifierFailure("c1", "bad.example.com", "dns says no", now); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RecordIdentifierFailure("c1", "good.example.com", "one blip", now); err != nil {
		t.Fatal(err)
	}

	got, err := s.ListIdentifierFailures("c1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("应当有两条记录，实际 %d", len(got))
	}
	// 按 identifier 排序，保证同样的输入给出同样的输出。
	if got[0].Identifier != "bad.example.com" || got[0].Failures != 3 {
		t.Errorf("第一条 = %+v，期望 bad.example.com 计 3 次", got[0])
	}
	if got[1].Identifier != "good.example.com" || got[1].Failures != 1 {
		t.Errorf("第二条 = %+v", got[1])
	}
	if !got[0].LastFailedAt.Equal(now) {
		t.Errorf("LastFailedAt = %v，期望 %v", got[0].LastFailedAt, now)
	}
}

// 账本是按证书隔离的：一张证书的坏名字不该影响另一张。
func TestIdentifierFailureLedgerIsPerCertificate(t *testing.T) {
	s := newStore(t)
	now := time.Now()

	if err := s.RecordIdentifierFailure("c1", "bad.example.com", "x", now); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListIdentifierFailures("c2")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("另一张证书不该看到这条记录，实际 %v", got)
	}
}

func TestClearIdentifierFailures(t *testing.T) {
	s := newStore(t)
	now := time.Now()

	if err := s.RecordIdentifierFailure("c1", "bad.example.com", "x", now); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearIdentifierFailures("c1"); err != nil {
		t.Fatal(err)
	}

	got, err := s.ListIdentifierFailures("c1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("清理之后应当为空，实际 %v", got)
	}
}

// 老记录必须能被丢掉：被摘掉的名字永远不会再被尝试，
// 所以它等不到一次成功来洗白自己，唯一的出路就是过期。
func TestPruneIdentifierFailuresDropsOnlyStaleRows(t *testing.T) {
	s := newStore(t)
	now := time.Now().Truncate(time.Second)

	if err := s.RecordIdentifierFailure("c1", "stale.example.com", "x", now.Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordIdentifierFailure("c1", "fresh.example.com", "x", now); err != nil {
		t.Fatal(err)
	}

	if err := s.PruneIdentifierFailures("c1", now, 24*time.Hour); err != nil {
		t.Fatal(err)
	}

	got, err := s.ListIdentifierFailures("c1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Identifier != "fresh.example.com" {
		t.Fatalf("只该留下新鲜的记录，实际 %v", got)
	}
}

func TestFallbackRoundTrip(t *testing.T) {
	s := newStore(t)
	now := time.Now().Truncate(time.Second)

	fb, err := s.GetFallback("c1")
	if err != nil {
		t.Fatal(err)
	}
	if fb != nil {
		t.Fatalf("没有记录时应当返回 nil，实际 %+v", fb)
	}

	if err := s.PutFallback(&Fallback{
		CertName: "c1",
		// 故意乱序：落盘时应当排序，读回来才稳定。
		Dropped: []string{"z.example.com", "a.example.com"},
		Since:   now,
		Reason:  "keeps failing",
	}); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetFallback("c1")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("应当读回降级记录")
	}
	if len(got.Dropped) != 2 || got.Dropped[0] != "a.example.com" || got.Dropped[1] != "z.example.com" {
		t.Errorf("被摘名字应当排序后读出，实际 %v", got.Dropped)
	}
	if !got.Since.Equal(now) {
		t.Errorf("Since = %v，期望 %v", got.Since, now)
	}
	if got.Reason != "keeps failing" {
		t.Errorf("Reason = %q", got.Reason)
	}

	if err := s.ClearFallback("c1"); err != nil {
		t.Fatal(err)
	}
	if again, err := s.GetFallback("c1"); err != nil || again != nil {
		t.Fatalf("清理之后应当为空，实际 %+v, %v", again, err)
	}
}
