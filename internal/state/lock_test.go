//go:build unix

package state

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain 兼作"崩溃的子进程"入口。
//
// 这里要验的是 flock 相对 PID 文件最关键的那条性质：进程死掉时内核会自动
// 释放锁。那件事没法在本进程里测 —— 只能起一个子进程，让它拿了锁之后
// 直接 os.Exit，不调用 Close。
func TestMain(m *testing.M) {
	if os.Getenv("WECERT_LOCK_HELPER") == "1" {
		s, err := Open(os.Getenv("WECERT_LOCK_PATH"))
		if err != nil {
			os.Stderr.WriteString("helper: " + err.Error() + "\n")
			os.Exit(3)
		}
		_ = s // 故意不 Close：模拟被 kill -9
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func lockTestPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "state.db")
}

// 这道闸门存在的理由：daemon 和 timer 同时启用时，两个进程各自持有
// "每张证书最多一个在飞订单"的局部视图，于是并发下单 —— 而撞上的是
// 7 天不可恢复的 exact-set 限额。
func TestOpenTakesAnExclusiveLock(t *testing.T) {
	path := lockTestPath(t)

	first, err := Open(path)
	if err != nil {
		t.Fatalf("第一次打开失败: %v", err)
	}
	defer first.Close()

	_, err = Open(path)
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("第二次打开应当拿到 ErrLocked，实际: %v", err)
	}
	// 错误信息要能看出是哪个文件被占了，否则多实例排查会很难受。
	if !strings.Contains(err.Error(), "state.db.lock") {
		t.Errorf("错误信息应当带上锁文件路径，实际: %v", err)
	}
}

func TestCloseReleasesTheLock(t *testing.T) {
	path := lockTestPath(t)

	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	second, err := Open(path)
	if err != nil {
		t.Fatalf("释放之后应当能重新打开，实际: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

// -dry-run 那条路径必须能在 daemon 正在跑的时候工作。
//
// 它只读已有的 ACME 账号、不发起签发，所以不取锁是安全的；
// 而"因为 daemon 在跑所以连配置都校验不了"会把人逼去瞎改配置。
func TestOpenUnlockedIgnoresTheLock(t *testing.T) {
	path := lockTestPath(t)

	held, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	unlocked, err := OpenUnlocked(path)
	if err != nil {
		t.Fatalf("不取锁的路径不该被挡住，实际: %v", err)
	}
	if err := unlocked.Close(); err != nil {
		t.Fatal(err)
	}

	// 而且它不能把别人的锁放掉。
	if _, err := Open(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("不取锁的 Close 不该释放别人的锁，实际: %v", err)
	}
}

// 这是选 flock 而不是 PID 文件的原因：崩溃之后不留陈旧锁。
//
// 换成一个 PID 文件的话，被 kill -9 之后会留下一个永远删不掉的锁，
// 而它最终一定会被人手动 rm 掉 —— 那时这道保护就形同虚设了。
func TestLockIsReleasedWhenTheProcessDiesWithoutClosing(t *testing.T) {
	path := lockTestPath(t)

	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(),
		"WECERT_LOCK_HELPER=1",
		"WECERT_LOCK_PATH="+path,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("子进程失败: %v\n%s", err, out)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("进程死后不该留下陈旧锁，实际: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

// 锁必须在建库文件之前拿到：两个进程同时初始化一个空库比同时写一个
// 已有库更难排查，因为它们会各自建出不同的表结构。
func TestLockFileIsCreatedNextToTheDatabase(t *testing.T) {
	path := lockTestPath(t)

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, err := os.Stat(path + ".lock"); err != nil {
		t.Fatalf("应当生成锁文件: %v", err)
	}
}
