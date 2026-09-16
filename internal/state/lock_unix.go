//go:build unix

package state

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// fileLock 是一个基于 flock 的跨进程排他锁。
//
// 为什么是 flock 而不是 PID 文件：内核会在进程退出时自动释放它 ——
// 包括被 kill -9 的情况。PID 文件在崩溃后会留下一个永远删不掉的陈旧锁，
// 而那种锁最终一定会被人手动 rm 掉，于是这道保护就形同虚设了。
type fileLock struct {
	f    *os.File
	path string
}

func acquireLock(path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create lock file %s: %w", path, err)
	}

	// LOCK_NB：拿不到就立刻失败，绝不在这里等。
	//
	// 等下去意味着一个误启动的进程会安静地排在前一个后面，等它退出之后
	// 突然开始签发 —— 那比直接报错危险得多：一次误操作会在几小时之后
	// 才显现，而那时已经没人记得自己启动过第二个进程了。
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		// EWOULDBLOCK 和 EAGAIN 在 Linux/macOS 上是同一个值，但不同平台的
		// syscall 包暴露的名字不完全一致，所以两个都认一下。
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("%w (lock file: %s)", ErrLocked, path)
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}

	return &fileLock{f: f, path: path}, nil
}

func (l *fileLock) release() error {
	if l == nil || l.f == nil {
		return nil
	}
	// 显式解锁再关闭。关闭本身也会释放，但显式做一遍让"锁是什么时候放的"
	// 在代码里可读，而不是依赖读者知道 close 的副作用。
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	return l.f.Close()
}
