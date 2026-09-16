//go:build !unix

package state

// fileLock 在非 Unix 平台上是空操作。
//
// wecert 的目标平台只有 linux 和 darwin，这条分支唯一的作用是让它在别的
// 平台上也编译得过。它**不提供跨进程保护**，这一点必须说清楚 ——
// 安静地假装成功比直接失败危险得多。
//
// 真的要在 Windows 上跑之前，这里需要换成 LockFileEx。
type fileLock struct{}

func acquireLock(string) (*fileLock, error) { return &fileLock{}, nil }

func (l *fileLock) release() error { return nil }
