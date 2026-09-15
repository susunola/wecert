//go:build unix

package state

import "syscall"

// setUmask 临时设置进程 umask，并返回原值以便还原。
//
// 只用于测试：想证明文件权限是代码显式设置的，就必须在一个"什么都不挡"的
// umask 下验证 —— 用 umask 077 跑出来的 0600 是 umask 的功劳，不是代码的。
func setUmask(mask int) int { return syscall.Umask(mask) }
