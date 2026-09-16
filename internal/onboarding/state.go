package onboarding

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// State 是 onboarding 组件自己的持久化状态。
//
// 必须落盘，不能靠内存：onboarding 多半是定时任务，跑完就退出，
// 而"重启之后忘了这个名字已经缺席三天"会让删除宽限期永远走不完 ——
// 宽限期失效就等于删除变激进，那正是 §5.3 要防的事。
//
// 所有名字集合都用**展开后**的形式：通配符写成 "*.example.com" 单独占一项。
// 这样"通配符声明被删掉"和"具体名字声明被删掉"是两条独立的记录，
// 各自的宽限期互不干扰。
type State struct {
	// AbsentSince 记录每个"上轮在、这轮不见了"的名字第一次被观察到缺席的时刻。
	AbsentSince map[string]time.Time `json:"absentSince,omitempty"`

	// LastRevision 是上一版写出去的文档指纹。
	LastRevision string `json:"lastRevision,omitempty"`

	// LastNames 是上一版期望状态覆盖的展开名字集合，供骤变熔断比较。
	LastNames []string `json:"lastNames,omitempty"`

	// Changes 是最近若干次"名字集合真的变了"的时刻，用于配额预算。
	Changes []time.Time `json:"changes,omitempty"`

	// UpdatedAt 是最后一次成功写入时刻。
	UpdatedAt time.Time `json:"updatedAt,omitempty"`
}

// LoadState 读取状态文件。文件不存在视为空状态（第一次跑）。
func LoadState(path string) (*State, error) {
	st := &State{AbsentSince: map[string]time.Time{}}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return st, nil
		}
		return nil, fmt.Errorf("read onboarding state: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return st, nil
	}

	// 状态文件坏掉时**不能**当空状态用：那会让所有宽限期归零，
	// 也就是把删除从保守路径变成激进路径。宁可拒绝跑这一轮。
	if err := json.Unmarshal(data, st); err != nil {
		return nil, fmt.Errorf("parse onboarding state %s: %w", path, err)
	}
	if st.AbsentSince == nil {
		st.AbsentSince = map[string]time.Time{}
	}
	return st, nil
}

// Save 原子地写回状态文件。
func (s *State) Save(path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encode onboarding state: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".onboard-state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp state file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write onboarding state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync onboarding state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close onboarding state: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("chmod onboarding state: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	tmpName = ""
	return nil
}

// MarkPresent 清掉某个名字的缺席标记。名字回来了，宽限期就该重置。
func (s *State) MarkPresent(name string) {
	delete(s.AbsentSince, name)
}

// MarkAbsent 记录某个名字缺席，返回它最**早**一次被观察到缺席的时刻，
// 以及这次是不是新记录下来的。
//
// 保留最早的时刻而不是不断刷新，是因为宽限期问的是"它已经缺席多久了"，
// 不是"上次看到它缺席是什么时候"。
func (s *State) MarkAbsent(name string, now time.Time) (since time.Time, isNew bool) {
	if prev, ok := s.AbsentSince[name]; ok {
		return prev, false
	}
	s.AbsentSince[name] = now
	return now, true
}

// RecordChange 记下一次真实发生过的名字集合变更。
func (s *State) RecordChange(now time.Time) {
	s.Changes = append(s.Changes, now)
}

// ChangesWithin 返回 window 内发生过的集合变更次数，并顺手丢掉过期的记录。
func (s *State) ChangesWithin(window time.Duration, now time.Time) int {
	cutoff := now.Add(-window)
	kept := s.Changes[:0]
	n := 0
	for _, t := range s.Changes {
		if t.Before(cutoff) {
			continue
		}
		kept = append(kept, t)
		n++
	}
	s.Changes = kept
	return n
}

// LastNameSet 返回上一版名字集合，方便比较。
func (s *State) LastNameSet() map[string]bool {
	out := make(map[string]bool, len(s.LastNames))
	for _, n := range s.LastNames {
		out[n] = true
	}
	return out
}

// SetLastNames 记录这一版的名字集合，顺序稳定以便 diff 可读。
func (s *State) SetLastNames(names []string) {
	cp := append([]string(nil), names...)
	sort.Strings(cp)
	s.LastNames = cp
}
