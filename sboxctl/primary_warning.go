package main

import "sync"

// MissingPrimaryWarningItem 表示一个因订阅刷新而消失的主备组主节点。
type MissingPrimaryWarningItem struct {
	// Group 是受影响的动态组 key。
	Group string `json:"group"`
	// Member 是已经消失的主节点引用。
	Member string `json:"member"`
}

// PrimaryMissingWarning 是页面必须确认的唯一内存告警。
type PrimaryMissingWarning struct {
	// ID 是告警版本，防止旧页面确认掉更新后的告警。
	ID uint64 `json:"id"`
	// Items 保存全部尚未确认的主节点缺失事件。
	Items []MissingPrimaryWarningItem `json:"items"`
}

// PrimaryWarningStore 保存当前进程内唯一的主节点缺失告警。
type PrimaryWarningStore struct {
	// Mutex 保护告警版本和内容。
	Mutex sync.Mutex
	// Warning 是当前尚未确认的告警。
	Warning *PrimaryMissingWarning
	// NextID 是下一次内容变化使用的版本号。
	NextID uint64
}

// NewPrimaryWarningStore 创建空告警存储。
// 示例：NewPrimaryWarningStore() -> Snapshot() == nil。
func NewPrimaryWarningStore() *PrimaryWarningStore {
	return &PrimaryWarningStore{NextID: 1}
}

// primaryWarningStore 返回 App 的共享告警存储，并兼容手工构造的 App。
// 示例：PrimaryWarnings 为空 -> 创建一个空存储。
func (a *App) primaryWarningStore() *PrimaryWarningStore {
	if a.PrimaryWarnings == nil {
		a.PrimaryWarnings = NewPrimaryWarningStore()
	}
	return a.PrimaryWarnings
}

// Record 合并主节点缺失项，并按 group/member 去重。
// 示例：重复写入 main/kr -> 唯一告警中只保留一项。
func (s *PrimaryWarningStore) Record(items []MissingPrimaryWarningItem) {
	if s == nil || len(items) == 0 {
		return
	}
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	merged := make([]MissingPrimaryWarningItem, 0, len(items))
	seen := map[string]bool{}
	if s.Warning != nil {
		for _, item := range s.Warning.Items {
			key := item.Group + "\x00" + item.Member
			seen[key] = true
			merged = append(merged, item)
		}
	}
	changed := false
	for _, item := range items {
		key := item.Group + "\x00" + item.Member
		if seen[key] {
			continue
		}
		seen[key] = true
		merged = append(merged, item)
		changed = true
	}
	if !changed {
		return
	}
	s.Warning = &PrimaryMissingWarning{ID: s.NextID, Items: merged}
	s.NextID++
}

// Snapshot 返回当前告警副本，避免响应序列化读取共享切片。
// 示例：记录一项后 Snapshot() 返回含一项的新对象。
func (s *PrimaryWarningStore) Snapshot() *PrimaryMissingWarning {
	if s == nil {
		return nil
	}
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	if s.Warning == nil {
		return nil
	}
	return &PrimaryMissingWarning{
		ID:    s.Warning.ID,
		Items: append([]MissingPrimaryWarningItem(nil), s.Warning.Items...),
	}
}

// Acknowledge 仅在版本匹配时清空告警。
// 示例：当前 ID 为 2，确认 1 -> false；确认 2 -> true。
func (s *PrimaryWarningStore) Acknowledge(id uint64) bool {
	if s == nil {
		return false
	}
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	if s.Warning == nil || s.Warning.ID != id {
		return false
	}
	s.Warning = nil
	return true
}
