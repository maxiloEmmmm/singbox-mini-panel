package main

import (
	"reflect"
	"testing"
)

// TestPrimaryWarningStore 验证唯一告警会合并去重并按版本确认。
func TestPrimaryWarningStore(t *testing.T) {
	store := NewPrimaryWarningStore()
	if store.Snapshot() != nil {
		t.Fatal("新告警存储应该为空")
	}
	mainKR := MissingPrimaryWarningItem{Group: "main", Member: "sub.main.kr"}
	videoJP := MissingPrimaryWarningItem{Group: "video", Member: "sub.main.jp"}
	store.Record([]MissingPrimaryWarningItem{mainKR, mainKR})
	first := store.Snapshot()
	if first == nil || first.ID != 1 || !reflect.DeepEqual(first.Items, []MissingPrimaryWarningItem{mainKR}) {
		t.Fatalf("首次告警内容错误: %#v", first)
	}
	store.Record([]MissingPrimaryWarningItem{mainKR})
	if got := store.Snapshot(); got.ID != first.ID {
		t.Fatalf("重复告警不应改变版本: %#v", got)
	}
	store.Record([]MissingPrimaryWarningItem{videoJP})
	second := store.Snapshot()
	if second.ID == first.ID || !reflect.DeepEqual(second.Items, []MissingPrimaryWarningItem{mainKR, videoJP}) {
		t.Fatalf("新增告警应该合并并更新版本: %#v", second)
	}
	if store.Acknowledge(first.ID) {
		t.Fatal("旧页面不应确认掉新版告警")
	}
	if !store.Acknowledge(second.ID) || store.Snapshot() != nil {
		t.Fatal("当前版本确认后应该清空内存告警")
	}
}
