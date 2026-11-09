package main

import (
	"reflect"
	"testing"
)

// testHY2Backend 创建带稳定 key 的测试订阅节点。
// 示例：testHY2Backend("kr") -> BackendKey() == "kr"。
func testHY2Backend(key string) ProxyBackend {
	return &HY2Backend{
		Key:      key,
		Name:     key,
		Server:   key + ".example.com",
		Port:     443,
		Password: "secret",
	}
}

// TestReconcileSubscriptionReferences 验证订阅节点消失后清理全部引用并保留空组。
func TestReconcileSubscriptionReferences(t *testing.T) {
	krRef := "sub.main.kr"
	jpRef := "sub.main.jp"
	emptyGroupTag := RuntimeBackendTag("group", "empty")
	cfg := DefaultConfig()
	cfg.Backend.Subscription = []Subscription{{Key: "main", Name: "main", Default: "kr", Enabled: true}}
	cfg.Backend.Static = []StaticBackend{
		{Key: "via-kr", Detour: krRef},
		{Key: "via-empty", Detour: "group.empty"},
		{Key: "untouched", Detour: jpRef},
	}
	cfg.Backend.Groups = []DynamicGroupConfig{
		{Key: "failover", Mode: dynamicGroupModePrimaryBackup, Primary: krRef, Members: []string{krRef, jpRef}},
		{Key: "empty", Mode: dynamicGroupModeDynamic, Members: []string{krRef}},
		{Key: "healthy", Mode: dynamicGroupModeDynamic, Members: []string{jpRef}},
	}
	cfg.Policy.Default = emptyGroupTag
	cfg.Policy.Fallback = []string{RuntimeBackendTag("sub-main", "kr"), RuntimeBackendTag("sub-main", "jp")}
	cfg.Policy.DynamicOutbound = []DynamicOutboundRule{
		{Match: "domain:removed.example", Outbound: RuntimeBackendTag("sub-main", "kr")},
		{Match: "domain:empty.example", Outbound: emptyGroupTag},
		{Match: "domain:keep.example", Outbound: RuntimeBackendTag("sub-main", "jp")},
	}

	next, report := ReconcileSubscriptionReferences(
		cfg,
		"main",
		[]ProxyBackend{testHY2Backend("kr"), testHY2Backend("jp")},
		[]ProxyBackend{testHY2Backend("jp")},
	)

	if !report.Changed {
		t.Fatal("节点消失后应该报告配置已变化")
	}
	wantWarnings := []MissingPrimaryWarningItem{{Group: "failover", Member: krRef}}
	if !reflect.DeepEqual(report.MissingPrimaries, wantWarnings) {
		t.Fatalf("主节点告警错误: %#v", report.MissingPrimaries)
	}
	if got := next.Backend.Groups[0]; got.Primary != "" || !reflect.DeepEqual(got.Members, []string{jpRef}) {
		t.Fatalf("主备组清理错误: %#v", got)
	}
	if got := next.Backend.Groups[1]; len(got.Members) != 0 {
		t.Fatalf("空组应该保留但没有成员: %#v", got)
	}
	if len(next.Backend.Groups) != 3 {
		t.Fatalf("动态组不应被删除: %#v", next.Backend.Groups)
	}
	if next.Policy.Default != "" {
		t.Fatalf("空组默认出口应该清空: %q", next.Policy.Default)
	}
	if !reflect.DeepEqual(next.Policy.Fallback, []string{RuntimeBackendTag("sub-main", "jp")}) {
		t.Fatalf("fallback 清理错误: %#v", next.Policy.Fallback)
	}
	if len(next.Policy.DynamicOutbound) != 1 || next.Policy.DynamicOutbound[0].Match != "domain:keep.example" {
		t.Fatalf("动态出口清理错误: %#v", next.Policy.DynamicOutbound)
	}
	if next.Backend.Static[0].Detour != "" || next.Backend.Static[1].Detour != "" || next.Backend.Static[2].Detour != jpRef {
		t.Fatalf("detour 清理错误: %#v", next.Backend.Static)
	}
	if next.Backend.Subscription[0].Default != "" {
		t.Fatalf("订阅默认节点应该清空: %q", next.Backend.Subscription[0].Default)
	}
	if cfg.Backend.Groups[0].Primary != krRef || len(cfg.Backend.Groups[1].Members) != 1 {
		t.Fatalf("输入配置不应被原地修改: %#v", cfg.Backend.Groups)
	}
}

// TestReconcileSubscriptionReferencesUnchanged 验证订阅节点未减少时配置保持不变。
func TestReconcileSubscriptionReferencesUnchanged(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Backend.Groups = []DynamicGroupConfig{{Key: "main", Members: []string{"sub.main.jp"}}}
	next, report := ReconcileSubscriptionReferences(
		cfg,
		"main",
		[]ProxyBackend{testHY2Backend("jp")},
		[]ProxyBackend{testHY2Backend("jp"), testHY2Backend("sg")},
	)
	if report.Changed || len(report.MissingPrimaries) != 0 {
		t.Fatalf("仅新增节点不应触发清理: %#v", report)
	}
	if !reflect.DeepEqual(next.Backend.Groups, cfg.Backend.Groups) {
		t.Fatalf("仅新增节点不应修改组: %#v", next.Backend.Groups)
	}
}

// TestNormalizeDynamicGroupPrimaryKeepsMissingPrimaryEmpty 验证缺失主节点不会被静默改成备节点。
func TestNormalizeDynamicGroupPrimaryKeepsMissingPrimaryEmpty(t *testing.T) {
	if got := normalizeDynamicGroupPrimary(dynamicGroupModePrimaryBackup, "", []string{"sub.main.jp"}); got != "" {
		t.Fatalf("空主节点应该保持为空: %q", got)
	}
}
