package main

import "strings"

// SubscriptionReconcileReport 描述订阅节点消失后自动清理的配置引用。
type SubscriptionReconcileReport struct {
	// Changed 表示配置内容是否被清理。
	Changed bool
	// MissingPrimaries 保存被删除的主备组主节点。
	MissingPrimaries []MissingPrimaryWarningItem
}

// ReconcileSubscriptionReferences 清理指定订阅已消失节点的全部配置引用。
// 示例：main 删除 kr -> 从组成员移除 sub.main.kr，并清空命中的出口规则。
func ReconcileSubscriptionReferences(cfg Config, subKey string, oldNodes []ProxyBackend, newNodes []ProxyBackend) (Config, SubscriptionReconcileReport) {
	cfg.Backend.Static = append([]StaticBackend(nil), cfg.Backend.Static...)
	cfg.Backend.Subscription = append([]Subscription(nil), cfg.Backend.Subscription...)
	cfg.Backend.Groups = append([]DynamicGroupConfig(nil), cfg.Backend.Groups...)
	for index := range cfg.Backend.Groups {
		cfg.Backend.Groups[index].Members = append([]string(nil), cfg.Backend.Groups[index].Members...)
	}
	cfg.Policy.DynamicOutbound = append([]DynamicOutboundRule(nil), cfg.Policy.DynamicOutbound...)
	removedKeys := removedSubscriptionNodeKeys(oldNodes, newNodes)
	if len(removedKeys) == 0 {
		return cfg, SubscriptionReconcileReport{}
	}

	removedRefs := map[string]bool{}
	removedTargets := map[string]bool{}
	for _, node := range oldNodes {
		key := node.BackendKey()
		if !removedKeys[key] {
			continue
		}
		removedRefs["sub."+subKey+"."+key] = true
		addRemovedTarget(removedTargets, key)
		addRemovedTarget(removedTargets, node.BackendName())
		addRemovedTarget(removedTargets, RuntimeBackendTag("sub-"+subKey, key))
	}

	report := SubscriptionReconcileReport{}
	for index := range cfg.Backend.Groups {
		group := &cfg.Backend.Groups[index]
		members := make([]string, 0, len(group.Members))
		for _, member := range group.Members {
			if removedRefs[strings.TrimSpace(member)] {
				report.Changed = true
				continue
			}
			members = append(members, member)
		}
		group.Members = members
		if normalizeDynamicGroupMode(group.Mode) == dynamicGroupModePrimaryBackup && removedRefs[strings.TrimSpace(group.Primary)] {
			report.MissingPrimaries = append(report.MissingPrimaries, MissingPrimaryWarningItem{
				Group:  group.Key,
				Member: group.Primary,
			})
			group.Primary = ""
			report.Changed = true
		}
		if len(group.Members) == 0 {
			addRemovedTarget(removedTargets, RuntimeBackendTag("group", group.Key))
			addRemovedTarget(removedTargets, group.Key)
			addRemovedTarget(removedTargets, group.Name)
			removedRefs["group."+group.Key] = true
		}
	}

	if removedTargets[strings.TrimSpace(cfg.Policy.Default)] || removedTargets[SanitizeTag(cfg.Policy.Default)] {
		cfg.Policy.Default = ""
		report.Changed = true
	}
	fallback := make([]string, 0, len(cfg.Policy.Fallback))
	for _, outbound := range cfg.Policy.Fallback {
		if removedTargets[strings.TrimSpace(outbound)] || removedTargets[SanitizeTag(outbound)] {
			report.Changed = true
			continue
		}
		fallback = append(fallback, outbound)
	}
	cfg.Policy.Fallback = fallback
	for index := range cfg.Backend.Subscription {
		sub := &cfg.Backend.Subscription[index]
		if sub.Key != subKey {
			continue
		}
		if removedTargets[strings.TrimSpace(sub.Default)] || removedTargets[SanitizeTag(sub.Default)] {
			sub.Default = ""
			report.Changed = true
		}
	}

	dynamicRules := make([]DynamicOutboundRule, 0, len(cfg.Policy.DynamicOutbound))
	for _, rule := range cfg.Policy.DynamicOutbound {
		if removedTargets[strings.TrimSpace(rule.Outbound)] || removedTargets[SanitizeTag(rule.Outbound)] {
			report.Changed = true
			continue
		}
		dynamicRules = append(dynamicRules, rule)
	}
	cfg.Policy.DynamicOutbound = dynamicRules

	for index := range cfg.Backend.Static {
		detour := strings.TrimSpace(cfg.Backend.Static[index].Detour)
		if removedRefs[detour] {
			cfg.Backend.Static[index].Detour = ""
			report.Changed = true
		}
	}
	return cfg, report
}

// removedSubscriptionNodeKeys 返回旧订阅中已经不在新订阅里的节点 key。
// 示例：[jp,kr] 与 [jp] -> {kr:true}。
func removedSubscriptionNodeKeys(oldNodes []ProxyBackend, newNodes []ProxyBackend) map[string]bool {
	MakeUniqueBackendKeys(oldNodes)
	MakeUniqueBackendKeys(newNodes)
	current := map[string]bool{}
	for _, node := range newNodes {
		current[node.BackendKey()] = true
	}
	removed := map[string]bool{}
	for _, node := range oldNodes {
		if !current[node.BackendKey()] {
			removed[node.BackendKey()] = true
		}
	}
	return removed
}

// addRemovedTarget 添加一个配置出口可能使用的原始值和清洗值。
// 示例："HK Node" -> 同时记录 "HK Node" 和 "hk-node"。
func addRemovedTarget(targets map[string]bool, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	targets[value] = true
	targets[SanitizeTag(value)] = true
}
