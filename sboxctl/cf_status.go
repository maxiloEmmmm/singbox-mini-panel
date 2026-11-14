package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const defaultCFOutboundStatusDirectory = "/run/sboxctl/cf-outbound"

// CFOutboundRuntimeStatus 表示 sing-box CF outbound 暴露的无凭据运行状态。
//
// Example: static-cf-main -> HKG and connected=true.
type CFOutboundRuntimeStatus struct {
	// Tag 是 sing-box outbound 的唯一标识。
	Tag string `json:"tag"`
	// Colo 是本次 WSS 握手命中的 Cloudflare POP。
	Colo string `json:"colo"`
	// Connected 表示记录对应的载体当前仍连接。
	Connected bool `json:"connected"`
	// ConnectedAt 是最近成功建立 WSS 的 UTC 时间。
	ConnectedAt string `json:"connected_at"`
}

// LoadCFOutboundStatuses 读取由 sing-box 原子发布的全部 CF 运行状态。
//
// Example: 不存在的 /run 目录返回空 map，单个坏文件不丢弃其他有效状态。
func LoadCFOutboundStatuses(directory string) (map[string]CFOutboundRuntimeStatus, error) {
	statuses := make(map[string]CFOutboundRuntimeStatus)
	entries, err := os.ReadDir(directory)
	if os.IsNotExist(err) {
		return statuses, nil
	}
	if err != nil {
		return statuses, err
	}
	var lastErr error
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			lastErr = readErr
			continue
		}
		var status CFOutboundRuntimeStatus
		if decodeErr := json.Unmarshal(content, &status); decodeErr != nil {
			lastErr = fmt.Errorf("解析 CF outbound 状态 %s: %w", entry.Name(), decodeErr)
			continue
		}
		status.Tag = strings.TrimSpace(status.Tag)
		status.Colo = strings.ToUpper(strings.TrimSpace(status.Colo))
		if status.Tag == "" || !validCFColo(status.Colo) {
			lastErr = fmt.Errorf("CF outbound 状态 %s 字段非法", entry.Name())
			continue
		}
		statuses[status.Tag] = status
	}
	return statuses, lastErr
}

// validCFColo 验证面板只接收三位大写 Cloudflare POP 代码。
//
// Example: HKG returns true; hk and HKG1 return false.
func validCFColo(colo string) bool {
	if len(colo) != 3 {
		return false
	}
	for _, character := range colo {
		if character < 'A' || character > 'Z' {
			return false
		}
	}
	return true
}

// ApplyCFOutboundStatuses 把运行状态合并到同 tag 的 CF 静态节点。
//
// Example: status static-cf-main=HKG makes that node expose cf_colo=HKG.
func ApplyCFOutboundStatuses(nodes []WebBackend, statuses map[string]CFOutboundRuntimeStatus) {
	for index := range nodes {
		if nodes[index].Protocol != staticProtocolCF {
			continue
		}
		status, exists := statuses[nodes[index].Tag]
		if !exists {
			continue
		}
		nodes[index].CFColo = status.Colo
		nodes[index].CFConnected = status.Connected
		nodes[index].CFConnectedAt = status.ConnectedAt
	}
}
