package main

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	trafficStatsRetentionDays = 15
	trafficStatsPollInterval  = time.Second
)

// TrafficCounter 表示一个目标在单日内累计的代理流量。
type TrafficCounter struct {
	// UpCount 是累计上传字节数。
	UpCount int64 `json:"up_count"`
	// DownCount 是累计下载字节数。
	DownCount int64 `json:"down_count"`
}

// TrafficDailyResponse 表示内存中的每日代理流量快照。
type TrafficDailyResponse struct {
	// UpdatedAt 是最后一次成功采样时间，未采样时为空。
	UpdatedAt string `json:"updated_at"`
	// Days 按本地自然日和目标保存累计流量。
	Days map[string]map[string]TrafficCounter `json:"days"`
}

// trafficConnectionSample 表示一条代理连接上次采样到的累计值。
type trafficConnectionSample struct {
	// Upload 是上次采样时的累计上传字节数。
	Upload int64
	// Download 是上次采样时的累计下载字节数。
	Download int64
}

// TrafficStats 保存服务进程内的每日代理流量，适用于轻量历史排行。
type TrafficStats struct {
	// mutex 保护采样状态和每日累计值。
	mutex sync.RWMutex
	// days 按本地自然日和目标保存累计流量。
	days map[string]map[string]TrafficCounter
	// samples 保存活跃代理连接的上次累计值。
	samples map[string]trafficConnectionSample
	// updatedAt 是最后一次成功采样时间。
	updatedAt time.Time
}

// NewTrafficStats 创建空的内存流量统计器，例如启动服务时初始化。
// 示例：NewTrafficStats() -> 15 天容量的空统计器。
func NewTrafficStats() *TrafficStats {
	return &TrafficStats{
		days:    map[string]map[string]TrafficCounter{},
		samples: map[string]trafficConnectionSample{},
	}
}

// Run 每秒采样一次当前连接，适用于 daemon 或独立 Web 服务生命周期。
// 示例：Run(ctx, fetch) -> 持续更新内存统计直到 ctx 取消。
func (s *TrafficStats) Run(ctx context.Context, fetch func() (WebConnectionsResponse, error)) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			connections, err := fetch()
			if err == nil {
				s.Collect(time.Now(), connections.Connections)
			}
			timer.Reset(trafficStatsPollInterval)
		}
	}
}

// Collect 把当前代理连接累计值转换成增量，适用于每轮 Clash API 快照。
// 示例：连接下载从 10 增至 25 -> 当日目标下载增加 15。
func (s *TrafficStats) Collect(now time.Time, connections []WebConnection) {
	day := now.Format("2006-01-02")
	nextSamples := make(map[string]trafficConnectionSample, len(connections))

	s.mutex.Lock()
	defer s.mutex.Unlock()
	for _, connection := range connections {
		if connection.Decision != "proxy" || strings.TrimSpace(connection.ID) == "" {
			continue
		}
		target := trafficStatsTarget(connection)
		if target == "" {
			continue
		}
		current := trafficConnectionSample{Upload: connection.Upload, Download: connection.Download}
		previous := s.samples[connection.ID]
		upDelta := nonNegativeDelta(current.Upload, previous.Upload)
		downDelta := nonNegativeDelta(current.Download, previous.Download)
		nextSamples[connection.ID] = current
		if upDelta == 0 && downDelta == 0 {
			continue
		}
		if s.days[day] == nil {
			s.days[day] = map[string]TrafficCounter{}
		}
		counter := s.days[day][target]
		counter.UpCount += upDelta
		counter.DownCount += downDelta
		s.days[day][target] = counter
	}
	s.samples = nextSamples
	s.updatedAt = now
	s.pruneLocked()
}

// Snapshot 复制当前统计结果，适用于并发响应 Web API。
// 示例：Snapshot() -> 不共享内部 map 的只读响应。
func (s *TrafficStats) Snapshot() TrafficDailyResponse {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	days := make(map[string]map[string]TrafficCounter, len(s.days))
	for day, targets := range s.days {
		days[day] = make(map[string]TrafficCounter, len(targets))
		for target, counter := range targets {
			days[day][target] = counter
		}
	}
	updatedAt := ""
	if !s.updatedAt.IsZero() {
		updatedAt = s.updatedAt.Format(time.RFC3339)
	}
	return TrafficDailyResponse{UpdatedAt: updatedAt, Days: days}
}

// pruneLocked 删除保留窗口之外的自然日，调用方必须持有写锁。
// 示例：第 16 个自然日采样 -> 删除最早一天。
func (s *TrafficStats) pruneLocked() {
	days := make([]string, 0, len(s.days))
	for day := range s.days {
		days = append(days, day)
	}
	if len(days) <= trafficStatsRetentionDays {
		return
	}
	sort.Strings(days)
	for _, day := range days[:len(days)-trafficStatsRetentionDays] {
		delete(s.days, day)
	}
}

// trafficStatsTarget 返回统计目标，适用于域名优先、IP 兜底的归因。
// 示例：host=example.com -> example.com；host 为空 -> 目标 IP。
func trafficStatsTarget(connection WebConnection) string {
	if host := strings.TrimSpace(connection.Host); host != "" {
		return strings.ToLower(strings.TrimSuffix(host, "."))
	}
	return strings.TrimSpace(connection.DestinationIP)
}

// nonNegativeDelta 计算单调计数器增量，适用于计数异常回退时防止负数。
// 示例：25, 10 -> 15；5, 10 -> 5。
func nonNegativeDelta(current int64, previous int64) int64 {
	if current >= previous {
		return current - previous
	}
	return current
}
