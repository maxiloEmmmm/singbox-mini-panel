package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	defaultDNSHealthInterval  = 5 * time.Minute
	defaultDNSProbeTimeout    = 3 * time.Second
	defaultDNSProbeAttempts   = 3
	defaultDNSRestartCooldown = 5 * time.Minute
	defaultDNSProbeAddress    = "119.29.29.29:53"
	defaultDirectProbeSuffix  = "qq.com"
	defaultRemoteProbeSuffix  = "example.net"
)

// DNSHealthConfig 描述 DNS 自愈策略，适用于旁路由持续检查 hijack-dns 数据面。
// 示例：Interval=5m -> 每 5 分钟检查一次远程 DNS 链路。
type DNSHealthConfig struct {
	// Interval 是周期兜底检查间隔。
	Interval time.Duration
	// ProbeTimeout 是单次 DNS 查询超时时间。
	ProbeTimeout time.Duration
	// ProbeAttempts 是判定链路失败前的连续查询次数。
	ProbeAttempts int
	// RestartCooldown 是两次自动重启之间的最短间隔。
	RestartCooldown time.Duration
	// ResolverAddress 是被 auto_redirect 劫持的 DNS 目标地址。
	ResolverAddress string
	// DirectProbeSuffix 是命中 direct-dns 规则的探针域名后缀。
	DirectProbeSuffix string
	// RemoteProbeSuffix 是命中 remote-dns 最终规则的探针域名后缀。
	RemoteProbeSuffix string
}

// DNSHealthMonitor 检查 DNS 分流并在远程链路独立故障时执行恢复。
// 示例：remote 失败且 direct 正常 -> 调用 Restart。
type DNSHealthMonitor struct {
	// Config 保存探针间隔、域名和恢复冷却策略。
	Config DNSHealthConfig
	// Logger 记录 DNS 故障分类和恢复结果。
	Logger *Logger
	// Restart 重建 sing-box 数据面，由 App 初始化时注入。
	Restart func() error
	// TriggerC 合并日志和 selector 产生的即时检查请求。
	TriggerC chan string
	// Mutex 保护最近一次自动重启时间。
	Mutex sync.Mutex
	// LastRestartAt 是最近一次 DNS 自愈重启开始时间。
	LastRestartAt time.Time
}

// DefaultDNSHealthConfig 返回旁路由使用的 DNS 自愈参数。
// 示例：DefaultDNSHealthConfig().Interval -> 5m。
func DefaultDNSHealthConfig() DNSHealthConfig {
	return DNSHealthConfig{
		Interval:          defaultDNSHealthInterval,
		ProbeTimeout:      defaultDNSProbeTimeout,
		ProbeAttempts:     defaultDNSProbeAttempts,
		RestartCooldown:   defaultDNSRestartCooldown,
		ResolverAddress:   defaultDNSProbeAddress,
		DirectProbeSuffix: defaultDirectProbeSuffix,
		RemoteProbeSuffix: defaultRemoteProbeSuffix,
	}
}

// NewDNSHealthMonitor 创建串行 DNS 健康监控器。
// 示例：NewDNSHealthMonitor(cfg, logger, restart) -> 可运行监控器。
func NewDNSHealthMonitor(config DNSHealthConfig, logger *Logger, restart func() error) *DNSHealthMonitor {
	return &DNSHealthMonitor{
		Config:   config,
		Logger:   logger,
		Restart:  restart,
		TriggerC: make(chan string, 1),
	}
}

// Run 周期检查 DNS，并处理日志或 selector 发出的即时检查。
// 示例：go monitor.Run(ctx) -> 直到 ctx 取消后退出。
func (m *DNSHealthMonitor) Run(ctx context.Context) {
	timer := time.NewTimer(m.Config.Interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			m.check(ctx, "periodic")
			timer.Reset(m.Config.Interval)
		case reason := <-m.TriggerC:
			m.check(ctx, reason)
		}
	}
}

// Trigger 请求一次即时检查，已有请求排队时直接合并。
// 示例：Trigger("selector changed") -> 最多排队一次检查。
func (m *DNSHealthMonitor) Trigger(reason string) {
	if m == nil {
		return
	}
	select {
	case m.TriggerC <- strings.TrimSpace(reason):
	default:
	}
}

// check 判断 remote-dns 是否独立故障，并按冷却策略恢复。
// 示例：remote 超时且 direct 有响应 -> 重启 sing-box。
func (m *DNSHealthMonitor) check(ctx context.Context, reason string) {
	remoteErr := m.probeWithRetries(ctx, m.Config.RemoteProbeSuffix)
	if remoteErr == nil {
		return
	}
	directErr := m.probeWithRetries(ctx, m.Config.DirectProbeSuffix)
	if directErr != nil {
		if m.Logger != nil {
			m.Logger.Warn("DNS 健康检查失败，direct 与 remote 均不可用 reason=%s direct=%v remote=%v", reason, directErr, remoteErr)
		}
		return
	}
	if !m.allowRestart(time.Now()) {
		if m.Logger != nil {
			m.Logger.Warn("remote-dns 失败但仍在重启冷却期 reason=%s err=%v", reason, remoteErr)
		}
		return
	}
	if m.Logger != nil {
		m.Logger.Warn("remote-dns 独立故障，开始重建 sing-box reason=%s err=%v", reason, remoteErr)
	}
	if m.Restart == nil {
		if m.Logger != nil {
			m.Logger.Error("remote-dns 自愈缺少重启函数")
		}
		return
	}
	if err := m.Restart(); err != nil {
		if m.Logger != nil {
			m.Logger.Error("remote-dns 自愈重启失败 err=%v", err)
		}
		return
	}
	if m.Logger != nil {
		m.Logger.Info("remote-dns 自愈重启完成")
	}
}

// probeWithRetries 连续检查同一 DNS 分支，任意一次响应即视为可用。
// 示例：Attempts=3，第二次返回 NXDOMAIN -> nil。
func (m *DNSHealthMonitor) probeWithRetries(ctx context.Context, suffix string) error {
	attempts := m.Config.ProbeAttempts
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for range attempts {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		probeCtx, cancel := context.WithTimeout(ctx, m.Config.ProbeTimeout)
		lastErr = m.probe(probeCtx, suffix)
		cancel()
		if lastErr == nil {
			return nil
		}
	}
	return lastErr
}

// probe 通过实际 hijack-dns 路径查询随机域名，避免缓存掩盖故障。
// 示例：health-abcd.example.net 返回 NXDOMAIN -> nil。
func (m *DNSHealthMonitor) probe(ctx context.Context, suffix string) error {
	// 触发条件：探针运行在旁路由本机。
	// 本机 LAN 地址会走 lo 并跳过 OUTPUT DNS 劫持，不能代表客户端路径。
	// 使用公网 DNS 地址可进入 auto_redirect，防止探针绕开 sing-box。
	resolver := &net.Resolver{
		PreferGo:     true,
		StrictErrors: true,
		Dial: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, network, m.Config.ResolverAddress)
		},
	}
	name := randomProbeDomain(suffix)
	_, err := resolver.LookupIP(ctx, "ip4", name)
	if err == nil || isDNSNotFound(err) {
		return nil
	}
	return fmt.Errorf("query %s: %w", name, err)
}

// allowRestart 记录并限制 DNS 自愈重启频率。
// 示例：上次重启在 1 分钟前且冷却为 5 分钟 -> false。
func (m *DNSHealthMonitor) allowRestart(now time.Time) bool {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()
	if !m.LastRestartAt.IsZero() && now.Sub(m.LastRestartAt) < m.Config.RestartCooldown {
		return false
	}
	m.LastRestartAt = now
	return true
}

// randomProbeDomain 生成不会命中 sing-box DNS 缓存的完整域名。
// 示例：randomProbeDomain("example.net") -> health-a1b2.example.net.。
func randomProbeDomain(suffix string) string {
	randomBytes := make([]byte, 6)
	if _, err := rand.Read(randomBytes); err == nil {
		return "health-" + hex.EncodeToString(randomBytes) + "." + strings.TrimSuffix(suffix, ".") + "."
	}
	return fmt.Sprintf("health-%x.%s.", time.Now().UnixNano(), strings.TrimSuffix(suffix, "."))
}

// isDNSNotFound 判断错误是否为有效 DNS NXDOMAIN 响应。
// 示例：net.DNSError{IsNotFound:true} -> true。
func isDNSNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// isDNSExchangeFailure 判断日志是否表示 sing-box DNS 上游交换失败。
// 示例："dns: exchange failed for example.net" -> true。
func isDNSExchangeFailure(payload string) bool {
	return strings.Contains(strings.ToLower(payload), "dns: exchange failed")
}
