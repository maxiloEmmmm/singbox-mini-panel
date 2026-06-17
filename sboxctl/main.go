package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	defaultConfigPath          = "/etc/sboxctl/config.yaml"
	defaultForceProxyPath      = "/etc/sboxctl/force_proxy.list"
	defaultForceDirectPath     = "/etc/sboxctl/force_direct.list"
	defaultGeoDir              = "/etc/sboxctl/geofiles"
	defaultSubscriptionDir     = "/etc/sboxctl/subscriptions"
	defaultSingBoxConfig       = "/etc/sing-box/config.json"
	defaultSingBoxBinary       = "/usr/bin/sing-box"
	defaultSingBoxWorkDir      = "/usr/share/sing-box"
	defaultMixedListen         = "0.0.0.0"
	defaultMixedPort           = 1080
	defaultBootstrapDNS        = "119.29.29.29"
	defaultDirectDNS           = "119.29.29.29"
	defaultRemoteDNSServer     = "cloudflare-dns.com"
	defaultRemoteDNSPath       = "/dns-query"
	defaultHostsPath           = "/etc/hosts"
	defaultHostsDNSTag         = "hosts-dns"
	defaultLogDir              = "/var/log/sboxctl"
	defaultLogMaxSize          = 5 * 1024 * 1024
	defaultLogMaxFiles         = 5
	defaultTimeout             = 120 * time.Second
	defaultSubscriptionUA      = "sing-box/1.13.12"
	defaultDownloadRetries     = 3
	defaultUpdateDNS           = "223.5.5.5:53"
	defaultStatePath           = "/etc/sboxctl/state.json"
	defaultWebListen           = "0.0.0.0"
	defaultWebPort             = 9000
	defaultWebTokenTTL         = "24h"
	defaultWebLockAttempts     = 3
	defaultWebLockDuration     = "1h"
	defaultClashAPIListen      = "127.0.0.1:9090"
	defaultCurrentSelector     = "current"
	defaultProbeURL            = "https://www.google.com/generate_204"
	defaultProbeTimeoutMS      = 2000
	defaultGroupProbeCycle     = 5 * time.Minute
	singBoxStopWarnAfter       = 5 * time.Second
	singBoxGracefulStopTimeout = 10 * time.Second
	singBoxReadyTimeout        = 500 * time.Millisecond
)

var groupProbeDelays = []time.Duration{5 * time.Second, 30 * time.Second, 60 * time.Second}

// Version 是编译期注入的编排器版本，未注入时显示 dev。
var Version = "dev"

// ProcessStartedAt 是当前 sboxctl 进程启动时间。
var ProcessStartedAt = time.Now()

// ErrNoAvailableBackend 表示当前配置无法生成 sing-box 数据面出口。
var ErrNoAvailableBackend = errors.New("没有可用 backend")

//go:embed web/dist/*
var embeddedWebAssets embed.FS

var (
	baseDirectRuleSets = []string{
		"geoip-private",
		"geosite-private",
		"geoip-cn",
		"geosite-cn",
		"geosite-geolocation-cn",
	}
	noFakeIPDomains = []string{
		"amobile.music.tc.qq.com",
		"api-jooxtt.sanook.com",
		"api.joox.com",
		"aqqmusic.tc.qq.com",
		"dl.stream.qqmusic.qq.com",
		"ff.dorado.sdo.com",
		"heartbeat.belkin.com",
		"isure.stream.qq.com",
		"joox.com",
		"lens.l.google.com",
		"localhost.ptlogin2.qq.com",
		"localhost.sec.qq.com",
		"mesu.apple.com",
		"mobileoc.music.tc.qq.com",
		"music.taihe.com",
		"musicapi.taihe.com",
		"na.b.g-tun.com",
		"proxy.golang.org",
		"ps.res.netease.com",
		"shark007.net",
		"songsearch.kugou.com",
		"static.adtidy.org",
		"streamoc.music.tc.qq.com",
		"swcdn.apple.com",
		"swdist.apple.com",
		"swdownload.apple.com",
		"swquery.apple.com",
		"swscan.apple.com",
		"turn.cloudflare.com",
		"trackercdn.kugou.com",
		"xnotify.xboxlive.com",
	}
	noFakeIPDomainKeywords = []string{
		"ntp",
		"stun",
		"time",
	}
	noFakeIPDomainRegex = []string{
		`^[^.]+$`,
		`^[^.]+\.[^.]+\.xboxlive\.com$`,
		`^localhost\.[^.]+\.weixin\.qq\.com$`,
		`^mijia\scloud$`,
		`^xbox\.[^.]+\.microsoft\.com$`,
		`^xbox\.[^.]+\.[^.]+\.microsoft\.com$`,
	}
	noFakeIPDomainSuffixes = []string{
		"126.net",
		"3gppnetwork.org",
		"battle.net",
		"battlenet.com.cn",
		"cdn.nintendo.net",
		"cmbchina.com",
		"cmbimg.com",
		"ff14.sdo.com",
		"ffxiv.com",
		"finalfantasyxiv.com",
		"gcloudcs.com",
		"home.arpa",
		"invalid",
		"kuwo.cn",
		"lan",
		"linksys.com",
		"linksyssmartwifi.com",
		"local",
		"localdomain",
		"localhost",
		"market.xiaomi.com",
		"mcdn.bilivideo.cn",
		"media.dssott.com",
		"msftconnecttest.com",
		"msftncsi.com",
		"music.163.com",
		"music.migu.cn",
		"n0808.com",
		"nflxvideo.net",
		"oray.com",
		"orayimg.com",
		"router.asus.com",
		"sandai.net",
		"square-enix.com",
		"srv.nintendo.net",
		"steamcontent.com",
		"tailscale.com",
		"tailscale.io",
		"ts.net",
		"uu.163.com",
		"wargaming.net",
		"wggames.cn",
		"wotgame.cn",
		"wowsgame.cn",
		"xiami.com",
		"y.qq.com",
	}
	defaultProxyRuleSets = []string{
		"geosite-gfw",
		"geosite-greatfire",
		"geosite-google",
		"geoip-google",
		"geoip-facebook",
		"geoip-fastly",
		"geoip-netflix",
		"geoip-telegram",
		"geoip-twitter",
	}
	tailscaleDirectDomainSuffixes = []string{
		"tailscale.com",
		"tailscale.io",
		"ts.net",
	}
	tailscaleDirectIPCIDRs = []string{
		"100.64.0.0/10",
		"fd7a:115c:a1e0::/48",
	}
	tailscaleWireGuardPort = 41641
	tailscaleSTUNPort      = 3478
	geoIPNames             = []string{
		"private",
		"cn",
		"facebook",
		"fastly",
		"google",
		"netflix",
		"telegram",
		"twitter",
	}
	geoSiteNames = []string{
		"cn",
		"gfw",
		"google",
		"greatfire",
		"geolocation-cn",
		"category-ads-all",
		"private",
	}
)

// Config 表示编排器主配置，适用于 OpenWrt 网关全局透明代理场景。
type Config struct {
	// Service 控制 sing-box 数据面是否启用。
	Service ServiceConfig `yaml:"service"`
	// Log 控制编排器和 sing-box 的日志落点与轮换策略。
	Log LogConfig `yaml:"log"`
	// Inbound 控制入口模式，默认使用 TUN 全局透明代理。
	Inbound InboundConfig `yaml:"inbound"`
	// Backend 保存静态代理节点和订阅来源。
	Backend BackendConfig `yaml:"backend"`
	// Update 控制 geofiles 和订阅更新行为。
	Update UpdateConfig `yaml:"update"`
	// GeoFiles 控制 geofiles 规则启用策略。
	GeoFiles GeoFilesConfig `yaml:"geofiles"`
	// Policy 控制最终出口选择策略。
	Policy PolicyConfig `yaml:"policy"`
	// Web 控制内置 Web 面板和登录策略。
	Web WebConfig `yaml:"web"`
}

// ServiceConfig 表示核心服务开关，适用于只停数据面保留 Web 管理。
type ServiceConfig struct {
	// Enabled 控制是否启动 sing-box，旧配置缺失时默认为 true。
	Enabled *bool `yaml:"enabled"`
}

// InboundConfig 表示入口配置，适用于 TUN 和手动代理两种模式。
type InboundConfig struct {
	// Mode 是入口模式，支持 tun 和 mixed。
	Mode string `yaml:"mode"`
	// Mixed 是 socks/http 混合端口配置。
	Mixed MixedInboundConfig `yaml:"mixed"`
}

// MixedInboundConfig 表示 mixed 入站配置，适用于非 TUN 手动代理。
type MixedInboundConfig struct {
	// Listen 是监听地址，默认 0.0.0.0 便于局域网设备使用。
	Listen string `yaml:"listen"`
	// Port 是 socks/http 混合端口，默认 1080。
	Port int `yaml:"port"`
	// Users 是 socks/http 认证用户，空数组表示无需认证。
	Users []MixedUser `yaml:"users"`
}

// MixedUser 表示 mixed 入站认证用户。
type MixedUser struct {
	// Username 是 socks/http 用户名。
	Username string `yaml:"username"`
	// Password 是 socks/http 密码。
	Password string `yaml:"password"`
}

// UpdateConfig 表示更新配置，适用于已有代理下刷新规则。
type UpdateConfig struct {
	// Proxy 是更新使用的 HTTP 代理地址，空值表示直连。
	Proxy string `yaml:"proxy"`
	// DNS 是更新下载使用的解析服务器，避免被本机异常 DNS 卡住。
	DNS string `yaml:"dns"`
	// GeoFilesUseProxy 控制 geofiles 更新是否使用 Proxy。
	GeoFilesUseProxy bool `yaml:"geofiles_use_proxy"`
	// SubscriptionUseProxy 控制订阅更新是否使用 Proxy。
	SubscriptionUseProxy bool `yaml:"subscription_use_proxy"`
}

// GeoFilesConfig 表示 geofiles 规则策略配置。
type GeoFilesConfig struct {
	// AdsBlock 控制广告规则是否 reject。
	AdsBlock bool `yaml:"ads_block"`
	// HostsOverride 控制是否把 /etc/hosts 作为 sing-box hosts DNS。
	HostsOverride *bool `yaml:"hosts_override"`
	// ProxyRuleSets 控制参与代理匹配的 rule-set。
	ProxyRuleSets []string `yaml:"proxy_rule_sets"`
}

// LogConfig 表示日志配置，适用于闪存空间有限的 OpenWrt。
type LogConfig struct {
	// Level 是日志级别，当前用于写入日志时标记，不过滤关键流程。
	Level string `yaml:"level"`
	// Dir 是整体日志目录。
	Dir string `yaml:"dir"`
	// MaxSizeMB 是单个日志文件最大 MB 数。
	MaxSizeMB int64 `yaml:"max_size_mb"`
	// MaxFiles 是每类日志保留文件数量。
	MaxFiles int `yaml:"max_files"`
}

// BackendConfig 表示出口来源配置，适用于静态节点与订阅节点混合。
type BackendConfig struct {
	// Static 保存手工写入的扁平静态后端。
	Static []StaticBackend `yaml:"static"`
	// Subscription 保存订阅地址。
	Subscription []Subscription `yaml:"subscription"`
	// Imports 保存手动导入的离线节点来源。
	Imports []ImportedNodeGroup `yaml:"imports"`
	// Groups 保存动态节点组。
	Groups []DynamicGroupConfig `yaml:"groups"`
}

// DynamicGroupConfig 表示动态节点组配置。
type DynamicGroupConfig struct {
	// Key 是动态组唯一机器标识。
	Key string `yaml:"key" json:"key"`
	// Name 是旧配置兼容字段，新配置保存时不再写入。
	Name string `yaml:"name,omitempty" json:"-"`
	// Mode 是组策略，支持 dynamic 和 primary_backup。
	Mode string `yaml:"mode" json:"mode"`
	// Primary 是主备模式下固定优先使用的成员链路 key。
	Primary string `yaml:"primary" json:"primary"`
	// Members 保存成员链路 key，如 static.xx 或 sub.main.jp。
	Members []string `yaml:"members" json:"members"`
}

const (
	// dynamicGroupModeDynamic 表示按所有成员探测结果动态择优。
	dynamicGroupModeDynamic = "dynamic"
	// dynamicGroupModePrimaryBackup 表示主节点优先，主失败后备择优。
	dynamicGroupModePrimaryBackup = "primary_backup"
	// staticProtocolHY2 表示静态节点使用 Hysteria2 协议。
	staticProtocolHY2 = "hy2"
	// staticProtocolVMess 表示静态节点使用 VMess 协议。
	staticProtocolVMess = "vmess"
	// staticProtocolSS 表示静态节点使用 Shadowsocks 协议。
	staticProtocolSS = "ss"
	// staticProtocolTrojan 表示静态节点使用 Trojan 协议。
	staticProtocolTrojan = "trojan"
	// staticProtocolAnyTLS 表示静态节点使用 AnyTLS 协议。
	staticProtocolAnyTLS = "anytls"
	// staticProtocolSocks 表示静态节点使用 SOCKS5 协议。
	staticProtocolSocks = "socks"
	// staticProtocolHTTP 表示静态节点使用 HTTP CONNECT 代理。
	staticProtocolHTTP = "http"
)

// PolicyConfig 表示路由最终策略，适用于多个代理后端场景。
type PolicyConfig struct {
	// Default 是最终出口 tag。
	Default string `yaml:"default"`
	// Fallback 是预留的故障切换顺序，当前用于选择器生成。
	Fallback []string `yaml:"fallback"`
	// Overrides 保存目的地址静态跳转规则。
	Overrides []OverrideRule `yaml:"overrides"`
	// DynamicOutbound 保存目的匹配到指定出口的规则。
	DynamicOutbound []DynamicOutboundRule `yaml:"dynamic_outbound"`
}

// OverrideRule 表示命中目标后改写连接目标的静态跳转规则。
type OverrideRule struct {
	// Key 是规则唯一机器标识，适用于 Web 编辑和去重。
	Key string `yaml:"key" json:"key"`
	// Match 是匹配条件，支持 domain:xx.com 或 IP/CIDR。
	Match string `yaml:"match" json:"match"`
	// Address 是连接被改写后的目标地址。
	Address string `yaml:"address" json:"address"`
	// Port 是连接被改写后的目标端口。
	Port int `yaml:"port" json:"port"`
	// Outbound 是改写后使用的出站，空值时使用 direct。
	Outbound string `yaml:"outbound" json:"outbound"`
	// Enabled 控制该跳转规则是否参与渲染。
	Enabled *bool `yaml:"enabled" json:"enabled"`
}

// DynamicOutboundRule 表示目的地址固定走指定 backend 的规则。
type DynamicOutboundRule struct {
	// Match 是匹配条件，支持 domain:xx.com 或 IP/CIDR。
	Match string `yaml:"match" json:"match"`
	// Outbound 是目标 backend tag。
	Outbound string `yaml:"outbound" json:"outbound"`
}

// WebConfig 表示内置 Web 面板配置，适用于路由器本机管理。
type WebConfig struct {
	// Enabled 控制 daemon 是否启动 Web 面板。
	Enabled bool `yaml:"enabled"`
	// Listen 是 Web 监听地址。
	Listen string `yaml:"listen"`
	// Port 是 Web 监听端口。
	Port int `yaml:"port"`
	// JWTSecret 是 JWT 签名密钥，空值时使用登录密码兜底。
	JWTSecret string `yaml:"jwt_secret"`
	// TokenTTL 是登录令牌有效期。
	TokenTTL string `yaml:"token_ttl"`
	// Auth 保存明文登录账号密码。
	Auth WebAuthConfig `yaml:"auth"`
	// Lock 控制登录失败锁定策略。
	Lock WebLockConfig `yaml:"lock"`
}

// WebAuthConfig 表示 Web 登录账号密码配置。
type WebAuthConfig struct {
	// Username 是登录账号。
	Username string `yaml:"username"`
	// Password 是登录密码。
	Password string `yaml:"password"`
}

// WebLockConfig 表示 Web 登录失败锁定策略。
type WebLockConfig struct {
	// MaxAttempts 是锁定前允许的连续失败次数。
	MaxAttempts int `yaml:"max_attempts"`
	// Duration 是锁定持续时间。
	Duration string `yaml:"duration"`
}

// RuntimeState 表示持久化运行状态，适用于记录最后一次成功更新。
type RuntimeState struct {
	// LastUpdateSuccess 是最后一次 update 成功的时间。
	LastUpdateSuccess string `json:"last_update_success"`
}

// ProxyBackend 表示运行时代理节点，适用于混合协议出口编排。
type ProxyBackend interface {
	// BackendKey 返回节点在所属范围内的机器 key。
	BackendKey() string
	// BackendTag 返回 sing-box outbound tag。
	BackendTag() string
	// BackendName 返回人类可读节点名称。
	BackendName() string
	// BackendProtocol 返回节点协议。
	BackendProtocol() string
	// BackendServer 返回节点服务端。
	BackendServer() string
	// BackendPort 返回节点端口。
	BackendPort() int
	// SetBackendTag 写入规范化后的 tag。
	SetBackendTag(string)
	// SetBackendKey 写入规范化后的 key。
	SetBackendKey(string)
	// SetBackendSource 写入节点来源。
	SetBackendSource(string)
	// BuildOutbound 构造 sing-box outbound。
	BuildOutbound() map[string]any
}

// HY2Backend 表示一个 Hysteria2 出站节点。
type HY2Backend struct {
	// Key 是静态列表或订阅内唯一机器标识。
	Key string `yaml:"key" json:"key"`
	// Tag 是 sing-box outbound 的唯一标识。
	Tag string `yaml:"tag" json:"tag"`
	// Name 是人类可读节点名称。
	Name string `yaml:"name" json:"name"`
	// Server 是 HY2 服务端域名或 IP。
	Server string `yaml:"server" json:"server"`
	// Port 是 HY2 服务端端口。
	Port int `yaml:"port" json:"port"`
	// Password 是 HY2 认证密码。
	Password string `yaml:"password" json:"password"`
	// SNI 是 TLS SNI。
	SNI string `yaml:"sni" json:"sni"`
	// Insecure 控制是否跳过 TLS 证书校验。
	Insecure bool `yaml:"insecure" json:"insecure"`
	// ObfsPassword 是 salamander 混淆密码，空值表示不开启混淆。
	ObfsPassword string `yaml:"obfs_password" json:"obfs_password"`
	// Source 记录节点来自 static 还是 subscription，便于日志定位。
	Source string `yaml:"-" json:"-"`
}

// VMessBackend 表示一个 VMess 出站节点。
type VMessBackend struct {
	// Key 是静态列表或订阅内唯一机器标识。
	Key string `yaml:"key" json:"key"`
	// Tag 是 sing-box outbound 的唯一标识。
	Tag string `yaml:"tag" json:"tag"`
	// Name 是人类可读节点名称。
	Name string `yaml:"name" json:"name"`
	// Server 是 VMess 服务端域名或 IP。
	Server string `yaml:"server" json:"server"`
	// Port 是 VMess 服务端端口。
	Port int `yaml:"port" json:"port"`
	// UUID 是 VMess 用户 ID。
	UUID string `yaml:"uuid" json:"uuid"`
	// Security 是 VMess 加密方式。
	Security string `yaml:"security" json:"security"`
	// AlterID 是 VMess 旧协议 alterId。
	AlterID int `yaml:"alter_id" json:"alter_id"`
	// SNI 是 TLS SNI。
	SNI string `yaml:"sni" json:"sni"`
	// TLS 控制是否启用 TLS。
	TLS bool `yaml:"tls" json:"tls"`
	// Insecure 控制是否跳过 TLS 证书校验。
	Insecure bool `yaml:"insecure" json:"insecure"`
	// Transport 是 V2Ray 传输层类型。
	Transport string `yaml:"transport" json:"transport"`
	// Path 是 WebSocket/HTTP 路径。
	Path string `yaml:"path" json:"path"`
	// Host 是 WebSocket/HTTP Host 头。
	Host string `yaml:"host" json:"host"`
	// Source 记录节点来自 static 还是 subscription，便于日志定位。
	Source string `yaml:"-" json:"-"`
}

// SSBackend 表示一个 Shadowsocks 出站节点。
type SSBackend struct {
	// Key 是静态列表或订阅内唯一机器标识。
	Key string `yaml:"key" json:"key"`
	// Tag 是 sing-box outbound 的唯一标识。
	Tag string `yaml:"tag" json:"tag"`
	// Name 是人类可读节点名称。
	Name string `yaml:"name" json:"name"`
	// Server 是 Shadowsocks 服务端域名或 IP。
	Server string `yaml:"server" json:"server"`
	// Port 是 Shadowsocks 服务端端口。
	Port int `yaml:"port" json:"port"`
	// Method 是 Shadowsocks 加密方式。
	Method string `yaml:"method" json:"method"`
	// Password 是 Shadowsocks 密码。
	Password string `yaml:"password" json:"password"`
	// Plugin 是 SIP003 插件名。
	Plugin string `yaml:"plugin,omitempty" json:"plugin,omitempty"`
	// PluginOpts 是 SIP003 插件参数。
	PluginOpts string `yaml:"plugin_opts,omitempty" json:"plugin_opts,omitempty"`
	// Source 记录节点来自 static 还是 subscription，便于日志定位。
	Source string `yaml:"-" json:"-"`
}

// TrojanBackend 表示一个 Trojan 出站节点。
type TrojanBackend struct {
	// Key 是静态列表或订阅内唯一机器标识。
	Key string `yaml:"key" json:"key"`
	// Tag 是 sing-box outbound 的唯一标识。
	Tag string `yaml:"tag" json:"tag"`
	// Name 是人类可读节点名称。
	Name string `yaml:"name" json:"name"`
	// Server 是 Trojan 服务端域名或 IP。
	Server string `yaml:"server" json:"server"`
	// Port 是 Trojan 服务端端口。
	Port int `yaml:"port" json:"port"`
	// Password 是 Trojan 认证密码。
	Password string `yaml:"password" json:"password"`
	// SNI 是 TLS SNI。
	SNI string `yaml:"sni" json:"sni"`
	// TLS 控制是否启用 TLS。
	TLS bool `yaml:"tls" json:"tls"`
	// Insecure 控制是否跳过 TLS 证书校验。
	Insecure bool `yaml:"insecure" json:"insecure"`
	// Transport 是 V2Ray 传输层类型。
	Transport string `yaml:"transport" json:"transport"`
	// Path 是 WebSocket/HTTP 路径。
	Path string `yaml:"path" json:"path"`
	// Host 是 WebSocket/HTTP Host 头。
	Host string `yaml:"host" json:"host"`
	// Source 记录节点来自 static 还是 subscription，便于日志定位。
	Source string `yaml:"-" json:"-"`
}

// AnyTLSBackend 表示一个 AnyTLS 出站节点。
type AnyTLSBackend struct {
	// Key 是静态列表或订阅内唯一机器标识。
	Key string `yaml:"key" json:"key"`
	// Tag 是 sing-box outbound 的唯一标识。
	Tag string `yaml:"tag" json:"tag"`
	// Name 是人类可读节点名称。
	Name string `yaml:"name" json:"name"`
	// Server 是 AnyTLS 服务端域名或 IP。
	Server string `yaml:"server" json:"server"`
	// Port 是 AnyTLS 服务端端口。
	Port int `yaml:"port" json:"port"`
	// Password 是 AnyTLS 认证密码。
	Password string `yaml:"password" json:"password"`
	// SNI 是 TLS SNI。
	SNI string `yaml:"sni" json:"sni"`
	// Insecure 控制是否跳过 TLS 证书校验。
	Insecure bool `yaml:"insecure" json:"insecure"`
	// IdleSessionCheckInterval 是空闲会话检查间隔。
	IdleSessionCheckInterval string `yaml:"idle_session_check_interval,omitempty" json:"idle_session_check_interval,omitempty"`
	// IdleSessionTimeout 是空闲会话超时时间。
	IdleSessionTimeout string `yaml:"idle_session_timeout,omitempty" json:"idle_session_timeout,omitempty"`
	// MinIdleSession 是至少保留的空闲会话数量。
	MinIdleSession int `yaml:"min_idle_session,omitempty" json:"min_idle_session,omitempty"`
	// Source 记录节点来自 static 还是 subscription，便于日志定位。
	Source string `yaml:"-" json:"-"`
}

// SocksBackend 表示一个 SOCKS5 出站节点。
type SocksBackend struct {
	// Key 是静态列表或订阅内唯一机器标识。
	Key string `yaml:"key" json:"key"`
	// Tag 是 sing-box outbound 的唯一标识。
	Tag string `yaml:"tag" json:"tag"`
	// Name 是人类可读节点名称。
	Name string `yaml:"name" json:"name"`
	// Server 是 SOCKS5 服务端域名或 IP。
	Server string `yaml:"server" json:"server"`
	// Port 是 SOCKS5 服务端端口。
	Port int `yaml:"port" json:"port"`
	// Username 是 SOCKS5 认证用户名，空值表示无认证。
	Username string `yaml:"username,omitempty" json:"username,omitempty"`
	// Password 是 SOCKS5 认证密码，空值表示无认证或仅用户名。
	Password string `yaml:"password,omitempty" json:"password,omitempty"`
	// Source 记录节点来自 static 还是 subscription，便于日志定位。
	Source string `yaml:"-" json:"-"`
}

// HTTPBackend 表示一个 HTTP CONNECT 出站节点。
type HTTPBackend struct {
	// Key 是静态列表或订阅内唯一机器标识。
	Key string `yaml:"key" json:"key"`
	// Tag 是 sing-box outbound 的唯一标识。
	Tag string `yaml:"tag" json:"tag"`
	// Name 是人类可读节点名称。
	Name string `yaml:"name" json:"name"`
	// Server 是 HTTP 代理服务端域名或 IP。
	Server string `yaml:"server" json:"server"`
	// Port 是 HTTP 代理服务端端口。
	Port int `yaml:"port" json:"port"`
	// Username 是 HTTP 代理认证用户名，空值表示无认证。
	Username string `yaml:"username,omitempty" json:"username,omitempty"`
	// Password 是 HTTP 代理认证密码，空值表示无认证或仅用户名。
	Password string `yaml:"password,omitempty" json:"password,omitempty"`
	// Source 记录节点来自 static 还是 subscription，便于日志定位。
	Source string `yaml:"-" json:"-"`
}

// StaticBackend 表示 Web 可编辑的扁平静态节点。
type StaticBackend struct {
	// Protocol 是节点协议，支持 hy2、vmess、ss、trojan、anytls、socks 和 http。
	Protocol string `yaml:"protocol,omitempty" json:"protocol"`
	// Key 是静态列表内唯一机器标识。
	Key string `yaml:"key,omitempty" json:"key"`
	// Tag 是运行时 outbound tag，保存配置时会清空重建。
	Tag string `yaml:"tag,omitempty" json:"tag"`
	// Name 是人类可读节点名称。
	Name string `yaml:"name,omitempty" json:"name"`
	// Server 是服务端域名或 IP。
	Server string `yaml:"server,omitempty" json:"server"`
	// Port 是服务端端口。
	Port int `yaml:"port,omitempty" json:"port"`
	// Password 是 HY2、Shadowsocks、Trojan、AnyTLS、SOCKS 或 HTTP 密码。
	Password string `yaml:"password,omitempty" json:"password"`
	// Username 是 SOCKS5 或 HTTP 代理认证用户名。
	Username string `yaml:"username,omitempty" json:"username"`
	// SNI 是 TLS SNI。
	SNI string `yaml:"sni,omitempty" json:"sni"`
	// Insecure 控制是否跳过 TLS 证书校验。
	Insecure bool `yaml:"insecure,omitempty" json:"insecure"`
	// ObfsPassword 是 HY2 salamander 混淆密码。
	ObfsPassword string `yaml:"obfs_password,omitempty" json:"obfs_password"`
	// UUID 是 VMess 用户 ID。
	UUID string `yaml:"uuid,omitempty" json:"uuid"`
	// Security 是 VMess 加密方式。
	Security string `yaml:"security,omitempty" json:"security"`
	// AlterID 是 VMess 旧协议 alterId。
	AlterID int `yaml:"alter_id,omitempty" json:"alter_id"`
	// TLS 控制 VMess 是否启用 TLS。
	TLS bool `yaml:"tls,omitempty" json:"tls"`
	// Transport 是 VMess 传输层类型。
	Transport string `yaml:"transport,omitempty" json:"transport"`
	// Path 是 VMess WebSocket/HTTP 路径。
	Path string `yaml:"path,omitempty" json:"path"`
	// Host 是 VMess WebSocket/HTTP Host 头。
	Host string `yaml:"host,omitempty" json:"host"`
	// Method 是 Shadowsocks 加密方式。
	Method string `yaml:"method,omitempty" json:"method"`
	// Plugin 是 Shadowsocks SIP003 插件名。
	Plugin string `yaml:"plugin,omitempty" json:"plugin"`
	// PluginOpts 是 Shadowsocks SIP003 插件参数。
	PluginOpts string `yaml:"plugin_opts,omitempty" json:"plugin_opts"`
	// IdleSessionCheckInterval 是 AnyTLS 空闲会话检查间隔。
	IdleSessionCheckInterval string `yaml:"idle_session_check_interval,omitempty" json:"idle_session_check_interval"`
	// IdleSessionTimeout 是 AnyTLS 空闲会话超时时间。
	IdleSessionTimeout string `yaml:"idle_session_timeout,omitempty" json:"idle_session_timeout"`
	// MinIdleSession 是 AnyTLS 至少保留的空闲会话数量。
	MinIdleSession int `yaml:"min_idle_session,omitempty" json:"min_idle_session"`
	// Detour 是拨号前置出口引用，支持 static/sub/import/group 范围。
	Detour string `yaml:"detour,omitempty" json:"detour"`
	// Source 记录节点来源，便于运行日志定位。
	Source string `yaml:"-" json:"-"`
	// RuntimeDetour 是 ResolveBackends 解析后的 sing-box outbound tag。
	RuntimeDetour string `yaml:"-" json:"-"`
}

// DynamicGroupBackend 表示一个动态组虚拟出站。
type DynamicGroupBackend struct {
	// Key 是动态组唯一机器标识。
	Key string
	// Tag 是 sing-box selector outbound tag。
	Tag string
	// Mode 是动态组策略。
	Mode string
	// PrimaryTag 是主备模式主节点 outbound tag。
	PrimaryTag string
	// Members 是已解析的成员 outbound tag。
	Members []string
	// BestTag 是当前担当成员 outbound tag。
	BestTag string
}

// SubscriptionCacheNode 表示订阅缓存中的一个协议节点 envelope。
type SubscriptionCacheNode struct {
	// Protocol 是节点协议，用于反序列化到具体结构。
	Protocol string `json:"protocol"`
	// HY2 保存 Hysteria2 节点。
	HY2 *HY2Backend `json:"hy2,omitempty"`
	// VMess 保存 VMess 节点。
	VMess *VMessBackend `json:"vmess,omitempty"`
	// SS 保存 Shadowsocks 节点。
	SS *SSBackend `json:"ss,omitempty"`
	// Trojan 保存 Trojan 节点。
	Trojan *TrojanBackend `json:"trojan,omitempty"`
	// AnyTLS 保存 AnyTLS 节点。
	AnyTLS *AnyTLSBackend `json:"anytls,omitempty"`
	// Socks 保存 SOCKS5 节点。
	Socks *SocksBackend `json:"socks,omitempty"`
	// HTTP 保存 HTTP 代理节点。
	HTTP *HTTPBackend `json:"http,omitempty"`
}

// BackendTag 返回 HY2 节点 tag。
func (b *HY2Backend) BackendTag() string {
	return b.Tag
}

// BackendKey 返回 HY2 节点范围内 key。
func (b *HY2Backend) BackendKey() string {
	return firstNonEmpty(b.Key, b.Tag)
}

// BackendName 返回 HY2 展示名称。
func (b *HY2Backend) BackendName() string {
	return firstNonEmpty(b.Name, b.Key, b.Tag)
}

// BackendProtocol 返回 HY2 协议名。
func (b *HY2Backend) BackendProtocol() string {
	return "hy2"
}

// BackendServer 返回 HY2 服务端。
func (b *HY2Backend) BackendServer() string {
	return b.Server
}

// BackendPort 返回 HY2 服务端端口。
func (b *HY2Backend) BackendPort() int {
	return b.Port
}

// SetBackendTag 写入 HY2 节点 tag。
func (b *HY2Backend) SetBackendTag(tag string) {
	b.Tag = tag
}

// SetBackendKey 写入 HY2 节点 key。
func (b *HY2Backend) SetBackendKey(key string) {
	b.Key = key
}

// SetBackendSource 写入 HY2 节点来源。
func (b *HY2Backend) SetBackendSource(source string) {
	b.Source = source
}

// BuildOutbound 构造 HY2 sing-box outbound。
func (b *HY2Backend) BuildOutbound() map[string]any {
	return BuildHY2Outbound(*b)
}

// BackendTag 返回 VMess 节点 tag。
func (b *VMessBackend) BackendTag() string {
	return b.Tag
}

// BackendKey 返回 VMess 节点范围内 key。
func (b *VMessBackend) BackendKey() string {
	return firstNonEmpty(b.Key, b.Tag)
}

// BackendName 返回 VMess 展示名称。
func (b *VMessBackend) BackendName() string {
	return firstNonEmpty(b.Name, b.Key, b.Tag)
}

// BackendProtocol 返回 VMess 协议名。
func (b *VMessBackend) BackendProtocol() string {
	return "vmess"
}

// BackendServer 返回 VMess 服务端。
func (b *VMessBackend) BackendServer() string {
	return b.Server
}

// BackendPort 返回 VMess 服务端端口。
func (b *VMessBackend) BackendPort() int {
	return b.Port
}

// SetBackendTag 写入 VMess 节点 tag。
func (b *VMessBackend) SetBackendTag(tag string) {
	b.Tag = tag
}

// SetBackendKey 写入 VMess 节点 key。
func (b *VMessBackend) SetBackendKey(key string) {
	b.Key = key
}

// SetBackendSource 写入 VMess 节点来源。
func (b *VMessBackend) SetBackendSource(source string) {
	b.Source = source
}

// BuildOutbound 构造 VMess sing-box outbound。
func (b *VMessBackend) BuildOutbound() map[string]any {
	return BuildVMessOutbound(*b)
}

// BackendTag 返回 Shadowsocks 节点 tag。
func (b *SSBackend) BackendTag() string {
	return b.Tag
}

// BackendKey 返回 Shadowsocks 节点范围内 key。
func (b *SSBackend) BackendKey() string {
	return firstNonEmpty(b.Key, b.Tag)
}

// BackendName 返回 Shadowsocks 展示名称。
func (b *SSBackend) BackendName() string {
	return firstNonEmpty(b.Name, b.Key, b.Tag)
}

// BackendProtocol 返回 Shadowsocks 协议名。
func (b *SSBackend) BackendProtocol() string {
	return "ss"
}

// BackendServer 返回 Shadowsocks 服务端。
func (b *SSBackend) BackendServer() string {
	return b.Server
}

// BackendPort 返回 Shadowsocks 服务端端口。
func (b *SSBackend) BackendPort() int {
	return b.Port
}

// SetBackendTag 写入 Shadowsocks 节点 tag。
func (b *SSBackend) SetBackendTag(tag string) {
	b.Tag = tag
}

// SetBackendKey 写入 Shadowsocks 节点 key。
func (b *SSBackend) SetBackendKey(key string) {
	b.Key = key
}

// SetBackendSource 写入 Shadowsocks 节点来源。
func (b *SSBackend) SetBackendSource(source string) {
	b.Source = source
}

// BuildOutbound 构造 Shadowsocks sing-box outbound。
func (b *SSBackend) BuildOutbound() map[string]any {
	return BuildSSOutbound(*b)
}

// BackendTag 返回 Trojan 节点 tag。
func (b *TrojanBackend) BackendTag() string {
	return b.Tag
}

// BackendKey 返回 Trojan 节点范围内 key。
func (b *TrojanBackend) BackendKey() string {
	return firstNonEmpty(b.Key, b.Tag)
}

// BackendName 返回 Trojan 展示名称。
func (b *TrojanBackend) BackendName() string {
	return firstNonEmpty(b.Name, b.Key, b.Tag)
}

// BackendProtocol 返回 Trojan 协议名。
func (b *TrojanBackend) BackendProtocol() string {
	return "trojan"
}

// BackendServer 返回 Trojan 服务端。
func (b *TrojanBackend) BackendServer() string {
	return b.Server
}

// BackendPort 返回 Trojan 服务端端口。
func (b *TrojanBackend) BackendPort() int {
	return b.Port
}

// SetBackendTag 写入 Trojan 节点 tag。
func (b *TrojanBackend) SetBackendTag(tag string) {
	b.Tag = tag
}

// SetBackendKey 写入 Trojan 节点 key。
func (b *TrojanBackend) SetBackendKey(key string) {
	b.Key = key
}

// SetBackendSource 写入 Trojan 节点来源。
func (b *TrojanBackend) SetBackendSource(source string) {
	b.Source = source
}

// BuildOutbound 构造 Trojan sing-box outbound。
func (b *TrojanBackend) BuildOutbound() map[string]any {
	return BuildTrojanOutbound(*b)
}

// BackendTag 返回 AnyTLS 节点 tag。
func (b *AnyTLSBackend) BackendTag() string {
	return b.Tag
}

// BackendKey 返回 AnyTLS 节点范围内 key。
func (b *AnyTLSBackend) BackendKey() string {
	return firstNonEmpty(b.Key, b.Tag)
}

// BackendName 返回 AnyTLS 展示名称。
func (b *AnyTLSBackend) BackendName() string {
	return firstNonEmpty(b.Name, b.Key, b.Tag)
}

// BackendProtocol 返回 AnyTLS 协议名。
func (b *AnyTLSBackend) BackendProtocol() string {
	return "anytls"
}

// BackendServer 返回 AnyTLS 服务端。
func (b *AnyTLSBackend) BackendServer() string {
	return b.Server
}

// BackendPort 返回 AnyTLS 服务端端口。
func (b *AnyTLSBackend) BackendPort() int {
	return b.Port
}

// SetBackendTag 写入 AnyTLS 节点 tag。
func (b *AnyTLSBackend) SetBackendTag(tag string) {
	b.Tag = tag
}

// SetBackendKey 写入 AnyTLS 节点 key。
func (b *AnyTLSBackend) SetBackendKey(key string) {
	b.Key = key
}

// SetBackendSource 写入 AnyTLS 节点来源。
func (b *AnyTLSBackend) SetBackendSource(source string) {
	b.Source = source
}

// BuildOutbound 构造 AnyTLS sing-box outbound。
func (b *AnyTLSBackend) BuildOutbound() map[string]any {
	return BuildAnyTLSOutbound(*b)
}

// BackendTag 返回 SOCKS5 节点 tag。
func (b *SocksBackend) BackendTag() string {
	return b.Tag
}

// BackendKey 返回 SOCKS5 节点范围内 key。
func (b *SocksBackend) BackendKey() string {
	return firstNonEmpty(b.Key, b.Tag)
}

// BackendName 返回 SOCKS5 展示名称。
func (b *SocksBackend) BackendName() string {
	return firstNonEmpty(b.Name, b.Key, b.Tag)
}

// BackendProtocol 返回 SOCKS5 协议名。
func (b *SocksBackend) BackendProtocol() string {
	return "socks"
}

// BackendServer 返回 SOCKS5 服务端。
func (b *SocksBackend) BackendServer() string {
	return b.Server
}

// BackendPort 返回 SOCKS5 服务端端口。
func (b *SocksBackend) BackendPort() int {
	return b.Port
}

// SetBackendTag 写入 SOCKS5 节点 tag。
func (b *SocksBackend) SetBackendTag(tag string) {
	b.Tag = tag
}

// SetBackendKey 写入 SOCKS5 节点 key。
func (b *SocksBackend) SetBackendKey(key string) {
	b.Key = key
}

// SetBackendSource 写入 SOCKS5 节点来源。
func (b *SocksBackend) SetBackendSource(source string) {
	b.Source = source
}

// BuildOutbound 构造 SOCKS5 sing-box outbound。
func (b *SocksBackend) BuildOutbound() map[string]any {
	return BuildSocksOutbound(*b)
}

// BackendTag 返回 HTTP 代理节点 tag。
func (b *HTTPBackend) BackendTag() string {
	return b.Tag
}

// BackendKey 返回 HTTP 代理节点范围内 key。
func (b *HTTPBackend) BackendKey() string {
	return firstNonEmpty(b.Key, b.Tag)
}

// BackendName 返回 HTTP 代理展示名称。
func (b *HTTPBackend) BackendName() string {
	return firstNonEmpty(b.Name, b.Key, b.Tag)
}

// BackendProtocol 返回 HTTP 代理协议名。
func (b *HTTPBackend) BackendProtocol() string {
	return "http"
}

// BackendServer 返回 HTTP 代理服务端。
func (b *HTTPBackend) BackendServer() string {
	return b.Server
}

// BackendPort 返回 HTTP 代理服务端端口。
func (b *HTTPBackend) BackendPort() int {
	return b.Port
}

// SetBackendTag 写入 HTTP 代理节点 tag。
func (b *HTTPBackend) SetBackendTag(tag string) {
	b.Tag = tag
}

// SetBackendKey 写入 HTTP 代理节点 key。
func (b *HTTPBackend) SetBackendKey(key string) {
	b.Key = key
}

// SetBackendSource 写入 HTTP 代理节点来源。
func (b *HTTPBackend) SetBackendSource(source string) {
	b.Source = source
}

// BuildOutbound 构造 HTTP 代理 sing-box outbound。
func (b *HTTPBackend) BuildOutbound() map[string]any {
	return BuildHTTPOutbound(*b)
}

// BackendTag 返回静态节点运行时 tag。
func (b *StaticBackend) BackendTag() string {
	return b.Tag
}

// BackendKey 返回静态节点范围内 key。
func (b *StaticBackend) BackendKey() string {
	return firstNonEmpty(b.Key, b.Tag)
}

// BackendName 返回静态节点展示名称。
func (b *StaticBackend) BackendName() string {
	return firstNonEmpty(b.Name, b.Key, b.Tag)
}

// BackendProtocol 返回静态节点协议。
func (b *StaticBackend) BackendProtocol() string {
	return normalizeStaticProtocol(b.Protocol)
}

// BackendServer 返回静态节点服务端。
func (b *StaticBackend) BackendServer() string {
	return b.Server
}

// BackendPort 返回静态节点服务端口。
func (b *StaticBackend) BackendPort() int {
	return b.Port
}

// SetBackendTag 写入静态节点运行时 tag。
func (b *StaticBackend) SetBackendTag(tag string) {
	b.Tag = tag
}

// SetBackendKey 写入静态节点 key。
func (b *StaticBackend) SetBackendKey(key string) {
	b.Key = key
}

// SetBackendSource 写入静态节点来源。
func (b *StaticBackend) SetBackendSource(source string) {
	b.Source = source
}

// BuildOutbound 按协议构造静态节点 sing-box outbound。
func (b *StaticBackend) BuildOutbound() map[string]any {
	switch b.BackendProtocol() {
	case staticProtocolVMess:
		node := b.toVMessBackend()
		return applyStaticDetour(node.BuildOutbound(), b.RuntimeDetour)
	case staticProtocolSS:
		node := b.toSSBackend()
		return applyStaticDetour(node.BuildOutbound(), b.RuntimeDetour)
	case staticProtocolTrojan:
		node := b.toTrojanBackend()
		return applyStaticDetour(node.BuildOutbound(), b.RuntimeDetour)
	case staticProtocolAnyTLS:
		node := b.toAnyTLSBackend()
		return applyStaticDetour(node.BuildOutbound(), b.RuntimeDetour)
	case staticProtocolSocks:
		node := b.toSocksBackend()
		return applyStaticDetour(node.BuildOutbound(), b.RuntimeDetour)
	case staticProtocolHTTP:
		node := b.toHTTPBackend()
		return applyStaticDetour(node.BuildOutbound(), b.RuntimeDetour)
	default:
		node := b.toHY2Backend()
		return applyStaticDetour(node.BuildOutbound(), b.RuntimeDetour)
	}
}

// toHY2Backend 将扁平静态配置投影为 HY2 运行节点。
func (b *StaticBackend) toHY2Backend() HY2Backend {
	return HY2Backend{
		Key:          b.Key,
		Tag:          b.Tag,
		Name:         b.Name,
		Server:       b.Server,
		Port:         b.Port,
		Password:     b.Password,
		SNI:          b.SNI,
		Insecure:     b.Insecure,
		ObfsPassword: b.ObfsPassword,
		Source:       b.Source,
	}
}

// toVMessBackend 将扁平静态配置投影为 VMess 运行节点。
func (b *StaticBackend) toVMessBackend() VMessBackend {
	return VMessBackend{
		Key:       b.Key,
		Tag:       b.Tag,
		Name:      b.Name,
		Server:    b.Server,
		Port:      b.Port,
		UUID:      b.UUID,
		Security:  b.Security,
		AlterID:   b.AlterID,
		SNI:       b.SNI,
		TLS:       b.TLS,
		Insecure:  b.Insecure,
		Transport: b.Transport,
		Path:      b.Path,
		Host:      b.Host,
		Source:    b.Source,
	}
}

// toSSBackend 将扁平静态配置投影为 Shadowsocks 运行节点。
func (b *StaticBackend) toSSBackend() SSBackend {
	return SSBackend{
		Key:        b.Key,
		Tag:        b.Tag,
		Name:       b.Name,
		Server:     b.Server,
		Port:       b.Port,
		Method:     b.Method,
		Password:   b.Password,
		Plugin:     b.Plugin,
		PluginOpts: b.PluginOpts,
		Source:     b.Source,
	}
}

// applyStaticDetour 写入静态节点 sing-box 拨号前置出口。
func applyStaticDetour(out map[string]any, detour string) map[string]any {
	if strings.TrimSpace(detour) != "" {
		out["detour"] = strings.TrimSpace(detour)
	}
	return out
}

// toTrojanBackend 将扁平静态配置投影为 Trojan 运行节点。
func (b *StaticBackend) toTrojanBackend() TrojanBackend {
	return TrojanBackend{
		Key:       b.Key,
		Tag:       b.Tag,
		Name:      b.Name,
		Server:    b.Server,
		Port:      b.Port,
		Password:  b.Password,
		SNI:       b.SNI,
		TLS:       b.TLS,
		Insecure:  b.Insecure,
		Transport: b.Transport,
		Path:      b.Path,
		Host:      b.Host,
		Source:    b.Source,
	}
}

// toAnyTLSBackend 将扁平静态配置投影为 AnyTLS 运行节点。
func (b *StaticBackend) toAnyTLSBackend() AnyTLSBackend {
	return AnyTLSBackend{
		Key:                      b.Key,
		Tag:                      b.Tag,
		Name:                     b.Name,
		Server:                   b.Server,
		Port:                     b.Port,
		Password:                 b.Password,
		SNI:                      b.SNI,
		Insecure:                 b.Insecure,
		IdleSessionCheckInterval: b.IdleSessionCheckInterval,
		IdleSessionTimeout:       b.IdleSessionTimeout,
		MinIdleSession:           b.MinIdleSession,
		Source:                   b.Source,
	}
}

// toSocksBackend 将扁平静态配置投影为 SOCKS5 运行节点。
func (b *StaticBackend) toSocksBackend() SocksBackend {
	return SocksBackend{
		Key:      b.Key,
		Tag:      b.Tag,
		Name:     b.Name,
		Server:   b.Server,
		Port:     b.Port,
		Username: b.Username,
		Password: b.Password,
		Source:   b.Source,
	}
}

// toHTTPBackend 将扁平静态配置投影为 HTTP 代理运行节点。
func (b *StaticBackend) toHTTPBackend() HTTPBackend {
	return HTTPBackend{
		Key:      b.Key,
		Tag:      b.Tag,
		Name:     b.Name,
		Server:   b.Server,
		Port:     b.Port,
		Username: b.Username,
		Password: b.Password,
		Source:   b.Source,
	}
}

// BackendKey 返回动态组 key。
func (b *DynamicGroupBackend) BackendKey() string {
	return b.Key
}

// BackendTag 返回动态组 outbound tag。
func (b *DynamicGroupBackend) BackendTag() string {
	return b.Tag
}

// BackendName 返回动态组展示名称。
func (b *DynamicGroupBackend) BackendName() string {
	return firstNonEmpty(b.Key, b.Tag)
}

// BackendProtocol 返回动态组协议名。
func (b *DynamicGroupBackend) BackendProtocol() string {
	return "group"
}

// BackendServer 返回动态组展示服务端。
func (b *DynamicGroupBackend) BackendServer() string {
	return "dynamic"
}

// BackendPort 返回动态组展示端口。
func (b *DynamicGroupBackend) BackendPort() int {
	return len(b.Members)
}

// SetBackendTag 写入动态组 tag。
func (b *DynamicGroupBackend) SetBackendTag(tag string) {
	b.Tag = tag
}

// SetBackendKey 写入动态组 key。
func (b *DynamicGroupBackend) SetBackendKey(key string) {
	b.Key = key
}

// SetBackendSource 忽略动态组来源写入。
func (b *DynamicGroupBackend) SetBackendSource(_ string) {
}

// BuildOutbound 构造动态组 selector outbound。
func (b *DynamicGroupBackend) BuildOutbound() map[string]any {
	return BuildDynamicGroupOutbound(*b)
}

// Status 返回动态组状态副本，适用于 Web 只读展示。
func (r *GroupRuntime) Status(groupKey string) DynamicGroupStatus {
	if r == nil {
		return DynamicGroupStatus{Results: map[string][]GroupProbeRecord{}}
	}
	r.Mutex.Lock()
	defer r.Mutex.Unlock()
	item := r.Groups[groupKey]
	if item == nil {
		return DynamicGroupStatus{Results: map[string][]GroupProbeRecord{}}
	}
	return cloneDynamicGroupStatus(*item)
}

// BestTag 返回动态组当前担当 tag，适用于渲染 selector 默认项。
func (r *GroupRuntime) BestTag(groupKey string) string {
	if r == nil {
		return ""
	}
	r.Mutex.Lock()
	defer r.Mutex.Unlock()
	item := r.Groups[groupKey]
	if item == nil {
		return ""
	}
	return item.BestTag
}

// AppendProbe 写入单次探测结果，并只保留最近三次。
func (r *GroupRuntime) AppendProbe(groupKey string, memberRef string, record GroupProbeRecord) {
	if r == nil {
		return
	}
	r.Mutex.Lock()
	defer r.Mutex.Unlock()
	item := r.ensureLocked(groupKey)
	item.Results[memberRef] = append(item.Results[memberRef], record)
	if len(item.Results[memberRef]) > 3 {
		item.Results[memberRef] = item.Results[memberRef][len(item.Results[memberRef])-3:]
	}
}

// SetBest 写入动态组担当，适用于探测批次结束后的切换。
func (r *GroupRuntime) SetBest(groupKey string, memberRef string, tag string) {
	if r == nil {
		return
	}
	r.Mutex.Lock()
	defer r.Mutex.Unlock()
	item := r.ensureLocked(groupKey)
	item.BestMember = memberRef
	item.BestTag = tag
	item.UpdatedAt = time.Now().Format(time.RFC3339)
}

// ensureLocked 返回动态组状态，调用方必须已经持有锁。
func (r *GroupRuntime) ensureLocked(groupKey string) *DynamicGroupStatus {
	item := r.Groups[groupKey]
	if item == nil {
		item = &DynamicGroupStatus{Results: map[string][]GroupProbeRecord{}}
		r.Groups[groupKey] = item
	}
	if item.Results == nil {
		item.Results = map[string][]GroupProbeRecord{}
	}
	return item
}

// cloneDynamicGroupStatus 复制动态组状态，避免 Web 读到可变 map。
func cloneDynamicGroupStatus(item DynamicGroupStatus) DynamicGroupStatus {
	next := DynamicGroupStatus{
		BestMember: item.BestMember,
		BestTag:    item.BestTag,
		UpdatedAt:  item.UpdatedAt,
		Results:    map[string][]GroupProbeRecord{},
	}
	for key, records := range item.Results {
		next.Results[key] = append([]GroupProbeRecord(nil), records...)
	}
	return next
}

// Subscription 表示一个节点订阅地址。
type Subscription struct {
	// Key 是订阅列表内唯一机器标识。
	Key string `yaml:"key" json:"key"`
	// Name 是订阅名称，用于日志和 tag 前缀。
	Name string `yaml:"name" json:"name"`
	// URL 是订阅下载地址。
	URL string `yaml:"url" json:"url"`
	// Enabled 控制该订阅是否启用。
	Enabled bool `yaml:"enabled" json:"enabled"`
	// UserAgent 控制订阅请求头，部分订阅按客户端返回协议。
	UserAgent string `yaml:"user_agent" json:"user_agent"`
	// Default 是该订阅中优先选用的节点 tag。
	Default string `yaml:"default" json:"default"`
}

// ImportedNodeGroup 表示一个手动导入的离线节点来源。
type ImportedNodeGroup struct {
	// Key 是导入来源唯一机器标识。
	Key string `yaml:"key" json:"key"`
	// Name 是导入来源展示名。
	Name string `yaml:"name" json:"name"`
	// Source 是导入格式，目前支持 clash。
	Source string `yaml:"source" json:"source"`
}

// LocalRule 表示一行自定义规则，适用于强制直连和强制代理列表。
type LocalRule struct {
	// Kind 是规则类型，取值为 domain、src、dst。
	Kind string
	// Value 是规则原始值。
	Value string
	// Line 是规则所在行号。
	Line int
}

// Logger 表示简单文件日志器，适用于无外部日志服务的路由器。
type Logger struct {
	// Dir 是日志目录。
	Dir string
	// MaxSize 是单个日志文件最大字节数。
	MaxSize int64
	// MaxFiles 是保留文件数量。
	MaxFiles int
	// Level 是日志级别。
	Level string
}

// App 表示编排器运行实例，集中持有路径和日志。
type App struct {
	// ConfigPath 是主配置文件路径。
	ConfigPath string
	// ForceProxyPath 是强制代理规则路径。
	ForceProxyPath string
	// ForceDirectPath 是强制直连规则路径。
	ForceDirectPath string
	// GeoDir 是 geofile 本地缓存目录。
	GeoDir string
	// SubscriptionDir 是订阅解析结果缓存目录。
	SubscriptionDir string
	// SingBoxConfig 是生成的 sing-box 配置路径。
	SingBoxConfig string
	// Logger 是整体日志器。
	Logger *Logger
	// HTTPClient 复用 geofile 和订阅下载连接。
	HTTPClient *http.Client
	// GroupRuntime 保存动态组内存探测状态。
	GroupRuntime *GroupRuntime
	// SingBoxMutex 保护 sing-box 子进程句柄。
	SingBoxMutex sync.Mutex
	// SingBoxCmd 是当前由编排器托管的 sing-box 子进程。
	SingBoxCmd *exec.Cmd
	// SingBoxExit 在 sing-box 子进程退出时收到 Wait 结果。
	SingBoxExit chan error
	// SingBoxStopping 表示当前退出由编排器主动触发。
	SingBoxStopping bool
	// SingBoxExpectedExit 保存主动杀掉的 sing-box 进程 PID。
	SingBoxExpectedExit map[int]bool
	// SingBoxRestarting 表示 supervisor 正在重拉 sing-box。
	SingBoxRestarting bool
	// SingBoxBackoff 保存异常退出后的重拉退避。
	SingBoxBackoff time.Duration
}

// GroupRuntime 表示动态组内存运行状态。
type GroupRuntime struct {
	// Mutex 保护动态组探测结果。
	Mutex sync.Mutex
	// Groups 保存每个动态组的探测状态。
	Groups map[string]*DynamicGroupStatus
}

// DynamicGroupStatus 表示单个动态组运行状态。
type DynamicGroupStatus struct {
	// BestMember 是当前担当成员链路 key。
	BestMember string `json:"best_member"`
	// BestTag 是当前担当成员 outbound tag。
	BestTag string `json:"best_tag"`
	// CurrentMember 是 sing-box selector 当前成员链路 key。
	CurrentMember string `json:"current_member"`
	// CurrentTag 是 sing-box selector 当前 outbound tag。
	CurrentTag string `json:"current_tag"`
	// UpdatedAt 是最后一次评估时间。
	UpdatedAt string `json:"updated_at"`
	// Results 保存每个成员最后三次探测。
	Results map[string][]GroupProbeRecord `json:"results"`
}

// GroupProbeRecord 表示一次动态组成员探测记录。
type GroupProbeRecord struct {
	// At 是探测时间。
	At string `json:"at"`
	// DelayMS 是延迟毫秒。
	DelayMS int `json:"delay_ms"`
	// OK 表示探测是否成功。
	OK bool `json:"ok"`
	// Error 是失败原因。
	Error string `json:"error,omitempty"`
}

// WebServer 表示内置 Web 服务实例。
type WebServer struct {
	// App 是共享的编排器实例。
	App *App
	// Server 是标准库 HTTP 服务。
	Server *http.Server
	// Mutex 串行化保存和重启操作。
	Mutex sync.Mutex
	// LoginFailures 保存每个 IP 的失败状态。
	LoginFailures map[string]*LoginFailure
	// FailureMutex 保护登录失败状态。
	FailureMutex sync.Mutex
}

// LoginFailure 表示单个 IP 的登录失败状态。
type LoginFailure struct {
	// Count 是连续失败次数。
	Count int
	// LockedUntil 是锁定截止时间。
	LockedUntil time.Time
}

// WebHealthResponse 表示无需登录的探测响应。
type WebHealthResponse struct {
	// OK 表示 Web 服务自身可用。
	OK bool `json:"ok"`
	// SetupRequired 表示账号密码尚未配置。
	SetupRequired bool `json:"setup_required"`
	// ServiceEnabled 表示配置层是否启用 sing-box 数据面。
	ServiceEnabled bool `json:"service_enabled"`
	// SingBoxStatus 是 sing-box 运行状态。
	SingBoxStatus string `json:"sing_box_status"`
	// StartedAt 是当前 sboxctl 进程启动时间。
	StartedAt string `json:"started_at"`
	// ActiveOutbound 是当前选用节点。
	ActiveOutbound string `json:"active_outbound"`
	// LastUpdateSuccess 是最后一次成功更新时间。
	LastUpdateSuccess string `json:"last_update_success"`
	// Version 是 sboxctl 当前版本。
	Version string `json:"version"`
}

// WebLoginRequest 表示登录请求。
type WebLoginRequest struct {
	// Username 是登录账号。
	Username string `json:"username"`
	// Password 是登录密码。
	Password string `json:"password"`
}

// WebLoginResponse 表示登录响应。
type WebLoginResponse struct {
	// Token 是后续 API 使用的 JWT。
	Token string `json:"token"`
	// ExpiresAt 是 JWT 过期时间。
	ExpiresAt string `json:"expires_at"`
}

// WebSetupRequest 表示首次初始化 Web 账号密码的请求。
type WebSetupRequest struct {
	// Username 是要写入配置的登录账号。
	Username string `json:"username"`
	// Password 是要写入配置的登录密码。
	Password string `json:"password"`
}

// WebStateResponse 表示前端主页面需要的完整状态。
type WebStateResponse struct {
	// Health 是当前探测状态。
	Health WebHealthResponse `json:"health"`
	// ConfigHash 是当前可编辑配置内容哈希。
	ConfigHash string `json:"config_hash"`
	// Static 保存静态代理节点列表。
	Static []WebBackend `json:"static"`
	// Subscriptions 保存订阅分组节点列表。
	Subscriptions []WebSubscription `json:"subscriptions"`
	// Imports 保存手动导入分组节点列表。
	Imports []WebImportedGroup `json:"imports"`
	// DynamicGroups 保存动态节点组列表。
	DynamicGroups []WebDynamicGroup `json:"dynamic_groups"`
	// GeoFiles 保存 geofiles 本地缓存详情。
	GeoFiles []WebGeoFile `json:"geofiles"`
	// HostsOverride 控制是否启用 /etc/hosts DNS。
	HostsOverride bool `json:"hosts_override"`
	// Inbound 保存入口模式和 mixed 监听配置。
	Inbound WebInboundConfig `json:"inbound"`
	// ForceProxy 是强制代理规则文件内容。
	ForceProxy string `json:"force_proxy"`
	// ForceDirect 是强制直连规则文件内容。
	ForceDirect string `json:"force_direct"`
	// Overrides 保存目的地址静态跳转规则。
	Overrides []OverrideRule `json:"overrides"`
	// DynamicOutbound 保存目的匹配到指定出口的规则。
	DynamicOutbound []DynamicOutboundRule `json:"dynamic_outbound"`
	// SingBoxConfig 是当前保存配置生成的 sing-box JSON。
	SingBoxConfig string `json:"sing_box_config"`
	// Warnings 是配置诊断提醒。
	Warnings []string `json:"warnings"`
}

// WebBackend 表示前端展示的一个节点。
type WebBackend struct {
	// Key 是节点在所属范围内的机器标识。
	Key string `json:"key"`
	// Tag 是节点唯一标识。
	Tag string `json:"tag"`
	// Name 是节点展示名称。
	Name string `json:"name"`
	// Protocol 是节点协议。
	Protocol string `json:"protocol"`
	// Server 是节点服务器。
	Server string `json:"server"`
	// Port 是节点端口。
	Port int `json:"port"`
	// Source 是节点来源。
	Source string `json:"source"`
	// Password 是 HY2 静态节点认证密码或 Shadowsocks 密码。
	Password string `json:"password,omitempty"`
	// Username 是 SOCKS5 静态节点认证用户名。
	Username string `json:"username,omitempty"`
	// SNI 是 HY2 静态节点 TLS SNI。
	SNI string `json:"sni,omitempty"`
	// Insecure 控制 HY2 静态节点是否跳过证书校验。
	Insecure bool `json:"insecure,omitempty"`
	// ObfsPassword 是 HY2 静态节点混淆密码。
	ObfsPassword string `json:"obfs_password,omitempty"`
	// UUID 是 VMess 静态节点用户 ID。
	UUID string `json:"uuid,omitempty"`
	// Security 是 VMess 静态节点加密方式。
	Security string `json:"security,omitempty"`
	// AlterID 是 VMess 静态节点 alterId。
	AlterID int `json:"alter_id,omitempty"`
	// TLS 控制 VMess 静态节点是否启用 TLS。
	TLS bool `json:"tls,omitempty"`
	// Transport 是 VMess 静态节点传输层类型。
	Transport string `json:"transport,omitempty"`
	// Path 是 VMess 静态节点 WebSocket/HTTP 路径。
	Path string `json:"path,omitempty"`
	// Host 是 VMess 静态节点 WebSocket/HTTP Host 头。
	Host string `json:"host,omitempty"`
	// Method 是 Shadowsocks 加密方式。
	Method string `json:"method,omitempty"`
	// Plugin 是 Shadowsocks SIP003 插件名。
	Plugin string `json:"plugin,omitempty"`
	// PluginOpts 是 Shadowsocks SIP003 插件参数。
	PluginOpts string `json:"plugin_opts,omitempty"`
	// IdleSessionCheckInterval 是 AnyTLS 空闲会话检查间隔。
	IdleSessionCheckInterval string `json:"idle_session_check_interval,omitempty"`
	// IdleSessionTimeout 是 AnyTLS 空闲会话超时时间。
	IdleSessionTimeout string `json:"idle_session_timeout,omitempty"`
	// MinIdleSession 是 AnyTLS 至少保留的空闲会话数量。
	MinIdleSession int `json:"min_idle_session,omitempty"`
	// Detour 是静态节点链式拨号前置出口引用。
	Detour string `json:"detour,omitempty"`
}

// WebSubscription 表示前端展示的订阅分组。
type WebSubscription struct {
	// Key 是订阅机器标识。
	Key string `json:"key"`
	// Name 是订阅名称。
	Name string `json:"name"`
	// Enabled 表示订阅是否启用。
	Enabled bool `json:"enabled"`
	// URL 是订阅地址。
	URL string `json:"url"`
	// UserAgent 是订阅请求 UA。
	UserAgent string `json:"user_agent"`
	// Default 是订阅内默认节点 key。
	Default string `json:"default"`
	// Nodes 是该订阅缓存中的节点。
	Nodes []WebBackend `json:"nodes"`
	// Error 是读取缓存失败时的说明。
	Error string `json:"error,omitempty"`
}

// WebImportedGroup 表示前端展示的手动导入分组。
type WebImportedGroup struct {
	// Key 是导入分组机器标识。
	Key string `json:"key"`
	// Name 是导入分组展示名。
	Name string `json:"name"`
	// Source 是导入格式，目前支持 clash。
	Source string `json:"source"`
	// Nodes 是该导入缓存中的节点。
	Nodes []WebBackend `json:"nodes"`
	// Error 是读取缓存失败时的说明。
	Error string `json:"error,omitempty"`
}

// WebDynamicGroup 表示前端展示的动态节点组。
type WebDynamicGroup struct {
	// Key 是动态组机器标识。
	Key string `json:"key"`
	// Tag 是动态组 selector outbound tag。
	Tag string `json:"tag"`
	// Name 是动态组展示名称。
	Name string `json:"name"`
	// Mode 是动态组策略。
	Mode string `json:"mode"`
	// Primary 是主备模式主节点链路 key。
	Primary string `json:"primary"`
	// Members 保存成员链路 key。
	Members []string `json:"members"`
	// BestMember 是当前担当成员链路 key。
	BestMember string `json:"best_member"`
	// BestTag 是当前担当成员 outbound tag。
	BestTag string `json:"best_tag"`
	// CurrentMember 是 sing-box selector 当前成员链路 key。
	CurrentMember string `json:"current_member"`
	// CurrentTag 是 sing-box selector 当前 outbound tag。
	CurrentTag string `json:"current_tag"`
	// UpdatedAt 是最后一次评估时间。
	UpdatedAt string `json:"updated_at"`
	// Results 保存成员最近探测结果。
	Results map[string][]GroupProbeRecord `json:"results"`
}

// WebGeoFile 表示一个 geofile 本地缓存状态。
type WebGeoFile struct {
	// Kind 是 geoip 或 geosite。
	Kind string `json:"kind"`
	// Tag 是 sing-box rule-set tag。
	Tag string `json:"tag"`
	// Path 是本地缓存路径。
	Path string `json:"path"`
	// Exists 表示文件是否存在。
	Exists bool `json:"exists"`
	// SizeBytes 是文件大小。
	SizeBytes int64 `json:"size_bytes"`
	// ModifiedAt 是文件修改时间。
	ModifiedAt string `json:"modified_at"`
	// Locked 表示该规则由基础策略锁定。
	Locked bool `json:"locked"`
	// Enabled 表示该规则当前参与路由。
	Enabled bool `json:"enabled"`
	// Role 表示规则用途。
	Role string `json:"role"`
}

// WebInboundConfig 表示 Web 可编辑的入口配置。
type WebInboundConfig struct {
	// InboundMode 是入口模式，支持 tun 和 mixed。
	InboundMode string `json:"inbound_mode"`
	// MixedListen 是 mixed 入站监听地址。
	MixedListen string `json:"mixed_listen"`
	// MixedPort 是 mixed 入站监听端口。
	MixedPort int `json:"mixed_port"`
}

// WebSaveRequest 表示保存策略和规则的请求。
type WebSaveRequest struct {
	// ServiceEnabled 表示保存后是否启用 sing-box 数据面。
	ServiceEnabled bool `json:"service_enabled"`
	// ActiveOutbound 是保存后选用的节点 tag。
	ActiveOutbound string `json:"active_outbound"`
	// ConfigHash 是前端加载时拿到的配置哈希。
	ConfigHash string `json:"config_hash"`
	// ConfirmOverwrite 表示用户确认覆盖较新的配置。
	ConfirmOverwrite bool `json:"confirm_overwrite"`
	// Static 是 Web 提交的静态节点配置。
	Static []StaticBackend `json:"static"`
	// Subscriptions 是 Web 提交的订阅配置。
	Subscriptions []Subscription `json:"subscriptions"`
	// Imports 是 Web 提交的手动导入来源配置。
	Imports []ImportedNodeGroup `json:"imports"`
	// DynamicGroups 是 Web 提交的动态节点组配置。
	DynamicGroups []DynamicGroupConfig `json:"dynamic_groups"`
	// Inbound 保存入口模式和 mixed 监听配置。
	Inbound WebInboundConfig `json:"inbound"`
	// ForceProxy 是强制代理规则文件内容。
	ForceProxy string `json:"force_proxy"`
	// ForceDirect 是强制直连规则文件内容。
	ForceDirect string `json:"force_direct"`
	// Overrides 保存目的地址静态跳转规则。
	Overrides []OverrideRule `json:"overrides"`
	// DynamicOutbound 保存目的匹配到指定出口的规则。
	DynamicOutbound []DynamicOutboundRule `json:"dynamic_outbound"`
	// AdsBlock 控制广告规则是否启用。
	AdsBlock bool `json:"ads_block"`
	// HostsOverride 控制是否启用 /etc/hosts DNS。
	HostsOverride bool `json:"hosts_override"`
	// ProxyRuleSets 控制参与代理匹配的 rule-set。
	ProxyRuleSets []string `json:"proxy_rule_sets"`
}

// WebApplyPlan 表示 Web 保存后的应用方式。
type WebApplyPlan struct {
	// ServiceEnabled 表示应用后是否应保持 sing-box 运行。
	ServiceEnabled bool
	// Restart 表示必须重启 sing-box 才能应用。
	Restart bool
	// SelectorSwitches 保存可通过 Clash API 热切的 selector。
	SelectorSwitches map[string]string
}

// WebSubscriptionUpdateRequest 表示单个订阅更新请求。
type WebSubscriptionUpdateRequest struct {
	// Name 是要更新的订阅名称。
	Name string `json:"name"`
	// UseProxy 表示这次 Web 手动更新是否强制使用 update.proxy。
	UseProxy bool `json:"use_proxy"`
}

// WebImportRequest 表示一次手动导入请求。
type WebImportRequest struct {
	// Key 是要写入或替换的导入分组 key。
	Key string `json:"key"`
	// Name 是导入分组展示名。
	Name string `json:"name"`
	// Source 是导入格式，目前支持 clash。
	Source string `json:"source"`
	// Content 是用户粘贴的原始配置内容。
	Content string `json:"content"`
}

// WebImportResponse 表示手动导入解析结果。
type WebImportResponse struct {
	// Imported 是最终写入缓存的节点数量。
	Imported int `json:"imported"`
	// Skipped 是不支持或缺字段而跳过的节点数量。
	Skipped int `json:"skipped"`
	// Failed 是解析失败的节点数量。
	Failed int `json:"failed"`
}

// WebRouteCheckRequest 表示 Web 路由检查请求。
type WebRouteCheckRequest struct {
	// Target 是要检查的域名、IP 或 CIDR。
	Target string `json:"target"`
}

// WebRouteCheckResponse 表示单个目标的路由判断结果。
type WebRouteCheckResponse struct {
	// Input 是用户原始输入。
	Input string `json:"input"`
	// Target 是清洗后的目标。
	Target string `json:"target"`
	// Kind 是 domain、ip 或 cidr。
	Kind string `json:"kind"`
	// Decision 是 proxy、direct 或 reject。
	Decision string `json:"decision"`
	// Outbound 是最终出站标签。
	Outbound string `json:"outbound"`
	// MatchedRule 是命中的规则名称。
	MatchedRule string `json:"matched_rule"`
	// Reason 是面向用户的命中原因。
	Reason string `json:"reason"`
	// ViaProxy 表示该目标是否会走代理出口。
	ViaProxy bool `json:"via_proxy"`
	// Notes 保存额外说明。
	Notes []string `json:"notes"`
}

// WebProbeRequest 表示节点时延探测请求。
type WebProbeRequest struct {
	// Tag 是要探测的 outbound tag。
	Tag string `json:"tag"`
	// URL 是本次 Web 临时探测目标，空值使用默认地址。
	URL string `json:"url"`
}

// WebProbeResponse 表示节点时延探测结果。
type WebProbeResponse struct {
	// Tag 是已探测的 outbound tag。
	Tag string `json:"tag"`
	// DelayMS 是 HTTP 探测时延，单位毫秒。
	DelayMS int `json:"delay_ms"`
}

// WebConnectionsResponse 表示 Web 连接流水响应。
type WebConnectionsResponse struct {
	// UpdatedAt 是本次读取连接的时间。
	UpdatedAt string `json:"updated_at"`
	// Total 是当前连接数量。
	Total int `json:"total"`
	// UploadTotal 是 sing-box 累计上传字节数。
	UploadTotal int64 `json:"upload_total"`
	// DownloadTotal 是 sing-box 累计下载字节数。
	DownloadTotal int64 `json:"download_total"`
	// Connections 是按当前连接流量倒序排列的连接列表。
	Connections []WebConnection `json:"connections"`
}

// WebConnection 表示单条 sing-box 当前连接。
type WebConnection struct {
	// ID 是 Clash API 返回的连接 ID。
	ID string `json:"id"`
	// Network 是 tcp 或 udp。
	Network string `json:"network"`
	// Source 是来源地址和端口。
	Source string `json:"source"`
	// Destination 是目标域名或 IP 和端口。
	Destination string `json:"destination"`
	// Host 是目标域名，可能为空。
	Host string `json:"host"`
	// DestinationIP 是目标 IP，可能为空。
	DestinationIP string `json:"destination_ip"`
	// DestinationPort 是目标端口。
	DestinationPort int `json:"destination_port"`
	// Upload 是当前连接上传字节数。
	Upload int64 `json:"upload"`
	// Download 是当前连接下载字节数。
	Download int64 `json:"download"`
	// Total 是当前连接上传和下载字节数之和。
	Total int64 `json:"total"`
	// Chains 是 sing-box 出站链路。
	Chains []string `json:"chains"`
	// ChainText 是出站链路展示文本。
	ChainText string `json:"chain_text"`
	// Decision 是 direct、proxy、reject 或 unknown。
	Decision string `json:"decision"`
	// Rule 是命中的规则文本。
	Rule string `json:"rule"`
	// RulePayload 是命中的规则 payload。
	RulePayload string `json:"rule_payload"`
	// StartedAt 是连接开始时间。
	StartedAt string `json:"started_at"`
}

// clashConnectionsResponse 表示 Clash API 当前连接响应。
type clashConnectionsResponse struct {
	// UploadTotal 是累计上传字节数。
	UploadTotal int64 `json:"uploadTotal"`
	// DownloadTotal 是累计下载字节数。
	DownloadTotal int64 `json:"downloadTotal"`
	// Connections 是当前连接列表。
	Connections []clashConnection `json:"connections"`
}

// clashConnection 表示 Clash API 的单条连接。
type clashConnection struct {
	// ID 是连接 ID。
	ID string `json:"id"`
	// Metadata 是连接五元组和域名信息。
	Metadata clashConnectionMetadata `json:"metadata"`
	// Upload 是当前连接上传字节数。
	Upload int64 `json:"upload"`
	// Download 是当前连接下载字节数。
	Download int64 `json:"download"`
	// Chains 是出站链路。
	Chains []string `json:"chains"`
	// Rule 是命中的规则文本。
	Rule string `json:"rule"`
	// RulePayload 是命中的规则 payload。
	RulePayload string `json:"rulePayload"`
	// Start 是连接开始时间。
	Start string `json:"start"`
}

// clashConnectionMetadata 表示 Clash API 连接元数据。
type clashConnectionMetadata struct {
	// Network 是 tcp 或 udp。
	Network string `json:"network"`
	// SourceIP 是来源 IP。
	SourceIP string `json:"sourceIP"`
	// SourcePort 是来源端口。
	SourcePort flexibleInt `json:"sourcePort"`
	// DestinationIP 是目标 IP。
	DestinationIP string `json:"destinationIP"`
	// DestinationPort 是目标端口。
	DestinationPort flexibleInt `json:"destinationPort"`
	// Host 是目标域名。
	Host string `json:"host"`
}

// flexibleInt 兼容 Clash API 中数字或字符串形式的端口。
type flexibleInt int

// UnmarshalJSON 解析数字或字符串端口，适用于 sing-box Clash API 差异。
func (v *flexibleInt) UnmarshalJSON(data []byte) error {
	var number int
	if err := json.Unmarshal(data, &number); err == nil {
		*v = flexibleInt(number)
		return nil
	}
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	if strings.TrimSpace(text) == "" {
		*v = 0
		return nil
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil {
		return err
	}
	*v = flexibleInt(parsed)
	return nil
}

// ConfigConflictError 表示保存时配置已被其他来源修改。
type ConfigConflictError struct {
	// CurrentHash 是服务端当前配置哈希。
	CurrentHash string
}

// Error 返回配置冲突说明。
func (e ConfigConflictError) Error() string {
	return "配置已经不是最新"
}

// clashDelayResponse 表示 Clash API delay 响应。
type clashDelayResponse struct {
	// Delay 是指定节点访问测试 URL 的毫秒时延。
	Delay int `json:"delay"`
}

// clashProxyResponse 表示 Clash API 单个代理响应。
type clashProxyResponse struct {
	// Now 是 selector 当前选中的 outbound tag。
	Now string `json:"now"`
}

// main 是命令入口，适用于本机执行和 OpenWrt 服务调用。
func main() {
	app := NewAppFromFlags()
	if err := app.Run(flag.Args()); err != nil {
		app.ensureLogger(DefaultLogConfig())
		app.Logger.Error("命令失败: %v", err)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// NewAppFromFlags 从命令行参数创建编排器实例。
func NewAppFromFlags() *App {
	configPath := flag.String("config", defaultConfigPath, "配置文件路径")
	forceProxyPath := flag.String("force-proxy", defaultForceProxyPath, "强制代理规则路径")
	forceDirectPath := flag.String("force-direct", defaultForceDirectPath, "强制直连规则路径")
	geoDir := flag.String("geo-dir", defaultGeoDir, "geofile 缓存目录")
	singBoxConfig := flag.String("sing-box-config", defaultSingBoxConfig, "sing-box 配置路径")
	flag.Parse()
	return &App{
		ConfigPath:      *configPath,
		ForceProxyPath:  *forceProxyPath,
		ForceDirectPath: *forceDirectPath,
		GeoDir:          *geoDir,
		SubscriptionDir: defaultSubscriptionDir,
		SingBoxConfig:   *singBoxConfig,
		HTTPClient:      NewHTTPClient(defaultTimeout, "", defaultUpdateDNS),
		GroupRuntime:    NewGroupRuntime(),
	}
}

// NewGroupRuntime 创建动态组内存状态，适用于 daemon 周期探测。
func NewGroupRuntime() *GroupRuntime {
	return &GroupRuntime{Groups: map[string]*DynamicGroupStatus{}}
}

// ResolveSingBoxRuntime 返回实际 sing-box 二进制和工作目录。
func ResolveSingBoxRuntime() (string, string) {
	executablePath, err := os.Executable()
	if err == nil {
		if binary := SiblingSingBoxBinary(executablePath); binary != "" {
			return binary, filepath.Dir(binary)
		}
	}
	return defaultSingBoxBinary, defaultSingBoxWorkDir
}

// SiblingSingBoxBinary 查找 sboxctl 同级目录里的 sing-box。
func SiblingSingBoxBinary(executablePath string) string {
	if strings.TrimSpace(executablePath) == "" {
		return ""
	}
	dir := filepath.Dir(executablePath)
	candidate := filepath.Join(dir, "sing-box")
	if samePath(candidate, executablePath) {
		return ""
	}
	if isUsableSingBoxBinary(candidate) {
		return candidate
	}
	return ""
}

// isUsableSingBoxBinary 判断路径是否可作为 sing-box 二进制执行。
func isUsableSingBoxBinary(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode().Perm()&0111 != 0
}

// samePath 判断两个本地路径是否指向同一个清洗后的路径。
func samePath(left string, right string) bool {
	return filepath.Clean(left) == filepath.Clean(right)
}

// Run 根据子命令执行编排操作。
func (a *App) Run(args []string) error {
	cmd := "help"
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "init":
		return a.Init()
	case "update":
		return a.Update(false)
	case "render":
		return a.Render()
	case "start":
		return a.Start()
	case "daemon":
		return a.Daemon()
	case "stop":
		return a.Stop()
	case "restart":
		return a.Restart()
	case "status":
		return a.Status()
	case "web":
		return a.Web()
	case "install-openwrt":
		return a.InstallOpenWrt()
	case "log":
		return a.PrintLog(args[1:])
	case "doctor":
		return a.Doctor(args[1:])
	case "help", "-h", "--help":
		PrintHelp(os.Stdout)
		return nil
	default:
		return fmt.Errorf("未知命令: %s", cmd)
	}
}

// DefaultLogConfig 返回默认日志配置。
func DefaultLogConfig() LogConfig {
	return LogConfig{
		Level:     "info",
		Dir:       defaultLogDir,
		MaxSizeMB: 5,
		MaxFiles:  5,
	}
}

// PrintHelp 输出命令帮助。
func PrintHelp(w io.Writer) {
	fmt.Fprintln(w, "sboxctl init|update|render|start|daemon|stop|restart|status|web|install-openwrt|log|doctor cleanup-tun")
}

// Doctor 执行显式诊断和修复命令，适用于人工介入的故障现场。
func (a *App) Doctor(args []string) error {
	if len(args) == 0 {
		return errors.New("doctor 需要子命令: cleanup-tun")
	}
	switch args[0] {
	case "cleanup-tun":
		return a.CleanupTunNetwork()
	default:
		return fmt.Errorf("未知 doctor 子命令: %s", args[0])
	}
}

// Init 创建默认目录、配置文件和规则文件。
func (a *App) Init() error {
	cfg := DefaultConfig()
	a.ensureLogger(cfg.Log)
	a.Logger.Info("初始化目录和默认配置")
	if err := os.MkdirAll(filepath.Dir(a.ConfigPath), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(a.GeoDir, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(a.SubscriptionDir, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.SingBoxConfig), 0755); err != nil {
		return err
	}
	if err := writeFileIfMissing(a.ConfigPath, []byte(DefaultConfigYAML())); err != nil {
		return err
	}
	if err := writeFileIfMissing(a.ForceProxyPath, []byte("# domain:openai.com\n# src:10.0.0.10\n# dst:8.8.8.8\n")); err != nil {
		return err
	}
	if err := writeFileIfMissing(a.ForceDirectPath, []byte("# domain:lan\n# src:10.0.0.0/24\n# dst:10.0.0.0/8\n")); err != nil {
		return err
	}
	return nil
}

// DefaultConfig 返回可运行的默认配置。
func DefaultConfig() Config {
	return Config{
		Service: ServiceConfig{
			Enabled: boolPtr(true),
		},
		Log: DefaultLogConfig(),
		Policy: PolicyConfig{
			Default: "",
		},
		Web: WebConfig{
			Enabled:  true,
			Listen:   defaultWebListen,
			Port:     defaultWebPort,
			TokenTTL: defaultWebTokenTTL,
			Lock: WebLockConfig{
				MaxAttempts: defaultWebLockAttempts,
				Duration:    defaultWebLockDuration,
			},
		},
		GeoFiles: GeoFilesConfig{
			AdsBlock:      true,
			HostsOverride: boolPtr(true),
			ProxyRuleSets: append([]string(nil), defaultProxyRuleSets...),
		},
	}
}

// boolPtr 返回布尔指针，适用于区分未配置和显式 false。
func boolPtr(value bool) *bool {
	return &value
}

// ServiceEnabled 返回数据面服务开关，旧配置缺失时按开启处理。
func ServiceEnabled(cfg Config) bool {
	return cfg.Service.Enabled == nil || *cfg.Service.Enabled
}

// DefaultConfigYAML 返回默认 YAML 文本。
func DefaultConfigYAML() string {
	return `service:
  enabled: true

log:
  level: info
  dir: /var/log/sboxctl
  max_size_mb: 5
  max_files: 5

backend:
  static:
    # - protocol: hy2
    #   key: hy2-a
    #   server: example.com
    #   port: 443
    #   password: change-me
    #   sni: example.com
    #   insecure: false
    #   obfs_password:
    # - protocol: vmess
    #   key: vmess-a
    #   server: example.com
    #   port: 443
    #   uuid: 00000000-0000-0000-0000-000000000000
    #   security: auto
    #   tls: true
    #   transport: ws
    #   path: /
    #   host: example.com
    # - protocol: ss
    #   key: ss-a
    #   server: example.com
    #   port: 8388
    #   method: aes-128-gcm
    #   password: change-me
    #   plugin: obfs-local
    #   plugin_opts: obfs=http;obfs-host=example.com
    # - protocol: trojan
    #   key: trojan-a
    #   server: example.com
    #   port: 443
    #   password: change-me
    #   sni: example.com
    #   tls: true
    #   insecure: false
    #   transport: ws
    #   path: /
    #   host: example.com
    # - protocol: anytls
    #   key: anytls-a
    #   server: example.com
    #   port: 443
    #   password: change-me
    #   sni: example.com
    #   insecure: false
    #   idle_session_check_interval:
    #   idle_session_timeout:
    #   min_idle_session: 0
  subscription:
    # - name: main
    #   url: https://example.com/sub
    #   enabled: true
    #   user_agent: sing-box/1.13.12
    #   default: jp-hy2

inbound:
  mode: tun
  mixed:
    listen: 0.0.0.0
    port: 1080
    users:
      # - username: user
      #   password: pass

update:
  # proxy: http://127.0.0.1:7890
  dns: 223.5.5.5:53
  geofiles_use_proxy: true
  subscription_use_proxy: false

geofiles:
  ads_block: true
  hosts_override: true
  proxy_rule_sets:
    - geosite-gfw
    - geosite-greatfire
    - geosite-google
    - geoip-google
    - geoip-facebook
    - geoip-fastly
    - geoip-netflix
    - geoip-telegram
    - geoip-twitter

policy:
  default:
  fallback:

web:
  enabled: true
  listen: 0.0.0.0
  port: 9000
  jwt_secret:
  token_ttl: 24h
  auth:
    username:
    password:
  lock:
    max_attempts: 3
    duration: 1h
`
}

// Update 更新内置 geofiles，forceMissing 为 true 时只补齐缺失文件。
func (a *App) Update(forceMissing bool) error {
	cfg, err := a.LoadConfig()
	if err != nil {
		return err
	}
	a.ensureLogger(cfg.Log)
	a.configureHTTPClient(cfg.Update, cfg.Update.GeoFilesUseProxy)
	a.Logger.Info("开始更新 geofiles")
	if err := os.MkdirAll(a.GeoDir, 0755); err != nil {
		return err
	}
	changed := 0
	total := 0
	for _, name := range geoIPNames {
		total++
		ok, err := a.downloadGeo("geoip", name, forceMissing)
		if err != nil {
			if forceMissing {
				return err
			}
			a.Logger.Warn("geoip 更新失败 name=%s err=%v", name, err)
			continue
		}
		if ok {
			changed++
		}
	}
	for _, name := range geoSiteNames {
		total++
		ok, err := a.downloadGeo("geosite", name, forceMissing)
		if err != nil {
			if forceMissing {
				return err
			}
			a.Logger.Warn("geosite 更新失败 name=%s err=%v", name, err)
			continue
		}
		if ok {
			changed++
		}
	}
	a.Logger.Info("geofiles 更新完成 changed=%d total=%d", changed, total)
	if err := a.UpdateSubscriptionCaches(&cfg, forceMissing); err != nil {
		return err
	}
	if !forceMissing {
		if err := SaveRuntimeState(RuntimeState{LastUpdateSuccess: time.Now().Format(time.RFC3339)}); err != nil {
			a.Logger.Warn("运行状态写入失败 err=%v", err)
		}
	}
	return nil
}

// Render 读取配置并生成 sing-box 配置文件。
func (a *App) Render() error {
	return a.render(true)
}

// GenerateSingBoxConfigText 生成 Web 展示用 sing-box JSON。
func (a *App) GenerateSingBoxConfigText(cfg Config) (string, error) {
	backends, err := a.ResolveBackends(&cfg, false)
	if err != nil {
		return "", err
	}
	directRules, err := ParseLocalRulesFile(a.ForceDirectPath)
	if err != nil {
		return "", err
	}
	proxyRules, err := ParseLocalRulesFile(a.ForceProxyPath)
	if err != nil {
		return "", err
	}
	doc, err := a.BuildSingBoxConfig(cfg, backends, directRules, proxyRules, cfg.Policy.DynamicOutbound)
	if err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	data = append(data, '\n')
	return string(data), nil
}

// render 读取配置并生成 sing-box 配置文件，可选择是否补齐缺失缓存。
func (a *App) render(ensureMissing bool) error {
	cfg, err := a.LoadConfig()
	if err != nil {
		return err
	}
	a.ensureLogger(cfg.Log)
	a.configureHTTPClient(cfg.Update, cfg.Update.GeoFilesUseProxy)
	a.Logger.Info("开始渲染 sing-box 配置")
	if ensureMissing {
		if err := a.Update(true); err != nil {
			return err
		}
	}
	backends, err := a.ResolveBackends(&cfg, false)
	if err != nil {
		return err
	}
	directRules, err := ParseLocalRulesFile(a.ForceDirectPath)
	if err != nil {
		return err
	}
	proxyRules, err := ParseLocalRulesFile(a.ForceProxyPath)
	if err != nil {
		return err
	}
	doc, err := a.BuildSingBoxConfig(cfg, backends, directRules, proxyRules, cfg.Policy.DynamicOutbound)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(a.SingBoxConfig), 0755); err != nil {
		return err
	}
	tmp := a.SingBoxConfig + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmp, a.SingBoxConfig); err != nil {
		return err
	}
	a.Logger.Info("sing-box 配置渲染完成 path=%s", a.SingBoxConfig)
	return nil
}

// Start 渲染配置后启动 sing-box。
func (a *App) Start() error {
	cfg, err := a.LoadConfig()
	if err != nil {
		return err
	}
	a.ensureLogger(cfg.Log)
	if !ServiceEnabled(cfg) {
		a.Logger.Info("sing-box 服务开关关闭，跳过启动")
		return a.Stop()
	}
	a.Logger.Info("启动流程开始")
	if err := a.Render(); err != nil {
		if errors.Is(err, ErrNoAvailableBackend) {
			a.Logger.Warn("没有可用 backend，跳过 sing-box 启动")
			return a.Stop()
		}
		return err
	}
	a.Logger.RotateFile(filepath.Join(a.Logger.Dir, "sing-box.log"))
	// 触发条件：启动入口需要确保旧数据面已退出。
	// 不能直接叠加启动，避免新旧 sing-box 同时占用 TUN。
	// 防止控制面误判数据面已经替换成功。
	if err := a.restartSingBoxService(); err != nil {
		return err
	}
	a.Logger.Info("sing-box 启动完成")
	return nil
}

// Stop 停止 sing-box。
func (a *App) Stop() error {
	cfg, _ := a.LoadConfig()
	a.ensureLogger(cfg.Log)
	a.Logger.Info("停止 sing-box")
	if err := a.stopSingBoxProcess(); err != nil {
		return err
	}
	return nil
}

// CleanupTunNetwork 强制清理 sing-box TUN 残留网络状态。
func (a *App) CleanupTunNetwork() error {
	cfg, err := a.LoadConfig()
	if err != nil {
		cfg = DefaultConfig()
	}
	a.ensureLogger(cfg.Log)
	a.Logger.Warn("开始强制清理 TUN 网络残留")
	// 触发条件：sing-box TUN 被 SIGKILL、断电或内核异常打断。
	// 不能调用 sing-box/sing-tun 的 Close，因为旧进程的随机表状态已丢失。
	// 防止把恢复命令挂到启动流程，导致平时偷偷改系统网络。
	cmd := exec.Command("sh", "-c", CleanupTunNetworkScript())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		a.Logger.Error("强制清理 TUN 网络残留失败 err=%v", err)
		return err
	}
	a.Logger.Warn("强制清理 TUN 网络残留完成")
	return nil
}

// CleanupTunNetworkScript 返回强制清理 TUN 残留的 shell 脚本。
func CleanupTunNetworkScript() string {
	return `set +e

log() {
  printf '%s\n' "$*"
}

try() {
  log "+ $*"
  "$@" 2>/dev/null || true
}

if [ "$(id -u)" != "0" ]; then
  printf 'cleanup-tun 需要 root 权限\n' >&2
  exit 1
fi

log "停止 sing-box 进程"
try pkill -TERM -x sing-box
try pkill -TERM -x singbox
try pkill -TERM -f '[s]ing-box.*run'
sleep 2
try pkill -KILL -x sing-box
try pkill -KILL -x singbox
try pkill -KILL -f '[s]ing-box.*run'

log "清理 systemd-resolved 的 TUN DNS 状态"
for dev in sbox0 singbox_tun tun tun0 tun1 tun2 tun3 tun4 tun5; do
  try resolvectl revert "$dev"
done
try resolvectl flush-caches

log "清理 nftables 和 OpenWrt fw4 残留"
if command -v nft >/dev/null 2>&1; then
  for family in inet ip ip6 bridge netdev arp; do
    try nft delete table "$family" sing-box
    try nft delete table "$family" sboxctl
  done
  nft -a list ruleset 2>/dev/null | awk '
    /^table / { family=$2; table=$3 }
    /^[ \t]*chain / { chain=$2 }
    /!sing-box:/ || /!sboxctl:/ {
      for (i = 1; i <= NF; i++) {
        if ($i == "handle") print family, table, chain, $(i + 1)
      }
    }
  ' | while read family table chain handle; do
    [ -n "$family" ] && try nft delete rule "$family" "$table" "$chain" handle "$handle"
  done
fi
try rm -f /etc/nftables.d/0-sing-box-auto-redirect.nft
try rm -f /etc/nftables.d/0-sboxctl-auto-redirect.nft

log "清理 iptables fallback 链"
for bin in iptables ip6tables iptables-nft ip6tables-nft iptables-legacy ip6tables-legacy; do
  if command -v "$bin" >/dev/null 2>&1; then
    for chain in sing-box-output sing-box-prerouting sboxctl-output sboxctl-prerouting; do
      try "$bin" -t nat -D OUTPUT -j "$chain"
      try "$bin" -t nat -D PREROUTING -j "$chain"
      try "$bin" -t nat -F "$chain"
      try "$bin" -t nat -X "$chain"
    done
  fi
done

cleanup_tables=$({
  printf '%s\n' 2022
  ip -4 rule show 2>/dev/null
  ip -6 rule show 2>/dev/null
  ip -4 route show table all 2>/dev/null
  ip -6 route show table all 2>/dev/null
} | awk '
  /^local 127\.0\.0\.1/ || /^local ::1/ || / dev (sbox0|singbox_tun|tun[0-9]*)/ {
    for (i = 1; i < NF; i++) if ($i == "table") print $(i + 1)
  }
  {
    p=$1
    sub(":", "", p)
    pn=p+0
    suspicious=(pn == 1 || (pn >= 9000 && pn <= 9010) || pn == 32768 || index($0, "0x2023") || index($0, "0x2024") || index($0, "0x2025") || index($0, "lookup 2022"))
    if (suspicious) {
      for (i = 1; i < NF; i++) if ($i == "lookup") print $(i + 1)
    }
  }
' | sort -u)

log "清理可疑 route table"
for table in $cleanup_tables; do
  case "$table" in
    ""|local|main|default|unspec)
      continue
      ;;
  esac
  try ip -4 route flush table "$table"
  try ip -6 route flush table "$table"
done

delete_rules_for_family() {
  fam="$1"
  while :; do
    pref=$(ip "$fam" rule show 2>/dev/null | awk '
      {
        p=$1
        sub(":", "", p)
        pn=p+0
        if (pn == 1 || (pn >= 9000 && pn <= 9010) || pn == 32768 || index($0, "0x2023") || index($0, "0x2024") || index($0, "0x2025") || index($0, "lookup 2022")) {
          print pn
          exit
        }
      }
    ')
    [ -n "$pref" ] || break
    try ip "$fam" rule del pref "$pref"
  done
}

log "清理可疑 ip rule"
delete_rules_for_family -4
delete_rules_for_family -6

log "删除 TUN 设备"
for dev in $(ip -o link show 2>/dev/null | awk -F': ' '{ dev=$2; sub("@.*", "", dev); if (dev ~ /^(sbox0|singbox_tun|tun[0-9]*)$/) print dev }' | sort -u); do
  try resolvectl revert "$dev"
  try ip link set "$dev" down
  try ip link del "$dev"
done

try ip route flush cache
try ip -6 route flush cache
try conntrack -F

log "重载网络服务"
try fw4 reload
if [ -x /etc/init.d/firewall ]; then
  try /etc/init.d/firewall restart
fi
if [ -x /etc/init.d/dnsmasq ]; then
  try /etc/init.d/dnsmasq restart
fi
if [ -x /etc/init.d/network ]; then
  try /etc/init.d/network reload
fi
try systemctl restart systemd-resolved
try systemctl restart NetworkManager
try systemctl restart firewalld

log "cleanup-tun 完成"
`
}

// Restart 渲染配置后重启 sing-box。
func (a *App) Restart() error {
	cfg, err := a.LoadConfig()
	if err != nil {
		return err
	}
	a.ensureLogger(cfg.Log)
	if !ServiceEnabled(cfg) {
		a.Logger.Info("sing-box 服务开关关闭，执行停止")
		return a.Stop()
	}
	a.Logger.Info("重启流程开始")
	if err := a.render(true); err != nil {
		if errors.Is(err, ErrNoAvailableBackend) {
			a.Logger.Warn("没有可用 backend，停止 sing-box 数据面")
			return a.Stop()
		}
		return err
	}
	a.Logger.RotateFile(filepath.Join(a.Logger.Dir, "sing-box.log"))
	if err := a.restartSingBoxService(); err != nil {
		return err
	}
	a.Logger.Info("sing-box 重启完成")
	return nil
}

// Status 输出 sing-box 运行状态。
func (a *App) Status() error {
	cfg, _ := a.LoadConfig()
	a.ensureLogger(cfg.Log)
	running, err := hasSingBoxProcess()
	if err != nil {
		return err
	}
	if running {
		fmt.Println("running")
		return nil
	}
	fmt.Println("stopped")
	return nil
}

// Web 前台启动内置 Web 面板，适用于本地排障和手动运行。
func (a *App) Web() error {
	cfg, err := a.LoadConfig()
	if err != nil {
		return err
	}
	a.ensureLogger(cfg.Log)
	server, err := a.StartWebServer(cfg)
	if err != nil {
		return err
	}
	a.Logger.Info("web 面板启动 addr=%s", server.Server.Addr)
	return server.Server.ListenAndServe()
}

// Daemon 常驻运行编排器，适用于 OpenWrt 服务托管更新调度。
func (a *App) Daemon() error {
	cfg, err := a.LoadConfig()
	if err != nil {
		return err
	}
	a.ensureLogger(cfg.Log)
	a.Logger.Info("daemon 启动")
	if err := a.Start(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.RunDynamicGroupProber(ctx)
	var webServer *WebServer
	if cfg.Web.Enabled {
		webServer, err = a.StartWebServer(cfg)
		if err != nil {
			return err
		}
		go func() {
			if serveErr := webServer.Server.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				a.Logger.Error("web 面板异常退出: %v", serveErr)
			}
		}()
		a.Logger.Info("web 面板启动 addr=%s", webServer.Server.Addr)
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	for {
		next := NextDailyTime(time.Now(), 4, 0)
		wait := time.NewTimer(time.Until(next))
		a.Logger.Info("下一次自动更新时间: %s", next.Format(time.RFC3339))
		select {
		case sig := <-signals:
			wait.Stop()
			cancel()
			a.Logger.Info("daemon 收到退出信号: %s", sig)
			if webServer != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_ = webServer.Server.Shutdown(ctx)
				cancel()
			}
			if err := a.Stop(); err != nil {
				a.Logger.Warn("停止 sing-box 失败 err=%v", err)
			}
			return nil
		case <-wait.C:
			a.Logger.Info("开始自动更新")
			if err := a.Update(false); err != nil {
				a.Logger.Error("自动更新失败: %v", err)
				continue
			}
			if err := a.Restart(); err != nil {
				a.Logger.Error("自动重启失败: %v", err)
				continue
			}
			a.Logger.Info("自动更新完成")
		}
	}
}

// RunDynamicGroupProber 周期探测被配置引用的动态组。
func (a *App) RunDynamicGroupProber(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			startedAt := time.Now()
			a.probeReferencedDynamicGroups(ctx)
			nextWait := defaultGroupProbeCycle - time.Since(startedAt)
			if nextWait < 0 {
				nextWait = 0
			}
			timer.Reset(nextWait)
		}
	}
}

// probeReferencedDynamicGroups 探测所有被配置引用的动态组。
func (a *App) probeReferencedDynamicGroups(ctx context.Context) {
	cfg, err := a.LoadConfig()
	if err != nil {
		a.Logger.Warn("动态组读取配置失败 err=%v", err)
		return
	}
	if !ServiceEnabled(cfg) {
		return
	}
	groups := referencedDynamicGroups(cfg)
	if len(groups) == 0 {
		return
	}
	memberTags, err := a.ResolveMemberTagMap(&cfg)
	if err != nil {
		a.Logger.Warn("动态组解析成员失败 err=%v", err)
		return
	}
	for _, group := range groups {
		if !sleepContext(ctx, 0) {
			return
		}
		if err := a.ProbeDynamicGroup(ctx, group, memberTags); err != nil {
			a.Logger.Warn("动态组探测失败 group=%s err=%v", group.Key, err)
		}
	}
}

// ProbeDynamicGroup 执行动态组三轮探测并切换 selector。
func (a *App) ProbeDynamicGroup(ctx context.Context, group DynamicGroupConfig, memberTags map[string]string) error {
	if a.GroupRuntime == nil {
		a.GroupRuntime = NewGroupRuntime()
	}
	groupTag := RuntimeBackendTag("group", group.Key)
	activeMembers := GroupMemberTags(group, memberTags)
	if len(activeMembers) == 0 {
		return fmt.Errorf("动态组没有可用成员: %s", group.Key)
	}
	immediateMember := a.GroupRuntime.Status(group.Key).BestMember
	for i, delay := range groupProbeDelays {
		if !sleepContext(ctx, delay) {
			return ctx.Err()
		}
		for _, memberRef := range group.Members {
			tag := activeMembers[memberRef]
			if tag == "" {
				continue
			}
			record := GroupProbeRecord{At: time.Now().Format(time.RFC3339)}
			delayMS, err := a.ProbeOutboundDelay(tag, "")
			if err != nil {
				record.Error = err.Error()
			} else {
				record.OK = true
				record.DelayMS = delayMS
			}
			a.GroupRuntime.AppendProbe(group.Key, memberRef, record)
			a.Logger.Info("动态组探测 group=%s member=%s round=%d ok=%v delay=%d", group.Key, memberRef, i+1, record.OK, record.DelayMS)
			// 触发条件：主备模式主节点最新探测失败。
			// 不能直接等三轮结束，否则失败已经出现时仍会继续走主节点。
			// 防止故障主节点在完整探测窗口内继续承载流量。
			nextImmediateMember, switchErr := a.SwitchPrimaryBackupAfterProbe(group, groupTag, activeMembers, immediateMember)
			if switchErr != nil {
				return switchErr
			}
			if nextImmediateMember != "" {
				immediateMember = nextImmediateMember
			}
		}
	}
	status := a.GroupRuntime.Status(group.Key)
	bestMember := EvaluateGroupTarget(group, status.Results)
	if bestMember == "" {
		return fmt.Errorf("动态组没有成功探测结果: %s", group.Key)
	}
	bestTag := activeMembers[bestMember]
	currentMember := status.BestMember
	a.GroupRuntime.SetBest(group.Key, bestMember, bestTag)
	if err := a.SwitchSelectorOutbound(groupTag, bestTag); err != nil {
		return err
	}
	if normalizeDynamicGroupMode(group.Mode) == dynamicGroupModePrimaryBackup {
		if bestMember == group.Primary && currentMember != "" && currentMember != group.Primary {
			a.Logger.Info("主备组主节点恢复 group=%s primary=%s tag=%s", group.Key, group.Primary, bestTag)
		} else if bestMember != group.Primary && currentMember != bestMember {
			a.Logger.Warn("主备组主节点失败，切换备节点 group=%s primary=%s backup=%s tag=%s", group.Key, group.Primary, bestMember, bestTag)
		}
	} else {
		a.Logger.Info("动态组切换 group=%s member=%s tag=%s", group.Key, bestMember, bestTag)
	}
	return nil
}

// SwitchPrimaryBackupAfterProbe 在主节点单次失败后立即切到已知可用备节点。
func (a *App) SwitchPrimaryBackupAfterProbe(group DynamicGroupConfig, groupTag string, activeMembers map[string]string, currentMember string) (string, error) {
	if normalizeDynamicGroupMode(group.Mode) != dynamicGroupModePrimaryBackup {
		return "", nil
	}
	primary := strings.TrimSpace(group.Primary)
	if currentMember != "" && currentMember != primary {
		return "", nil
	}
	status := a.GroupRuntime.Status(group.Key)
	bestMember := EvaluatePrimaryBackupImmediateTarget(group, status.Results)
	if bestMember == "" || bestMember == currentMember {
		return "", nil
	}
	bestTag := activeMembers[bestMember]
	if bestTag == "" {
		return "", nil
	}
	a.GroupRuntime.SetBest(group.Key, bestMember, bestTag)
	if err := a.SwitchSelectorOutbound(groupTag, bestTag); err != nil {
		return "", err
	}
	a.Logger.Warn("主备组主节点失败，立即切换备节点 group=%s primary=%s backup=%s tag=%s", group.Key, group.Primary, bestMember, bestTag)
	return bestMember, nil
}

// ResolveMemberTagMap 解析所有真实节点链路 key 到 outbound tag。
func (a *App) ResolveMemberTagMap(cfg *Config) (map[string]string, error) {
	refs := map[string]string{}
	for _, b := range cfg.Backend.Static {
		node := b
		NormalizeBackendIdentity(&node)
		refs["static."+node.BackendKey()] = RuntimeBackendTag("static", node.BackendKey())
	}
	for _, sub := range cfg.Backend.Subscription {
		if !sub.Enabled {
			continue
		}
		nodes, err := a.ResolveSubscriptionNodes(cfg, sub, false)
		if err != nil {
			a.Logger.Warn("动态组跳过不可用订阅 name=%s err=%v", sub.Name, err)
			continue
		}
		MakeUniqueBackendKeys(nodes)
		for _, node := range nodes {
			refs["sub."+sub.Key+"."+node.BackendKey()] = RuntimeBackendTag("sub-"+sub.Key, node.BackendKey())
		}
	}
	for _, item := range cfg.Backend.Imports {
		nodes, err := a.LoadSubscriptionCache(item.Key)
		if err != nil {
			a.Logger.Warn("动态组跳过不可用导入 key=%s err=%v", item.Key, err)
			continue
		}
		MakeUniqueBackendKeys(nodes)
		for _, node := range nodes {
			refs["import."+item.Key+"."+node.BackendKey()] = RuntimeBackendTag("import-"+item.Key, node.BackendKey())
		}
	}
	return refs, nil
}

// GroupMemberTags 返回动态组成员链路 key 到 outbound tag 的映射。
func GroupMemberTags(group DynamicGroupConfig, memberTags map[string]string) map[string]string {
	result := map[string]string{}
	for _, member := range group.Members {
		if tag := memberTags[member]; tag != "" {
			result[member] = tag
		}
	}
	return result
}

// EvaluateGroupBest 根据最近记录选出稳定成员。
func EvaluateGroupBest(members []string, results map[string][]GroupProbeRecord) string {
	best := ""
	bestOK := -1
	bestAvg := int(^uint(0) >> 1)
	for _, member := range members {
		records := results[member]
		okCount := 0
		sum := 0
		for _, record := range records {
			if !record.OK {
				continue
			}
			okCount++
			sum += record.DelayMS
		}
		if okCount == 0 {
			continue
		}
		avg := sum / okCount
		if okCount > bestOK || okCount == bestOK && avg < bestAvg {
			best = member
			bestOK = okCount
			bestAvg = avg
		}
	}
	return best
}

// EvaluateGroupTarget 根据组模式选出目标成员。
func EvaluateGroupTarget(group DynamicGroupConfig, results map[string][]GroupProbeRecord) string {
	if normalizeDynamicGroupMode(group.Mode) != dynamicGroupModePrimaryBackup {
		return EvaluateGroupBest(group.Members, results)
	}
	primary := strings.TrimSpace(group.Primary)
	if primary == "" {
		return EvaluateGroupBest(group.Members, results)
	}
	if groupMemberRecentlyOK(primary, results) {
		return primary
	}
	var backups []string
	for _, member := range group.Members {
		if member != primary {
			backups = append(backups, member)
		}
	}
	if best := EvaluateGroupBest(backups, results); best != "" {
		return best
	}
	return primary
}

// EvaluatePrimaryBackupImmediateTarget 在主节点最新记录失败时选择可立即接管的备节点。
func EvaluatePrimaryBackupImmediateTarget(group DynamicGroupConfig, results map[string][]GroupProbeRecord) string {
	if normalizeDynamicGroupMode(group.Mode) != dynamicGroupModePrimaryBackup {
		return ""
	}
	primary := strings.TrimSpace(group.Primary)
	if primary == "" || !groupMemberLastFailed(primary, results) {
		return ""
	}
	var backups []string
	for _, member := range group.Members {
		if member != primary {
			backups = append(backups, member)
		}
	}
	return EvaluateGroupBest(backups, results)
}

// groupMemberRecentlyOK 判断成员最新一次探测是否成功。
func groupMemberRecentlyOK(member string, results map[string][]GroupProbeRecord) bool {
	records := results[member]
	if len(records) == 0 {
		return false
	}
	// 触发条件：主备组一轮三次探测中间发生抖动。
	// 不能直接看三次里是否存在失败，否则最后恢复的主节点仍被判异常。
	// 防止主节点短暂失败后在轮末被错误留在备节点。
	return records[len(records)-1].OK
}

// groupMemberLastFailed 判断成员最新一次探测是否失败。
func groupMemberLastFailed(member string, results map[string][]GroupProbeRecord) bool {
	records := results[member]
	if len(records) == 0 {
		return false
	}
	return !records[len(records)-1].OK
}

// normalizeDynamicGroupMode 规范化动态组模式。
func normalizeDynamicGroupMode(mode string) string {
	switch strings.TrimSpace(mode) {
	case dynamicGroupModePrimaryBackup:
		return dynamicGroupModePrimaryBackup
	default:
		return dynamicGroupModeDynamic
	}
}

// normalizeDynamicGroupPrimary 清洗主备模式主节点引用。
func normalizeDynamicGroupPrimary(mode string, primary string, members []string) string {
	if mode != dynamicGroupModePrimaryBackup {
		return ""
	}
	primary = strings.TrimSpace(primary)
	if containsString(members, primary) {
		return primary
	}
	return firstString(members)
}

// SwitchSelectorOutbound 通过 Clash API 切换 selector 当前出口。
func (a *App) SwitchSelectorOutbound(selectorTag string, outboundTag string) error {
	endpoint := "http://" + defaultClashAPIListen + "/proxies/" + url.PathEscape(selectorTag)
	body, err := json.Marshal(map[string]string{"name": outboundTag})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("selector 切换失败: %s %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}

// CloseClashConnections 关闭 sing-box 当前连接，适用于 selector 热切后立即生效。
func (a *App) CloseClashConnections() error {
	endpoint := "http://" + defaultClashAPIListen + "/connections"
	req, err := http.NewRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("连接清理失败: %s %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}

// FetchWebConnections 读取 sing-box 当前连接并整理为 Web 展示结构。
func (a *App) FetchWebConnections() (WebConnectionsResponse, error) {
	endpoint := "http://" + defaultClashAPIListen + "/connections"
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	resp, err := client.Get(endpoint)
	if err != nil {
		return WebConnectionsResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return WebConnectionsResponse{}, fmt.Errorf("连接读取失败: %s %s", resp.Status, strings.TrimSpace(string(data)))
	}
	var raw clashConnectionsResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8*1024*1024)).Decode(&raw); err != nil {
		return WebConnectionsResponse{}, err
	}
	connections := make([]WebConnection, 0, len(raw.Connections))
	for _, item := range raw.Connections {
		connections = append(connections, WebConnectionFromClash(item))
	}
	sort.SliceStable(connections, func(i, j int) bool {
		return connections[i].Total > connections[j].Total
	})
	return WebConnectionsResponse{
		UpdatedAt:     time.Now().Format(time.RFC3339),
		Total:         len(connections),
		UploadTotal:   raw.UploadTotal,
		DownloadTotal: raw.DownloadTotal,
		Connections:   connections,
	}, nil
}

// WebConnectionFromClash 把 Clash API 连接转换成 Web 展示行。
func WebConnectionFromClash(item clashConnection) WebConnection {
	total := item.Upload + item.Download
	destinationHost := firstNonEmpty(item.Metadata.Host, item.Metadata.DestinationIP)
	return WebConnection{
		ID:              item.ID,
		Network:         item.Metadata.Network,
		Source:          formatHostPort(item.Metadata.SourceIP, int(item.Metadata.SourcePort)),
		Destination:     formatHostPort(destinationHost, int(item.Metadata.DestinationPort)),
		Host:            item.Metadata.Host,
		DestinationIP:   item.Metadata.DestinationIP,
		DestinationPort: int(item.Metadata.DestinationPort),
		Upload:          item.Upload,
		Download:        item.Download,
		Total:           total,
		Chains:          append([]string(nil), item.Chains...),
		ChainText:       strings.Join(item.Chains, " > "),
		Decision:        classifyConnectionDecision(item.Chains),
		Rule:            item.Rule,
		RulePayload:     item.RulePayload,
		StartedAt:       item.Start,
	}
}

// classifyConnectionDecision 根据出站链路判断连接最终方向。
func classifyConnectionDecision(chains []string) string {
	if len(chains) == 0 {
		return "unknown"
	}
	for _, chain := range chains {
		clean := strings.ToLower(strings.TrimSpace(chain))
		if clean == "block" || clean == "reject" {
			return "reject"
		}
	}
	for _, chain := range chains {
		if strings.TrimSpace(chain) == "direct" {
			return "direct"
		}
	}
	return "proxy"
}

// formatHostPort 格式化地址和端口，允许地址为空时只展示端口。
func formatHostPort(host string, port int) string {
	host = strings.TrimSpace(host)
	if port <= 0 {
		return host
	}
	if host == "" {
		return ":" + strconv.Itoa(port)
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(port))
}

// sleepContext 等待指定时长，并在退出信号到来时中断。
func sleepContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// NextDailyTime 返回下一次每天固定时间。
func NextDailyTime(now time.Time, hour int, minute int) time.Time {
	next := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, now.Location())
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return next
}

// InstallOpenWrt 写入 OpenWrt init.d 服务配置。
func (a *App) InstallOpenWrt() error {
	cfg, err := a.LoadConfig()
	if err != nil {
		return err
	}
	a.ensureLogger(cfg.Log)
	a.Logger.Info("安装 OpenWrt daemon 服务")
	if err := a.Init(); err != nil {
		return err
	}
	if err := writeExecutable("/etc/init.d/sboxctl", []byte(initScript())); err != nil {
		return err
	}
	if err := runCommand("/etc/init.d/sboxctl", "enable"); err != nil {
		return err
	}
	if err := removeCronLine("sboxctl update"); err != nil {
		return err
	}
	return nil
}

// PrintLog 打印指定日志文件内容。
func (a *App) PrintLog(args []string) error {
	cfg, _ := a.LoadConfig()
	a.ensureLogger(cfg.Log)
	name := "sboxctl.log"
	if len(args) > 0 {
		switch args[0] {
		case "error":
			name = "error.log"
		case "singbox", "sing-box":
			name = "sing-box.log"
		}
	}
	data, err := os.ReadFile(filepath.Join(a.Logger.Dir, name))
	if err != nil {
		return err
	}
	fmt.Print(string(data))
	return nil
}

// LoadConfig 读取并解析主配置文件。
func (a *App) LoadConfig() (Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(a.ConfigPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, err
	}
	return ParseConfigYAML(data)
}

// ResolveBackends 合并静态后端和订阅后端，启动路径只在缓存缺失时联网。
func (a *App) ResolveBackends(cfg *Config, refreshSubscriptions bool) ([]ProxyBackend, error) {
	result := make([]ProxyBackend, 0, len(cfg.Backend.Static))
	memberTags := map[string]string{}
	staticNodes := make([]*StaticBackend, 0, len(cfg.Backend.Static))
	for _, b := range cfg.Backend.Static {
		node := b
		NormalizeBackendIdentity(&node)
		node.SetBackendSource("static")
		node.SetBackendTag(RuntimeBackendTag("static", node.BackendKey()))
		memberTags["static."+node.BackendKey()] = node.BackendTag()
		staticNodes = append(staticNodes, &node)
		result = append(result, &node)
	}
	for _, sub := range cfg.Backend.Subscription {
		if !sub.Enabled {
			continue
		}
		nodes, err := a.ResolveSubscriptionNodes(cfg, sub, refreshSubscriptions)
		if err != nil {
			a.Logger.Warn("跳过不可用订阅 name=%s err=%v", sub.Name, err)
			continue
		}
		MakeUniqueBackendKeys(nodes)
		for _, node := range nodes {
			node.SetBackendSource("subscription:" + sub.Name)
			node.SetBackendTag(RuntimeBackendTag("sub-"+sub.Key, node.BackendKey()))
			memberTags["sub."+sub.Key+"."+node.BackendKey()] = node.BackendTag()
			result = append(result, node)
		}
		if cfg.Policy.Default == "" && sub.Default != "" {
			cfg.Policy.Default = sub.Default
		}
	}
	for _, group := range cfg.Backend.Imports {
		nodes, err := a.LoadSubscriptionCache(group.Key)
		if err != nil {
			a.Logger.Warn("跳过不可用导入 key=%s err=%v", group.Key, err)
			continue
		}
		MakeUniqueBackendKeys(nodes)
		for _, node := range nodes {
			node.SetBackendSource("import:" + group.Key)
			node.SetBackendTag(RuntimeBackendTag("import-"+group.Key, node.BackendKey()))
			memberTags["import."+group.Key+"."+node.BackendKey()] = node.BackendTag()
			result = append(result, node)
		}
	}
	SortBackendsByProtocol(result)
	for _, group := range cfg.Backend.Groups {
		members := ResolveGroupMemberTags(group, memberTags)
		if len(members) == 0 {
			continue
		}
		primaryTag := memberTags[group.Primary]
		bestTag := a.dynamicGroupInitialTag(group, members, primaryTag)
		result = append(result, &DynamicGroupBackend{
			Key:        group.Key,
			Tag:        RuntimeBackendTag("group", group.Key),
			Mode:       normalizeDynamicGroupMode(group.Mode),
			PrimaryTag: primaryTag,
			Members:    members,
			BestTag:    bestTag,
		})
		memberTags["group."+group.Key] = RuntimeBackendTag("group", group.Key)
	}
	// 触发条件：静态节点 detour 指向订阅、导入或动态组。
	// 不能在静态节点初始化时解析，因为这些目标此时尚未加载。
	// 防止链式出口生成空 detour，导致 sing-box 静默走直连拨号。
	for _, node := range staticNodes {
		if detour := strings.TrimSpace(node.Detour); detour != "" {
			node.RuntimeDetour = memberTags[detour]
		}
	}
	ResolveConfiguredDefault(cfg, result)
	return result, nil
}

// dynamicGroupBestTag 安全读取动态组当前担当 tag。
func (a *App) dynamicGroupBestTag(groupKey string) string {
	if a.GroupRuntime == nil {
		a.GroupRuntime = NewGroupRuntime()
	}
	return a.GroupRuntime.BestTag(groupKey)
}

// dynamicGroupInitialTag 返回渲染 selector 时的默认成员。
func (a *App) dynamicGroupInitialTag(group DynamicGroupConfig, members []string, primaryTag string) string {
	if normalizeDynamicGroupMode(group.Mode) == dynamicGroupModePrimaryBackup && containsString(members, primaryTag) {
		return primaryTag
	}
	bestTag := a.dynamicGroupBestTag(group.Key)
	if containsString(members, bestTag) {
		return bestTag
	}
	return firstString(members)
}

// ResolveGroupMemberTags 将动态组成员链路 key 解析为 outbound tag。
func ResolveGroupMemberTags(group DynamicGroupConfig, memberTags map[string]string) []string {
	tags := make([]string, 0, len(group.Members))
	seen := map[string]bool{}
	for _, member := range group.Members {
		tag := memberTags[member]
		if tag == "" || seen[tag] {
			continue
		}
		seen[tag] = true
		tags = append(tags, tag)
	}
	return tags
}

// ResolveSubscriptionNodes 解析单个订阅，适用于启动和刷新两类路径。
func (a *App) ResolveSubscriptionNodes(cfg *Config, sub Subscription, refresh bool) ([]ProxyBackend, error) {
	if !refresh {
		cached, err := a.LoadSubscriptionCache(sub.Key)
		if err == nil {
			a.Logger.Info("使用订阅缓存 name=%s nodes=%d", sub.Name, len(cached))
			return cached, nil
		}
		a.Logger.Warn("订阅缓存缺失，开始下载 name=%s err=%v", sub.Name, err)
	}
	nodes, err := a.FetchAndCacheSubscription(cfg, sub)
	if err == nil {
		return nodes, nil
	}
	a.Logger.Error("订阅下载失败 name=%s err=%v", sub.Name, err)
	cached, cacheErr := a.LoadSubscriptionCache(sub.Key)
	if cacheErr != nil {
		return nil, err
	}
	a.Logger.Warn("使用订阅缓存 name=%s nodes=%d", sub.Name, len(cached))
	return cached, nil
}

// UpdateSubscriptionCaches 更新订阅缓存，适用于手动和 daemon 周期更新。
func (a *App) UpdateSubscriptionCaches(cfg *Config, missingOnly bool) error {
	for _, sub := range cfg.Backend.Subscription {
		if !sub.Enabled {
			continue
		}
		if missingOnly {
			if cached, err := a.LoadSubscriptionCache(sub.Key); err == nil {
				a.Logger.Info("订阅缓存已存在，跳过下载 name=%s nodes=%d", sub.Name, len(cached))
				continue
			}
		}
		if _, err := a.FetchAndCacheSubscription(cfg, sub); err != nil {
			a.Logger.Error("订阅更新失败 name=%s err=%v", sub.Name, err)
		}
	}
	return nil
}

// FetchAndCacheSubscription 下载订阅并保存缓存，失败时不会覆盖旧缓存。
func (a *App) FetchAndCacheSubscription(cfg *Config, sub Subscription) ([]ProxyBackend, error) {
	a.configureHTTPClient(cfg.Update, cfg.Update.SubscriptionUseProxy)
	return a.fetchAndCacheSubscription(sub, "配置")
}

// FetchAndCacheSubscriptionForWeb 按 Web 按钮语义下载订阅，不读取自动更新开关。
func (a *App) FetchAndCacheSubscriptionForWeb(cfg *Config, sub Subscription, useProxy bool) ([]ProxyBackend, error) {
	if err := a.configureWebSubscriptionHTTPClient(*cfg, useProxy); err != nil {
		return nil, err
	}
	mode := "直连"
	if useProxy {
		mode = "代理"
	}
	return a.fetchAndCacheSubscription(sub, mode)
}

// fetchAndCacheSubscription 下载订阅并保存缓存，调用方负责配置 HTTP client。
func (a *App) fetchAndCacheSubscription(sub Subscription, mode string) ([]ProxyBackend, error) {
	a.Logger.Info("开始更新订阅 name=%s mode=%s", sub.Name, mode)
	nodes, skipped, failed, err := FetchSubscription(a.client(), sub)
	if err != nil {
		return nil, err
	}
	a.Logger.Info("订阅解析完成 name=%s nodes=%d skipped=%d failed=%d", sub.Name, len(nodes), skipped, failed)
	changed, err := a.SaveSubscriptionCache(sub.Key, nodes)
	if err != nil {
		return nil, err
	}
	if !changed {
		a.Logger.Info("订阅缓存无变化，跳过写入 name=%s", sub.Name)
	}
	return nodes, nil
}

// UpdateChangedSubscriptions 更新新增或修改过的订阅缓存。
func (a *App) UpdateChangedSubscriptions(before *Config, after *Config) error {
	beforeByKey := map[string]Subscription{}
	for _, sub := range before.Backend.Subscription {
		beforeByKey[sub.Key] = sub
	}
	for _, sub := range after.Backend.Subscription {
		if !sub.Enabled {
			continue
		}
		old, ok := beforeByKey[sub.Key]
		if ok && sameSubscriptionConfig(old, sub) {
			continue
		}
		if ok && a.subscriptionFetchUnchangedWithCache(old, sub) {
			continue
		}
		if _, err := a.FetchAndCacheSubscription(after, sub); err != nil {
			return fmt.Errorf("订阅更新失败 name=%s err=%w", sub.Name, err)
		}
	}
	return nil
}

// subscriptionFetchUnchangedWithCache 判断订阅内容来源未变且已有缓存。
func (a *App) subscriptionFetchUnchangedWithCache(left Subscription, right Subscription) bool {
	if !sameSubscriptionFetchSource(left, right) {
		return false
	}
	cached, err := a.LoadSubscriptionCache(right.Key)
	if err != nil || len(cached) == 0 {
		return false
	}
	// 触发条件：用户只启用已有缓存的订阅。
	// 不能直接重新下载，因为保存应用会被网络卡住。
	// 防止 enabled 切换后 sing-box 配置迟迟不渲染。
	return true
}

// sameSubscriptionConfig 判断订阅配置是否没有变化。
func sameSubscriptionConfig(left Subscription, right Subscription) bool {
	return left.Key == right.Key &&
		left.Name == right.Name &&
		left.URL == right.URL &&
		left.Enabled == right.Enabled &&
		left.UserAgent == right.UserAgent &&
		left.Default == right.Default
}

// sameSubscriptionFetchSource 判断会影响订阅下载内容的字段是否没变。
func sameSubscriptionFetchSource(left Subscription, right Subscription) bool {
	return left.Key == right.Key &&
		left.URL == right.URL &&
		left.UserAgent == right.UserAgent
}

// SaveSubscriptionCache 保存订阅解析结果，适用于订阅服务失败时兜底。
func (a *App) SaveSubscriptionCache(name string, nodes []ProxyBackend) (bool, error) {
	if err := os.MkdirAll(a.SubscriptionDir, 0755); err != nil {
		return false, err
	}
	data, err := json.MarshalIndent(SubscriptionCacheFromBackends(nodes), "", "  ")
	if err != nil {
		return false, err
	}
	path := filepath.Join(a.SubscriptionDir, SanitizeTag(name)+".json")
	return writeFileIfChanged(path, append(data, '\n'), 0644)
}

// LoadSubscriptionCache 读取订阅解析缓存。
func (a *App) LoadSubscriptionCache(name string) ([]ProxyBackend, error) {
	path := filepath.Join(a.SubscriptionDir, SanitizeTag(name)+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	nodes, err := BackendsFromSubscriptionCache(data)
	if err != nil {
		return nil, err
	}
	MakeUniqueBackendKeys(nodes)
	SortBackendsByProtocol(nodes)
	return nodes, nil
}

// StartWebServer 构造内置 Web 服务，适用于 daemon 和前台 web 命令。
func (a *App) StartWebServer(cfg Config) (*WebServer, error) {
	mux := http.NewServeMux()
	web := &WebServer{
		App:           a,
		LoginFailures: map[string]*LoginFailure{},
	}
	addr := net.JoinHostPort(cfg.Web.Listen, strconv.Itoa(cfg.Web.Port))
	web.Server = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	mux.HandleFunc("/api/health", web.handleHealth)
	mux.HandleFunc("/api/login", web.handleLogin)
	mux.HandleFunc("/api/setup", web.handleSetup)
	mux.HandleFunc("/api/state", web.withAuth(web.handleState))
	mux.HandleFunc("/api/save", web.withAuth(web.handleSave))
	mux.HandleFunc("/api/subscription/update", web.withAuth(web.handleSubscriptionUpdate))
	mux.HandleFunc("/api/import", web.withAuth(web.handleImport))
	mux.HandleFunc("/api/node/probe", web.withAuth(web.handleNodeProbe))
	mux.HandleFunc("/api/route/check", web.withAuth(web.handleRouteCheck))
	mux.HandleFunc("/api/connections", web.withAuth(web.handleConnections))
	mux.HandleFunc("/", web.handleStatic)
	return web, nil
}

// handleHealth 返回轻量探测结果，适用于首屏和异常页轮询。
func (w *WebServer) handleHealth(rw http.ResponseWriter, req *http.Request) {
	cfg, err := w.App.LoadConfig()
	if err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, w.App.BuildWebHealth(cfg))
}

// handleLogin 校验账号密码并签发 JWT。
func (w *WebServer) handleLogin(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	cfg, err := w.App.LoadConfig()
	if err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if isWebSetupRequired(cfg) {
		writeJSON(rw, http.StatusForbidden, map[string]string{"error": "web auth not configured"})
		return
	}
	clientIP := clientIP(req)
	if locked, until := w.isLocked(clientIP, cfg); locked {
		writeJSON(rw, http.StatusTooManyRequests, map[string]string{"error": "locked", "locked_until": until.Format(time.RFC3339)})
		return
	}
	var body WebLoginRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if body.Username != cfg.Web.Auth.Username || body.Password != cfg.Web.Auth.Password {
		w.recordLoginFailure(clientIP, cfg)
		writeJSON(rw, http.StatusUnauthorized, map[string]string{"error": "账号或密码错误"})
		return
	}
	w.clearLoginFailure(clientIP)
	ttl := parseDurationOrDefault(cfg.Web.TokenTTL, 24*time.Hour)
	expiresAt := time.Now().Add(ttl)
	token, err := MakeJWT(body.Username, webJWTSecret(cfg), expiresAt)
	if err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, WebLoginResponse{Token: token, ExpiresAt: expiresAt.Format(time.RFC3339)})
}

// handleSetup 首次写入 Web 账号密码，只允许未配置时调用。
func (w *WebServer) handleSetup(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var body WebSetupRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	w.Mutex.Lock()
	defer w.Mutex.Unlock()
	if err := w.App.SaveWebSetup(body); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	cfg, err := w.App.LoadConfig()
	if err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, w.App.BuildWebHealth(cfg))
}

// handleState 返回首屏完整状态，适用于登录后的单次快速加载。
func (w *WebServer) handleState(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	state, err := w.App.BuildWebState()
	if err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, state)
}

// handleSave 保存策略和规则文件，然后等待 sing-box 应用完成。
func (w *WebServer) handleSave(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var body WebSaveRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	w.Mutex.Lock()
	beforeCfg, beforeCfgErr := w.App.LoadConfig()
	beforeForceProxy := readOptionalText(w.App.ForceProxyPath)
	beforeForceDirect := readOptionalText(w.App.ForceDirectPath)
	if err := w.App.SaveWebState(body); err != nil {
		w.Mutex.Unlock()
		var conflict ConfigConflictError
		if errors.As(err, &conflict) {
			writeJSON(rw, http.StatusConflict, map[string]string{
				"error":        conflict.Error(),
				"current_hash": conflict.CurrentHash,
			})
			return
		}
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	afterCfg, afterCfgErr := w.App.LoadConfig()
	if beforeCfgErr == nil && afterCfgErr == nil {
		if err := w.App.UpdateChangedSubscriptions(&beforeCfg, &afterCfg); err != nil {
			w.Mutex.Unlock()
			writeJSON(rw, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
	}
	plan := WebApplyPlan{ServiceEnabled: body.ServiceEnabled, Restart: true}
	if beforeCfgErr == nil && afterCfgErr == nil {
		plan = BuildWebApplyPlan(beforeCfg, beforeForceProxy, beforeForceDirect, afterCfg, body.ForceProxy, body.ForceDirect)
	}
	if err := w.App.ApplyWebPlan(plan); err != nil {
		w.Mutex.Unlock()
		if w.App.Logger != nil {
			w.App.Logger.Error("保存后应用失败: %v", err)
		}
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.Mutex.Unlock()

	state, err := w.App.BuildWebState()
	if err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(rw, http.StatusOK, state)
}

// handleSubscriptionUpdate 刷新单个订阅缓存，失败时保留旧缓存。
func (w *WebServer) handleSubscriptionUpdate(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var body WebSubscriptionUpdateRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	cfg, err := w.App.LoadConfig()
	if err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	sub, ok := findSubscription(cfg, body.Name)
	if !ok {
		writeJSON(rw, http.StatusNotFound, map[string]string{"error": "subscription not found"})
		return
	}
	w.Mutex.Lock()
	defer w.Mutex.Unlock()
	_, err = w.App.FetchAndCacheSubscriptionForWeb(&cfg, sub, body.UseProxy)
	if err != nil {
		writeJSON(rw, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if err := SaveRuntimeState(RuntimeState{LastUpdateSuccess: time.Now().Format(time.RFC3339)}); err != nil {
		w.App.Logger.Warn("运行状态写入失败 err=%v", err)
	}
	if err := w.App.ApplyWebPlan(WebApplyPlan{
		ServiceEnabled:   ServiceEnabled(cfg),
		Restart:          true,
		SelectorSwitches: DesiredSelectorSwitches(cfg),
	}); err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	state, err := w.App.BuildWebState()
	if err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, state)
}

// handleImport 解析手动导入内容并替换同 key 导入缓存。
func (w *WebServer) handleImport(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var body WebImportRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	w.Mutex.Lock()
	defer w.Mutex.Unlock()
	result, err := w.App.ImportNodeGroup(body)
	if err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	cfg, err := w.App.LoadConfig()
	if err == nil {
		if err := w.App.ApplyWebPlan(WebApplyPlan{
			ServiceEnabled:   ServiceEnabled(cfg),
			Restart:          true,
			SelectorSwitches: DesiredSelectorSwitches(cfg),
		}); err != nil {
			writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}
	state, err := w.App.BuildWebState()
	if err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"result": result, "state": state})
}

// handleNodeProbe 触发单个节点时延探测。
func (w *WebServer) handleNodeProbe(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var body WebProbeRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	cfg, err := w.App.LoadConfig()
	if err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !w.App.WebBackendExists(cfg, body.Tag) {
		writeJSON(rw, http.StatusNotFound, map[string]string{"error": "outbound not found"})
		return
	}
	delay, err := w.App.ProbeOutboundDelay(body.Tag, body.URL)
	if err != nil {
		writeJSON(rw, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, WebProbeResponse{Tag: body.Tag, DelayMS: delay})
}

// handleRouteCheck 判断目标会走代理还是直连。
func (w *WebServer) handleRouteCheck(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var body WebRouteCheckRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	result, err := w.App.CheckRouteTarget(body.Target)
	if err != nil {
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, result)
}

// handleConnections 返回当前连接流水，适用于 Web 持续刷新。
func (w *WebServer) handleConnections(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	connections, err := w.App.FetchWebConnections()
	if err != nil {
		writeJSON(rw, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, connections)
}

// handleStatic 返回内嵌前端资源，未知路径回退到 index.html。
func (w *WebServer) handleStatic(rw http.ResponseWriter, req *http.Request) {
	cleanPath := strings.TrimPrefix(filepath.Clean(req.URL.Path), string(filepath.Separator))
	if cleanPath == "." || cleanPath == "" {
		cleanPath = "index.html"
	}
	data, err := fs.ReadFile(embeddedWebAssets, filepath.Join("web", "dist", cleanPath))
	if err != nil {
		data, err = fs.ReadFile(embeddedWebAssets, filepath.Join("web", "dist", "index.html"))
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		cleanPath = "index.html"
	}
	if ctype := mime.TypeByExtension(filepath.Ext(cleanPath)); ctype != "" {
		rw.Header().Set("Content-Type", ctype)
	}
	http.ServeContent(rw, req, cleanPath, time.Time{}, bytes.NewReader(data))
}

// withAuth 校验 JWT，适用于保护会修改代理策略的 API。
func (w *WebServer) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		cfg, err := w.App.LoadConfig()
		if err != nil {
			writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if isWebSetupRequired(cfg) {
			writeJSON(rw, http.StatusForbidden, map[string]string{"error": "web auth not configured"})
			return
		}
		token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
		if token == "" {
			writeJSON(rw, http.StatusUnauthorized, map[string]string{"error": "missing token"})
			return
		}
		if _, err := VerifyJWT(token, webJWTSecret(cfg)); err != nil {
			writeJSON(rw, http.StatusUnauthorized, map[string]string{"error": err.Error()})
			return
		}
		next(rw, req)
	}
}

// isLocked 判断指定 IP 是否处于登录锁定状态。
func (w *WebServer) isLocked(ip string, cfg Config) (bool, time.Time) {
	w.FailureMutex.Lock()
	defer w.FailureMutex.Unlock()
	item := w.LoginFailures[ip]
	if item == nil || item.LockedUntil.IsZero() {
		return false, time.Time{}
	}
	if time.Now().After(item.LockedUntil) {
		delete(w.LoginFailures, ip)
		return false, time.Time{}
	}
	return true, item.LockedUntil
}

// recordLoginFailure 记录登录失败并在达到阈值时锁定 IP。
func (w *WebServer) recordLoginFailure(ip string, cfg Config) {
	w.FailureMutex.Lock()
	defer w.FailureMutex.Unlock()
	item := w.LoginFailures[ip]
	if item == nil {
		item = &LoginFailure{}
		w.LoginFailures[ip] = item
	}
	item.Count++
	if item.Count >= cfg.Web.Lock.MaxAttempts {
		item.LockedUntil = time.Now().Add(parseDurationOrDefault(cfg.Web.Lock.Duration, time.Hour))
	}
}

// clearLoginFailure 清除指定 IP 的登录失败状态。
func (w *WebServer) clearLoginFailure(ip string) {
	w.FailureMutex.Lock()
	defer w.FailureMutex.Unlock()
	delete(w.LoginFailures, ip)
}

// BuildWebHealth 构造轻量探测状态。
func (a *App) BuildWebHealth(cfg Config) WebHealthResponse {
	state, _ := LoadRuntimeState()
	return WebHealthResponse{
		OK:                true,
		SetupRequired:     isWebSetupRequired(cfg),
		ServiceEnabled:    ServiceEnabled(cfg),
		SingBoxStatus:     singBoxStatus(),
		StartedAt:         ProcessStartedAt.Format(time.RFC3339),
		ActiveOutbound:    configuredActiveOutbound(cfg),
		LastUpdateSuccess: state.LastUpdateSuccess,
		Version:           Version,
	}
}

// BuildWebState 构造前端首屏完整数据。
func (a *App) BuildWebState() (WebStateResponse, error) {
	cfg, err := a.LoadConfig()
	if err != nil {
		return WebStateResponse{}, err
	}
	a.ensureLogger(cfg.Log)
	staticNodes := make([]WebBackend, 0, len(cfg.Backend.Static))
	for _, item := range cfg.Backend.Static {
		node := item
		NormalizeBackendIdentity(&node)
		node.SetBackendTag(RuntimeBackendTag("static", node.BackendKey()))
		staticNodes = append(staticNodes, WebBackendFromBackend(&node, "static"))
	}
	subscriptions := make([]WebSubscription, 0, len(cfg.Backend.Subscription))
	for _, sub := range cfg.Backend.Subscription {
		group := WebSubscription{
			Key:       sub.Key,
			Name:      sub.Name,
			Enabled:   sub.Enabled,
			URL:       sub.URL,
			UserAgent: sub.UserAgent,
			Default:   sub.Default,
			Nodes:     make([]WebBackend, 0),
		}
		// 触发条件：用户手动更新了未启用订阅。
		// 不能直接沿用运行配置过滤，因为前端需要展示缓存结果。
		// 防止更新成功但节点列表仍为空的回归。
		nodes, cacheErr := a.LoadSubscriptionCache(sub.Key)
		if cacheErr != nil {
			group.Error = cacheErr.Error()
		}
		MakeUniqueBackendKeys(nodes)
		for _, node := range nodes {
			node.SetBackendTag(RuntimeBackendTag("sub-"+sub.Key, node.BackendKey()))
			group.Nodes = append(group.Nodes, WebBackendFromBackend(node, "subscription:"+sub.Key))
		}
		SortWebBackends(group.Nodes)
		subscriptions = append(subscriptions, group)
	}
	imports := make([]WebImportedGroup, 0, len(cfg.Backend.Imports))
	for _, item := range cfg.Backend.Imports {
		group := WebImportedGroup{
			Key:    item.Key,
			Name:   firstNonEmpty(item.Name, item.Key),
			Source: normalizeImportSource(item.Source),
			Nodes:  make([]WebBackend, 0),
		}
		nodes, cacheErr := a.LoadSubscriptionCache(item.Key)
		if cacheErr != nil {
			group.Error = cacheErr.Error()
		}
		MakeUniqueBackendKeys(nodes)
		for _, node := range nodes {
			node.SetBackendTag(RuntimeBackendTag("import-"+item.Key, node.BackendKey()))
			group.Nodes = append(group.Nodes, WebBackendFromBackend(node, "import:"+item.Key))
		}
		SortWebBackends(group.Nodes)
		imports = append(imports, group)
	}
	SortWebBackends(staticNodes)
	dynamicGroups := a.BuildWebDynamicGroups(cfg)
	forceProxy, _ := os.ReadFile(a.ForceProxyPath)
	forceDirect, _ := os.ReadFile(a.ForceDirectPath)
	singBoxConfig, err := a.GenerateSingBoxConfigText(cfg)
	if err != nil {
		singBoxConfig = fmt.Sprintf("生成 sing-box 配置失败: %v\n", err)
	}
	configHash, err := a.ConfigHash()
	if err != nil {
		return WebStateResponse{}, err
	}
	health := a.BuildWebHealth(cfg)
	if active := firstConfiguredOutbound(cfg, staticNodes, subscriptions, imports, dynamicGroups); active != "" {
		health.ActiveOutbound = active
	}
	return WebStateResponse{
		Health:        health,
		ConfigHash:    configHash,
		Static:        staticNodes,
		Subscriptions: subscriptions,
		Imports:       imports,
		DynamicGroups: dynamicGroups,
		GeoFiles:      a.BuildWebGeoFiles(),
		HostsOverride: HostsOverrideEnabled(cfg),
		Inbound:       WebInboundFromConfig(cfg),
		ForceProxy:    string(forceProxy),
		ForceDirect:   string(forceDirect),
		Overrides: append(make([]OverrideRule, 0, len(cfg.Policy.Overrides)),
			cfg.Policy.Overrides...),
		DynamicOutbound: append(make([]DynamicOutboundRule, 0, len(cfg.Policy.DynamicOutbound)),
			cfg.Policy.DynamicOutbound...),
		SingBoxConfig: singBoxConfig,
		Warnings:      append([]string{}, a.ConfigWarnings(cfg)...),
	}, nil
}

// BuildWebDynamicGroups 构造动态组 Web 状态。
func (a *App) BuildWebDynamicGroups(cfg Config) []WebDynamicGroup {
	groups := make([]WebDynamicGroup, 0, len(cfg.Backend.Groups))
	memberTags, _ := a.ResolveMemberTagMap(&cfg)
	memberRefsByTag := make(map[string]string, len(memberTags))
	for ref, tag := range memberTags {
		memberRefsByTag[tag] = ref
	}
	for _, group := range cfg.Backend.Groups {
		status := a.GroupRuntime.Status(group.Key)
		groupTag := RuntimeBackendTag("group", group.Key)
		currentTag, _ := a.ClashSelectorNow(groupTag)
		results := status.Results
		if results == nil {
			results = map[string][]GroupProbeRecord{}
		}
		groups = append(groups, WebDynamicGroup{
			Key:           group.Key,
			Tag:           groupTag,
			Name:          group.Key,
			Mode:          normalizeDynamicGroupMode(group.Mode),
			Primary:       strings.TrimSpace(group.Primary),
			Members:       append(make([]string, 0, len(group.Members)), group.Members...),
			BestMember:    status.BestMember,
			BestTag:       status.BestTag,
			CurrentMember: memberRefsByTag[currentTag],
			CurrentTag:    currentTag,
			UpdatedAt:     status.UpdatedAt,
			Results:       results,
		})
	}
	return groups
}

// BuildWebGeoFiles 构造 geofiles 缓存状态，适用于 Web 详情页。
func (a *App) BuildWebGeoFiles() []WebGeoFile {
	cfg, _ := a.LoadConfig()
	files := make([]WebGeoFile, 0, len(geoIPNames)+len(geoSiteNames))
	for _, name := range geoIPNames {
		files = append(files, a.WebGeoFile("geoip", name, cfg))
	}
	for _, name := range geoSiteNames {
		files = append(files, a.WebGeoFile("geosite", name, cfg))
	}
	return files
}

// WebGeoFile 读取单个 geofile 状态。
func (a *App) WebGeoFile(kind string, name string, cfg Config) WebGeoFile {
	tag := kind + "-" + name
	path := filepath.Join(a.GeoDir, tag+".srs")
	item := WebGeoFile{Kind: kind, Tag: tag, Path: path}
	item.Locked = containsString(baseDirectRuleSets, tag)
	item.Enabled = item.Locked || containsString(cfg.GeoFiles.ProxyRuleSets, tag)
	item.Role = "optional"
	if item.Locked {
		item.Role = "direct-base"
	}
	if tag == "geosite-category-ads-all" {
		item.Role = "ads-block"
		item.Enabled = cfg.GeoFiles.AdsBlock
	}
	info, err := os.Stat(path)
	if err != nil {
		return item
	}
	item.Exists = true
	item.SizeBytes = info.Size()
	item.ModifiedAt = info.ModTime().Format(time.RFC3339)
	return item
}

// WebInboundFromConfig 生成 Web 可编辑的入口配置。
func WebInboundFromConfig(cfg Config) WebInboundConfig {
	MergeConfigDefaults(&cfg)
	return WebInboundConfig{
		InboundMode: cfg.Inbound.Mode,
		MixedListen: cfg.Inbound.Mixed.Listen,
		MixedPort:   cfg.Inbound.Mixed.Port,
	}
}

// ApplyWebInboundConfig 把 Web 提交的入口配置写回主配置。
func ApplyWebInboundConfig(cfg *Config, inbound WebInboundConfig) error {
	if !WebInboundConfigProvided(inbound) {
		return nil
	}
	mode, err := normalizeInboundMode(inbound.InboundMode, cfg.Inbound.Mode)
	if err != nil {
		return err
	}
	mixedListen, err := normalizeMixedListen(inbound.MixedListen, cfg.Inbound.Mixed.Listen)
	if err != nil {
		return err
	}
	mixedPort, err := normalizeConfigPort(inbound.MixedPort, cfg.Inbound.Mixed.Port, defaultMixedPort, "mixed port")
	if err != nil {
		return err
	}
	cfg.Inbound.Mode = mode
	cfg.Inbound.Mixed.Listen = mixedListen
	cfg.Inbound.Mixed.Port = mixedPort
	return nil
}

// WebInboundConfigProvided 判断旧前端保存请求是否携带入口配置。
func WebInboundConfigProvided(inbound WebInboundConfig) bool {
	return strings.TrimSpace(inbound.InboundMode) != "" ||
		strings.TrimSpace(inbound.MixedListen) != "" ||
		inbound.MixedPort != 0
}

// normalizeInboundMode 校验入口模式，空值沿用当前配置。
func normalizeInboundMode(value string, fallback string) (string, error) {
	mode := strings.TrimSpace(value)
	if mode == "" {
		mode = strings.TrimSpace(fallback)
	}
	if mode == "" {
		mode = "tun"
	}
	switch mode {
	case "tun", "mixed":
		return mode, nil
	default:
		return "", fmt.Errorf("入口模式不支持: %s", mode)
	}
}

// normalizeMixedListen 校验 mixed 监听地址，防止把 host:port 写进 host 字段。
func normalizeMixedListen(value string, fallback string) (string, error) {
	listen := strings.TrimSpace(value)
	if listen == "" {
		listen = strings.TrimSpace(fallback)
	}
	if listen == "" {
		listen = defaultMixedListen
	}
	if strings.Contains(listen, "://") || strings.ContainsAny(listen, "/ \t\r\n") {
		return "", errors.New("mixed listen 只能填写监听地址，不能包含协议、端口或路径")
	}
	if _, _, err := net.SplitHostPort(listen); err == nil {
		return "", errors.New("mixed listen 不要包含端口，端口请填单独字段")
	}
	trimmedIPv6 := strings.TrimPrefix(strings.TrimSuffix(listen, "]"), "[")
	if strings.Contains(trimmedIPv6, ":") {
		if _, err := netip.ParseAddr(trimmedIPv6); err != nil {
			return "", fmt.Errorf("mixed listen IPv6 地址无效: %s", listen)
		}
		return trimmedIPv6, nil
	}
	return listen, nil
}

// normalizeConfigPort 校验监听端口，空值沿用当前配置。
func normalizeConfigPort(value int, fallback int, defaultValue int, field string) (int, error) {
	port := value
	if port == 0 {
		port = fallback
	}
	if port == 0 {
		port = defaultValue
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("%s 端口非法: %d", field, port)
	}
	return port, nil
}

// ConfigHash 计算 Web 可编辑配置哈希，用于保存时冲突检测。
func (a *App) ConfigHash() (string, error) {
	hash := sha256.New()
	for _, path := range []string{a.ConfigPath, a.ForceProxyPath, a.ForceDirectPath} {
		data, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		_, _ = hash.Write([]byte(path))
		_, _ = hash.Write([]byte{0})
		if err == nil {
			_, _ = hash.Write(data)
		}
		_, _ = hash.Write([]byte{0xff})
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// SaveWebState 保存 Web 面板提交的策略和规则。
func (a *App) SaveWebState(req WebSaveRequest) error {
	cfg, err := a.LoadConfig()
	if err != nil {
		return err
	}
	currentHash, err := a.ConfigHash()
	if err != nil {
		return err
	}
	if req.ConfigHash != "" && req.ConfigHash != currentHash && !req.ConfirmOverwrite {
		return ConfigConflictError{CurrentHash: currentHash}
	}
	if err := ValidateLocalRulesText(req.ForceProxy); err != nil {
		return fmt.Errorf("强制代理规则错误: %w", err)
	}
	if err := ValidateLocalRulesText(req.ForceDirect); err != nil {
		return fmt.Errorf("强制直连规则错误: %w", err)
	}
	if req.ActiveOutbound == "" {
		return errors.New("必须选择一个 outbound")
	}
	oldCfg := cfg
	cfg.Service.Enabled = boolPtr(req.ServiceEnabled)
	if err := ApplyWebInboundConfig(&cfg, req.Inbound); err != nil {
		return err
	}
	staticNodes, err := NormalizeStaticBackendsForSave(req.Static)
	if err != nil {
		return err
	}
	subscriptions, err := NormalizeSubscriptionsForSave(req.Subscriptions)
	if err != nil {
		return err
	}
	imports, err := NormalizeImportedGroupsForSave(req.Imports)
	if err != nil {
		return err
	}
	cfg.Backend.Static = staticNodes
	cfg.Backend.Subscription = subscriptions
	cfg.Backend.Imports = imports
	groups, err := NormalizeDynamicGroupsForSave(req.DynamicGroups, a.AvailableMemberRefs(cfg))
	if err != nil {
		return err
	}
	cfg.Backend.Groups = groups
	if err := a.ValidateStaticDetours(cfg); err != nil {
		return err
	}
	overrides, err := NormalizeOverrideRules(req.Overrides)
	if err != nil {
		return err
	}
	dynamicRules, err := a.NormalizeDynamicOutboundRules(cfg, req.DynamicOutbound)
	if err != nil {
		return err
	}
	if !a.WebBackendExists(cfg, req.ActiveOutbound) {
		return fmt.Errorf("outbound 不存在: %s", req.ActiveOutbound)
	}
	cfg.Policy.Default = req.ActiveOutbound
	cfg.Policy.Overrides = overrides
	cfg.Policy.DynamicOutbound = dynamicRules
	if blockers := a.RemovedBackendBlockers(oldCfg, cfg); len(blockers) > 0 {
		return fmt.Errorf("删除被引用的 backend: %s", strings.Join(blockers, "; "))
	}
	cfg.GeoFiles.AdsBlock = req.AdsBlock
	cfg.GeoFiles.HostsOverride = boolPtr(req.HostsOverride)
	cfg.GeoFiles.ProxyRuleSets = NormalizeProxyRuleSets(req.ProxyRuleSets)
	if err := SaveConfig(a.ConfigPath, cfg); err != nil {
		return err
	}
	if err := writeAtomicFile(a.ForceProxyPath, []byte(req.ForceProxy), 0644); err != nil {
		return err
	}
	return writeAtomicFile(a.ForceDirectPath, []byte(req.ForceDirect), 0644)
}

// BuildWebApplyPlan 判断 Web 保存后能否只用 selector 热切。
func BuildWebApplyPlan(before Config, beforeForceProxy string, beforeForceDirect string, after Config, afterForceProxy string, afterForceDirect string) WebApplyPlan {
	plan := WebApplyPlan{ServiceEnabled: ServiceEnabled(after), Restart: true, SelectorSwitches: DesiredSelectorSwitches(after)}
	if !ServiceEnabled(after) {
		return plan
	}
	if ServiceEnabled(before) != ServiceEnabled(after) {
		return plan
	}
	if beforeForceProxy != afterForceProxy || beforeForceDirect != afterForceDirect {
		return plan
	}
	if !sameDynamicOutboundMatches(before.Policy.DynamicOutbound, after.Policy.DynamicOutbound) {
		return plan
	}
	baseBefore := normalizeHotComparableConfig(before)
	baseAfter := normalizeHotComparableConfig(after)
	if !reflect.DeepEqual(baseBefore, baseAfter) {
		return plan
	}
	plan.Restart = false
	return plan
}

// DesiredSelectorSwitches 返回配置声明的 selector 目标。
func DesiredSelectorSwitches(cfg Config) map[string]string {
	switches := map[string]string{}
	if outbound := SanitizeTag(cfg.Policy.Default); outbound != "" {
		switches[defaultCurrentSelector] = outbound
	}
	for _, rule := range cfg.Policy.DynamicOutbound {
		if outbound := SanitizeTag(rule.Outbound); outbound != "" {
			switches[DynamicOutboundSelectorTag(rule)] = outbound
		}
	}
	return switches
}

// ApplyWebPlan 应用 Web 保存计划，能热切时只切 selector。
func (a *App) ApplyWebPlan(plan WebApplyPlan) error {
	if !plan.ServiceEnabled {
		return a.Stop()
	}
	if plan.Restart {
		if err := a.Restart(); err != nil {
			return err
		}
		running, err := hasSingBoxProcess()
		if err != nil {
			return err
		}
		if !running {
			// 触发条件：Web 保存后没有任何可用 backend。
			// 不能继续等待 Clash API，因为数据面已被主动停止。
			// 防止控制面保存成功却因无数据面被误报失败。
			return nil
		}
		if err := a.WaitClashAPIReady(); err != nil {
			return err
		}
	}
	if err := a.SyncSelectorSwitches(plan.SelectorSwitches); err != nil {
		return err
	}
	if len(plan.SelectorSwitches) > 0 {
		if err := a.CloseClashConnections(); err != nil && a.Logger != nil {
			a.Logger.Warn("保存后清理旧连接失败 err=%v", err)
		}
	}
	return nil
}

// SyncSelectorSwitches 按配置同步 selector，覆盖运行时旧选择。
func (a *App) SyncSelectorSwitches(switches map[string]string) error {
	for selector, outbound := range switches {
		if selector == "" || outbound == "" {
			continue
		}
		if err := a.SwitchSelectorOutbound(selector, outbound); err != nil {
			return err
		}
	}
	return nil
}

// normalizeHotComparableConfig 清空允许热切的字段后用于结构比较。
func normalizeHotComparableConfig(cfg Config) Config {
	cfg.Policy.Default = ""
	cfg.Policy.DynamicOutbound = append([]DynamicOutboundRule(nil), cfg.Policy.DynamicOutbound...)
	for i := range cfg.Policy.DynamicOutbound {
		cfg.Policy.DynamicOutbound[i].Outbound = ""
	}
	return cfg
}

// sameDynamicOutboundMatches 判断动态出口规则形状是否未变。
func sameDynamicOutboundMatches(left []DynamicOutboundRule, right []DynamicOutboundRule) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if strings.TrimSpace(left[i].Match) != strings.TrimSpace(right[i].Match) {
			return false
		}
	}
	return true
}

// readOptionalText 读取可选文本文件，缺失时视为空内容。
func readOptionalText(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

// parsedRouteTarget 表示路由检查时清洗后的目标。
type parsedRouteTarget struct {
	// Input 是用户原始输入。
	Input string
	// Target 是规范化后的目标文本。
	Target string
	// Kind 是 domain、ip 或 cidr。
	Kind string
	// Domain 是域名目标。
	Domain string
	// Addr 是 IP 目标。
	Addr netip.Addr
	// Prefix 是 CIDR 目标。
	Prefix netip.Prefix
	// Notes 保存解析阶段说明。
	Notes []string
}

// CheckRouteTarget 按当前编排规则判断目标出口。
func (a *App) CheckRouteTarget(input string) (WebRouteCheckResponse, error) {
	target, err := parseRouteTarget(input)
	if err != nil {
		return WebRouteCheckResponse{}, err
	}
	cfg, err := a.LoadConfig()
	if err != nil {
		return WebRouteCheckResponse{}, err
	}
	backends, err := a.ResolveBackends(&cfg, false)
	if err != nil {
		return WebRouteCheckResponse{}, err
	}
	defaultOutbound := cfg.Policy.Default
	if defaultOutbound == "" && len(backends) > 0 {
		defaultOutbound = backends[0].BackendTag()
	}
	directRules, err := ParseLocalRulesFile(a.ForceDirectPath)
	if err != nil {
		return WebRouteCheckResponse{}, err
	}
	proxyRules, err := ParseLocalRulesFile(a.ForceProxyPath)
	if err != nil {
		return WebRouteCheckResponse{}, err
	}
	if result, ok := checkOverrideTarget(target, cfg.Policy.Overrides); ok {
		return result, nil
	}
	if result, ok := a.checkDynamicOutboundTarget(target, cfg.Policy.DynamicOutbound); ok {
		return result, nil
	}
	if result, ok := checkLocalRulesTarget(target, directRules, "direct"); ok {
		return result, nil
	}
	if result, ok := checkLocalRulesTarget(target, proxyRules, defaultCurrentSelector); ok {
		return result, nil
	}
	if isPrivateRouteTarget(target) {
		return routeCheckResult(target, "direct", "direct", "内网地址直连", "ip_is_private", false), nil
	}
	if target.Kind == "domain" && matchesAnyDomainSuffix(target.Domain, []string{"lan", "local", "localhost"}) {
		return routeCheckResult(target, "direct", "direct", "本地域名直连", "domain_suffix:local", false), nil
	}
	if cfg.GeoFiles.AdsBlock && target.Kind == "domain" {
		if ok, err := a.matchRuleSet("geosite-category-ads-all", target.Domain); err != nil {
			return WebRouteCheckResponse{}, err
		} else if ok {
			return routeCheckResult(target, "reject", "", "命中广告拦截规则", "geosite-category-ads-all", false), nil
		}
	}
	if result, ok, err := a.checkProxyGeoTarget(target, cfg.GeoFiles.ProxyRuleSets); err != nil {
		return WebRouteCheckResponse{}, err
	} else if ok {
		return result, nil
	}
	if result, ok, err := a.checkDirectGeoTarget(target); err != nil {
		return WebRouteCheckResponse{}, err
	} else if ok {
		return result, nil
	}
	return routeCheckResult(target, "proxy", firstNonEmpty(defaultOutbound, defaultCurrentSelector), "未命中直连规则，使用默认出口", "route.final", true), nil
}

// parseRouteTarget 解析 Web 输入的域名、IP 或 CIDR。
func parseRouteTarget(input string) (parsedRouteTarget, error) {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return parsedRouteTarget{}, errors.New("请输入域名、IP 或 IP 段")
	}
	clean := raw
	if strings.Contains(clean, "://") {
		parsedURL, err := url.Parse(clean)
		if err == nil && parsedURL.Host != "" {
			clean = parsedURL.Host
		}
	}
	if strings.Contains(clean, "@") {
		parts := strings.Split(clean, "@")
		clean = parts[len(parts)-1]
	}
	if host, _, err := net.SplitHostPort(clean); err == nil {
		clean = host
	}
	clean = strings.Trim(clean, "[] \t\r\n")
	if strings.HasPrefix(strings.ToLower(clean), "domain:") {
		clean = strings.TrimSpace(clean[len("domain:"):])
	}
	if prefix, err := netip.ParsePrefix(clean); err == nil {
		prefix = prefix.Masked()
		return parsedRouteTarget{Input: raw, Target: prefix.String(), Kind: "cidr", Prefix: prefix, Notes: []string{"IP 段的 GeoFiles 使用网络地址抽样判断"}}, nil
	}
	if addr, err := netip.ParseAddr(clean); err == nil {
		addr = addr.Unmap()
		return parsedRouteTarget{Input: raw, Target: addr.String(), Kind: "ip", Addr: addr}, nil
	}
	domain := strings.TrimSuffix(strings.ToLower(clean), ".")
	if domain == "" || strings.ContainsAny(domain, " /") {
		return parsedRouteTarget{}, fmt.Errorf("目标格式错误: %s", raw)
	}
	return parsedRouteTarget{Input: raw, Target: domain, Kind: "domain", Domain: domain}, nil
}

// checkOverrideTarget 判断目标是否命中静态跳转规则。
func checkOverrideTarget(target parsedRouteTarget, rules []OverrideRule) (WebRouteCheckResponse, bool) {
	for _, rule := range rules {
		if !OverrideEnabled(rule) || !routeTargetMatchesRuleTarget(target, rule.Match) {
			continue
		}
		outbound := SanitizeTag(firstNonEmpty(rule.Outbound, "direct"))
		reason := fmt.Sprintf("命中静态跳转到 %s:%d", rule.Address, rule.Port)
		result := routeCheckResult(target, "override", outbound, reason, "override:"+rule.Key, false)
		result.Notes = append(result.Notes, fmt.Sprintf("目标地址改写为 %s:%d", rule.Address, rule.Port))
		return result, true
	}
	return WebRouteCheckResponse{}, false
}

// checkDynamicOutboundTarget 判断目标是否命中动态出口规则。
func (a *App) checkDynamicOutboundTarget(target parsedRouteTarget, rules []DynamicOutboundRule) (WebRouteCheckResponse, bool) {
	for _, rule := range rules {
		if routeTargetMatchesRuleTarget(target, rule.Match) {
			reason := fmt.Sprintf("命中动态出口 %s", strings.TrimSpace(rule.Match))
			return routeCheckResult(target, "proxy", rule.Outbound, reason, "dynamic_outbound", true), true
		}
	}
	return WebRouteCheckResponse{}, false
}

// checkLocalRulesTarget 判断目标是否命中自定义强制规则。
func checkLocalRulesTarget(target parsedRouteTarget, rules []LocalRule, outbound string) (WebRouteCheckResponse, bool) {
	for _, rule := range rules {
		if !localRuleMatchesTarget(rule, target) {
			continue
		}
		if outbound == "direct" {
			return routeCheckResult(target, "direct", "direct", fmt.Sprintf("命中强制不走代理第 %d 行", rule.Line), "force_direct", false), true
		}
		return routeCheckResult(target, "proxy", outbound, fmt.Sprintf("命中强制走代理第 %d 行", rule.Line), "force_proxy", true), true
	}
	return WebRouteCheckResponse{}, false
}

// checkDirectGeoTarget 判断目标是否命中内置 Geo 直连规则。
func (a *App) checkDirectGeoTarget(target parsedRouteTarget) (WebRouteCheckResponse, bool, error) {
	tags := []string{}
	if target.Kind == "domain" {
		tags = []string{"geosite-private", "geosite-cn", "geosite-geolocation-cn"}
	} else {
		tags = []string{"geoip-private", "geoip-cn"}
	}
	matchTarget := ruleSetMatchTarget(target)
	for _, tag := range tags {
		ok, err := a.matchRuleSet(tag, matchTarget)
		if err != nil {
			return WebRouteCheckResponse{}, false, err
		}
		if ok {
			return routeCheckResult(target, "direct", "direct", "命中内置 Geo 直连规则", tag, false), true, nil
		}
	}
	return WebRouteCheckResponse{}, false, nil
}

// checkProxyGeoTarget 判断目标是否命中启用的 Geo 代理规则。
func (a *App) checkProxyGeoTarget(target parsedRouteTarget, tags []string) (WebRouteCheckResponse, bool, error) {
	matchTarget := ruleSetMatchTarget(target)
	for _, tag := range tags {
		if target.Kind == "domain" && !strings.HasPrefix(tag, "geosite-") {
			continue
		}
		if target.Kind != "domain" && !strings.HasPrefix(tag, "geoip-") {
			continue
		}
		ok, err := a.matchRuleSet(tag, matchTarget)
		if err != nil {
			return WebRouteCheckResponse{}, false, err
		}
		if ok {
			return routeCheckResult(target, "proxy", defaultCurrentSelector, "命中启用的 Geo 代理规则", tag, true), true, nil
		}
	}
	return WebRouteCheckResponse{}, false, nil
}

// matchRuleSet 调用 sing-box 检查本地二进制 rule-set 是否命中。
func (a *App) matchRuleSet(tag string, target string) (bool, error) {
	path := filepath.Join(a.GeoDir, tag+".srs")
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	singBoxBinary, _ := ResolveSingBoxRuntime()
	output, err := exec.CommandContext(ctx, singBoxBinary, "rule-set", "match", "-f", "binary", path, target).CombinedOutput()
	if ctx.Err() != nil {
		return false, fmt.Errorf("rule-set 检查超时 tag=%s", tag)
	}
	if err != nil {
		return false, fmt.Errorf("rule-set 检查失败 tag=%s err=%w output=%s", tag, err, strings.TrimSpace(string(output)))
	}
	return strings.Contains(string(output), "match "), nil
}

// routeCheckResult 构造统一路由检查结果。
func routeCheckResult(target parsedRouteTarget, decision string, outbound string, reason string, matchedRule string, viaProxy bool) WebRouteCheckResponse {
	return WebRouteCheckResponse{
		Input:       target.Input,
		Target:      target.Target,
		Kind:        target.Kind,
		Decision:    decision,
		Outbound:    outbound,
		MatchedRule: matchedRule,
		Reason:      reason,
		ViaProxy:    viaProxy,
		Notes:       append([]string(nil), target.Notes...),
	}
}

// localRuleMatchesTarget 判断自定义规则是否匹配目标。
func localRuleMatchesTarget(rule LocalRule, target parsedRouteTarget) bool {
	switch rule.Kind {
	case "domain":
		return target.Kind == "domain" && domainMatchesSuffix(target.Domain, rule.Value)
	case "dst":
		return target.Kind != "domain" && routeTargetMatchesCIDR(target, rule.Value)
	default:
		return false
	}
}

// routeTargetMatchesRuleTarget 判断目标是否匹配动态出口的匹配条件。
func routeTargetMatchesRuleTarget(target parsedRouteTarget, ruleTarget string) bool {
	kind, value := normalizeRouteRuleTarget(ruleTarget)
	if kind == "domain" {
		return target.Kind == "domain" && domainMatchesSuffix(target.Domain, value)
	}
	return target.Kind != "domain" && routeTargetMatchesCIDR(target, value)
}

// normalizeRouteRuleTarget 规范化规则里的域名、IP 或 CIDR。
func normalizeRouteRuleTarget(value string) (string, string) {
	text := strings.TrimSpace(value)
	key, rest, ok := splitKeyValue(text)
	if ok {
		if strings.EqualFold(key, "domain") {
			return "domain", cleanValue(rest)
		}
		if strings.EqualFold(key, "dst") {
			return "cidr", cleanValue(rest)
		}
	}
	if _, err := parseCIDROrIPPrefix(text); err == nil {
		return "cidr", text
	}
	return "domain", text
}

// routeTargetMatchesCIDR 判断 IP 或 CIDR 是否命中规则 CIDR。
func routeTargetMatchesCIDR(target parsedRouteTarget, value string) bool {
	rulePrefix, err := parseCIDROrIPPrefix(value)
	if err != nil {
		return false
	}
	if target.Kind == "ip" {
		return rulePrefix.Contains(target.Addr)
	}
	if target.Kind == "cidr" {
		return prefixesOverlap(target.Prefix, rulePrefix)
	}
	return false
}

// parseCIDROrIPPrefix 把 IP 或 CIDR 统一解析成 netip.Prefix。
func parseCIDROrIPPrefix(value string) (netip.Prefix, error) {
	text := strings.TrimSpace(cleanValue(value))
	if prefix, err := netip.ParsePrefix(text); err == nil {
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Prefix{}, err
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// prefixesOverlap 判断两个 IP 段是否有交集。
func prefixesOverlap(left netip.Prefix, right netip.Prefix) bool {
	if !left.IsValid() || !right.IsValid() || left.Addr().Is4() != right.Addr().Is4() {
		return false
	}
	return left.Contains(right.Addr()) || right.Contains(left.Addr())
}

// isPrivateRouteTarget 判断目标是否属于内网或本机地址。
func isPrivateRouteTarget(target parsedRouteTarget) bool {
	if target.Kind == "domain" {
		return false
	}
	addr := target.Addr
	if target.Kind == "cidr" {
		addr = target.Prefix.Addr()
	}
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast()
}

// ruleSetMatchTarget 返回用于 sing-box rule-set match 的目标。
func ruleSetMatchTarget(target parsedRouteTarget) string {
	if target.Kind == "domain" {
		return target.Domain
	}
	if target.Kind == "cidr" {
		return target.Prefix.Addr().String()
	}
	return target.Addr.String()
}

// matchesAnyDomainSuffix 判断域名是否命中任意后缀。
func matchesAnyDomainSuffix(domain string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if domainMatchesSuffix(domain, suffix) {
			return true
		}
	}
	return false
}

// domainMatchesSuffix 判断域名是否命中后缀规则。
func domainMatchesSuffix(domain string, suffix string) bool {
	cleanDomain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	cleanSuffix := strings.Trim(strings.ToLower(strings.TrimSpace(suffix)), ".")
	return cleanDomain == cleanSuffix || strings.HasSuffix(cleanDomain, "."+cleanSuffix)
}

// SaveWebSetup 首次保存 Web 账号密码，防止已有配置被未登录覆盖。
func (a *App) SaveWebSetup(req WebSetupRequest) error {
	username := strings.TrimSpace(req.Username)
	password := strings.TrimSpace(req.Password)
	if username == "" || password == "" {
		return errors.New("账号和密码不能为空")
	}
	cfg, err := a.LoadConfig()
	if err != nil {
		return err
	}
	if !isWebSetupRequired(cfg) {
		// 触发条件：Web 已完成初始化后又访问 /api/setup。
		// 不能直接覆盖配置，否则任何未登录请求都能重置账号。
		// 防止已配置面板被绕过登录接管。
		return errors.New("web auth 已配置")
	}
	cfg.Web.Auth.Username = username
	cfg.Web.Auth.Password = password
	return SaveConfig(a.ConfigPath, cfg)
}

// ProbeOutboundDelay 使用 sing-box Clash API 探测指定 outbound。
func (a *App) ProbeOutboundDelay(tag string, probeURL string) (int, error) {
	cleanTag := SanitizeTag(tag)
	if cleanTag == "" {
		return 0, errors.New("outbound tag 为空")
	}
	cleanURL, err := NormalizeProbeURL(probeURL)
	if err != nil {
		return 0, err
	}
	endpoint := url.URL{
		Scheme: "http",
		Host:   defaultClashAPIListen,
		Path:   "/proxies/" + url.PathEscape(cleanTag) + "/delay",
	}
	query := endpoint.Query()
	query.Set("timeout", strconv.Itoa(defaultProbeTimeoutMS))
	query.Set("url", cleanURL)
	endpoint.RawQuery = query.Encode()
	client := &http.Client{Timeout: time.Duration(defaultProbeTimeoutMS+500) * time.Millisecond}
	deadline := time.Now().Add(3 * time.Second)
	var lastErr error
	for {
		delay, err := fetchClashDelay(client, endpoint.String())
		if err == nil {
			return delay, nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			return 0, lastErr
		}
		time.Sleep(150 * time.Millisecond)
	}
}

// NormalizeProbeURL 清洗 Web 临时探测 URL，空值回退默认地址。
func NormalizeProbeURL(raw string) (string, error) {
	clean := strings.TrimSpace(raw)
	if clean == "" {
		return defaultProbeURL, nil
	}
	parsed, err := url.Parse(clean)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("探测目标 URL 格式错误")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("探测目标 URL 只支持 http 或 https")
	}
	return clean, nil
}

// ClashSelectorNow 读取 selector 当前出口，适用于展示缓存恢复的临时出口。
func (a *App) ClashSelectorNow(tag string) (string, error) {
	cleanTag := SanitizeTag(tag)
	if cleanTag == "" {
		return "", errors.New("selector tag 为空")
	}
	endpoint := "http://" + defaultClashAPIListen + "/proxies/" + url.PathEscape(cleanTag)
	client := &http.Client{Timeout: 800 * time.Millisecond}
	resp, err := client.Get(endpoint)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("clash api 状态异常: %s %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var data clashProxyResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}
	return data.Now, nil
}

// fetchClashDelay 请求 sing-box Clash API 的单节点 delay 接口。
func fetchClashDelay(client *http.Client, endpoint string) (int, error) {
	resp, err := client.Get(endpoint)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return 0, fmt.Errorf("clash api 状态异常: %s %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var data clashDelayResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return 0, err
	}
	if data.Delay <= 0 {
		return 0, errors.New("探测超时")
	}
	return data.Delay, nil
}

// WebBackendExists 判断指定 tag 是否来自静态、订阅、导入或动态组节点。
func (a *App) WebBackendExists(cfg Config, tag string) bool {
	for _, item := range cfg.Backend.Static {
		NormalizeBackendIdentity(&item)
		if RuntimeBackendTag("static", item.Key) == tag {
			return true
		}
	}
	for _, sub := range cfg.Backend.Subscription {
		nodes, err := a.LoadSubscriptionCache(sub.Key)
		if err != nil {
			continue
		}
		MakeUniqueBackendKeys(nodes)
		for _, node := range nodes {
			node.SetBackendTag(RuntimeBackendTag("sub-"+sub.Key, node.BackendKey()))
			if node.BackendTag() == tag {
				return true
			}
		}
	}
	for _, item := range cfg.Backend.Imports {
		nodes, err := a.LoadSubscriptionCache(item.Key)
		if err != nil {
			continue
		}
		MakeUniqueBackendKeys(nodes)
		for _, node := range nodes {
			node.SetBackendTag(RuntimeBackendTag("import-"+item.Key, node.BackendKey()))
			if node.BackendTag() == tag {
				return true
			}
		}
	}
	for _, group := range cfg.Backend.Groups {
		if RuntimeBackendTag("group", group.Key) == tag && len(group.Members) > 0 {
			return true
		}
	}
	return false
}

// ConfigWarnings 返回配置中已经悬空的引用，适用于页面进入时提醒。
func (a *App) ConfigWarnings(cfg Config) []string {
	var warnings []string
	if cfg.Policy.Default != "" && !a.WebBackendExists(cfg, cfg.Policy.Default) {
		warnings = append(warnings, "当前出口不存在: "+cfg.Policy.Default)
	}
	refs := a.AvailableMemberRefs(cfg)
	detourRefs := a.AvailableDetourRefs(cfg)
	for _, group := range cfg.Backend.Groups {
		for _, member := range group.Members {
			if !refs[member] {
				warnings = append(warnings, fmt.Sprintf("动态组 %s 成员不存在: %s", group.Key, member))
			}
		}
		if group.Primary != "" && !refs[group.Primary] {
			warnings = append(warnings, fmt.Sprintf("动态组 %s 主节点不存在: %s", group.Key, group.Primary))
		}
	}
	for _, node := range cfg.Backend.Static {
		detour := strings.TrimSpace(node.Detour)
		if detour != "" && !detourRefs[detour] {
			warnings = append(warnings, fmt.Sprintf("静态节点 %s detour 不存在: %s", node.Key, detour))
		}
	}
	for _, rule := range cfg.Policy.DynamicOutbound {
		if rule.Outbound != "" && !a.WebBackendExists(cfg, rule.Outbound) {
			warnings = append(warnings, fmt.Sprintf("动态出口 %s 指向不存在: %s", rule.Match, rule.Outbound))
		}
	}
	return warnings
}

// RemovedBackendBlockers 返回被删除 backend 的引用位置。
func (a *App) RemovedBackendBlockers(before Config, final Config) []string {
	var removedTags []string
	var removedRefs []string
	for _, item := range before.Backend.Static {
		node := item
		NormalizeBackendIdentity(&node)
		exists := false
		for _, next := range final.Backend.Static {
			nextNode := next
			NormalizeBackendIdentity(&nextNode)
			if nextNode.BackendKey() == node.BackendKey() {
				exists = true
				break
			}
		}
		if !exists {
			removedTags = append(removedTags, RuntimeBackendTag("static", node.BackendKey()))
			removedRefs = append(removedRefs, "static."+node.BackendKey())
		}
	}
	for _, sub := range before.Backend.Subscription {
		if findSubscriptionIndex(final.Backend.Subscription, sub.Key) >= 0 {
			continue
		}
		removedTags = append(removedTags, a.subscriptionBackendTags(sub.Key)...)
		removedRefs = append(removedRefs, a.subscriptionMemberRefs(sub.Key)...)
	}
	for _, item := range before.Backend.Imports {
		if findImportedGroupIndex(final.Backend.Imports, item.Key) >= 0 {
			continue
		}
		removedTags = append(removedTags, a.importBackendTags(item.Key)...)
		removedRefs = append(removedRefs, a.importMemberRefs(item.Key)...)
	}
	for _, group := range before.Backend.Groups {
		exists := false
		for _, next := range final.Backend.Groups {
			if next.Key == group.Key {
				exists = true
				break
			}
		}
		if !exists {
			removedTags = append(removedTags, RuntimeBackendTag("group", group.Key))
			removedRefs = append(removedRefs, "group."+group.Key)
		}
	}
	return backendReferenceBlockers(final, removedTags, removedRefs)
}

// subscriptionBackendTags 返回指定订阅缓存中的运行时 outbound tag。
func (a *App) subscriptionBackendTags(subKey string) []string {
	nodes, err := a.LoadSubscriptionCache(subKey)
	if err != nil {
		return nil
	}
	MakeUniqueBackendKeys(nodes)
	tags := make([]string, 0, len(nodes))
	for _, node := range nodes {
		tags = append(tags, RuntimeBackendTag("sub-"+subKey, node.BackendKey()))
	}
	return tags
}

// subscriptionMemberRefs 返回指定订阅缓存中的动态组成员引用。
func (a *App) subscriptionMemberRefs(subKey string) []string {
	nodes, err := a.LoadSubscriptionCache(subKey)
	if err != nil {
		return nil
	}
	MakeUniqueBackendKeys(nodes)
	refs := make([]string, 0, len(nodes))
	for _, node := range nodes {
		refs = append(refs, "sub."+subKey+"."+node.BackendKey())
	}
	return refs
}

// importBackendTags 返回指定导入缓存中的运行时 outbound tag。
func (a *App) importBackendTags(groupKey string) []string {
	nodes, err := a.LoadSubscriptionCache(groupKey)
	if err != nil {
		return nil
	}
	MakeUniqueBackendKeys(nodes)
	tags := make([]string, 0, len(nodes))
	for _, node := range nodes {
		tags = append(tags, RuntimeBackendTag("import-"+groupKey, node.BackendKey()))
	}
	return tags
}

// importMemberRefs 返回指定导入缓存中的动态组成员引用。
func (a *App) importMemberRefs(groupKey string) []string {
	nodes, err := a.LoadSubscriptionCache(groupKey)
	if err != nil {
		return nil
	}
	MakeUniqueBackendKeys(nodes)
	refs := make([]string, 0, len(nodes))
	for _, node := range nodes {
		refs = append(refs, "import."+groupKey+"."+node.BackendKey())
	}
	return refs
}

// backendReferenceBlockers 汇总被删除节点仍被哪些配置引用。
func backendReferenceBlockers(cfg Config, tags []string, refs []string) []string {
	tagSet := stringSet(tags)
	refSet := stringSet(refs)
	var blockers []string
	if tagSet[cfg.Policy.Default] {
		blockers = append(blockers, "当前出口 "+cfg.Policy.Default)
	}
	for _, group := range cfg.Backend.Groups {
		for _, member := range group.Members {
			if refSet[member] {
				blockers = append(blockers, fmt.Sprintf("动态组 %s 成员 %s", group.Key, member))
			}
		}
		if refSet[group.Primary] {
			blockers = append(blockers, fmt.Sprintf("动态组 %s 主节点 %s", group.Key, group.Primary))
		}
	}
	for _, rule := range cfg.Policy.DynamicOutbound {
		if tagSet[rule.Outbound] {
			blockers = append(blockers, fmt.Sprintf("动态出口 %s -> %s", rule.Match, rule.Outbound))
		}
	}
	for _, node := range cfg.Backend.Static {
		if refSet[strings.TrimSpace(node.Detour)] {
			blockers = append(blockers, fmt.Sprintf("静态节点 %s detour %s", node.Key, node.Detour))
		}
	}
	return blockers
}

// stringSet 把字符串切片转成集合。
func stringSet(values []string) map[string]bool {
	result := map[string]bool{}
	for _, value := range values {
		if value != "" {
			result[value] = true
		}
	}
	return result
}

// NormalizeDynamicOutboundRules 校验并清洗 Web 提交的动态出口规则。
func (a *App) NormalizeDynamicOutboundRules(cfg Config, rules []DynamicOutboundRule) ([]DynamicOutboundRule, error) {
	result := make([]DynamicOutboundRule, 0, len(rules))
	seen := map[string]bool{}
	seenMatch := map[string]bool{}
	for _, rule := range rules {
		match := strings.TrimSpace(rule.Match)
		outbound := SanitizeTag(rule.Outbound)
		if match == "" && outbound == "" {
			continue
		}
		if match == "" || outbound == "" {
			return nil, errors.New("动态出口规则必须同时填写匹配条件和出口")
		}
		if !a.WebBackendExists(cfg, outbound) {
			return nil, fmt.Errorf("动态出口 backend 不存在: %s", outbound)
		}
		if _, err := BuildDynamicOutboundRouteRule(DynamicOutboundRule{Match: match, Outbound: outbound}); err != nil {
			return nil, err
		}
		matchKey := strings.ToLower(match)
		if seenMatch[matchKey] {
			return nil, fmt.Errorf("动态出口匹配重复: %s", match)
		}
		seenMatch[matchKey] = true
		key := strings.ToLower(match) + "\x00" + outbound
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, DynamicOutboundRule{Match: match, Outbound: outbound})
	}
	return result, nil
}

// NormalizeOverrideRules 校验并清洗 Web 提交的静态跳转规则。
func NormalizeOverrideRules(rules []OverrideRule) ([]OverrideRule, error) {
	result := make([]OverrideRule, 0, len(rules))
	seenKey := map[string]bool{}
	seenMatch := map[string]bool{}
	for index, rule := range rules {
		key := SanitizeTag(rule.Key)
		match := strings.TrimSpace(rule.Match)
		address := strings.TrimSpace(rule.Address)
		outbound := SanitizeTag(firstNonEmpty(rule.Outbound, "direct"))
		empty := key == "" && match == "" && address == "" && rule.Port == 0
		if empty {
			continue
		}
		if key == "" {
			key = fmt.Sprintf("override-%d", index+1)
		}
		if match == "" || address == "" || rule.Port <= 0 {
			return nil, errors.New("静态跳转规则必须填写匹配条件、目标地址和端口")
		}
		if seenKey[key] {
			return nil, fmt.Errorf("静态跳转 key 重复: %s", key)
		}
		seenKey[key] = true
		enabled := OverrideEnabled(rule)
		if _, err := BuildOverrideRouteRule(OverrideRule{
			Key:      key,
			Match:    match,
			Address:  address,
			Port:     rule.Port,
			Outbound: outbound,
			Enabled:  boolPtr(enabled),
		}); err != nil {
			return nil, err
		}
		matchKey := strings.ToLower(match)
		if seenMatch[matchKey] {
			return nil, fmt.Errorf("静态跳转匹配重复: %s", match)
		}
		seenMatch[matchKey] = true
		result = append(result, OverrideRule{
			Key:      key,
			Match:    match,
			Address:  address,
			Port:     rule.Port,
			Outbound: outbound,
			Enabled:  boolPtr(enabled),
		})
	}
	return result, nil
}

// OverrideEnabled 返回静态跳转规则是否启用，缺省时按启用处理。
func OverrideEnabled(rule OverrideRule) bool {
	return rule.Enabled == nil || *rule.Enabled
}

// ValidateStaticDetours 校验静态节点链式拨号引用。
func (a *App) ValidateStaticDetours(cfg Config) error {
	refs := a.AvailableDetourRefs(cfg)
	edges := map[string][]string{}
	for _, node := range cfg.Backend.Static {
		key := SanitizeTag(node.Key)
		ref := "static." + key
		detour := strings.TrimSpace(node.Detour)
		if detour == "" {
			continue
		}
		if detour == ref {
			return fmt.Errorf("静态节点 %s 不能 detour 到自己", key)
		}
		if !refs[detour] {
			return fmt.Errorf("静态节点 %s detour 不存在: %s", key, detour)
		}
		edges[ref] = []string{detour}
	}
	for _, group := range cfg.Backend.Groups {
		key := SanitizeTag(group.Key)
		if key == "" {
			continue
		}
		edges["group."+key] = append([]string(nil), group.Members...)
	}
	// 触发条件：静态节点之间互相 detour，或 detour 到包含自己的动态组。
	// 不能只检查直接自引用，因为 group 会把链式关系隐藏一层。
	// 防止保存出 sing-box 无法稳定拨号的环形出站链路。
	if path := firstDetourCycle(edges); len(path) > 0 {
		return fmt.Errorf("静态节点 detour 存在循环: %s", strings.Join(path, " -> "))
	}
	return nil
}

// firstDetourCycle 查找静态 detour 和动态组成员构成的首个循环。
func firstDetourCycle(edges map[string][]string) []string {
	state := map[string]int{}
	stack := []string{}
	stackIndex := map[string]int{}
	var visit func(string) []string
	visit = func(node string) []string {
		if state[node] == 1 {
			start := stackIndex[node]
			return append(append([]string(nil), stack[start:]...), node)
		}
		if state[node] == 2 {
			return nil
		}
		state[node] = 1
		stackIndex[node] = len(stack)
		stack = append(stack, node)
		for _, next := range edges[node] {
			if cycle := visit(next); len(cycle) > 0 {
				return cycle
			}
		}
		stack = stack[:len(stack)-1]
		delete(stackIndex, node)
		state[node] = 2
		return nil
	}
	for node := range edges {
		if cycle := visit(node); len(cycle) > 0 {
			return cycle
		}
	}
	return nil
}

// AvailableDetourRefs 返回静态节点 detour 可引用的真实节点和动态组。
func (a *App) AvailableDetourRefs(cfg Config) map[string]bool {
	refs := a.AvailableMemberRefs(cfg)
	for _, group := range cfg.Backend.Groups {
		key := SanitizeTag(group.Key)
		if key != "" && len(group.Members) > 0 {
			refs["group."+key] = true
		}
	}
	return refs
}

// AvailableMemberRefs 返回可被动态组引用的真实节点链路 key。
func (a *App) AvailableMemberRefs(cfg Config) map[string]bool {
	refs := map[string]bool{}
	for _, item := range cfg.Backend.Static {
		NormalizeBackendIdentity(&item)
		refs["static."+item.BackendKey()] = true
	}
	for _, sub := range cfg.Backend.Subscription {
		nodes, err := a.LoadSubscriptionCache(sub.Key)
		if err != nil {
			continue
		}
		MakeUniqueBackendKeys(nodes)
		for _, node := range nodes {
			refs["sub."+sub.Key+"."+node.BackendKey()] = true
		}
	}
	for _, group := range cfg.Backend.Imports {
		nodes, err := a.LoadSubscriptionCache(group.Key)
		if err != nil {
			continue
		}
		MakeUniqueBackendKeys(nodes)
		for _, node := range nodes {
			refs["import."+group.Key+"."+node.BackendKey()] = true
		}
	}
	return refs
}

// NormalizeDynamicGroups 规范化动态组 key 和成员引用。
func NormalizeDynamicGroups(groups []DynamicGroupConfig, available map[string]bool) []DynamicGroupConfig {
	seenGroups := map[string]int{}
	result := make([]DynamicGroupConfig, 0, len(groups))
	for i, group := range groups {
		key := UniqueScopedKey(group.Key, seenGroups, fmt.Sprintf("group-%d", i+1))
		mode := normalizeDynamicGroupMode(group.Mode)
		seenMembers := map[string]bool{}
		members := make([]string, 0, len(group.Members))
		for _, member := range group.Members {
			member = strings.TrimSpace(member)
			if member == "" || seenMembers[member] {
				continue
			}
			if available != nil && !available[member] {
				continue
			}
			seenMembers[member] = true
			members = append(members, member)
		}
		primary := normalizeDynamicGroupPrimary(mode, group.Primary, members)
		result = append(result, DynamicGroupConfig{Key: key, Mode: mode, Primary: primary, Members: members})
	}
	return result
}

// NormalizeDynamicGroupsForSave 校验 Web 保存的动态组 key，并清洗成员引用。
func NormalizeDynamicGroupsForSave(groups []DynamicGroupConfig, available map[string]bool) ([]DynamicGroupConfig, error) {
	seenGroups := map[string]bool{}
	result := make([]DynamicGroupConfig, 0, len(groups))
	for i, group := range groups {
		key := SanitizeTag(group.Key)
		if key == "" {
			return nil, fmt.Errorf("动态组第 %d 个 key 为空", i+1)
		}
		if seenGroups[key] {
			return nil, fmt.Errorf("动态组 key 重复: %s", key)
		}
		seenGroups[key] = true
		mode := normalizeDynamicGroupMode(group.Mode)
		seenMembers := map[string]bool{}
		members := make([]string, 0, len(group.Members))
		for _, member := range group.Members {
			member = strings.TrimSpace(member)
			if member == "" || seenMembers[member] {
				continue
			}
			if available != nil && !available[member] {
				return nil, fmt.Errorf("动态组 %s 成员不存在: %s", key, member)
			}
			seenMembers[member] = true
			members = append(members, member)
		}
		primary := strings.TrimSpace(group.Primary)
		if mode == dynamicGroupModePrimaryBackup {
			if primary == "" {
				return nil, fmt.Errorf("主备动态组 %s 缺少主节点", key)
			}
			if !containsString(members, primary) {
				return nil, fmt.Errorf("主备动态组 %s 主节点不在成员列表: %s", key, primary)
			}
		} else {
			primary = ""
		}
		result = append(result, DynamicGroupConfig{Key: key, Mode: mode, Primary: primary, Members: members})
	}
	return result, nil
}

// normalizeStaticProtocol 规范化静态节点协议，旧配置空值按 HY2 兼容。
func normalizeStaticProtocol(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case staticProtocolVMess:
		return staticProtocolVMess
	case staticProtocolSS:
		return staticProtocolSS
	case staticProtocolTrojan:
		return staticProtocolTrojan
	case staticProtocolAnyTLS:
		return staticProtocolAnyTLS
	case staticProtocolSocks, "socks5":
		return staticProtocolSocks
	case staticProtocolHTTP:
		return staticProtocolHTTP
	default:
		return staticProtocolHY2
	}
}

// NormalizeStaticBackendsForSave 校验并清洗 Web 提交的静态节点。
func NormalizeStaticBackendsForSave(nodes []StaticBackend) ([]StaticBackend, error) {
	seen := map[string]bool{}
	result := make([]StaticBackend, 0, len(nodes))
	for i, node := range nodes {
		NormalizeBackendIdentity(&node)
		node.Key = SanitizeTag(node.Key)
		node.Protocol = normalizeStaticProtocol(node.Protocol)
		if node.Key == "" {
			return nil, fmt.Errorf("静态节点第 %d 个 key 为空", i+1)
		}
		if seen[node.Key] {
			return nil, fmt.Errorf("静态节点 key 重复: %s", node.Key)
		}
		if strings.TrimSpace(node.Server) == "" {
			return nil, fmt.Errorf("静态节点 %s server 为空", node.Key)
		}
		if node.Port <= 0 || node.Port > 65535 {
			return nil, fmt.Errorf("静态节点 %s port 非法", node.Key)
		}
		clean := StaticBackend{
			Protocol: node.Protocol,
			Key:      node.Key,
			Name:     strings.TrimSpace(node.Name),
			Server:   strings.TrimSpace(node.Server),
			Port:     node.Port,
			Detour:   strings.TrimSpace(node.Detour),
		}
		switch node.Protocol {
		case staticProtocolVMess:
			if strings.TrimSpace(node.UUID) == "" {
				return nil, fmt.Errorf("静态节点 %s uuid 为空", node.Key)
			}
			clean.UUID = strings.TrimSpace(node.UUID)
			clean.Security = firstNonEmpty(strings.TrimSpace(node.Security), "auto")
			clean.AlterID = node.AlterID
			clean.SNI = strings.TrimSpace(node.SNI)
			clean.TLS = node.TLS
			clean.Insecure = node.Insecure
			clean.Transport = strings.ToLower(strings.TrimSpace(node.Transport))
			clean.Path = strings.TrimSpace(node.Path)
			clean.Host = strings.TrimSpace(node.Host)
		case staticProtocolSS:
			if strings.TrimSpace(node.Method) == "" {
				return nil, fmt.Errorf("静态节点 %s method 为空", node.Key)
			}
			if strings.TrimSpace(node.Password) == "" {
				return nil, fmt.Errorf("静态节点 %s password 为空", node.Key)
			}
			clean.Method = strings.TrimSpace(node.Method)
			clean.Password = strings.TrimSpace(node.Password)
			clean.Plugin = normalizeSSPlugin(strings.TrimSpace(node.Plugin))
			clean.PluginOpts = normalizeSSPluginOpts(strings.TrimSpace(node.PluginOpts))
		case staticProtocolTrojan:
			if strings.TrimSpace(node.Password) == "" {
				return nil, fmt.Errorf("静态节点 %s password 为空", node.Key)
			}
			clean.Password = strings.TrimSpace(node.Password)
			clean.SNI = strings.TrimSpace(node.SNI)
			clean.TLS = node.TLS
			clean.Insecure = node.Insecure
			clean.Transport = strings.ToLower(strings.TrimSpace(node.Transport))
			clean.Path = strings.TrimSpace(node.Path)
			clean.Host = strings.TrimSpace(node.Host)
		case staticProtocolAnyTLS:
			if strings.TrimSpace(node.Password) == "" {
				return nil, fmt.Errorf("静态节点 %s password 为空", node.Key)
			}
			clean.Password = strings.TrimSpace(node.Password)
			clean.SNI = strings.TrimSpace(node.SNI)
			clean.Insecure = node.Insecure
			clean.IdleSessionCheckInterval = strings.TrimSpace(node.IdleSessionCheckInterval)
			clean.IdleSessionTimeout = strings.TrimSpace(node.IdleSessionTimeout)
			clean.MinIdleSession = node.MinIdleSession
		case staticProtocolSocks:
			clean.Username = strings.TrimSpace(node.Username)
			clean.Password = strings.TrimSpace(node.Password)
		case staticProtocolHTTP:
			clean.Username = strings.TrimSpace(node.Username)
			clean.Password = strings.TrimSpace(node.Password)
		default:
			if strings.TrimSpace(node.Password) == "" {
				return nil, fmt.Errorf("静态节点 %s password 为空", node.Key)
			}
			clean.Password = strings.TrimSpace(node.Password)
			clean.SNI = strings.TrimSpace(node.SNI)
			clean.Insecure = node.Insecure
			clean.ObfsPassword = strings.TrimSpace(node.ObfsPassword)
		}
		seen[node.Key] = true
		result = append(result, clean)
	}
	return result, nil
}

// NormalizeSubscriptionsForSave 校验并清洗 Web 提交的订阅配置。
func NormalizeSubscriptionsForSave(subscriptions []Subscription) ([]Subscription, error) {
	seen := map[string]bool{}
	result := make([]Subscription, 0, len(subscriptions))
	for i, sub := range subscriptions {
		sub.Key = SanitizeTag(firstNonEmpty(sub.Key, sub.Name))
		if sub.Key == "" {
			return nil, fmt.Errorf("订阅第 %d 个 key 为空", i+1)
		}
		if seen[sub.Key] {
			return nil, fmt.Errorf("订阅 key 重复: %s", sub.Key)
		}
		if strings.TrimSpace(sub.Name) == "" {
			sub.Name = sub.Key
		}
		if strings.TrimSpace(sub.URL) == "" {
			return nil, fmt.Errorf("订阅 %s url 为空", sub.Key)
		}
		if strings.TrimSpace(sub.UserAgent) == "" {
			sub.UserAgent = defaultSubscriptionUA
		}
		sub.Default = SanitizeTag(sub.Default)
		seen[sub.Key] = true
		result = append(result, sub)
	}
	return result, nil
}

// NormalizeImportedGroupsForSave 校验并清洗 Web 提交的导入来源配置。
func NormalizeImportedGroupsForSave(groups []ImportedNodeGroup) ([]ImportedNodeGroup, error) {
	seen := map[string]bool{}
	result := make([]ImportedNodeGroup, 0, len(groups))
	for i, group := range groups {
		group.Key = SanitizeTag(firstNonEmpty(group.Key, group.Name))
		if group.Key == "" {
			return nil, fmt.Errorf("导入分组第 %d 个 key 为空", i+1)
		}
		if seen[group.Key] {
			return nil, fmt.Errorf("导入分组 key 重复: %s", group.Key)
		}
		if strings.TrimSpace(group.Name) == "" {
			group.Name = group.Key
		}
		group.Source = normalizeImportSource(group.Source)
		if group.Source == "" {
			return nil, fmt.Errorf("导入分组 %s source 不支持", group.Key)
		}
		seen[group.Key] = true
		result = append(result, ImportedNodeGroup{
			Key:    group.Key,
			Name:   strings.TrimSpace(group.Name),
			Source: group.Source,
		})
	}
	return result, nil
}

// normalizeImportSource 规范化手动导入来源类型。
func normalizeImportSource(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "clash":
		return "clash"
	default:
		return ""
	}
}

// WebBackendFromBackend 将运行时节点转为前端节点对象。
func WebBackendFromBackend(node ProxyBackend, source string) WebBackend {
	tag := SanitizeTag(node.BackendTag())
	if tag == "" {
		tag = SanitizeTag(node.BackendServer())
	}
	item := WebBackend{
		Key:      node.BackendKey(),
		Tag:      tag,
		Name:     firstNonEmpty(node.BackendName(), tag),
		Protocol: node.BackendProtocol(),
		Server:   node.BackendServer(),
		Port:     node.BackendPort(),
		Source:   source,
	}
	if source == "static" {
		if staticNode, ok := node.(*StaticBackend); ok {
			item.Username = staticNode.Username
			item.Password = staticNode.Password
			item.SNI = staticNode.SNI
			item.Insecure = staticNode.Insecure
			item.ObfsPassword = staticNode.ObfsPassword
			item.UUID = staticNode.UUID
			item.Security = staticNode.Security
			item.AlterID = staticNode.AlterID
			item.TLS = staticNode.TLS
			item.Transport = staticNode.Transport
			item.Path = staticNode.Path
			item.Host = staticNode.Host
			item.Method = staticNode.Method
			item.Plugin = staticNode.Plugin
			item.PluginOpts = staticNode.PluginOpts
			item.IdleSessionCheckInterval = staticNode.IdleSessionCheckInterval
			item.IdleSessionTimeout = staticNode.IdleSessionTimeout
			item.MinIdleSession = staticNode.MinIdleSession
			item.Detour = staticNode.Detour
		}
	}
	return item
}

// SortWebBackends 保证前端列表按协议稳定排序。
func SortWebBackends(nodes []WebBackend) {
	sort.SliceStable(nodes, func(i, j int) bool {
		left := webProtocolRank(nodes[i].Protocol)
		right := webProtocolRank(nodes[j].Protocol)
		if left != right {
			return left < right
		}
		return nodes[i].Tag < nodes[j].Tag
	})
}

// webProtocolRank 返回前端节点协议排序权重。
func webProtocolRank(protocol string) int {
	switch protocol {
	case "hy2":
		return 0
	case "vmess":
		return 1
	case "trojan":
		return 2
	case "anytls":
		return 3
	case "socks":
		return 4
	case "http":
		return 5
	case "ss":
		return 6
	default:
		return 9
	}
}

// SaveConfig 原子写入主 YAML 配置。
func SaveConfig(path string, cfg Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return writeAtomicFile(path, data, 0644)
}

// ValidateLocalRulesText 验证规则文本是否符合一行一条约定。
func ValidateLocalRulesText(text string) error {
	_, err := ParseLocalRules(strings.NewReader(text))
	return err
}

// NormalizeProxyRuleSets 过滤 Web 提交的代理规则集。
func NormalizeProxyRuleSets(items []string) []string {
	allowed := make(map[string]bool, len(defaultProxyRuleSets))
	for _, item := range defaultProxyRuleSets {
		allowed[item] = true
	}
	seen := map[string]bool{}
	result := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if !allowed[item] || seen[item] {
			continue
		}
		seen[item] = true
		result = append(result, item)
	}
	return result
}

// SaveRuntimeState 保存运行状态文件。
func SaveRuntimeState(state RuntimeState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomicFile(defaultStatePath, append(data, '\n'), 0644)
}

// LoadRuntimeState 读取运行状态文件。
func LoadRuntimeState() (RuntimeState, error) {
	var state RuntimeState
	data, err := os.ReadFile(defaultStatePath)
	if err != nil {
		return state, err
	}
	err = json.Unmarshal(data, &state)
	return state, err
}

// MakeJWT 创建最小 HS256 JWT，适用于本机 Web 面板登录。
func MakeJWT(username string, secret string, expiresAt time.Time) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadData, err := json.Marshal(map[string]any{
		"sub": username,
		"exp": expiresAt.Unix(),
	})
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadData)
	unsigned := header + "." + payload
	signature := signJWT(unsigned, secret)
	return unsigned + "." + signature, nil
}

// VerifyJWT 校验 HS256 JWT 并返回用户名。
func VerifyJWT(token string, secret string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("token 格式错误")
	}
	expected := signJWT(parts[0]+"."+parts[1], secret)
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return "", errors.New("token 签名无效")
	}
	payloadData, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	var payload struct {
		// Subject 是登录账号。
		Subject string `json:"sub"`
		// ExpiresAt 是过期时间戳。
		ExpiresAt int64 `json:"exp"`
	}
	if err := json.Unmarshal(payloadData, &payload); err != nil {
		return "", err
	}
	if time.Now().Unix() >= payload.ExpiresAt {
		return "", errors.New("token 已过期")
	}
	return payload.Subject, nil
}

// signJWT 计算 JWT 签名。
func signJWT(unsigned string, secret string) string {
	mac := hmac.New(func() hash.Hash { return sha256.New() }, []byte(secret))
	_, _ = mac.Write([]byte(unsigned))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// writeJSON 写入 JSON 响应。
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// writeAtomicFile 原子替换文件，适用于配置和规则写入。
func writeAtomicFile(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// writeFileIfChanged 只在内容变化时写入文件，适用于闪存缓存文件。
func writeFileIfChanged(path string, data []byte, perm os.FileMode) (bool, error) {
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, data) {
		return false, nil
	}
	if err := writeAtomicFile(path, data, perm); err != nil {
		return false, err
	}
	return true, nil
}

// isWebSetupRequired 判断 Web 登录是否缺少账号密码。
func isWebSetupRequired(cfg Config) bool {
	return cfg.Web.Auth.Username == "" || cfg.Web.Auth.Password == ""
}

// webJWTSecret 返回 JWT 签名密钥。
func webJWTSecret(cfg Config) string {
	return firstNonEmpty(cfg.Web.JWTSecret, cfg.Web.Auth.Password)
}

// parseDurationOrDefault 解析 duration，失败时使用默认值。
func parseDurationOrDefault(value string, fallback time.Duration) time.Duration {
	duration, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return duration
}

// clientIP 从请求中提取客户端 IP。
func clientIP(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

// serviceStatus 返回 OpenWrt init 服务状态文本。
func serviceStatus(name string) string {
	err := exec.Command("/etc/init.d/"+name, "status").Run()
	if err == nil {
		return "running"
	}
	return "stopped"
}

// singBoxStatus 返回编排器托管的 sing-box 运行状态。
func singBoxStatus() string {
	running, err := hasSingBoxProcess()
	if err == nil && running {
		return "running"
	}
	return "stopped"
}

// restartSingBoxService 重启 sing-box，适用于保存后必须重建 TUN 的场景。
func (a *App) restartSingBoxService() error {
	if err := a.stopSingBoxProcess(); err != nil {
		return err
	}
	return a.startSingBoxProcess()
}

// startSingBoxProcess 直接启动 sing-box 子进程。
func (a *App) startSingBoxProcess() error {
	a.SingBoxMutex.Lock()
	defer a.SingBoxMutex.Unlock()
	if a.SingBoxCmd != nil && a.SingBoxCmd.Process != nil && a.SingBoxCmd.ProcessState == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(a.SingBoxConfig), 0755); err != nil {
		return err
	}
	logPath := filepath.Join(defaultLogDir, "sing-box.stderr.log")
	if a.Logger != nil {
		logPath = filepath.Join(a.Logger.Dir, "sing-box.stderr.log")
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0755); err != nil {
		return err
	}
	if err := a.cleanupAutoRedirectRouteResidue(); err != nil && a.Logger != nil {
		a.Logger.Warn("清理 auto_redirect 残留失败 err=%v", err)
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	singBoxBinary, singBoxWorkDir := ResolveSingBoxRuntime()
	cmd := exec.Command(singBoxBinary, "run", "-c", a.SingBoxConfig, "-D", singBoxWorkDir)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return err
	}
	exit := make(chan error, 1)
	a.SingBoxCmd = cmd
	a.SingBoxExit = exit
	a.SingBoxStopping = false
	go func() {
		err := cmd.Wait()
		_ = logFile.Close()
		exit <- err
		a.handleSingBoxExit(cmd, err)
	}()
	return a.waitSingBoxReady(singBoxReadyTimeout)
}

// cleanupAutoRedirectRouteResidue 清理 sing-tun auto_redirect 残留路由。
func (a *App) cleanupAutoRedirectRouteResidue() error {
	cmd := exec.Command("sh", "-c", CleanupAutoRedirectRouteResidueScript())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	if a.Logger != nil && strings.TrimSpace(string(output)) != "" {
		a.Logger.Warn("已清理 auto_redirect 残留: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

// CleanupAutoRedirectRouteResidueScript 返回窄口径 auto_redirect 残留清理脚本。
func CleanupAutoRedirectRouteResidueScript() string {
	return `#!/bin/sh
set -eu

cleanup_family() {
  fam="$1"
  loopback="$2"
  ip "$fam" rule show 2>/dev/null | awk '
    $1 == "1:" && $0 ~ /lookup/ {
      for (i = 1; i <= NF; i++) {
        if ($i == "lookup" && (i + 1) <= NF) print $(i + 1)
      }
    }
  ' | sort -u | while read -r table; do
    case "$table" in
      ''|local|main|default|0|253|254|255)
        continue
        ;;
    esac
    routes="$(ip "$fam" route show table "$table" 2>/dev/null || true)"
    printf '%s\n' "$routes" | grep -Eq "^local ${loopback}([ /]|$)" || continue
    ip "$fam" route flush table "$table" >/dev/null 2>&1 || true
    while ip "$fam" rule del pref 1 table "$table" >/dev/null 2>&1; do :; done
    printf '%s:%s\n' "$fam" "$table"
  done
}

cleanup_family -4 127.0.0.1
cleanup_family -6 ::1
`
}

// handleSingBoxExit 处理 sing-box 子进程退出，异常退出会自动重拉。
func (a *App) handleSingBoxExit(cmd *exec.Cmd, err error) {
	a.SingBoxMutex.Lock()
	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}
	expectedExit := false
	if pid != 0 && a.SingBoxExpectedExit != nil && a.SingBoxExpectedExit[pid] {
		expectedExit = true
		delete(a.SingBoxExpectedExit, pid)
	}
	intentional := a.SingBoxStopping || expectedExit || a.SingBoxCmd != cmd
	if a.SingBoxCmd == cmd {
		a.SingBoxCmd = nil
		a.SingBoxExit = nil
	}
	if intentional || a.SingBoxRestarting {
		a.SingBoxMutex.Unlock()
		return
	}
	a.SingBoxRestarting = true
	backoff := a.SingBoxBackoff
	if backoff <= 0 {
		backoff = time.Second
	} else if backoff < 10*time.Second {
		backoff *= 2
	}
	if backoff > 10*time.Second {
		backoff = 10 * time.Second
	}
	a.SingBoxBackoff = backoff
	a.SingBoxMutex.Unlock()

	if a.Logger != nil {
		if err != nil {
			a.Logger.Warn("sing-box 异常退出 err=%v，%s 后重拉", err, backoff)
		} else {
			a.Logger.Warn("sing-box 异常退出，%s 后重拉", backoff)
		}
	}
	time.Sleep(backoff)
	cfg, cfgErr := a.LoadConfig()
	if cfgErr == nil && !ServiceEnabled(cfg) {
		if a.Logger != nil {
			a.Logger.Info("sing-box 服务开关关闭，跳过异常重拉")
		}
		a.SingBoxMutex.Lock()
		a.SingBoxRestarting = false
		a.SingBoxMutex.Unlock()
		return
	}
	a.SingBoxMutex.Lock()
	a.SingBoxRestarting = false
	a.SingBoxMutex.Unlock()
	startErr := a.startSingBoxProcess()
	a.SingBoxMutex.Lock()
	if startErr == nil {
		a.SingBoxBackoff = 0
	}
	a.SingBoxMutex.Unlock()
	if startErr != nil && a.Logger != nil {
		a.Logger.Error("sing-box 重拉失败 err=%v", startErr)
	}
}

// stopSingBoxProcess 停止 sing-box，适用于保存和服务停止时释放数据面。
func (a *App) stopSingBoxProcess() error {
	a.SingBoxMutex.Lock()
	cmd := a.SingBoxCmd
	exit := a.SingBoxExit
	a.SingBoxStopping = true
	if cmd != nil && cmd.Process != nil {
		if a.SingBoxExpectedExit == nil {
			a.SingBoxExpectedExit = map[int]bool{}
		}
		a.SingBoxExpectedExit[cmd.Process.Pid] = true
	}
	a.SingBoxMutex.Unlock()
	if cmd != nil && cmd.Process != nil && cmd.ProcessState == nil {
		// 触发条件：Web 保存或服务停止要求释放 sing-box 数据面。
		// 不能直接 SIGKILL，否则 sing-box 无法执行 Close 清理 TUN。
		// 防止 TUN 状态残留导致下一次启动失败。
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		if exit != nil {
			select {
			case <-exit:
				a.SingBoxMutex.Lock()
				a.SingBoxCmd = nil
				a.SingBoxExit = nil
				a.SingBoxStopping = false
				a.SingBoxMutex.Unlock()
				return nil
			case <-time.After(singBoxGracefulStopTimeout):
				if a.Logger != nil {
					a.Logger.Warn("sing-box SIGTERM 后 %s 内未回收，准备强制清理", singBoxGracefulStopTimeout)
				}
			}
		}
	}
	if err := terminateSingBoxProcesses(); err != nil && a.Logger != nil {
		a.Logger.Warn("停止 sing-box 残留进程失败 err=%v", err)
	}
	if err := a.waitSingBoxStopped(); err != nil {
		return err
	}
	a.SingBoxMutex.Lock()
	a.SingBoxCmd = nil
	a.SingBoxExit = nil
	a.SingBoxStopping = false
	a.SingBoxMutex.Unlock()
	return nil
}

// terminateSingBoxProcesses 优雅停止残留 sing-box，超时后才强制结束。
func terminateSingBoxProcesses() error {
	if err := signalSingBoxProcesses(syscall.SIGTERM); err != nil {
		return err
	}
	deadline := time.Now().Add(singBoxGracefulStopTimeout)
	for time.Now().Before(deadline) {
		running, err := hasSingBoxProcess()
		if err != nil {
			return err
		}
		if !running {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return signalSingBoxProcesses(syscall.SIGKILL)
}

// waitSingBoxStopped 等待旧 sing-box 进程自然退出。
func (a *App) waitSingBoxStopped() error {
	started := time.Now()
	warned := false
	for {
		running, err := hasSingBoxProcess()
		if err != nil && a.Logger != nil {
			a.Logger.Warn("检查 sing-box 进程失败 err=%v", err)
		}
		if !running {
			return nil
		}
		if !warned && time.Since(started) >= singBoxStopWarnAfter {
			warned = true
			if a.Logger != nil {
				a.Logger.Warn("sing-box 自然退出超过 %s，继续等待", singBoxStopWarnAfter)
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// waitSingBoxReady 等待 sing-box 进程就绪。
func (a *App) waitSingBoxReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		running, err := hasSingBoxProcess()
		if err != nil && a.Logger != nil {
			a.Logger.Warn("检查 sing-box 进程失败 err=%v", err)
		}
		if running {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("sing-box 启动后进程未在 500 毫秒内出现")
}

// WaitClashAPIReady 等到 sing-box 北向 Clash API 可用。
func (a *App) WaitClashAPIReady() error {
	for {
		if clashAPIReady() {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// clashAPIReady 判断本地 Clash API 是否已经监听。
func clashAPIReady() bool {
	client := &http.Client{Timeout: 150 * time.Millisecond}
	resp, err := client.Get("http://" + defaultClashAPIListen + "/version")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// signalSingBoxProcesses 向当前所有 sing-box 进程发送指定信号。
func signalSingBoxProcesses(sig syscall.Signal) error {
	pids, err := singBoxPIDs()
	if err != nil {
		return err
	}
	var errs []string
	for _, pid := range pids {
		if err := syscall.Kill(pid, sig); err != nil && !errors.Is(err, syscall.ESRCH) {
			errs = append(errs, fmt.Sprintf("%d:%v", pid, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("signal sing-box: %s", strings.Join(errs, ", "))
	}
	return nil
}

// hasSingBoxProcess 判断系统中是否还有 sing-box 进程。
func hasSingBoxProcess() (bool, error) {
	pids, err := singBoxPIDs()
	if err != nil {
		return false, err
	}
	return len(pids) > 0, nil
}

// singBoxPIDs 从 /proc 扫描 sing-box 进程，避免依赖 pidof/pkill。
func singBoxPIDs() ([]int, error) {
	return singBoxPIDsFromProc("/proc", os.Getpid())
}

// singBoxPIDsFromProc 从指定 proc 目录扫描 sing-box 进程，适用于运行时和单元测试。
func singBoxPIDsFromProc(procDir string, selfPID int) ([]int, error) {
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == selfPID {
			continue
		}
		exe, err := os.Readlink(filepath.Join(procDir, entry.Name(), "exe"))
		if err == nil && filepath.Base(exe) == "sing-box" {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// firstConfiguredOutbound 计算配置中的第一个可用节点。
func firstConfiguredOutbound(cfg Config, static []WebBackend, subscriptions []WebSubscription, imports []WebImportedGroup, groups []WebDynamicGroup) string {
	if active := configuredActiveOutbound(cfg); active != "" {
		if tag := matchWebBackend(active, static, subscriptions, imports, groups); tag != "" {
			return tag
		}
	}
	if len(static) > 0 {
		return static[0].Tag
	}
	for _, sub := range subscriptions {
		if len(sub.Nodes) > 0 {
			return sub.Nodes[0].Tag
		}
	}
	for _, group := range imports {
		if len(group.Nodes) > 0 {
			return group.Nodes[0].Tag
		}
	}
	for _, group := range groups {
		if len(group.Members) > 0 {
			return group.Tag
		}
	}
	return ""
}

// matchWebBackend 将旧 key/name/default 映射到当前运行时 tag。
func matchWebBackend(value string, static []WebBackend, subscriptions []WebSubscription, imports []WebImportedGroup, groups []WebDynamicGroup) string {
	want := SanitizeTag(value)
	for _, group := range groups {
		if group.Tag == value {
			return group.Tag
		}
	}
	for _, node := range static {
		if node.Tag == value {
			return node.Tag
		}
	}
	for _, sub := range subscriptions {
		for _, node := range sub.Nodes {
			if node.Tag == value {
				return node.Tag
			}
		}
	}
	for _, group := range imports {
		for _, node := range group.Nodes {
			if node.Tag == value {
				return node.Tag
			}
		}
	}
	for _, node := range static {
		if node.Key == want || SanitizeTag(node.Name) == want {
			return node.Tag
		}
	}
	for _, sub := range subscriptions {
		for _, node := range sub.Nodes {
			if node.Key == want || SanitizeTag(node.Name) == want {
				return node.Tag
			}
		}
	}
	for _, group := range imports {
		for _, node := range group.Nodes {
			if node.Key == want || SanitizeTag(node.Name) == want {
				return node.Tag
			}
		}
	}
	for _, group := range groups {
		if group.Key == want || SanitizeTag(group.Name) == want {
			return group.Tag
		}
	}
	return ""
}

// configuredActiveOutbound 返回配置里显式指定的激活出口。
func configuredActiveOutbound(cfg Config) string {
	if cfg.Policy.Default != "" {
		return cfg.Policy.Default
	}
	for _, sub := range cfg.Backend.Subscription {
		if sub.Default != "" {
			return sub.Default
		}
	}
	return ""
}

// referencedDynamicGroups 返回当前配置中被引用的动态组。
func referencedDynamicGroups(cfg Config) []DynamicGroupConfig {
	byTag := map[string]DynamicGroupConfig{}
	byKey := map[string]DynamicGroupConfig{}
	for _, group := range cfg.Backend.Groups {
		if len(group.Members) == 0 {
			continue
		}
		normalized := group
		normalized.Key = SanitizeTag(group.Key)
		if normalized.Key == "" {
			continue
		}
		byTag[RuntimeBackendTag("group", normalized.Key)] = normalized
		byKey[normalized.Key] = normalized
		if name := SanitizeTag(normalized.Name); name != "" {
			byKey[name] = normalized
		}
	}
	seen := map[string]bool{}
	result := make([]DynamicGroupConfig, 0)
	addRef := func(ref string) {
		ref = SanitizeTag(ref)
		if ref == "" {
			return
		}
		group, ok := byTag[ref]
		if !ok {
			group, ok = byKey[ref]
		}
		if !ok || seen[group.Key] {
			return
		}
		seen[group.Key] = true
		result = append(result, group)
	}
	addRef(cfg.Policy.Default)
	for _, rule := range cfg.Policy.DynamicOutbound {
		// 触发条件：动态出口规则指向 group。
		// 不能只探测当前出口，否则被规则引用的 group 永远没有择优结果。
		// 防止动态出口 selector 引用 group 时一直停在旧成员。
		addRef(rule.Outbound)
	}
	return result
}

// findSubscription 按名称查找订阅配置。
func findSubscription(cfg Config, name string) (Subscription, bool) {
	index := findSubscriptionIndex(cfg.Backend.Subscription, name)
	if index >= 0 {
		return cfg.Backend.Subscription[index], true
	}
	return Subscription{}, false
}

// findSubscriptionIndex 返回订阅配置下标。
func findSubscriptionIndex(subscriptions []Subscription, name string) int {
	for i, sub := range subscriptions {
		if sub.Key == name || sub.Name == name {
			return i
		}
	}
	return -1
}

// findImportedGroupIndex 返回导入来源配置下标。
func findImportedGroupIndex(groups []ImportedNodeGroup, key string) int {
	for i, group := range groups {
		if group.Key == key {
			return i
		}
	}
	return -1
}

// BuildSingBoxConfig 构造 sing-box JSON 对象。
func (a *App) BuildSingBoxConfig(cfg Config, backends []ProxyBackend, directRules []LocalRule, proxyRules []LocalRule, dynamicRules []DynamicOutboundRule) (map[string]any, error) {
	if len(backends) == 0 {
		return nil, ErrNoAvailableBackend
	}
	defaultOutbound := cfg.Policy.Default
	if defaultOutbound == "" {
		defaultOutbound = backends[0].BackendTag()
	}
	routeProxyOutbound := defaultCurrentSelector
	outbounds := []map[string]any{
		{"type": "direct", "tag": "direct"},
	}
	backendTags := make([]string, 0, len(backends))
	for _, b := range backends {
		outbounds = append(outbounds, b.BuildOutbound())
		backendTags = append(backendTags, b.BackendTag())
	}
	outbounds = append(outbounds, BuildCurrentSelector(defaultOutbound, backendTags))
	for _, rule := range dynamicRules {
		outbounds = append(outbounds, BuildDynamicOutboundSelector(rule, backendTags))
	}
	routeRules := make([]map[string]any, 0)
	routeRules = append(routeRules,
		map[string]any{"action": "sniff"},
		map[string]any{"protocol": "dns", "action": "hijack-dns"},
	)
	if HostsOverrideEnabled(cfg) {
		hostsResolveRule, err := BuildHostsResolveRouteRule(defaultHostsPath)
		if err != nil {
			return nil, err
		}
		if hostsResolveRule != nil {
			routeRules = append(routeRules, hostsResolveRule)
		}
	}
	routeRules = append(routeRules, map[string]any{"network": "icmp", "action": "route", "outbound": "direct"})
	routeRules = append(routeRules, BuildTailscaleDirectRouteRules()...)
	for _, rule := range cfg.Policy.Overrides {
		if !OverrideEnabled(rule) {
			continue
		}
		routeRule, err := BuildOverrideRouteRule(rule)
		if err != nil {
			return nil, err
		}
		routeRules = append(routeRules, routeRule)
	}
	for _, rule := range dynamicRules {
		routeRule, err := BuildDynamicOutboundRouteRule(rule)
		if err != nil {
			return nil, err
		}
		routeRules = append(routeRules, routeRule)
	}
	for _, rule := range directRules {
		routeRules = append(routeRules, BuildRouteRule(rule, "direct"))
	}
	for _, rule := range proxyRules {
		routeRules = append(routeRules, BuildRouteRule(rule, routeProxyOutbound))
	}
	routeRules = append(routeRules,
		map[string]any{"ip_is_private": true, "action": "route", "outbound": "direct"},
		map[string]any{"domain_suffix": []string{".lan", ".local", ".localhost"}, "action": "route", "outbound": "direct"},
		map[string]any{"rule_set": []string{"geoip-private", "geosite-private"}, "action": "route", "outbound": "direct"},
	)
	if cfg.GeoFiles.AdsBlock {
		routeRules = append(routeRules, map[string]any{"rule_set": []string{"geosite-category-ads-all"}, "action": "reject", "method": "default"})
	}
	if len(cfg.GeoFiles.ProxyRuleSets) > 0 {
		routeRules = append(routeRules, map[string]any{"rule_set": cfg.GeoFiles.ProxyRuleSets, "action": "route", "outbound": routeProxyOutbound})
	}
	// 触发条件：同一域名同时存在于 geosite-google 与 geolocation-cn。
	// 不能先套 CN 直连规则，否则 Google 依赖域名会被直连超时。
	// 防止用户启用的代理规则被内置直连规则覆盖。
	routeRules = append(routeRules, map[string]any{"rule_set": []string{"geoip-cn", "geosite-cn", "geosite-geolocation-cn"}, "action": "route", "outbound": "direct"})
	dnsRules := []map[string]any{
		{"rule_set": []string{"geosite-cn", "geosite-private"}, "server": "direct-dns"},
		{"query_type": []int{64, 65}, "action": "predefined", "rcode": "NOERROR"},
	}
	if HostsOverrideEnabled(cfg) {
		dnsRules = append([]map[string]any{{"ip_accept_any": true, "server": defaultHostsDNSTag}}, dnsRules...)
	}
	if len(cfg.GeoFiles.ProxyRuleSets) > 0 {
		dnsRules = append(dnsRules, BuildProxyFakeIPDNSRule(cfg.GeoFiles.ProxyRuleSets))
	}
	dnsServers := []map[string]any{
		{"type": "udp", "tag": "local-dns", "server": defaultBootstrapDNS},
		{
			"type":            "https",
			"tag":             "remote-dns",
			"server":          defaultRemoteDNSServer,
			"path":            defaultRemoteDNSPath,
			"detour":          defaultCurrentSelector,
			"domain_resolver": "local-dns",
		},
		{
			"type":            "udp",
			"tag":             "direct-dns",
			"server":          defaultDirectDNS,
			"domain_resolver": "local-dns",
		},
	}
	if HostsOverrideEnabled(cfg) {
		dnsServers = append(dnsServers, map[string]any{
			"type": "hosts",
			"tag":  defaultHostsDNSTag,
			"path": defaultHostsPath,
		})
	}
	dnsServers = append(dnsServers, map[string]any{
		"type":        "fakeip",
		"tag":         "fakeip",
		"inet4_range": "198.18.0.0/15",
	})
	return map[string]any{
		"log": map[string]any{
			"level":     cfg.Log.Level,
			"output":    filepath.Join(cfg.Log.Dir, "sing-box.log"),
			"timestamp": true,
		},
		"experimental": map[string]any{
			"cache_file": map[string]any{
				"enabled":      true,
				"path":         "/etc/sboxctl/cache.db",
				"store_fakeip": true,
			},
			"clash_api": map[string]any{
				"external_controller": defaultClashAPIListen,
			},
		},
		"dns": map[string]any{
			"servers":           dnsServers,
			"rules":             dnsRules,
			"final":             "remote-dns",
			"independent_cache": true,
		},
		"inbounds":  BuildInbounds(cfg.Inbound),
		"outbounds": outbounds,
		"route": map[string]any{
			"rule_set": a.BuildRuleSets(),
			"rules":    routeRules,
			"final":    routeProxyOutbound,
			"default_domain_resolver": map[string]any{
				"server": "local-dns",
			},
			"auto_detect_interface": true,
		},
	}, nil
}

// HostsOverrideEnabled 返回 hosts DNS 开关，旧配置缺失时默认开启。
func HostsOverrideEnabled(cfg Config) bool {
	return cfg.GeoFiles.HostsOverride == nil || *cfg.GeoFiles.HostsOverride
}

// BuildHostsResolveRouteRule 构造 hosts 域名路由解析规则。
func BuildHostsResolveRouteRule(path string) (map[string]any, error) {
	domains, err := ParseHostsDomainsFile(path)
	if err != nil {
		return nil, err
	}
	if len(domains) == 0 {
		return nil, nil
	}
	return map[string]any{
		"action": "resolve",
		"domain": domains,
		"server": defaultHostsDNSTag,
	}, nil
}

// ParseHostsDomainsFile 读取 hosts 文件中的域名，适用于路由阶段解析。
func ParseHostsDomainsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	return ParseHostsDomains(f)
}

// ParseHostsDomains 解析 hosts 内容，返回可用于 sing-box route domain 的域名。
func ParseHostsDomains(r io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(r)
	seen := make(map[string]bool)
	var domains []string
	for scanner.Scan() {
		line := stripHostsComment(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if _, err := netip.ParseAddr(fields[0]); err != nil {
			continue
		}
		for _, field := range fields[1:] {
			domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(field), "."))
			if domain == "" || seen[domain] || strings.ContainsAny(domain, " /") {
				continue
			}
			seen[domain] = true
			domains = append(domains, domain)
		}
	}
	return domains, scanner.Err()
}

// stripHostsComment 移除 hosts 行内注释。
func stripHostsComment(line string) string {
	if idx := strings.Index(line, "#"); idx >= 0 {
		return line[:idx]
	}
	return line
}

// BuildNoFakeIPFilterRule 构造系统探测域名的 FakeIP 排除规则。
func BuildNoFakeIPFilterRule() map[string]any {
	return map[string]any{
		"domain":         append([]string(nil), noFakeIPDomains...),
		"domain_keyword": append([]string(nil), noFakeIPDomainKeywords...),
		"domain_regex":   append([]string(nil), noFakeIPDomainRegex...),
		"domain_suffix":  append([]string(nil), noFakeIPDomainSuffixes...),
	}
}

// BuildProxyFakeIPDNSRule 构造代理规则集使用的 FakeIP DNS 规则。
func BuildProxyFakeIPDNSRule(proxyRuleSets []string) map[string]any {
	filter := BuildNoFakeIPFilterRule()
	filter["invert"] = true
	// 触发条件：系统探测、STUN、NTP 等域名命中代理规则集。
	// 不能只按代理规则集全量 FakeIP，否则设备联网检测可能误判。
	// 防止 Apple/Windows/Xbox 等系统服务拿到 FakeIP 后证书或连通性异常。
	return map[string]any{
		"type":        "logical",
		"mode":        "and",
		"server":      "fakeip",
		"rewrite_ttl": 1,
		"rules": []map[string]any{
			{"query_type": []int{1}},
			{"rule_set": append([]string(nil), proxyRuleSets...)},
			filter,
		},
	}
}

// BuildInbounds 根据入口模式生成 sing-box inbounds。
func BuildInbounds(cfg InboundConfig) []map[string]any {
	if cfg.Mode == "mixed" {
		inbound := map[string]any{
			"type":        "mixed",
			"tag":         "mixed-in",
			"listen":      cfg.Mixed.Listen,
			"listen_port": cfg.Mixed.Port,
		}
		if len(cfg.Mixed.Users) > 0 {
			users := make([]map[string]any, 0, len(cfg.Mixed.Users))
			for _, user := range cfg.Mixed.Users {
				users = append(users, map[string]any{
					"username": user.Username,
					"password": user.Password,
				})
			}
			inbound["users"] = users
		}
		return []map[string]any{inbound}
	}
	return []map[string]any{
		{
			"type":           "tun",
			"tag":            "tun-in",
			"interface_name": "sbox0",
			"address":        []string{"172.19.0.1/30"},
			"auto_route":     true,
			"auto_redirect":  true,
			"strict_route":   true,
			"stack":          "mixed",
		},
	}
}

// BuildRuleSets 构造本地 srs 规则集引用。
func (a *App) BuildRuleSets() []map[string]any {
	var sets []map[string]any
	for _, name := range geoIPNames {
		tag := "geoip-" + name
		sets = append(sets, map[string]any{
			"type":   "local",
			"tag":    tag,
			"format": "binary",
			"path":   filepath.Join(a.GeoDir, tag+".srs"),
		})
	}
	for _, name := range geoSiteNames {
		tag := "geosite-" + name
		sets = append(sets, map[string]any{
			"type":   "local",
			"tag":    tag,
			"format": "binary",
			"path":   filepath.Join(a.GeoDir, tag+".srs"),
		})
	}
	return sets
}

// BuildHY2Outbound 构造 sing-box hysteria2 outbound。
func BuildHY2Outbound(b HY2Backend) map[string]any {
	out := map[string]any{
		"type":        "hysteria2",
		"tag":         b.Tag,
		"server":      b.Server,
		"server_port": b.Port,
		"password":    b.Password,
		"tls": map[string]any{
			"enabled":  true,
			"insecure": b.Insecure,
		},
	}
	if b.SNI != "" {
		out["tls"].(map[string]any)["server_name"] = b.SNI
	}
	if b.ObfsPassword != "" {
		out["obfs"] = map[string]any{"type": "salamander", "password": b.ObfsPassword}
	}
	return out
}

// BuildVMessOutbound 构造 sing-box vmess outbound。
func BuildVMessOutbound(b VMessBackend) map[string]any {
	out := map[string]any{
		"type":        "vmess",
		"tag":         b.Tag,
		"server":      b.Server,
		"server_port": b.Port,
		"uuid":        b.UUID,
		"security":    firstNonEmpty(b.Security, "auto"),
		"alter_id":    b.AlterID,
	}
	if b.TLS {
		tls := map[string]any{"enabled": true, "insecure": b.Insecure}
		if b.SNI != "" {
			tls["server_name"] = b.SNI
		}
		out["tls"] = tls
	}
	if b.Transport == "ws" {
		transport := map[string]any{"type": "ws"}
		if b.Path != "" {
			transport["path"] = b.Path
		}
		if b.Host != "" {
			transport["headers"] = map[string]any{"Host": b.Host}
		}
		out["transport"] = transport
	}
	return out
}

// BuildSSOutbound 构造 sing-box shadowsocks outbound。
func BuildSSOutbound(b SSBackend) map[string]any {
	out := map[string]any{
		"type":        "shadowsocks",
		"tag":         b.Tag,
		"server":      b.Server,
		"server_port": b.Port,
		"method":      b.Method,
		"password":    b.Password,
	}
	if b.Plugin != "" {
		out["plugin"] = normalizeSSPlugin(b.Plugin)
	}
	if b.PluginOpts != "" {
		out["plugin_opts"] = normalizeSSPluginOpts(b.PluginOpts)
	}
	return out
}

// BuildTrojanOutbound 构造 sing-box trojan outbound。
func BuildTrojanOutbound(b TrojanBackend) map[string]any {
	out := map[string]any{
		"type":        "trojan",
		"tag":         b.Tag,
		"server":      b.Server,
		"server_port": b.Port,
		"password":    b.Password,
	}
	if b.TLS {
		tls := map[string]any{"enabled": true, "insecure": b.Insecure}
		if b.SNI != "" {
			tls["server_name"] = b.SNI
		}
		out["tls"] = tls
	}
	if b.Transport == "ws" {
		transport := map[string]any{"type": "ws"}
		if b.Path != "" {
			transport["path"] = b.Path
		}
		if b.Host != "" {
			transport["headers"] = map[string]any{"Host": b.Host}
		}
		out["transport"] = transport
	}
	return out
}

// BuildAnyTLSOutbound 构造 sing-box anytls outbound。
func BuildAnyTLSOutbound(b AnyTLSBackend) map[string]any {
	out := map[string]any{
		"type":        "anytls",
		"tag":         b.Tag,
		"server":      b.Server,
		"server_port": b.Port,
		"password":    b.Password,
		"tls": map[string]any{
			"enabled":  true,
			"insecure": b.Insecure,
		},
	}
	if b.SNI != "" {
		out["tls"].(map[string]any)["server_name"] = b.SNI
	}
	if b.IdleSessionCheckInterval != "" {
		out["idle_session_check_interval"] = b.IdleSessionCheckInterval
	}
	if b.IdleSessionTimeout != "" {
		out["idle_session_timeout"] = b.IdleSessionTimeout
	}
	if b.MinIdleSession > 0 {
		out["min_idle_session"] = b.MinIdleSession
	}
	return out
}

// BuildSocksOutbound 构造 sing-box socks outbound。
func BuildSocksOutbound(b SocksBackend) map[string]any {
	out := map[string]any{
		"type":        "socks",
		"tag":         b.Tag,
		"server":      b.Server,
		"server_port": b.Port,
		"version":     "5",
	}
	if strings.TrimSpace(b.Username) != "" {
		out["username"] = strings.TrimSpace(b.Username)
	}
	if strings.TrimSpace(b.Password) != "" {
		out["password"] = strings.TrimSpace(b.Password)
	}
	return out
}

// BuildHTTPOutbound 构造 sing-box http outbound。
func BuildHTTPOutbound(b HTTPBackend) map[string]any {
	out := map[string]any{
		"type":        "http",
		"tag":         b.Tag,
		"server":      b.Server,
		"server_port": b.Port,
	}
	if strings.TrimSpace(b.Username) != "" {
		out["username"] = strings.TrimSpace(b.Username)
	}
	if strings.TrimSpace(b.Password) != "" {
		out["password"] = strings.TrimSpace(b.Password)
	}
	return out
}

// BuildDynamicGroupOutbound 构造动态组 selector outbound。
func BuildDynamicGroupOutbound(b DynamicGroupBackend) map[string]any {
	out := map[string]any{
		"type":      "selector",
		"tag":       b.Tag,
		"outbounds": b.Members,
	}
	if best := firstNonEmpty(b.BestTag, firstString(b.Members)); best != "" {
		out["default"] = best
	}
	return out
}

// BuildCurrentSelector 构造全局当前出口 selector。
func BuildCurrentSelector(defaultOutbound string, candidates []string) map[string]any {
	out := map[string]any{
		"type":      "selector",
		"tag":       defaultCurrentSelector,
		"outbounds": append([]string(nil), candidates...),
	}
	if containsString(candidates, defaultOutbound) {
		out["default"] = defaultOutbound
	}
	return out
}

// BuildDynamicOutboundSelector 构造单条动态出口规则的热切 selector。
func BuildDynamicOutboundSelector(rule DynamicOutboundRule, candidates []string) map[string]any {
	out := map[string]any{
		"type":      "selector",
		"tag":       DynamicOutboundSelectorTag(rule),
		"outbounds": append([]string(nil), candidates...),
	}
	if outbound := SanitizeTag(rule.Outbound); containsString(candidates, outbound) {
		out["default"] = outbound
	}
	return out
}

// DynamicOutboundSelectorTag 生成动态出口规则的稳定 selector tag。
func DynamicOutboundSelectorTag(rule DynamicOutboundRule) string {
	match := strings.ToLower(strings.TrimSpace(rule.Match))
	sum := sha256.Sum256([]byte(match))
	return "dynout-" + fmt.Sprintf("%x", sum[:])[:16]
}

// BuildRouteRule 将一行本地规则转成 sing-box 路由规则。
func BuildRouteRule(rule LocalRule, outbound string) map[string]any {
	m := map[string]any{"action": "route", "outbound": outbound}
	switch rule.Kind {
	case "domain":
		domain := strings.TrimPrefix(strings.TrimSpace(rule.Value), ".")
		m["domain"] = []string{domain}
		m["domain_suffix"] = []string{"." + domain}
	case "src":
		m["source_ip_cidr"] = []string{NormalizeCIDR(rule.Value)}
	case "dst":
		m["ip_cidr"] = []string{NormalizeCIDR(rule.Value)}
	}
	return m
}

// BuildTailscaleDirectRouteRules 构造 Tailscale 直连规则。
func BuildTailscaleDirectRouteRules() []map[string]any {
	// 触发条件：TUN 透明代理接管默认公网流量。
	// 不能让 Tailscale 控制面和 tailnet 地址走代理。
	// 防止 DERP、STUN、MagicDNS 或 peer 访问被代理链路破坏。
	return []map[string]any{
		{
			"action":        "route",
			"outbound":      "direct",
			"domain_suffix": prefixDomainSuffixes(tailscaleDirectDomainSuffixes),
		},
		{
			"action":   "route",
			"outbound": "direct",
			"ip_cidr":  append([]string(nil), tailscaleDirectIPCIDRs...),
		},
		{
			"action":      "route",
			"outbound":    "direct",
			"network":     "udp",
			"source_port": []int{tailscaleWireGuardPort},
		},
		{
			"action":   "route",
			"outbound": "direct",
			"network":  "udp",
			"port":     []int{tailscaleWireGuardPort},
		},
		{
			"action":   "route",
			"outbound": "direct",
			"network":  "udp",
			"port":     []int{tailscaleSTUNPort},
		},
	}
}

// prefixDomainSuffixes 生成 sing-box 使用的点号后缀。
func prefixDomainSuffixes(suffixes []string) []string {
	result := make([]string, 0, len(suffixes))
	for _, suffix := range suffixes {
		clean := strings.TrimPrefix(strings.TrimSpace(suffix), ".")
		if clean == "" {
			continue
		}
		result = append(result, "."+clean)
	}
	return result
}

// BuildDynamicOutboundRouteRule 将动态出口规则转成 selector 路由规则。
func BuildDynamicOutboundRouteRule(rule DynamicOutboundRule) (map[string]any, error) {
	match := strings.TrimSpace(rule.Match)
	outbound := SanitizeTag(rule.Outbound)
	if match == "" || outbound == "" {
		return nil, errors.New("动态出口规则缺少匹配条件或出口")
	}
	m := map[string]any{"action": "route", "outbound": DynamicOutboundSelectorTag(rule)}
	if err := applyRouteMatch(m, match, "动态出口"); err != nil {
		return nil, err
	}
	return m, nil
}

// BuildOverrideRouteRule 将静态跳转规则转成 sing-box 目标改写路由规则。
func BuildOverrideRouteRule(rule OverrideRule) (map[string]any, error) {
	match := strings.TrimSpace(rule.Match)
	address := strings.TrimSpace(rule.Address)
	outbound := SanitizeTag(firstNonEmpty(rule.Outbound, "direct"))
	if match == "" || address == "" || rule.Port <= 0 {
		return nil, errors.New("静态跳转规则缺少匹配条件、目标地址或端口")
	}
	if rule.Port > 65535 {
		return nil, fmt.Errorf("静态跳转端口超出范围: %d", rule.Port)
	}
	if outbound != "direct" {
		// 触发条件：用户手写配置把静态跳转指向代理 backend。
		// 不能允许保存后静默失败，因为 sing-box 目标改写只适合 direct 路径。
		// 防止 UI 显示已生效但实际仍走原目标或代理链路。
		return nil, fmt.Errorf("静态跳转 outbound 只支持 direct: %s", outbound)
	}
	if strings.ContainsAny(address, " \t/") {
		return nil, fmt.Errorf("静态跳转地址格式错误: %s", address)
	}
	m := map[string]any{
		"action":           "route",
		"outbound":         "direct",
		"override_address": address,
		"override_port":    rule.Port,
	}
	if err := applyRouteMatch(m, match, "静态跳转"); err != nil {
		return nil, err
	}
	return m, nil
}

// applyRouteMatch 将域名或 IP/CIDR 匹配条件写入 sing-box 路由规则。
func applyRouteMatch(m map[string]any, match string, label string) error {
	match = strings.TrimSpace(match)
	if strings.HasPrefix(strings.ToLower(match), "domain:") {
		domain := strings.TrimPrefix(strings.TrimSpace(match[len("domain:"):]), ".")
		if domain == "" {
			return fmt.Errorf("%s域名为空: %s", label, match)
		}
		m["domain"] = []string{domain}
		m["domain_suffix"] = []string{"." + domain}
		return nil
	}
	if looksLikeIPOrCIDR(match) {
		m["ip_cidr"] = []string{NormalizeCIDR(match)}
		return nil
	}
	if strings.ContainsAny(match, " \t/") {
		return fmt.Errorf("%s只支持域名或 IP/CIDR: %s", label, match)
	}
	domain := strings.TrimPrefix(match, ".")
	if domain == "" {
		return fmt.Errorf("%s域名为空: %s", label, match)
	}
	m["domain"] = []string{domain}
	m["domain_suffix"] = []string{"." + domain}
	return nil
}

// looksLikeIPOrCIDR 判断文本是否为 IP 或 CIDR。
func looksLikeIPOrCIDR(value string) bool {
	value = strings.TrimSpace(value)
	if ip := net.ParseIP(value); ip != nil {
		return true
	}
	_, _, err := net.ParseCIDR(value)
	return err == nil
}

// ParseConfigYAML 解析约定子集 YAML，避免在路由器引入三方依赖。
func ParseConfigYAML(data []byte) (Config, error) {
	cfg := DefaultConfig()
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, err
	}
	MergeConfigDefaults(&cfg)
	return cfg, nil
}

// MergeConfigDefaults 补齐 YAML 未显式配置的默认值。
func MergeConfigDefaults(cfg *Config) {
	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}
	if cfg.Log.Dir == "" {
		cfg.Log.Dir = defaultLogDir
	}
	if cfg.Log.MaxSizeMB == 0 {
		cfg.Log.MaxSizeMB = 5
	}
	if cfg.Log.MaxFiles == 0 {
		cfg.Log.MaxFiles = 5
	}
	if cfg.Update.DNS == "" {
		cfg.Update.DNS = defaultUpdateDNS
	}
	if cfg.GeoFiles.ProxyRuleSets == nil {
		cfg.GeoFiles.ProxyRuleSets = append([]string(nil), defaultProxyRuleSets...)
	}
	if cfg.GeoFiles.HostsOverride == nil {
		cfg.GeoFiles.HostsOverride = boolPtr(true)
	}
	cfg.GeoFiles.ProxyRuleSets = NormalizeProxyRuleSets(cfg.GeoFiles.ProxyRuleSets)
	if !cfg.Update.GeoFilesUseProxy {
		// 触发条件：旧配置没有该字段时 Go bool 为 false。
		// 不能直接保持 false，因为 geofiles 默认要求借助已有代理更新。
		// 防止升级旧配置后规则更新又退回直连 GitHub raw。
		cfg.Update.GeoFilesUseProxy = true
	}
	if cfg.Inbound.Mode == "" {
		cfg.Inbound.Mode = "tun"
	}
	if cfg.Inbound.Mixed.Listen == "" {
		cfg.Inbound.Mixed.Listen = defaultMixedListen
	}
	if cfg.Inbound.Mixed.Port == 0 {
		cfg.Inbound.Mixed.Port = defaultMixedPort
	}
	if cfg.Web.Listen == "" {
		cfg.Web.Listen = defaultWebListen
	}
	if cfg.Web.Port == 0 {
		cfg.Web.Port = defaultWebPort
	}
	if cfg.Web.TokenTTL == "" {
		cfg.Web.TokenTTL = defaultWebTokenTTL
	}
	if cfg.Web.Lock.MaxAttempts == 0 {
		cfg.Web.Lock.MaxAttempts = defaultWebLockAttempts
	}
	if cfg.Web.Lock.Duration == "" {
		cfg.Web.Lock.Duration = defaultWebLockDuration
	}
	seenStatic := map[string]int{}
	for i := range cfg.Backend.Static {
		NormalizeBackendIdentity(&cfg.Backend.Static[i])
		cfg.Backend.Static[i].Key = UniqueScopedKey(cfg.Backend.Static[i].Key, seenStatic, fmt.Sprintf("static-%d", i+1))
	}
	seenSubscriptions := map[string]int{}
	for i := range cfg.Backend.Subscription {
		key := SanitizeTag(firstNonEmpty(cfg.Backend.Subscription[i].Key, cfg.Backend.Subscription[i].Name))
		cfg.Backend.Subscription[i].Key = UniqueScopedKey(key, seenSubscriptions, fmt.Sprintf("sub-%d", i+1))
		if cfg.Backend.Subscription[i].Name == "" {
			cfg.Backend.Subscription[i].Name = cfg.Backend.Subscription[i].Key
		}
		if cfg.Backend.Subscription[i].UserAgent == "" {
			cfg.Backend.Subscription[i].UserAgent = defaultSubscriptionUA
		}
	}
	seenImports := map[string]int{}
	for i := range cfg.Backend.Imports {
		key := SanitizeTag(firstNonEmpty(cfg.Backend.Imports[i].Key, cfg.Backend.Imports[i].Name))
		cfg.Backend.Imports[i].Key = UniqueScopedKey(key, seenImports, fmt.Sprintf("import-%d", i+1))
		if cfg.Backend.Imports[i].Name == "" {
			cfg.Backend.Imports[i].Name = cfg.Backend.Imports[i].Key
		}
		cfg.Backend.Imports[i].Source = normalizeImportSource(cfg.Backend.Imports[i].Source)
	}
	cfg.Backend.Groups = NormalizeDynamicGroups(cfg.Backend.Groups, nil)
}

// ParseLocalRulesFile 解析一行一条的强制规则文件。
func ParseLocalRulesFile(path string) ([]LocalRule, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	return ParseLocalRules(f)
}

// ParseLocalRules 从 reader 解析一行一条的规则。
func ParseLocalRules(r io.Reader) ([]LocalRule, error) {
	scanner := bufio.NewScanner(r)
	var rules []LocalRule
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := stripInlineRuleComment(scanner.Text())
		if strings.TrimSpace(line) == "" {
			continue
		}
		key, value, ok := splitKeyValue(strings.TrimSpace(line))
		if !ok {
			return nil, fmt.Errorf("规则第 %d 行格式错误", lineNo)
		}
		key = strings.ToLower(key)
		if key != "domain" && key != "src" && key != "dst" {
			return nil, fmt.Errorf("规则第 %d 行未知类型: %s", lineNo, key)
		}
		rules = append(rules, LocalRule{Kind: key, Value: cleanValue(value), Line: lineNo})
	}
	return rules, scanner.Err()
}

// FetchSubscription 下载并解析订阅，只保留 HY2、VMess、SS、Trojan、AnyTLS、SOCKS5 和 HTTP。
func FetchSubscription(client *http.Client, sub Subscription) ([]ProxyBackend, int, int, error) {
	req, err := http.NewRequest(http.MethodGet, sub.URL, nil)
	if err != nil {
		return nil, 0, 0, err
	}
	req.Header.Set("User-Agent", firstNonEmpty(sub.UserAgent, defaultSubscriptionUA))
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, 0, 0, fmt.Errorf("订阅 HTTP 状态异常: %s", resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, 0, err
	}
	text := DecodeSubscriptionText(data)
	lines := strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' })
	var nodes []ProxyBackend
	skipped := 0
	failed := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "hy2://") || strings.HasPrefix(line, "hysteria2://") {
			node, err := ParseHY2URI(line)
			if err != nil {
				failed++
				continue
			}
			nodes = append(nodes, node)
			continue
		}
		if strings.HasPrefix(line, "vmess://") {
			node, err := ParseVMessURI(line)
			if err != nil {
				failed++
				continue
			}
			nodes = append(nodes, node)
			continue
		}
		if strings.HasPrefix(line, "ss://") {
			node, err := ParseSSURI(line)
			if err != nil {
				failed++
				continue
			}
			nodes = append(nodes, node)
			continue
		}
		if strings.HasPrefix(line, "trojan://") {
			node, err := ParseTrojanURI(line)
			if err != nil {
				failed++
				continue
			}
			nodes = append(nodes, node)
			continue
		}
		if strings.HasPrefix(line, "anytls://") {
			node, err := ParseAnyTLSURI(line)
			if err != nil {
				failed++
				continue
			}
			nodes = append(nodes, node)
			continue
		}
		if strings.HasPrefix(line, "socks5://") || strings.HasPrefix(line, "socks://") {
			node, err := ParseSocksURI(line)
			if err != nil {
				failed++
				continue
			}
			nodes = append(nodes, node)
			continue
		}
		if strings.HasPrefix(line, "http://") {
			node, err := ParseHTTPProxyURI(line)
			if err != nil {
				failed++
				continue
			}
			nodes = append(nodes, node)
			continue
		}
		if strings.Contains(line, "://") {
			skipped++
			continue
		}
		skipped++
	}
	SortBackendsByProtocol(nodes)
	return nodes, skipped, failed, nil
}

// ImportNodeGroup 保存一次手动导入，key 相同会替换配置和缓存。
func (a *App) ImportNodeGroup(req WebImportRequest) (WebImportResponse, error) {
	key := SanitizeTag(firstNonEmpty(req.Key, req.Name))
	if key == "" {
		return WebImportResponse{}, errors.New("导入分组 key 不能为空")
	}
	source := normalizeImportSource(req.Source)
	if source == "" {
		return WebImportResponse{}, fmt.Errorf("导入 source 不支持: %s", req.Source)
	}
	if strings.TrimSpace(req.Content) == "" {
		return WebImportResponse{}, errors.New("导入内容不能为空")
	}
	nodes, skipped, failed, err := ParseImportedNodes(source, []byte(req.Content))
	if err != nil {
		return WebImportResponse{}, err
	}
	if len(nodes) == 0 {
		return WebImportResponse{}, fmt.Errorf("导入内容没有可用节点，skipped=%d failed=%d", skipped, failed)
	}
	MakeUniqueBackendKeys(nodes)
	if _, err := a.SaveSubscriptionCache(key, nodes); err != nil {
		return WebImportResponse{}, err
	}
	cfg, err := a.LoadConfig()
	if err != nil {
		return WebImportResponse{}, err
	}
	nextGroup := ImportedNodeGroup{
		Key:    key,
		Name:   firstNonEmpty(strings.TrimSpace(req.Name), key),
		Source: source,
	}
	if index := findImportedGroupIndex(cfg.Backend.Imports, key); index >= 0 {
		cfg.Backend.Imports[index] = nextGroup
	} else {
		cfg.Backend.Imports = append(cfg.Backend.Imports, nextGroup)
	}
	if cfg.Policy.Default == "" && len(nodes) > 0 {
		cfg.Policy.Default = RuntimeBackendTag("import-"+key, nodes[0].BackendKey())
	}
	if err := SaveConfig(a.ConfigPath, cfg); err != nil {
		return WebImportResponse{}, err
	}
	return WebImportResponse{Imported: len(nodes), Skipped: skipped, Failed: failed}, nil
}

// ParseImportedNodes 按来源格式解析手动导入节点。
func ParseImportedNodes(source string, data []byte) ([]ProxyBackend, int, int, error) {
	switch normalizeImportSource(source) {
	case "clash":
		return ParseClashProxyNodes(data)
	default:
		return nil, 0, 0, fmt.Errorf("导入 source 不支持: %s", source)
	}
}

// ParseClashProxyNodes 解析 Clash YAML proxies 字段并按端点去重。
func ParseClashProxyNodes(data []byte) ([]ProxyBackend, int, int, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, 0, 0, err
	}
	proxies := clashProxySequenceNode(&root)
	if proxies == nil {
		return nil, 0, 0, errors.New("Clash 配置缺少 proxies")
	}
	skipped := 0
	failed := 0
	backendByEndpoint := map[string]ProxyBackend{}
	indexByEndpoint := map[string]int{}
	order := make([]string, 0, len(proxies.Content))
	for index, item := range proxies.Content {
		values := yamlMappingValues(item)
		if len(values) == 0 {
			failed++
			continue
		}
		node, ok, err := clashProxyBackend(values)
		if err != nil {
			failed++
			continue
		}
		if !ok {
			skipped++
			continue
		}
		endpoint := clashProxyEndpointKey(node)
		if endpoint == "" {
			failed++
			continue
		}
		if _, exists := backendByEndpoint[endpoint]; !exists {
			order = append(order, endpoint)
		}
		backendByEndpoint[endpoint] = node
		indexByEndpoint[endpoint] = index
	}
	nodes := make([]ProxyBackend, 0, len(backendByEndpoint))
	sort.SliceStable(order, func(i, j int) bool {
		return indexByEndpoint[order[i]] < indexByEndpoint[order[j]]
	})
	for _, endpoint := range order {
		nodes = append(nodes, backendByEndpoint[endpoint])
	}
	MakeUniqueBackendKeys(nodes)
	return nodes, skipped, failed, nil
}

// clashProxySequenceNode 返回 Clash 根对象中的 proxies sequence。
func clashProxySequenceNode(root *yaml.Node) *yaml.Node {
	node := root
	if node != nil && node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		node = node.Content[0]
	}
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == "proxies" && node.Content[i+1].Kind == yaml.SequenceNode {
			return node.Content[i+1]
		}
	}
	return nil
}

// yamlMappingValues 将 YAML mapping 转成按 key 读取的节点表。
func yamlMappingValues(node *yaml.Node) map[string]*yaml.Node {
	result := map[string]*yaml.Node{}
	if node == nil || node.Kind != yaml.MappingNode {
		return result
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := strings.ToLower(strings.TrimSpace(node.Content[i].Value))
		if key == "" {
			continue
		}
		result[key] = node.Content[i+1]
	}
	return result
}

// clashProxyBackend 将一个 Clash proxy mapping 转成内部节点。
func clashProxyBackend(values map[string]*yaml.Node) (ProxyBackend, bool, error) {
	protocol := strings.ToLower(strings.TrimSpace(yamlString(values["type"])))
	server := strings.TrimSpace(yamlString(values["server"]))
	port := yamlInt(values["port"])
	if protocol == "" || server == "" || port <= 0 || port > 65535 {
		return nil, false, fmt.Errorf("Clash proxy 缺少 type/server/port")
	}
	name := strings.TrimSpace(yamlString(values["name"]))
	key := SanitizeTag(firstNonEmpty(name, server))
	switch protocol {
	case "hysteria2", "hy2":
		password := strings.TrimSpace(yamlString(values["password"]))
		if password == "" {
			return nil, false, fmt.Errorf("HY2 proxy 缺少 password")
		}
		return &HY2Backend{
			Key:          key,
			Name:         firstNonEmpty(name, key),
			Server:       server,
			Port:         port,
			Password:     password,
			SNI:          firstNonEmpty(yamlString(values["sni"]), yamlString(values["peer"])),
			Insecure:     yamlBool(values["skip-cert-verify"]) || yamlBool(values["insecure"]),
			ObfsPassword: firstNonEmpty(yamlString(values["obfs-password"]), yamlString(values["obfs_password"])),
		}, true, nil
	case "vmess":
		uuid := strings.TrimSpace(firstNonEmpty(yamlString(values["uuid"]), yamlString(values["id"])))
		if uuid == "" {
			return nil, false, fmt.Errorf("VMess proxy 缺少 uuid")
		}
		return &VMessBackend{
			Key:       key,
			Name:      firstNonEmpty(name, key),
			Server:    server,
			Port:      port,
			UUID:      uuid,
			Security:  firstNonEmpty(yamlString(values["cipher"]), yamlString(values["security"]), "auto"),
			AlterID:   yamlInt(values["alterid"]),
			SNI:       firstNonEmpty(yamlString(values["servername"]), yamlString(values["sni"])),
			TLS:       yamlBool(values["tls"]),
			Insecure:  yamlBool(values["skip-cert-verify"]) || yamlBool(values["insecure"]),
			Transport: strings.ToLower(strings.TrimSpace(firstNonEmpty(yamlString(values["network"]), yamlString(values["type"])))),
			Path:      firstNonEmpty(yamlString(values["ws-path"]), yamlString(values["path"])),
			Host:      firstNonEmpty(yamlNestedString(values["ws-headers"], "host"), yamlString(values["host"])),
		}, true, nil
	case "ss", "shadowsocks":
		method := strings.TrimSpace(firstNonEmpty(yamlString(values["cipher"]), yamlString(values["method"])))
		password := strings.TrimSpace(yamlString(values["password"]))
		if method == "" || password == "" {
			return nil, false, fmt.Errorf("SS proxy 缺少 cipher 或 password")
		}
		return &SSBackend{
			Key:        key,
			Name:       firstNonEmpty(name, key),
			Server:     server,
			Port:       port,
			Method:     method,
			Password:   password,
			Plugin:     normalizeSSPlugin(yamlString(values["plugin"])),
			PluginOpts: normalizeSSPluginOpts(yamlString(values["plugin-opts"])),
		}, true, nil
	case "trojan":
		password := strings.TrimSpace(yamlString(values["password"]))
		if password == "" {
			return nil, false, fmt.Errorf("Trojan proxy 缺少 password")
		}
		return &TrojanBackend{
			Key:       key,
			Name:      firstNonEmpty(name, key),
			Server:    server,
			Port:      port,
			Password:  password,
			SNI:       firstNonEmpty(yamlString(values["sni"]), yamlString(values["servername"])),
			TLS:       true,
			Insecure:  yamlBool(values["skip-cert-verify"]) || yamlBool(values["insecure"]),
			Transport: strings.ToLower(strings.TrimSpace(firstNonEmpty(yamlString(values["network"]), yamlString(values["type"])))),
			Path:      firstNonEmpty(yamlString(values["ws-path"]), yamlString(values["path"])),
			Host:      firstNonEmpty(yamlNestedString(values["ws-headers"], "host"), yamlString(values["host"])),
		}, true, nil
	case "anytls":
		password := strings.TrimSpace(yamlString(values["password"]))
		if password == "" {
			return nil, false, fmt.Errorf("AnyTLS proxy 缺少 password")
		}
		return &AnyTLSBackend{
			Key:                      key,
			Name:                     firstNonEmpty(name, key),
			Server:                   server,
			Port:                     port,
			Password:                 password,
			SNI:                      firstNonEmpty(yamlString(values["sni"]), yamlString(values["servername"])),
			Insecure:                 yamlBool(values["skip-cert-verify"]) || yamlBool(values["insecure"]),
			IdleSessionCheckInterval: yamlDurationString(values["idle-session-check-interval"]),
			IdleSessionTimeout:       yamlDurationString(values["idle-session-timeout"]),
			MinIdleSession:           yamlInt(values["min-idle-session"]),
		}, true, nil
	default:
		return nil, false, nil
	}
}

// clashProxyEndpointKey 生成 type+port+server 去重键。
func clashProxyEndpointKey(node ProxyBackend) string {
	if node == nil || node.BackendServer() == "" || node.BackendPort() == 0 {
		return ""
	}
	return strings.ToLower(node.BackendProtocol()) + "\x00" + strings.ToLower(node.BackendServer()) + "\x00" + strconv.Itoa(node.BackendPort())
}

// yamlString 读取 YAML 标量字符串。
func yamlString(node *yaml.Node) string {
	if node == nil {
		return ""
	}
	if node.Kind == yaml.MappingNode {
		return yamlStringFromMapping(node)
	}
	if node.Kind == yaml.SequenceNode {
		values := make([]string, 0, len(node.Content))
		for _, item := range node.Content {
			if value := yamlString(item); value != "" {
				values = append(values, value)
			}
		}
		return strings.Join(values, ",")
	}
	return strings.TrimSpace(node.Value)
}

// yamlStringFromMapping 将小型 YAML mapping 转成分号参数字符串。
func yamlStringFromMapping(node *yaml.Node) string {
	values := make([]string, 0, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := strings.TrimSpace(node.Content[i].Value)
		value := yamlString(node.Content[i+1])
		if key == "" || value == "" {
			continue
		}
		values = append(values, key+"="+value)
	}
	return strings.Join(values, ";")
}

// yamlNestedString 读取 YAML mapping 中的子字段。
func yamlNestedString(node *yaml.Node, key string) string {
	if node == nil || node.Kind != yaml.MappingNode {
		return ""
	}
	want := strings.ToLower(strings.TrimSpace(key))
	for i := 0; i+1 < len(node.Content); i += 2 {
		if strings.ToLower(strings.TrimSpace(node.Content[i].Value)) == want {
			return yamlString(node.Content[i+1])
		}
	}
	return ""
}

// yamlBool 读取 YAML 布尔值，兼容字符串 true/false。
func yamlBool(node *yaml.Node) bool {
	value := strings.ToLower(strings.TrimSpace(yamlString(node)))
	return value == "true" || value == "1" || value == "yes" || value == "on"
}

// yamlInt 读取 YAML 整数值，非法时返回 0。
func yamlInt(node *yaml.Node) int {
	value := strings.TrimSpace(yamlString(node))
	if value == "" {
		return 0
	}
	number, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return number
}

// yamlDurationString 读取 Clash 数字秒字段并转成 sing-box duration。
func yamlDurationString(node *yaml.Node) string {
	value := strings.TrimSpace(yamlString(node))
	if value == "" {
		return ""
	}
	if _, err := strconv.Atoi(value); err == nil {
		return value + "s"
	}
	return value
}

// DecodeSubscriptionText 识别 plain 和 base64 两类订阅正文。
func DecodeSubscriptionText(data []byte) string {
	raw := strings.TrimSpace(string(data))
	compact := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, raw)
	if decoded, err := base64.StdEncoding.DecodeString(padBase64(compact)); err == nil && looksLikeSubscription(decoded) {
		return string(decoded)
	}
	if decoded, err := base64.URLEncoding.DecodeString(padBase64(compact)); err == nil && looksLikeSubscription(decoded) {
		return string(decoded)
	}
	return raw
}

// ParseHY2URI 解析 hy2 分享链接。
func ParseHY2URI(raw string) (*HY2Backend, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "hy2" && u.Scheme != "hysteria2" {
		return nil, fmt.Errorf("不是 hy2 协议")
	}
	password := ""
	if u.User != nil {
		password, _ = u.User.Password()
		if password == "" {
			password = u.User.Username()
		}
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, fmt.Errorf("端口无效")
	}
	q := u.Query()
	insecure := parseBool(q.Get("insecure"))
	name, _ := url.QueryUnescape(u.Fragment)
	tag := SanitizeTag(name)
	if tag == "" {
		tag = SanitizeTag(u.Hostname())
	}
	return &HY2Backend{
		Key:          tag,
		Name:         firstNonEmpty(strings.TrimSpace(name), tag),
		Server:       u.Hostname(),
		Port:         port,
		Password:     password,
		SNI:          firstNonEmpty(q.Get("sni"), q.Get("peer")),
		Insecure:     insecure,
		ObfsPassword: firstNonEmpty(q.Get("obfs-password"), q.Get("obfs_password")),
	}, nil
}

// vmessShare 表示 v2rayN 常见 VMess 分享 JSON。
type vmessShare struct {
	// PS 是节点别名。
	PS string `json:"ps"`
	// Add 是服务端地址。
	Add string `json:"add"`
	// Port 是服务端端口。
	Port string `json:"port"`
	// ID 是用户 UUID。
	ID string `json:"id"`
	// Aid 是 alterId。
	Aid string `json:"aid"`
	// Scy 是加密方式。
	Scy string `json:"scy"`
	// Net 是传输层类型。
	Net string `json:"net"`
	// Host 是传输层 Host 头。
	Host string `json:"host"`
	// Path 是传输层路径。
	Path string `json:"path"`
	// TLS 是 TLS 标记。
	TLS string `json:"tls"`
	// SNI 是 TLS SNI。
	SNI string `json:"sni"`
}

// ParseVMessURI 解析 v2rayN base64 JSON 形式的 VMess 分享链接。
func ParseVMessURI(raw string) (*VMessBackend, error) {
	payload := strings.TrimPrefix(strings.TrimSpace(raw), "vmess://")
	decoded, err := base64.StdEncoding.DecodeString(padBase64(payload))
	if err != nil {
		if decoded, err = base64.URLEncoding.DecodeString(padBase64(payload)); err != nil {
			return nil, err
		}
	}
	var share vmessShare
	if err := json.Unmarshal(decoded, &share); err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(strings.TrimSpace(share.Port))
	if err != nil {
		return nil, fmt.Errorf("端口无效")
	}
	alterID, _ := strconv.Atoi(strings.TrimSpace(share.Aid))
	name := strings.TrimSpace(share.PS)
	tag := SanitizeTag(firstNonEmpty(name, share.Add))
	return &VMessBackend{
		Key:       tag,
		Name:      firstNonEmpty(name, tag),
		Server:    strings.TrimSpace(share.Add),
		Port:      port,
		UUID:      strings.TrimSpace(share.ID),
		Security:  firstNonEmpty(strings.TrimSpace(share.Scy), "auto"),
		AlterID:   alterID,
		SNI:       strings.TrimSpace(share.SNI),
		TLS:       strings.EqualFold(strings.TrimSpace(share.TLS), "tls"),
		Transport: strings.ToLower(strings.TrimSpace(share.Net)),
		Path:      strings.TrimSpace(share.Path),
		Host:      strings.TrimSpace(share.Host),
	}, nil
}

// ParseSSURI 解析 Shadowsocks SIP002 和旧式 base64 分享链接。
func ParseSSURI(raw string) (*SSBackend, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "ss://") {
		return nil, fmt.Errorf("不是 ss 协议")
	}
	if node, err := parseSIP002SSURI(raw); err == nil {
		return node, nil
	}
	return parseLegacySSURI(raw)
}

// parseSIP002SSURI 解析 ss://base64(method:password)@host:port 形式。
func parseSIP002SSURI(raw string) (*SSBackend, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "ss" || u.User == nil || u.Hostname() == "" {
		return nil, fmt.Errorf("不是 SIP002 ss 链接")
	}
	userInfo := u.User.Username()
	if pass, ok := u.User.Password(); ok {
		userInfo += ":" + pass
	}
	method, password, err := decodeSSUserInfo(userInfo)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, fmt.Errorf("端口无效")
	}
	name, _ := url.QueryUnescape(u.Fragment)
	tag := SanitizeTag(firstNonEmpty(strings.TrimSpace(name), u.Hostname()))
	plugin, pluginOpts := parseSSPlugin(u.Query().Get("plugin"))
	return &SSBackend{
		Key:        tag,
		Name:       firstNonEmpty(strings.TrimSpace(name), tag),
		Server:     u.Hostname(),
		Port:       port,
		Method:     method,
		Password:   password,
		Plugin:     plugin,
		PluginOpts: pluginOpts,
	}, nil
}

// parseLegacySSURI 解析 ss://base64(method:password@host:port) 形式。
func parseLegacySSURI(raw string) (*SSBackend, error) {
	body := strings.TrimPrefix(raw, "ss://")
	fragment := ""
	if index := strings.Index(body, "#"); index >= 0 {
		fragment, _ = url.QueryUnescape(body[index+1:])
		body = body[:index]
	}
	decoded, err := decodeBase64String(body)
	if err != nil {
		return nil, err
	}
	at := strings.LastIndex(decoded, "@")
	if at < 0 {
		return nil, fmt.Errorf("ss 链接缺少服务端")
	}
	method, password, err := splitSSCredential(decoded[:at])
	if err != nil {
		return nil, err
	}
	host, portText, err := net.SplitHostPort(decoded[at+1:])
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, fmt.Errorf("端口无效")
	}
	tag := SanitizeTag(firstNonEmpty(strings.TrimSpace(fragment), host))
	return &SSBackend{
		Key:      tag,
		Name:     firstNonEmpty(strings.TrimSpace(fragment), tag),
		Server:   strings.Trim(host, "[]"),
		Port:     port,
		Method:   method,
		Password: password,
	}, nil
}

// ParseTrojanURI 解析 Trojan 分享链接。
func ParseTrojanURI(raw string) (*TrojanBackend, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	if u.Scheme != "trojan" {
		return nil, fmt.Errorf("不是 trojan 协议")
	}
	if u.User == nil || u.Hostname() == "" {
		return nil, fmt.Errorf("trojan 链接缺少认证或服务端")
	}
	password := u.User.Username()
	if pass, ok := u.User.Password(); ok && pass != "" {
		password = pass
	}
	if password == "" {
		return nil, fmt.Errorf("trojan 密码为空")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, fmt.Errorf("端口无效")
	}
	q := u.Query()
	name, _ := url.QueryUnescape(u.Fragment)
	tag := SanitizeTag(firstNonEmpty(strings.TrimSpace(name), u.Hostname()))
	security := strings.ToLower(strings.TrimSpace(q.Get("security")))
	tlsEnabled := security != "none"
	transport := strings.ToLower(strings.TrimSpace(firstNonEmpty(q.Get("type"), q.Get("transport"))))
	return &TrojanBackend{
		Key:       tag,
		Name:      firstNonEmpty(strings.TrimSpace(name), tag),
		Server:    u.Hostname(),
		Port:      port,
		Password:  password,
		SNI:       firstNonEmpty(q.Get("sni"), q.Get("peer")),
		TLS:       tlsEnabled,
		Insecure:  parseBool(firstNonEmpty(q.Get("allowInsecure"), q.Get("insecure"), q.Get("skip-cert-verify"))),
		Transport: transport,
		Path:      strings.TrimSpace(q.Get("path")),
		Host:      strings.TrimSpace(q.Get("host")),
	}, nil
}

// ParseAnyTLSURI 解析 AnyTLS 分享链接。
func ParseAnyTLSURI(raw string) (*AnyTLSBackend, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	if u.Scheme != "anytls" {
		return nil, fmt.Errorf("不是 anytls 协议")
	}
	if u.User == nil || u.Hostname() == "" {
		return nil, fmt.Errorf("anytls 链接缺少认证或服务端")
	}
	password := u.User.Username()
	if pass, ok := u.User.Password(); ok && pass != "" {
		password = pass
	}
	if password == "" {
		return nil, fmt.Errorf("anytls 密码为空")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, fmt.Errorf("端口无效")
	}
	q := u.Query()
	name, _ := url.QueryUnescape(u.Fragment)
	tag := SanitizeTag(firstNonEmpty(strings.TrimSpace(name), u.Hostname()))
	return &AnyTLSBackend{
		Key:                      tag,
		Name:                     firstNonEmpty(strings.TrimSpace(name), tag),
		Server:                   u.Hostname(),
		Port:                     port,
		Password:                 password,
		SNI:                      firstNonEmpty(q.Get("sni"), q.Get("peer"), q.Get("server_name"), q.Get("servername")),
		Insecure:                 parseBool(firstNonEmpty(q.Get("allowInsecure"), q.Get("insecure"), q.Get("skip-cert-verify"))),
		IdleSessionCheckInterval: firstNonEmpty(q.Get("idle_session_check_interval"), q.Get("idle-session-check-interval")),
		IdleSessionTimeout:       firstNonEmpty(q.Get("idle_session_timeout"), q.Get("idle-session-timeout")),
		MinIdleSession:           parseIntDefault(firstNonEmpty(q.Get("min_idle_session"), q.Get("min-idle-session")), 0),
	}, nil
}

// ParseSocksURI 解析 socks5 分享链接。
func ParseSocksURI(raw string) (*SocksBackend, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	if u.Scheme != "socks5" && u.Scheme != "socks" {
		return nil, fmt.Errorf("不是 socks5 协议")
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("socks5 链接缺少服务端")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, fmt.Errorf("端口无效")
	}
	username := ""
	password := ""
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
	}
	name, _ := url.QueryUnescape(u.Fragment)
	tag := SanitizeTag(firstNonEmpty(strings.TrimSpace(name), username, u.Hostname()))
	return &SocksBackend{
		Key:      tag,
		Name:     firstNonEmpty(strings.TrimSpace(name), tag),
		Server:   u.Hostname(),
		Port:     port,
		Username: username,
		Password: password,
	}, nil
}

// ParseHTTPProxyURI 解析 http 代理分享链接。
func ParseHTTPProxyURI(raw string) (*HTTPBackend, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" {
		return nil, fmt.Errorf("不是 http 代理协议")
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("http 代理链接缺少服务端")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, fmt.Errorf("端口无效")
	}
	username := ""
	password := ""
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
	}
	name, _ := url.QueryUnescape(u.Fragment)
	tag := SanitizeTag(firstNonEmpty(strings.TrimSpace(name), username, u.Hostname()))
	return &HTTPBackend{
		Key:      tag,
		Name:     firstNonEmpty(strings.TrimSpace(name), tag),
		Server:   u.Hostname(),
		Port:     port,
		Username: username,
		Password: password,
	}, nil
}

// decodeSSUserInfo 解码 SIP002 userinfo 中的 method:password。
func decodeSSUserInfo(value string) (string, string, error) {
	decoded, err := decodeBase64String(value)
	if err != nil {
		return "", "", err
	}
	return splitSSCredential(decoded)
}

// splitSSCredential 拆分 Shadowsocks method:password。
func splitSSCredential(value string) (string, string, error) {
	index := strings.Index(value, ":")
	if index <= 0 {
		return "", "", fmt.Errorf("ss 凭据格式错误")
	}
	method := strings.TrimSpace(value[:index])
	password := strings.TrimSpace(value[index+1:])
	if method == "" || password == "" {
		return "", "", fmt.Errorf("ss method 或 password 为空")
	}
	return method, password, nil
}

// parseSSPlugin 解析 SIP002 plugin 参数。
func parseSSPlugin(value string) (string, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ""
	}
	parts := strings.Split(value, ";")
	plugin := normalizeSSPlugin(parts[0])
	opts := strings.Join(parts[1:], ";")
	return plugin, normalizeSSPluginOpts(opts)
}

// normalizeSSPlugin 将常见客户端插件名映射到 sing-box 内部插件名。
func normalizeSSPlugin(plugin string) string {
	switch strings.TrimSpace(plugin) {
	case "simple-obfs":
		return "obfs-local"
	default:
		return strings.TrimSpace(plugin)
	}
}

// normalizeSSPluginOpts 清理 SIP003 plugin 参数。
func normalizeSSPluginOpts(opts string) string {
	return strings.TrimSpace(strings.TrimPrefix(opts, ";"))
}

// SortBackendsByProtocol 保证运行节点按协议稳定排序。
func SortBackendsByProtocol(backends []ProxyBackend) {
	sort.SliceStable(backends, func(i, j int) bool {
		left := backendProtocolRank(backends[i])
		right := backendProtocolRank(backends[j])
		if left != right {
			return left < right
		}
		return SanitizeTag(backends[i].BackendTag()) < SanitizeTag(backends[j].BackendTag())
	})
}

// backendProtocolRank 返回节点协议排序权重。
func backendProtocolRank(node ProxyBackend) int {
	switch node.BackendProtocol() {
	case "hy2":
		return 0
	case "vmess":
		return 1
	case "trojan":
		return 2
	case "anytls":
		return 3
	case "socks":
		return 4
	case "http":
		return 5
	case "ss":
		return 6
	default:
		return 9
	}
}

// NormalizeBackendIdentity 补齐节点 key 和展示名。
func NormalizeBackendIdentity(backend ProxyBackend) {
	key := SanitizeTag(backend.BackendKey())
	if key == "" {
		key = SanitizeTag(firstNonEmpty(backend.BackendName(), backend.BackendServer()))
	}
	backend.SetBackendKey(key)
}

// MakeUniqueBackendKeys 使同一范围内节点 key 唯一。
func MakeUniqueBackendKeys(backends []ProxyBackend) {
	seen := map[string]int{}
	for i := range backends {
		NormalizeBackendIdentity(backends[i])
		key := UniqueScopedKey(backends[i].BackendKey(), seen, fmt.Sprintf("%s-%d", backends[i].BackendProtocol(), i+1))
		backends[i].SetBackendKey(key)
	}
}

// UniqueScopedKey 返回同一范围内唯一 key。
func UniqueScopedKey(key string, seen map[string]int, fallback string) string {
	key = SanitizeTag(firstNonEmpty(key, fallback))
	if key == "" {
		key = SanitizeTag(fallback)
	}
	seen[key]++
	if seen[key] == 1 {
		return key
	}
	return fmt.Sprintf("%s-%d", key, seen[key])
}

// RuntimeBackendTag 构造 sing-box 全局 outbound tag。
func RuntimeBackendTag(scope string, key string) string {
	return SanitizeTag(scope + "-" + key)
}

// ResolveConfiguredDefault 将旧 key 形式默认出口映射到运行时 tag。
func ResolveConfiguredDefault(cfg *Config, backends []ProxyBackend) {
	if cfg.Policy.Default == "" {
		return
	}
	for _, backend := range backends {
		if backend.BackendTag() == cfg.Policy.Default {
			return
		}
	}
	want := SanitizeTag(cfg.Policy.Default)
	for _, backend := range backends {
		if backend.BackendKey() == want || SanitizeTag(backend.BackendName()) == want {
			cfg.Policy.Default = backend.BackendTag()
			return
		}
	}
}

// SubscriptionCacheFromBackends 将运行时节点转换为可持久化缓存。
func SubscriptionCacheFromBackends(backends []ProxyBackend) []SubscriptionCacheNode {
	nodes := make([]SubscriptionCacheNode, 0, len(backends))
	for _, backend := range backends {
		switch node := backend.(type) {
		case *HY2Backend:
			copyNode := *node
			nodes = append(nodes, SubscriptionCacheNode{Protocol: "hy2", HY2: &copyNode})
		case *VMessBackend:
			copyNode := *node
			nodes = append(nodes, SubscriptionCacheNode{Protocol: "vmess", VMess: &copyNode})
		case *SSBackend:
			copyNode := *node
			nodes = append(nodes, SubscriptionCacheNode{Protocol: "ss", SS: &copyNode})
		case *TrojanBackend:
			copyNode := *node
			nodes = append(nodes, SubscriptionCacheNode{Protocol: "trojan", Trojan: &copyNode})
		case *AnyTLSBackend:
			copyNode := *node
			nodes = append(nodes, SubscriptionCacheNode{Protocol: "anytls", AnyTLS: &copyNode})
		case *SocksBackend:
			copyNode := *node
			nodes = append(nodes, SubscriptionCacheNode{Protocol: "socks", Socks: &copyNode})
		case *HTTPBackend:
			copyNode := *node
			nodes = append(nodes, SubscriptionCacheNode{Protocol: "http", HTTP: &copyNode})
		}
	}
	return nodes
}

// BackendsFromSubscriptionCache 从订阅缓存恢复运行时节点。
func BackendsFromSubscriptionCache(data []byte) ([]ProxyBackend, error) {
	var envelopes []SubscriptionCacheNode
	if err := json.Unmarshal(data, &envelopes); err == nil {
		nodes := make([]ProxyBackend, 0, len(envelopes))
		for _, envelope := range envelopes {
			switch envelope.Protocol {
			case "hy2":
				if envelope.HY2 != nil {
					nodes = append(nodes, envelope.HY2)
				}
			case "vmess":
				if envelope.VMess != nil {
					nodes = append(nodes, envelope.VMess)
				}
			case "ss":
				if envelope.SS != nil {
					nodes = append(nodes, envelope.SS)
				}
			case "trojan":
				if envelope.Trojan != nil {
					nodes = append(nodes, envelope.Trojan)
				}
			case "anytls":
				if envelope.AnyTLS != nil {
					nodes = append(nodes, envelope.AnyTLS)
				}
			case "socks", "socks5":
				if envelope.Socks != nil {
					nodes = append(nodes, envelope.Socks)
				}
			case "http":
				if envelope.HTTP != nil {
					nodes = append(nodes, envelope.HTTP)
				}
			}
		}
		if len(nodes) > 0 || len(envelopes) == 0 {
			return nodes, nil
		}
	}
	// 触发条件：老版本缓存是扁平 HY2 数组。
	// 不能直接按新 envelope 读，否则会得到空协议节点。
	// 防止升级后订阅缓存全部丢失导致无出口。
	var legacy []HY2Backend
	if err := json.Unmarshal(data, &legacy); err != nil {
		return nil, err
	}
	nodes := make([]ProxyBackend, 0, len(legacy))
	for i := range legacy {
		node := legacy[i]
		nodes = append(nodes, &node)
	}
	return nodes, nil
}

// SanitizeTag 将任意名称转为 sing-box tag 可读形式。
func SanitizeTag(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	re := regexp.MustCompile(`[^a-z0-9._-]+`)
	s = re.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return ""
	}
	return s
}

// NormalizeCIDR 将单 IP 转为 /32 或 /128，CIDR 原样返回。
func NormalizeCIDR(value string) string {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "/") {
		return value
	}
	if strings.Contains(value, ":") {
		return value + "/128"
	}
	return value + "/32"
}

// NewLogger 创建日志器。
func NewLogger(cfg LogConfig) *Logger {
	maxSize := cfg.MaxSizeMB * 1024 * 1024
	if maxSize <= 0 {
		maxSize = defaultLogMaxSize
	}
	maxFiles := cfg.MaxFiles
	if maxFiles <= 0 {
		maxFiles = defaultLogMaxFiles
	}
	dir := cfg.Dir
	if dir == "" {
		dir = defaultLogDir
	}
	level := cfg.Level
	if level == "" {
		level = "info"
	}
	return &Logger{Dir: dir, MaxSize: maxSize, MaxFiles: maxFiles, Level: level}
}

// Info 写入 info 级别日志。
func (l *Logger) Info(format string, args ...any) {
	l.write("INFO", "sboxctl.log", format, args...)
}

// Warn 写入 warn 级别日志。
func (l *Logger) Warn(format string, args ...any) {
	l.write("WARN", "sboxctl.log", format, args...)
}

// Error 写入 error 级别日志和总日志。
func (l *Logger) Error(format string, args ...any) {
	l.write("ERROR", "sboxctl.log", format, args...)
	l.write("ERROR", "error.log", format, args...)
}

// RotateFile 对指定日志文件执行轮换，适用于 sing-box 自写日志。
func (l *Logger) RotateFile(path string) {
	l.rotate(path)
}

// write 执行日志写入和轮换。
func (l *Logger) write(level string, name string, format string, args ...any) {
	if err := os.MkdirAll(l.Dir, 0755); err != nil {
		return
	}
	path := filepath.Join(l.Dir, name)
	l.rotate(path)
	line := fmt.Sprintf("%s %s %s\n", time.Now().Format("2006-01-02 15:04:05"), level, fmt.Sprintf(format, args...))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(line)
}

// rotate 在文件超过上限时轮换日志。
func (l *Logger) rotate(path string) {
	info, err := os.Stat(path)
	if err != nil || info.Size() < l.MaxSize {
		return
	}
	for i := l.MaxFiles - 1; i >= 1; i-- {
		oldPath := fmt.Sprintf("%s.%d", path, i)
		newPath := fmt.Sprintf("%s.%d", path, i+1)
		if i == l.MaxFiles-1 {
			_ = os.Remove(newPath)
		}
		_ = os.Rename(oldPath, newPath)
	}
	_ = os.Rename(path, path+".1")
}

// ensureLogger 确保 App 拥有日志器。
func (a *App) ensureLogger(cfg LogConfig) {
	if a.Logger == nil {
		a.Logger = NewLogger(cfg)
	}
}

// configureHTTPClient 根据更新配置刷新下载客户端。
func (a *App) configureHTTPClient(cfg UpdateConfig, useProxy bool) {
	proxy := ""
	if useProxy {
		proxy = cfg.Proxy
	}
	a.HTTPClient = NewHTTPClient(defaultTimeout, proxy, cfg.DNS)
}

// configureWebSubscriptionHTTPClient 配置 Web 手动订阅更新的明确代理语义。
func (a *App) configureWebSubscriptionHTTPClient(cfg Config, useProxy bool) error {
	proxy := ""
	if useProxy {
		nextProxy, err := webSubscriptionProxy(cfg)
		if err != nil {
			return err
		}
		proxy = nextProxy
	}
	a.HTTPClient = NewHTTPClientNoEnvProxy(defaultTimeout, proxy, cfg.Update.DNS)
	return nil
}

// webSubscriptionProxy 返回 Web 手动订阅更新应使用的代理入口。
func webSubscriptionProxy(cfg Config) (string, error) {
	configuredProxy := strings.TrimSpace(cfg.Update.Proxy)
	if configuredProxy != "" {
		if err := validateProxyURL(configuredProxy); err != nil {
			return "", err
		}
		return configuredProxy, nil
	}
	if cfg.Inbound.Mode != "mixed" {
		return "", nil
	}
	if cfg.Inbound.Mixed.Port <= 0 {
		return "", fmt.Errorf("mixed 入口端口非法，不能执行走代理更新")
	}
	host := mixedProxyHost(cfg.Inbound.Mixed.Listen)
	u := url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(host, strconv.Itoa(cfg.Inbound.Mixed.Port)),
	}
	if len(cfg.Inbound.Mixed.Users) > 0 {
		user := cfg.Inbound.Mixed.Users[0]
		u.User = url.UserPassword(user.Username, user.Password)
	}
	return u.String(), nil
}

// validateProxyURL 检查显式代理地址是否可被 HTTP client 使用。
func validateProxyURL(proxy string) error {
	proxyURL, err := url.Parse(proxy)
	if err != nil {
		return fmt.Errorf("update.proxy 无效: %w", err)
	}
	if proxyURL.Scheme == "" || proxyURL.Host == "" {
		return fmt.Errorf("update.proxy 必须包含协议和主机，例如 http://127.0.0.1:7890")
	}
	return nil
}

// mixedProxyHost 返回后端进程访问本机 mixed 入站时应使用的地址。
func mixedProxyHost(listen string) string {
	listen = strings.TrimSpace(listen)
	if listen == "" || listen == "0.0.0.0" || listen == "::" || listen == "[::]" {
		return "127.0.0.1"
	}
	return strings.Trim(listen, "[]")
}

// client 返回可复用 HTTP 客户端，适用于订阅和 geofile 周期更新。
func (a *App) client() *http.Client {
	if a.HTTPClient == nil {
		a.HTTPClient = NewHTTPClient(defaultTimeout, "", defaultUpdateDNS)
	}
	return a.HTTPClient
}

// NewHTTPClient 创建带连接复用的 HTTP 客户端。
func NewHTTPClient(timeout time.Duration, proxyAddr string, dnsServer string) *http.Client {
	proxy := http.ProxyFromEnvironment
	if proxyAddr != "" {
		if proxyURL, err := url.Parse(proxyAddr); err == nil {
			proxy = http.ProxyURL(proxyURL)
		}
	}
	if dnsServer == "" {
		dnsServer = defaultUpdateDNS
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network string, address string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: 5 * time.Second}
			// 触发条件：OpenWrt 本机 DNS 被 sing-box 或旧配置占用时。
			// 不能直接使用系统 resolver，否则更新会卡在 127.0.0.1 或 ::1。
			// 防止 geofiles 和订阅更新失败后覆盖现有可用缓存。
			return dialer.DialContext(ctx, "udp", dnsServer)
		},
	}
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver:  resolver,
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:               proxy,
			DialContext:         dialer.DialContext,
			MaxIdleConns:        16,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}

// NewHTTPClientNoEnvProxy 创建不读取环境代理的客户端，适用于显式直连语义。
func NewHTTPClientNoEnvProxy(timeout time.Duration, proxyAddr string, dnsServer string) *http.Client {
	proxy := func(*http.Request) (*url.URL, error) {
		// 触发条件：Web 手动点击“不走代理”刷新订阅。
		// 不能直接使用 http.ProxyFromEnvironment，否则环境变量会劫持直连语义。
		// 防止用户明确直连时仍被 HTTP_PROXY/HTTPS_PROXY 转发。
		return nil, nil
	}
	if proxyAddr != "" {
		if proxyURL, err := url.Parse(proxyAddr); err == nil {
			proxy = http.ProxyURL(proxyURL)
		}
	}
	return NewHTTPClientWithProxy(timeout, dnsServer, proxy)
}

// NewHTTPClientWithProxy 创建指定 Proxy 函数的 HTTP 客户端。
func NewHTTPClientWithProxy(timeout time.Duration, dnsServer string, proxy func(*http.Request) (*url.URL, error)) *http.Client {
	if dnsServer == "" {
		dnsServer = defaultUpdateDNS
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network string, address string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: 5 * time.Second}
			// 触发条件：OpenWrt 本机 DNS 被 sing-box 或旧配置占用时。
			// 不能直接使用系统 resolver，否则更新会卡在 127.0.0.1 或 ::1。
			// 防止 geofiles 和订阅更新失败后覆盖现有可用缓存。
			return dialer.DialContext(ctx, "udp", dnsServer)
		},
	}
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver:  resolver,
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:               proxy,
			DialContext:         dialer.DialContext,
			MaxIdleConns:        16,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}

// downloadGeo 下载一个 geofile，missingOnly 为 true 时存在则跳过。
func (a *App) downloadGeo(kind string, name string, missingOnly bool) (bool, error) {
	tag := kind + "-" + name
	path := filepath.Join(a.GeoDir, tag+".srs")
	if missingOnly {
		if _, err := os.Stat(path); err == nil {
			return false, nil
		}
	}
	url := fmt.Sprintf("https://raw.githubusercontent.com/2dust/sing-box-rules/rule-set-%s/%s.srs", kind, tag)
	var lastErr error
	for attempt := 1; attempt <= defaultDownloadRetries; attempt++ {
		data, err := a.downloadBytes(url)
		if err != nil {
			lastErr = err
			a.Logger.Warn("geofile 下载失败 tag=%s attempt=%d err=%v", tag, attempt, err)
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		}
		changed, err := writeFileIfChanged(path, data, 0644)
		if err != nil {
			return false, err
		}
		return changed, nil
	}
	return false, lastErr
}

// downloadBytes 下载单个文件到内存，适用于先比较后写盘的缓存更新。
func (a *App) downloadBytes(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sboxctl/0.1")
	resp, err := a.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP 状态异常: %s", resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// applyLogValue 将 YAML 键值写入日志配置。
func applyLogValue(cfg *LogConfig, key string, value string) {
	value = cleanValue(value)
	switch key {
	case "level":
		cfg.Level = value
	case "dir":
		cfg.Dir = value
	case "max_size_mb":
		if n, err := strconv.ParseInt(value, 10, 64); err == nil {
			cfg.MaxSizeMB = n
		}
	case "max_files":
		if n, err := strconv.Atoi(value); err == nil {
			cfg.MaxFiles = n
		}
	}
}

// applyBackendValue 将 YAML 键值写入 HY2 后端。
func applyBackendValue(b *HY2Backend, key string, value string) {
	value = cleanValue(value)
	switch key {
	case "tag":
		b.Tag = value
	case "name":
		b.Name = value
	case "server":
		b.Server = value
	case "port":
		b.Port, _ = strconv.Atoi(value)
	case "password":
		b.Password = value
	case "sni":
		b.SNI = value
	case "insecure":
		b.Insecure = parseBool(value)
	case "obfs_password":
		b.ObfsPassword = value
	}
}

// applySubscriptionValue 将 YAML 键值写入订阅配置。
func applySubscriptionValue(s *Subscription, key string, value string) {
	value = cleanValue(value)
	switch key {
	case "name":
		s.Name = value
	case "url":
		s.URL = value
	case "enabled":
		s.Enabled = parseBool(value)
	}
}

// splitKeyValue 拆分 key:value。
func splitKeyValue(text string) (string, string, bool) {
	idx := strings.Index(text, ":")
	if idx < 0 {
		return "", "", false
	}
	return strings.TrimSpace(text[:idx]), strings.TrimSpace(text[idx+1:]), true
}

// cleanValue 清理 YAML 标量外层引号。
func cleanValue(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'`)
	return value
}

// stripComment 删除 YAML 行注释。
func stripComment(line string) string {
	idx := strings.Index(line, "#")
	if idx >= 0 {
		return line[:idx]
	}
	return line
}

// stripInlineRuleComment 删除规则文件中的注释。
func stripInlineRuleComment(line string) string {
	if idx := strings.Index(line, "//"); idx >= 0 {
		line = line[:idx]
	}
	if idx := strings.Index(line, "#"); idx >= 0 {
		line = line[:idx]
	}
	return line
}

// leadingSpaces 计算行首空格数。
func leadingSpaces(line string) int {
	n := 0
	for _, ch := range line {
		if ch != ' ' {
			break
		}
		n++
	}
	return n
}

// parseBool 解析常见布尔字符串。
func parseBool(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "true" || value == "1" || value == "yes" || value == "on"
}

// parseIntDefault 解析整数，空值或非法值返回默认值。
func parseIntDefault(value string, fallback int) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	result, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return result
}

// padBase64 为 base64 字符串补齐填充。
func padBase64(s string) string {
	switch len(s) % 4 {
	case 2:
		return s + "=="
	case 3:
		return s + "="
	default:
		return s
	}
}

// decodeBase64String 解码标准和 URL-safe base64 字符串。
func decodeBase64String(value string) (string, error) {
	value = strings.TrimSpace(value)
	decoded, err := base64.StdEncoding.DecodeString(padBase64(value))
	if err != nil {
		if decoded, err = base64.URLEncoding.DecodeString(padBase64(value)); err != nil {
			return "", err
		}
	}
	return string(decoded), nil
}

// looksLikeSubscription 判断解码结果是否像订阅。
func looksLikeSubscription(data []byte) bool {
	text := string(data)
	return strings.Contains(text, "://")
}

// firstNonEmpty 返回第一个非空字符串。
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// firstString 返回字符串切片首项，适用于空切片安全取值。
func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// containsString 判断字符串切片是否包含指定值。
func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// writeFileIfMissing 在文件不存在时写入内容。
func writeFileIfMissing(path string, data []byte) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	return os.WriteFile(path, data, 0644)
}

// writeExecutable 写入可执行脚本。
func writeExecutable(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0755); err != nil {
		return err
	}
	return nil
}

// runService 调用 OpenWrt init.d 服务。
func runService(name string, action string) error {
	return runCommand("/etc/init.d/"+name, action)
}

// runCommand 执行外部命令并透传输出。
func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// removeCronLine 删除旧版 cron 更新任务。
func removeCronLine(pattern string) error {
	current, _ := exec.Command("crontab", "-l").Output()
	lines := strings.Split(string(current), "\n")
	var buf bytes.Buffer
	for _, item := range lines {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, pattern) {
			continue
		}
		buf.WriteString(item)
		buf.WriteByte('\n')
	}
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = &buf
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// initScript 返回 OpenWrt 服务脚本。
func initScript() string {
	return `#!/bin/sh /etc/rc.common

START=99
STOP=10
USE_PROCD=1

start_service() {
	procd_open_instance
	procd_set_param command /usr/sbin/sboxctl daemon
	procd_set_param respawn 3600 5 5
	procd_close_instance
}
`
}
