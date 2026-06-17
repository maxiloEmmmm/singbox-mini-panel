package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestParseLocalRules 验证一行一条规则能解析 domain/src/dst。
func TestParseLocalRules(t *testing.T) {
	rules, err := ParseLocalRules(strings.NewReader(`
domain:xx.com // 注释
src:192.168.1.1
dst:10.0.0.0/8
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 {
		t.Fatalf("规则数量错误: %d", len(rules))
	}
	if rules[0].Kind != "domain" || rules[0].Value != "xx.com" {
		t.Fatalf("domain 解析错误: %+v", rules[0])
	}
}

// mustJSON 将对象编码为 JSON，适用于测试准备缓存正文。
func mustJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestBuildRouteRuleDomain 验证 domain 规则会同时匹配裸域和子域。
func TestBuildRouteRuleDomain(t *testing.T) {
	rule := BuildRouteRule(LocalRule{Kind: "domain", Value: "xx.com"}, "direct")
	domain := rule["domain"].([]string)
	suffix := rule["domain_suffix"].([]string)
	if domain[0] != "xx.com" || suffix[0] != ".xx.com" {
		t.Fatalf("域名匹配生成错误: %+v", rule)
	}
}

// TestDecodeSubscriptionText 验证 base64 订阅能自动解码。
func TestDecodeSubscriptionText(t *testing.T) {
	raw := "hy2://pass@example.com:443?sni=example.com#node"
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))
	got := DecodeSubscriptionText([]byte(encoded))
	if got != raw {
		t.Fatalf("订阅解码错误: %s", got)
	}
}

// TestParseHY2URI 验证 HY2 分享链接能解析为后端。
func TestParseHY2URI(t *testing.T) {
	node, err := ParseHY2URI("hy2://secret@example.com:443?sni=example.com&insecure=1#A")
	if err != nil {
		t.Fatal(err)
	}
	if node.Password != "secret" || node.Server != "example.com" || node.Port != 443 || !node.Insecure {
		t.Fatalf("hy2 解析错误: %+v", node)
	}
}

// TestParseAnyTLSURI 验证 AnyTLS 分享链接能解析为后端。
func TestParseAnyTLSURI(t *testing.T) {
	node, err := ParseAnyTLSURI("anytls://secret@example.com:443?sni=sni.example&insecure=1&idle_session_check_interval=10s&idle_session_timeout=20s&min_idle_session=2#A")
	if err != nil {
		t.Fatal(err)
	}
	if node.Password != "secret" || node.Server != "example.com" || node.Port != 443 || !node.Insecure {
		t.Fatalf("anytls 基本字段解析错误: %+v", node)
	}
	if node.SNI != "sni.example" || node.IdleSessionCheckInterval != "10s" || node.IdleSessionTimeout != "20s" || node.MinIdleSession != 2 {
		t.Fatalf("anytls 可选字段解析错误: %+v", node)
	}
}

// TestParseVMessURI 验证 v2rayN VMess 分享链接能解析。
func TestParseVMessURI(t *testing.T) {
	raw := `{"v":"2","ps":"jp-vmess","add":"example.com","port":"443","id":"bf000d23-0752-40b4-affe-68f7707a9661","aid":"0","scy":"auto","net":"ws","host":"cdn.example.com","path":"/ws","tls":"tls","sni":"sni.example.com"}`
	node, err := ParseVMessURI("vmess://" + base64.StdEncoding.EncodeToString([]byte(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if node.Key != "jp-vmess" || node.Name != "jp-vmess" || node.Transport != "ws" || !node.TLS || node.Host != "cdn.example.com" {
		t.Fatalf("vmess 解析错误: %+v", node)
	}
}

// TestParseSSSIP002URI 验证 SIP002 Shadowsocks 链接和 simple-obfs 插件能解析。
func TestParseSSSIP002URI(t *testing.T) {
	userInfo := base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:secret"))
	raw := "ss://" + userInfo + "@example.com:8388/?plugin=simple-obfs%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example.com#hk-ss"
	node, err := ParseSSURI(raw)
	if err != nil {
		t.Fatal(err)
	}
	if node.Key != "hk-ss" || node.Method != "aes-128-gcm" || node.Password != "secret" {
		t.Fatalf("ss 基本字段解析错误: %+v", node)
	}
	if node.Plugin != "obfs-local" || node.PluginOpts != "obfs=http;obfs-host=cdn.example.com" {
		t.Fatalf("ss 插件解析错误: %+v", node)
	}
}

// TestParseSSLegacyURI 验证旧式整段 base64 Shadowsocks 链接能解析。
func TestParseSSLegacyURI(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:secret@example.com:8388"))
	node, err := ParseSSURI("ss://" + payload + "#legacy")
	if err != nil {
		t.Fatal(err)
	}
	if node.Name != "legacy" || node.Server != "example.com" || node.Port != 8388 || node.Method != "aes-256-gcm" {
		t.Fatalf("旧式 ss 解析错误: %+v", node)
	}
}

// TestBackendProtocolSort 验证 HY2 在混合节点列表中排在 VMess 前面。
func TestBackendProtocolSort(t *testing.T) {
	nodes := []ProxyBackend{
		&SSBackend{Tag: "b-ss", Server: "s.example", Port: 8388},
		&AnyTLSBackend{Tag: "d-anytls", Server: "a.example", Port: 443},
		&TrojanBackend{Tag: "c-trojan", Server: "t.example", Port: 443},
		&VMessBackend{Tag: "a-vmess", Server: "v.example", Port: 443},
		&HY2Backend{Tag: "z-hy2", Server: "h.example", Port: 443},
	}
	SortBackendsByProtocol(nodes)
	if nodes[0].BackendProtocol() != "hy2" || nodes[1].BackendProtocol() != "vmess" ||
		nodes[2].BackendProtocol() != "trojan" || nodes[3].BackendProtocol() != "anytls" ||
		nodes[4].BackendProtocol() != "ss" {
		t.Fatalf("协议排序错误: %s/%s/%s/%s/%s",
			nodes[0].BackendProtocol(), nodes[1].BackendProtocol(),
			nodes[2].BackendProtocol(), nodes[3].BackendProtocol(), nodes[4].BackendProtocol())
	}
}

// TestNormalizeStaticBackendsForSaveFlatProtocols 验证静态节点保存支持扁平协议。
func TestNormalizeStaticBackendsForSaveFlatProtocols(t *testing.T) {
	nodes := []StaticBackend{
		{Protocol: "hy2", Key: "jp", Server: "hy2.example", Port: 443, Password: "p"},
		{Protocol: "vmess", Key: "vm", Server: "vm.example", Port: 443, UUID: "u", TLS: true, Transport: "ws", Path: "/ws"},
		{Protocol: "ss", Key: "ss", Server: "ss.example", Port: 8388, Method: "aes-128-gcm", Password: "p", Plugin: "simple-obfs", PluginOpts: "obfs=http"},
		{Protocol: "trojan", Key: "tj", Server: "tj.example", Port: 443, Password: "p", SNI: "sni.example", TLS: true, Transport: "ws", Path: "/ws"},
		{Protocol: "anytls", Key: "at", Server: "at.example", Port: 443, Password: "p", SNI: "at-sni.example", Insecure: true, IdleSessionCheckInterval: "10s", IdleSessionTimeout: "20s", MinIdleSession: 2},
	}
	got, err := NormalizeStaticBackendsForSave(nodes)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 || got[0].Protocol != "hy2" || got[1].Protocol != "vmess" ||
		got[2].Protocol != "ss" || got[3].Protocol != "trojan" || got[4].Protocol != "anytls" {
		t.Fatalf("静态协议清洗错误: %+v", got)
	}
	if got[1].Security != "auto" || got[1].Password != "" {
		t.Fatalf("vmess 字段清洗错误: %+v", got[1])
	}
	if got[2].Plugin != "obfs-local" || got[2].PluginOpts != "obfs=http" {
		t.Fatalf("ss 字段清洗错误: %+v", got[2])
	}
	if !got[3].TLS || got[3].SNI != "sni.example" || got[3].Transport != "ws" || got[3].Path != "/ws" {
		t.Fatalf("trojan 字段清洗错误: %+v", got[3])
	}
	if got[4].SNI != "at-sni.example" || !got[4].Insecure || got[4].IdleSessionCheckInterval != "10s" ||
		got[4].IdleSessionTimeout != "20s" || got[4].MinIdleSession != 2 {
		t.Fatalf("anytls 字段清洗错误: %+v", got[4])
	}
}

// TestSubscriptionCacheEnvelope 验证订阅缓存按协议恢复具体结构。
func TestSubscriptionCacheEnvelope(t *testing.T) {
	nodes := []ProxyBackend{
		&HY2Backend{Tag: "hy2-a", Server: "h.example", Port: 443},
		&VMessBackend{Tag: "vmess-a", Server: "v.example", Port: 443},
		&SSBackend{Tag: "ss-a", Server: "s.example", Port: 8388, Method: "aes-128-gcm", Password: "p"},
		&TrojanBackend{Tag: "trojan-a", Server: "t.example", Port: 443, Password: "p", TLS: true},
		&AnyTLSBackend{Tag: "anytls-a", Server: "a.example", Port: 443, Password: "p"},
	}
	data := []byte(mustJSON(t, SubscriptionCacheFromBackends(nodes)))
	got, err := BackendsFromSubscriptionCache(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 || got[0].BackendProtocol() != "hy2" || got[1].BackendProtocol() != "vmess" ||
		got[2].BackendProtocol() != "ss" || got[3].BackendProtocol() != "trojan" ||
		got[4].BackendProtocol() != "anytls" {
		t.Fatalf("缓存恢复错误: %+v", got)
	}
}

// TestFetchSubscriptionParsesSS 验证订阅正文中的 Shadowsocks 节点会进入缓存节点列表。
func TestFetchSubscriptionParsesSS(t *testing.T) {
	userInfo := base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:secret"))
	line := "ss://" + userInfo + "@example.com:8388/?plugin=simple-obfs%3Bobfs%3Dhttp#ss-node"
	body := base64.StdEncoding.EncodeToString([]byte(line + "\n"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	nodes, skipped, failed, err := FetchSubscription(server.Client(), Subscription{Name: "ss", URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 0 || failed != 0 || len(nodes) != 1 || nodes[0].BackendProtocol() != "ss" {
		t.Fatalf("ss 订阅解析错误 nodes=%+v skipped=%d failed=%d", nodes, skipped, failed)
	}
}

// TestFetchSubscriptionParsesTrojan 验证订阅正文中的 Trojan 节点会进入缓存节点列表。
func TestFetchSubscriptionParsesTrojan(t *testing.T) {
	line := "trojan://secret@example.com:443?security=tls&sni=sni.example&type=ws&path=%2Fws&host=host.example#trojan-node"
	body := base64.StdEncoding.EncodeToString([]byte(line + "\n"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	nodes, skipped, failed, err := FetchSubscription(server.Client(), Subscription{Name: "trojan", URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 0 || failed != 0 || len(nodes) != 1 || nodes[0].BackendProtocol() != "trojan" {
		t.Fatalf("trojan 订阅解析错误 nodes=%+v skipped=%d failed=%d", nodes, skipped, failed)
	}
	node := nodes[0].(*TrojanBackend)
	if !node.TLS || node.SNI != "sni.example" || node.Transport != "ws" || node.Path != "/ws" || node.Host != "host.example" {
		t.Fatalf("trojan 参数解析错误: %+v", node)
	}
}

// TestFetchSubscriptionParsesAnyTLS 验证订阅正文中的 AnyTLS 节点会进入缓存节点列表。
func TestFetchSubscriptionParsesAnyTLS(t *testing.T) {
	line := "anytls://secret@example.com:443?sni=sni.example&idle_session_check_interval=10s#anytls-node"
	body := base64.StdEncoding.EncodeToString([]byte(line + "\n"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	nodes, skipped, failed, err := FetchSubscription(server.Client(), Subscription{Name: "anytls", URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 0 || failed != 0 || len(nodes) != 1 || nodes[0].BackendProtocol() != "anytls" {
		t.Fatalf("anytls 订阅解析错误 nodes=%+v skipped=%d failed=%d", nodes, skipped, failed)
	}
	node := nodes[0].(*AnyTLSBackend)
	if node.SNI != "sni.example" || node.IdleSessionCheckInterval != "10s" {
		t.Fatalf("anytls 参数解析错误: %+v", node)
	}
}

// TestHostsOverrideDefaultEnabled 验证 hosts DNS 旧配置缺失时默认开启。
func TestHostsOverrideDefaultEnabled(t *testing.T) {
	cfg := Config{}
	MergeConfigDefaults(&cfg)
	if !HostsOverrideEnabled(cfg) {
		t.Fatal("hosts override 默认应该开启")
	}
	cfg.GeoFiles.HostsOverride = boolPtr(false)
	MergeConfigDefaults(&cfg)
	if HostsOverrideEnabled(cfg) {
		t.Fatal("hosts override 显式关闭后不应开启")
	}
}

// TestBuildSingBoxConfigUsesV2rayNDNSNoIPv6 验证 DNS 结构贴近 v2rayN 且不启用 IPv6 FakeIP。
func TestBuildSingBoxConfigUsesV2rayNDNSNoIPv6(t *testing.T) {
	cfg := DefaultConfig()
	app := &App{}
	doc, err := app.BuildSingBoxConfig(cfg, []ProxyBackend{
		&HY2Backend{Tag: "hy2-a", Server: "example.com", Port: 443, Password: "p"},
	}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	dns := doc["dns"].(map[string]any)
	if dns["independent_cache"] != true || dns["final"] != "remote-dns" {
		t.Fatalf("DNS 基础字段错误: %+v", dns)
	}
	servers := dns["servers"].([]map[string]any)
	remote := findMapByString(servers, "tag", "remote-dns")
	if remote["server"] != defaultRemoteDNSServer || remote["path"] != defaultRemoteDNSPath ||
		remote["detour"] != defaultCurrentSelector || remote["domain_resolver"] != "local-dns" {
		t.Fatalf("remote DNS 不符合 v2rayN 结构: %+v", remote)
	}
	direct := findMapByString(servers, "tag", "direct-dns")
	if direct["server"] != defaultDirectDNS || direct["domain_resolver"] != "local-dns" {
		t.Fatalf("direct DNS 不符合 v2rayN 结构: %+v", direct)
	}
	hosts := findMapByString(servers, "tag", defaultHostsDNSTag)
	if hosts["type"] != "hosts" || hosts["path"] != defaultHostsPath {
		t.Fatalf("hosts DNS 不符合 v2rayN 结构: %+v", hosts)
	}
	fakeip := findMapByString(servers, "tag", "fakeip")
	if fakeip["inet4_range"] != "198.18.0.0/15" {
		t.Fatalf("FakeIP IPv4 范围错误: %+v", fakeip)
	}
	if _, ok := fakeip["inet6_range"]; ok {
		t.Fatalf("不应启用 IPv6 FakeIP: %+v", fakeip)
	}
	rules := dns["rules"].([]map[string]any)
	hostsRule := findMapByString(rules, "server", defaultHostsDNSTag)
	if hostsRule["ip_accept_any"] != true {
		t.Fatalf("hosts DNS 规则错误: %+v", hostsRule)
	}
	blockRule := findMapByString(rules, "rcode", "NOERROR")
	if blockRule["action"] != "predefined" || strings.Join(intsToStrings(blockRule["query_type"].([]int)), ",") != "64,65" {
		t.Fatalf("HTTPS/SVCB 规则错误: %+v", blockRule)
	}
	fakeRule := findMapByString(rules, "server", "fakeip")
	if fakeRule["rewrite_ttl"] != 1 {
		t.Fatalf("FakeIP TTL 规则错误: %+v", fakeRule)
	}
	nested := fakeRule["rules"].([]map[string]any)
	if strings.Join(intsToStrings(nested[0]["query_type"].([]int)), ",") != "1" {
		t.Fatalf("FakeIP 不应处理 AAAA: %+v", nested[0])
	}
}

// TestBuildSingBoxConfigSkipsHostsDNSWhenDisabled 验证关闭开关后不生成 hosts DNS。
func TestBuildSingBoxConfigSkipsHostsDNSWhenDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.GeoFiles.HostsOverride = boolPtr(false)
	app := &App{}
	doc, err := app.BuildSingBoxConfig(cfg, []ProxyBackend{
		&HY2Backend{Tag: "hy2-a", Server: "example.com", Port: 443, Password: "p"},
	}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	dns := doc["dns"].(map[string]any)
	if findMapByString(dns["servers"].([]map[string]any), "tag", defaultHostsDNSTag) != nil {
		t.Fatal("hosts DNS 关闭后不应生成 hosts server")
	}
	if findMapByString(dns["rules"].([]map[string]any), "server", defaultHostsDNSTag) != nil {
		t.Fatal("hosts DNS 关闭后不应生成 hosts rule")
	}
}

// TestBuildSingBoxConfigIncludesOverrideRule 验证静态跳转规则会生成目标改写路由。
func TestBuildSingBoxConfigIncludesOverrideRule(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Policy.Overrides = []OverrideRule{{
		Key:      "example-local",
		Match:    "domain:example.com",
		Address:  "127.0.0.1",
		Port:     10820,
		Outbound: "direct",
		Enabled:  boolPtr(true),
	}}
	app := &App{}
	doc, err := app.BuildSingBoxConfig(cfg, []ProxyBackend{
		&HY2Backend{Tag: "hy2-a", Server: "example.com", Port: 443, Password: "p"},
	}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	route := doc["route"].(map[string]any)
	rule := findMapByString(route["rules"].([]map[string]any), "override_address", "127.0.0.1")
	if rule == nil {
		t.Fatal("未生成静态跳转规则")
	}
	if rule["override_port"] != 10820 || rule["outbound"] != "direct" {
		t.Fatalf("静态跳转目标错误: %+v", rule)
	}
	domains := rule["domain"].([]string)
	if len(domains) != 1 || domains[0] != "example.com" {
		t.Fatalf("静态跳转域名错误: %+v", rule)
	}
}

// TestBuildTrojanOutbound 验证 Trojan 节点生成 sing-box 出站配置。
func TestBuildTrojanOutbound(t *testing.T) {
	out := BuildTrojanOutbound(TrojanBackend{
		Tag:       "trojan-a",
		Server:    "example.com",
		Port:      443,
		Password:  "secret",
		SNI:       "sni.example",
		TLS:       true,
		Insecure:  true,
		Transport: "ws",
		Path:      "/ws",
		Host:      "host.example",
	})
	if out["type"] != "trojan" || out["server_port"] != 443 || out["password"] != "secret" {
		t.Fatalf("Trojan 基础字段错误: %+v", out)
	}
	tls := out["tls"].(map[string]any)
	if tls["server_name"] != "sni.example" || tls["insecure"] != true {
		t.Fatalf("Trojan TLS 字段错误: %+v", tls)
	}
	transport := out["transport"].(map[string]any)
	headers := transport["headers"].(map[string]any)
	if transport["type"] != "ws" || transport["path"] != "/ws" || headers["Host"] != "host.example" {
		t.Fatalf("Trojan transport 字段错误: %+v", transport)
	}
}

// TestBuildAnyTLSOutbound 验证 AnyTLS 节点生成 sing-box 出站配置。
func TestBuildAnyTLSOutbound(t *testing.T) {
	out := BuildAnyTLSOutbound(AnyTLSBackend{
		Tag:                      "anytls-a",
		Server:                   "example.com",
		Port:                     443,
		Password:                 "secret",
		SNI:                      "sni.example",
		Insecure:                 true,
		IdleSessionCheckInterval: "10s",
		IdleSessionTimeout:       "20s",
		MinIdleSession:           2,
	})
	if out["type"] != "anytls" || out["server_port"] != 443 || out["password"] != "secret" {
		t.Fatalf("AnyTLS 基础字段错误: %+v", out)
	}
	if out["idle_session_check_interval"] != "10s" || out["idle_session_timeout"] != "20s" || out["min_idle_session"] != 2 {
		t.Fatalf("AnyTLS 空闲会话字段错误: %+v", out)
	}
	tls := out["tls"].(map[string]any)
	if tls["server_name"] != "sni.example" || tls["insecure"] != true || tls["enabled"] != true {
		t.Fatalf("AnyTLS TLS 字段错误: %+v", tls)
	}
}

// TestBuildSingBoxConfigNoBackendError 验证无 backend 时返回可识别错误。
func TestBuildSingBoxConfigNoBackendError(t *testing.T) {
	app := &App{}
	_, err := app.BuildSingBoxConfig(DefaultConfig(), nil, nil, nil, nil)
	if !errors.Is(err, ErrNoAvailableBackend) {
		t.Fatalf("无 backend 错误不匹配: %v", err)
	}
}

// TestSiblingSingBoxBinaryUsesExecutableSibling 验证同级 sing-box 可执行文件优先使用。
func TestSiblingSingBoxBinaryUsesExecutableSibling(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "sing-box")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	got := SiblingSingBoxBinary(filepath.Join(dir, "sboxctl"))
	if got != binary {
		t.Fatalf("同级 sing-box 未命中: %s", got)
	}
}

// TestSiblingSingBoxBinarySkipsPlainFile 验证普通文件不会被当作 sing-box 二进制。
func TestSiblingSingBoxBinarySkipsPlainFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sing-box"), []byte("plain"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := SiblingSingBoxBinary(filepath.Join(dir, "sboxctl")); got != "" {
		t.Fatalf("普通文件不应命中: %s", got)
	}
}

// findMapByString 返回指定字段等于目标值的 map，适用于检查生成配置。
func findMapByString(items []map[string]any, key string, value string) map[string]any {
	for _, item := range items {
		if item[key] == value {
			return item
		}
	}
	return nil
}

// intsToStrings 将整数列表转为字符串列表，适用于稳定比较 query_type。
func intsToStrings(items []int) []string {
	result := make([]string, 0, len(items))
	for _, item := range items {
		result = append(result, strconv.Itoa(item))
	}
	return result
}

// TestUpdateChangedSubscriptionsUsesCacheWhenOnlyEnabled 验证启用已有缓存订阅不会阻塞下载。
func TestUpdateChangedSubscriptionsUsesCacheWhenOnlyEnabled(t *testing.T) {
	dir := t.TempDir()
	app := &App{SubscriptionDir: filepath.Join(dir, "sub")}
	if _, err := app.SaveSubscriptionCache("baji", []ProxyBackend{
		&SSBackend{Key: "ss", Server: "example.com", Port: 8388, Method: "aes-128-gcm", Password: "p"},
	}); err != nil {
		t.Fatal(err)
	}
	before := &Config{Backend: BackendConfig{Subscription: []Subscription{
		{Key: "baji", Name: "baji", URL: "http://127.0.0.1:1/sub", UserAgent: "ua", Enabled: false},
	}}}
	after := &Config{Backend: BackendConfig{Subscription: []Subscription{
		{Key: "baji", Name: "baji", URL: "http://127.0.0.1:1/sub", UserAgent: "ua", Enabled: true},
	}}}
	if err := app.UpdateChangedSubscriptions(before, after); err != nil {
		t.Fatalf("已有缓存启用订阅不应下载: %v", err)
	}
}

// TestFetchClashDelay 验证 Clash delay 响应能解析为毫秒值。
func TestFetchClashDelay(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"delay":123}`))
	}))
	defer server.Close()
	delay, err := fetchClashDelay(server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if delay != 123 {
		t.Fatalf("delay 解析错误: %d", delay)
	}
}

// TestParseConfigYAML 验证约定 YAML 能解析静态后端和订阅。
func TestParseConfigYAML(t *testing.T) {
	cfg, err := ParseConfigYAML([]byte(`
backend:
  static:
    - tag: hy2-a
      server: example.com
      port: 443
      password: p
  subscription:
    - name: main
      url: https://example.com/sub
      enabled: true
policy:
  default: hy2-a
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Backend.Static) != 1 || len(cfg.Backend.Subscription) != 1 {
		t.Fatalf("配置解析错误: %+v", cfg)
	}
	if cfg.Policy.Default != "hy2-a" {
		t.Fatalf("默认策略解析错误: %+v", cfg.Policy)
	}
}

// TestBuildInboundsDefaultTun 验证默认入口仍是 TUN 模式。
func TestBuildInboundsDefaultTun(t *testing.T) {
	cfg := Config{}
	MergeConfigDefaults(&cfg)
	inbounds := BuildInbounds(cfg.Inbound)
	if inbounds[0]["type"] != "tun" {
		t.Fatalf("默认入口不是 tun: %+v", inbounds)
	}
}

// TestBuildInboundsMixed 验证 mixed 模式会生成 socks/http 混合端口。
func TestBuildInboundsMixed(t *testing.T) {
	inbounds := BuildInbounds(InboundConfig{
		Mode: "mixed",
		Mixed: MixedInboundConfig{
			Listen: "0.0.0.0",
			Port:   1080,
			Users: []MixedUser{
				{Username: "u", Password: "p"},
			},
		},
	})
	if inbounds[0]["type"] != "mixed" || inbounds[0]["listen_port"] != 1080 {
		t.Fatalf("mixed 入口生成错误: %+v", inbounds)
	}
	users := inbounds[0]["users"].([]map[string]any)
	if users[0]["username"] != "u" || users[0]["password"] != "p" {
		t.Fatalf("mixed 用户生成错误: %+v", users)
	}
}

// TestApplyWebInboundConfig 验证 Web 保存 mixed 监听配置。
func TestApplyWebInboundConfig(t *testing.T) {
	cfg := DefaultConfig()
	err := ApplyWebInboundConfig(&cfg, WebInboundConfig{
		InboundMode: "mixed",
		MixedListen: "127.0.0.1",
		MixedPort:   2080,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Inbound.Mode != "mixed" || cfg.Inbound.Mixed.Listen != "127.0.0.1" || cfg.Inbound.Mixed.Port != 2080 {
		t.Fatalf("mixed 监听保存错误: %+v", cfg.Inbound)
	}
}

// TestApplyWebInboundConfigRejectsHostPort 验证 mixed listen 不接受端口混写。
func TestApplyWebInboundConfigRejectsHostPort(t *testing.T) {
	cfg := DefaultConfig()
	err := ApplyWebInboundConfig(&cfg, WebInboundConfig{
		InboundMode: "mixed",
		MixedListen: "127.0.0.1:1080",
		MixedPort:   1080,
	})
	if err == nil {
		t.Fatal("mixed listen 混写端口应该报错")
	}
}

// TestWebConnectionFromClashDirect 验证连接流水能识别 direct。
func TestWebConnectionFromClashDirect(t *testing.T) {
	row := WebConnectionFromClash(clashConnection{
		ID:       "1",
		Upload:   10,
		Download: 20,
		Chains:   []string{"direct"},
		Rule:     "rule_set=geoip-cn => route(direct)",
		Metadata: clashConnectionMetadata{
			Network:         "tcp",
			SourceIP:        "192.168.88.130",
			SourcePort:      50000,
			DestinationIP:   "1.2.3.4",
			DestinationPort: 443,
		},
	})
	if row.Decision != "direct" || row.Total != 30 {
		t.Fatalf("连接 direct 识别错误: %+v", row)
	}
}

// TestWebConnectionFromClashProxy 验证连接流水能识别代理链路。
func TestWebConnectionFromClashProxy(t *testing.T) {
	row := WebConnectionFromClash(clashConnection{
		ID:       "2",
		Upload:   7,
		Download: 11,
		Chains:   []string{"sub-main-jp-hy2", "group-main", "current"},
		Metadata: clashConnectionMetadata{
			Network:         "tcp",
			SourceIP:        "192.168.88.164",
			SourcePort:      50001,
			Host:            "chatgpt.com",
			DestinationPort: 443,
		},
	})
	if row.Decision != "proxy" || row.Destination != "chatgpt.com:443" {
		t.Fatalf("连接 proxy 识别错误: %+v", row)
	}
}

// TestNextDailyTime 验证 daemon 会计算下一次固定更新时间。
func TestNextDailyTime(t *testing.T) {
	loc := time.FixedZone("test", 8*60*60)
	before := time.Date(2026, 5, 14, 3, 59, 0, 0, loc)
	next := NextDailyTime(before, 4, 0)
	if next.Day() != 14 || next.Hour() != 4 || next.Minute() != 0 {
		t.Fatalf("当天更新时间错误: %s", next)
	}
	after := time.Date(2026, 5, 14, 4, 1, 0, 0, loc)
	next = NextDailyTime(after, 4, 0)
	if next.Day() != 15 || next.Hour() != 4 || next.Minute() != 0 {
		t.Fatalf("次日更新时间错误: %s", next)
	}
}

// TestJWT 验证 Web 登录令牌能通过签名和过期校验。
func TestJWT(t *testing.T) {
	token, err := MakeJWT("admin", "secret", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	subject, err := VerifyJWT(token, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if subject != "admin" {
		t.Fatalf("JWT subject 错误: %s", subject)
	}
	if _, err := VerifyJWT(token, "wrong"); err == nil {
		t.Fatal("错误密钥不应通过校验")
	}
}

// TestExpiredJWT 验证过期 JWT 会被拒绝。
func TestExpiredJWT(t *testing.T) {
	token, err := MakeJWT("admin", "secret", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyJWT(token, "secret"); err == nil {
		t.Fatal("过期 JWT 不应通过校验")
	}
}

// TestValidateLocalRulesText 验证 Web 保存前会校验规则格式。
func TestValidateLocalRulesText(t *testing.T) {
	if err := ValidateLocalRulesText("domain:example.com\nsrc:10.0.0.1\n"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateLocalRulesText("bad:example.com\n"); err == nil {
		t.Fatal("非法规则不应通过校验")
	}
}

// TestNormalizeProxyRuleSets 验证 Web 提交的 geofile 选择会被白名单过滤。
func TestNormalizeProxyRuleSets(t *testing.T) {
	got := NormalizeProxyRuleSets([]string{
		"geosite-google",
		"geoip-cn",
		"geosite-google",
		"geoip-twitter",
	})
	if strings.Join(got, ",") != "geosite-google,geoip-twitter" {
		t.Fatalf("规则集过滤错误: %+v", got)
	}
}

// TestBuildSingBoxConfigGeoFiles 验证 geofile 开关会影响路由规则生成。
func TestBuildSingBoxConfigGeoFiles(t *testing.T) {
	app := &App{GeoDir: "/tmp/geofiles"}
	cfg := DefaultConfig()
	cfg.Policy.Default = "jp"
	cfg.GeoFiles.AdsBlock = false
	cfg.GeoFiles.ProxyRuleSets = []string{"geosite-google"}
	doc, err := app.BuildSingBoxConfig(cfg, []ProxyBackend{&HY2Backend{Tag: "jp", Server: "example.com", Port: 443, Password: "p"}}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	route := doc["route"].(map[string]any)
	if route["final"] != defaultCurrentSelector {
		t.Fatalf("主出口应指向 current selector: %+v", route["final"])
	}
	foundCurrent := false
	for _, outbound := range doc["outbounds"].([]map[string]any) {
		if outbound["tag"] == defaultCurrentSelector && outbound["type"] == "selector" {
			foundCurrent = true
			if outbound["default"] != "jp" {
				t.Fatalf("current 默认出口错误: %+v", outbound)
			}
		}
	}
	if !foundCurrent {
		t.Fatal("未生成 current selector")
	}
	rules := route["rules"].([]map[string]any)
	for _, rule := range rules {
		if sets, ok := rule["rule_set"].([]string); ok {
			joined := strings.Join(sets, ",")
			if strings.Contains(joined, "geosite-category-ads-all") {
				t.Fatal("广告规则关闭后不应生成 reject 规则")
			}
			if strings.Contains(joined, "geosite-google") && len(sets) != 1 {
				t.Fatalf("代理规则集未按配置生成: %+v", sets)
			}
			if strings.Contains(joined, "geosite-google") && rule["outbound"] != defaultCurrentSelector {
				t.Fatalf("代理规则集应指向 current selector: %+v", rule)
			}
		}
	}
	dns := doc["dns"].(map[string]any)
	dnsRules := dns["rules"].([]map[string]any)
	foundFakeIPFilter := false
	for _, rule := range dnsRules {
		if rule["server"] != "fakeip" || rule["type"] != "logical" {
			continue
		}
		parts := rule["rules"].([]map[string]any)
		for _, part := range parts {
			suffixes, ok := part["domain_suffix"].([]string)
			if !ok || part["invert"] != true {
				continue
			}
			if containsString(suffixes, "msftconnecttest.com") && containsString(suffixes, "msftncsi.com") {
				foundFakeIPFilter = true
			}
		}
	}
	if !foundFakeIPFilter {
		t.Fatal("未生成 no-fakeip 过滤规则")
	}
}

// TestBuildDynamicOutboundRouteRule 验证动态出口支持域名和 IP/CIDR。
func TestBuildDynamicOutboundRouteRule(t *testing.T) {
	domainRule, err := BuildDynamicOutboundRouteRule(DynamicOutboundRule{
		Match:    "domain:chatgpt.com",
		Outbound: "sub-main-jp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if domainRule["outbound"] != DynamicOutboundSelectorTag(DynamicOutboundRule{Match: "domain:chatgpt.com", Outbound: "sub-main-jp"}) {
		t.Fatalf("动态出口 outbound 错误: %+v", domainRule)
	}
	if strings.Join(domainRule["domain_suffix"].([]string), ",") != ".chatgpt.com" {
		t.Fatalf("动态出口域名后缀错误: %+v", domainRule)
	}
	plainDomainRule, err := BuildDynamicOutboundRouteRule(DynamicOutboundRule{
		Match:    "ipdata.co",
		Outbound: "sub-main-jp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(plainDomainRule["domain_suffix"].([]string), ",") != ".ipdata.co" {
		t.Fatalf("动态出口普通域名后缀错误: %+v", plainDomainRule)
	}
	ipRule, err := BuildDynamicOutboundRouteRule(DynamicOutboundRule{
		Match:    "8.8.8.8",
		Outbound: "sub-main-jp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ipRule["ip_cidr"].([]string), ",") != "8.8.8.8/32" {
		t.Fatalf("动态出口 IP 规则错误: %+v", ipRule)
	}
}

// TestBuildDynamicOutboundSelector 验证动态出口 selector 支持热切。
func TestBuildDynamicOutboundSelector(t *testing.T) {
	rule := DynamicOutboundRule{Match: "ipdata.co", Outbound: "sub-main-jp"}
	out := BuildDynamicOutboundSelector(rule, []string{"sub-main-jp", "sub-main-hk"})
	if out["type"] != "selector" || out["tag"] != DynamicOutboundSelectorTag(rule) {
		t.Fatalf("动态出口 selector 基础字段错误: %+v", out)
	}
	if out["default"] != "sub-main-jp" {
		t.Fatalf("动态出口 selector 默认值错误: %+v", out)
	}
}

// TestBuildWebApplyPlanHotSwitch 验证仅修改动态出口 backend 时不重启。
func TestBuildWebApplyPlanHotSwitch(t *testing.T) {
	before := Config{}
	before.Policy.Default = "sub-main-jp"
	before.Policy.DynamicOutbound = []DynamicOutboundRule{{Match: "ipdata.co", Outbound: "sub-main-jp"}}
	after := before
	after.Policy.Default = "sub-main-hk"
	after.Policy.DynamicOutbound = []DynamicOutboundRule{{Match: "ipdata.co", Outbound: "sub-main-hk"}}
	plan := BuildWebApplyPlan(before, "", "", after, "", "")
	if plan.Restart {
		t.Fatalf("仅切换动态出口 backend 不应重启: %+v", plan)
	}
	if plan.SelectorSwitches[defaultCurrentSelector] != "sub-main-hk" {
		t.Fatalf("当前出口热切计划错误: %+v", plan)
	}
	if plan.SelectorSwitches[DynamicOutboundSelectorTag(after.Policy.DynamicOutbound[0])] != "sub-main-hk" {
		t.Fatalf("动态出口热切计划错误: %+v", plan)
	}
}

// TestBuildDynamicGroupOutbound 验证动态组会生成 selector outbound。
func TestBuildDynamicGroupOutbound(t *testing.T) {
	out := BuildDynamicGroupOutbound(DynamicGroupBackend{
		Tag:     "group-main",
		Members: []string{"sub-main-jp", "sub-main-sg"},
		BestTag: "sub-main-sg",
	})
	if out["type"] != "selector" || out["tag"] != "group-main" {
		t.Fatalf("动态组 outbound 基础字段错误: %+v", out)
	}
	if out["default"] != "sub-main-sg" {
		t.Fatalf("动态组默认成员错误: %+v", out)
	}
}

// TestResolveMemberTagMapIncludesImports 验证导入节点能被动态组探测解析。
func TestResolveMemberTagMapIncludesImports(t *testing.T) {
	dir := t.TempDir()
	app := &App{SubscriptionDir: filepath.Join(dir, "sub")}
	if _, err := app.SaveSubscriptionCache("frank", []ProxyBackend{
		&HY2Backend{Key: "kr", Server: "kr.example", Port: 443, Password: "p"},
	}); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Backend: BackendConfig{Imports: []ImportedNodeGroup{{Key: "frank", Source: "clash"}}}}
	refs, err := app.ResolveMemberTagMap(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	if refs["import.frank.kr"] != "import-frank-kr" {
		t.Fatalf("导入节点引用解析错误: %+v", refs)
	}
}

// TestReferencedDynamicGroups 验证被当前出口和动态出口引用的组都会被探测。
func TestReferencedDynamicGroups(t *testing.T) {
	cfg := Config{}
	cfg.Policy.Default = "group-main"
	cfg.Policy.DynamicOutbound = []DynamicOutboundRule{{Match: "chatgpt.com", Outbound: "group-chat"}}
	cfg.Backend.Subscription = []Subscription{{Key: "sub", Default: "group-sub"}}
	cfg.Backend.Groups = []DynamicGroupConfig{
		{Key: "main", Members: []string{"static.a"}},
		{Key: "chat", Members: []string{"static.b"}},
		{Key: "sub", Members: []string{"static.c"}},
		{Key: "empty"},
	}
	groups := referencedDynamicGroups(cfg)
	var keys []string
	for _, group := range groups {
		keys = append(keys, group.Key)
	}
	if strings.Join(keys, ",") != "main,chat" {
		t.Fatalf("动态组引用收集错误: %v", keys)
	}
}

// TestEvaluateGroupBest 验证动态组按成功次数和平均延迟选择担当。
func TestEvaluateGroupBest(t *testing.T) {
	best := EvaluateGroupBest([]string{"a", "b"}, map[string][]GroupProbeRecord{
		"a": {
			{OK: true, DelayMS: 100},
			{OK: false},
			{OK: true, DelayMS: 120},
		},
		"b": {
			{OK: true, DelayMS: 20},
		},
	})
	if best != "a" {
		t.Fatalf("成功次数优先选择错误: %s", best)
	}
	best = EvaluateGroupBest([]string{"a", "b"}, map[string][]GroupProbeRecord{
		"a": {{OK: true, DelayMS: 100}},
		"b": {{OK: true, DelayMS: 20}},
	})
	if best != "b" {
		t.Fatalf("平均延迟选择错误: %s", best)
	}
}

// TestEvaluateGroupTargetPrimaryBackup 验证主备组优先主节点，主失败后才选备节点。
func TestEvaluateGroupTargetPrimaryBackup(t *testing.T) {
	group := DynamicGroupConfig{
		Key:     "main",
		Mode:    dynamicGroupModePrimaryBackup,
		Primary: "a",
		Members: []string{"a", "b", "c"},
	}
	best := EvaluateGroupTarget(group, map[string][]GroupProbeRecord{
		"a": {{OK: true, DelayMS: 300}},
		"b": {{OK: true, DelayMS: 20}},
		"c": {{OK: true, DelayMS: 30}},
	})
	if best != "a" {
		t.Fatalf("主节点成功时应该固定使用主节点: %s", best)
	}
	best = EvaluateGroupTarget(group, map[string][]GroupProbeRecord{
		"a": {{OK: false}},
		"b": {{OK: true, DelayMS: 80}},
		"c": {{OK: true, DelayMS: 20}},
	})
	if best != "c" {
		t.Fatalf("主节点失败时应该选择最优备节点: %s", best)
	}
	best = EvaluateGroupTarget(group, map[string][]GroupProbeRecord{
		"a": {
			{OK: true, DelayMS: 300},
			{OK: true, DelayMS: 310},
			{OK: true, DelayMS: 320},
		},
		"b": {{OK: true, DelayMS: 20}},
	})
	if best != "a" {
		t.Fatalf("主节点恢复后应该切回主节点: %s", best)
	}
	best = EvaluateGroupTarget(group, map[string][]GroupProbeRecord{
		"a": {
			{OK: true, DelayMS: 100},
			{OK: false},
			{OK: true, DelayMS: 110},
		},
		"b": {{OK: true, DelayMS: 20}},
	})
	if best != "a" {
		t.Fatalf("主节点最新一次恢复时应该回主节点: %s", best)
	}
	best = EvaluateGroupTarget(group, map[string][]GroupProbeRecord{
		"a": {
			{OK: false},
			{OK: false},
		},
		"b": {{OK: true, DelayMS: 80}},
		"c": {{OK: true, DelayMS: 20}},
	})
	if best != "c" {
		t.Fatalf("完整探测结束后主未恢复时应该选择最优备节点: %s", best)
	}
}

// TestEvaluatePrimaryBackupImmediateTarget 验证主节点单次失败后立刻选择可用备节点。
func TestEvaluatePrimaryBackupImmediateTarget(t *testing.T) {
	group := DynamicGroupConfig{
		Key:     "main",
		Mode:    dynamicGroupModePrimaryBackup,
		Primary: "a",
		Members: []string{"a", "b", "c"},
	}
	best := EvaluatePrimaryBackupImmediateTarget(group, map[string][]GroupProbeRecord{
		"a": {{OK: false}},
		"b": {{OK: true, DelayMS: 80}},
		"c": {{OK: true, DelayMS: 20}},
	})
	if best != "c" {
		t.Fatalf("主节点失败后应该立即选择最优备节点: %s", best)
	}
	best = EvaluatePrimaryBackupImmediateTarget(group, map[string][]GroupProbeRecord{
		"a": {{OK: false}},
		"b": {{OK: false}},
	})
	if best != "" {
		t.Fatalf("没有成功备节点时不应立即切换: %s", best)
	}
	best = EvaluatePrimaryBackupImmediateTarget(group, map[string][]GroupProbeRecord{
		"a": {{OK: true, DelayMS: 300}},
		"b": {{OK: true, DelayMS: 20}},
	})
	if best != "" {
		t.Fatalf("主节点成功时不应立即切换: %s", best)
	}
}

// TestNormalizeDynamicGroups 验证动态组 key 唯一且成员只保留有效引用。
func TestNormalizeDynamicGroups(t *testing.T) {
	got := NormalizeDynamicGroups([]DynamicGroupConfig{
		{Key: "main", Mode: dynamicGroupModePrimaryBackup, Primary: "static.jp", Members: []string{"static.jp", "bad", "static.jp"}},
		{Key: "main", Members: []string{"sub.main.jp"}},
	}, map[string]bool{
		"static.jp":   true,
		"sub.main.jp": true,
	})
	if got[0].Key != "main" || got[1].Key != "main-2" {
		t.Fatalf("动态组 key 未唯一化: %+v", got)
	}
	if strings.Join(got[0].Members, ",") != "static.jp" {
		t.Fatalf("动态组成员过滤错误: %+v", got[0].Members)
	}
	if got[0].Mode != dynamicGroupModePrimaryBackup || got[0].Primary != "static.jp" {
		t.Fatalf("动态组主备字段错误: %+v", got[0])
	}
}

// TestNormalizeDynamicGroupsForSave 验证 Web 保存时重复 key 和错误主节点会被拒绝。
func TestNormalizeDynamicGroupsForSave(t *testing.T) {
	_, err := NormalizeDynamicGroupsForSave([]DynamicGroupConfig{
		{Key: "main", Members: []string{"static.jp"}},
		{Key: "MAIN", Members: []string{"sub.main.jp"}},
	}, map[string]bool{
		"static.jp":   true,
		"sub.main.jp": true,
	})
	if err == nil {
		t.Fatal("重复动态组 key 应该报错")
	}
	_, err = NormalizeDynamicGroupsForSave([]DynamicGroupConfig{
		{Key: "main", Mode: dynamicGroupModePrimaryBackup, Primary: "sub.main.jp", Members: []string{"static.jp"}},
	}, map[string]bool{"static.jp": true, "sub.main.jp": true})
	if err == nil {
		t.Fatal("主备动态组主节点不在成员列表应该报错")
	}
	_, err = NormalizeDynamicGroupsForSave([]DynamicGroupConfig{
		{Key: "main", Members: []string{"bad"}},
	}, map[string]bool{"static.jp": true})
	if err == nil {
		t.Fatal("动态组成员不存在应该报错")
	}
	got, err := NormalizeDynamicGroupsForSave([]DynamicGroupConfig{
		{Key: "Main", Mode: dynamicGroupModePrimaryBackup, Primary: "static.jp", Members: []string{"static.jp", "static.jp"}},
	}, map[string]bool{"static.jp": true})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Key != "main" || strings.Join(got[0].Members, ",") != "static.jp" {
		t.Fatalf("动态组保存清洗错误: %+v", got)
	}
	if got[0].Mode != dynamicGroupModePrimaryBackup || got[0].Primary != "static.jp" {
		t.Fatalf("动态组保存主备字段错误: %+v", got[0])
	}
}

// TestSaveWebStateConfigConflict 验证保存时会拒绝旧 hash 覆盖新配置。
func TestSaveWebStateConfigConflict(t *testing.T) {
	dir := t.TempDir()
	app := &App{
		ConfigPath:      filepath.Join(dir, "config.yaml"),
		ForceProxyPath:  filepath.Join(dir, "force_proxy.list"),
		ForceDirectPath: filepath.Join(dir, "force_direct.list"),
		GeoDir:          filepath.Join(dir, "geo"),
		SubscriptionDir: filepath.Join(dir, "sub"),
		GroupRuntime:    NewGroupRuntime(),
	}
	cfg := DefaultConfig()
	cfg.Backend.Static = []StaticBackend{{Protocol: "hy2", Key: "jp", Name: "jp", Server: "example.com", Port: 443, Password: "p"}}
	cfg.Policy.Default = RuntimeBackendTag("static", "jp")
	if err := SaveConfig(app.ConfigPath, cfg); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicFile(app.ForceProxyPath, []byte("domain:example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicFile(app.ForceDirectPath, nil, 0644); err != nil {
		t.Fatal(err)
	}
	oldHash, err := app.ConfigHash()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicFile(app.ForceProxyPath, []byte("domain:example.org\n"), 0644); err != nil {
		t.Fatal(err)
	}
	err = app.SaveWebState(WebSaveRequest{
		ActiveOutbound: RuntimeBackendTag("static", "jp"),
		ConfigHash:     oldHash,
		ForceProxy:     "domain:example.net\n",
	})
	var conflict ConfigConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("旧 hash 保存应返回冲突: %v", err)
	}
	if conflict.CurrentHash == "" || conflict.CurrentHash == oldHash {
		t.Fatalf("冲突 hash 不正确: %+v", conflict)
	}
}

// TestSingBoxPIDsFromProc 验证 /proc 扫描只返回 sing-box 进程。
func TestSingBoxPIDsFromProc(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"100": "/usr/bin/sing-box",
		"101": "/bin/ash",
		"102": "/usr/bin/sing-box",
		"abc": "/usr/bin/sing-box",
	}
	for name, exe := range cases {
		proc := filepath.Join(dir, name)
		if err := os.Mkdir(proc, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(exe, filepath.Join(proc, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	got, err := singBoxPIDsFromProc(dir, 102)
	if err != nil {
		t.Fatal(err)
	}
	sort.Ints(got)
	if strings.Trim(strings.ReplaceAll(fmt.Sprint(got), " ", ","), "[]") != "100" {
		t.Fatalf("sing-box pid 扫描错误: %+v", got)
	}
}

// TestCleanupTunNetworkScriptCoversAggressivePaths 验证强制清理脚本覆盖关键网络残留面。
func TestCleanupTunNetworkScriptCoversAggressivePaths(t *testing.T) {
	script := CleanupTunNetworkScript()
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("清理脚本语法错误: %v\n%s", err, output)
	}
	required := []string{
		"pkill -KILL -x sing-box",
		"nft delete table \"$family\" sing-box",
		"/etc/nftables.d/0-sing-box-auto-redirect.nft",
		"sing-box-output",
		"ip -4 route flush table",
		"ip \"$fam\" rule del pref",
		"resolvectl revert",
		"ip link del",
		"conntrack -F",
		"systemctl restart NetworkManager",
	}
	for _, item := range required {
		if !strings.Contains(script, item) {
			t.Fatalf("清理脚本缺少关键片段 %q", item)
		}
	}
}

// TestCleanupAutoRedirectRouteResidueScriptIsNarrow 验证启动前清理只匹配 auto_redirect 指纹。
func TestCleanupAutoRedirectRouteResidueScriptIsNarrow(t *testing.T) {
	script := CleanupAutoRedirectRouteResidueScript()
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("auto_redirect 清理脚本语法错误: %v\n%s", err, output)
	}
	required := []string{
		`$1 == "1:"`,
		`grep -Eq "^local ${loopback}([ /]|$)"`,
		`ip "$fam" route flush table "$table"`,
		`ip "$fam" rule del pref 1 table "$table"`,
	}
	for _, item := range required {
		if !strings.Contains(script, item) {
			t.Fatalf("auto_redirect 清理脚本缺少保护片段 %q", item)
		}
	}
	forbidden := []string{
		"ip route flush cache",
		"nft delete table",
		"iptables",
		"pkill",
		"ip link del",
	}
	for _, item := range forbidden {
		if strings.Contains(script, item) {
			t.Fatalf("auto_redirect 清理脚本不应包含高风险片段 %q", item)
		}
	}
}
