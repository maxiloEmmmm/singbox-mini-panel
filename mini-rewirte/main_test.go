package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

// staticResolver 适用于测试时固定域名解析结果。
type staticResolver struct {
	// addr 是测试返回的固定 IP。
	addr string
	// calls 是测试中累计解析次数。
	calls int
}

// LookupNetIP 返回测试固定 IP，避免单元测试依赖外部 DNS。
func (r *staticResolver) LookupNetIP(ctx context.Context, network string, host string) ([]netip.Addr, error) {
	r.calls++
	addr, err := netip.ParseAddr(r.addr)
	if err != nil {
		return nil, err
	}
	return []netip.Addr{addr}, nil
}

// TestSplitHostPortDefault 验证 Host 解析能兼容带端口和无端口场景。
func TestSplitHostPortDefault(t *testing.T) {
	host, port, err := splitHostPortDefault("example.com:8080", "80")
	if err != nil {
		t.Fatalf("split failed: %v", err)
	}
	if host != "example.com" || port != "8080" {
		t.Fatalf("unexpected split result: %s %s", host, port)
	}
	host, port, err = splitHostPortDefault("example.com", "80")
	if err != nil {
		t.Fatalf("split fallback failed: %v", err)
	}
	if host != "example.com" || port != "80" {
		t.Fatalf("unexpected fallback result: %s %s", host, port)
	}
}

// TestProxyHandlerRewritesHostToIP 验证代理会把请求 Host 改成解析后的 IP。
func TestProxyHandlerRewritesHostToIP(t *testing.T) {
	upstreamHost := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		upstreamHost <- req.Host
		rw.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	_, upstreamPort, err := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	if err != nil {
		t.Fatalf("split upstream failed: %v", err)
	}
	handler := &proxyHandler{
		client:   upstream.Client(),
		resolver: &staticResolver{addr: "127.0.0.1"},
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.com:"+upstreamPort+"/", nil)
	req.Host = "example.com:" + upstreamPort
	req = req.WithContext(context.Background())

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("unexpected status: %d", recorder.Code)
	}
	got := <-upstreamHost
	if got != "127.0.0.1:"+upstreamPort && got != "[::1]:"+upstreamPort {
		t.Fatalf("host was not rewritten to ip: %s", got)
	}
}

// TestProxyHandlerRewritesOriginFormHost 验证 sing-box 静态跳转后的 origin-form 请求。
func TestProxyHandlerRewritesOriginFormHost(t *testing.T) {
	upstreamHost := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		upstreamHost <- req.Host
		rw.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	_, upstreamPort, err := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	if err != nil {
		t.Fatalf("split upstream failed: %v", err)
	}
	handler := &proxyHandler{
		client:   upstream.Client(),
		resolver: &staticResolver{addr: "127.0.0.1"},
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "example.com:" + upstreamPort

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("unexpected status: %d", recorder.Code)
	}
	got := <-upstreamHost
	if got != "127.0.0.1:"+upstreamPort && got != "[::1]:"+upstreamPort {
		t.Fatalf("host was not rewritten to ip: %s", got)
	}
}

// TestRewriteTargetKeepsRequestPort 验证代理保留原请求端口。
func TestRewriteTargetKeepsRequestPort(t *testing.T) {
	handler := &proxyHandler{
		client:   http.DefaultClient,
		resolver: &staticResolver{addr: "47.245.88.42"},
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.com:1234/", nil)
	req.Host = "example.com:1234"
	target, err := handler.rewriteTarget(req)
	if err != nil {
		t.Fatalf("rewrite target failed: %v", err)
	}
	if target != "47.245.88.42:1234" {
		t.Fatalf("unexpected target: %s", target)
	}
}

// TestRewriteTargetDomainOverrideWins 验证 -domain 优先于请求 Host。
func TestRewriteTargetDomainOverrideWins(t *testing.T) {
	handler := &proxyHandler{
		client:   http.DefaultClient,
		resolver: &staticResolver{addr: "47.245.88.42"},
		override: overrideTarget{Host: "example.com"},
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "wrong.example:1234"
	target, err := handler.rewriteTarget(req)
	if err != nil {
		t.Fatalf("rewrite target failed: %v", err)
	}
	if target != "47.245.88.42:1234" {
		t.Fatalf("unexpected target: %s", target)
	}
}

// TestRewriteTargetDomainOverridePortWins 验证 -domain 带端口时也覆盖请求端口。
func TestRewriteTargetDomainOverridePortWins(t *testing.T) {
	handler := &proxyHandler{
		client:   http.DefaultClient,
		resolver: &staticResolver{addr: "47.245.88.42"},
		override: overrideTarget{
			Host: "example.com",
			Port: "8080",
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "wrong.example:1234"
	target, err := handler.rewriteTarget(req)
	if err != nil {
		t.Fatalf("rewrite target failed: %v", err)
	}
	if target != "47.245.88.42:8080" {
		t.Fatalf("unexpected target: %s", target)
	}
}

// TestOverrideDomainCache 验证固定 domain 模式会缓存解析结果。
func TestOverrideDomainCache(t *testing.T) {
	resolver := &staticResolver{addr: "47.245.88.42"}
	handler := &proxyHandler{
		client:   http.DefaultClient,
		resolver: resolver,
		override: overrideTarget{Host: "example.com"},
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "wrong.example:1234"
	if _, err := handler.rewriteTarget(req); err != nil {
		t.Fatalf("first rewrite failed: %v", err)
	}
	if _, err := handler.rewriteTarget(req); err != nil {
		t.Fatalf("second rewrite failed: %v", err)
	}
	if resolver.calls != 1 {
		t.Fatalf("unexpected resolver calls: %d", resolver.calls)
	}
}

// TestOverrideDomainPriority 验证命令行域名优先于环境变量域名。
func TestOverrideDomainPriority(t *testing.T) {
	got := parseOverrideTarget(firstNonEmpty("flag.example.com", "env.example.com"))
	if got.Host != "flag.example.com" || got.Port != "" {
		t.Fatalf("flag domain should win: %+v", got)
	}
	got = parseOverrideTarget(firstNonEmpty("", "env.example.com:8080"))
	if got.Host != "env.example.com" || got.Port != "8080" {
		t.Fatalf("env domain should be used with port: %+v", got)
	}
}

// TestProxyHandlerRejectsConnect 验证代理拒绝 HTTPS CONNECT 隧道。
func TestProxyHandlerRejectsConnect(t *testing.T) {
	handler := &proxyHandler{
		client:   http.DefaultClient,
		resolver: &staticResolver{addr: "47.245.88.42"},
	}
	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443/", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unexpected status: %d", recorder.Code)
	}
}

// TestRewriteTargetRejectsHTTPS 验证代理只接受明文 http scheme。
func TestRewriteTargetRejectsHTTPS(t *testing.T) {
	handler := &proxyHandler{
		client:   http.DefaultClient,
		resolver: &staticResolver{addr: "47.245.88.42"},
	}
	req := httptest.NewRequest(http.MethodGet, "https://example.com:443/", nil)
	_, err := handler.rewriteTarget(req)
	if err == nil {
		t.Fatal("expected scheme error")
	}
}
