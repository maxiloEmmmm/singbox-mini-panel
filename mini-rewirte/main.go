package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	defaultListenAddr = "0.0.0.0:10820"
	defaultTimeout    = 30 * time.Second
	defaultCacheTTL   = 120 * time.Second
	envDomainName     = "MINI_DOMAIN"
)

// proxyHandler 适用于明文 HTTP 改写，支持代理请求和普通服务端请求。
type proxyHandler struct {
	// client 是访问上游 HTTP 服务的客户端。
	client *http.Client
	// resolver 是域名解析器，默认使用系统解析行为。
	resolver ipResolver
	// override 是强制解析和改写 Host 的目标，空值时使用请求 Host。
	override overrideTarget
	// cachedAddr 是近期解析得到的 IP，适用于单一 domain 场景。
	cachedAddr netip.Addr
	// cacheExpiresAt 是 cachedAddr 的过期时间。
	cacheExpiresAt time.Time
}

// overrideTarget 表示命令行或环境变量指定的强制上游目标。
type overrideTarget struct {
	// Host 是强制用于解析的域名或 IP。
	Host string
	// Port 是强制使用的端口，空值时使用请求端口。
	Port string
}

// ipResolver 适用于抽象 DNS 解析，便于测试固定解析结果。
type ipResolver interface {
	// LookupNetIP 返回指定域名的 IP 列表。
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// main 初始化监听地址和 HTTP 代理服务。
func main() {
	listen := flag.String("listen", defaultListenAddr, "listen address")
	domain := flag.String("domain", "", "override upstream host domain")
	flag.Parse()

	overrideDomain := firstNonEmpty(*domain, os.Getenv(envDomainName))
	server := &http.Server{
		Addr:         *listen,
		Handler:      newProxyHandler(overrideDomain),
		ReadTimeout:  defaultTimeout,
		WriteTimeout: defaultTimeout,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Printf("mini-rewirte http_proxy listening on http://%s", *listen)
		errCh <- server.ListenAndServe()
	}()

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-signalCh:
		log.Printf("shutting down: %s", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Fatalf("shutdown failed: %v", err)
		}
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server failed: %v", err)
		}
	}
}

// newProxyHandler 创建 HTTP 代理处理器。
func newProxyHandler(domain string) *proxyHandler {
	return &proxyHandler{
		client:   &http.Client{Timeout: defaultTimeout},
		resolver: net.DefaultResolver,
		override: parseOverrideTarget(domain),
	}
}

// ServeHTTP 接收明文 HTTP 请求，改写 Host 后转发到解析出的 IP。
func (h *proxyHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		http.Error(rw, "CONNECT is not supported", http.StatusMethodNotAllowed)
		return
	}
	target, err := h.rewriteTarget(req)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	outReq, err := h.newUpstreamRequest(req, target)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	resp, err := h.client.Do(outReq)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeaders(rw.Header(), resp.Header)
	rw.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(rw, resp.Body); err != nil {
		log.Printf("copy response failed: %v", err)
	}
}

// rewriteTarget 根据请求 URL 或 Host 头构造上游 ip:port 目标。
func (h *proxyHandler) rewriteTarget(req *http.Request) (string, error) {
	if req.URL == nil {
		return "", errors.New("missing request URL")
	}
	if req.URL.Scheme != "" && req.URL.Scheme != "http" {
		return "", fmt.Errorf("only http scheme is supported: %s", req.URL.Scheme)
	}
	host := strings.TrimSpace(req.URL.Host)
	if host == "" {
		// 触发条件：sing-box override_address 转入本地端口后。
		// 不能依赖 absolute-form URL，因为此时是普通 HTTP origin-form。
		// 防止静态跳转场景因 URL scheme 为空被拒绝。
		host = strings.TrimSpace(req.Host)
	}
	if host == "" {
		return "", errors.New("missing target host")
	}
	name, port, err := splitHostPortDefault(host, "80")
	if err != nil {
		return "", err
	}
	if h.override.Host != "" {
		// 触发条件：用户通过 -domain 指定固定上游域名。
		// 不能继续使用请求 Host，否则 sing-box 改写场景仍受原 Host 影响。
		// 防止请求 Host 被污染时解析到错误上游或端口。
		name = h.override.Host
		if h.override.Port != "" {
			port = h.override.Port
		}
	}
	addr, err := h.resolveFirstIP(req.Context(), name)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(addr.String(), port), nil
}

// newUpstreamRequest 把代理请求改成 origin-form，并把上游 Host 改成 ip:port。
func (h *proxyHandler) newUpstreamRequest(req *http.Request, target string) (*http.Request, error) {
	if req.URL == nil {
		return nil, errors.New("missing request URL")
	}
	upstreamURL := *req.URL
	upstreamURL.Scheme = "http"
	upstreamURL.Host = target
	upstreamURL.User = nil
	outReq, err := http.NewRequestWithContext(req.Context(), req.Method, upstreamURL.String(), req.Body)
	if err != nil {
		return nil, err
	}
	copyHeaders(outReq.Header, req.Header)
	outReq.Header.Del("Proxy-Connection")
	outReq.Header.Del("Proxy-Authorization")
	outReq.Host = target
	outReq.RequestURI = ""
	return outReq, nil
}

// resolveFirstIP 解析域名并返回第一个可用 IP，IP 字面量会直接返回。
func (h *proxyHandler) resolveFirstIP(ctx context.Context, name string) (netip.Addr, error) {
	name = strings.TrimSpace(name)
	if addr, err := netip.ParseAddr(strings.Trim(name, "[]")); err == nil {
		return addr, nil
	}
	useCache := h.override.Host != ""
	if useCache && h.cachedAddr.IsValid() && time.Now().Before(h.cacheExpiresAt) {
		return h.cachedAddr, nil
	}
	addrs, err := h.resolver.LookupNetIP(ctx, "ip", name)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, addr := range addrs {
		if addr.Is4() || addr.Is6() {
			if useCache {
				h.cachedAddr = addr
				h.cacheExpiresAt = time.Now().Add(defaultCacheTTL)
			}
			return addr, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no ip found for %s", name)
}

// splitHostPortDefault 拆分 host 和端口，缺省端口按 fallback 返回。
func splitHostPortDefault(value string, fallback string) (string, string, error) {
	host := strings.TrimSpace(value)
	if host == "" {
		return "", "", errors.New("empty host")
	}
	if strings.Contains(host, "://") {
		return "", "", errors.New("host must not include scheme")
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		return strings.Trim(h, "[]"), p, nil
	}
	if strings.Count(host, ":") > 1 {
		trimmed := strings.Trim(host, "[]")
		if _, err := netip.ParseAddr(trimmed); err == nil {
			return trimmed, fallback, nil
		}
		return "", "", fmt.Errorf("invalid host: %s", value)
	}
	if h, p, ok := strings.Cut(host, ":"); ok {
		return h, p, nil
	}
	return host, fallback, nil
}

// parseOverrideTarget 解析 -domain 或 MINI_DOMAIN，端口存在时也强制覆盖。
func parseOverrideTarget(value string) overrideTarget {
	host := strings.TrimSpace(value)
	if host == "" {
		return overrideTarget{}
	}
	if strings.Contains(host, "://") {
		parsedHost := strings.TrimPrefix(host, "http://")
		if h, p, err := splitHostPortDefault(parsedHost, ""); err == nil {
			return overrideTarget{Host: h, Port: p}
		}
		return overrideTarget{Host: host}
	}
	if h, p, err := splitHostPortDefault(host, ""); err == nil {
		return overrideTarget{Host: h, Port: p}
	}
	return overrideTarget{Host: strings.Trim(host, "[]")}
}

// firstNonEmpty 返回第一段非空文本，适用于配置优先级选择。
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// copyHeaders 复制 HTTP header，适用于请求和响应转发。
func copyHeaders(dst http.Header, src http.Header) {
	for key, values := range src {
		dst.Del(key)
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}
