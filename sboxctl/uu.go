package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// uuStatus contains the non-sensitive fields returned in the ordinary panel state.
type uuStatus struct {
	// Auth is the current sign-in state.
	Auth string `json:"auth"`
	// Connection is the current state of this outbound's carrier.
	Connection string `json:"connection"`
}

// uuSocketPath locates the Unix API published by sing-box-x, e.g. static-home -> its tagged socket.
func uuSocketPath(tag string) string {
	dir := os.Getenv("SBOXCTL_UU_RUNTIME_DIR")
	if dir == "" {
		dir = "/run/sboxctl/uu-outbound"
	}
	digest := sha256.Sum256([]byte(tag))
	return filepath.Join(dir, hex.EncodeToString(digest[:12])+".sock")
}

// requestUU calls one owner-only local API, e.g. GET /devices -> the account's device list.
func requestUU(ctx context.Context, tag, method, path string) (int, []byte, error) {
	socket := uuSocketPath(tag)
	dialer := net.Dialer{}
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socket)
		},
	}
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://uu"+path, nil)
	if err != nil {
		return 0, nil, err
	}
	reply, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer reply.Body.Close()
	body, err := io.ReadAll(io.LimitReader(reply.Body, (1<<20)+1))
	if err != nil {
		return 0, nil, err
	}
	if len(body) > 1<<20 || !json.Valid(body) {
		return 0, nil, errors.New("UU 接口响应无效")
	}
	return reply.StatusCode, body, nil
}

// handleUU bridges the authenticated UI to a saved UU outbound, e.g. POST /api/uu/login?tag=static-home.
func (w *WebServer) handleUU(rw http.ResponseWriter, req *http.Request) {
	path := strings.TrimPrefix(req.URL.Path, "/api/uu")
	if !((req.Method == http.MethodGet && (path == "/status" || path == "/devices")) ||
		(req.Method == http.MethodPost && path == "/login")) {
		writeJSON(rw, http.StatusNotFound, map[string]string{"error": "UU 接口不存在"})
		return
	}
	tag := req.URL.Query().Get("tag")
	cfg, err := w.App.LoadConfig()
	if err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": "无法读取 UU 节点配置"})
		return
	}
	profile := req.URL.Query().Get("profile")
	saved := tag == uuCenterTag && hasUUCenter(cfg) && hasUUProfile(cfg.UU, profile)
	for _, node := range cfg.Backend.Static {
		if profile == "" && normalizeStaticProtocol(node.Protocol) == staticProtocolUU && RuntimeBackendTag("static", node.Key) == tag {
			saved = true
			break
		}
	}
	if !saved {
		writeJSON(rw, http.StatusNotFound, map[string]string{"error": "请先保存并应用 UU 配置"})
		return
	}

	if profile != "" {
		path += "?profile=" + url.QueryEscape(profile)
	}
	ctx, cancel := context.WithTimeout(req.Context(), 12*time.Second)
	defer cancel()
	status, body, err := requestUU(ctx, tag, req.Method, path)
	rw.Header().Set("Cache-Control", "no-store")
	if err != nil {
		writeJSON(rw, http.StatusServiceUnavailable, map[string]string{"error": "UU 模块未就绪，请检查配置应用状态"})
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	_, _ = rw.Write(body)
}

// applyUUStatuses fills panel status without copying temporary QR credentials into /api/state.
func applyUUStatuses(nodes []WebBackend) {
	ctx, cancel := context.WithTimeout(context.Background(), 450*time.Millisecond)
	defer cancel()
	for index := range nodes {
		node := &nodes[index]
		if node.Protocol != staticProtocolUU {
			continue
		}
		code, body, err := requestUU(ctx, node.Tag, http.MethodGet, "/status")
		var status uuStatus
		if err == nil && code == http.StatusOK && json.Unmarshal(body, &status) == nil {
			node.UUAuth, node.UUConnection = status.Auth, status.Connection
		}
	}
}

// uuCenterTag is the single control endpoint shared by all UU roles.
const uuCenterTag = "uu-host"

// UUConfig stores the global receiver and the named controller profiles.
type UUConfig struct {
	// HostEnabled publishes the local mixed port as a UU receiver.
	HostEnabled bool `yaml:"host_enabled,omitempty" json:"host_enabled"`
	// HostAccount reuses a connection account; empty selects the receiver's independent login.
	HostAccount string `yaml:"host_account,omitempty" json:"host_account"`
	// Accounts are additional connection accounts, beyond the built-in default.
	Accounts []UUAccount `yaml:"accounts,omitempty" json:"accounts"`
}

// UUAccount names one configurable connection account.
type UUAccount struct {
	// Key is the stable profile key used by static UU nodes.
	Key string `yaml:"key" json:"key"`
	// Name is the account label shown in the panel.
	Name string `yaml:"name" json:"name"`
}

// hasUUCenter reports whether to start the auth center, e.g. one legacy UU node -> true.
func hasUUCenter(cfg Config) bool {
	if cfg.UU.HostEnabled || cfg.UU.HostAccount != "" || len(cfg.UU.Accounts) > 0 {
		return true
	}
	for _, node := range cfg.Backend.Static {
		if normalizeStaticProtocol(node.Protocol) == staticProtocolUU {
			return true
		}
	}
	return false
}

// hasUUProfile looks up a controller account, including the legacy default.
func hasUUProfile(cfg UUConfig, key string) bool {
	if key == "" || key == "default" {
		return true
	}
	for _, profile := range cfg.Accounts {
		if profile.Key == key {
			return true
		}
	}
	return false
}

// normalizeUUConfig validates saved account references and the receiver's loopback target.
func normalizeUUConfig(cfg *Config) error {
	profiles := make([]UUAccount, 0, len(cfg.UU.Accounts))
	seen := map[string]bool{"default": true, "host": true}
	for _, profile := range cfg.UU.Accounts {
		key, name := strings.TrimSpace(profile.Key), strings.TrimSpace(profile.Name)
		if key == "" || len(key) > 64 || strings.ContainsFunc(key, func(c rune) bool {
			return !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_')
		}) || seen[key] {
			return errors.New("UU 连接账号 key 无效或已使用")
		}
		seen[key] = true
		profiles = append(profiles, UUAccount{Key: key, Name: firstNonEmpty(name, key)})
	}
	if len(profiles) == 0 {
		profiles = nil
	}
	cfg.UU.Accounts = profiles
	cfg.UU.HostAccount = strings.TrimSpace(cfg.UU.HostAccount)
	if !hasUUProfile(cfg.UU, cfg.UU.HostAccount) {
		return errors.New("UU 接收端选择的连接账号不存在")
	}
	for _, node := range cfg.Backend.Static {
		if normalizeStaticProtocol(node.Protocol) == staticProtocolUU && !hasUUProfile(cfg.UU, node.UUAccount) {
			return fmt.Errorf("UU 节点 %s 选择的连接账号不存在", node.Key)
		}
	}
	if cfg.UU.HostEnabled {
		if cfg.Inbound.Mode != "both" && cfg.Inbound.Mode != "mixed" {
			return errors.New("开启 UU 接收需要启用 Mixed 入站")
		}
		if cfg.Inbound.Mixed.Listen != "" && cfg.Inbound.Mixed.Listen != "0.0.0.0" && cfg.Inbound.Mixed.Listen != "127.0.0.1" && cfg.Inbound.Mixed.Listen != "::" {
			return errors.New("UU 接收需要 Mixed 入站能从 127.0.0.1 访问")
		}
	}
	return nil
}

// buildUUService renders one global service, e.g. an enabled receiver -> the mixed port.
func buildUUService(cfg Config) (map[string]any, error) {
	if !hasUUCenter(cfg) {
		return nil, nil
	}
	if err := normalizeUUConfig(&cfg); err != nil {
		return nil, err
	}
	options := map[string]any{"type": "uu", "tag": uuCenterTag}
	if cfg.UU.HostEnabled {
		options["local_port"] = cfg.Inbound.Mixed.Port
	}
	if cfg.UU.HostAccount != "" {
		options["host_account"] = cfg.UU.HostAccount
	}
	var profiles []string
	for _, profile := range cfg.UU.Accounts {
		profiles = append(profiles, profile.Key)
	}
	if len(profiles) > 0 {
		options["accounts"] = profiles
	}
	return options, nil
}
