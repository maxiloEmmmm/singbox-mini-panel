package main

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// TestParseHostsDomains 适用于验证 hosts 文件域名提取逻辑。
func TestParseHostsDomains(t *testing.T) {
	content := strings.Join([]string{
		"# ignored",
		"127.0.0.1 localhost localhost.localdomain",
		"not-ip ignored.example",
		"192.0.2.33 app.example.test app.example.test.",
		"::1 ip6-localhost # inline comment",
		"192.0.2.34 app.example.test",
	}, "\n")

	got, err := ParseHostsDomains(strings.NewReader(content))
	if err != nil {
		t.Fatalf("ParseHostsDomains() error = %v", err)
	}

	want := []string{
		"localhost",
		"localhost.localdomain",
		"app.example.test",
		"ip6-localhost",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseHostsDomains() = %#v, want %#v", got, want)
	}
}

// TestBuildHostsResolveRouteRule 适用于验证 hosts 域名会生成路由解析规则。
func TestBuildHostsResolveRouteRule(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "hosts")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	if _, err := file.WriteString("192.0.2.33 app.example.test\n"); err != nil {
		t.Fatalf("WriteString() error = %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	got, err := BuildHostsResolveRouteRule(file.Name())
	if err != nil {
		t.Fatalf("BuildHostsResolveRouteRule() error = %v", err)
	}

	want := map[string]any{
		"action": "resolve",
		"domain": []string{"app.example.test"},
		"server": defaultHostsDNSTag,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("BuildHostsResolveRouteRule() = %#v, want %#v", got, want)
	}
}

// TestNormalizeProbeURL 适用于验证 Web 临时探测 URL 的清洗规则。
func TestNormalizeProbeURL(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "default", raw: "", want: defaultProbeURL},
		{name: "https", raw: " https://example.com/ping ", want: "https://example.com/ping"},
		{name: "http", raw: "http://example.com/generate_204", want: "http://example.com/generate_204"},
		{name: "missing scheme", raw: "example.com/ping", wantErr: true},
		{name: "ftp", raw: "ftp://example.com/ping", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeProbeURL(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NormalizeProbeURL() error = nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeProbeURL() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("NormalizeProbeURL() = %q, want %q", got, tc.want)
			}
		})
	}
}
