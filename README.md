# sboxctl

`sboxctl` 是面向 OpenWrt 路由器的 sing-box 编排工具。

<p align="center">
  <strong>OpenWrt sing-box control plane</strong><br />
  管理订阅、geofiles、动态出口、FakeIP DNS 和内嵌 Web 面板，把路由器上的 sing-box 数据面收进一个可维护的控制面。
</p>

```text
config.yaml | subscription cache | geofiles | generated sing-box config | managed sing-box process
```

## 产品定位

路由器上的代理配置通常会散在订阅脚本、规则下载、手写配置、init.d 服务、日志文件和临时命令里。`sboxctl` 把这些动作收敛成一个小型控制面：它生成 sing-box 配置、托管 sing-box 进程、维护规则缓存，并提供一个内网 Web 面板做日常操作。

它不是通用代理客户端，也不是桌面 GUI。它的主要目标是让 OpenWrt 上的 sing-box 长期运行时更容易更新、观察和回滚。

## 运行模型

`sboxctl` 自己托管 sing-box 子进程：

```text
sboxctl daemon/start/restart
  -> 读取 /etc/sboxctl/config.yaml
  -> 补齐缺失 geofiles 和订阅缓存
  -> 生成 /etc/sing-box/config.json
  -> 停止旧 sing-box
  -> 启动 sing-box run -c <config> -D <workdir>
```

默认使用 `/usr/bin/sing-box` 和 `/usr/share/sing-box`。如果 `sboxctl` 二进制同级目录存在可执行的 `sing-box`，会优先使用同级二进制，并把同级目录作为 sing-box 工作目录。

没有任何可用 backend 时，控制面仍会启动；只是不启动 sing-box 数据面。

## 主要工作流

### 管理入口

默认入口是 TUN，全局接管局域网客户端流量。也可以切到 mixed 模式，对外提供 socks/http 混合端口。

ICMP 会直连，ping 只用于判断连通性，不代表 TCP/HTTPS 代理路径。

### 管理节点和订阅

支持静态节点和订阅节点混用：

- Hysteria2
- VMess
- Shadowsocks
- Trojan
- AnyTLS

Trojan 支持静态节点和订阅 URI。静态节点可配置 TLS、SNI、跳过证书校验，以及 WebSocket transport 的 path 和 Host。
AnyTLS 支持静态节点和订阅 URI。静态节点可配置 SNI、跳过证书校验，以及空闲会话检查参数。

订阅默认 UA 是 `sing-box/1.13.12`。订阅更新失败不会覆盖旧缓存；启动时没有新缓存会尝试补齐，普通更新失败会保留已有可用状态。

### DNS 和 FakeIP

DNS 结构贴近 v2rayN 的 sing-box 配置口径，但不启用 IPv6 FakeIP。

- `local-dns` 和 `direct-dns` 默认使用 `119.29.29.29`
- `remote-dns` 使用 Cloudflare DoH，并通过当前代理出口解析
- `/etc/hosts` 通过 hosts DNS server 接入，前端可开关，默认开启
- FakeIP 只处理 A 查询，范围是 `198.18.0.0/15`
- HTTPS/SVCB 查询返回 `NOERROR`，避免浏览器绕开 FakeIP 机制

### 规则和路由

规则来源有四类：

- 内置 direct 基础规则
- geofiles rule-set
- 强制代理和强制直连本地文本规则
- 动态出口规则

本地规则一行一个：

```text
domain:example.com
src:10.0.0.0/8
dst:203.0.113.10
```

`domain:example.com` 会匹配 `example.com` 和它的子域名。

### 动态组

动态组在 sing-box 中表现为一个 selector outbound，成员引用静态节点或订阅节点。

```yaml
backend:
  groups:
    - key: main
      mode: dynamic
      members:
        - sub.main.jp-hy2
        - sub.main.sg-hy2
```

动态组只探测被配置引用的组。当前引用来源是：

- `policy.default`
- `policy.dynamic_outbound[].outbound`

探测周期是 5 分钟。每轮对成员做 3 次探测，间隔为 `5s`、`30s`、`60s`，目标是 `https://www.google.com/generate_204`。

`dynamic` 模式按成功次数和平均延迟择优。`primary_backup` 模式优先主节点，主节点最近窗口内出现失败后切到备节点，主恢复后切回。

### Web 面板

daemon 模式会启动内嵌 Web 面板：

```text
http://<router-ip>:9000
```

第一次进入时如果没有账号密码，会进入初始化页面。账号密码保存在本机配置文件里，适合内网自用。

Web 面板可以管理静态节点、订阅、动态组、geofiles、hosts DNS 开关、强制规则、动态出口规则，并展示生成后的 sing-box JSON。

## 配置模型

默认路径：

```text
/etc/sboxctl/config.yaml
/etc/sboxctl/force_proxy.list
/etc/sboxctl/force_direct.list
/etc/sboxctl/geofiles/
/etc/sboxctl/subscriptions/
/etc/sing-box/config.json
/var/log/sboxctl/
```

初始化：

```bash
sboxctl init
```

常用命令：

```bash
sboxctl update
sboxctl render
sboxctl start
sboxctl daemon
sboxctl restart
sboxctl stop
sboxctl status
sboxctl web
sboxctl log
sboxctl doctor cleanup-tun
```

OpenWrt 服务安装：

```bash
sboxctl install-openwrt
```

安装后会写入 `/etc/init.d/sboxctl`，并由 procd 托管 `sboxctl daemon`。

## 发布包

GitHub Actions 会发布 Linux 包：

```text
linux-amd64.tgz
linux-arm64.tgz
linux-mipsle.tgz
```

每个包内包含：

```text
sboxctl
sing-box
```

`sing-box` 固定随包下载官方 `1.13.12`，并放在 `sboxctl` 同级目录。运行时会优先使用这个同级二进制。

`linux-mipsle` 使用 `GOMIPS=softfloat`，面向常见 MT7621 OpenWrt 设备。

## 安装使用

先下载适合设备架构的 release 包，上传到路由器临时目录：

```bash
scp linux-mipsle.tgz root@<router-ip>:/tmp/
```

在路由器上解包并安装：

```bash
ssh root@<router-ip>
cd /tmp
tar -xzf linux-mipsle.tgz
install -m 0755 linux-mipsle/sboxctl /usr/sbin/sboxctl
install -m 0755 linux-mipsle/sing-box /usr/sbin/sing-box
```

首次初始化：

```bash
sboxctl init
sboxctl install-openwrt
/etc/init.d/sboxctl start
```

打开 Web 面板：

```text
http://<router-ip>:9000
```

第一次进入会要求设置账号密码。之后在 Web 面板里添加订阅或静态节点，保存后会自动生成 sing-box 配置并启动数据面。

常用命令：

```bash
sboxctl status
sboxctl log
sboxctl log sing-box
sboxctl restart
sboxctl doctor cleanup-tun
```

`doctor cleanup-tun` 用于 sing-box TUN 被 `kill -9` 或断电打断后的网络恢复，会强制清理 TUN、nftables、iptables、ip rule、route table、resolved 和常见网络服务状态。

## 运维注意

OpenWrt 的闪存要少写：

- geofiles 和订阅缓存只在内容变化时写入
- 更新失败不会覆盖旧缓存
- `/tmp` 可以作为上传中转，但替换后应及时清理
- 日志默认写到 `/var/log/sboxctl`，常见 OpenWrt 上 `/var/log` 可能位于 tmpfs

部署示例：

```bash
scp linux-mipsle.tgz root@<router-ip>:/tmp/
ssh root@<router-ip> 'cd /tmp && tar -xzf linux-mipsle.tgz && install -m 0755 linux-mipsle/sboxctl /usr/sbin/sboxctl && install -m 0755 linux-mipsle/sing-box /usr/sbin/sing-box && /etc/init.d/sboxctl restart && rm -rf /tmp/linux-mipsle /tmp/linux-mipsle.tgz'
```

## 产品边界

`sboxctl` 不试图成为：

- 通用跨平台代理客户端
- 桌面图形客户端
- 完整订阅服务端
- 网络诊断套件
- 多用户权限系统

它的范围更窄：

```text
维护规则和订阅
生成 sing-box 配置
托管 sing-box 进程
在内网 Web 面板里完成日常操作
```

这个边界让它适合长期放在 OpenWrt 上运行，而不是把每个客户端场景都揉进一个二进制里。
