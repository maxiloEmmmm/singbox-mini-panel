<p align="center">
  <img src="docs/assets/sboxctl-hero.svg" width="100%" alt="sboxctl" />
</p>

<p align="center">
  <a href="https://github.com/maxiloEmmmm/singbox-mini-panel/actions/workflows/nightly-release.yml"><img src="https://img.shields.io/github/actions/workflow/status/maxiloEmmmm/singbox-mini-panel/nightly-release.yml?style=flat-square&label=release&color=6366f1" alt="Release" /></a>
  <img src="https://img.shields.io/badge/OpenWrt-00B5E2?style=flat-square&logo=openwrt&logoColor=white" alt="OpenWrt" />
  <img src="https://img.shields.io/badge/sing--box-1.13.12-8b5cf6?style=flat-square" alt="sing-box 1.13.12" />
</p>

`sboxctl` 是运行在 OpenWrt 上的 sing-box 控制面：维护一份配置，生成 sing-box JSON，托管数据面进程，并提供内嵌 Web 面板。

## 这个项目解决什么

它主要解决三件事：

1. **配置归一**：订阅、静态出口、动态组和定向路由最终都由 `/etc/sboxctl/config.yaml` 生成，不手改易被覆盖的 sing-box JSON。
2. **进程归一**：sboxctl 负责生成、启动、重启和恢复 sing-box，避免配置脚本与服务管理彼此脱节。
3. **跨网段互联**：配合 `singbox-x` 的 CF Mux outbound，把对端网段作为透明路由目标，并在一条 WSS 上复用 TCP/UDP 流。

常规节点、订阅、FakeIP、TUN/mixed 和规则管理由 Web 面板提供，这里不重复罗列 sing-box 已有能力。

## 运行关系

```text
LAN / local app
      │
   TUN / mixed
      │
   sing-box  ◀──── sboxctl ──── config.yaml / Web panel
      │
      ├── normal outbound
      │
      └── CF Mux outbound ── one WSS ── remote daemon ── target network
```

sboxctl 启动时：

```text
读取 config.yaml
→ 更新必要缓存
→ 生成 /etc/sing-box/config.json
→ 启动并托管 sing-box
```

如果 sboxctl 同级目录存在可执行的 `sing-box`，会优先使用它；否则使用 `/usr/bin/sing-box`。

## CF Mux

CF Mux 是本项目区别于普通 sing-box 面板的部分。

sing-box 把 TUN 捕获到的原始目标直接交给自定义 outbound：

```text
192.0.2.154:22
→ static-cf
→ OPEN(stream_id=1, 192.0.2.154:22)
→ shared WSS
→ daemon 连接真实目标
```

一条 WSS 可以同时承载多条 TCP 和 UDP 流：

```text
stream 1       → TCP target A
stream 3       → TCP target B
association 5  → UDP target C
```

实现包含：

- stream ID 隔离多条逻辑流。
- 单流窗口和总窗口，窗口耗尽时停止读取相邻 TCP。
- 按字节公平调度，避免大流长期压制交互流。
- UDP 数据报边界和 association 回包映射。
- 显式 `detour` 控制 WSS 的物理出口。
- 从 `CF-Ray` 读取实际 POP，例如 `HKG`。

配置示例：

```yaml
backend:
  static:
    - protocol: cf
      key: home
      name: Home
      kv_key: cfp/demo
      detour: group.fast_cn
```

`protocol: cf` 需要定制版 [singbox-x](https://github.com/maxiloEmmmm/singbox-x)。当前发布包仍携带官方 sing-box `1.13.12`，使用 CF Mux 时需要替换为兼容二进制。

## 安装

从 [Releases](https://github.com/maxiloEmmmm/singbox-mini-panel/releases) 下载对应架构：

```text
linux-amd64.tgz
linux-arm64.tgz
linux-mipsle.tgz
```

```bash
tar -xzf linux-arm64.tgz
install -m 0755 linux-arm64/sboxctl /usr/sbin/sboxctl
install -m 0755 linux-arm64/sing-box /usr/sbin/sing-box

sboxctl init
sboxctl install-openwrt
/etc/init.d/sboxctl start
```

面板默认地址：

```text
http://<router-ip>:9000
```

## 后续

- [ ] 发布包直接集成 singbox-x。
- [ ] 两端通过 TUN 和 CIDR 规则透明互联整个网段。
- [ ] 完成双向网段路由的配置、观测与故障恢复闭环。
- [ ] 在面板展示 CF session、重连、窗口压力和逻辑流数量。

路线图只描述当前方向，不承诺发布日期。
