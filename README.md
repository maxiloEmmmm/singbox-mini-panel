<p align="center">
  <img src="docs/assets/sboxctl-hero.svg" width="100%" alt="sboxctl" />
</p>

<p align="center">
  <a href="https://github.com/maxiloEmmmm/singbox-mini-panel/actions/workflows/nightly-release.yml"><img src="https://img.shields.io/github/actions/workflow/status/maxiloEmmmm/singbox-mini-panel/nightly-release.yml?style=flat-square&label=release&color=6366f1" alt="Release" /></a>
  <img src="https://img.shields.io/badge/OpenWrt-00B5E2?style=flat-square&logo=openwrt&logoColor=white" alt="OpenWrt" />
  <img src="https://img.shields.io/badge/sing--box-1.13.12-8b5cf6?style=flat-square" alt="sing-box 1.13.12" />
</p>

sboxctl 在 OpenWrt 和 Linux 上生成配置、托管 sing-box 并提供 Web 面板。配合定制内核，可通过 CF 或 UU 双向访问远端网段。[singbox-x](https://github.com/maxiloEmmmm/singbox-x)

## 跨网段互联

| 出口 | 适用场景 | 对端入口 |
| --- | --- | --- |
| **UU** | 扫码后选择已上线的 UU 设备，转发 TCP 和 UDP | singbox-x 内置的 Go 接收端，转给本机 mixed 入站 |
| **CF Mux** | 通过 Cloudflare Tunnel 访问对端，在一条 WSS 上复用 TCP 和 UDP | 支持 Mux 的 tmp-proxy daemon |

两种出口都能绑定到目标 CIDR。比如 A 将远端的 `198.51.100.0/24` 指向 UU 节点，B 将 A 的 `192.0.2.0/24` 指向反向 UU 节点。需要透明代理时，在各自接入端启用 TUN。

### UU 配置

1. **接收端**打开右侧「UU」页，启用「开启 UU 接收」，选择已有连接账号或「独立扫码」，再保存并应用。独立登录在保存后扫码。状态显示「已认证 · 已上线」后，其他设备可以选到它。接收端是全局设置，同一台设备只开一次。
2. **连接端**新增一个 `uu` 静态节点，填写对端 mixed 端口，例如 `1080`，并保存并应用。首次使用时，设备可以稍后再选。
3. 回到「UU」页选择「默认连接账号」，点「扫码认证」并在手机确认。已有登录可以直接用。只有需要管理多个连接账号时，才添加一个本地别名，比如「公司」，保存并应用后为这个别名扫码。
4. 编辑静态节点，选择连接账号及其设备，再把目标网段指向这个节点。双向访问时，两边都启用接收并分别配置出站路由。

### CF Mux 配置

静态节点选择 `cf`，填入对端发布的完整 `kv_key`。按需选择 `detour` 指定 KV 查询和 WSS 的出口。面板会显示 WSS 实际接入的 Cloudflare POP，例如 `HKG`。[数据面配置](https://github.com/maxiloEmmmm/singbox-x#cf-mux) · [对端 daemon](https://github.com/maxiloEmmmm/tmp-proxy)

```yaml
backend:
  static:
    - protocol: cf
      key: home
      name: Home
      kv_key: cfp/demo
      detour: group.fast_cn
```

## 安装

在 [Releases](https://github.com/maxiloEmmmm/singbox-mini-panel/releases) 下载对应架构的 `linux-amd64.tgz`、`linux-arm64.tgz` 或 `linux-mipsle.tgz`。下面使用 ARM64 OpenWrt 安装包。

```bash
tar -xzf linux-arm64.tgz
install -m 0755 linux-arm64/sboxctl /usr/sbin/sboxctl
install -m 0755 linux-arm64/sing-box /usr/sbin/sing-box

sboxctl init
sboxctl install-openwrt
/etc/init.d/sboxctl start
```

发布包内置官方 sing-box 1.13.12。使用 **CF 或 UU** 时，将 sboxctl 同目录下的 `sing-box` 替换为对应架构的定制内核，再重启 sboxctl。[singbox-x 构建说明](https://github.com/maxiloEmmmm/singbox-x#构建)

## 配置与运行

面板默认地址为 `http://<router-ip>:9000`。sboxctl 从 `/etc/sboxctl/config.yaml` 生成 `/etc/sing-box/config.json` 并启动内核。持久修改通过面板或 YAML 完成，生成的 JSON 会在应用时覆盖。

sboxctl 优先使用同目录下的 `sing-box`，其次使用 `/usr/bin/sing-box`。在 Linux 上也可用 `sboxctl daemon` 前台运行。通过 systemd 部署 UU 时，若服务没有 `HOME`，为该服务设置 `SBOXCTL_UU_STATE_DIR`，指向仅服务账号可访问的持久凭据目录。

## 后续

- [ ] 在发布包中集成 singbox-x。
- [ ] 在面板展示 CF 会话重连、窗口压力和逻辑流数量。
