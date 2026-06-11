/** 后端节点适用于页面列表展示、编辑和出口选择。 */
export interface BackendNode {
  /** 节点范围内机器 key。 */
  key: string
  /** 节点唯一 tag。 */
  tag: string
  /** 节点展示名称。 */
  name: string
  /** 节点协议。 */
  protocol: string
  /** 服务端地址。 */
  server: string
  /** 服务端端口。 */
  port: number
  /** 节点来源。 */
  source: string
  /** HY2/SS/Trojan/AnyTLS 静态节点认证密码。 */
  password?: string
  /** SOCKS5/HTTP 静态节点认证用户名。 */
  username?: string
  /** TLS 类静态节点 SNI。 */
  sni?: string
  /** TLS 类静态节点是否跳过证书校验。 */
  insecure?: boolean
  /** HY2 静态节点混淆密码。 */
  obfs_password?: string
  /** VMess 静态节点用户 ID。 */
  uuid?: string
  /** VMess 静态节点加密方式。 */
  security?: string
  /** VMess 静态节点 alterId。 */
  alter_id?: number
  /** VMess/Trojan 静态节点是否启用 TLS。 */
  tls?: boolean
  /** VMess/Trojan 静态节点传输层类型。 */
  transport?: string
  /** VMess/Trojan 静态节点 WebSocket/HTTP 路径。 */
  path?: string
  /** VMess/Trojan 静态节点 WebSocket/HTTP Host 头。 */
  host?: string
  /** Shadowsocks 加密方式。 */
  method?: string
  /** Shadowsocks SIP003 插件名。 */
  plugin?: string
  /** Shadowsocks SIP003 插件参数。 */
  plugin_opts?: string
  /** AnyTLS 空闲会话检查间隔。 */
  idle_session_check_interval?: string
  /** AnyTLS 空闲会话超时时间。 */
  idle_session_timeout?: string
  /** AnyTLS 至少保留的空闲会话数量。 */
  min_idle_session?: number
  /** 静态节点链式拨号前置出口引用。 */
  detour?: string
}

/** 订阅分组适用于左侧纵向列表。 */
export interface SubscriptionGroup {
  /** 订阅机器 key。 */
  key: string
  /** 订阅名称。 */
  name: string
  /** 是否启用。 */
  enabled: boolean
  /** 订阅地址。 */
  url: string
  /** 订阅请求 UA。 */
  user_agent: string
  /** 订阅缓存中的代理节点。 */
  nodes: BackendNode[]
  /** 订阅缓存错误。 */
  error?: string
}

/** 导入分组适用于离线配置导入节点列表。 */
export interface ImportedNodeGroup {
  /** 导入机器 key。 */
  key: string
  /** 导入名称。 */
  name: string
  /** 导入来源格式。 */
  source: string
  /** 导入缓存中的代理节点。 */
  nodes: BackendNode[]
  /** 导入缓存错误。 */
  error?: string
}

/** 动态组探测记录适用于展示后台最近三次结果。 */
export interface GroupProbeRecord {
  /** 探测时间。 */
  at: string
  /** 延迟毫秒。 */
  delay_ms: number
  /** 是否成功。 */
  ok: boolean
  /** 失败原因。 */
  error?: string
}

/** 动态组适用于虚拟节点选择和成员编辑。 */
export interface DynamicGroup {
  /** 组机器 key。 */
  key: string
  /** 组 outbound tag。 */
  tag: string
  /** 组展示名称。 */
  name: string
  /** 组策略模式。 */
  mode: string
  /** 主备模式主节点链路 key。 */
  primary: string
  /** 成员链路 key。 */
  members: string[]
  /** 当前担当成员链路 key。 */
  best_member: string
  /** 当前担当 outbound tag。 */
  best_tag: string
  /** sing-box selector 当前成员链路 key。 */
  current_member: string
  /** sing-box selector 当前 outbound tag。 */
  current_tag: string
  /** 最后一次评估时间。 */
  updated_at: string
  /** 每个成员最近探测结果。 */
  results: Record<string, GroupProbeRecord[]>
}

/** 动态出口规则适用于目的地址固定走指定 backend。 */
export interface DynamicOutboundRule {
  /** 匹配条件，支持 domain:xx.com 或 IP/CIDR。 */
  match: string
  /** 目标 backend tag。 */
  outbound: string
}

/** 路由检查结果适用于输入目标后的解释展示。 */
export interface RouteCheckResult {
  /** 用户原始输入。 */
  input: string
  /** 后端清洗后的目标。 */
  target: string
  /** 目标类型。 */
  kind: string
  /** 判断结果。 */
  decision: string
  /** 出站标签。 */
  outbound: string
  /** 命中的规则。 */
  matched_rule: string
  /** 命中原因。 */
  reason: string
  /** 是否走代理。 */
  via_proxy: boolean
  /** 附加说明。 */
  notes: string[]
}

/** 当前连接响应适用于连接流水页。 */
export interface ConnectionsResponse {
  /** 本次刷新时间。 */
  updated_at: string
  /** 当前连接数量。 */
  total: number
  /** 累计上传字节数。 */
  upload_total: number
  /** 累计下载字节数。 */
  download_total: number
  /** 当前连接列表。 */
  connections: ConnectionRow[]
}

/** 当前连接行适用于判断域名是否走代理。 */
export interface ConnectionRow {
  /** 连接 ID。 */
  id: string
  /** 网络类型。 */
  network: string
  /** 来源地址。 */
  source: string
  /** 目标地址。 */
  destination: string
  /** 目标域名。 */
  host: string
  /** 目标 IP。 */
  destination_ip: string
  /** 目标端口。 */
  destination_port: number
  /** 上传字节数。 */
  upload: number
  /** 下载字节数。 */
  download: number
  /** 上传下载合计。 */
  total: number
  /** 出站链路。 */
  chains: string[]
  /** 出站链路展示文本。 */
  chain_text: string
  /** direct、proxy、reject 或 unknown。 */
  decision: string
  /** 命中规则。 */
  rule: string
  /** 命中规则 payload。 */
  rule_payload: string
  /** 连接开始时间。 */
  started_at: string
}

/** 入口配置适用于 Web 修改 mixed 监听。 */
export interface InboundSettings {
  /** 入口模式。 */
  inbound_mode: string
  /** mixed 监听地址。 */
  mixed_listen: string
  /** mixed 监听端口。 */
  mixed_port: number
}

/** 动态组候选节点适用于成员选择列表。 */
export interface MemberOption {
  /** 成员链路 key。 */
  ref: string
  /** 展示名称。 */
  label: string
  /** 节点协议。 */
  protocol: string
  /** 节点地址摘要。 */
  subtitle: string
}

/** 动态组候选来源适用于竖向分组选择。 */
export interface MemberSourceGroup {
  /** 来源 key。 */
  key: string
  /** 来源展示名。 */
  name: string
  /** 该来源下可选节点。 */
  nodes: MemberOption[]
}

/** Geofile 状态适用于展示本地规则缓存。 */
export interface GeoFileItem {
  /** 类型，geoip 或 geosite。 */
  kind: string
  /** rule-set tag。 */
  tag: string
  /** 本地路径。 */
  path: string
  /** 文件是否存在。 */
  exists: boolean
  /** 文件大小。 */
  size_bytes: number
  /** 修改时间。 */
  modified_at: string
  /** 是否锁定不可编辑。 */
  locked: boolean
  /** 是否参与当前规则。 */
  enabled: boolean
  /** 规则用途。 */
  role: 'direct-base' | 'ads-block' | 'optional'
}

/** 健康状态适用于首屏探测。 */
export interface HealthState {
  /** Web 服务是否可用。 */
  ok: boolean
  /** 是否缺少登录配置。 */
  setup_required: boolean
  /** 配置层是否启用 sing-box。 */
  service_enabled: boolean
  /** sing-box 服务状态。 */
  sing_box_status: string
  /** 当前 sboxctl 进程启动时间。 */
  started_at: string
  /** 当前激活出口。 */
  active_outbound: string
  /** 最后一次更新成功时间。 */
  last_update_success: string
  /** sboxctl 当前版本。 */
  version: string
}

/** 主状态适用于单次加载整个首屏。 */
export interface PanelState {
  /** 轻量健康状态。 */
  health: HealthState
  /** 打开页面或保存成功时的配置哈希。 */
  config_hash: string
  /** 静态节点列表。 */
  static: BackendNode[]
  /** 订阅分组列表。 */
  subscriptions: SubscriptionGroup[]
  /** 手动导入分组列表。 */
  imports: ImportedNodeGroup[]
  /** 动态节点组列表。 */
  dynamic_groups: DynamicGroup[]
  /** Geofiles 本地缓存详情。 */
  geofiles: GeoFileItem[]
  /** /etc/hosts DNS 开关。 */
  hosts_override: boolean
  /** 入口配置。 */
  inbound: InboundSettings
  /** 强制代理规则文本。 */
  force_proxy: string
  /** 强制直连规则文本。 */
  force_direct: string
  /** 动态出口规则。 */
  dynamic_outbound: DynamicOutboundRule[]
  /** 当前保存配置生成的 sing-box JSON。 */
  sing_box_config: string
  /** 配置诊断提醒。 */
  warnings: string[]
}

/** 静态节点编辑表单。 */
export interface StaticForm {
  /** 节点协议。 */
  protocol: string
  /** 节点 key。 */
  key: string
  /** 展示名。 */
  name: string
  /** 服务端地址。 */
  server: string
  /** 服务端端口。 */
  port: number
  /** 协议密码。 */
  password: string
  /** SOCKS5/HTTP 用户名。 */
  username: string
  /** 链式拨号前置出口引用。 */
  detour: string
  /** TLS SNI。 */
  sni: string
  /** 是否跳过 TLS 校验。 */
  insecure: boolean
  /** HY2 混淆密码。 */
  obfs_password: string
  /** VMess 用户 ID。 */
  uuid: string
  /** VMess 加密方式。 */
  security: string
  /** VMess alterId。 */
  alter_id: number
  /** VMess/Trojan 是否启用 TLS。 */
  tls: boolean
  /** VMess/Trojan 传输层类型。 */
  transport: string
  /** VMess/Trojan 传输层路径。 */
  path: string
  /** VMess/Trojan Host 头。 */
  host: string
  /** Shadowsocks 加密方式。 */
  method: string
  /** Shadowsocks 插件名。 */
  plugin: string
  /** Shadowsocks 插件参数。 */
  plugin_opts: string
  /** AnyTLS 空闲会话检查间隔。 */
  idle_session_check_interval: string
  /** AnyTLS 空闲会话超时时间。 */
  idle_session_timeout: string
  /** AnyTLS 至少保留的空闲会话数量。 */
  min_idle_session: number
}

/** 订阅编辑表单。 */
export interface SubscriptionForm {
  /** 订阅 key。 */
  key: string
  /** 订阅名称。 */
  name: string
  /** 订阅地址。 */
  url: string
  /** 是否启用。 */
  enabled: boolean
  /** 请求 User-Agent。 */
  user_agent: string
}

/** 导入表单适用于提交一份离线配置内容。 */
export interface ImportForm {
  /** 导入分组 key。 */
  key: string
  /** 导入分组名称。 */
  name: string
  /** 导入来源格式。 */
  source: string
  /** 原始配置内容。 */
  content: string
}

/** 登录响应适用于保存 JWT。 */
export interface LoginResponse {
  /** JWT 字符串。 */
  token: string
  /** 过期时间。 */
  expires_at: string
}

/** 节点探测响应适用于展示时延。 */
export interface ProbeResponse {
  /** 被探测节点 tag。 */
  tag: string
  /** 节点时延，单位毫秒。 */
  delay_ms: number
}

/** 机制说明分组适用于 Web 帮助弹窗。 */
export interface HelpSection {
  /** 分组标题。 */
  title: string
  /** 分组说明条目。 */
  items: string[]
}
