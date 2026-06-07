<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'

/** 后端节点适用于页面列表展示、编辑和出口选择。 */
interface BackendNode {
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
  /** HY2 静态节点认证密码。 */
  password?: string
  /** HY2 静态节点 SNI。 */
  sni?: string
  /** HY2 静态节点是否跳过证书校验。 */
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
}

/** 订阅分组适用于左侧纵向列表。 */
interface SubscriptionGroup {
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

/** 动态组探测记录适用于展示后台最近三次结果。 */
interface GroupProbeRecord {
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
interface DynamicGroup {
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
interface DynamicOutboundRule {
  /** 匹配条件，支持 domain:xx.com 或 IP/CIDR。 */
  match: string
  /** 目标 backend tag。 */
  outbound: string
}

/** 路由检查结果适用于输入目标后的解释展示。 */
interface RouteCheckResult {
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
interface ConnectionsResponse {
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
interface ConnectionRow {
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
interface InboundSettings {
  /** 入口模式。 */
  inbound_mode: string
  /** mixed 监听地址。 */
  mixed_listen: string
  /** mixed 监听端口。 */
  mixed_port: number
}

/** 动态组候选节点适用于成员选择列表。 */
interface MemberOption {
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
interface MemberSourceGroup {
  /** 来源 key。 */
  key: string
  /** 来源展示名。 */
  name: string
  /** 该来源下可选节点。 */
  nodes: MemberOption[]
}

/** Geofile 状态适用于展示本地规则缓存。 */
interface GeoFileItem {
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
interface HealthState {
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
interface PanelState {
  /** 轻量健康状态。 */
  health: HealthState
  /** 打开页面或保存成功时的配置哈希。 */
  config_hash: string
  /** 静态节点列表。 */
  static: BackendNode[]
  /** 订阅分组列表。 */
  subscriptions: SubscriptionGroup[]
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
interface StaticForm {
  protocol: string
  key: string
  name: string
  server: string
  port: number
  password: string
  sni: string
  insecure: boolean
  obfs_password: string
  uuid: string
  security: string
  alter_id: number
  tls: boolean
  transport: string
  path: string
  host: string
  method: string
  plugin: string
  plugin_opts: string
}

/** 订阅编辑表单。 */
interface SubscriptionForm {
  key: string
  name: string
  url: string
  enabled: boolean
  user_agent: string
}

/** 登录响应适用于保存 JWT。 */
interface LoginResponse {
  /** JWT 字符串。 */
  token: string
  /** 过期时间。 */
  expires_at: string
}

/** 节点探测响应适用于展示时延。 */
interface ProbeResponse {
  /** 被探测节点 tag。 */
  tag: string
  /** 节点时延，单位毫秒。 */
  delay_ms: number
}

/** 机制说明分组适用于 Web 帮助弹窗。 */
interface HelpSection {
  /** 分组标题。 */
  title: string
  /** 分组说明条目。 */
  items: string[]
}

const token = ref(localStorage.getItem('sboxctl_token') || '')
const health = ref<HealthState | null>(null)
const panel = ref<PanelState | null>(null)
const username = ref('')
const password = ref('')
const setupUsername = ref('')
const setupPassword = ref('')
const setupConfirm = ref('')
const selectedTag = ref('')
const staticNodes = ref<BackendNode[]>([])
const savedStaticNodes = ref<BackendNode[]>([])
const subscriptions = ref<SubscriptionGroup[]>([])
const savedSubscriptions = ref<SubscriptionGroup[]>([])
const dynamicGroups = ref<DynamicGroup[]>([])
const savedDynamicGroups = ref<DynamicGroup[]>([])
const editingDynamicGroupKey = ref('')
const editingOriginalDynamicGroupKey = ref('')
const dynamicOutbound = ref<DynamicOutboundRule[]>([])
const savedDynamicOutbound = ref<DynamicOutboundRule[]>([])
const selectedDynamicOutboundIndex = ref(0)
const forceProxy = ref('')
const forceDirect = ref('')
const inboundMode = ref('tun')
const mixedListen = ref('0.0.0.0')
const mixedPort = ref(1080)
const serviceEnabled = ref(true)
const configHash = ref('')
const savedSelectedTag = ref('')
const savedForceProxy = ref('')
const savedForceDirect = ref('')
const savedInboundMode = ref('tun')
const savedMixedListen = ref('0.0.0.0')
const savedMixedPort = ref(1080)
const savedServiceEnabled = ref(true)
const adsBlock = ref(true)
const savedAdsBlock = ref(true)
const hostsOverride = ref(true)
const savedHostsOverride = ref(true)
const proxyRuleSets = ref<string[]>([])
const savedProxyRuleSets = ref<string[]>([])
const loginError = ref('')
const setupError = ref('')
const pageError = ref('')
const activeNodeTab = ref('static')
const nowTick = ref(Date.now())
const activeMemberSourceKey = ref('static')
const activeOutboundSourceKey = ref('static')
const memberModalOpen = ref(false)
const outboundModalOpen = ref(false)
const saving = ref(false)
const setupSaving = ref(false)
const probing = ref(true)
const loading = ref(true)
const updatingSubscription = ref('')
const probingGroup = ref('')
const probingNode = ref('')
const nodeDelays = ref<Record<string, string>>({})
const probeModalNode = ref<BackendNode | null>(null)
const probeSeriesCount = ref<Record<string, number>>({})
const probeSeriesResults = ref<Record<string, string[]>>({})
const probingSeriesTag = ref('')
const staticModalOpen = ref(false)
const staticEditingKey = ref('')
const staticForm = ref<StaticForm>(emptyStaticForm())
const subscriptionModalOpen = ref(false)
const subscriptionEditingKey = ref('')
const subscriptionForm = ref<SubscriptionForm>(emptySubscriptionForm())
const listSearch = ref<Record<string, string>>({})
const helpOpen = ref(false)
const routeCheckInput = ref('')
const routeCheckLoading = ref(false)
const routeCheckError = ref('')
const routeCheckResult = ref<RouteCheckResult | null>(null)
const connections = ref<ConnectionRow[]>([])
const connectionsUpdatedAt = ref('')
const connectionUploadTotal = ref(0)
const connectionDownloadTotal = ref(0)
const connectionFilter = ref('')
const connectionDecisionFilter = ref('all')
const connectionSort = ref('total')
const connectionsLoading = ref(false)
const connectionsError = ref('')

const helpSections: HelpSection[] = [
  {
    title: '保存与应用',
    items: [
      '页面里的新增、修改、删除先进入临时配置，只有右上角保存并应用才写入配置。',
      '保存时会带配置 hash，发现后台配置已经变化会要求确认覆盖。',
      '只改当前出口或动态出口目标时会即时生效，不会重启核心服务。',
      '节点内容、订阅结构、静态节点、入口模式、DNS、Geo 规则或规则内容变化时会重新应用核心配置。',
      '保存按钮会一直等待核心配置重新可用后才结束 loading。',
      '出口切换后会清理旧连接，避免新访问继续沿用旧出口。',
      '右上角服务开关只控制 sing-box 数据面；关闭后 Web 管理页仍可访问。',
      '服务从关闭切回开启时，会等待核心接口可用后才结束 loading。',
    ],
  },
  {
    title: '订阅与缓存',
    items: [
      '新增或修改订阅后，右上角保存并应用会自动拉取一次启用的变更订阅。',
      '订阅列表里的更新按钮只按已经保存的订阅配置拉取，不读取未应用的表单内容。',
      '启动和渲染只补缺失缓存；每天 04:00 会更新 geofiles 和所有启用订阅。',
      '订阅更新失败不会覆盖旧缓存，内容无变化时也不会重复写缓存文件。',
      '订阅更新后如果节点消失，页面会提示被当前出口、动态组或动态出口引用的失效链路。',
    ],
  },
  {
    title: '入口模式',
    items: [
      '默认是 TUN，全局接管局域网客户端流量。',
      '可切 mixed 模式，对外提供 socks/http 混合端口，默认 1080，支持账号密码。',
      'ICMP 被路由到 direct，ping 只用于判断连通性，不代表 TCP/HTTPS 代理路径。',
    ],
  },
  {
    title: 'DNS 与 FakeIP',
    items: [
      '所有 DNS 流量会被接管到本机统一处理。',
      '命中代理规则的 A 记录默认返回 FakeIP，范围是 198.18.0.0/15，并持久保存域名映射。',
      'Apple、Windows、STUN、NTP、局域网等系统探测域名内置排除 FakeIP。',
      'CN 和 private 域名走 direct DNS 119.29.29.29，默认远端 DNS 使用 Cloudflare DoH。',
      'HTTPS/SVCB 查询会被拒绝，避免浏览器绕过 FakeIP 机制。',
    ],
  },
  {
    title: '路由优先级',
    items: [
      '顺序是域名识别、DNS 接管、ping 直连、动态出口、强制不走、强制走、内网和 CN 直连、广告拦截、Geo 代理规则、默认出口。',
      '强制走代理在内网和 CN 直连规则前面，手写规则会更优先。',
      '强制规则支持 domain:xx.com、src:CIDR、dst:CIDR；不写前缀按域名后缀处理。',
    ],
  },
  {
    title: 'GeoFiles',
    items: [
      'GeoFiles 来自内置列表，缓存为本地 srs 文件，缺失时会自动补齐。',
      '可在 Web 里开关可选代理规则集；private、CN 等基础直连规则会被锁定。',
      'geofiles 默认通过已有代理更新，下载失败保留旧文件。',
    ],
  },
  {
    title: 'Backend',
    items: [
      '静态节点支持扁平配置的 HY2、VMess、SS 和 Trojan；订阅目前解析 HY2、VMess、SS 和 Trojan，其它协议先跳过。',
      '节点 key 在各自范围内必须唯一；订阅内 key 只要求订阅内唯一，跨订阅可重复。',
      '删除订阅或静态节点时，如果动态组、动态出口或当前出口仍引用，会拒绝保存。',
      '静态节点的新增、修改和删除也都是临时配置，刷新页面前会提示未保存改动。',
    ],
  },
  {
    title: '动态组',
    items: [
      '只有当前出口选中动态组时才后台探测，没被选中的组不探测。',
      '每 5 分钟一轮，每轮按 5s、30s、60s 做三次探测，内存保存最近三次结果。',
      '动态模式按成功次数优先，成功次数相同再按平均延迟选担当。',
      '主备模式优先主节点；主节点最近一次失败就切备，最近一次恢复成功就切回主。',
      '主备模式切到备节点会写 warn 日志，主节点恢复会写 info 日志。',
      '动态组内部担当变化会即时生效，不会重启核心服务。',
    ],
  },
  {
    title: '动态出口',
    items: [
      '动态出口用于把特定目的域名或 IP 固定到指定 backend。',
      '匹配支持 domain:xx.com 和 IP/CIDR；不写 domain: 时按域名后缀处理。',
      '只修改动态出口绑定的 backend 会即时生效，不会重启核心服务。',
      '动态出口规则优先于强制走和强制不走规则。',
    ],
  },
  {
    title: '探测与日志',
    items: [
      '节点探测会通过指定节点访问固定连通性地址，超时 2 秒。',
      'Web 手动探测只展示延迟，不会切换当前出口。',
      '编排器日志和 sing-box 日志写入配置的 log.dir，默认保留 5 个 5MB 文件。',
      '登录连续失败 3 次会按 IP 锁定 1 小时。',
    ],
  },
]

const isLoggedIn = computed(() => token.value.length > 0)
const setupRequired = computed(() => health.value?.setup_required === true)
const isServiceRunning = computed(() => health.value?.sing_box_status === 'running')
const showAbnormal = computed(() => !loading.value && !health.value)
const lastUpdateText = computed(() => formatTime(health.value?.last_update_success || ''))
const uptimeText = computed(() => formatDurationSince(health.value?.started_at || ''))
const versionText = computed(() => health.value?.version || 'dev')
const geoIPFiles = computed(() => arrayOrEmpty(panel.value?.geofiles).filter((file) => file.kind === 'geoip'))
const geoSiteFiles = computed(
  () => arrayOrEmpty(panel.value?.geofiles).filter((file) => file.kind === 'geosite'),
)
const editingDynamicGroup = computed(
  () => dynamicGroups.value.find((group) => group.key === editingDynamicGroupKey.value) || null,
)
const selectedDynamicOutboundRule = computed(
  () => dynamicOutbound.value[selectedDynamicOutboundIndex.value] || null,
)
const activeOutboundText = computed(() => outboundDisplayLabel(selectedTag.value))
const configWarnings = computed(() => panel.value?.warnings || [])
const filteredConnections = computed(() => {
  const query = connectionFilter.value.trim().toLowerCase()
  return connections.value.filter((item) => {
    if (connectionDecisionFilter.value !== 'all' && item.decision !== connectionDecisionFilter.value) {
      return false
    }
    if (!query) {
      return true
    }
    return [
      item.source,
      item.destination,
      item.host,
      item.destination_ip,
      item.network,
      item.decision,
      item.chain_text,
      item.rule,
      item.rule_payload,
    ].join(' ').toLowerCase().includes(query)
  }).sort(compareConnections)
})
const memberSourceGroups = computed<MemberSourceGroup[]>(() => {
  const groups: MemberSourceGroup[] = [
    {
      key: 'static',
      name: '静态',
      nodes: staticNodes.value.map((node) => ({
        ref: `static.${node.key}`,
        label: node.name || node.key,
        protocol: node.protocol,
        subtitle: nodeSubtitle(node),
      })),
    },
  ]
  for (const subscription of subscriptions.value) {
    groups.push({
      key: `sub.${subscription.key}`,
      name: subscription.name,
      nodes: arrayOrEmpty(subscription.nodes).map((node) => ({
        ref: `sub.${subscription.key}.${node.key}`,
        label: node.name || node.key,
        protocol: node.protocol,
        subtitle: nodeSubtitle(node),
      })),
    })
  }
  return groups
})
const memberOptions = computed<MemberOption[]>(() => {
  return memberSourceGroups.value.flatMap((group) => group.nodes)
})
const outboundSourceGroups = computed<MemberSourceGroup[]>(() => {
  const groups: MemberSourceGroup[] = [
    {
      key: 'static',
      name: '静态',
      nodes: staticNodes.value.map((node) => ({
        ref: node.tag,
        label: node.name || node.key,
        protocol: node.protocol,
        subtitle: nodeSubtitle(node),
      })),
    },
  ]
  for (const subscription of subscriptions.value) {
    groups.push({
      key: `sub.${subscription.key}`,
      name: subscription.name,
      nodes: arrayOrEmpty(subscription.nodes).map((node) => ({
        ref: node.tag,
        label: node.name || node.key,
        protocol: node.protocol,
        subtitle: nodeSubtitle(node),
      })),
    })
  }
  if (dynamicGroups.value.length > 0) {
    groups.push({
      key: 'dynamic',
      name: '动态',
      nodes: dynamicGroups.value.map((group) => ({
        ref: group.tag,
        label: group.name || group.key,
        protocol: 'group',
        subtitle: `${arrayOrEmpty(group.members).length} 个成员`,
      })),
    })
  }
  return groups
})
const hasChanges = computed(() => {
  return (
    selectedTag.value !== savedSelectedTag.value ||
    serializeStaticNodes(staticNodes.value) !== serializeStaticNodes(savedStaticNodes.value) ||
    serializeSubscriptions(subscriptions.value) !== serializeSubscriptions(savedSubscriptions.value) ||
    serializeDynamicGroups(dynamicGroups.value) !== serializeDynamicGroups(savedDynamicGroups.value) ||
    serializeDynamicOutbound(dynamicOutbound.value) !== serializeDynamicOutbound(savedDynamicOutbound.value) ||
    forceProxy.value !== savedForceProxy.value ||
    forceDirect.value !== savedForceDirect.value ||
    inboundMode.value !== savedInboundMode.value ||
    mixedListen.value !== savedMixedListen.value ||
    Number(mixedPort.value) !== Number(savedMixedPort.value) ||
    serviceEnabled.value !== savedServiceEnabled.value ||
    adsBlock.value !== savedAdsBlock.value ||
    hostsOverride.value !== savedHostsOverride.value ||
    sortedRuleSets(proxyRuleSets.value) !== sortedRuleSets(savedProxyRuleSets.value)
  )
})

window.addEventListener('beforeunload', (event) => {
  if (!hasChanges.value) {
    return
  }
  event.preventDefault()
  event.returnValue = ''
})

// 适用场景：格式化文件大小。
function formatBytes(value: number) {
  if (value <= 0) {
    return '0 B'
  }
  if (value < 1024) {
    return `${value} B`
  }
  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KB`
  }
  return `${(value / 1024 / 1024).toFixed(2)} MB`
}

// 适用场景：把后端时间转成人类可读短格式。
function formatTime(value: string) {
  if (!value) {
    return '无记录'
  }
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value
  }
  const month = `${date.getMonth() + 1}`.padStart(2, '0')
  const day = `${date.getDate()}`.padStart(2, '0')
  const hour = `${date.getHours()}`.padStart(2, '0')
  const minute = `${date.getMinutes()}`.padStart(2, '0')
  return `${month}-${day} ${hour}:${minute}`
}

// 适用场景：把启动时间换算成当前进程已运行多久。
function formatDurationSince(value: string) {
  if (!value) {
    return '无记录'
  }
  const startedAt = new Date(value).getTime()
  if (Number.isNaN(startedAt)) {
    return value
  }
  let seconds = Math.max(0, Math.floor((nowTick.value - startedAt) / 1000))
  const days = Math.floor(seconds / 86400)
  seconds %= 86400
  const hours = Math.floor(seconds / 3600)
  seconds %= 3600
  const minutes = Math.floor(seconds / 60)
  const remainSeconds = seconds % 60
  if (days > 0) {
    return `${days}天${hours}小时`
  }
  if (hours > 0) {
    return `${hours}小时${minutes}分`
  }
  if (minutes > 0) {
    return `${minutes}分${remainSeconds}秒`
  }
  return `${remainSeconds}秒`
}

// 适用场景：生成带 JWT 的请求头。
function authHeaders() {
  return {
    Authorization: `Bearer ${token.value}`,
    'Content-Type': 'application/json',
  }
}

// 适用场景：解析 API 错误消息。
async function readError(response: Response) {
  try {
    const data = await response.json()
    return data.error || response.statusText
  } catch {
    return response.statusText
  }
}

// 适用场景：把后端状态同步到页面响应式数据。
function applyPanelState(nextPanel: PanelState) {
  panel.value = normalizedPanelState(nextPanel)
  nextPanel = panel.value
  health.value = nextPanel.health
  configHash.value = nextPanel.config_hash
  selectedTag.value = nextPanel.health.active_outbound
  staticNodes.value = cloneStaticNodes(nextPanel.static)
  subscriptions.value = cloneSubscriptions(nextPanel.subscriptions)
  dynamicGroups.value = cloneDynamicGroups(nextPanel.dynamic_groups)
  if (!dynamicGroups.value.some((group) => group.key === editingDynamicGroupKey.value)) {
    editingDynamicGroupKey.value = ''
    editingOriginalDynamicGroupKey.value = ''
    memberModalOpen.value = false
  }
  if (!memberSourceGroups.value.some((group) => group.key === activeMemberSourceKey.value)) {
    activeMemberSourceKey.value = memberSourceGroups.value[0]?.key || 'static'
  }
  dynamicOutbound.value = cloneDynamicOutbound(nextPanel.dynamic_outbound)
  if (selectedDynamicOutboundIndex.value >= dynamicOutbound.value.length) {
    selectedDynamicOutboundIndex.value = Math.max(dynamicOutbound.value.length - 1, 0)
  }
  activeNodeTab.value = tabKeyForOutbound(selectedTag.value)
  if (!outboundSourceGroups.value.some((group) => group.key === activeOutboundSourceKey.value)) {
    activeOutboundSourceKey.value = outboundSourceGroups.value[0]?.key || 'static'
  }
  forceProxy.value = nextPanel.force_proxy
  forceDirect.value = nextPanel.force_direct
  inboundMode.value = normalizedInboundMode(nextPanel.inbound?.inbound_mode)
  mixedListen.value = nextPanel.inbound?.mixed_listen || '0.0.0.0'
  mixedPort.value = nextPanel.inbound?.mixed_port || 1080
  serviceEnabled.value = nextPanel.health.service_enabled !== false
  hostsOverride.value = nextPanel.hosts_override !== false
  const geofiles = arrayOrEmpty(nextPanel.geofiles)
  adsBlock.value = geofiles.some((file) => file.role === 'ads-block' && file.enabled)
  proxyRuleSets.value = geofiles
    .filter((file) => file.role === 'optional' && file.enabled)
    .map((file) => file.tag)
  savedSelectedTag.value = selectedTag.value
  savedStaticNodes.value = cloneStaticNodes(staticNodes.value)
  savedSubscriptions.value = cloneSubscriptions(subscriptions.value)
  savedDynamicGroups.value = cloneDynamicGroups(dynamicGroups.value)
  savedDynamicOutbound.value = cloneDynamicOutbound(dynamicOutbound.value)
  savedForceProxy.value = forceProxy.value
  savedForceDirect.value = forceDirect.value
  savedInboundMode.value = inboundMode.value
  savedMixedListen.value = mixedListen.value
  savedMixedPort.value = Number(mixedPort.value)
  savedServiceEnabled.value = serviceEnabled.value
  savedAdsBlock.value = adsBlock.value
  savedHostsOverride.value = hostsOverride.value
  savedProxyRuleSets.value = [...proxyRuleSets.value]
}

// 适用场景：归一化 Web 主状态，避免模板读取 null 列表时中断渲染。
function normalizedPanelState(nextPanel: PanelState) {
  return {
    ...nextPanel,
    static: cloneStaticNodes(nextPanel.static),
    subscriptions: cloneSubscriptions(nextPanel.subscriptions),
    dynamic_groups: cloneDynamicGroups(nextPanel.dynamic_groups),
    geofiles: arrayOrEmpty(nextPanel.geofiles).map((file) => ({ ...file })),
    inbound: normalizeInboundSettings(nextPanel.inbound),
    dynamic_outbound: cloneDynamicOutbound(nextPanel.dynamic_outbound),
    warnings: [...arrayOrEmpty(nextPanel.warnings)],
  }
}

// 适用场景：归一化入口配置，兼容旧后端状态。
function normalizeInboundSettings(value: InboundSettings | null | undefined) {
  return {
    inbound_mode: normalizedInboundMode(value?.inbound_mode || ''),
    mixed_listen: value?.mixed_listen || '0.0.0.0',
    mixed_port: value?.mixed_port || 1080,
  }
}

// 适用场景：归一化入口模式，兼容旧配置空值。
function normalizedInboundMode(value: string) {
  return value === 'mixed' ? 'mixed' : 'tun'
}

// 适用场景：把后端空 slice 编码出的 null 规整成前端可遍历列表。
function arrayOrEmpty<T>(items: T[] | null | undefined) {
  return Array.isArray(items) ? items : []
}

// 适用场景：复制静态节点，避免编辑污染保存基线。
function cloneStaticNodes(nodes: BackendNode[] | null | undefined) {
  return arrayOrEmpty(nodes).map((node) => ({ ...node }))
}

// 适用场景：复制订阅配置和缓存节点。
function cloneSubscriptions(items: SubscriptionGroup[] | null | undefined) {
  return arrayOrEmpty(items).map((item) => ({
    ...item,
    nodes: arrayOrEmpty(item.nodes).map((node) => ({ ...node })),
  }))
}

// 适用场景：稳定比较静态节点配置是否变更。
function serializeStaticNodes(nodes: BackendNode[]) {
  return JSON.stringify(nodes.map((node) => ({
    protocol: normalizeStaticProtocol(node.protocol),
    key: node.key,
    name: node.name,
    server: node.server,
    port: node.port,
    password: node.password || '',
    sni: node.sni || '',
    insecure: node.insecure === true,
    obfs_password: node.obfs_password || '',
    uuid: node.uuid || '',
    security: node.security || '',
    alter_id: node.alter_id || 0,
    tls: node.tls === true,
    transport: node.transport || '',
    path: node.path || '',
    host: node.host || '',
    method: node.method || '',
    plugin: node.plugin || '',
    plugin_opts: node.plugin_opts || '',
  })))
}

// 适用场景：稳定比较订阅配置是否变更。
function serializeSubscriptions(items: SubscriptionGroup[]) {
  return JSON.stringify(items.map((item) => ({
    key: item.key,
    name: item.name,
    url: item.url,
    enabled: item.enabled,
    user_agent: item.user_agent,
  })))
}

// 适用场景：稳定比较 geofile 规则集选择。
function sortedRuleSets(items: string[]) {
  return [...items].sort().join(',')
}

// 适用场景：规范化静态节点协议，兼容旧配置空协议。
function normalizeStaticProtocol(protocol: string) {
  if (protocol === 'vmess') {
    return 'vmess'
  }
  if (protocol === 'ss') {
    return 'ss'
  }
  if (protocol === 'trojan') {
    return 'trojan'
  }
  return 'hy2'
}

// 适用场景：复制动态组，避免编辑时污染保存基线。
function cloneDynamicGroups(groups: DynamicGroup[] | null | undefined) {
  return arrayOrEmpty(groups).map((group) => ({
    ...group,
    members: [...arrayOrEmpty(group.members)],
    results: Object.fromEntries(
      Object.entries(group.results || {}).map(([key, records]) => [
        key,
        arrayOrEmpty(records).map((item) => ({ ...item })),
      ]),
    ),
  }))
}

// 适用场景：稳定比较动态组配置是否变更。
function serializeDynamicGroups(groups: DynamicGroup[]) {
  return JSON.stringify(
    groups.map((group) => ({
      key: group.key,
      mode: normalizeGroupMode(group.mode),
      primary: normalizeGroupMode(group.mode) === 'primary_backup' ? group.primary : '',
      members: [...arrayOrEmpty(group.members)],
    })),
  )
}

// 适用场景：把后端或旧前端状态中的动态组模式规整成有效值。
function normalizeGroupMode(mode: string) {
  return mode === 'primary_backup' ? 'primary_backup' : 'dynamic'
}

// 适用场景：复制动态出口规则，避免编辑污染保存基线。
function cloneDynamicOutbound(rules: DynamicOutboundRule[] | null | undefined) {
  return arrayOrEmpty(rules).map((rule) => ({ ...rule }))
}

// 适用场景：稳定比较动态出口规则是否变更。
function serializeDynamicOutbound(rules: DynamicOutboundRule[]) {
  return JSON.stringify(rules.map((rule) => ({
    match: rule.match,
    outbound: rule.outbound,
  })))
}

// 适用场景：生成空静态节点表单。
function emptyStaticForm(): StaticForm {
  return {
    protocol: 'hy2',
    key: '',
    name: '',
    server: '',
    port: 443,
    password: '',
    sni: '',
    insecure: false,
    obfs_password: '',
    uuid: '',
    security: 'auto',
    alter_id: 0,
    tls: false,
    transport: '',
    path: '',
    host: '',
    method: 'aes-128-gcm',
    plugin: '',
    plugin_opts: '',
  }
}

// 适用场景：切换静态节点协议时补齐该协议的常见默认项。
function updateStaticProtocol(protocol: string) {
  const nextProtocol = normalizeStaticProtocol(protocol)
  staticForm.value.protocol = nextProtocol
  if (nextProtocol === 'trojan') {
    staticForm.value.port = Number(staticForm.value.port) || 443
    staticForm.value.tls = true
  }
}

// 适用场景：生成空订阅表单。
function emptySubscriptionForm(): SubscriptionForm {
  return {
    key: '',
    name: '',
    url: '',
    enabled: true,
    user_agent: 'sing-box/1.13.12',
  }
}

// 适用场景：用节点生成静态编辑表单。
function staticFormFromNode(node: BackendNode): StaticForm {
  return {
    protocol: normalizeStaticProtocol(node.protocol),
    key: node.key,
    name: node.name,
    server: node.server,
    port: node.port,
    password: node.password || '',
    sni: node.sni || '',
    insecure: node.insecure === true,
    obfs_password: node.obfs_password || '',
    uuid: node.uuid || '',
    security: node.security || 'auto',
    alter_id: node.alter_id || 0,
    tls: node.tls === true,
    transport: node.transport || '',
    path: node.path || '',
    host: node.host || '',
    method: node.method || 'aes-128-gcm',
    plugin: node.plugin || '',
    plugin_opts: node.plugin_opts || '',
  }
}

// 适用场景：用订阅生成订阅编辑表单。
function subscriptionFormFromItem(item: SubscriptionGroup): SubscriptionForm {
  return {
    key: item.key,
    name: item.name,
    url: item.url,
    enabled: item.enabled,
    user_agent: item.user_agent,
  }
}

// 适用场景：打开新增静态节点弹窗。
function addStaticNode() {
  staticEditingKey.value = ''
  staticForm.value = emptyStaticForm()
  staticModalOpen.value = true
}

// 适用场景：打开静态节点编辑弹窗。
function editStaticNode(node: BackendNode) {
  staticEditingKey.value = node.key
  staticForm.value = staticFormFromNode(node)
  staticModalOpen.value = true
}

// 适用场景：把静态节点表单保存到页面临时状态。
function saveStaticDraft() {
  const item = staticForm.value
  const protocol = normalizeStaticProtocol(item.protocol)
  const key = sanitizeLocalKey(item.key)
  if (!key) {
    pageError.value = '静态节点 key 不能为空'
    return
  }
  if (staticNodes.value.some((node) => node.key === key && node.key !== staticEditingKey.value)) {
    pageError.value = `静态节点 key 重复: ${key}`
    return
  }
  if (!item.server.trim()) {
    pageError.value = '静态节点 server 必填'
    return
  }
  if ((protocol === 'hy2' || protocol === 'trojan') && !item.password.trim()) {
    pageError.value = `${protocol.toUpperCase()} 静态节点 password 必填`
    return
  }
  if (protocol === 'vmess' && !item.uuid.trim()) {
    pageError.value = 'VMess 静态节点 uuid 必填'
    return
  }
  if (protocol === 'ss' && !item.method.trim()) {
    pageError.value = 'SS 静态节点 method 必填'
    return
  }
  if (protocol === 'ss' && !item.password.trim()) {
    pageError.value = 'SS 静态节点 password 必填'
    return
  }
  const next: BackendNode = {
    key,
    tag: `static-${key}`,
    name: item.name.trim() || key,
    protocol,
    server: item.server.trim(),
    port: Number(item.port) || 443,
    source: 'static',
    password: protocol === 'hy2' || protocol === 'ss' || protocol === 'trojan' ? item.password.trim() : '',
    sni: item.sni.trim(),
    insecure: item.insecure,
    obfs_password: protocol === 'hy2' ? item.obfs_password.trim() : '',
    uuid: protocol === 'vmess' ? item.uuid.trim() : '',
    security: protocol === 'vmess' ? item.security.trim() || 'auto' : '',
    alter_id: protocol === 'vmess' ? Number(item.alter_id) || 0 : 0,
    tls: protocol === 'vmess' || protocol === 'trojan' ? item.tls === true : false,
    transport: protocol === 'vmess' || protocol === 'trojan' ? item.transport.trim().toLowerCase() : '',
    path: protocol === 'vmess' || protocol === 'trojan' ? item.path.trim() : '',
    host: protocol === 'vmess' || protocol === 'trojan' ? item.host.trim() : '',
    method: protocol === 'ss' ? item.method.trim() : '',
    plugin: protocol === 'ss' ? item.plugin.trim() : '',
    plugin_opts: protocol === 'ss' ? item.plugin_opts.trim() : '',
  }
  if (staticEditingKey.value) {
    if (staticEditingKey.value !== key) {
      replaceBackendReferences(`static-${staticEditingKey.value}`, `static-${key}`, `static.${staticEditingKey.value}`, `static.${key}`)
    }
    staticNodes.value = staticNodes.value.map((node) => (node.key === staticEditingKey.value ? next : node))
  } else {
    staticNodes.value = [...staticNodes.value, next]
  }
  staticModalOpen.value = false
}

// 适用场景：删除静态节点前检查页面临时配置引用。
function removeStaticNode(node: BackendNode) {
  const blockers = localBackendBlockers(node.tag, `static.${node.key}`)
  if (blockers.length > 0) {
    pageError.value = `不能删除，仍被引用: ${blockers.join('；')}`
    return
  }
  staticNodes.value = staticNodes.value.filter((item) => item.key !== node.key)
  if (selectedTag.value === node.tag) {
    selectedTag.value = firstAvailableNodeTag()
  }
}

// 适用场景：打开新增订阅弹窗。
function addSubscription() {
  subscriptionEditingKey.value = ''
  subscriptionForm.value = emptySubscriptionForm()
  subscriptionModalOpen.value = true
}

// 适用场景：打开订阅编辑弹窗。
function editSubscription(subscription: SubscriptionGroup) {
  subscriptionEditingKey.value = subscription.key
  subscriptionForm.value = subscriptionFormFromItem(subscription)
  subscriptionModalOpen.value = true
}

// 适用场景：把订阅表单保存到页面临时状态。
function saveSubscriptionDraft() {
  const item = subscriptionForm.value
  const key = sanitizeLocalKey(item.key || item.name)
  if (!key) {
    pageError.value = '订阅 key 不能为空'
    return
  }
  if (subscriptions.value.some((sub) => sub.key === key && sub.key !== subscriptionEditingKey.value)) {
    pageError.value = `订阅 key 重复: ${key}`
    return
  }
  if (!item.url.trim()) {
    pageError.value = '订阅 url 不能为空'
    return
  }
  const previous = subscriptions.value.find((sub) => sub.key === subscriptionEditingKey.value)
  const nodes = arrayOrEmpty(previous?.nodes).map((node) => ({
    ...node,
    tag: subscriptionEditingKey.value ? node.tag.replace(`sub-${subscriptionEditingKey.value}-`, `sub-${key}-`) : node.tag,
    source: `subscription:${key}`,
  })) || []
  const next: SubscriptionGroup = {
    key,
    name: item.name.trim() || key,
    url: item.url.trim(),
    enabled: item.enabled,
    user_agent: item.user_agent.trim() || 'sing-box/1.13.12',
    nodes,
    error: previous?.error,
  }
  if (subscriptionEditingKey.value) {
    if (subscriptionEditingKey.value !== key) {
      replaceSubscriptionReferences(subscriptionEditingKey.value, key, previous?.nodes)
    }
    subscriptions.value = subscriptions.value.map((sub) => (sub.key === subscriptionEditingKey.value ? next : sub))
  } else {
    subscriptions.value = [...subscriptions.value, next]
  }
  subscriptionModalOpen.value = false
}

// 适用场景：重命名静态节点时同步临时引用。
function replaceBackendReferences(oldTag: string, newTag: string, oldRef: string, newRef: string) {
  if (selectedTag.value === oldTag) {
    selectedTag.value = newTag
  }
  dynamicGroups.value = dynamicGroups.value.map((group) => ({
    ...group,
    primary: group.primary === oldRef ? newRef : group.primary,
    members: arrayOrEmpty(group.members).map((member) => (member === oldRef ? newRef : member)),
  }))
  dynamicOutbound.value = dynamicOutbound.value.map((rule) => ({
    ...rule,
    outbound: rule.outbound === oldTag ? newTag : rule.outbound,
  }))
}

// 适用场景：重命名订阅 key 时同步临时引用。
function replaceSubscriptionReferences(oldKey: string, newKey: string, nodes: BackendNode[] | null | undefined) {
  for (const node of arrayOrEmpty(nodes)) {
    replaceBackendReferences(
      `sub-${oldKey}-${node.key}`,
      `sub-${newKey}-${node.key}`,
      `sub.${oldKey}.${node.key}`,
      `sub.${newKey}.${node.key}`,
    )
  }
}

// 适用场景：删除订阅前检查页面临时配置引用。
function removeSubscription(subscription: SubscriptionGroup) {
  const nodes = arrayOrEmpty(subscription.nodes)
  const refs = nodes.map((node) => `sub.${subscription.key}.${node.key}`)
  const tags = nodes.map((node) => node.tag)
  const blockers = localBackendBlockers(tags, refs)
  if (blockers.length > 0) {
    pageError.value = `不能删除，仍被引用: ${blockers.join('；')}`
    return
  }
  subscriptions.value = subscriptions.value.filter((item) => item.key !== subscription.key)
  if (tags.includes(selectedTag.value)) {
    selectedTag.value = firstAvailableNodeTag()
  }
}

// 适用场景：按前端规则清洗 key。
function sanitizeLocalKey(value: string) {
  return value.trim().toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '')
}

// 适用场景：查找本地临时配置里仍引用某 backend 的位置。
function localBackendBlockers(tags: string | string[], refs: string | string[]) {
  const tagSet = new Set(Array.isArray(tags) ? tags : [tags])
  const refSet = new Set(Array.isArray(refs) ? refs : [refs])
  const blockers: string[] = []
  if (tagSet.has(selectedTag.value)) {
    blockers.push(`当前出口 ${selectedTag.value}`)
  }
  for (const group of dynamicGroups.value) {
    for (const member of arrayOrEmpty(group.members)) {
      if (refSet.has(member)) {
        blockers.push(`动态组 ${group.key} 成员 ${member}`)
      }
    }
    if (refSet.has(group.primary)) {
      blockers.push(`动态组 ${group.key} 主节点 ${group.primary}`)
    }
  }
  for (const rule of dynamicOutbound.value) {
    if (tagSet.has(rule.outbound)) {
      blockers.push(`动态出口 ${rule.match}`)
    }
  }
  return blockers
}

// 适用场景：新增一个动态组配置。
function addDynamicGroup() {
  const key = nextDynamicGroupKey()
  dynamicGroups.value = [
    ...dynamicGroups.value,
    {
      key,
      tag: `group-${key}`,
      name: key,
      mode: 'dynamic',
      primary: '',
      members: [],
      best_member: '',
      best_tag: '',
      current_member: '',
      current_tag: '',
      updated_at: '',
      results: {},
    },
  ]
  editingDynamicGroupKey.value = key
  editingOriginalDynamicGroupKey.value = key
  activeMemberSourceKey.value = memberSourceGroups.value[0]?.key || 'static'
  activeNodeTab.value = 'dynamic'
}

// 适用场景：删除正在编辑的动态组，未保存新增组时等价于取消添加。
function removeEditingDynamicGroup() {
  const group = editingDynamicGroup.value
  if (!group) {
    return
  }
  dynamicGroups.value = dynamicGroups.value.filter((item) => item.key !== group.key)
  editingDynamicGroupKey.value = ''
  editingOriginalDynamicGroupKey.value = ''
  memberModalOpen.value = false
  if (selectedTag.value === group.tag) {
    selectedTag.value = firstAvailableNodeTag()
  }
}

// 适用场景：取消动态组编辑，并恢复到最后一次保存或加载的状态。
function cancelDynamicGroupEdit() {
  const group = editingDynamicGroup.value
  if (!group) {
    return
  }
  const originalKey = editingOriginalDynamicGroupKey.value || group.key
  const saved = savedDynamicGroups.value.find((item) => item.key === originalKey)
  if (saved) {
    dynamicGroups.value = dynamicGroups.value.map((item) =>
      item.key === group.key ? cloneDynamicGroups([saved])[0] : item,
    )
  } else {
    dynamicGroups.value = dynamicGroups.value.filter((item) => item.key !== group.key)
    if (selectedTag.value === group.tag) {
      selectedTag.value = firstAvailableNodeTag()
    }
  }
  editingDynamicGroupKey.value = ''
  editingOriginalDynamicGroupKey.value = ''
  memberModalOpen.value = false
}

// 适用场景：动态组被删除后回退到一个真实节点。
function firstAvailableNodeTag() {
  if (staticNodes.value[0]) {
    return staticNodes.value[0].tag
  }
  for (const subscription of subscriptions.value) {
    const nodes = arrayOrEmpty(subscription.nodes)
    if (nodes[0]) {
      return nodes[0].tag
    }
  }
  return ''
}

// 适用场景：生成前端临时动态组 key。
function nextDynamicGroupKey() {
  const used = new Set(dynamicGroups.value.map((group) => group.key))
  let index = dynamicGroups.value.length + 1
  while (used.has(`group-${index}`)) {
    index += 1
  }
  return `group-${index}`
}

// 适用场景：选择动态组作为当前出口。
function selectDynamicGroup(group: DynamicGroup) {
  selectedTag.value = group.tag
}

// 适用场景：进入动态组编辑态。
function editDynamicGroup(group: DynamicGroup) {
  editingDynamicGroupKey.value = group.key
  editingOriginalDynamicGroupKey.value = group.key
  activeMemberSourceKey.value = memberSourceGroups.value[0]?.key || 'static'
}

// 适用场景：修改当前动态组 key，并同步依赖该 tag 的本地选择。
function updateSelectedDynamicGroupKey(value: string) {
  const group = editingDynamicGroup.value
  if (!group) {
    return
  }
  const oldTag = group.tag
  const nextKey = value.trim()
  group.key = nextKey
  group.tag = nextKey ? `group-${nextKey}` : ''
  editingDynamicGroupKey.value = group.key
  if (selectedTag.value === oldTag) {
    selectedTag.value = group.tag
  }
  dynamicOutbound.value = dynamicOutbound.value.map((rule) => ({
    ...rule,
    outbound: rule.outbound === oldTag ? group.tag : rule.outbound,
  }))
}

// 适用场景：切换动态组成员引用。
function toggleDynamicMember(refKey: string, checked: boolean) {
  const group = editingDynamicGroup.value
  if (!group) {
    return
  }
  const next = new Set(arrayOrEmpty(group.members))
  if (checked) {
    next.add(refKey)
  } else {
    next.delete(refKey)
  }
  group.members = [...next]
  if (normalizeGroupMode(group.mode) === 'primary_backup') {
    const members = arrayOrEmpty(group.members)
    if (!members.includes(group.primary)) {
      group.primary = members[0] || ''
    }
  } else {
    group.primary = ''
  }
}

// 适用场景：切换动态组择优策略。
function updateSelectedDynamicGroupMode(value: string) {
  const group = editingDynamicGroup.value
  if (!group) {
    return
  }
  group.mode = normalizeGroupMode(value)
  const members = arrayOrEmpty(group.members)
  if (group.mode === 'primary_backup' && !members.includes(group.primary)) {
    group.primary = members[0] || ''
  }
  if (group.mode === 'dynamic') {
    group.primary = ''
  }
}

// 适用场景：设置主备动态组的主节点。
function updateSelectedDynamicGroupPrimary(value: string) {
  const group = editingDynamicGroup.value
  if (!group || !arrayOrEmpty(group.members).includes(value)) {
    return
  }
  group.primary = value
}

// 适用场景：判断动态组是否包含候选节点。
function hasDynamicMember(refKey: string) {
  return arrayOrEmpty(editingDynamicGroup.value?.members).includes(refKey)
}

// 适用场景：从动态组移除一个已有成员。
function removeDynamicMember(refKey: string) {
  toggleDynamicMember(refKey, false)
}

// 适用场景：打开动态组成员选择弹窗。
function openMemberModal() {
  if (!editingDynamicGroup.value) {
    return
  }
  activeMemberSourceKey.value = memberSourceGroups.value[0]?.key || 'static'
  memberModalOpen.value = true
}

// 适用场景：查找成员引用对应的来源和节点。
function findMemberOption(refKey: string) {
  for (const source of memberSourceGroups.value) {
    const option = arrayOrEmpty(source.nodes).find((item) => item.ref === refKey)
    if (option) {
      return { source, option }
    }
  }
  return null
}

// 适用场景：返回动态组成员展示文案。
function memberLabel(refKey: string) {
  const found = findMemberOption(refKey)
  if (!found) {
    return refKey
  }
  return `${found.source.name} / ${found.option.label}`
}

// 适用场景：返回成员协议和地址摘要。
function memberSubtitle(refKey: string) {
  const found = findMemberOption(refKey)
  if (!found) {
    return ''
  }
  return `${found.option.protocol.toUpperCase()} ${found.option.subtitle}`
}

// 适用场景：返回动态组担当展示文案。
function groupBestText(group: DynamicGroup) {
  if (!group.best_member) {
    if (selectedTag.value === group.tag) {
      if (group.current_member) {
        return `暂无担当，暂用 ${memberLabel(group.current_member)}`
      }
      if (group.current_tag) {
        return `暂无担当，暂用 ${group.current_tag}`
      }
    }
    return '暂无担当'
  }
  return `担当 ${memberLabel(group.best_member)}`
}

// 适用场景：显示动态组当前策略标签。
function groupModeText(group: DynamicGroup) {
  return normalizeGroupMode(group.mode) === 'primary_backup' ? '主备' : '动态'
}

// 适用场景：格式化动态组成员最近探测结果。
function groupProbeText(group: DynamicGroup, refKey: string) {
  const records = arrayOrEmpty(group.results?.[refKey])
  if (records.length === 0) {
    return '无记录'
  }
  return records
    .map((record) => (record.ok ? `${record.delay_ms}ms` : '失败'))
    .join(' / ')
}

// 适用场景：新增一条动态出口规则。
function addDynamicOutboundRule() {
  dynamicOutbound.value = [...dynamicOutbound.value, { match: '', outbound: '' }]
  selectedDynamicOutboundIndex.value = dynamicOutbound.value.length - 1
  activeOutboundSourceKey.value = outboundSourceGroups.value[0]?.key || 'static'
}

// 适用场景：选择正在编辑的动态出口规则。
function selectDynamicOutboundRule(index: number) {
  selectedDynamicOutboundIndex.value = index
}

// 适用场景：删除当前动态出口规则。
function removeSelectedDynamicOutboundRule() {
  if (!selectedDynamicOutboundRule.value) {
    return
  }
  dynamicOutbound.value = dynamicOutbound.value.filter((_, index) => index !== selectedDynamicOutboundIndex.value)
  selectedDynamicOutboundIndex.value = Math.max(Math.min(selectedDynamicOutboundIndex.value, dynamicOutbound.value.length - 1), 0)
}

// 适用场景：更新当前动态出口匹配条件。
function updateSelectedDynamicOutboundMatch(value: string) {
  const rule = selectedDynamicOutboundRule.value
  if (!rule) {
    return
  }
  rule.match = value
}

// 适用场景：选择当前动态出口规则的目标 backend。
function selectDynamicOutboundTarget(tag: string) {
  const rule = selectedDynamicOutboundRule.value
  if (!rule) {
    return
  }
  rule.outbound = tag
}

// 适用场景：展示动态出口规则目标名称。
function outboundLabel(tag: string) {
  for (const group of outboundSourceGroups.value) {
    const node = arrayOrEmpty(group.nodes).find((item) => item.ref === tag)
    if (node) {
      return `${group.name} / ${node.label}`
    }
  }
  return tag || '未选择'
}

// 适用场景：判断 geofile 当前是否启用。
function isGeoFileEnabled(file: GeoFileItem) {
  if (file.role === 'ads-block') {
    return adsBlock.value
  }
  if (file.locked) {
    return true
  }
  return proxyRuleSets.value.includes(file.tag)
}

// 适用场景：切换 geofile 规则启用状态。
function setGeoFileEnabled(file: GeoFileItem, enabled: boolean) {
  if (file.locked) {
    return
  }
  if (file.role === 'ads-block') {
    adsBlock.value = enabled
    return
  }
  const next = new Set(proxyRuleSets.value)
  if (enabled) {
    next.add(file.tag)
  } else {
    next.delete(file.tag)
  }
  proxyRuleSets.value = [...next]
}

// 适用场景：生成 geofile 的人类可读说明。
function geoFileDescription(file: GeoFileItem) {
  if (file.role === 'direct-base') {
    return file.kind === 'geoip' ? '基础直连 IP 规则' : '基础直连域名规则'
  }
  if (file.role === 'ads-block') {
    return '广告拦截域名规则'
  }
  return file.kind === 'geoip' ? '可选代理 IP 规则' : '可选代理域名规则'
}

// 适用场景：按列表 key 读取搜索词。
function listQuery(key: string) {
  return (listSearch.value[key] || '').trim().toLowerCase()
}

// 适用场景：设置列表搜索词。
function setListQuery(key: string, value: string) {
  listSearch.value = { ...listSearch.value, [key]: value }
}

// 适用场景：判断节点是否命中搜索。
function nodeMatchesSearch(node: BackendNode, query: string) {
  if (!query) {
    return true
  }
  return [node.key, node.name, node.tag, node.protocol, node.server, `${node.port}`]
    .join(' ')
    .toLowerCase()
    .includes(query)
}

// 适用场景：返回过滤后的静态节点。
function filteredStaticNodes() {
  const query = listQuery('static')
  return staticNodes.value.filter((node) => nodeMatchesSearch(node, query))
}

// 适用场景：返回过滤后的订阅节点。
function filteredSubscriptionNodes(subscription: SubscriptionGroup) {
  const query = listQuery(`sub.${subscription.key}`)
  return arrayOrEmpty(subscription.nodes).filter((node) => nodeMatchesSearch(node, query))
}

// 适用场景：返回过滤后的动态组。
function filteredDynamicGroups() {
  const query = listQuery('dynamic')
  if (!query) {
    return dynamicGroups.value
  }
  return dynamicGroups.value.filter((group) =>
    [group.key, group.name, group.tag, group.mode, group.primary, ...arrayOrEmpty(group.members)]
      .join(' ')
      .toLowerCase()
      .includes(query),
  )
}

// 适用场景：首屏轻量探测 Web 和 sing-box 状态。
function fetchHealth(finishLoading = true) {
  return fetchHealthInternal(finishLoading)
}

// 适用场景：执行健康探测，并按启动阶段控制 loading 结束时机。
async function fetchHealthInternal(finishLoading: boolean) {
  try {
    const response = await fetch('/api/health', { cache: 'no-store' })
    if (!response.ok) {
      throw new Error(await readError(response))
    }
    health.value = await response.json()
    probing.value = false
  } catch (error) {
    health.value = null
    pageError.value = error instanceof Error ? error.message : String(error)
  } finally {
    if (finishLoading) {
      loading.value = false
    }
  }
}

// 适用场景：登录后加载完整首屏数据。
async function fetchState() {
  if (!token.value) {
    return
  }
  const response = await fetch('/api/state', {
    cache: 'no-store',
    headers: authHeaders(),
  })
  if (response.status === 401 || response.status === 403) {
    logout()
    return
  }
  if (!response.ok) {
    throw new Error(await readError(response))
  }
  applyPanelState(await response.json())
}

// 适用场景：刷新当前连接流水，供 Web 自动轮询。
async function fetchConnections() {
  if (!token.value || connectionsLoading.value) {
    return
  }
  connectionsLoading.value = true
  try {
    const response = await fetch('/api/connections', {
      cache: 'no-store',
      headers: authHeaders(),
    })
    if (response.status === 401 || response.status === 403) {
      logout()
      return
    }
    if (!response.ok) {
      throw new Error(await readError(response))
    }
    const data = (await response.json()) as ConnectionsResponse
    connections.value = arrayOrEmpty(data.connections).map((item) => ({ ...item }))
    connectionsUpdatedAt.value = data.updated_at
    connectionUploadTotal.value = data.upload_total || 0
    connectionDownloadTotal.value = data.download_total || 0
    connectionsError.value = ''
  } catch (error) {
    connectionsError.value = error instanceof Error ? error.message : String(error)
  } finally {
    connectionsLoading.value = false
  }
}

// 适用场景：把连接方向转成中文标签。
function connectionDecisionText(decision: string) {
  if (decision === 'direct') {
    return '直连'
  }
  if (decision === 'proxy') {
    return '代理'
  }
  if (decision === 'reject') {
    return '拦截'
  }
  return '未知'
}

// 适用场景：给连接方向选择展示颜色。
function connectionDecisionColor(decision: string) {
  if (decision === 'direct') {
    return 'green'
  }
  if (decision === 'proxy') {
    return 'blue'
  }
  if (decision === 'reject') {
    return 'red'
  }
  return 'default'
}

// 适用场景：连接流水排序，保持域名在 IP 前面。
function compareConnections(left: ConnectionRow, right: ConnectionRow) {
  const leftRank = connectionIsDomain(left) ? 0 : 1
  const rightRank = connectionIsDomain(right) ? 0 : 1
  if (leftRank !== rightRank) {
    return leftRank - rightRank
  }
  if (connectionSort.value !== 'target') {
    const delta = connectionSortValue(right) - connectionSortValue(left)
    if (delta !== 0) {
      return delta
    }
  }
  return compareConnectionTarget(left, right)
}

// 适用场景：根据用户选择返回连接排序用流量值。
function connectionSortValue(item: ConnectionRow) {
  if (connectionSort.value === 'upload') {
    return item.upload || 0
  }
  if (connectionSort.value === 'download') {
    return item.download || 0
  }
  return item.total || 0
}

// 适用场景：判断连接目标是否为域名。
function connectionIsDomain(item: ConnectionRow) {
  const host = (item.host || '').trim()
  return host !== '' && !looksLikeIP(host)
}

// 适用场景：比较连接目标，域名按英文排序，IPv4 按数值排序。
function compareConnectionTarget(left: ConnectionRow, right: ConnectionRow) {
  const leftTarget = connectionSortTarget(left)
  const rightTarget = connectionSortTarget(right)
  const leftIPv4 = ipv4SortValue(leftTarget)
  const rightIPv4 = ipv4SortValue(rightTarget)
  if (leftIPv4 !== null && rightIPv4 !== null) {
    return leftIPv4 - rightIPv4
  }
  return leftTarget.localeCompare(rightTarget, 'en', { numeric: true, sensitivity: 'base' })
}

// 适用场景：取连接排序目标，优先使用域名，其次目标 IP。
function connectionSortTarget(item: ConnectionRow) {
  return (item.host || item.destination_ip || item.destination || '').trim().toLowerCase()
}

// 适用场景：粗略判断目标是否是 IP。
function looksLikeIP(value: string) {
  const clean = value.trim().replace(/^\[/, '').replace(/\]$/, '')
  return ipv4SortValue(clean) !== null || clean.includes(':')
}

// 适用场景：把 IPv4 转成可比较数值，非 IPv4 返回空。
function ipv4SortValue(value: string) {
  const parts = value.trim().split('.')
  if (parts.length !== 4) {
    return null
  }
  let result = 0
  for (const part of parts) {
    if (!/^\d+$/.test(part)) {
      return null
    }
    const number = Number(part)
    if (number < 0 || number > 255) {
      return null
    }
    result = result * 256 + number
  }
  return result
}

// 适用场景：提交登录表单。
async function login() {
  loginError.value = ''
  const response = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: username.value, password: password.value }),
  })
  if (!response.ok) {
    loginError.value = await readError(response)
    return
  }
  const data = (await response.json()) as LoginResponse
  token.value = data.token
  localStorage.setItem('sboxctl_token', data.token)
  await fetchState()
  await fetchConnections()
}

// 适用场景：首次在 Web 页面初始化账号密码。
async function setupWebAuth() {
  setupError.value = ''
  if (setupPassword.value !== setupConfirm.value) {
    setupError.value = '两次密码不一致'
    return
  }
  setupSaving.value = true
  try {
    const response = await fetch('/api/setup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: setupUsername.value,
        password: setupPassword.value,
      }),
    })
    if (!response.ok) {
      throw new Error(await readError(response))
    }
    health.value = await response.json()
    username.value = setupUsername.value
    password.value = ''
    setupPassword.value = ''
    setupConfirm.value = ''
  } catch (error) {
    setupError.value = error instanceof Error ? error.message : String(error)
  } finally {
    setupSaving.value = false
  }
}

// 适用场景：清除本地登录态。
function logout() {
  token.value = ''
  localStorage.removeItem('sboxctl_token')
  panel.value = null
}

// 适用场景：选择当前激活出口。
function selectNode(node: BackendNode) {
  selectedTag.value = node.tag
}

// 适用场景：格式化节点协议和服务端信息。
function nodeSubtitle(node: BackendNode) {
  return `${node.server}:${node.port}`
}

// 适用场景：把当前出口 tag 转成人能看懂的来源和名称。
function outboundDisplayLabel(tag: string) {
  if (!tag || !panel.value) {
    return '未选择'
  }
  const staticNode = staticNodes.value.find((node) => node.tag === tag)
  if (staticNode) {
    return `静态 / ${staticNode.name || staticNode.key}`
  }
  for (const subscription of subscriptions.value) {
    const node = arrayOrEmpty(subscription.nodes).find((item) => item.tag === tag)
    if (node) {
      return `${subscription.name} / ${node.name || node.key}`
    }
  }
  const group = dynamicGroups.value.find((item) => item.tag === tag)
  if (group) {
    return `group / ${group.name || group.key}`
  }
  return tag
}

// 适用场景：首屏加载后自动跳到当前出口所在的节点 tab。
function tabKeyForOutbound(tag: string) {
  if (!tag || !panel.value) {
    return 'static'
  }
  if (staticNodes.value.some((node) => node.tag === tag)) {
    return 'static'
  }
  for (const subscription of subscriptions.value) {
    if (arrayOrEmpty(subscription.nodes).some((node) => node.tag === tag)) {
      return subscription.key
    }
  }
  if (dynamicGroups.value.some((group) => group.tag === tag)) {
    return 'dynamic'
  }
  return activeNodeTab.value || 'static'
}

// 适用场景：返回节点当前探测显示文本。
function nodeDelayText(node: BackendNode) {
  if (probingNode.value === node.tag) {
    return '探测中'
  }
  return nodeDelays.value[node.tag] || '未测'
}

// 适用场景：返回协议标签颜色。
function protocolColor(node: BackendNode) {
  if (node.protocol === 'group') {
    return 'orange'
  }
  if (node.protocol === 'hy2') {
    return 'geekblue'
  }
  if (node.protocol === 'trojan') {
    return 'gold'
  }
  if (node.protocol === 'ss') {
    return 'green'
  }
  return 'purple'
}

// 适用场景：把探测接口错误归一成短标签。
function probeErrorText(error: unknown) {
  const message = error instanceof Error ? error.message : String(error)
  if (message.includes('outbound not found')) {
    return '未加载'
  }
  if (message.includes('Timeout') || message.includes('探测超时')) {
    return '超时'
  }
  return message || '失败'
}

// 适用场景：打开单节点连续探测弹窗。
function openProbeModal(node: BackendNode) {
  probeModalNode.value = node
  if (!probeSeriesCount.value[node.tag]) {
    probeSeriesCount.value = { ...probeSeriesCount.value, [node.tag]: 10 }
  }
}

// 适用场景：关闭单节点连续探测弹窗。
function closeProbeModal() {
  probeModalNode.value = null
}

// 适用场景：写入单节点连续探测次数。
function setProbeSeriesCount(tag: string, value: number | null) {
  const count = Math.max(1, Math.floor(Number(value || 1)))
  probeSeriesCount.value = { ...probeSeriesCount.value, [tag]: count }
}

// 适用场景：读取单节点连续探测次数。
function currentProbeSeriesCount(tag: string) {
  return probeSeriesCount.value[tag] || 10
}

// 适用场景：读取单节点连续探测结果列表。
function currentProbeSeriesResults(tag: string) {
  return probeSeriesResults.value[tag] || []
}

// 适用场景：追加一次连续探测展示结果。
function appendProbeSeriesResult(tag: string, value: string) {
  probeSeriesResults.value = {
    ...probeSeriesResults.value,
    [tag]: [...currentProbeSeriesResults(tag), value],
  }
}

// 适用场景：保存出口选择和两份规则文件。
async function saveAll(confirmOverwrite: boolean | Event = false) {
  if (!panel.value) {
    return
  }
  const overwrite = confirmOverwrite === true
  saving.value = true
  probing.value = true
  pageError.value = ''
  try {
    const response = await fetch('/api/save', {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({
        service_enabled: serviceEnabled.value,
        active_outbound: selectedTag.value,
        config_hash: configHash.value,
        confirm_overwrite: overwrite,
        static: staticNodes.value.map((node) => ({
          protocol: normalizeStaticProtocol(node.protocol),
          key: node.key,
          name: node.name,
          server: node.server,
          port: Number(node.port),
          password: node.password || '',
          sni: node.sni || '',
          insecure: node.insecure === true,
          obfs_password: node.obfs_password || '',
          uuid: node.uuid || '',
          security: node.security || '',
          alter_id: node.alter_id || 0,
          tls: node.tls === true,
          transport: node.transport || '',
          path: node.path || '',
          host: node.host || '',
          method: node.method || '',
          plugin: node.plugin || '',
          plugin_opts: node.plugin_opts || '',
        })),
        subscriptions: subscriptions.value.map((subscription) => ({
          key: subscription.key,
          name: subscription.name,
          url: subscription.url,
          enabled: subscription.enabled,
          user_agent: subscription.user_agent,
        })),
        dynamic_groups: dynamicGroups.value.map((group) => ({
          key: group.key,
          mode: normalizeGroupMode(group.mode),
          primary: normalizeGroupMode(group.mode) === 'primary_backup' ? group.primary : '',
          members: arrayOrEmpty(group.members),
        })),
        inbound: {
          inbound_mode: normalizedInboundMode(inboundMode.value),
          mixed_listen: mixedListen.value,
          mixed_port: Number(mixedPort.value),
        },
        dynamic_outbound: dynamicOutbound.value,
        force_proxy: forceProxy.value,
        force_direct: forceDirect.value,
        ads_block: adsBlock.value,
        hosts_override: hostsOverride.value,
        proxy_rule_sets: proxyRuleSets.value,
      }),
    })
    if (response.status === 409) {
      const data = await response.json()
      const confirmed = window.confirm(`${data.error || '配置已经不是最新'}，确认覆盖保存？`)
      if (confirmed) {
        await saveAll(true)
      } else {
        pageError.value = data.error || '配置已经不是最新'
      }
      return
    }
    if (!response.ok) {
      throw new Error(await readError(response))
    }
    applyPanelState(await response.json())
  } catch (error) {
    pageError.value = error instanceof Error ? error.message : String(error)
  } finally {
    probing.value = false
    saving.value = false
  }
}

// 适用场景：检查输入目标会命中哪条路由规则。
async function checkRouteTarget() {
  routeCheckError.value = ''
  routeCheckResult.value = null
  const target = routeCheckInput.value.trim()
  if (!target) {
    routeCheckError.value = '请输入域名、IP 或 IP 段'
    return
  }
  routeCheckLoading.value = true
  try {
    const response = await fetch('/api/route/check', {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({ target }),
    })
    if (!response.ok) {
      throw new Error(await readError(response))
    }
    routeCheckResult.value = await response.json()
  } catch (error) {
    routeCheckError.value = error instanceof Error ? error.message : String(error)
  } finally {
    routeCheckLoading.value = false
  }
}

// 适用场景：把路由判断结果转成中文标签。
function routeDecisionText(result: RouteCheckResult | null) {
  if (!result) {
    return ''
  }
  if (result.decision === 'direct') {
    return '直连'
  }
  if (result.decision === 'reject') {
    return '拦截'
  }
  return '代理'
}

// 适用场景：给路由判断结果选择展示颜色。
function routeDecisionColor(result: RouteCheckResult | null) {
  if (!result) {
    return 'default'
  }
  if (result.decision === 'direct') {
    return 'green'
  }
  if (result.decision === 'reject') {
    return 'red'
  }
  return 'purple'
}

// 适用场景：生成订阅更新按钮 loading key。
function subscriptionUpdateKey(name: string, useProxy: boolean) {
  return `${name}:${useProxy ? 'proxy' : 'direct'}`
}

// 适用场景：刷新单个订阅缓存，代理语义由按钮明确指定。
async function updateSubscription(name: string, useProxy: boolean) {
  updatingSubscription.value = subscriptionUpdateKey(name, useProxy)
  pageError.value = ''
  try {
    const response = await fetch('/api/subscription/update', {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({ name, use_proxy: useProxy }),
    })
    if (!response.ok) {
      throw new Error(await readError(response))
    }
    applyPanelState(await response.json())
  } catch (error) {
    pageError.value = error instanceof Error ? error.message : String(error)
  } finally {
    updatingSubscription.value = ''
  }
}

// 适用场景：请求一次节点时延探测并返回展示文本。
async function probeNodeOnce(node: BackendNode) {
  const response = await fetch('/api/node/probe', {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ tag: node.tag }),
  })
  if (!response.ok) {
    throw new Error(await readError(response))
  }
  const data = (await response.json()) as ProbeResponse
  return `${data.delay_ms} ms`
}

// 适用场景：探测单个节点一次，供批量探测复用。
async function probeNode(node: BackendNode) {
  probingNode.value = node.tag
  try {
    nodeDelays.value = { ...nodeDelays.value, [node.tag]: await probeNodeOnce(node) }
  } catch (error) {
    nodeDelays.value = { ...nodeDelays.value, [node.tag]: probeErrorText(error) }
  } finally {
    probingNode.value = ''
  }
}

// 适用场景：按用户指定次数连续探测单个节点。
async function probeNodeSeries(node: BackendNode) {
  if (probingSeriesTag.value) {
    return
  }
  const count = currentProbeSeriesCount(node.tag)
  probingSeriesTag.value = node.tag
  probeModalNode.value = node
  probeSeriesResults.value = { ...probeSeriesResults.value, [node.tag]: [] }
  try {
    for (let index = 0; index < count; index += 1) {
      probingNode.value = node.tag
      try {
        const result = await probeNodeOnce(node)
        nodeDelays.value = { ...nodeDelays.value, [node.tag]: result }
        appendProbeSeriesResult(node.tag, `第 ${index + 1} 次 ${result}`)
      } catch (error) {
        const result = probeErrorText(error)
        nodeDelays.value = { ...nodeDelays.value, [node.tag]: result }
        appendProbeSeriesResult(node.tag, `第 ${index + 1} 次 ${result}`)
      }
    }
  } finally {
    probingNode.value = ''
    probingSeriesTag.value = ''
  }
}

// 适用场景：按顺序探测一个列表内的节点时延。
async function probeNodes(group: string, nodes: BackendNode[]) {
  probingGroup.value = group
  pageError.value = ''
  try {
    for (const node of nodes) {
      await probeNode(node)
    }
  } finally {
    probingGroup.value = ''
  }
}

// 适用场景：启动首屏探测和登录态恢复。
async function boot() {
  try {
    await fetchHealth(false)
    if (token.value && health.value && !health.value.setup_required) {
      await fetchState()
      await fetchConnections()
    }
  } catch (error) {
    pageError.value = error instanceof Error ? error.message : String(error)
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  void boot()
})

const uptimeTimer = window.setInterval(() => {
  nowTick.value = Date.now()
}, 1000)

const connectionsTimer = window.setInterval(() => {
  void fetchConnections()
}, 2000)

onUnmounted(() => {
  window.clearInterval(uptimeTimer)
  window.clearInterval(connectionsTimer)
})
</script>

<template>
  <main v-if="loading" class="center-page">
    <a-alert message="正在探测 sboxctl" type="info" show-icon />
  </main>

  <main v-else-if="showAbnormal" class="center-page">
    <a-alert
      message="面板暂不可用"
      :description="pageError || '正在持续探测服务状态'"
      type="error"
      show-icon
    />
  </main>

  <main v-else-if="setupRequired" class="login-page">
    <section class="login-panel">
      <h1>初始化登录</h1>
      <p>首次进入需要配置 Web 账号密码</p>
      <a-form layout="vertical" @submit.prevent="setupWebAuth">
        <a-form-item label="账号">
          <a-input v-model:value="setupUsername" autocomplete="username" />
        </a-form-item>
        <a-form-item label="密码">
          <a-input-password v-model:value="setupPassword" autocomplete="new-password" />
        </a-form-item>
        <a-form-item label="确认密码">
          <a-input-password v-model:value="setupConfirm" autocomplete="new-password" />
        </a-form-item>
        <a-alert v-if="setupError" :message="setupError" type="error" show-icon />
        <a-button class="full-button" type="primary" html-type="submit" :loading="setupSaving">
          保存账号密码
        </a-button>
      </a-form>
    </section>
  </main>

  <main v-else-if="!isLoggedIn || !panel" class="login-page">
    <section class="login-panel">
      <h1>sboxctl</h1>
      <p>88.1 代理编排面板</p>
      <a-form layout="vertical" @submit.prevent="login">
        <a-form-item label="账号">
          <a-input v-model:value="username" autocomplete="username" />
        </a-form-item>
        <a-form-item label="密码">
          <a-input-password v-model:value="password" autocomplete="current-password" />
        </a-form-item>
        <a-alert v-if="loginError" :message="loginError" type="error" show-icon />
        <a-button class="full-button" type="primary" html-type="submit">登录</a-button>
      </a-form>
    </section>
  </main>

  <main v-else class="panel-page">
    <header class="panel-header">
      <div>
        <strong>sboxctl</strong>
        <span>当前出口 {{ activeOutboundText }}</span>
        <div class="feature-row">
          <a-tag color="blue">TUN</a-tag>
          <a-tag color="purple">FakeIP</a-tag>
          <a-tag color="cyan">Geo Rules</a-tag>
          <a-tag color="geekblue">HY2</a-tag>
          <a-tag color="orange">Dynamic</a-tag>
          <a-tag color="green">Cache</a-tag>
          <a-tag color="orange">Force Rules</a-tag>
        </div>
      </div>
      <div class="status-row">
        <label class="service-switch">
          <span>服务</span>
          <a-switch
            v-model:checked="serviceEnabled"
            size="small"
            :loading="saving && serviceEnabled !== savedServiceEnabled"
          />
        </label>
        <a-tag :color="isServiceRunning ? 'green' : 'red'">
          sing-box {{ health?.sing_box_status }}
        </a-tag>
        <a-tag color="default">运行 {{ uptimeText }}</a-tag>
        <a-tag color="default">版本 {{ versionText }}</a-tag>
        <a-tag color="blue">更新 {{ lastUpdateText }}</a-tag>
        <a-tag v-if="probing" color="gold">探测中</a-tag>
        <a-button size="small" @click="helpOpen = true">查看说明</a-button>
        <a-button size="small" @click="logout">退出</a-button>
        <a-button
          type="primary"
          :class="{ 'dirty-save': hasChanges }"
          :disabled="!hasChanges"
          :loading="saving"
          @click="saveAll"
        >
          {{ hasChanges ? '保存并应用' : '无改动' }}
        </a-button>
      </div>
    </header>

    <a-modal
      v-model:open="helpOpen"
      title="机制说明"
      width="760px"
      :footer="null"
    >
      <div class="help-list">
        <section v-for="section in helpSections" :key="section.title" class="help-section">
          <h3>{{ section.title }}</h3>
          <ul>
            <li v-for="item in section.items" :key="item">{{ item }}</li>
          </ul>
        </section>
      </div>
    </a-modal>

    <a-alert
      v-if="pageError"
      class="page-alert"
      :message="pageError"
      type="error"
      show-icon
      closable
      @close="pageError = ''"
    />
    <a-alert
      v-for="warning in configWarnings"
      :key="warning"
      class="page-alert"
      :message="warning"
      type="warning"
      show-icon
    />

    <section class="workbench">
      <aside class="node-column">
        <section class="node-tabs">
          <div class="node-actions">
            <a-button size="small" @click="addStaticNode">新增静态</a-button>
            <a-button size="small" @click="addSubscription">新增订阅</a-button>
          </div>
          <a-tabs v-model:activeKey="activeNodeTab" size="small">
            <a-tab-pane key="static" :tab="`静态 (${staticNodes.length})`">
              <div class="tab-toolbar">
                <a-input
                  :value="listSearch.static || ''"
                  size="small"
                  placeholder="搜索静态节点"
                  @change="(event: Event) => setListQuery('static', (event.target as HTMLInputElement).value)"
                />
                <a-button
                  size="small"
                  :loading="probingGroup === 'static'"
                  :disabled="staticNodes.length === 0"
                  @click="probeNodes('static', staticNodes)"
                >
                  探测
                </a-button>
              </div>
              <div class="tab-body">
                <div
                  v-for="node in filteredStaticNodes()"
                  :key="node.tag"
                  class="node-list-row"
                >
                  <button
                    class="node-item"
                    :class="{ active: node.tag === selectedTag }"
                    type="button"
                    @click="selectNode(node)"
                  >
                    <div class="node-title">
                      <a-tag :color="protocolColor(node)">{{ node.protocol.toUpperCase() }}</a-tag>
                      <span>{{ node.name || node.tag }}</span>
                    </div>
                    <small>{{ nodeSubtitle(node) }}</small>
                    <em>{{ nodeDelayText(node) }}</em>
                  </button>
                  <div class="row-actions">
                    <a-button
                      size="small"
                      :loading="probingSeriesTag === node.tag"
                      :disabled="probingSeriesTag !== '' && probingSeriesTag !== node.tag"
                      @click="openProbeModal(node)"
                    >
                      探测
                    </a-button>
                    <a-button size="small" @click="editStaticNode(node)">修改</a-button>
                    <a-button size="small" danger @click="removeStaticNode(node)">删除</a-button>
                  </div>
                </div>
                <div v-if="filteredStaticNodes().length === 0" class="empty-line">无静态节点</div>
              </div>
            </a-tab-pane>

            <a-tab-pane
              v-for="subscription in subscriptions"
              :key="subscription.key"
              :tab="`${subscription.name} (${arrayOrEmpty(subscription.nodes).length})`"
            >
              <div class="tab-toolbar">
                <a-input
                  :value="listSearch[`sub.${subscription.key}`] || ''"
                  size="small"
                  :placeholder="`搜索 ${subscription.name}`"
                  @change="(event: Event) => setListQuery(`sub.${subscription.key}`, (event.target as HTMLInputElement).value)"
                />
                <div class="toolbar-actions">
                  <a-button
                    size="small"
                    :loading="updatingSubscription === subscriptionUpdateKey(subscription.key, true)"
                    :disabled="updatingSubscription.startsWith(`${subscription.key}:`)"
                    @click="updateSubscription(subscription.key, true)"
                  >
                    更新
                  </a-button>
                  <a-button
                    size="small"
                    :loading="updatingSubscription === subscriptionUpdateKey(subscription.key, false)"
                    :disabled="updatingSubscription.startsWith(`${subscription.key}:`)"
                    @click="updateSubscription(subscription.key, false)"
                  >
                    更新不走代理
                  </a-button>
                  <a-button size="small" @click="editSubscription(subscription)">修改</a-button>
                  <a-button size="small" danger @click="removeSubscription(subscription)">删除</a-button>
                  <a-button
                    size="small"
                    :loading="probingGroup === subscription.key"
                    :disabled="arrayOrEmpty(subscription.nodes).length === 0"
                    @click="probeNodes(subscription.key, arrayOrEmpty(subscription.nodes))"
                  >
                    探测
                  </a-button>
                </div>
              </div>
              <a-alert
                v-if="subscription.error"
                class="mini-alert"
                :message="subscription.error"
                type="warning"
                show-icon
              />
              <div class="tab-body">
                <div
                  v-for="node in filteredSubscriptionNodes(subscription)"
                  :key="node.tag"
                  class="node-list-row"
                >
                  <button
                    class="node-item"
                    :class="{ active: node.tag === selectedTag }"
                    type="button"
                    @click="selectNode(node)"
                  >
                    <div class="node-title">
                      <a-tag :color="protocolColor(node)">{{ node.protocol.toUpperCase() }}</a-tag>
                      <span>{{ node.name || node.tag }}</span>
                    </div>
                    <small>{{ nodeSubtitle(node) }}</small>
                    <em>{{ nodeDelayText(node) }}</em>
                  </button>
                  <div class="row-actions">
                    <a-button
                      size="small"
                      :loading="probingSeriesTag === node.tag"
                      :disabled="probingSeriesTag !== '' && probingSeriesTag !== node.tag"
                      @click="openProbeModal(node)"
                    >
                      探测
                    </a-button>
                  </div>
                </div>
                <div v-if="filteredSubscriptionNodes(subscription).length === 0" class="empty-line">
                  无可用节点缓存
                </div>
              </div>
            </a-tab-pane>

            <a-tab-pane key="dynamic" :tab="`动态 (${dynamicGroups.length})`">
              <div class="tab-toolbar">
                <a-input
                  :value="listSearch.dynamic || ''"
                  size="small"
                  placeholder="搜索动态组"
                  @change="(event: Event) => setListQuery('dynamic', (event.target as HTMLInputElement).value)"
                />
                <a-button size="small" @click="addDynamicGroup">添加</a-button>
              </div>
              <div class="tab-body">
                <div
                  v-for="group in filteredDynamicGroups()"
                  :key="group.key"
                  class="node-item group-item"
                  :class="{ active: group.tag === selectedTag }"
                >
                  <button class="group-select-button" type="button" @click="selectDynamicGroup(group)">
                    <div class="node-title">
                      <a-tag color="orange">GROUP</a-tag>
                      <a-tag :color="normalizeGroupMode(group.mode) === 'primary_backup' ? 'gold' : 'blue'">
                        {{ groupModeText(group) }}
                      </a-tag>
                      <span>{{ group.name || group.key }}</span>
                    </div>
                    <small>{{ arrayOrEmpty(group.members).length }} 个成员 · {{ groupBestText(group) }}</small>
                    <em>{{ group.updated_at ? formatTime(group.updated_at) : '未评估' }}</em>
                  </button>
                  <a-button size="small" @click="editDynamicGroup(group)">编辑</a-button>
                </div>
                <div v-if="dynamicGroups.length === 0" class="empty-line">无动态组</div>

                <section v-if="editingDynamicGroup" class="dynamic-editor">
                  <div class="pane-title">
                    <strong>组配置</strong>
                    <div class="toolbar-actions">
                      <span>{{ editingDynamicGroup.tag }}</span>
                      <a-button size="small" @click="cancelDynamicGroupEdit">取消</a-button>
                      <a-button size="small" danger @click="removeEditingDynamicGroup">删除</a-button>
                    </div>
                  </div>
                  <label class="field-row">
                    <span>组 key</span>
                    <a-input
                      :value="editingDynamicGroup.key"
                      placeholder="例如 main"
                      @change="(event: Event) => updateSelectedDynamicGroupKey((event.target as HTMLInputElement).value)"
                    />
                  </label>
                  <label class="field-row">
                    <span>模式</span>
                    <a-segmented
                      :value="normalizeGroupMode(editingDynamicGroup.mode)"
                      :options="[
                        { label: '动态', value: 'dynamic' },
                        { label: '主备', value: 'primary_backup' },
                      ]"
                      @change="(value: string | number) => updateSelectedDynamicGroupMode(String(value))"
                    />
                  </label>
                  <label
                    v-if="normalizeGroupMode(editingDynamicGroup.mode) === 'primary_backup'"
                    class="field-row"
                  >
                    <span>主节点</span>
                    <a-select
                      :value="editingDynamicGroup.primary"
                      placeholder="选择主节点"
                      @change="(value: string) => updateSelectedDynamicGroupPrimary(value)"
                    >
                      <a-select-option
                        v-for="member in arrayOrEmpty(editingDynamicGroup.members)"
                        :key="member"
                        :value="member"
                      >
                        {{ memberLabel(member) }}
                      </a-select-option>
                    </a-select>
                  </label>
                  <div class="tab-toolbar member-toolbar">
                    <span>已选成员</span>
                    <a-button size="small" @click="openMemberModal">新增节点</a-button>
                  </div>
                  <div class="probe-history selected-member-list">
                    <div
                      v-for="member in arrayOrEmpty(editingDynamicGroup.members)"
                      :key="member"
                      class="probe-row selected-member-row"
                    >
                      <span>
                        <strong>{{ memberLabel(member) }}</strong>
                        <a-tag
                          v-if="normalizeGroupMode(editingDynamicGroup.mode) === 'primary_backup' && editingDynamicGroup.primary === member"
                          color="gold"
                        >
                          主
                        </a-tag>
                        <small>{{ memberSubtitle(member) }}</small>
                      </span>
                      <em>{{ groupProbeText(editingDynamicGroup, member) }}</em>
                      <a-button size="small" danger @click="removeDynamicMember(member)">删除</a-button>
                    </div>
                <div v-if="arrayOrEmpty(editingDynamicGroup.members).length === 0" class="empty-line">
                      还没有成员
                    </div>
                  </div>
                </section>

                <a-modal
                  v-if="editingDynamicGroup"
                  v-model:open="memberModalOpen"
                  title="新增节点"
                  :footer="null"
                  width="720px"
                >
                  <a-tabs
                    v-model:activeKey="activeMemberSourceKey"
                    class="member-source-tabs member-modal-tabs"
                    tab-position="left"
                    size="small"
                  >
                    <a-tab-pane
                      v-for="source in memberSourceGroups"
                      :key="source.key"
                      :tab="`${source.name} (${arrayOrEmpty(source.nodes).length})`"
                    >
                      <div class="member-list">
                        <label
                          v-for="option in arrayOrEmpty(source.nodes)"
                          :key="option.ref"
                          class="member-option"
                        >
                          <input
                            type="checkbox"
                            :checked="hasDynamicMember(option.ref)"
                            @change="(event: Event) => toggleDynamicMember(option.ref, (event.target as HTMLInputElement).checked)"
                          />
                          <span>
                            <strong>{{ option.label }}</strong>
                            <small>{{ option.protocol.toUpperCase() }} {{ option.subtitle }}</small>
                          </span>
                        </label>
                        <div v-if="arrayOrEmpty(source.nodes).length === 0" class="empty-line">无可选节点</div>
                      </div>
                    </a-tab-pane>
                  </a-tabs>
                </a-modal>
              </div>
            </a-tab-pane>

            <a-tab-pane key="geofiles" :tab="`GeoFiles (${panel.geofiles.length})`">
              <div class="geofile-list geofile-option-list">
                <div class="geofile-item">
                  <div class="geofile-info">
                    <strong>Hosts override</strong>
                    <small>/etc/hosts</small>
                  </div>
                  <div class="geofile-meta">
                    <a-tag color="cyan">DNS</a-tag>
                    <a-tag :color="hostsOverride ? 'green' : 'default'">
                      {{ hostsOverride ? '开启' : '关闭' }}
                    </a-tag>
                  </div>
                  <div class="geofile-switch">
                    <a-switch v-model:checked="hostsOverride" size="small" />
                  </div>
                </div>
              </div>
              <a-tabs class="geo-inner-tabs" tab-position="left" size="small">
                <a-tab-pane key="geoip" :tab="`geoip (${geoIPFiles.length})`">
                  <div class="geofile-list">
                    <div
                      v-for="file in geoIPFiles"
                      :key="file.tag"
                      class="geofile-item"
                      :class="{ missing: !file.exists }"
                    >
                      <div class="geofile-info">
                        <strong>{{ file.tag }}</strong>
                        <small>{{ geoFileDescription(file) }}</small>
                      </div>
                      <div class="geofile-meta">
                        <a-tag v-if="file.locked" color="blue">锁定</a-tag>
                        <a-tag v-else-if="file.role === 'ads-block'" color="orange">广告</a-tag>
                        <a-tag v-else color="purple">代理</a-tag>
                        <a-tag :color="file.exists ? 'green' : 'red'">
                          {{ file.exists ? '存在' : '缺失' }}
                        </a-tag>
                        <span>{{ formatBytes(file.size_bytes) }}</span>
                      </div>
                      <div class="geofile-switch">
                        <a-switch
                          size="small"
                          :disabled="file.locked"
                          :checked="isGeoFileEnabled(file)"
                          @change="(checked: boolean) => setGeoFileEnabled(file, checked)"
                        />
                      </div>
                    </div>
                  </div>
                </a-tab-pane>

                <a-tab-pane key="geosite" :tab="`geosite (${geoSiteFiles.length})`">
                  <div class="geofile-list">
                    <div
                      v-for="file in geoSiteFiles"
                      :key="file.tag"
                      class="geofile-item"
                      :class="{ missing: !file.exists }"
                    >
                      <div class="geofile-info">
                        <strong>{{ file.tag }}</strong>
                        <small>{{ geoFileDescription(file) }}</small>
                      </div>
                      <div class="geofile-meta">
                        <a-tag v-if="file.locked" color="blue">锁定</a-tag>
                        <a-tag v-else-if="file.role === 'ads-block'" color="orange">广告</a-tag>
                        <a-tag v-else color="purple">代理</a-tag>
                        <a-tag :color="file.exists ? 'green' : 'red'">
                          {{ file.exists ? '存在' : '缺失' }}
                        </a-tag>
                        <span>{{ formatBytes(file.size_bytes) }}</span>
                      </div>
                      <div class="geofile-switch">
                        <a-switch
                          size="small"
                          :disabled="file.locked"
                          :checked="isGeoFileEnabled(file)"
                          @change="(checked: boolean) => setGeoFileEnabled(file, checked)"
                        />
                      </div>
                    </div>
                  </div>
                </a-tab-pane>
              </a-tabs>
          </a-tab-pane>
        </a-tabs>
          <a-modal
            :open="probeModalNode !== null"
            title="节点探测"
            width="420px"
            :footer="null"
            @cancel="closeProbeModal"
          >
            <div v-if="probeModalNode" class="probe-modal">
              <div class="probe-modal-head">
                <strong>{{ probeModalNode.name || probeModalNode.tag }}</strong>
                <small>{{ probeModalNode.protocol.toUpperCase() }} {{ nodeSubtitle(probeModalNode) }}</small>
              </div>
              <div class="probe-popover-controls">
                <span>次数</span>
                <a-input-number
                  class="probe-count-input"
                  size="small"
                  :min="1"
                  :value="currentProbeSeriesCount(probeModalNode.tag)"
                  @change="(value: number | null) => probeModalNode && setProbeSeriesCount(probeModalNode.tag, value)"
                />
                <a-button
                  size="small"
                  type="primary"
                  :loading="probingSeriesTag === probeModalNode.tag"
                  :disabled="probingSeriesTag !== '' && probingSeriesTag !== probeModalNode.tag"
                  @click="probeNodeSeries(probeModalNode)"
                >
                  开始
                </a-button>
              </div>
              <div class="probe-popover-results probe-modal-results">
                <div
                  v-for="(result, index) in currentProbeSeriesResults(probeModalNode.tag)"
                  :key="`${probeModalNode.tag}-${index}`"
                >
                  {{ result }}
                </div>
                <div v-if="currentProbeSeriesResults(probeModalNode.tag).length === 0">暂无结果</div>
              </div>
            </div>
          </a-modal>
          <a-modal
            v-model:open="staticModalOpen"
            title="静态节点"
            width="520px"
            ok-text="保存到临时配置"
            @ok="saveStaticDraft"
          >
            <div class="form-grid">
              <label class="field-row">
                <span>类型</span>
                <a-select v-model:value="staticForm.protocol" @change="(value: string | number) => updateStaticProtocol(String(value))">
                  <a-select-option value="hy2">HY2</a-select-option>
                  <a-select-option value="vmess">VMess</a-select-option>
                  <a-select-option value="ss">SS</a-select-option>
                  <a-select-option value="trojan">Trojan</a-select-option>
                </a-select>
              </label>
              <label class="field-row">
                <span>key</span>
                <a-input v-model:value="staticForm.key" placeholder="jp-hy2" />
              </label>
              <label class="field-row">
                <span>名称</span>
                <a-input v-model:value="staticForm.name" placeholder="日本JP-HY2" />
              </label>
              <label class="field-row">
                <span>server</span>
                <a-input v-model:value="staticForm.server" placeholder="example.com" />
              </label>
              <label class="field-row">
                <span>port</span>
                <a-input v-model:value="staticForm.port" type="number" />
              </label>
              <label v-if="staticForm.protocol === 'hy2' || staticForm.protocol === 'trojan'" class="field-row">
                <span>password</span>
                <a-input v-model:value="staticForm.password" />
              </label>
              <label v-if="staticForm.protocol !== 'ss'" class="field-row">
                <span>sni</span>
                <a-input v-model:value="staticForm.sni" />
              </label>
              <label v-if="staticForm.protocol === 'hy2'" class="field-row">
                <span>obfs password</span>
                <a-input v-model:value="staticForm.obfs_password" />
              </label>
              <template v-if="staticForm.protocol === 'vmess'">
                <label class="field-row">
                  <span>uuid</span>
                  <a-input v-model:value="staticForm.uuid" />
                </label>
                <label class="field-row">
                  <span>security</span>
                  <a-input v-model:value="staticForm.security" placeholder="auto" />
                </label>
                <label class="field-row">
                  <span>alter id</span>
                  <a-input v-model:value="staticForm.alter_id" type="number" />
                </label>
              </template>
              <template v-if="staticForm.protocol === 'vmess' || staticForm.protocol === 'trojan'">
                <label class="field-row">
                  <span>transport</span>
                  <a-select v-model:value="staticForm.transport">
                    <a-select-option value="">tcp</a-select-option>
                    <a-select-option value="ws">ws</a-select-option>
                  </a-select>
                </label>
                <label v-if="staticForm.transport === 'ws'" class="field-row">
                  <span>path</span>
                  <a-input v-model:value="staticForm.path" placeholder="/" />
                </label>
                <label v-if="staticForm.transport === 'ws'" class="field-row">
                  <span>host</span>
                  <a-input v-model:value="staticForm.host" />
                </label>
                <label class="field-row inline-field">
                  <span>tls</span>
                  <a-switch v-model:checked="staticForm.tls" size="small" />
                </label>
              </template>
              <template v-if="staticForm.protocol === 'ss'">
                <label class="field-row">
                  <span>method</span>
                  <a-input v-model:value="staticForm.method" placeholder="aes-128-gcm" />
                </label>
                <label class="field-row">
                  <span>password</span>
                  <a-input v-model:value="staticForm.password" />
                </label>
                <label class="field-row">
                  <span>plugin</span>
                  <a-input v-model:value="staticForm.plugin" placeholder="obfs-local" />
                </label>
                <label class="field-row">
                  <span>plugin opts</span>
                  <a-input v-model:value="staticForm.plugin_opts" placeholder="obfs=http;obfs-host=example.com" />
                </label>
              </template>
              <label v-if="staticForm.protocol !== 'ss'" class="field-row inline-field">
                <span>insecure</span>
                <a-switch v-model:checked="staticForm.insecure" size="small" />
              </label>
            </div>
          </a-modal>
          <a-modal
            v-model:open="subscriptionModalOpen"
            title="订阅"
            width="560px"
            ok-text="保存到临时配置"
            @ok="saveSubscriptionDraft"
          >
            <a-alert
              class="modal-hint"
              type="info"
              show-icon
              message="这里保存到临时配置；右上角保存并应用后，新增或修改的订阅才会拉取并生效。"
              description="订阅列表里的更新按钮只使用已经保存的订阅配置，不会读取这个表单里未应用的内容。"
            />
            <div class="form-grid">
              <label class="field-row">
                <span>key</span>
                <a-input v-model:value="subscriptionForm.key" placeholder="main" />
              </label>
              <label class="field-row">
                <span>名称</span>
                <a-input v-model:value="subscriptionForm.name" placeholder="main" />
              </label>
              <label class="field-row wide-field">
                <span>url</span>
                <a-input v-model:value="subscriptionForm.url" />
              </label>
              <label class="field-row">
                <span>user agent</span>
                <a-input v-model:value="subscriptionForm.user_agent" />
              </label>
              <label class="field-row inline-field">
                <span>启用</span>
                <a-switch v-model:checked="subscriptionForm.enabled" size="small" />
              </label>
            </div>
          </a-modal>
        </section>
      </aside>

      <section class="rules-column">
        <a-tabs class="rule-tabs" size="small">
          <a-tab-pane key="inbound" tab="入口">
            <div class="rule-pane">
              <div class="pane-title">
                <strong>入口配置</strong>
                <span>mixed 监听</span>
              </div>
              <div class="form-grid">
                <label class="field-row">
                  <span>模式</span>
                  <a-segmented
                    v-model:value="inboundMode"
                    :options="[
                      { label: 'TUN', value: 'tun' },
                      { label: 'Mixed', value: 'mixed' },
                    ]"
                  />
                </label>
                <label class="field-row">
                  <span>mixed listen</span>
                  <a-input v-model:value="mixedListen" placeholder="0.0.0.0" />
                </label>
                <label class="field-row">
                  <span>mixed port</span>
                  <a-input-number v-model:value="mixedPort" :min="1" :max="65535" />
                </label>
              </div>
            </div>
          </a-tab-pane>

          <a-tab-pane key="proxy" tab="强制走代理">
            <div class="rule-pane">
              <div class="pane-title">
                <strong>强制走代理</strong>
                <span>force_proxy.list</span>
              </div>
              <a-textarea
                v-model:value="forceProxy"
                class="rule-textarea"
                spellcheck="false"
              />
            </div>
          </a-tab-pane>

          <a-tab-pane key="direct" tab="强制不走代理">
            <div class="rule-pane">
              <div class="pane-title">
                <strong>强制不走代理</strong>
                <span>force_direct.list</span>
              </div>
              <a-textarea
                v-model:value="forceDirect"
                class="rule-textarea"
                spellcheck="false"
              />
            </div>
          </a-tab-pane>

          <a-tab-pane key="dynamic-outbound" :tab="`动态出口 (${dynamicOutbound.length})`">
            <div class="rule-pane dynamic-outbound-pane">
              <div class="tab-toolbar">
                <span>目的域名或 IP 固定走指定 backend</span>
                <a-button size="small" @click="addDynamicOutboundRule">添加</a-button>
              </div>
              <div class="dynamic-outbound-layout">
                <div class="dynamic-rule-list">
                  <button
                    v-for="(rule, index) in dynamicOutbound"
                    :key="`${rule.match}-${index}`"
                    class="dynamic-rule-item"
                    :class="{ active: index === selectedDynamicOutboundIndex }"
                    type="button"
                    @click="selectDynamicOutboundRule(index)"
                  >
                    <strong>{{ rule.match || '未填写匹配' }}</strong>
                    <small>{{ outboundLabel(rule.outbound) }}</small>
                  </button>
                  <div v-if="dynamicOutbound.length === 0" class="empty-line">无动态出口规则</div>
                </div>

                <section v-if="selectedDynamicOutboundRule" class="dynamic-outbound-editor">
                  <div class="pane-title">
                    <strong>规则配置</strong>
                    <a-button size="small" danger @click="removeSelectedDynamicOutboundRule">删除</a-button>
                  </div>
                  <a-input
                    :value="selectedDynamicOutboundRule.match"
                    placeholder="domain:chatgpt.com 或 1.2.3.4/32"
                    @change="(event: Event) => updateSelectedDynamicOutboundMatch((event.target as HTMLInputElement).value)"
                  />
                  <div class="outbound-target-row">
                    <span>{{ outboundLabel(selectedDynamicOutboundRule.outbound) }}</span>
                    <a-button size="small" @click="outboundModalOpen = true">选择 backend</a-button>
                  </div>
                </section>

                <a-modal
                  v-if="selectedDynamicOutboundRule"
                  v-model:open="outboundModalOpen"
                  title="选择动态出口 backend"
                  :footer="null"
                  width="720px"
                >
                  <a-tabs
                    v-model:activeKey="activeOutboundSourceKey"
                    class="member-source-tabs member-modal-tabs"
                    tab-position="left"
                    size="small"
                  >
                    <a-tab-pane
                      v-for="source in outboundSourceGroups"
                      :key="source.key"
                      :tab="`${source.name} (${arrayOrEmpty(source.nodes).length})`"
                    >
                      <div class="member-list">
                        <button
                          v-for="option in arrayOrEmpty(source.nodes)"
                          :key="option.ref"
                          class="outbound-option"
                          :class="{ active: option.ref === selectedDynamicOutboundRule.outbound }"
                          type="button"
                          @click="selectDynamicOutboundTarget(option.ref); outboundModalOpen = false"
                        >
                          <span>
                            <strong>{{ option.label }}</strong>
                            <small>{{ option.protocol.toUpperCase() }} {{ option.subtitle }}</small>
                          </span>
                        </button>
                        <div v-if="arrayOrEmpty(source.nodes).length === 0" class="empty-line">无可选 backend</div>
                      </div>
                    </a-tab-pane>
                  </a-tabs>
                </a-modal>
              </div>
            </div>
          </a-tab-pane>

          <a-tab-pane key="route-check" tab="路由检查">
            <div class="rule-pane route-check-pane">
              <div class="pane-title">
                <strong>路由检查</strong>
                <span>域名 / IP / IP 段</span>
              </div>
              <div class="route-check-form">
                <a-input
                  v-model:value="routeCheckInput"
                  placeholder="www.google.com 或 8.8.8.8 或 192.168.0.0/16"
                  @pressEnter="checkRouteTarget"
                />
                <a-button
                  type="primary"
                  :loading="routeCheckLoading"
                  @click="checkRouteTarget"
                >
                  检查
                </a-button>
              </div>
              <a-alert v-if="routeCheckError" :message="routeCheckError" type="error" show-icon />
              <section v-if="routeCheckResult" class="route-check-result">
                <div class="route-result-head">
                  <a-tag :color="routeDecisionColor(routeCheckResult)">
                    {{ routeDecisionText(routeCheckResult) }}
                  </a-tag>
                  <strong>{{ routeCheckResult.target }}</strong>
                  <span>{{ routeCheckResult.kind }}</span>
                </div>
                <dl>
                  <dt>命中</dt>
                  <dd>{{ routeCheckResult.matched_rule }}</dd>
                  <dt>原因</dt>
                  <dd>{{ routeCheckResult.reason }}</dd>
                  <dt>出站</dt>
                  <dd>{{ routeCheckResult.outbound || '-' }}</dd>
                </dl>
                <p v-for="note in routeCheckResult.notes" :key="note">{{ note }}</p>
              </section>
            </div>
          </a-tab-pane>

          <a-tab-pane key="connections" tab="连接">
            <div class="rule-pane connections-pane">
              <div class="pane-title">
                <strong>当前连接</strong>
                <span>{{ filteredConnections.length }} / {{ connections.length }}</span>
              </div>
              <div class="connection-toolbar">
                <a-input
                  v-model:value="connectionFilter"
                  placeholder="过滤域名、IP、来源、规则"
                />
                <a-select v-model:value="connectionSort" class="connection-sort-select">
                  <a-select-option value="total">总流量</a-select-option>
                  <a-select-option value="download">下载</a-select-option>
                  <a-select-option value="upload">上传</a-select-option>
                  <a-select-option value="target">目标</a-select-option>
                </a-select>
                <a-segmented
                  v-model:value="connectionDecisionFilter"
                  :options="[
                    { label: '全部', value: 'all' },
                    { label: '代理', value: 'proxy' },
                    { label: '直连', value: 'direct' },
                    { label: '拦截', value: 'reject' },
                  ]"
                />
              </div>
              <div class="connection-summary">
                <span>上传 {{ formatBytes(connectionUploadTotal) }}</span>
                <span>下载 {{ formatBytes(connectionDownloadTotal) }}</span>
                <span>{{ connectionsUpdatedAt ? formatTime(connectionsUpdatedAt) : '未刷新' }}</span>
                <a-tag :color="connectionsLoading ? 'gold' : 'green'">
                  {{ connectionsLoading ? '刷新中' : '实时' }}
                </a-tag>
              </div>
              <a-alert v-if="connectionsError" :message="connectionsError" type="error" show-icon />
              <div class="connection-list">
                <div
                  v-for="item in filteredConnections.slice(0, 200)"
                  :key="item.id || `${item.source}-${item.destination}-${item.total}`"
                  class="connection-row"
                >
                  <div class="connection-main">
                    <a-tag :color="connectionDecisionColor(item.decision)">
                      {{ connectionDecisionText(item.decision) }}
                    </a-tag>
                    <strong>{{ item.destination || '-' }}</strong>
                    <small>{{ item.network.toUpperCase() }} {{ item.source }}</small>
                  </div>
                  <div class="connection-meta">
                    <span>{{ formatBytes(item.total) }}</span>
                    <span>↓ {{ formatBytes(item.download) }}</span>
                    <span>↑ {{ formatBytes(item.upload) }}</span>
                  </div>
                  <div class="connection-rule">
                    <span>{{ item.chain_text || '-' }}</span>
                    <small>{{ item.rule || 'final' }}</small>
                  </div>
                </div>
                <div v-if="filteredConnections.length === 0" class="empty-line">无连接</div>
              </div>
            </div>
          </a-tab-pane>

          <a-tab-pane key="singbox" tab="SingBox">
            <div class="rule-pane">
              <div class="pane-title">
                <strong>SingBox</strong>
                <span>当前生成配置</span>
              </div>
              <pre class="singbox-config-view">{{ panel.sing_box_config }}</pre>
            </div>
          </a-tab-pane>
        </a-tabs>
      </section>
    </section>
  </main>
</template>
