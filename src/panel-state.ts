import type {
  BackendNode,
  DynamicGroup,
  DynamicOutboundRule,
  ImportedNodeGroup,
  ImportForm,
  InboundSettings,
  OverrideRule,
  PanelState,
  StaticForm,
  SubscriptionForm,
  SubscriptionGroup,
} from './types'

/** arrayOrEmpty 把后端 null slice 规整成可遍历列表。 */
export function arrayOrEmpty<T>(items: T[] | null | undefined) {
  return Array.isArray(items) ? items : []
}

/** cloneStaticNodes 复制静态节点，避免编辑污染保存基线。 */
export function cloneStaticNodes(nodes: BackendNode[] | null | undefined) {
  return arrayOrEmpty(nodes).map((node) => ({ ...node }))
}

/** cloneSubscriptions 复制订阅配置和缓存节点。 */
export function cloneSubscriptions(items: SubscriptionGroup[] | null | undefined) {
  return arrayOrEmpty(items).map((item) => ({
    ...item,
    nodes: arrayOrEmpty(item.nodes).map((node) => ({ ...node })),
  }))
}

/** cloneImportedGroups 复制导入配置和缓存节点。 */
export function cloneImportedGroups(items: ImportedNodeGroup[] | null | undefined) {
  return arrayOrEmpty(items).map((item) => ({
    ...item,
    nodes: arrayOrEmpty(item.nodes).map((node) => ({ ...node })),
  }))
}

/** serializeStaticNodes 稳定比较静态节点配置是否变更。 */
export function serializeStaticNodes(nodes: BackendNode[]) {
  return JSON.stringify(nodes.map((node) => ({
    protocol: normalizeStaticProtocol(node.protocol),
    key: node.key,
    name: node.name,
    server: node.server,
    port: node.port,
    username: node.username || '',
    password: node.password || '',
    detour: node.detour || '',
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
    idle_session_check_interval: node.idle_session_check_interval || '',
    idle_session_timeout: node.idle_session_timeout || '',
    min_idle_session: node.min_idle_session || 0,
  })))
}

/** serializeSubscriptions 稳定比较订阅配置是否变更。 */
export function serializeSubscriptions(items: SubscriptionGroup[]) {
  return JSON.stringify(items.map((item) => ({
    key: item.key,
    name: item.name,
    url: item.url,
    enabled: item.enabled,
    user_agent: item.user_agent,
  })))
}

/** serializeImportedGroups 稳定比较导入配置是否变更。 */
export function serializeImportedGroups(items: ImportedNodeGroup[]) {
  return JSON.stringify(items.map((item) => ({
    key: item.key,
    name: item.name,
    source: item.source,
  })))
}

/** sortedRuleSets 稳定比较 geofile 规则集选择。 */
export function sortedRuleSets(items: string[]) {
  return [...items].sort().join(',')
}

/** normalizeStaticProtocol 规范化静态节点协议，兼容旧配置空协议。 */
export function normalizeStaticProtocol(protocol: string) {
  if (protocol === 'vmess') {
    return 'vmess'
  }
  if (protocol === 'ss') {
    return 'ss'
  }
  if (protocol === 'trojan') {
    return 'trojan'
  }
  if (protocol === 'anytls') {
    return 'anytls'
  }
  if (protocol === 'socks' || protocol === 'socks5') {
    return 'socks'
  }
  if (protocol === 'http') {
    return 'http'
  }
  return 'hy2'
}

/** cloneDynamicGroups 复制动态组，避免编辑时污染保存基线。 */
export function cloneDynamicGroups(groups: DynamicGroup[] | null | undefined) {
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

/** serializeDynamicGroups 稳定比较动态组配置是否变更。 */
export function serializeDynamicGroups(groups: DynamicGroup[]) {
  return JSON.stringify(
    groups.map((group) => ({
      key: group.key,
      mode: normalizeGroupMode(group.mode),
      primary: normalizeGroupMode(group.mode) === 'primary_backup' ? group.primary : '',
      members: [...arrayOrEmpty(group.members)],
    })),
  )
}

/** normalizeGroupMode 把动态组模式规整成有效值。 */
export function normalizeGroupMode(mode: string) {
  return mode === 'primary_backup' ? 'primary_backup' : 'dynamic'
}

/** cloneDynamicOutbound 复制动态出口规则，避免编辑污染保存基线。 */
export function cloneDynamicOutbound(rules: DynamicOutboundRule[] | null | undefined) {
  return arrayOrEmpty(rules).map((rule) => ({ ...rule }))
}

/** serializeDynamicOutbound 稳定比较动态出口规则是否变更。 */
export function serializeDynamicOutbound(rules: DynamicOutboundRule[]) {
  return JSON.stringify(rules.map((rule) => ({
    match: rule.match,
    outbound: rule.outbound,
  })))
}

/** cloneOverrides 复制静态跳转规则，避免编辑污染保存基线。 */
export function cloneOverrides(rules: OverrideRule[] | null | undefined) {
  return arrayOrEmpty(rules).map((rule) => ({
    ...rule,
    outbound: rule.outbound || 'direct',
    enabled: rule.enabled !== false,
  }))
}

/** serializeOverrides 稳定比较静态跳转规则是否变更。 */
export function serializeOverrides(rules: OverrideRule[]) {
  return JSON.stringify(rules.map((rule) => ({
    key: rule.key,
    match: rule.match,
    address: rule.address,
    port: Number(rule.port) || 0,
    outbound: rule.outbound || 'direct',
    enabled: rule.enabled !== false,
  })))
}

/** emptyStaticForm 生成空静态节点表单。 */
export function emptyStaticForm(): StaticForm {
  return {
    protocol: 'hy2',
    key: '',
    name: '',
    server: '',
    port: 443,
    username: '',
    password: '',
    detour: '',
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
    idle_session_check_interval: '',
    idle_session_timeout: '',
    min_idle_session: 0,
  }
}

/** emptySubscriptionForm 生成空订阅表单。 */
export function emptySubscriptionForm(): SubscriptionForm {
  return {
    key: '',
    name: '',
    url: '',
    enabled: true,
    user_agent: 'sing-box/1.13.12',
  }
}

/** emptyImportForm 生成空导入表单。 */
export function emptyImportForm(): ImportForm {
  return {
    key: '',
    name: '',
    source: 'clash',
    content: '',
  }
}

/** staticFormFromNode 用节点生成静态编辑表单。 */
export function staticFormFromNode(node: BackendNode): StaticForm {
  return {
    protocol: normalizeStaticProtocol(node.protocol),
    key: node.key,
    name: node.name,
    server: node.server,
    port: node.port,
    username: node.username || '',
    password: node.password || '',
    detour: node.detour || '',
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
    idle_session_check_interval: node.idle_session_check_interval || '',
    idle_session_timeout: node.idle_session_timeout || '',
    min_idle_session: node.min_idle_session || 0,
  }
}

/** subscriptionFormFromItem 用订阅生成订阅编辑表单。 */
export function subscriptionFormFromItem(item: SubscriptionGroup): SubscriptionForm {
  return {
    key: item.key,
    name: item.name,
    url: item.url,
    enabled: item.enabled,
    user_agent: item.user_agent,
  }
}

/** normalizedPanelState 归一化主状态，避免模板读取 null 列表。 */
export function normalizedPanelState(nextPanel: PanelState) {
  return {
    ...nextPanel,
    static: cloneStaticNodes(nextPanel.static),
    subscriptions: cloneSubscriptions(nextPanel.subscriptions),
    imports: cloneImportedGroups(nextPanel.imports),
    dynamic_groups: cloneDynamicGroups(nextPanel.dynamic_groups),
    geofiles: arrayOrEmpty(nextPanel.geofiles).map((file) => ({ ...file })),
    inbound: normalizeInboundSettings(nextPanel.inbound),
    overrides: cloneOverrides(nextPanel.overrides),
    dynamic_outbound: cloneDynamicOutbound(nextPanel.dynamic_outbound),
    warnings: [...arrayOrEmpty(nextPanel.warnings)],
  }
}

/** normalizeInboundSettings 归一化入口配置，兼容旧后端状态。 */
export function normalizeInboundSettings(value: InboundSettings | null | undefined) {
  return {
    inbound_mode: normalizedInboundMode(value?.inbound_mode || ''),
    tun_route_exclude_address: arrayOrEmpty(value?.tun_route_exclude_address)
      .map((item) => `${item}`.trim())
      .filter(Boolean),
    mixed_listen: value?.mixed_listen || '0.0.0.0',
    mixed_port: value?.mixed_port || 1080,
  }
}

/** normalizedInboundMode 归一化入口模式，兼容旧配置空值。 */
export function normalizedInboundMode(value: string) {
  return value === 'mixed' ? 'mixed' : 'tun'
}

/** sanitizeLocalKey 按前端规则清洗 key。 */
export function sanitizeLocalKey(value: string) {
  return value.trim().toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '')
}
