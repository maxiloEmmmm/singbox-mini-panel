import { ref, watch, type Ref } from 'vue'
import { authHeaders, readError } from './api'

/** UUStatus 表示本地出站状态。 */
export interface UUStatus {
  /** auth 是共享 UU 账户的认证状态。 */
  auth: string
  /** connection 是当前设备的转发连接状态。 */
  connection: string
  /** qr 是扫码期间使用的临时二维码。 */
  qr?: string
  /** auth_error 是登录流程错误。 */
  auth_error?: string
  /** connection_error 是建立端口映射时的错误。 */
  connection_error?: string
}

/** UUDevice 是已登录账户下可选的对端。 */
export interface UUDevice {
  /** device_id 用于保存对端设备。 */
  device_id: string
  /** name 用于显示设备名称。 */
  name: string
}

/** UUScope 限定弹窗内的运行时请求。 */
interface UUScope {
  /** tag 是已经保存的出站标识。 */
  tag: string
  /** sessionToken 是面板登录 token。 */
  sessionToken: string
  /** profile 为空时选择接收端，否则为指定连接账号。 */
  profile: string
  /** abort 在关闭或切换弹窗时取消请求。 */
  abort: AbortController
  /** loading 避免重叠轮询。 */
  loading: boolean
  /** loadedDevices 表示已获取本次认证的设备列表。 */
  loadedDevices: boolean
}

/** uuAuthLabel 格式化账户状态，例如 authenticated -> 已认证。 */
export function uuAuthLabel(auth?: string) {
  switch (auth) {
    case 'authenticated': return '已认证'
    case 'starting': return '正在生成二维码'
    case 'waiting_scan': return '等待扫码'
    case 'scanned': return '已扫码，等待手机确认'
    case 'expired': return '认证已过期'
    case 'qr_expired': return '二维码已过期'
    case 'error': return '认证失败'
    default: return '未认证'
  }
}

/** uuConnectionLabel 格式化转发状态，例如 idle -> 等待流量。 */
export function uuConnectionLabel(connection?: string) {
  switch (connection) {
    case 'selecting_device': return '未选择设备'
    case 'connecting': return '正在连接'
    case 'connected': return '已连接'
    case 'error': return '连接失败'
    case 'idle': return '等待流量'
    default: return '出站未就绪'
  }
}

/** useUU 在编辑已应用的 UU 节点时管理扫码和设备选择。 */
export function useUU(tag: Readonly<Ref<string>>, token: Readonly<Ref<string>>, profile: Readonly<Ref<string>>, loadDevices = false) {
  const status = ref<UUStatus | null>(null)
  const devices = ref<UUDevice[]>([])
  const error = ref('')
  const starting = ref(false)
  let active: UUScope | null = null

  /** request 获取指定出站的私有状态，例如 GET status -> 当前认证状态。 */
  async function request<T>(scope: UUScope, path: string, method = 'GET'): Promise<T> {
    const query = new URLSearchParams({ tag: scope.tag })
    if (scope.profile) query.set('profile', scope.profile)
    const response = await fetch(`/api/uu/${path}?${query}`, {
      method,
      headers: authHeaders(scope.sessionToken),
      cache: 'no-store',
      signal: scope.abort.signal,
    })
    if (!response.ok) throw new Error(await readError(response))
    return response.json() as Promise<T>
  }

  /** refresh 轮询状态，认证成功后按需读取设备列表。 */
  async function refresh(scope: UUScope) {
    if (scope.loading || starting.value) return
    scope.loading = true
    try {
      const view = await request<UUStatus>(scope, 'status')
      if (active !== scope || starting.value) return
      status.value = view
      if (view.auth !== 'authenticated') {
        scope.loadedDevices = false
        devices.value = []
      } else if (loadDevices && !scope.loadedDevices) {
        const reply = await request<{ devices: UUDevice[] }>(scope, 'devices')
        if (active !== scope || starting.value) return
        devices.value = reply.devices
        scope.loadedDevices = true
      }
      error.value = ''
    } catch (reason) {
      if (active === scope) error.value = reason instanceof Error ? reason.message : String(reason)
    } finally {
      scope.loading = false
    }
  }

  /** startLogin 生成或恢复二维码，例如点「扫码认证」后进入等待扫码。 */
  async function startLogin() {
    const scope = active
    if (!scope || starting.value) return
    starting.value = true
    error.value = ''
    try {
      const view = await request<UUStatus>(scope, 'login', 'POST')
      if (active !== scope) return
      status.value = view
      scope.loadedDevices = false
      devices.value = []
    } catch (reason) {
      if (active === scope) error.value = reason instanceof Error ? reason.message : String(reason)
    } finally {
      if (active === scope) starting.value = false
    }
  }

  watch([tag, token, profile], ([outboundTag, sessionToken, account], _previous, onCleanup) => {
    active = null
    status.value = null
    devices.value = []
    error.value = ''
    starting.value = false
    if (!outboundTag || !sessionToken) return
    const scope: UUScope = { tag: outboundTag, sessionToken, profile: account, abort: new AbortController(), loading: false, loadedDevices: false }
    active = scope
    void refresh(scope)
    const timer = window.setInterval(() => void refresh(scope), 1500)
    onCleanup(() => {
      window.clearInterval(timer)
      scope.abort.abort()
    })
  }, { immediate: true })

  return { status, devices, error, starting, startLogin }
}
