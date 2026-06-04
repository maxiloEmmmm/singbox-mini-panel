const CDP_RESPONSE_TIMEOUT_MS = 5_000

// 适用场景：等待 Obscura 异步事件落到客户端。
export function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

// 适用场景：把 Obscura CDP 返回的 Runtime 结果转为普通 JS 值。
export function readRuntimeValue(result) {
  return result?.result?.value ?? result?.result?.description ?? null
}

// 适用场景：连接 Obscura 的 browser 级 CDP WebSocket。
function connectWebSocket(cdpUrl) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(cdpUrl)
    ws.addEventListener('open', () => resolve(ws), { once: true })
    ws.addEventListener('error', reject, { once: true })
  })
}

// 适用场景：给 CDP 请求附加超时，避免 Obscura 无响应时挂死。
function withTimeout(promise, method) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`CDP 请求超时：${method}`))
    }, CDP_RESPONSE_TIMEOUT_MS)

    promise.then(
      (value) => {
        clearTimeout(timer)
        resolve(value)
      },
      (error) => {
        clearTimeout(timer)
        reject(error)
      },
    )
  })
}

// 适用场景：创建一个最小 CDP 客户端，只使用 Obscura 已实现的协议路径。
export async function createObscuraClient(cdpUrl) {
  const ws = await connectWebSocket(cdpUrl)
  const events = []
  const pending = new Map()
  let nextId = 0
  let sessionId = null

  ws.addEventListener('message', (event) => {
    const data = JSON.parse(event.data)
    if (data.params?.sessionId) {
      sessionId = data.params.sessionId
    }

    if (data.id && pending.has(data.id)) {
      const request = pending.get(data.id)
      pending.delete(data.id)
      if (data.error) {
        request.reject(new Error(JSON.stringify(data.error)))
      } else {
        request.resolve(data.result)
      }
      return
    }

    events.push(data)
  })

  // 适用场景：发送 CDP 请求，目标页面命令自动带上 sessionId。
  function send(method, params = {}, options = {}) {
    const message = { id: ++nextId, method, params }
    if (options.session !== false && sessionId) {
      message.sessionId = sessionId
    }

    ws.send(JSON.stringify(message))
    const response = new Promise((resolve, reject) => {
      pending.set(message.id, { resolve, reject })
    })
    return withTimeout(response, method)
  }

  // 适用场景：创建 Obscura 页面目标，并等待它自动附加 session。
  async function createPage() {
    await send('Target.createTarget', { url: 'about:blank' }, { session: false })
    for (let i = 0; i < 50; i += 1) {
      if (sessionId) {
        return sessionId
      }
      await wait(50)
    }
    throw new Error('Obscura 未返回 Target.attachedToTarget sessionId')
  }

  // 适用场景：关闭 CDP 连接。
  function close() {
    ws.close()
  }

  return { close, createPage, events, send }
}
