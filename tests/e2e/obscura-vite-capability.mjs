#!/usr/bin/env node

import { createObscuraClient, readRuntimeValue, wait } from './obscura-cdp-client.mjs'

const DEFAULT_WEB_BASE_URL = 'http://127.0.0.1:5173/'
const DEFAULT_CDP_URL = 'ws://127.0.0.1:9222/devtools/browser'
const APP_READY_TIMEOUT_MS = 5_000

// 适用场景：读取 Web 地址，默认使用本机 Vite 地址。
function getWebBaseUrl() {
  return process.env.WEB_BASE_URL || DEFAULT_WEB_BASE_URL
}

// 适用场景：读取 Obscura CDP 地址。
function getCdpUrl() {
  return process.env.OBSCURA_CDP_URL || DEFAULT_CDP_URL
}

// 适用场景：生成带时间戳的无缓存访问地址。
function getFreshUrl(baseUrl) {
  const url = new URL(baseUrl)
  url.searchParams.set('t', String(Date.now()))
  return url.toString()
}

// 适用场景：收集 Obscura 看到的页面状态。
async function getPageDiagnostic(client) {
  const result = await client.send('Runtime.evaluate', {
    expression: `JSON.stringify({
      title: document.title,
      bodyText: document.body.innerText.trim(),
      appChildCount: document.querySelector('#app')?.children.length ?? null,
      appHtml: document.querySelector('#app')?.innerHTML ?? null,
      scripts: Array.from(document.scripts).map((script) => ({
        type: script.type,
        src: script.src,
      })),
    })`,
    returnByValue: true,
  })
  return JSON.parse(readRuntimeValue(result))
}

// 适用场景：等待 Vue 根节点挂载。
async function waitForVueMounted(client) {
  const deadline = Date.now() + APP_READY_TIMEOUT_MS
  while (Date.now() < deadline) {
    const diagnostic = await getPageDiagnostic(client)
    if ((diagnostic.appChildCount ?? 0) > 0) {
      return diagnostic
    }

    await wait(250)
  }

  return getPageDiagnostic(client)
}

// 适用场景：摘取脚本请求事件，辅助判断 Obscura 是否真正拿到模块内容。
function getScriptNetworkEvents(events) {
  return events
    .filter((event) => event.method === 'Network.loadingFinished')
    .map((event) => event.params)
    .filter((params) => params?.requestId?.includes('.'))
}

// 适用场景：验证 Obscura 是否具备运行 Vite/Vue ESM 页面能力。
async function main() {
  const client = await createObscuraClient(getCdpUrl())

  try {
    await client.createPage()
    await client.send('Page.enable')
    await client.send('Runtime.enable')
    await client.send('Page.navigate', { url: getFreshUrl(getWebBaseUrl()) })
    const diagnostic = await waitForVueMounted(client)

    if ((diagnostic.appChildCount ?? 0) === 0) {
      console.error('obscura vite capability failed')
      console.error(JSON.stringify({
        ...diagnostic,
        scriptNetworkEvents: getScriptNetworkEvents(client.events),
      }, null, 2))
      process.exitCode = 1
      return
    }

    console.log('obscura vite capability passed')
    console.log(JSON.stringify(diagnostic, null, 2))
  } finally {
    client.close()
  }
}

await main()
