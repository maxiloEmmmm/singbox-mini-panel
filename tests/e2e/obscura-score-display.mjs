#!/usr/bin/env node

import { createObscuraClient, readRuntimeValue, wait } from './obscura-cdp-client.mjs'

const DEFAULT_WEB_BASE_URL = 'http://127.0.0.1:5173/'
const DEFAULT_CDP_URL = 'ws://127.0.0.1:9222/devtools/browser'
const TARGET_SCORE = 76
const APP_READY_TIMEOUT_MS = 5_000

// 适用场景：读取 Web 地址，允许外部环境覆盖。
function getWebBaseUrl() {
  return process.env.WEB_BASE_URL || DEFAULT_WEB_BASE_URL
}

// 适用场景：读取 Obscura CDP 地址，允许外部环境覆盖。
function getCdpUrl() {
  return process.env.OBSCURA_CDP_URL || DEFAULT_CDP_URL
}

// 适用场景：生成无缓存页面地址。
function getFreshUrl(baseUrl) {
  const url = new URL(baseUrl)
  url.searchParams.set('t', String(Date.now()))
  return url.toString()
}

// 适用场景：等待 Vue 应用在 Obscura 页面中挂载。
async function waitForAppMounted(client) {
  const deadline = Date.now() + APP_READY_TIMEOUT_MS
  while (Date.now() < deadline) {
    const result = await client.send('Runtime.evaluate', {
      expression: `Boolean(document.querySelector('#app')?.children.length)`,
      returnByValue: true,
    })
    const isMounted = Boolean(readRuntimeValue(result))

    if (isMounted) {
      return
    }

    await wait(250)
  }

  const result = await client.send('Runtime.evaluate', {
    expression: `JSON.stringify({
      title: document.title,
      bodyText: document.body.innerText,
      appHtml: document.querySelector('#app')?.innerHTML ?? null,
      scripts: Array.from(document.scripts).map((script) => ({
        type: script.type,
        src: script.src,
      })),
    })`,
    returnByValue: true,
  })
  const diagnostic = JSON.parse(readRuntimeValue(result))

  throw new Error(`Vue 应用未挂载：${JSON.stringify(diagnostic)}`)
}

// 适用场景：通过页面脚本执行稳定分修改流程。
async function updateScore(client) {
  const result = await client.send('Runtime.evaluate', {
    expression: `(() => {
      document.querySelector('[data-testid="open-mission"]')?.click()
      const input = document.querySelector('[data-testid="mission-score-input"] input')
      if (!input) return null
      input.value = '${TARGET_SCORE}'
      input.dispatchEvent(new Event('input', { bubbles: true }))
      input.dispatchEvent(new Event('change', { bubbles: true }))
      input.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true, key: 'Enter', code: 'Enter' }))
      return document.querySelector('[data-testid="drawer-score"]')?.innerText ?? null
    })()`,
    returnByValue: true,
  })

  return readRuntimeValue(result)
}

// 适用场景：用 Obscura CDP 验证稳定分修改后的展示格式。
async function main() {
  const client = await createObscuraClient(getCdpUrl())

  try {
    await client.createPage()
    await client.send('Page.enable')
    await client.send('Runtime.enable')
    await client.send('Page.navigate', { url: getFreshUrl(getWebBaseUrl()) })
    await waitForAppMounted(client)

    const scoreText = await updateScore(client)
    if (!scoreText.includes(`${TARGET_SCORE} 分`)) {
      throw new Error(`稳定分展示错误：${scoreText}`)
    }

    console.log(`obscura score display passed: ${TARGET_SCORE} 分`)
  } finally {
    client.close()
  }
}

await main()
