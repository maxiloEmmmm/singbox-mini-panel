#!/usr/bin/env node

import { chromium } from 'playwright-core'

const WEB_BASE_URL = process.env.WEB_BASE_URL || 'http://127.0.0.1:5173/'
const CHROME_EXECUTABLE_PATH = process.env.CHROME_EXECUTABLE_PATH || '/usr/bin/google-chrome'

const health = {
  ok: true,
  setup_required: false,
  service_enabled: true,
  sing_box_status: 'running',
  started_at: '2026-11-14T08:00:00+08:00',
  active_outbound: 'direct',
  last_update_success: '2026-11-14T09:00:00+08:00',
  version: 'e2e',
}

const panelState = {
  health,
  config_hash: 'cf-e2e',
  static: [{
    key: 'cf-live',
    tag: 'static-cf-live',
    name: 'CF 在线链路',
    protocol: 'cf',
    server: '',
    port: 0,
    source: 'static',
    kv_key: 'com/com.live',
    cf_colo: 'HKG',
    cf_connected: true,
  }],
  subscriptions: [],
  imports: [],
  dynamic_groups: [],
  geofiles: [],
  hosts_override: true,
  inbound: {
    inbound_mode: 'tun',
    tun_route_exclude_address: [],
    tun_route_exclude_address_set: [],
    mixed_listen: '0.0.0.0',
    mixed_port: 1080,
  },
  force_proxy: '',
  force_direct: '',
  overrides: [],
  dynamic_outbound: [],
  sing_box_config: '{}',
  warnings: [],
}

let saveRequest = null

// 适用场景：为 CF 表单提供稳定的面板 API 快照并捕获保存请求。
// 示例：POST /api/save -> 记录 JSON 后返回成功状态。
async function fulfillAPI(route) {
  const request = route.request()
  const pathname = new URL(request.url()).pathname
  if (pathname === '/api/save') {
    saveRequest = request.postDataJSON()
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(panelState) })
    return
  }
  const responses = {
    '/api/health': health,
    '/api/state': panelState,
    '/api/connections': { updated_at: '', total: 0, upload_total: 0, download_total: 0, connections: [] },
    '/api/traffic/daily': { updated_at: '', days: {} },
  }
  const body = responses[pathname]
  await route.fulfill({
    status: body ? 200 : 404,
    contentType: 'application/json',
    body: JSON.stringify(body || { error: `unexpected api: ${pathname}` }),
  })
}

// 适用场景：定位静态节点弹窗中的包装式表单输入框。
// 示例：fieldInput(modal, 'kv-key') -> 对应 Ant Input。
function fieldInput(modal, fieldName) {
  return modal.locator('label.field-row').filter({ hasText: new RegExp(`^\\s*${fieldName}\\s*$`) }).locator('input')
}

// 适用场景：验证 CF 类型只要求 KV key，并贯通临时状态与保存请求。
// 示例：cfp/demo -> static-cf-main outbound 草稿。
async function verifyCFForm(page) {
  await page.addInitScript(() => localStorage.setItem('sboxctl_token', 'e2e-token'))
  await page.route('**/api/**', fulfillAPI)
  await page.goto(WEB_BASE_URL, { waitUntil: 'domcontentloaded' })
  const liveNodeText = await page.locator('.node-list-row').filter({ hasText: 'CF 在线链路' }).innerText()
  if (!liveNodeText.includes('com/com.live · HKG')) {
    throw new Error(`CF POP 未回显：${liveNodeText}`)
  }
  await page.getByRole('button', { name: '新增静态' }).click()
  const modal = page.getByRole('dialog', { name: '静态节点' })
  await modal.waitFor({ state: 'visible' })
  await modal.locator('.ant-select').first().click()
  await page.locator('.ant-select-item-option').filter({ hasText: /^CF$/ }).click()

  if (await fieldInput(modal, 'server').count() !== 0 || await fieldInput(modal, 'port').count() !== 0) {
    throw new Error('CF 表单仍展示 server 或 port')
  }
  await fieldInput(modal, 'key').fill('cf-main')
  await fieldInput(modal, '名称').fill('CF 主链路')
  await fieldInput(modal, 'kv-key').fill('cfp/demo')
  await modal.getByRole('button', { name: '保存到临时配置' }).click()

  const node = page.locator('.node-list-row').filter({ hasText: 'CF 主链路' })
  await node.waitFor({ state: 'visible' })
  const nodeText = await node.innerText()
  if (!nodeText.includes('CF') || !nodeText.includes('cfp/demo')) {
    throw new Error(`CF 节点展示不完整：${nodeText}`)
  }

  await page.getByRole('button', { name: '保存并应用' }).click()
  await page.waitForFunction(() => document.body.innerText.includes('无改动'))
  const saved = saveRequest?.static?.find((node) => node.key === 'cf-main')
  if (!saved || saved.protocol !== 'cf' || saved.kv_key !== 'cfp/demo' || saved.server !== '' || saved.port !== 0) {
    throw new Error(`CF 保存请求错误：${JSON.stringify(saved)}`)
  }
}

// 适用场景：在真实 Chromium 中执行 CF outbound 表单闭环验证。
// 示例：main() -> 渲染、编辑、保存均通过。
async function main() {
  const browser = await chromium.launch({ executablePath: CHROME_EXECUTABLE_PATH, headless: true })
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } })
    await verifyCFForm(page)
    await page.screenshot({ path: '/tmp/sboxctl-cf-outbound-form.png', fullPage: true })
    console.log('CF outbound form passed')
  } finally {
    await browser.close()
  }
}

await main()
