#!/usr/bin/env node

import assert from 'node:assert/strict'
import { chromium } from 'playwright-core'

const url = process.env.WEB_BASE_URL || 'http://127.0.0.1:5173/'
const chrome = process.env.CHROME_EXECUTABLE_PATH || '/usr/bin/google-chrome'
const qr = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+pXioAAAAASUVORK5CYII='
const ready = {
  ok: true, setup_required: false, service_enabled: true, sing_box_status: 'running',
  active_outbound: 'direct', started_at: '2026-11-19T00:00:00+08:00', version: 'e2e',
}
const state = {
  health: ready, config_hash: 'uu-e2e', static: [], subscriptions: [], imports: [],
  uu: { host_enabled: false, host_account: '', accounts: [] },
  dynamic_groups: [], geofiles: [], hosts_override: true, force_proxy: '', force_direct: '',
  overrides: [], dynamic_outbound: [], sing_box_config: '{}', warnings: [],
  inbound: {
    inbound_mode: 'mixed', mixed_listen: '127.0.0.1', mixed_port: 1080,
    tun_route_exclude_address: [], tun_route_exclude_address_set: [],
  },
}
const profiles = new Map([['default', 'authenticated'], ['', 'unsigned']])
let nextDevices = []
let saves = []
let participants = 0

/** 提供测试面板的配置和 UU 状态，例如扫码后设备列表包含 185。 */
async function respond(route) {
  const request = route.request()
  const endpoint = new URL(request.url())
  let body
  switch (endpoint.pathname) {
    case '/api/save': {
      const payload = request.postDataJSON()
      const saved = payload.static
      state.uu = payload.uu
      saves.push(payload)
      state.static = saved.map((node) => ({
        ...node, tag: `static-${node.key}`, source: 'static', uu_auth: profiles.get(node.uu_account),
        uu_connection: node.uu_device_id ? 'idle' : 'selecting_device',
      }))
      body = state
      break
    }
    case '/api/uu/login': {
      const profile = endpoint.searchParams.get('profile') || ''
      assert.equal(request.method(), 'POST')
      assert.equal(endpoint.searchParams.get('tag'), 'uu-host')
      profiles.set(profile, 'waiting_scan')
      body = { auth: 'waiting_scan', connection: 'idle', qr }
      break
    }
    case '/api/uu/status': {
      assert.equal(endpoint.searchParams.get('tag'), 'uu-host')
      const profile = endpoint.searchParams.get('profile') || ''
      const hostProfile = !profile && state.uu.host_account ? state.uu.host_account : profile
      const auth = profiles.get(hostProfile) || 'unsigned'
      const connection = profile ? 'idle' : state.uu.host_enabled ? 'online' : 'disabled'
      body = { auth, connection, qr: auth === 'waiting_scan' ? qr : undefined }
      break
    }
    case '/api/uu/devices': {
      const profile = endpoint.searchParams.get('profile')
      assert.equal(profiles.get(profile), 'authenticated')
      participants++
      nextDevices.push(profile)
      body = { devices: profile === 'default'
        ? [{ device_id: 'default-device', name: '默认设备' }]
        : [{ device_id: 'device-185', name: '185 家里' }]
      }
      break
    }
    case '/api/health': body = ready; break
    case '/api/state': body = state; break
    case '/api/apply': body = { applying: false }; break
    case '/api/connections': body = { updated_at: '', connections: [] }; break
    case '/api/traffic/daily': body = { updated_at: '', days: {} }; break
  }
  await route.fulfill({ status: body ? 200 : 404, json: body || { error: 'unexpected endpoint' } })
}

/** 按字段名找到弹窗中的输入框，例如远端入站端口 -> 端口输入。 */
function input(modal, label) {
  return modal.locator('label.field-row').filter({ hasText: new RegExp(`^\\s*${label}\\s*$`) }).locator('input')
}

/** 用现有 Chrome E2E 路径验证全局认证、复用和账号决定设备列表。 */
async function verifyUU(page) {
  await page.addInitScript(() => localStorage.setItem('sboxctl_token', 'e2e-token'))
  await page.route('**/api/**', respond)
  await page.goto(url, { waitUntil: 'domcontentloaded' })
  await page.getByRole('tab', { name: 'UU', exact: true }).click()
  const center = page.getByRole('tabpanel', { name: 'UU' })
  await center.getByPlaceholder('账号名称').fill('Office')
  await center.getByRole('button', { name: /添\s*加/ }).click()
  await page.getByRole('button', { name: '保存并应用' }).click()
  await page.getByText('无改动', { exact: true }).waitFor()
  assert.deepEqual(saves.at(-1).uu.accounts, [{ key: 'office', name: 'Office' }])
  await center.getByRole('button', { name: '扫码认证' }).last().click()
  await center.getByRole('img', { name: 'UU 连接账号登录二维码' }).waitFor()
  profiles.set('office', 'authenticated')
  await center.getByText('已认证', { exact: true }).waitFor()

  await page.getByRole('button', { name: '新增静态' }).click()
  const modal = page.getByRole('dialog', { name: '静态节点' })
  await modal.locator('.ant-select').first().click()
  await page.locator('.ant-select-item-option').filter({ hasText: /^UU$/ }).click()
  assert.equal(await input(modal, 'server').count(), 0)
  assert.equal(await modal.getByText('对端设备', { exact: true }).count(), 0)
  await input(modal, 'key').fill('uu-home')
  await input(modal, '名称').fill('UU 家里')
  await input(modal, '远端入站端口').fill('1080')
  const account = modal.locator('label.field-row').filter({ hasText: '连接账号' }).locator('.ant-select')
  await account.click()
  await page.locator('.ant-select-item-option:visible').filter({ hasText: '默认连接账号' }).click()
  const devices = modal.locator('label.field-row').filter({ hasText: '对端设备' }).locator('.ant-select')
  await page.waitForFunction(() => document.querySelector('[role="dialog"] [aria-disabled="true"]') === null)
  await devices.click()
  await page.locator('.ant-select-item-option:visible').filter({ hasText: '默认设备' }).click()
  await account.click()
  await page.locator('.ant-select-item-option:visible').filter({ hasText: /^Office$/ }).click()
  assert.equal(await devices.getByText('默认设备').count(), 0)
  await page.waitForFunction(() => document.querySelector('[role="dialog"] [aria-disabled="true"]') === null)
  await devices.click()
  await page.locator('.ant-select-item-option:visible').filter({ hasText: '185 家里' }).click()
  await modal.getByRole('button', { name: '保存到临时配置' }).click()

  await center.getByRole('switch').click()
  const host = center.locator('label.field-row').filter({ hasText: '接收端认证' }).locator('.ant-select')
  await host.click()
  await page.locator('.ant-select-item-option:visible').filter({ hasText: /^Office$/ }).click()
  await page.getByRole('button', { name: '保存并应用' }).click()
  await page.getByText('无改动', { exact: true }).waitFor()
  const saved = saves.at(-1)
  assert.deepEqual([saved.static[0].protocol, saved.static[0].port, saved.static[0].uu_account, saved.static[0].uu_device_id],
    ['uu', 1080, 'office', 'device-185'])
  assert.equal(saved.uu.host_enabled, true)
  assert.equal(saved.uu.host_account, 'office')
  assert.deepEqual(nextDevices, ['default', 'office'])
  assert.ok(participants > 0)
  await center.getByText(/已认证.*已上线/).waitFor()
}

/** 运行浏览器测试并释放 Chromium。 */
async function main() {
  const browser = await chromium.launch({ executablePath: chrome, headless: true })
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } })
    await verifyUU(page)
    console.log('UU outbound form passed')
  } finally {
    await browser.close()
  }
}

await main()
