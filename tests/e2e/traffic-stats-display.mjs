#!/usr/bin/env node

import { chromium } from 'playwright-core'

const DEFAULT_WEB_BASE_URL = 'http://127.0.0.1:5173/'
const DEFAULT_CHROME_EXECUTABLE_PATH = '/usr/bin/google-chrome'

const health = {
  ok: true,
  setup_required: false,
  service_enabled: true,
  sing_box_status: 'running',
  started_at: '2026-10-09T08:00:00+08:00',
  active_outbound: 'static-demo',
  last_update_success: '2026-10-09T09:00:00+08:00',
  version: 'e2e',
}

const panelState = {
  health,
  config_hash: 'e2e',
  static: [],
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

const trafficDaily = {
  updated_at: '2026-10-09T12:30:00+08:00',
  days: {
    '2026-10-09': {
      'video.example.com': { up_count: 1048576, down_count: 20971520 },
      '203.0.113.8': { up_count: 2048, down_count: 4096 },
    },
  },
}

// 适用场景：读取 Chrome 可执行文件路径，默认使用当前验证机 Chrome。
// 示例：未设置环境变量 -> /usr/bin/google-chrome。
function getChromeExecutablePath() {
  return process.env.CHROME_EXECUTABLE_PATH || DEFAULT_CHROME_EXECUTABLE_PATH
}

// 适用场景：读取待测 Web 地址，默认指向当前 Vite 服务。
// 示例：未设置环境变量 -> http://127.0.0.1:5173/。
function getWebBaseUrl() {
  return process.env.WEB_BASE_URL || DEFAULT_WEB_BASE_URL
}

// 适用场景：按 API 路径返回稳定服务端快照。
// 示例：/api/traffic/daily -> trafficDaily。
async function fulfillAPI(route) {
  const pathname = new URL(route.request().url()).pathname
  let body
  if (pathname === '/api/health') {
    body = health
  } else if (pathname === '/api/state') {
    body = panelState
  } else if (pathname === '/api/connections') {
    body = { updated_at: trafficDaily.updated_at, total: 0, upload_total: 0, download_total: 0, connections: [] }
  } else if (pathname === '/api/traffic/daily') {
    body = trafficDaily
  } else {
    body = { error: `unexpected api: ${pathname}` }
  }
  await route.fulfill({
    status: pathname in { '/api/health': 1, '/api/state': 1, '/api/connections': 1, '/api/traffic/daily': 1 } ? 200 : 404,
    contentType: 'application/json',
    body: JSON.stringify(body),
  })
}

// 适用场景：打开已登录面板并进入每日流量页签。
// 示例：openTrafficPane(page) -> 流量页签可见。
async function openTrafficPane(page) {
  await page.addInitScript(() => localStorage.setItem('sboxctl_token', 'e2e-token'))
  await page.route('**/api/**', fulfillAPI)
  await page.goto(getWebBaseUrl(), { waitUntil: 'domcontentloaded' })
  await page.getByRole('tab', { name: '流量', exact: true }).click()
  await page.locator('[data-testid="traffic-daily-pane"]').waitFor({ state: 'visible' })
}

// 适用场景：验证服务端域名和 IP 统计都被正确展示。
// 示例：trafficDaily -> 两条目标行。
async function assertTrafficRows(page) {
  const pane = page.locator('[data-testid="traffic-daily-pane"]')
  const text = await pane.innerText()
  for (const expected of ['2026-10-09', 'video.example.com', '21.00 MB', '203.0.113.8', '6.0 KB', '仅代理']) {
    if (!text.includes(expected)) {
      throw new Error(`每日代理流量缺少展示内容：${expected}\n${text}`)
    }
  }
  const rows = pane.locator('[data-testid="traffic-target-row"]')
  if (await rows.count() !== 2) {
    throw new Error(`每日代理流量行数错误：${await rows.count()}`)
  }
}

// 适用场景：验证小屏幕没有产生横向溢出。
// 示例：390x844 -> 文档宽度不超过 390。
async function assertMobileLayout(page) {
  await page.setViewportSize({ width: 390, height: 844 })
  const layout = await page.locator('[data-testid="traffic-daily-pane"]').evaluate((element) => ({
    paneRight: element.getBoundingClientRect().right,
    viewportWidth: window.innerWidth,
    documentWidth: document.documentElement.scrollWidth,
    offenders: Array.from(document.querySelectorAll('body *'))
      .map((item) => ({
        className: typeof item.className === 'string' ? item.className : item.tagName,
        right: item.getBoundingClientRect().right,
        width: item.getBoundingClientRect().width,
      }))
      .filter((item) => item.right > window.innerWidth + 1)
      .sort((left, right) => right.width - left.width)
      .slice(0, 8),
  }))
  if (layout.paneRight > layout.viewportWidth + 1 || layout.documentWidth > layout.viewportWidth + 1) {
    throw new Error(`手机视口出现横向溢出：${JSON.stringify(layout)}`)
  }
}

// 适用场景：在真实浏览器中完成每日代理流量渲染闭环。
// 示例：main() -> 桌面和手机视口验证通过。
async function main() {
  const browser = await chromium.launch({
    executablePath: getChromeExecutablePath(),
    headless: true,
  })
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } })
    await openTrafficPane(page)
    await assertTrafficRows(page)
    await page.screenshot({ path: '/tmp/sboxctl-traffic-stats-desktop.png', fullPage: true })
    await assertMobileLayout(page)
    await page.screenshot({ path: '/tmp/sboxctl-traffic-stats-mobile.png', fullPage: true })
    console.log('traffic stats display passed')
  } finally {
    await browser.close()
  }
}

await main()
