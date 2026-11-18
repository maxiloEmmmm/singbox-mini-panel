import assert from 'node:assert/strict'
import { access, readFile, unlink, writeFile } from 'node:fs/promises'
import { setTimeout } from 'node:timers/promises'
import { chromium } from 'playwright-core'

const baseURL = 'http://127.0.0.1:9000'
const fixture = process.env.APPLY_FIXTURE
const initialPID = Number(process.env.APPLY_INITIAL_PID)
assert.ok(fixture && initialPID > 1)

// Read the runtime TUN config. Example: liveExclusions() -> ["192.0.2.0/24"].
async function liveExclusions() {
  const doc = JSON.parse(await readFile(`${fixture}/sing-box.json`, 'utf8'))
  return doc.inbounds.find((entry) => entry.type === 'tun').route_exclude_address
}

// Submit the current draft and wait only for its save receipt. Example: saveDraft(page) -> HTTP 202.
async function saveDraft(page) {
  const button = page.getByRole('button', { name: '保存并应用' })
  await button.waitFor({ state: 'visible' })
  const [response] = await Promise.all([
    page.waitForResponse((result) => result.url().endsWith('/api/save'), { timeout: 3000 }),
    button.evaluate((element) => element.click()),
  ])
  assert.equal(response.status(), 202, await response.text())
  await page.getByRole('button', { name: '无改动' }).waitFor()
  return response.json()
}

// Edit the TUN field and save. Example: bare IP -> a response containing a CIDR.
async function saveExclusions(page, text) {
  const field = page.locator('label.field-row').filter({ hasText: 'TUN 排除网段' }).locator('textarea')
  await field.fill(text)
  return saveDraft(page)
}

// Drive failure and recovery against the real API. Example: failed -> later applied.
async function verifyApply(page) {
  const response = await page.request.post(`${baseURL}/api/login`, {
    data: { username: 'fixture', password: 'fixture-secret' },
  })
  assert.ok(response.ok())
  const { token } = await response.json()
  await page.addInitScript((value) => localStorage.setItem('sboxctl_token', value), token)
  await page.goto(baseURL, { waitUntil: 'domcontentloaded' })
  await page.getByRole('tab', { name: '入口', selected: true }).waitFor()

  await writeFile(`${fixture}/check-mode`, 'fail')
  const failed = await saveExclusions(page, '192.0.2.0/24\n203.0.113.80')
  assert.deepEqual(failed.inbound.tun_route_exclude_address, ['192.0.2.0/24', '203.0.113.80/32'])
  await page.getByText('配置已保存，应用失败', { exact: true }).waitFor()
  await page.getByText(/fixture rejected candidate/).waitFor()
  process.kill(initialPID, 0)
  assert.deepEqual(await liveExclusions(), ['192.0.2.0/24'])

  await unlink(`${fixture}/check-started`)
  await writeFile(`${fixture}/check-mode`, 'hold')
  await saveExclusions(page, '192.0.2.0/24\n203.0.113.81')
  await page.getByText('正在应用配置', { exact: true }).waitFor()
  for (let attempt = 0; attempt < 30; attempt++) {
    if (await access(`${fixture}/check-started`).then(() => true, () => false)) break
    await setTimeout(50)
  }
  await access(`${fixture}/check-started`)
  const last = await saveExclusions(page, '192.0.2.0/24\n2001:db8::5')
  assert.deepEqual(last.inbound.tun_route_exclude_address, ['192.0.2.0/24', '2001:db8::5/128'])
  assert.deepEqual(await liveExclusions(), ['192.0.2.0/24'])
  await writeFile(`${fixture}/check-mode`, 'ok')
  await page.getByText('配置已生效', { exact: true }).waitFor()
  assert.deepEqual(await liveExclusions(), ['192.0.2.0/24', '2001:db8::5/128'])

  // A valid candidate can still fail to bind at runtime. The previous service must return.
  await page.getByText('同时', { exact: true }).evaluate((element) => element.click())
  await page.locator('label.field-row').filter({ hasText: 'mixed port' }).locator('input').fill('18081')
  const busy = await saveDraft(page)
  assert.equal(busy.inbound.inbound_mode, 'both')
  await page.getByText('配置已保存，应用失败', { exact: true }).waitFor({ timeout: 12000 })
  const running = JSON.parse(await readFile(`${fixture}/sing-box.json`, 'utf8'))
  assert.deepEqual(running.inbounds.map((entry) => entry.type), ['tun'])
  assert.ok((await page.request.get('http://127.0.0.1:9090/version')).ok())
}

const browser = await chromium.launch({
  executablePath: process.env.CHROME_EXECUTABLE_PATH || '/usr/bin/google-chrome',
  headless: true,
})
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } })
  page.setDefaultTimeout(6000)
  await verifyApply(page)
  console.log('web config apply passed')
} finally {
  await browser.close()
}
