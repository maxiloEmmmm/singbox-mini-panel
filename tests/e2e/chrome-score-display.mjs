#!/usr/bin/env node

import { chromium } from 'playwright-core'

const DEFAULT_WEB_BASE_URL = 'http://127.0.0.1:5173/'
const DEFAULT_CHROME_EXECUTABLE_PATH = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
const TARGET_SCORE = 76

// 适用场景：读取 Chrome 可执行文件路径，默认使用 macOS 系统 Chrome。
function getChromeExecutablePath() {
  return process.env.CHROME_EXECUTABLE_PATH || DEFAULT_CHROME_EXECUTABLE_PATH
}

// 适用场景：读取待测 Web 地址，默认指向当前 Vite dev server。
function getWebBaseUrl() {
  return process.env.WEB_BASE_URL || DEFAULT_WEB_BASE_URL
}

// 适用场景：生成无缓存页面地址，避免复用旧页面状态。
function getFreshUrl(baseUrl) {
  const url = new URL(baseUrl)
  url.searchParams.set('t', String(Date.now()))
  return url.toString()
}

// 适用场景：启动本机 Chrome 浏览器执行真实页面交互。
async function launchChrome() {
  return chromium.launch({
    executablePath: getChromeExecutablePath(),
    headless: true,
  })
}

// 适用场景：打开任务抽屉并修改稳定分。
async function updateScore(page) {
  const openButton = page.locator('[data-testid="open-mission"]').first()
  await openButton.waitFor({ state: 'visible' })
  await openButton.click()
  await page.locator('[data-testid="mission-score-input"]').fill(String(TARGET_SCORE))
  await page.locator('[data-testid="mission-score-input"]').press('Enter')
}

// 适用场景：验证抽屉中的稳定分按中文分数格式展示。
async function assertScoreText(page) {
  const pageText = await page.locator('body').innerText()
  if (!pageText.includes(`${TARGET_SCORE} 分`)) {
    throw new Error(`稳定分展示错误：${pageText}`)
  }
}

// 适用场景：用本机 Chrome 验证 Vue 页面真实交互。
async function main() {
  const browser = await launchChrome()

  try {
    const page = await browser.newPage()
    await page.goto(getFreshUrl(getWebBaseUrl()), { waitUntil: 'domcontentloaded' })
    await updateScore(page)
    await assertScoreText(page)
    console.log(`chrome score display passed: ${TARGET_SCORE} 分`)
  } finally {
    await browser.close()
  }
}

await main()
