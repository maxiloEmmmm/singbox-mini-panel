#!/usr/bin/env node

const DEFAULT_WEB_BASE_URL = 'http://127.0.0.1:5173/'
const EXPECTED_TITLE = 'LLM 闭环 Web 测试靶场'

// 适用场景：读取 E2E 目标地址，允许外部环境覆盖默认 dev server。
function getWebBaseUrl() {
  return process.env.WEB_BASE_URL || DEFAULT_WEB_BASE_URL
}

// 适用场景：把输入文本按脚本输出需求压成单行摘要。
function toSingleLine(text) {
  return text.replace(/\s+/g, ' ').trim()
}

// 适用场景：请求 Web 首页并返回响应正文。
async function fetchHomePage(url) {
  const response = await fetch(url)
  if (!response.ok) {
    throw new Error(`Web 服务响应异常：${response.status}`)
  }

  return response.text()
}

// 适用场景：确认 Vite 首页 HTML 来自当前项目。
function assertHomePage(html) {
  if (!html.includes(EXPECTED_TITLE)) {
    throw new Error(`未找到页面标题：${EXPECTED_TITLE}`)
  }
}

// 适用场景：执行 Web dev server 活性探测。
async function main() {
  const url = getWebBaseUrl()
  try {
    const html = await fetchHomePage(url)
    assertHomePage(html)
    console.log(`web ready: ${url} ${toSingleLine(EXPECTED_TITLE)}`)
  } catch (error) {
    console.error(`web not ready: ${url}`)
    console.error(error instanceof Error ? error.message : String(error))
    process.exitCode = 1
  }
}

await main()
