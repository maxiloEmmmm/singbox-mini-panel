#!/usr/bin/env node

import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { createServer } from 'node:net'

const HOST = '127.0.0.1'
const EXPECTED_TITLE = 'LLM 闭环 Web 测试靶场'
const READY_TIMEOUT_MS = 20_000

// 适用场景：向操作系统申请一个当前可用端口。
async function getFreePort() {
  const server = createServer()
  server.listen(0, HOST)
  await once(server, 'listening')

  const address = server.address()
  await new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error)
        return
      }

      resolve(undefined)
    })
  })

  if (address === null || typeof address === 'string') {
    throw new Error('无法获取临时端口')
  }

  return address.port
}

// 适用场景：把输入文本按脚本输出需求压成单行摘要。
function toSingleLine(text) {
  return text.replace(/\s+/g, ' ').trim()
}

// 适用场景：判断错误是否来自服务尚未就绪。
function isRetryableFetchError(error) {
  return error instanceof TypeError || error?.cause?.code === 'ECONNREFUSED'
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

// 适用场景：轮询等待临时 Web 服务可访问。
async function waitForWebReady(url) {
  const deadline = Date.now() + READY_TIMEOUT_MS
  let lastError = null

  while (Date.now() < deadline) {
    try {
      const html = await fetchHomePage(url)
      assertHomePage(html)
      return
    } catch (error) {
      lastError = error
      if (!isRetryableFetchError(error)) {
        throw error
      }
    }

    await new Promise((resolve) => {
      setTimeout(resolve, 250)
    })
  }

  throw new Error(`等待 Web 服务超时：${lastError?.message ?? 'unknown'}`)
}

// 适用场景：启动临时 Vite preview 服务。
function startPreviewServer(port) {
  return spawn('npm', ['run', 'preview', '--', '--host', HOST, '--port', String(port)], {
    stdio: ['ignore', 'pipe', 'pipe'],
  })
}

// 适用场景：把子进程输出接到当前终端。
function pipeProcessOutput(child) {
  child.stdout.on('data', (chunk) => {
    process.stdout.write(chunk)
  })
  child.stderr.on('data', (chunk) => {
    process.stderr.write(chunk)
  })
}

// 适用场景：关闭临时服务并等待进程退出。
async function stopPreviewServer(child) {
  if (child.exitCode !== null || child.signalCode !== null) {
    return
  }

  child.kill('SIGTERM')
  await Promise.race([
    once(child, 'exit'),
    new Promise((resolve) => {
      setTimeout(resolve, 2_000)
    }),
  ])
}

// 适用场景：执行一次自包含 Web 验证。
async function main() {
  const port = await getFreePort()
  const url = `http://${HOST}:${port}/`
  const preview = startPreviewServer(port)
  pipeProcessOutput(preview)

  try {
    await waitForWebReady(url)
    console.log(`web verify passed: ${url} ${toSingleLine(EXPECTED_TITLE)}`)
  } finally {
    await stopPreviewServer(preview)
  }
}

await main()
