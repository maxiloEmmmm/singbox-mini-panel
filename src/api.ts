/** authHeaders 生成带 JWT 的 JSON 请求头。 */
export function authHeaders(token: string) {
  return {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
  }
}

/** readError 从失败响应中解析后端错误消息。 */
export async function readError(response: Response) {
  try {
    const data = await response.json()
    return data.error || response.statusText
  } catch {
    return response.statusText
  }
}
