/** formatBytes 把字节数转成人类可读短格式，适用于文件大小展示。 */
export function formatBytes(value: number) {
  if (value <= 0) {
    return '0 B'
  }
  if (value < 1024) {
    return `${value} B`
  }
  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KB`
  }
  return `${(value / 1024 / 1024).toFixed(2)} MB`
}

/** formatTime 把后端时间转成人类可读短格式。 */
export function formatTime(value: string) {
  if (!value) {
    return '无记录'
  }
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value
  }
  const month = `${date.getMonth() + 1}`.padStart(2, '0')
  const day = `${date.getDate()}`.padStart(2, '0')
  const hour = `${date.getHours()}`.padStart(2, '0')
  const minute = `${date.getMinutes()}`.padStart(2, '0')
  return `${month}-${day} ${hour}:${minute}`
}

/** formatDurationSince 把启动时间换算成当前进程已运行多久。 */
export function formatDurationSince(value: string, now: number) {
  if (!value) {
    return '无记录'
  }
  const startedAt = new Date(value).getTime()
  if (Number.isNaN(startedAt)) {
    return value
  }
  let seconds = Math.max(0, Math.floor((now - startedAt) / 1000))
  const days = Math.floor(seconds / 86400)
  seconds %= 86400
  const hours = Math.floor(seconds / 3600)
  seconds %= 3600
  const minutes = Math.floor(seconds / 60)
  const remainSeconds = seconds % 60
  if (days > 0) {
    return `${days}天${hours}小时`
  }
  if (hours > 0) {
    return `${hours}小时${minutes}分`
  }
  if (minutes > 0) {
    return `${minutes}分${remainSeconds}秒`
  }
  return `${remainSeconds}秒`
}
