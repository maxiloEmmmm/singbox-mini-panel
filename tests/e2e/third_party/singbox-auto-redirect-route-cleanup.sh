#!/bin/sh
# 验证背景：
# sing-box TUN auto_redirect 异常退出后，OpenWrt 可能残留
# local 127.0.0.1 dev wan/br-lan 路由，下一次 start 会报 file exists。
# 这里不直接操作系统路由，只验证清理命令生成逻辑不会误选普通路由。

set -eu

sample='default via 192.168.1.1 dev wan proto static src 192.168.1.2
local 127.0.0.1 dev wan table 186522128 scope host
local 127.0.0.1 dev br-lan table 186522128 scope host
local 127.0.0.1 dev lo table local proto kernel scope host src 127.0.0.1
local 10.0.0.1 dev br-lan table local proto kernel scope host src 10.0.0.1'

actual=$(printf '%s\n' "$sample" | awk '/^local 127\.0\.0\.1 dev (wan|br-lan)/ {dev=$4; table=""; for (i=1; i<=NF; i++) if ($i=="table") table=$(i+1); if (table=="") print "ip route del local 127.0.0.1 dev " dev; else print "ip route del local 127.0.0.1 dev " dev " table " table;}')
expected='ip route del local 127.0.0.1 dev wan table 186522128
ip route del local 127.0.0.1 dev br-lan table 186522128'

if [ "$actual" != "$expected" ]; then
  printf 'unexpected cleanup commands\nactual:\n%s\nexpected:\n%s\n' "$actual" "$expected" >&2
  exit 1
fi
