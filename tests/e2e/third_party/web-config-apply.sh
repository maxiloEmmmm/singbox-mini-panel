#!/usr/bin/env bash
# Run the real panel and sing-box in isolated namespaces for the Chromium apply flow.
# Example: sudo bash tests/e2e/third_party/web-config-apply.sh ./sboxctl/sboxctl ./sboxctl/sing-box /etc/sboxctl/geofiles
set -euo pipefail

if [[ ${1:-} != --isolated ]]; then
    exec unshare --net --mount --propagation private --pid --fork --kill-child --mount-proc \
        bash "$(realpath "$0")" --isolated "$(realpath "$1")" "$(realpath "$2")" \
        "$(realpath "$3")" "$(readlink /proc/self/ns/net)"
fi

[[ $$ == 1 && $(id -u) == 0 && $(readlink /proc/self/ns/net) != "$5" ]]
mount -t tmpfs -o mode=0755 tmpfs /run
export APPLY_FIXTURE=/run/web-apply
export APPLY_REAL_SING_BOX=$3
mkdir -p "$APPLY_FIXTURE"/{bin,state,logs,geo}
cp "$2" "$APPLY_FIXTURE/bin/sboxctl"
cp "$4/"*.srs "$APPLY_FIXTURE/geo/"
mount --bind "$APPLY_FIXTURE/state" /etc/sboxctl

# Control config-check completion while keeping the real validator and data plane.
printf '%s\n' \
    '#!/bin/bash' \
    'if [[ $1 == check && -f $APPLY_FIXTURE/check-mode ]]; then' \
    '  touch "$APPLY_FIXTURE/check-started"' \
    '  while [[ $(<"$APPLY_FIXTURE/check-mode") == hold ]]; do sleep 0.05; done' \
    '  if [[ $(<"$APPLY_FIXTURE/check-mode") == fail ]]; then' \
    '    printf "%s\n" "fixture rejected candidate" >&2' \
    '    exit 1' \
    '  fi' \
    'fi' \
    'exec "$APPLY_REAL_SING_BOX" "$@"' > "$APPLY_FIXTURE/bin/sing-box"
chmod +x "$APPLY_FIXTURE/bin/sing-box"
printf '%s\n' \
    'inbound: {mode: tun, tun: {route_exclude_address: [192.0.2.0/24]}}' \
    'backend: {static: [{protocol: socks, key: fixture, server: 192.0.2.1, port: 1080}]}' \
    'web: {enabled: true, listen: 127.0.0.1, port: 9000, auth: {username: fixture, password: fixture-secret}}' \
    'geofiles: {ads_block: false, hosts_override: false}' \
    "log: {dir: $APPLY_FIXTURE/logs}" > "$APPLY_FIXTURE/config.yaml"
touch "$APPLY_FIXTURE/force-direct" "$APPLY_FIXTURE/force-proxy"
ip link set lo up
ip link add wan0 type dummy
ip addr add 192.0.2.154/24 dev wan0
ip link set wan0 up
ip route add default via 192.0.2.1 dev wan0
socat TCP4-LISTEN:18081,bind=127.0.0.1,reuseaddr,fork EXEC:/usr/bin/true &

"$APPLY_FIXTURE/bin/sboxctl" -config "$APPLY_FIXTURE/config.yaml" -geo-dir "$APPLY_FIXTURE/geo" \
    -force-direct "$APPLY_FIXTURE/force-direct" -force-proxy "$APPLY_FIXTURE/force-proxy" \
    -sing-box-config "$APPLY_FIXTURE/sing-box.json" daemon > "$APPLY_FIXTURE/daemon.log" 2>&1 &
panel=$!
for attempt in {1..60}; do
    if curl --noproxy '*' -fsS --max-time 1 http://127.0.0.1:9000/api/health >/dev/null 2>&1 &&
        curl --noproxy '*' -fsS --max-time 1 http://127.0.0.1:9090/version >/dev/null 2>&1; then break; fi
    sleep 0.1
done
APPLY_INITIAL_PID=$(pgrep -P "$panel" -x sing-box)
export APPLY_INITIAL_PID
if ! node "$(dirname "$0")/../web-config-apply.mjs"; then
    tail -n 18 "$APPLY_FIXTURE/logs/sboxctl.log" "$APPLY_FIXTURE/logs/sing-box.stderr.log" >&2 || true
    exit 1
fi
kill -TERM "$panel"
wait "$panel"
