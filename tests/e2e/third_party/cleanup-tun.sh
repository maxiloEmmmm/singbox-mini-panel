#!/usr/bin/env bash
# Verify that doctor survives and removes TUN state in an isolated namespace.
# Example: sudo bash tests/e2e/third_party/cleanup-tun.sh ./sboxctl/sboxctl
set -euo pipefail

if [[ ${1:-} != --isolated ]]; then
    binary=$(realpath "${1:?provide the sboxctl binary}")
    exec unshare --net --mount --propagation private --pid --fork --kill-child --mount-proc \
        bash "$(realpath "$0")" --isolated "$binary" "$(readlink /proc/self/ns/net)"
fi

[[ $$ == 1 && $(id -u) == 0 && $(readlink /proc/self/ns/net) != "$3" ]]
mount -t tmpfs -o mode=0755 tmpfs /run
work=/run/tun-doctor
mkdir -p "$work/log" "$work/empty"
# Keep the host's service scripts and nftables snippets out of the cleanup path.
for path in /etc/init.d /etc/nftables.d; do
    if [[ -d $path ]]; then mount --bind "$work/empty" "$path"; fi
done
printf 'log: {dir: %s/log}\n' "$work" > "$work/config.yaml"

ip link add sbox0 type dummy
ip link set sbox0 up
ip -4 route add 198.51.100.0/24 dev sbox0 table 2022
ip -4 rule add pref 9001 fwmark 0x2023 lookup 2022
nft add table inet sing-box

cp "$(command -v sleep)" "$work/sing-box"
"$work/sing-box" 30 &
sing_box=$!
sh -c 'sleep 30 & wait' fixture /usr/bin/sing-box run &
unrelated=$!
for attempt in {1..30}; do
    if [[ $(<"/proc/$sing_box/comm") == sing-box && $(<"/proc/$unrelated/comm") == sh ]]; then break; fi
    sleep 0.1
done
[[ $(<"/proc/$sing_box/comm") == sing-box && $(<"/proc/$unrelated/comm") == sh ]]

if ! timeout 12s "$2" -config "$work/config.yaml" doctor cleanup-tun > "$work/doctor.log" 2>&1; then
    tail -n 12 "$work/doctor.log" >&2
    exit 1
fi
grep -Fxq 'cleanup-tun 完成' "$work/doctor.log"
kill -0 "$unrelated"
if kill -0 "$sing_box" 2>/dev/null || nft list table inet sing-box >/dev/null 2>&1 ||
    ip link show sbox0 >/dev/null 2>&1 || ip -4 rule show | grep -q '^9001:'; then
    printf '%s\n' 'doctor left TUN state behind' >&2
    exit 1
fi
