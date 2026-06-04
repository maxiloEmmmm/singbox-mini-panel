#!/bin/sh
# 验证背景：
# release workflow 下载官方 sing-box tar.gz 后，需要把其中的
# sing-box 二进制复制到 sboxctl 同级目录。
# 这里用本地临时 tar 包验证抽取逻辑，避免依赖真实网络下载。

set -eu

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

archive_root="$tmp_dir/sing-box-1.13.12-linux-amd64"
archive_path="$tmp_dir/sing-box-1.13.12-linux-amd64.tar.gz"
stage_dir="$tmp_dir/stage"

mkdir -p "$archive_root" "$stage_dir"
printf '#!/bin/sh\n' > "$archive_root/sing-box"
chmod 0755 "$archive_root/sing-box"
tar -C "$tmp_dir" -czf "$archive_path" "$(basename "$archive_root")"

extract_dir="$tmp_dir/extract"
mkdir -p "$extract_dir"
tar -xzf "$archive_path" -C "$extract_dir"
sing_box_path=$(find "$extract_dir" -type f -name sing-box -perm -111 | head -n 1)
if [ -z "$sing_box_path" ]; then
  echo "sing-box binary not found" >&2
  exit 1
fi

cp "$sing_box_path" "$stage_dir/sing-box"
chmod 0755 "$stage_dir/sing-box"

if [ ! -x "$stage_dir/sing-box" ]; then
  echo "stage sing-box is not executable" >&2
  exit 1
fi
