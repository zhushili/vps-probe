#!/usr/bin/env bash
# VPS Probe 一键脚本
#   打开菜单：curl -fsSL https://raw.githubusercontent.com/zhushili/vps-probe/main/install.sh | bash
#   直接安装：... | bash -s -- install [--port 9000 --password xxx --domain probe.example.com]
#   卸载：    ... | bash -s -- uninstall
# 安装后可随时运行 vps-probe 打开菜单。设置 PROBE_REF=<分支/提交> 可固定版本。
set -euo pipefail
REPO=${PROBE_REPO:-zhushili/vps-probe}
REF=${PROBE_REF:-main}

die() { printf '\033[31m错误：%s\033[0m\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "请用 root 运行（普通用户把 | bash 换成 | sudo bash）"
command -v systemctl >/dev/null || die "需要 systemd"

if ! command -v python3 >/dev/null; then
  echo "正在安装 python3 ..."
  if command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y -qq python3
  elif command -v dnf >/dev/null; then dnf install -y -q python3
  elif command -v yum >/dev/null; then yum install -y -q python3
  else die "请先手动安装 python3"; fi
fi
python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' || die "需要 Python 3.8 或更高版本"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
here=${BASH_SOURCE[0]:-}
if [[ -n $here && -f $(dirname "$here")/vps_probe/__init__.py ]]; then
  src=$(cd "$(dirname "$here")" && pwd)                     # 在仓库目录里直接运行
else
  url="https://codeload.github.com/$REPO/tar.gz/$REF"
  if command -v curl >/dev/null; then curl -fsSL "$url" -o "$tmp/src.tgz"; else wget -qO "$tmp/src.tgz" "$url"; fi \
    || die "下载失败，请检查能否访问 GitHub"
  tar -xzf "$tmp/src.tgz" -C "$tmp" || die "解压失败，请重试"
  init=$(find "$tmp" -path '*/vps_probe/__init__.py' | head -n 1)
  [[ -n $init ]] || die "下载的文件不完整，请重试"
  src=$(dirname "$(dirname "$init")")
fi

if [[ $# -eq 0 ]]; then
  if (exec </dev/tty) 2>/dev/null; then set -- menu; else set -- install; fi   # 有终端时打开菜单
elif [[ $1 == -* ]]; then
  set -- install "$@"                                       # 兼容旧写法：bash -s -- --port 9000
fi
cd "$src" && python3 -m vps_probe "$@"
