#!/usr/bin/env bash
# VPS Probe 一键安装 / 升级 / 卸载
#   安装：  curl -fsSL https://raw.githubusercontent.com/zhushili/vps-probe/main/install.sh | bash
#   带参数：... | bash -s -- --port 9000 --password 'xxx'     （参数原样传给 probe.py install）
#   卸载：  ... | bash -s -- uninstall
# 设置 PROBE_REF 可固定安装某个提交，例如 PROBE_REF=<commit> bash install.sh
set -euo pipefail
REPO=${PROBE_REPO:-zhushili/vps-probe}
REF=${PROBE_REF:-main}

die() { printf '\033[31m错误：%s\033[0m\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "请用 root 运行（普通用户把 | bash 换成 | sudo bash）"
command -v systemctl >/dev/null || die "需要 systemd"

if ! command -v python3 >/dev/null; then
  echo "正在安装 python3 ..."
  if command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y -qq python3-minimal
  elif command -v dnf >/dev/null; then dnf install -y -q python3
  elif command -v yum >/dev/null; then yum install -y -q python3
  else die "请先手动安装 python3"; fi
fi
python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' || die "需要 Python 3.8 或更高版本"

cmd=install
if [[ ${1:-} == uninstall || ${1:-} == --uninstall ]]; then cmd=uninstall; shift; fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
here=${BASH_SOURCE[0]:-}
if [[ -n $here && -f $(dirname "$here")/probe.py ]]; then
  cp "$(dirname "$here")/probe.py" "$tmp/probe.py"          # 在仓库目录里直接运行 install.sh
else
  url="https://raw.githubusercontent.com/$REPO/$REF/probe.py"
  if command -v curl >/dev/null; then curl -fsSL "$url" -o "$tmp/probe.py"; else wget -qO "$tmp/probe.py" "$url"; fi \
    || die "下载 probe.py 失败，请检查能否访问 GitHub"
fi
python3 -c 'import ast, sys; ast.parse(open(sys.argv[1], encoding="utf-8").read())' "$tmp/probe.py" 2>/dev/null \
  || die "probe.py 不完整，请重试"
python3 "$tmp/probe.py" "$cmd" "$@"
