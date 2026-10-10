"""命令行入口：vps-probe [命令] [参数]，不带命令时打开菜单"""
import argparse
import os
import sys

from .config import PANEL, VERSION
from .util import read_text


def _add_install_options(p):
    p.add_argument("--host", help="监听地址，默认 0.0.0.0")
    p.add_argument("--port", type=int, help="监听端口，默认 8899")
    p.add_argument("--user", help="登录用户名，默认 admin")
    p.add_argument("--password", help="登录密码，安装时不指定则自动生成")
    p.add_argument("--interval", type=float, help="采样间隔（秒），默认 2")
    p.add_argument("--reset-day", type=int, help="月流量重置日 1-28，默认每月 1 号")
    p.add_argument("--ifaces", help="只统计这些网卡的流量，逗号分隔，支持通配符，如 eth0,ens*")
    p.add_argument("--agent", metavar="URL", help="子服务器模式：面板地址，如 https://probe.example.com")
    p.add_argument("--token", help="子服务器模式：在面板上添加服务器时生成的 token")
    p.add_argument("--allow-http", action="store_true", help="子服务器模式：允许面板地址使用 HTTP（仅限可信内网）")


def build_parser():
    ap = argparse.ArgumentParser(prog="vps-probe", description="VPS Probe %s - 轻量级 Linux 服务器探针，不带命令时打开管理菜单" % VERSION)
    ap.add_argument("--version", action="version", version=VERSION)
    sub = ap.add_subparsers(dest="command", metavar="命令")

    sub.add_parser("menu", help="交互式管理菜单")
    p = sub.add_parser("install", help="安装或升级面板 / 子服务器")
    _add_install_options(p)
    p.add_argument("--no-auth", action="store_true", help="不设登录密码")
    p.add_argument("--domain", help="同时配置域名和 HTTPS 反向代理")
    p.add_argument("--email", default="", help="证书到期提醒邮箱（可选）")
    p.add_argument("--proxy", choices=("caddy", "nginx"), help="指定反向代理，默认自动选择")
    sub.add_parser("uninstall", help="卸载（从子服务器目录运行时只卸载子服务器）")
    p = sub.add_parser("proxy", help="配置域名和 HTTPS 反向代理")
    p.add_argument("--domain", help="域名，需要已解析到本机公网 IP")
    p.add_argument("--email", default="", help="证书到期提醒邮箱（可选）")
    p.add_argument("--proxy", choices=("caddy", "nginx"), help="指定反向代理，默认自动选择")
    p.add_argument("--lock", action="store_true", help="子服务器都改用 HTTPS 后，关闭面板的 HTTP 端口")
    p.add_argument("--remove", action="store_true", help="撤销 HTTPS，面板恢复为 HTTP 访问")
    sub.add_parser("status", help="查看状态和登录信息")
    p = sub.add_parser("upgrade", help="从 GitHub 升级到最新版本")
    p.add_argument("--ref", default="main", help="分支、标签或提交，默认 main")
    p = sub.add_parser("run", help="前台运行（systemd 服务使用）")
    _add_install_options(p)
    p.add_argument("--data-dir", help="数据保存目录，传空字符串则不保存")
    return ap


def _run(args):
    """前台运行：命令行参数优先，其次是环境变量（systemd 服务通过 EnvironmentFile 传入）"""
    env = os.environ.get
    args.host = args.host or env("PROBE_HOST") or "0.0.0.0"
    args.port = args.port or int(env("PROBE_PORT") or 8899)
    args.user = args.user if args.user is not None else env("PROBE_USER", "")
    args.password = args.password if args.password is not None else env("PROBE_PASSWORD", "")
    args.interval = min(10.0, max(1.0, args.interval or float(env("PROBE_INTERVAL") or 2)))
    args.reset_day = min(28, max(1, args.reset_day or int(env("PROBE_RESET_DAY") or 1)))
    args.ifaces = args.ifaces if args.ifaces is not None else env("PROBE_IFACES", "")
    args.ifaces_exclude = env("PROBE_IFACES_EXCLUDE", "")
    if args.data_dir is None:
        args.data_dir = env("STATE_DIRECTORY") or env("PROBE_DATA_DIR") or os.path.join(os.getcwd(), "data")
    args.agent = args.agent or env("PROBE_AGENT", "")
    args.token = args.token or env("PROBE_TOKEN", "")
    args.allow_http = args.allow_http or env("PROBE_ALLOW_HTTP") == "1"
    if args.agent:
        from .agent import run_agent
        run_agent(args)
    else:
        from .panel import run_panel
        run_panel(args)


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)
    cmd = args.command or "menu"
    if not read_text("/proc/stat"):
        sys.exit("错误：找不到 /proc/stat，VPS Probe 只能运行在 Linux 上。")
    if cmd == "run":
        return _run(args)
    if cmd == "menu":
        from .menu import run_menu
        return run_menu()
    if cmd == "status":
        from .menu import show_status
        return show_status()
    if cmd == "upgrade":
        from .upgrade import cmd_upgrade
        return cmd_upgrade(args.ref)

    from . import proxy, service
    try:
        if cmd == "install":
            service.cmd_install(args)
            if args.domain and not args.agent:
                proxy.setup(args.domain, args.email, args.proxy)
        elif cmd == "uninstall":
            names = service.uninstall_targets()
            if PANEL in names and service.installed(PANEL):
                proxy.cleanup()
            service.cmd_uninstall(names)
        elif cmd == "proxy":
            if args.remove:
                proxy.remove()
            elif args.lock:
                proxy.lock_http()
            elif args.domain:
                proxy.setup(args.domain, args.email, args.proxy)
            else:
                ap.error("proxy 需要 --domain、--lock 或 --remove 之一")
    except proxy.ProxyError as e:
        sys.exit("错误：%s" % e)
