"""交互式管理菜单：一键脚本不带参数运行时，或安装后执行 vps-probe 时打开"""
import getpass
import sys
import unicodedata
from urllib.parse import urlparse

from . import proxy, service, upgrade
from .agent import is_loopback
from .config import AGENT, PANEL, VERSION
from .util import CorruptFile, load_json

GREEN, YELLOW, RED, BOLD, DIM, RESET = "\033[32m", "\033[33m", "\033[31m", "\033[1m", "\033[2m", "\033[0m"


def color(c, text):
    return c + text + RESET


def pad(text, width):
    """按显示宽度补空格（中文占两格）"""
    w = sum(2 if unicodedata.east_asian_width(ch) in "WF" else 1 for ch in text)
    return text + " " * max(0, width - w)


class Prompt:
    """从终端读输入：通过 curl | bash 运行时标准输入是脚本本身，改从 /dev/tty 读"""

    def __init__(self):
        self.f = sys.stdin if sys.stdin.isatty() else open("/dev/tty", encoding="utf-8", errors="replace")

    def ask(self, text, default=""):
        hint = color(DIM, "（默认 %s）" % default) if str(default) != "" else ""
        sys.stdout.write("%s%s：" % (text, hint))
        sys.stdout.flush()
        line = self.f.readline()
        if not line:
            raise EOFError
        return line.strip() or str(default)

    def yes(self, text, default=False):
        ans = self.ask("%s [%s]" % (text, "Y/n" if default else "y/N")).lower()
        return default if not ans else ans in ("y", "yes", "是")

    def password(self, text):
        try:
            return getpass.getpass(text + "：")
        except (EOFError, OSError):
            return self.ask(text)


# ---------------------------------------------------------------- 状态

def _agent_master(env):
    """子服务器实际使用的面板地址（收到 HTTPS 新地址后会记在数据目录里）"""
    try:
        moved = (load_json("/var/lib/%s/master.json" % AGENT) or {}).get("master")
    except CorruptFile:
        moved = None
    return moved or env.get("PROBE_AGENT", "")


def _nodes(env):
    try:
        return [n for n in service.panel_api(env, "/api/nodes")["nodes"] if not n["local"]]
    except (OSError, ValueError, KeyError):
        return None


def _summary():
    rows, st = [], service.status()
    for name, label in ((PANEL, "面板"), (AGENT, "子服务器")):
        s = st.get(name)
        if not s:
            rows.append("  %s%s" % (pad(label, 10), color(DIM, "○ 未安装")))
            continue
        env, parts = s["env"], []
        if name == PANEL:
            parts.append(service.public_url(env))
            nodes = _nodes(env) if s["active"] else None
            if nodes is not None:
                parts.append("子服务器 %d/%d 在线" % (sum(1 for n in nodes if n["online"]), len(nodes)))
        else:
            parts.append("上报到 " + _agent_master(env))
        if s["memory"]:
            parts.append("%.0f MB" % s["memory"])
        dot = color(GREEN, "● 运行中") if s["active"] else color(RED, "● 已停止")
        rows.append("  %s%s  %s" % (pad(label, 10), dot, "  ".join(parts)))
    return rows


def show_status():
    st = service.status()
    if not st:
        print("没有安装 VPS Probe")
        return
    p = st.get(PANEL)
    if p:
        env = p["env"]
        print(color(BOLD, "面板") + "  " + (color(GREEN, "运行中") if p["active"] else color(RED, "已停止")))
        print("  访问地址：%s" % service.public_url(env))
        if env.get("PROBE_DOMAIN"):
            print("  HTTPS：   %s 反向代理，面板%s" % (env.get("PROBE_PROXY", ""),
                  "只监听本机" if env.get("PROBE_HOST") == "127.0.0.1" else "仍开放 HTTP 端口 %s" % env.get("PROBE_PORT")))
        if env.get("PROBE_PASSWORD"):
            print("  用户名：  %s\n  密码：    %s" % (env.get("PROBE_USER", ""), env["PROBE_PASSWORD"]))
        else:
            print("  登录认证：未开启")
        if p["memory"]:
            print("  内存：    %.1f MB" % p["memory"])
        nodes = _nodes(env) if p["active"] else None
        if nodes:
            print("  子服务器：")
            for n in nodes:
                state = color(GREEN, "在线") if n["online"] else (color(RED, "离线") if n["reported"] else color(YELLOW, "等待接入"))
                print("    %s  %s%s" % (state, n["name"], color(DIM, "  HTTPS") if n.get("secure") else ""))
    a = st.get(AGENT)
    if a:
        print(color(BOLD, "子服务器") + "  " + (color(GREEN, "运行中") if a["active"] else color(RED, "已停止")))
        print("  上报到：  %s" % _agent_master(a["env"]))
        if a["memory"]:
            print("  内存：    %.1f MB" % a["memory"])


# ---------------------------------------------------------------- 菜单项

def act_install_panel(pr):
    env = service.read_env(service.paths(PANEL)["env"])
    print(color(DIM, "直接回车使用默认值"))
    port = pr.ask("监听端口", env.get("PROBE_PORT") or 8899)
    user = pr.ask("登录用户名", env.get("PROBE_USER") or "admin")
    pw = pr.password("登录密码（直接回车%s）" % ("保持不变" if env.get("PROBE_PASSWORD") else "自动生成"))
    rd = pr.ask("月流量重置日（1-28）", env.get("PROBE_RESET_DAY") or 1)
    if not (port.isdigit() and rd.isdigit()):
        print(color(RED, "端口和重置日需要是数字"))
        return
    service.cmd_install(service.make_args(port=int(port), user=user, password=pw or None, reset_day=int(rd)))
    if not service.read_env(service.paths(PANEL)["env"]).get("PROBE_DOMAIN") and \
            pr.yes("\n现在配置域名和 HTTPS 吗？（公网使用强烈建议）"):
        act_proxy(pr)


def act_install_agent(pr):
    print("先在面板上点「添加服务器」。也可以直接把面板生成的整条命令粘贴到终端执行，不必使用这个菜单。")
    url = pr.ask("面板地址（如 https://probe.example.com）")
    token = pr.ask("token")
    u = urlparse(url)
    allow = False
    if u.scheme == "http" and u.hostname and not is_loopback(u.hostname):
        print(color(YELLOW, "面板地址是 HTTP：token 和监控数据会以明文传输。"))
        if not pr.yes("确认面板与这台服务器之间是可信网络（内网 / 专线 / VPN）？"):
            return
        allow = True
    service.cmd_install(service.make_args(agent=url, token=token, allow_http=allow))


def act_proxy(pr):
    if not service.installed(PANEL):
        print("请先安装面板")
        return
    env = service.read_env(service.paths(PANEL)["env"])
    if env.get("PROBE_DOMAIN"):
        locked = env.get("PROBE_HOST") == "127.0.0.1"
        print("当前域名：https://%s（%s，面板%s）" % (env["PROBE_DOMAIN"], env.get("PROBE_PROXY", ""),
              "只监听本机" if locked else "仍开放 HTTP 端口"))
        print("  1  更换域名\n  2  关闭面板的 HTTP 端口\n  3  撤销 HTTPS\n  0  返回")
        c = pr.ask("请选择")
        if c == "2":
            proxy.lock_http()
        elif c == "3" and pr.yes("撤销后面板恢复为 HTTP 访问，确定吗？"):
            proxy.remove()
        if c != "1":
            return
    print("需要：一个已解析到本机公网 IP 的域名；云厂商安全组放行 80、443 端口。")
    domain = pr.ask("域名（如 probe.example.com）")
    if not domain:
        return
    email = pr.ask("邮箱（可选，用于证书到期提醒）", "")
    proxy.setup(domain, email)


def act_status(pr):
    show_status()


def act_logs(pr):
    names = [n for n in (PANEL, AGENT) if service.installed(n)]
    if not names:
        print("没有安装 VPS Probe")
        return
    name = names[0]
    if len(names) == 2 and pr.ask("查看哪个服务的日志：1 面板  2 子服务器", "1") == "2":
        name = AGENT
    print(service.journal(name, lines=50).rstrip() or "（没有日志）")


def act_restart(pr):
    for name in (PANEL, AGENT):
        if service.installed(name):
            service.systemctl("restart", name)
            ok = service.healthy(name, service.read_env(service.paths(name)["env"]))
            print("%s：%s" % (name, color(GREEN, "已重启") if ok else color(RED, "重启后未能正常运行，请查看日志")))


def act_upgrade(pr):
    if pr.yes("从 GitHub 下载最新版本并升级（配置和数据保留，失败自动回滚）？", True):
        upgrade.cmd_upgrade()
        print(color(GREEN, "升级完成，请重新运行 vps-probe 打开新版本的菜单"))
        return "exit"


def act_uninstall(pr):
    names = [n for n in (PANEL, AGENT) if service.installed(n)]
    if not names:
        print("没有安装 VPS Probe")
        return
    if len(names) == 2:
        c = pr.ask("卸载：1 全部  2 只卸载面板  3 只卸载子服务器", "1")
        names = {"2": [PANEL], "3": [AGENT]}.get(c, names)
    if not pr.yes("确定卸载%s吗？面板的历史数据会一起删除" % "、".join("面板" if n == PANEL else "子服务器" for n in names)):
        return
    if PANEL in names:
        proxy.cleanup()
    service.cmd_uninstall(names)
    if not any(service.installed(n) for n in (PANEL, AGENT)):
        return "exit"


ACTIONS = [
    ("安装面板 / 修改面板配置", act_install_panel),
    ("安装子服务器", act_install_agent),
    ("配置域名和 HTTPS", act_proxy),
    ("查看状态和登录信息", act_status),
    ("查看日志", act_logs),
    ("重启服务", act_restart),
    ("升级到最新版本", act_upgrade),
    ("卸载", act_uninstall),
]


def run_menu():
    service.require_root()
    try:
        pr = Prompt()
    except OSError:
        sys.exit("没有可用的终端，无法显示菜单。请使用命令行参数，例如：vps-probe install（查看全部：vps-probe -h）")
    while True:
        line = "─" * 52
        print("\n  %s\n  %s" % (color(BOLD, "VPS Probe %s" % VERSION), line))
        print("\n".join(_summary()))
        print("  " + line)
        for i, (label, _) in enumerate(ACTIONS, 1):
            print("   %d  %s" % (i, label))
        print("   0  退出\n")
        try:
            choice = pr.ask("请输入数字")
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if choice == "0":
            return
        if not choice.isdigit() or not 1 <= int(choice) <= len(ACTIONS):
            print(color(RED, "无效的选择"))
            continue
        print()
        result = None
        try:
            result = ACTIONS[int(choice) - 1][1](pr)
        except SystemExit as e:
            if e.code not in (None, 0):
                print(color(RED, str(e.code)) if isinstance(e.code, str) else color(RED, "操作失败"))
        except proxy.ProxyError as e:
            print(color(RED, "错误：%s" % e))
        except KeyboardInterrupt:
            print("\n已取消")
        except EOFError:
            return
        if result == "exit":
            return
        try:
            pr.ask(color(DIM, "\n按回车返回菜单"))
        except (EOFError, KeyboardInterrupt):
            print()
            return

