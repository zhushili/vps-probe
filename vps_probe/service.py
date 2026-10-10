"""systemd 服务管理：安装 / 升级 / 修改配置 / 卸载 / 状态

安装和升级的流程：先完成全部检查（参数、端口）再动现有服务；备份旧的代码、配置和服务文件；
写入新版本后重启并做健康检查（面板请求 /healthz，子服务器确认进程稳定运行），
失败则自动恢复旧版本并重新启动，首次安装失败则清理干净。
"""
import base64
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
import types
import urllib.request
from urllib.parse import urlparse

from .agent import is_loopback
from .config import AGENT, PANEL, SHIM, TOKEN_RE
from .util import write_atomic

PKG_DIR = os.path.dirname(os.path.abspath(__file__))     # 当前运行的 vps_probe 包

SERVICE = """[Unit]
Description=VPS Probe ({role})
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/{name}.env
Environment=PYTHONPATH=/opt/{name} PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ExecStart={python} -m vps_probe run
Restart=always
RestartSec=3
# 资源限制：给小内存机器留足余量
Nice=10
MemoryMax={mem}
CPUQuota=25%
TasksMax={tasks}
# 安全加固：以临时低权限用户运行，系统目录只读
DynamicUser=yes
StateDirectory={name}
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
"""

SHIM_TEXT = """#!/bin/sh
# VPS Probe 管理命令（由安装程序生成）：不带参数时打开菜单
[ $# -eq 0 ] && set -- menu
PYTHONPATH=/opt/{name} exec {python} -m vps_probe "$@"
"""

# 由安装程序维护的配置项；其他 PROBE_* 配置项（如反向代理写入的 PROBE_DOMAIN）在升级时原样保留
MANAGED_KEYS = {"PROBE_HOST", "PROBE_PORT", "PROBE_USER", "PROBE_PASSWORD", "PROBE_RESET_DAY", "PROBE_INTERVAL",
                "PROBE_IFACES", "PROBE_AGENT", "PROBE_TOKEN", "PROBE_ALLOW_HTTP"}


# ---------------------------------------------------------------- 路径与配置文件

def paths(name):
    return {"env": "/etc/%s.env" % name, "unit": "/etc/systemd/system/%s.service" % name, "home": "/opt/" + name}


def env_quote(v):
    """systemd EnvironmentFile 的双引号写法，密码里有引号、$ 等字符也没问题"""
    return '"%s"' % re.sub(r'([\\"$`])', r"\\\1", str(v))


def read_env(path):
    env = {}
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return env
    for line in text.splitlines():
        m = re.match(r"\s*(\w+)=(.*)$", line)
        if not m:
            continue
        v = m.group(2).strip()
        if len(v) >= 2 and v[0] == v[-1] == "'":
            v = v[1:-1]
        elif len(v) >= 2 and v[0] == v[-1] == '"':
            v = re.sub(r"\\(.)", r"\1", v[1:-1])
        env[m.group(1)] = v
    return env


def env_text(cfg):
    return "".join("%s=%s\n" % (k, env_quote(v)) for k, v in cfg.items()).encode("utf-8")


def make_args(**kw):
    """构造 install_config / cmd_install 需要的参数（菜单和升级时使用）"""
    base = dict(agent=None, token=None, allow_http=False, host=None, port=None, user=None, password=None,
                no_auth=False, interval=None, reset_day=None, ifaces=None)
    base.update(kw)
    return types.SimpleNamespace(**base)


def install_config(args, old):
    """根据命令行参数和已有配置算出新配置：重复安装即升级，没指定的选项沿用旧值"""
    def pick(v, key, default):
        return v if v is not None else (old.get(key) or default)

    interval = pick(args.interval, "PROBE_INTERVAL", 2)
    ifaces = pick(args.ifaces, "PROBE_IFACES", "")
    if args.agent:
        u = urlparse(args.agent)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError("面板地址格式不正确：%s" % args.agent)
        if u.scheme == "http" and not args.allow_http and not is_loopback(u.hostname):
            raise ValueError("面板地址是 HTTP，token 和监控数据会明文传输。建议给面板配置 HTTPS；"
                             "确认是可信内网时可加 --allow-http")
        if not TOKEN_RE.match(args.token or ""):
            raise ValueError("token 格式不正确")
        cfg = {"PROBE_AGENT": args.agent.rstrip("/"), "PROBE_TOKEN": args.token, "PROBE_INTERVAL": interval}
        if u.scheme == "http" and args.allow_http:
            cfg["PROBE_ALLOW_HTTP"] = "1"
    else:
        if args.no_auth:
            user = pw = ""
        elif args.user or args.password or not old:
            user = args.user or old.get("PROBE_USER") or "admin"
            pw = args.password or old.get("PROBE_PASSWORD") or secrets.token_urlsafe(12)
        else:
            user, pw = old.get("PROBE_USER", ""), old.get("PROBE_PASSWORD", "")
        if ":" in user:
            raise ValueError("用户名不能包含冒号")
        cfg = {"PROBE_HOST": pick(args.host, "PROBE_HOST", "0.0.0.0"), "PROBE_PORT": pick(args.port, "PROBE_PORT", 8899),
               "PROBE_USER": user, "PROBE_PASSWORD": pw,
               "PROBE_RESET_DAY": pick(args.reset_day, "PROBE_RESET_DAY", 1), "PROBE_INTERVAL": interval}
        try:
            port, rd = int(cfg["PROBE_PORT"]), int(cfg["PROBE_RESET_DAY"])
        except ValueError:
            port = rd = 0
        if not 1 <= port <= 65535:
            raise ValueError("端口无效：%s" % cfg["PROBE_PORT"])
        if not 1 <= rd <= 28:
            raise ValueError("流量重置日必须是 1-28")
    if ifaces:
        cfg["PROBE_IFACES"] = ifaces
    for k, v in old.items():        # 手动添加或由反向代理写入的配置，升级时保留
        if k.startswith("PROBE_") and k not in MANAGED_KEYS:
            cfg[k] = v
    try:
        ok = 1 <= float(interval) <= 10
    except ValueError:
        ok = False
    if not ok:
        raise ValueError("采样间隔必须在 1-10 秒之间")
    return cfg


# ---------------------------------------------------------------- 系统操作

def systemctl(*a):
    return subprocess.run(("systemctl",) + a, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def require_root():
    if os.geteuid() != 0:
        sys.exit("错误：请用 root 运行（普通用户在命令前加 sudo）")
    if not shutil.which("systemctl"):
        sys.exit("错误：需要 systemd")


def installed(name):
    return os.path.exists(paths(name)["unit"])


def active(name):
    return systemctl("is-active", "--quiet", name)


def port_free(host, port):
    with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def panel_url(cfg, path="/"):
    """面板在本机可访问的地址"""
    host = cfg.get("PROBE_HOST") or "0.0.0.0"
    host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    return "http://%s:%s%s" % ("[%s]" % host if ":" in host else host, cfg.get("PROBE_PORT") or 8899, path)


def panel_ok(cfg):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(panel_url(cfg, "/healthz"), timeout=2) as r:
            return r.status == 200 and r.read() == b"ok"
    except (OSError, ValueError):
        return False


def panel_api(cfg, path):
    """用配置里的账号访问本机面板的 API"""
    req = urllib.request.Request(panel_url(cfg, path))
    if cfg.get("PROBE_USER") or cfg.get("PROBE_PASSWORD"):
        token = base64.b64encode(("%s:%s" % (cfg.get("PROBE_USER", ""), cfg.get("PROBE_PASSWORD", ""))).encode())
        req.add_header("Authorization", "Basic " + token.decode())
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=5) as r:
        return json.loads(r.read())


def healthy(name, cfg, timeout=15):
    """面板：/healthz 返回 ok；子服务器：启动 4 秒后进程仍在运行"""
    if name == AGENT:
        for wait in (4, 1):
            time.sleep(wait)
            if not active(name):
                return False
        return True
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(1)
        if active(name) and panel_ok(cfg):
            return True
    return False


def journal(name, since=None, lines=None):
    cmd = ["journalctl", "-u", name, "-o", "cat", "--no-pager"]
    cmd += ["--since", since] if since else ["-n", str(lines or 50)]
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout


def local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))   # UDP connect 不会真的发包，只是让系统选出出口网卡
            return s.getsockname()[0]
    except OSError:
        return "服务器IP"


def public_url(cfg):
    if cfg.get("PROBE_DOMAIN"):
        return "https://" + cfg["PROBE_DOMAIN"]
    return "http://%s:%s" % (local_ip(), cfg.get("PROBE_PORT") or 8899)


def _copy_package(home):
    """把当前运行的 vps_probe 包复制到 /opt/<服务名>/vps_probe；正是从那里运行时不用复制"""
    dst = os.path.join(home, "vps_probe")
    if os.path.realpath(PKG_DIR) == os.path.realpath(dst):
        return
    tmp = dst + ".new"
    shutil.rmtree(tmp, ignore_errors=True)
    shutil.copytree(PKG_DIR, tmp, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for root, dirs, files in os.walk(tmp):
        os.chmod(root, 0o755)
        for f in files:
            os.chmod(os.path.join(root, f), 0o644)
    shutil.rmtree(dst, ignore_errors=True)
    os.replace(tmp, dst)
    legacy = os.path.join(home, "probe.py")      # 1.3 版是单文件
    if os.path.exists(legacy):
        os.remove(legacy)


def _write_shim(name):
    write_atomic(SHIM, SHIM_TEXT.format(name=name, python=sys.executable).encode("utf-8"), 0o755)


def _shim_target():
    m = re.search(r"PYTHONPATH=/opt/([\w-]+)", open(SHIM).read()) if os.path.exists(SHIM) else None
    return m.group(1) if m else None


# ---------------------------------------------------------------- 安装 / 升级

def cmd_install(args):
    """安装或升级（args.agent 非空时安装子服务器）。成功返回新配置，失败直接退出"""
    require_root()
    name = AGENT if args.agent else PANEL
    p = paths(name)
    old_env = read_env(p["env"])
    try:
        cfg = install_config(args, old_env)
    except ValueError as e:
        sys.exit("错误：%s" % e)

    # 1. 预检查：在动现有服务之前完成
    was_active = installed(name) and active(name)
    if name == PANEL:
        port = int(cfg["PROBE_PORT"])
        ours = was_active and str(old_env.get("PROBE_PORT", "")) == str(port)
        if not ours and not port_free(cfg["PROBE_HOST"], port):
            sys.exit("错误：端口 %d 已被占用，请换一个（现有服务未做任何改动）" % port)

    # 2. 备份旧版本：配置文件读进内存，代码目录复制一份
    backups = {}
    for f in (p["env"], p["unit"]):
        try:
            with open(f, "rb") as fh:
                backups[f] = fh.read()
        except OSError:
            pass
    bak = p["home"] + ".bak"
    shutil.rmtree(bak, ignore_errors=True)
    if os.path.isdir(p["home"]):
        shutil.copytree(p["home"], bak, symlinks=True)

    # 3. 写入新版本并重启
    since = time.strftime("%Y-%m-%d %H:%M:%S")
    service = SERVICE.format(name=name, python=sys.executable, role="子服务器" if name == AGENT else "面板",
                             mem="48M" if name == AGENT else "128M", tasks=32 if name == AGENT else 320)
    try:
        os.makedirs(p["home"], exist_ok=True)
        _copy_package(p["home"])
        write_atomic(p["env"], env_text(cfg), 0o600)
        write_atomic(p["unit"], service.encode("utf-8"), 0o644)
        systemctl("daemon-reload")
        systemctl("enable", name)
        systemctl("restart", name)
        ok = healthy(name, cfg)
    except OSError as e:
        print("写入文件失败：%s" % e)
        ok = False
    recent = journal(name, since)

    # 4. 失败回滚
    if not ok:
        print(recent.strip())
        if backups or os.path.isdir(bak):
            if os.path.isdir(bak):
                shutil.rmtree(p["home"], ignore_errors=True)
                os.replace(bak, p["home"])
            for f, data in backups.items():
                write_atomic(f, data, 0o600 if f.endswith(".env") else 0o644)
            systemctl("daemon-reload")
            if not was_active:
                sys.exit("错误：新版本启动失败，已回滚到原来的代码和配置")
            systemctl("restart", name)
            if healthy(name, read_env(p["env"])):
                sys.exit("错误：新版本启动失败，已回滚到原来的代码和配置，原服务已恢复运行")
            sys.exit("错误：新版本启动失败，已回滚到原来的代码和配置，但原服务也未能启动，请查看日志")
        systemctl("disable", "--now", name)
        for f in (p["unit"], p["env"]):
            try:
                os.remove(f)
            except OSError:
                pass
        shutil.rmtree(p["home"], ignore_errors=True)
        systemctl("daemon-reload")
        sys.exit("错误：服务启动失败，已撤销本次安装")

    shutil.rmtree(bak, ignore_errors=True)
    if name == PANEL or not installed(PANEL):
        _write_shim(name)
    green = "\033[32m%s\033[0m"
    if name == AGENT:
        print(green % ("✔ 子服务器探针已安装，正在向 %s 上报" % cfg["PROBE_AGENT"]))
        bad = [l for l in recent.splitlines() if "无法连接面板" in l or "token 无效" in l]
        if bad:
            print("\033[33m  注意：%s\033[0m" % bad[-1])
        print("  查看日志：journalctl -u %s -f" % name)
    else:
        print(green % ("✔ VPS Probe 面板%s成功" % ("升级" if backups else "安装")))
        print("  访问地址：%s" % public_url(cfg))
        if cfg["PROBE_PASSWORD"]:
            print("  用户名：  %s\n  密码：    %s" % (cfg["PROBE_USER"], cfg["PROBE_PASSWORD"]))
        else:
            print("  登录认证：未开启（任何人都能查看面板，且不能在网页上添加服务器）")
        if not cfg.get("PROBE_DOMAIN"):
            print("  公网使用请配置域名和 HTTPS：vps-probe proxy --domain 你的域名（或在菜单中选择）")
    print("  管理菜单：vps-probe")
    return cfg


def update_env(name, changes):
    """修改已安装服务的配置（值为 None 表示删除），重启并做健康检查；失败时恢复原配置。返回是否成功"""
    p = paths(name)
    with open(p["env"], "rb") as f:
        original = f.read()
    cfg = read_env(p["env"])
    for k, v in changes.items():
        if v is None:
            cfg.pop(k, None)
        else:
            cfg[k] = str(v)
    write_atomic(p["env"], env_text(cfg), 0o600)
    systemctl("restart", name)
    if healthy(name, cfg):
        return True
    write_atomic(p["env"], original, 0o600)
    systemctl("restart", name)
    return False


# ---------------------------------------------------------------- 卸载与状态

def uninstall_targets():
    """从 /opt/vps-probe-agent 运行时只卸载子服务器，其他情况全部卸载"""
    here = os.path.realpath(PKG_DIR)
    return [n for n in (PANEL, AGENT) if here.startswith("/opt/%s/" % n)] or [PANEL, AGENT]


def cmd_uninstall(names=None):
    require_root()
    names = names or uninstall_targets()
    found = False
    for name in names:
        p = paths(name)
        if not (os.path.exists(p["unit"]) or os.path.isdir(p["home"])):
            continue
        found = True
        systemctl("disable", "--now", name)
        for f in (p["unit"], p["env"], "/var/lib/" + name):   # /var/lib/X 是指向 private/X 的符号链接
            if os.path.islink(f) or os.path.isfile(f):
                os.remove(f)
        for d in (p["home"], p["home"] + ".bak", "/var/lib/private/" + name, "/var/lib/" + name):
            shutil.rmtree(d, ignore_errors=True)
        print("已卸载 %s" % name)
    systemctl("daemon-reload")
    target = _shim_target()
    if target and not installed(target):
        rest = [n for n in (PANEL, AGENT) if installed(n)]
        if rest:
            _write_shim(rest[0])
        else:
            os.remove(SHIM)
    if not found:
        print("没有发现已安装的 VPS Probe")


def memory_mb(name):
    out = subprocess.run(["systemctl", "show", name, "-p", "MemoryCurrent", "--value"], stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, universal_newlines=True).stdout.strip()
    return int(out) / 1048576 if out.isdigit() else None


def status():
    """两个角色的安装与运行状态"""
    out = {}
    for name in (PANEL, AGENT):
        if installed(name):
            out[name] = {"active": active(name), "env": read_env(paths(name)["env"]), "memory": memory_mb(name)}
    return out

