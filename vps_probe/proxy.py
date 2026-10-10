"""自动配置 HTTPS 反向代理

已经装了 Nginx 时用 Nginx + Certbot；否则系统软件源里有 Caddy 时（Ubuntu 23.04+、Debian 12+）安装 Caddy
（自动申请和续期证书），没有则安装 Nginx + Certbot。

流程：写入代理配置 → 等待证书签发，在本机通过 HTTPS 自检 → 面板记录域名，子服务器随后自动改用 HTTPS
→ 所有在线子服务器都已改用 HTTPS 后，面板改为只监听 127.0.0.1，外部只能通过 HTTPS 访问。
代理配置或自检失败时会撤销本次修改，面板保持原样。
"""
import os
import re
import shutil
import socket
import ssl
import subprocess
import time

from .config import PANEL
from .service import installed, panel_api, paths, read_env, require_root, systemctl, update_env
from .util import write_atomic

DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$")
MARK = "# 由 VPS Probe 生成，删除请运行：vps-probe proxy --remove"
CADDY_SITE = "/etc/caddy/vps-probe.caddy"
CADDYFILE = "/etc/caddy/Caddyfile"
CADDY_IMPORT = "import vps-probe.caddy"
NGINX_SITE = "/etc/nginx/conf.d/vps-probe.conf"
NGINX_CONF = """{mark}
limit_conn_zone $binary_remote_addr zone=vps_probe_conn:10m;
server {{
    listen 80;
{listen6}    server_name {domain};
    client_max_body_size 300k;
    location / {{
        limit_conn vps_probe_conn 32;
        proxy_pass http://127.0.0.1:{port};
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
    }}
}}
"""


class ProxyError(Exception):
    pass


def _say(msg):
    print(msg, flush=True)


def _run(cmd, **kw):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, **kw)


def _tail(text, n=12):
    return "\n".join(text.strip().splitlines()[-n:])


def _pkg_install(*pkgs):
    """安装软件包；失败时抛出 ProxyError，附上包管理器的输出"""
    if shutil.which("apt-get"):
        env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
        _run(["apt-get", "update", "-qq"], env=env)
        r = _run(["apt-get", "install", "-y", "-qq"] + list(pkgs), env=env)
    elif shutil.which("dnf") or shutil.which("yum"):
        r = _run([shutil.which("dnf") or shutil.which("yum"), "install", "-y"] + list(pkgs))
    else:
        raise ProxyError("找不到包管理器，请手动安装 %s" % " ".join(pkgs))
    if r.returncode != 0:
        raise ProxyError("安装 %s 失败：\n%s" % (" ".join(pkgs), _tail(r.stdout)))


def _port_users(port):
    """监听这个端口的进程名"""
    out = _run(["ss", "-Hltnp", "sport = :%d" % port]).stdout if shutil.which("ss") else ""
    return set(re.findall(r'"([^"]+)",pid=', out))


def _caddy_available():
    """已安装，或者系统软件源里有 Caddy"""
    if shutil.which("caddy"):
        return True
    if shutil.which("apt-get"):
        _run(["apt-get", "update", "-qq"])
        m = re.search(r"Candidate:\s*(\S+)", _run(["apt-cache", "policy", "caddy"]).stdout)
        return bool(m) and m.group(1) != "(none)"
    pm = shutil.which("dnf") or shutil.which("yum")
    return bool(pm) and _run([pm, "list", "--available", "caddy"]).returncode == 0


def _choose(pref):
    users = _port_users(80) | _port_users(443)
    others = users - {"nginx", "caddy"}
    if others:
        raise ProxyError("80 / 443 端口已被 %s 占用，无法自动配置反向代理" % "、".join(sorted(others)))
    if pref:
        if users and pref not in users:
            raise ProxyError("80 / 443 端口已被 %s 占用，请改用 --proxy %s" % ("、".join(users), users.pop()))
        if pref == "caddy" and not _caddy_available():
            raise ProxyError("系统软件源里没有 Caddy（如 Ubuntu 22.04），请改用 --proxy nginx，或手动安装 Caddy 后重试")
        return pref
    if users:
        return "nginx" if "nginx" in users else "caddy"
    if shutil.which("nginx") or not _caddy_available():
        return "nginx"
    return "caddy"


def _open_firewall():
    if shutil.which("ufw") and "Status: active" in _run(["ufw", "status"]).stdout:
        _run(["ufw", "allow", "80/tcp"])
        _run(["ufw", "allow", "443/tcp"])
        _say("已在 ufw 防火墙放行 80、443 端口")
    elif shutil.which("firewall-cmd") and _run(["firewall-cmd", "--state"]).returncode == 0:
        _run(["firewall-cmd", "--permanent", "--add-service=http", "--add-service=https"])
        _run(["firewall-cmd", "--reload"])
        _say("已在 firewalld 防火墙放行 80、443 端口")


def _read(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


# ---------------------------------------------------------------- Caddy

def _install_caddy():
    if not shutil.which("caddy"):
        _say("正在安装 Caddy ...")
        _pkg_install("caddy")


def _caddy_setup(domain, port, email):
    _install_caddy()
    write_atomic(CADDY_SITE, ("%s\n%s {\n    reverse_proxy 127.0.0.1:%s\n}\n" % (MARK, domain, port)).encode(), 0o644)
    text = _read(CADDYFILE)
    if CADDY_IMPORT not in text:
        if not text.strip() or "/usr/share/caddy" in text:     # 软件包自带的默认欢迎页，直接替换
            if text and not os.path.exists(CADDYFILE + ".vps-probe.bak"):
                write_atomic(CADDYFILE + ".vps-probe.bak", text.encode(), 0o644)
            text = ""
        write_atomic(CADDYFILE, (text.rstrip("\n") + "\n\n" + CADDY_IMPORT + "\n").lstrip("\n").encode(), 0o644)
    r = _run(["caddy", "validate", "--config", CADDYFILE, "--adapter", "caddyfile"])
    if r.returncode != 0:
        raise ProxyError("Caddy 配置检查失败：\n" + _tail(r.stdout))
    systemctl("enable", "caddy")
    systemctl("reload" if systemctl("is-active", "--quiet", "caddy") else "restart", "caddy")


def _caddy_remove():
    if os.path.exists(CADDY_SITE):
        os.remove(CADDY_SITE)
    text = _read(CADDYFILE)
    if CADDY_IMPORT in text:
        rest = "\n".join(l for l in text.splitlines() if l.strip() != CADDY_IMPORT).strip()
        bak = CADDYFILE + ".vps-probe.bak"
        if not rest and os.path.exists(bak):
            os.replace(bak, CADDYFILE)
        else:
            write_atomic(CADDYFILE, (rest + "\n").encode(), 0o644)
        if systemctl("is-active", "--quiet", "caddy"):
            systemctl("reload", "caddy")


# ---------------------------------------------------------------- Nginx + Certbot

def _nginx_setup(domain, port, email):
    if not shutil.which("nginx"):
        _say("正在安装 Nginx ...")
        _pkg_install("nginx")
    if not shutil.which("certbot") or "nginx" not in _run(["certbot", "plugins"]).stdout:
        _say("正在安装 Certbot ...")
        _pkg_install("certbot", "python3-certbot-nginx")
    listen6 = "    listen [::]:80;\n" if os.path.exists("/proc/net/if_inet6") else ""
    write_atomic(NGINX_SITE, NGINX_CONF.format(mark=MARK, listen6=listen6, domain=domain, port=port).encode(), 0o644)
    r = _run(["nginx", "-t"])
    if r.returncode != 0:
        raise ProxyError("Nginx 配置检查失败：\n" + _tail(r.stdout))
    systemctl("enable", "nginx")
    systemctl("reload" if systemctl("is-active", "--quiet", "nginx") else "restart", "nginx")
    _say("正在通过 Let's Encrypt 申请证书（使用即表示同意其服务条款）...")
    cmd = ["certbot", "--nginx", "-d", domain, "--non-interactive", "--agree-tos", "--keep-until-expiring", "--redirect"]
    cmd += ["-m", email] if email else ["--register-unsafely-without-email"]
    r = _run(cmd)
    if r.returncode != 0:
        raise ProxyError("申请证书失败：\n" + _tail(r.stdout))


def _nginx_remove():
    if os.path.exists(NGINX_SITE):
        os.remove(NGINX_SITE)
        if shutil.which("nginx") and _run(["nginx", "-t"]).returncode == 0:
            systemctl("reload", "nginx")


# ---------------------------------------------------------------- 对外接口

def _https_ok(domain):
    """连本机 443 端口，按域名校验证书后请求 /healthz（不依赖服务器能否访问自己的公网 IP）"""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection(("127.0.0.1", 443), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=domain) as s:
                s.sendall(("GET /healthz HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % domain).encode())
                data = b""
                while len(data) < 65536:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
        return data.startswith(b"HTTP/1.1 200") and data.rstrip().endswith(b"ok")
    except (OSError, ssl.SSLError):
        return False


def _remove_config(kind):
    if kind in (None, "caddy"):
        _caddy_remove()
    if kind in (None, "nginx"):
        _nginx_remove()


def setup(domain, email="", pref=None, lock=True):
    """配置域名和 HTTPS。成功返回 True；失败抛出 ProxyError，面板保持原样"""
    require_root()
    if not installed(PANEL):
        raise ProxyError("请先安装面板")
    domain = (domain or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.match(domain):
        raise ProxyError("域名格式不正确：%s" % domain)
    try:
        addrs = sorted({a[4][0] for a in socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)})
    except socket.gaierror:
        raise ProxyError("域名 %s 无法解析，请先把它解析到这台服务器的公网 IP" % domain)
    env = read_env(paths(PANEL)["env"])
    port = env.get("PROBE_PORT") or "8899"
    kind = _choose(pref)
    expected = [n["id"] for n in _remote_nodes(env) if n["online"]]     # 面板重启前在线的子服务器
    _say("域名 %s 解析到 %s，使用 %s 作为反向代理" % (domain, "、".join(addrs), "Caddy" if kind == "caddy" else "Nginx"))
    if env.get("PROBE_PROXY") and env["PROBE_PROXY"] != kind:
        _remove_config(env["PROBE_PROXY"])
    _open_firewall()
    was_running = systemctl("is-active", "--quiet", kind)
    try:
        (_caddy_setup if kind == "caddy" else _nginx_setup)(domain, port, email)
        _say("等待证书签发并检查 HTTPS 访问（最多 2 分钟）...")
        deadline = time.monotonic() + 120
        while not _https_ok(domain):
            if time.monotonic() > deadline:
                hint = _tail(_run(["journalctl", "-u", "caddy", "-n", "15", "-o", "cat", "--no-pager"]).stdout) \
                    if kind == "caddy" else ""
                raise ProxyError("HTTPS 检查没有通过。请确认域名已解析到本机公网 IP，且云厂商安全组放行了 80、443 端口。\n" + hint)
            time.sleep(3)
    except Exception:
        _remove_config(kind)
        if not was_running:             # 本次才启动的代理服务，失败后停掉，不占用 80 / 443 端口
            systemctl("disable", "--now", kind)
        raise
    # 面板记录域名：子服务器会在下一次上报时收到 HTTPS 地址并自动切换
    if not update_env(PANEL, {"PROBE_DOMAIN": domain, "PROBE_PROXY": kind, "PROBE_TRUST_PROXY": "1"}):
        _remove_config(kind)
        raise ProxyError("面板重启失败，已撤销反向代理配置")
    _say("\033[32m✔ HTTPS 已启用：https://%s\033[0m" % domain)
    if lock:
        lock_http(expected=expected)
    return True


def _remote_nodes(env):
    try:
        return [n for n in panel_api(env, "/api/nodes")["nodes"] if not n["local"]]
    except (OSError, ValueError, KeyError):
        return []


def lock_http(wait=90, expected=None):
    """expected（默认为当前在线的）子服务器都改用 HTTPS 后，让面板只监听 127.0.0.1。返回是否已锁定"""
    require_root()
    env = read_env(paths(PANEL)["env"])
    if not env.get("PROBE_DOMAIN"):
        raise ProxyError("还没有配置域名和 HTTPS")
    if env.get("PROBE_HOST") == "127.0.0.1":
        _say("面板已经只监听本机，外部只能通过 https://%s 访问" % env["PROBE_DOMAIN"])
        return True
    deadline = time.monotonic() + wait
    while True:
        nodes = _remote_nodes(env)
        if expected is None:
            expected = [n["id"] for n in nodes if n["online"]]
        by_id = {n["id"]: n for n in nodes}
        # 面板刚重启时子服务器会短暂显示离线，要等它们重新连上并改用 HTTPS
        pending = [by_id[i]["name"] for i in expected if i in by_id and not (by_id[i]["online"] and by_id[i].get("secure"))]
        if not pending or time.monotonic() > deadline:
            break
        _say("等待 %d 台子服务器改用 HTTPS ..." % len(pending))
        time.sleep(5)
    if pending:
        _say("\033[33m以下子服务器仍在通过 HTTP 上报（可能是 1.4 以前的版本）：%s\033[0m\n"
             "在这些服务器上升级（运行 vps-probe 选择升级，或重新执行面板上的安装命令）后，"
             "再运行 vps-probe proxy --lock 关闭面板的 HTTP 端口。" % "、".join(pending))
        return False
    if not update_env(PANEL, {"PROBE_HOST": "127.0.0.1"}):
        raise ProxyError("面板重启失败，已恢复原配置")
    _say("\033[32m✔ 面板已改为只监听 127.0.0.1，外部只能通过 https://%s 访问\033[0m" % env["PROBE_DOMAIN"])
    offline = [n["name"] for n in nodes if n["id"] not in expected and n.get("reported")]
    if offline:
        _say("\033[33m离线的子服务器（%s）恢复后无法再通过 HTTP 连接，需要在面板上重新执行它们的安装命令。\033[0m"
             % "、".join(offline))
    return True


def remove():
    """撤销反向代理：面板恢复监听所有地址，删除代理配置（证书和代理软件保留）"""
    require_root()
    env = read_env(paths(PANEL)["env"]) if installed(PANEL) else {}
    if env.get("PROBE_DOMAIN") or env.get("PROBE_PROXY") or env.get("PROBE_HOST") == "127.0.0.1":
        update_env(PANEL, {"PROBE_DOMAIN": None, "PROBE_PROXY": None, "PROBE_TRUST_PROXY": None, "PROBE_HOST": "0.0.0.0"})
    _remove_config(env.get("PROBE_PROXY"))
    _say("已撤销反向代理，面板恢复为 http://服务器IP:%s；已改用 HTTPS 的子服务器连续失败后会自动改回原地址"
         % (env.get("PROBE_PORT") or 8899))


def cleanup():
    """卸载面板时删除反向代理配置"""
    _remove_config(read_env(paths(PANEL)["env"]).get("PROBE_PROXY"))
