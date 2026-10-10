"""升级：从 GitHub 下载最新源码，用新代码重新安装已安装的面板 / 子服务器（配置和数据保留，失败自动回滚）"""
import glob
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

from .config import AGENT, PANEL, REPO, VERSION
from .service import installed, paths, read_env, require_root


def fetch(ref="main"):
    """下载并解压源码，返回 (临时目录, 包含 vps_probe 的目录)"""
    url = "https://codeload.github.com/%s/tar.gz/%s" % (REPO, ref)
    with urllib.request.urlopen(url, timeout=60) as r:
        data = r.read()
    tmp = tempfile.mkdtemp(prefix="vps-probe-")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        safe = [m for m in tar.getmembers() if (m.isfile() or m.isdir()) and not m.name.startswith("/")
                and ".." not in m.name.split("/")]
        kw = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
        tar.extractall(tmp, members=safe, **kw)
    found = glob.glob(os.path.join(tmp, "*", "vps_probe", "__init__.py"))
    if not found:
        shutil.rmtree(tmp, ignore_errors=True)
        raise OSError("下载的源码不完整")
    return tmp, os.path.dirname(os.path.dirname(found[0]))


def cmd_upgrade(ref="main"):
    require_root()
    roles = [n for n in (PANEL, AGENT) if installed(n)]
    if not roles:
        sys.exit("没有已安装的 VPS Probe")
    print("正在从 GitHub 下载 %s@%s ..." % (REPO, ref), flush=True)
    try:
        tmp, root = fetch(ref)
    except OSError as e:
        sys.exit("下载失败：%s" % e)
    try:
        with open(os.path.join(root, "vps_probe", "config.py"), encoding="utf-8") as f:
            m = re.search(r'^VERSION = "([^"]+)"', f.read(), re.M)
        print("当前版本 %s，下载的版本 %s" % (VERSION, m.group(1) if m else "未知"), flush=True)
        for name in roles:
            cmd = [sys.executable, "-m", "vps_probe", "install"]
            if name == AGENT:
                env = read_env(paths(AGENT)["env"])
                cmd += ["--agent=" + env.get("PROBE_AGENT", ""), "--token=" + env.get("PROBE_TOKEN", "")]
                if env.get("PROBE_ALLOW_HTTP") == "1":
                    cmd.append("--allow-http")
            r = subprocess.run(cmd, cwd=root, env=dict(os.environ, PYTHONPATH=root))
            if r.returncode:
                sys.exit(r.returncode)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
