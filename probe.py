#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPS Probe 1.3.0 —— 轻量级 Linux 服务器探针：单文件、零依赖，自带 Web 面板，支持多台服务器
https://github.com/zhushili/vps-probe

  sudo python3 probe.py install [--port 8899 --password xxx]   安装 / 升级面板
  sudo python3 probe.py install --agent=URL --token=XXXX       安装子服务器（命令由面板生成）
  sudo python3 probe.py uninstall                              卸载
  python3 probe.py [--port 8899 --user admin --password xxx]   不安装，直接前台运行
"""
import argparse
import base64
import fnmatch
import gzip
import hashlib
import hmac
import http.client
import json
import math
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import zlib
from array import array
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


# ==============================================================================
# 公共常量与工具函数
# ==============================================================================

VERSION = "1.3.0"
REPO = "zhushili/vps-probe"


def env_num(name, default, conv=int):
    try:
        return conv(os.environ.get(name) or default)
    except ValueError:
        return default


LIVE_SPAN = 600                 # 实时视图：最近 10 分钟
DAY_SPAN = 86400                # 24 小时视图
DAY_POINTS = 1440               # 24 小时视图每分钟 1 个点
ACTIVE_WINDOW = 30              # 最近 30 秒内有人在看详情，才扫描进程列表
MAX_NODES = 200                 # 面板最多管理的服务器数（含本机），容量实测见 docs/guide.md
MAX_REPORT = 256 * 1024         # 子服务器单次上报的最大体积（压缩后）
SAVE_EVERY = 300               # 24 小时历史写盘间隔（秒）
TRAFFIC_SAVE_EVERY = 60        # 流量统计写盘间隔（秒）

TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
NODE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")

# 历史数据点的字段顺序：时间戳 + 10 个指标
FIELDS = ("t", "cpu", "steal", "iowait", "mem", "cache", "swap", "rx", "tx", "rd", "wr")


def log(msg):
    print(time.strftime("[%Y-%m-%d %H:%M:%S] ") + msg, file=sys.stderr, flush=True)


def read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


# ---------------------------------------------------------------- 可靠的文件读写

class CorruptFile(Exception):
    pass


def load_json(path):
    """文件不存在返回 None；存在但读取或解析失败抛出 CorruptFile"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        raise CorruptFile(str(e))


def load_json_safe(path, what):
    """读取重要的 JSON 文件，返回 (数据, 警告)。主文件损坏时改名保留，再尝试 .bak 备份"""
    try:
        return load_json(path), None
    except CorruptFile as e:
        bad = "%s.corrupt-%s" % (path, time.strftime("%Y%m%d-%H%M%S"))
        try:
            os.replace(path, bad)
        except OSError:
            bad = path
        try:
            data = load_json(path + ".bak")
        except CorruptFile:
            data = None
        if data is not None:
            msg = "%s 已损坏（%s），已从备份恢复，原文件另存为 %s" % (what, e, bad)
        else:
            msg = "%s 已损坏（%s）且没有可用备份，已按空数据启动，原文件另存为 %s" % (what, e, bad)
        log("警告：" + msg)
        return data, msg


def _fsync_dir(d):
    try:
        fd = os.open(d, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def write_atomic(path, data, mode=0o600):
    """原子写入：同目录唯一临时文件 → fsync → 替换，任何时刻目标文件都是完整的旧版或新版"""
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=os.path.basename(path) + ".", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    _fsync_dir(d)


def save_json(path, obj, backup=False):
    """原子保存 JSON。backup=True 时先把当前（可正常解析的）版本复制为 .bak"""
    data = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if backup and os.path.exists(path):
        try:
            load_json(path)
            with open(path, "rb") as f:
                write_atomic(path + ".bak", f.read())
        except (CorruptFile, OSError):
            pass
    write_atomic(path, data)


# ---------------------------------------------------------------- 定时任务

def run_loop(interval, tick, stop):
    """按固定节拍执行 tick，直到 stop 被设置"""
    next_t = time.monotonic()
    while True:
        next_t += interval
        if stop.wait(max(0.0, next_t - time.monotonic())):
            break
        try:
            tick()
        except Exception as e:  # 采样线程永远不能挂
            log("采样失败: %r" % e)
        now = time.monotonic()
        if now > next_t + interval:   # 系统卡顿落后太多时重新对齐节拍
            next_t = now


def run_every(seconds, fn, stop):
    """每隔 seconds 秒执行一次 fn（独立线程里调用，不影响采样节拍）"""
    while not stop.wait(seconds):
        try:
            fn()
        except Exception as e:
            log("后台任务失败: %r" % e)


# ==============================================================================
# 系统指标读取：直接解析 /proc 与 /sys，不依赖任何第三方库
# ==============================================================================

# 默认不计入流量的虚拟网卡（前缀匹配），避免容器 / 隧道流量被重复统计
NET_SKIP = ("lo", "docker", "veth", "br-", "virbr", "vnet", "cni", "flannel", "cali", "kube",
            "tun", "tap", "wg", "tailscale", "zt", "lxc", "dummy", "ifb", "sit", "gre", "ipip", "ip6tnl")

# 不展示的文件系统类型与挂载点
FS_SKIP = {"proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup", "cgroup2", "securityfs", "pstore",
           "debugfs", "tracefs", "configfs", "fusectl", "mqueue", "hugetlbfs", "bpf", "autofs",
           "binfmt_misc", "squashfs", "nsfs", "ramfs", "efivarfs", "rpc_pipefs", "selinuxfs", "rootfs",
           "fuse.lxcfs", "fuse.snapfuse", "fuse.gvfsd-fuse", "iso9660", "overlay", "aufs", "nfsd"}
MOUNT_SKIP = ("/snap/", "/var/snap/", "/var/lib/docker/", "/var/lib/containers/",
              "/run/", "/sys/", "/proc/", "/dev/")

VIRT_NAMES = {"kvm": "KVM", "qemu": "QEMU", "vmware": "VMware", "microsoft": "Hyper-V", "xen": "Xen",
              "oracle": "VirtualBox", "amazon": "AWS Nitro", "bochs": "Bochs", "parallels": "Parallels",
              "openvz": "OpenVZ", "lxc": "LXC", "lxc-libvirt": "LXC", "docker": "Docker",
              "podman": "Podman", "systemd-nspawn": "nspawn", "wsl": "WSL", "none": "物理机"}

MAX_CORES = 4096


def detect_virt():
    try:
        out = subprocess.run(["systemd-detect-virt"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             universal_newlines=True, timeout=3).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        out = ""
    if not out:
        if os.path.exists("/proc/vz") and not os.path.exists("/proc/bc"):
            out = "openvz"
        elif os.path.exists("/.dockerenv"):
            out = "docker"
    return VIRT_NAMES.get(out, out or "未知")


def host_info():
    uname = platform.uname()
    os_name = ""
    for line in read_text("/etc/os-release").splitlines():
        if line.startswith("PRETTY_NAME="):
            os_name = line.split("=", 1)[1].strip().strip('"')
    model = ""
    for line in read_text("/proc/cpuinfo").splitlines():
        key, _, val = line.partition(":")
        if key.strip() in ("model name", "Model", "Hardware", "cpu model") and val.strip():
            model = " ".join(val.split())
            break
    cores = sum(1 for l in read_text("/proc/stat").splitlines() if l.startswith("cpu") and l[3:4].isdigit())
    return {
        "hostname": socket.gethostname(),
        "os": os_name or "%s %s" % (uname.system, uname.release),
        "kernel": uname.release,
        "arch": uname.machine,
        "cpu_model": model or uname.processor or "未知",
        "cores": cores or os.cpu_count() or 1,
        "virt": detect_virt(),
        "python": platform.python_version(),
        "version": VERSION,
    }


def read_cpu_times():
    """{"cpu": [...], "cpu0": [...]}，每项为 user nice system idle iowait irq softirq steal"""
    res = {}
    for line in read_text("/proc/stat").splitlines():
        if not line.startswith("cpu"):
            break
        parts = line.split()
        vals = [int(x) for x in parts[1:9]]
        res[parts[0]] = vals + [0] * (8 - len(vals))
        if len(res) > MAX_CORES:
            break
    return res


def cpu_usage(prev, cur):
    zero = {"pct": 0.0, "user": 0.0, "system": 0.0, "iowait": 0.0, "steal": 0.0}
    if not prev or not cur:
        return zero
    d = [max(0, b - a) for a, b in zip(prev, cur)]
    total = sum(d)
    if total <= 0:
        return zero
    user, nice, system, idle, iowait, irq, softirq, steal = d
    k = 100.0 / total
    return {
        "pct": round((total - idle - iowait) * k, 1),
        "user": round((user + nice) * k, 1),
        "system": round((system + irq + softirq) * k, 1),
        "iowait": round(iowait * k, 1),
        "steal": round(steal * k, 1),
    }


def read_memory():
    m = {}
    for line in read_text("/proc/meminfo").splitlines():
        key, _, val = line.partition(":")
        parts = val.split()
        if parts and parts[0].isdigit():
            m[key] = int(parts[0]) * 1024
    total = m.get("MemTotal", 0)
    avail = m.get("MemAvailable")
    if avail is None:
        avail = m.get("MemFree", 0) + m.get("Buffers", 0) + m.get("Cached", 0)
    swap_total = m.get("SwapTotal", 0)
    return {
        "total": total,
        "used": max(0, total - avail),
        "available": avail,
        "cache": m.get("Buffers", 0) + m.get("Cached", 0) + m.get("SReclaimable", 0),
        "swap_total": swap_total,
        "swap_used": max(0, swap_total - m.get("SwapFree", 0)),
    }


def _unescape_mount(s):
    # /proc/mounts 中空格、制表符等被转义成 \040 这种八进制形式
    return s.replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\")


def read_disks():
    entries = []
    for line in read_text("/proc/mounts").splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        dev, mnt, fs = parts[0], _unescape_mount(parts[1]), parts[2]
        if fs == "rootfs":
            continue
        if mnt != "/":
            if fs in FS_SKIP or mnt.startswith(MOUNT_SKIP) or mnt in ("/run", "/sys", "/proc", "/dev"):
                continue
            if not (dev.startswith("/") or fs in ("zfs", "btrfs", "nfs", "nfs4", "cifs", "fuse.sshfs")):
                continue
        entries.append((dev, mnt, fs))
    # 同一设备可能被 bind mount 到多处，只保留路径最短的那个
    entries.sort(key=lambda e: len(e[1]))
    seen, disks = set(), []
    for dev, mnt, fs in entries:
        if dev in seen or mnt in seen or len(disks) >= 64:
            continue
        try:
            st = os.statvfs(mnt)
        except OSError:
            continue
        total = st.f_blocks * st.f_frsize
        if total <= 0:
            continue
        seen.update((dev, mnt))
        free = st.f_bavail * st.f_frsize
        used = (st.f_blocks - st.f_bfree) * st.f_frsize
        disks.append({
            "mount": mnt, "device": dev, "fs": fs, "total": total, "used": used, "free": free,
            "pct": min(100.0, round(used * 100.0 / (used + free), 1)) if used + free else 0.0,
        })
    return disks


def whole_disks():
    """整块物理/虚拟磁盘（/sys/block/X/device 存在）。不含分区、loop、dm 等，避免 IO 重复计数"""
    try:
        names = os.listdir("/sys/block")
    except OSError:
        return set()
    return {n for n in names if not n.startswith(("loop", "ram", "zram", "sr", "fd"))
            and os.path.exists("/sys/block/%s/device" % n)}


def read_disk_io(disks):
    rd = wr = 0
    for line in read_text("/proc/diskstats").splitlines():
        p = line.split()
        if len(p) >= 10 and p[2].replace("/", "!") in disks:
            rd += int(p[5]) * 512
            wr += int(p[9]) * 512
    return rd, wr


def make_iface_filter(include="", exclude=""):
    """返回 (判断网卡是否计入流量的函数, 统计口径说明)。include 支持通配符，非空时只统计匹配的网卡"""
    inc = [p for p in (include or "").replace(",", " ").split() if p]
    exc = [p for p in (exclude or "").replace(",", " ").split() if p]

    def accept(name):
        if inc:
            return any(fnmatch.fnmatchcase(name, p) for p in inc)
        if any(fnmatch.fnmatchcase(name, p) for p in exc):
            return False
        return not name.startswith(NET_SKIP)

    if inc:
        rule = "只统计网卡 " + "、".join(inc)
    else:
        rule = "统计所有物理网卡（自动排除 lo、docker、veth、tun、wg 等虚拟网卡%s）" % (
            "，另外排除 " + "、".join(exc) if exc else "")
    return accept, rule


def read_net(accept):
    res = {}
    for line in read_text("/proc/net/dev").splitlines()[2:]:
        name, sep, data = line.partition(":")
        name = name.strip()
        if not sep or not accept(name):
            continue
        f = data.split()
        if len(f) >= 9:
            res[name] = (int(f[0]), int(f[8]))
        if len(res) >= 256:
            break
    return res


def read_conn():
    """连接数直接读内核汇总值（sockstat / snmp），不逐条遍历连接表，代理机上几万连接也不费 CPU"""
    c = {"tcp": 0, "established": 0, "time_wait": 0, "udp": 0}
    for path in ("/proc/net/sockstat", "/proc/net/sockstat6"):
        for line in read_text(path).splitlines():
            proto, _, rest = line.partition(":")
            f = rest.split()
            kv = dict(zip(f[::2], f[1::2]))
            if proto in ("TCP", "TCP6"):
                c["tcp"] += int(kv.get("inuse", 0))
                c["time_wait"] += int(kv.get("tw", 0))
            elif proto in ("UDP", "UDP6"):
                c["udp"] += int(kv.get("inuse", 0))
    c["tcp"] += c["time_wait"]
    lines = read_text("/proc/net/snmp").splitlines()
    for head, vals in zip(lines, lines[1:]):
        if head.startswith("Tcp:") and vals.startswith("Tcp:"):
            c["established"] = int(dict(zip(head.split(), vals.split())).get("CurrEstab", 0))
            break
    return c


def list_pids():
    try:
        return [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return []


def cycle_start(today, reset_day):
    """流量统计周期的起始日期，例如重置日为 15 号、今天 10-03，则周期从 09-15 开始"""
    if today.day >= reset_day:
        return today.replace(day=reset_day)
    year, month = (today.year, today.month - 1) if today.month > 1 else (today.year - 1, 12)
    return date(year, month, reset_day)


# ==============================================================================
# 本机采集器：定时采样，计算各项速率与月流量
#
# 流量统计（traffic.json）的恢复边界：
#   * 每 TRAFFIC_SAVE_EVERY 秒和每次统计周期切换时写盘；断电时最多丢失最近一个间隔内的增量
#   * 同一次开机内重启探针：从保存的网卡计数器接着算，停机期间的流量不会丢
#   * 系统重启后网卡计数器归零，只能把开机以来的流量算作新增，上次保存之后、关机之前的部分无法找回
#   * 停机跨越统计周期时，恢复的整段增量会计入新周期
#   因此这里的流量只供参考，不等同于服务商的计费数据。
# ==============================================================================

CLK_TCK = os.sysconf("SC_CLK_TCK")
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
PAST_CYCLES = 12                # 保留最近 12 个统计周期的流量


class Collector:
    def __init__(self, interval, data_dir, reset_day, ifaces="", ifaces_exclude=""):
        self.interval = interval
        self.data_dir = data_dir
        self.reset_day = reset_day
        self.lock = threading.Lock()
        self.info = host_info()
        self.boot_id = read_text("/proc/sys/kernel/random/boot_id").strip()
        self.started = int(time.time())
        self.accept_iface, self.iface_rule = make_iface_filter(ifaces, ifaces_exclude)
        self.want_procs_until = 0.0   # 在这个时间之前需要扫描进程列表
        self.warnings = []
        self.traffic = {"cycle": "", "rx": 0, "tx": 0, "past": []}
        self.prev_mono = None
        self.prev_cpu = {}
        self.prev_io = None
        self.disks, self.disks_at = set(), -1e9
        self.net_prev = {}
        self.net_default = None       # 系统重启后首次采样时，网卡计数器的基准值
        self.proc_prev = {}
        self.proc_prev_t = None
        self._load()

    # ---- 流量统计持久化 ----
    def _path(self):
        return os.path.join(self.data_dir, "traffic.json") if self.data_dir else None

    def _load(self):
        if not self._path():
            return
        st, warn = load_json_safe(self._path(), "流量统计 traffic.json")
        if warn:
            self.warnings.append(warn)
        if not isinstance(st, dict):
            return
        tr = st.get("traffic")
        try:
            if isinstance(tr, dict):
                past = [{"cycle": str(p.get("cycle", "")), "rx": max(0, int(p.get("rx", 0))),
                         "tx": max(0, int(p.get("tx", 0)))} for p in tr.get("past") or [] if isinstance(p, dict)]
                self.traffic = {"cycle": str(tr.get("cycle", "")), "rx": max(0, int(tr.get("rx", 0))),
                                "tx": max(0, int(tr.get("tx", 0))), "past": past[-PAST_CYCLES:]}
            counters = {str(k): (int(v[0]), int(v[1])) for k, v in (st.get("counters") or {}).items()}
        except (TypeError, ValueError, IndexError, AttributeError):
            self.warnings.append("流量统计 traffic.json 格式异常，已重新开始统计")
            return
        if st.get("boot_id") and st.get("boot_id") == self.boot_id:
            self.net_prev = counters      # 同一次开机内重启探针：从上次保存的计数器接着算
        elif st.get("boot_id"):
            self.net_default = (0, 0)     # 系统重启过：网卡计数器从 0 开始，开机以来的流量都属于新增

    def save(self):
        path = self._path()
        if not path:
            return
        with self.lock:
            st = {"version": 3, "boot_id": self.boot_id, "saved": int(time.time()),
                  "traffic": {k: (list(v) if k == "past" else v) for k, v in self.traffic.items()},
                  "counters": {k: list(v) for k, v in self.net_prev.items()}}
        try:
            save_json(path, st, backup=True)
        except (OSError, ValueError) as e:
            log("保存流量数据失败: %s" % e)

    # ---- 采样 ----
    def sample(self):
        """采样一次，返回 (快照, 是否有效)。第一次采样没有速率数据，返回 False"""
        now, mono = time.time(), time.monotonic()
        dt = mono - self.prev_mono if self.prev_mono else 0.0
        warm = dt > 0

        cpus = read_cpu_times()
        cpu = cpu_usage(self.prev_cpu.get("cpu"), cpus.get("cpu"))
        cpu["cores"] = [cpu_usage(self.prev_cpu.get(k), v)["pct"] for k, v in cpus.items() if k != "cpu"]
        la = read_text("/proc/loadavg").split()
        cpu["load"] = [float(x) for x in la[:3]] if len(la) >= 3 else [0.0, 0.0, 0.0]
        self.prev_cpu = cpus

        if mono - self.disks_at > 60:    # 磁盘列表很少变化，每分钟刷新一次
            self.disks, self.disks_at = whole_disks(), mono
        rd, wr = read_disk_io(self.disks)
        io = {"read": 0, "write": 0, "read_total": rd, "write_total": wr}
        if warm and self.prev_io:
            io["read"] = int(max(0, rd - self.prev_io[0]) / dt)
            io["write"] = int(max(0, wr - self.prev_io[1]) / dt)
        self.prev_io = (rd, wr)

        counters = read_net(self.accept_iface)
        ifaces, add_rx, add_tx = [], 0, 0
        for name, (rx, tx) in sorted(counters.items()):
            prev = self.net_prev.get(name, self.net_default)
            drx = dtx = 0
            if prev is not None:
                drx = rx - prev[0] if rx >= prev[0] else rx    # 计数器归零（网卡重建）时从 0 算起
                dtx = tx - prev[1] if tx >= prev[1] else tx
                add_rx += drx
                add_tx += dtx
            ifaces.append({"name": name, "rx_total": rx, "tx_total": tx,
                           "rx": int(drx / dt) if warm else 0, "tx": int(dtx / dt) if warm else 0})

        pids = list_pids()
        threads = int(la[3].split("/")[1]) if len(la) >= 4 and "/" in la[3] else 0
        proc = {"count": len(pids), "threads": threads}
        if now < self.want_procs_until:
            proc["running"], proc["top_cpu"], proc["top_mem"] = self._scan_processes(pids, mono)
        else:
            self.proc_prev, self.proc_prev_t = {}, None

        uptime = read_text("/proc/uptime").split()
        statm = read_text("/proc/self/statm").split()
        snapshot = {
            "ts": round(now, 3),
            "uptime": int(float(uptime[0])) if uptime else 0,
            "info": self.info,
            "cpu": cpu,
            "mem": read_memory(),
            "disks": read_disks(),
            "io": io,
            "net": {"rx": sum(i["rx"] for i in ifaces), "tx": sum(i["tx"] for i in ifaces), "ifaces": ifaces,
                    "rx_total": sum(c[0] for c in counters.values()),
                    "tx_total": sum(c[1] for c in counters.values()), "iface_rule": self.iface_rule},
            "conn": read_conn(),
            "proc": proc,
            "probe": {"rss": int(statm[1]) * PAGE_SIZE if len(statm) > 1 else 0,
                      "interval": self.interval, "started": self.started},
        }
        with self.lock:
            cycle = cycle_start(date.today(), self.reset_day).isoformat()
            changed = self.traffic.get("cycle") != cycle
            if changed:
                past = self.traffic.get("past", [])
                if self.traffic.get("cycle"):
                    past = (past + [{k: self.traffic[k] for k in ("cycle", "rx", "tx")}])[-PAST_CYCLES:]
                self.traffic = {"cycle": cycle, "rx": 0, "tx": 0, "past": past}
            self.traffic["rx"] += add_rx
            self.traffic["tx"] += add_tx
            self.net_prev, self.net_default = counters, None
            past = self.traffic["past"]
            snapshot["net"].update(cycle_start=cycle, cycle_rx=self.traffic["rx"], cycle_tx=self.traffic["tx"])
            if past:
                snapshot["net"]["prev_cycle"] = dict(past[-1])
        if changed and self.prev_mono is not None:
            self.save()                   # 周期切换时立即保存检查点
        self.prev_mono = mono
        return snapshot, warm

    def _scan_processes(self, pids, mono):
        dt = mono - self.proc_prev_t if self.proc_prev_t else 0.0
        cur, rows, running = {}, [], 0
        for pid in pids:
            s = read_text("/proc/%s/stat" % pid)
            r = s.rfind(")")
            if r < 0:
                continue
            f = s[r + 2:].split()
            if len(f) < 22:
                continue
            ticks = int(f[11]) + int(f[12])
            cur[pid] = ticks
            prev = self.proc_prev.get(pid)
            cpu = max(0.0, (ticks - prev) * 100.0 / CLK_TCK / dt) if prev is not None and dt > 0 else 0.0
            if f[0] == "R":
                running += 1
            rows.append((pid, s[s.find("(") + 1:r], cpu, int(f[21]) * PAGE_SIZE, int(f[17])))
        self.proc_prev, self.proc_prev_t = cur, mono

        def fmt(row):
            pid, name, cpu, rss, threads = row
            cmd = read_text("/proc/%s/cmdline" % pid).replace("\0", " ").strip()
            return {"pid": int(pid), "name": name[:64], "cmd": cmd[:200], "cpu": round(cpu, 1),
                    "rss": rss, "threads": threads}

        top_cpu = sorted(rows, key=lambda x: (x[2], x[3]), reverse=True)[:8]
        top_mem = sorted(rows, key=lambda x: x[3], reverse=True)[:8]
        return running, [fmt(x) for x in top_cpu], [fmt(x) for x in top_mem]


# ==============================================================================
# 面板数据：服务器列表（nodes.json）与每台服务器的实时 / 24 小时历史（history/<id>.bin）
#
# * 服务器列表的修改与写盘串行执行；写盘失败时撤销内存中的修改并报错
# * 历史数据用定长环形缓冲保存，按时间窗口淘汰，内存不随运行时间增长
# * 24 小时历史按服务器分文件追加写入新增的点，写盘量和峰值内存都与服务器数量线性相关且很小
# ==============================================================================

W = len(FIELDS) - 1                 # 每个点的指标个数
ROW = struct.Struct("<d%df" % W)    # 历史文件每条记录：时间戳 double + 指标 float32，共 48 字节


class StoreError(Exception):
    """配置写盘失败"""


def new_token():
    """随机 token；不以 "-" 开头，避免在命令行里被当成参数名"""
    while True:
        t = secrets.token_urlsafe(24)
        if not t.startswith("-"):
            return t


class Series:
    """定长环形缓冲：时间戳（double）+ 指标（float32），按时间窗口淘汰，内存固定"""

    def __init__(self, cap, span):
        self.cap, self.span = cap, span
        self.t = array("d", bytes(8 * cap))
        self.v = array("f", bytes(4 * cap * W))
        self.head = self.n = 0

    def __len__(self):
        return self.n

    def last(self):
        return self.t[(self.head + self.n - 1) % self.cap] if self.n else 0.0

    def append(self, t, vals):
        if self.n and t <= self.last():
            return                  # 只接受时间递增的点
        if self.n == self.cap:
            i = self.head
            self.head = (self.head + 1) % self.cap
        else:
            i = (self.head + self.n) % self.cap
            self.n += 1
        self.t[i] = t
        self.v[i * W:(i + 1) * W] = array("f", vals)

    def evict(self, now):
        cutoff = now - self.span
        while self.n and self.t[self.head] < cutoff:
            self.head = (self.head + 1) % self.cap
            self.n -= 1

    def points(self, since=0.0):
        """按时间顺序返回 [(t, 指标数组), ...]，只含 t > since 的点"""
        out = []
        for k in range(self.n):
            i = (self.head + k) % self.cap
            if self.t[i] > since:
                out.append((self.t[i], self.v[i * W:(i + 1) * W]))
        return out

    def columns(self, now):
        """按字段分列输出（API 用）：CPU 类保留 1 位小数，其余取整"""
        self.evict(now)
        cols = [[] for _ in FIELDS]
        for t, vals in self.points():
            cols[0].append(int(t))
            for j, x in enumerate(vals):
                cols[j + 1].append(round(x, 1) if j < 3 else int(x))
        return cols


class Node:
    """面板上的一台服务器"""

    def __init__(self, nid, name, token="", reset_day=1, created=0, local=False):
        self.id, self.name, self.token = nid, name, token
        self.reset_day, self.created, self.local = reset_day, created, local
        self.prev_token, self.prev_until = "", 0.0   # 更换 token 后的过渡期
        self.lock = threading.Lock()
        self.live = Series(LIVE_SPAN + 2, LIVE_SPAN)      # 采样间隔最短 1 秒
        self.day = Series(DAY_POINTS + 10, DAY_SPAN)
        self.minute = None            # 当前分钟的累加器 [bucket, count, sums]
        self.saved_upto = 0.0         # 已写入历史文件的最后一个点
        self.snapshot = None
        self.info = None
        self.interval = 2
        self.last_seen = 0.0
        self.last_view = 0.0
        self.last_report = 0.0

    def config(self):
        c = {"id": self.id, "name": self.name, "reset_day": self.reset_day}
        if not self.local:
            c.update(token=self.token, created=self.created)
            if self.prev_token and self.prev_until > time.time():
                c.update(prev_token=self.prev_token, prev_until=int(self.prev_until))
        return c

    def check_token(self, token):
        t = token.encode("utf-8", "replace")
        if self.token and hmac.compare_digest(self.token.encode("utf-8"), t):
            return True
        return bool(self.prev_token) and time.time() < self.prev_until and \
            hmac.compare_digest(self.prev_token.encode("utf-8"), t)

    def online(self):
        return self.snapshot is not None and time.time() - self.last_seen < self.interval * 3 + 10

    def meta(self):
        return {"id": self.id, "name": self.name, "local": self.local, "online": self.online(),
                "last_seen": int(self.last_seen), "reset_day": self.reset_day,
                "token_grace_until": int(self.prev_until) if self.prev_token and self.prev_until > time.time() else 0}

    def ingest(self, snap, warm=True):
        now = time.time()
        cpu, mem, io, net = snap["cpu"], snap["mem"], snap["io"], snap["net"]
        vals = (cpu["pct"], cpu["steal"], cpu["iowait"], mem["used"], mem["cache"], mem["swap_used"],
                net["rx"], net["tx"], io["read"], io["write"])
        with self.lock:
            if snap.get("info"):
                self.info = snap["info"]
            snap["info"] = self.info
            snap["ts"] = round(now, 3)    # 统一用面板的时钟，避免各服务器时间不一致
            self.snapshot = snap
            self.interval = min(60, max(1, snap["probe"].get("interval") or 2))
            self.last_seen = now
            if warm:
                self.live.append(now, vals)
                self.live.evict(now)
                self._aggregate(now, vals)

    def _aggregate(self, now, vals):
        """把实时点聚合成每分钟一个点；异常的分钟数据直接丢弃，不影响后续聚合"""
        bucket = int(now) // 60
        acc = self.minute
        if acc and acc[0] != bucket:
            avg = [s / acc[1] for s in acc[2]]
            if all(math.isfinite(x) for x in avg):
                self.day.append(acc[0] * 60, avg)
            self.day.evict(now)
            acc = None
        if acc is None:
            acc = self.minute = [bucket, 0, [0.0] * len(vals)]
        acc[1] += 1
        for i, v in enumerate(vals):
            acc[2][i] += v

    def stats(self):
        with self.lock:
            snap = self.snapshot
        out = dict(snap) if snap and snap.get("info") else {}
        out["node"] = self.meta()
        return out

    def history(self, rng):
        with self.lock:
            cols = (self.day if rng == "day" else self.live).columns(time.time())
        data = dict(zip(FIELDS, cols))
        data["interval"] = 60 if rng == "day" else self.interval
        return data

    def summary(self):
        """总览页卡片需要的精简数据"""
        with self.lock:
            s, info = self.snapshot, self.info
        d = {"id": self.id, "name": self.name, "local": self.local, "online": self.online(),
             "last_seen": int(self.last_seen), "reported": bool(s and info)}
        if not d["reported"]:
            return d
        disks, net = s["disks"], s["net"]
        root = next((x for x in disks if x["mount"] == "/"), disks[0] if disks else None)
        d.update(info={k: info.get(k) for k in ("hostname", "os", "virt", "arch", "cores")},
                 uptime=s["uptime"], cpu=s["cpu"]["pct"], load=(s["cpu"]["load"] or [0])[0],
                 mem=[s["mem"]["used"], s["mem"]["total"]],
                 disk=[root["used"], root["total"], root["pct"]] if root else None,
                 rx=net["rx"], tx=net["tx"], cycle=[net.get("cycle_rx", 0), net.get("cycle_tx", 0)])
        return d


class Hub:
    """面板模式：管理本机和所有子服务器"""

    def __init__(self, data_dir, local_name, reset_day):
        self.data_dir = data_dir
        self.lock = threading.Lock()          # 保护 self.nodes 字典
        self.commit_lock = threading.Lock()   # 串行化“修改配置 + 写盘”，避免旧快照覆盖新配置
        self.save_lock = threading.Lock()     # 串行化历史写盘
        self.warnings = []
        self.legacy = None
        self.local = Node("local", local_name, reset_day=reset_day, local=True)
        self.local_custom = False             # 本机名称 / 重置日是否在网页上改过
        self.nodes = {"local": self.local}
        if data_dir:
            self._load()

    def _path(self, *parts):
        return os.path.join(self.data_dir, *parts)

    # ---- 加载 ----
    def _load(self):
        items, warn = load_json_safe(self._path("nodes.json"), "服务器列表 nodes.json")
        if warn:
            self.warnings.append(warn)
        for c in items if isinstance(items, list) else []:
            self._load_node(c)
        self._load_history()
        if len(self.nodes) > 1:
            log("已加载 %d 台子服务器" % (len(self.nodes) - 1))

    def _load_node(self, c):
        if not isinstance(c, dict) or not isinstance(c.get("id"), str) or not NODE_ID_RE.match(c["id"]):
            return
        rd = c.get("reset_day")
        rd = rd if isinstance(rd, int) and not isinstance(rd, bool) and 1 <= rd <= 28 else 1
        name = str(c.get("name") or c["id"])[:40]
        if c["id"] == "local":
            self.local.name, self.local.reset_day, self.local_custom = name, rd, True
            return
        token = c.get("token")
        if not isinstance(token, str) or not TOKEN_RE.match(token) or len(self.nodes) >= MAX_NODES:
            return
        node = Node(c["id"], name, token, rd, int(c.get("created") or 0))
        prev = c.get("prev_token")
        if isinstance(prev, str) and TOKEN_RE.match(prev):
            node.prev_token, node.prev_until = prev, float(c.get("prev_until") or 0)
        self.nodes[node.id] = node

    def _load_history(self):
        now = time.time()
        # 兼容 1.2 版的 history.json：读入后在下次保存时转成新格式并删除
        try:
            old = load_json(self._path("history.json"))
        except CorruptFile:
            old = None
        if isinstance(old, dict):
            self.legacy = self._path("history.json")
            for nid, points in (old.get("nodes") or {}).items():
                node = self.nodes.get(nid)
                for p in points if node and isinstance(points, list) else []:
                    if isinstance(p, list) and len(p) == len(FIELDS) and \
                            all(isinstance(x, (int, float)) and math.isfinite(x) for x in p):
                        node.day.append(p[0], p[1:])
        hdir = self._path("history")
        for node in self.nodes.values():
            try:
                with open(os.path.join(hdir, node.id + ".bin"), "rb") as f:
                    data = f.read()
            except OSError:
                continue
            usable = len(data) - len(data) % ROW.size     # 忽略上次中断留下的半条记录
            last = 0.0
            for rec in ROW.iter_unpack(data[:usable]):
                if all(math.isfinite(x) for x in rec):
                    node.day.append(rec[0], rec[1:])
                    last = max(last, rec[0])
            node.saved_upto = last
        for node in self.nodes.values():
            node.day.evict(now)
        try:
            for fn in os.listdir(hdir):     # 清理已删除服务器遗留的历史文件
                if fn.endswith(".bin") and fn[:-4] not in self.nodes:
                    os.remove(os.path.join(hdir, fn))
        except OSError:
            pass

    # ---- 历史写盘 ----
    def save_history(self):
        """只追加上次保存之后的新点；文件超过两天的量时整体重写一次"""
        if not self.data_dir:
            return
        with self.save_lock:
            hdir = self._path("history")
            try:
                os.makedirs(hdir, exist_ok=True)
            except OSError as e:
                log("保存历史数据失败: %s" % e)
                return
            for node in self.all():
                with node.lock:
                    node.day.evict(time.time())
                    pts, upto = node.day.points(node.saved_upto), node.day.last()
                if not pts:
                    continue
                path = os.path.join(hdir, node.id + ".bin")
                try:
                    size = os.path.getsize(path) if os.path.exists(path) else 0
                    if size // ROW.size + len(pts) > 2 * DAY_POINTS:
                        with node.lock:
                            pts = node.day.points()
                        write_atomic(path, b"".join(ROW.pack(t, *v) for t, v in pts), 0o644)
                    else:
                        with open(path, "ab") as f:
                            if size % ROW.size:
                                f.truncate(size - size % ROW.size)
                            f.write(b"".join(ROW.pack(t, *v) for t, v in pts))
                            f.flush()
                            os.fsync(f.fileno())
                    node.saved_upto = upto
                except OSError as e:
                    log("保存「%s」的历史数据失败: %s" % (node.name, e))
            if self.legacy:
                try:
                    os.remove(self.legacy)
                except OSError:
                    pass
                self.legacy = None

    # ---- 配置修改（串行提交） ----
    def _configs(self):
        with self.lock:
            return [n.config() for n in self.nodes.values() if not n.local or self.local_custom]

    def _commit(self, change):
        """串行执行“修改内存中的配置 → 写盘”。写盘失败时撤销修改并抛出 StoreError"""
        with self.commit_lock:
            result, undo = change()
            if self.data_dir:
                try:
                    save_json(self._path("nodes.json"), self._configs(), backup=True)
                except (OSError, ValueError) as e:
                    undo()
                    log("保存服务器列表失败: %s" % e)
                    raise StoreError("保存配置失败：%s" % e)
            return result

    @staticmethod
    def _check(name, reset_day):
        name = name.strip() if isinstance(name, str) else ""
        if not 1 <= len(name) <= 40:
            raise ValueError("名称长度需要在 1-40 个字符之间")
        if isinstance(reset_day, bool) or not isinstance(reset_day, int) or not 1 <= reset_day <= 28:
            raise ValueError("流量重置日需要是 1-28 之间的整数")
        return name

    def add(self, name, reset_day):
        name = self._check(name, reset_day)

        def change():
            with self.lock:
                if len(self.nodes) >= MAX_NODES:
                    raise ValueError("服务器数量已达上限（%d 台）" % MAX_NODES)
                nid = secrets.token_hex(4)
                while nid in self.nodes:
                    nid = secrets.token_hex(4)
                node = Node(nid, name, new_token(), reset_day, int(time.time()))
                self.nodes[nid] = node

            def undo():
                with self.lock:
                    self.nodes.pop(nid, None)
            return node, undo

        node = self._commit(change)
        log("添加服务器：%s (%s)" % (node.name, node.id))
        return node

    def update(self, nid, name, reset_day):
        name = self._check(name, reset_day)

        def change():
            node = self._require(nid, allow_local=True)
            old = (node.name, node.reset_day, self.local_custom)
            node.name, node.reset_day = name, reset_day
            if node.local:
                self.local_custom = True

            def undo():
                node.name, node.reset_day, self.local_custom = old
            return node, undo

        return self._commit(change)

    def rotate(self, nid, grace):
        """更换 token。grace > 0 时旧 token 在这段时间内继续有效，便于平滑切换；0 表示立即作废"""
        try:
            grace = max(0, min(86400, int(grace)))
        except (TypeError, ValueError):
            raise ValueError("过渡时间无效")

        def change():
            node = self._require(nid)
            old = (node.token, node.prev_token, node.prev_until)
            node.prev_token, node.prev_until = (node.token, time.time() + grace) if grace else ("", 0.0)
            node.token = new_token()

            def undo():
                node.token, node.prev_token, node.prev_until = old
            return node, undo

        node = self._commit(change)
        log("更换服务器 token：%s (%s)，旧 token %s" % (node.name, nid, "保留 %d 秒" % grace if grace else "立即作废"))
        return node

    def remove(self, nid):
        def change():
            node = self._require(nid)
            with self.lock:
                del self.nodes[nid]

            def undo():
                with self.lock:
                    self.nodes[nid] = node
            return node, undo

        node = self._commit(change)
        if self.data_dir:
            try:
                os.remove(self._path("history", nid + ".bin"))
            except OSError:
                pass
        log("删除服务器：%s (%s)" % (node.name, nid))

    def _require(self, nid, allow_local=False):
        node = self.get(nid)
        if node is None or (node.local and not allow_local):
            raise LookupError("服务器不存在或不能执行此操作")
        return node

    # ---- 查询 ----
    def all(self):
        with self.lock:
            return list(self.nodes.values())

    def get(self, nid):
        with self.lock:
            return self.nodes.get(nid)

    def by_token(self, token):
        for n in self.all():
            if not n.local and n.check_token(token):
                return n
        return None

    def summaries(self):
        return [n.summary() for n in self.all()]


# ==============================================================================
# 子服务器上报数据的校验：字段白名单 + 类型 + 取值范围
#
# 任何字段类型不对或超出范围，整份上报都会被拒绝（HTTP 422），不会进入聚合。
# 缺少的字段按默认值处理，以兼容不同版本的子服务器。
# ==============================================================================

class Invalid(ValueError):
    pass


class Num:
    def __init__(self, lo, hi):
        self.lo, self.hi = lo, hi


class Str:
    def __init__(self, n=200):
        self.n = n


class Arr:
    def __init__(self, item, n):
        self.item, self.n = item, n


PCT = Num(0, 100)
BYTES = Num(0, 2 ** 62)             # 字节数、累计计数
RATE = Num(0, 2 ** 50)              # 每秒字节数
COUNT = Num(0, 10 ** 9)             # 连接数、进程数等
SECS = Num(0, 2 ** 40)              # 时间戳、秒数
TEXT = Str()

PROC_ROW = {"pid": Num(0, 2 ** 32), "name": Str(64), "cmd": Str(300), "cpu": Num(0, 100 * 4096),
            "rss": BYTES, "threads": COUNT}
REPORT_SCHEMA = {
    "uptime": SECS,
    "info": {"hostname": Str(253), "os": TEXT, "kernel": TEXT, "arch": Str(64), "cpu_model": TEXT,
             "cores": Num(0, 65536), "virt": Str(64), "python": Str(32), "version": Str(32)},
    "cpu": {"pct": PCT, "user": PCT, "system": PCT, "iowait": PCT, "steal": PCT,
            "cores": Arr(PCT, 4096), "load": Arr(Num(0, 10 ** 6), 3)},
    "mem": {"total": BYTES, "used": BYTES, "available": BYTES, "cache": BYTES,
            "swap_total": BYTES, "swap_used": BYTES},
    "disks": Arr({"mount": Str(256), "device": Str(256), "fs": Str(64), "total": BYTES, "used": BYTES,
                  "free": BYTES, "pct": PCT}, 64),
    "io": {"read": RATE, "write": RATE, "read_total": BYTES, "write_total": BYTES},
    "net": {"rx": RATE, "tx": RATE, "rx_total": BYTES, "tx_total": BYTES,
            "cycle_rx": BYTES, "cycle_tx": BYTES, "cycle_start": Str(10), "iface_rule": Str(200),
            "prev_cycle": {"cycle": Str(10), "rx": BYTES, "tx": BYTES},
            "ifaces": Arr({"name": Str(32), "rx": RATE, "tx": RATE, "rx_total": BYTES, "tx_total": BYTES}, 256)},
    "conn": {"tcp": COUNT, "established": COUNT, "time_wait": COUNT, "udp": COUNT},
    "proc": {"count": COUNT, "threads": COUNT, "running": COUNT,
             "top_cpu": Arr(PROC_ROW, 16), "top_mem": Arr(PROC_ROW, 16)},
    "probe": {"rss": BYTES, "interval": Num(1, 60), "started": SECS},
}
OPTIONAL = {"info", "running", "top_cpu", "top_mem", "prev_cycle"}


def default(spec):
    if isinstance(spec, dict):
        return {k: default(s) for k, s in spec.items() if k not in OPTIONAL}
    if isinstance(spec, Arr):
        return []
    if isinstance(spec, Str):
        return ""
    return spec.lo


def validate(v, spec, path="report"):
    if isinstance(spec, dict):
        if not isinstance(v, dict):
            raise Invalid("%s 应为对象" % path)
        return {k: validate(v[k], s, path + "." + k) if k in v else default(s)
                for k, s in spec.items() if k in v or k not in OPTIONAL}
    if isinstance(spec, Arr):
        if not isinstance(v, list):
            raise Invalid("%s 应为数组" % path)
        if len(v) > spec.n:
            raise Invalid("%s 最多 %d 项" % (path, spec.n))
        return [validate(x, spec.item, "%s[%d]" % (path, i)) for i, x in enumerate(v)]
    if isinstance(spec, Str):
        if not isinstance(v, str):
            raise Invalid("%s 应为字符串" % path)
        return v[:spec.n]
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise Invalid("%s 应为数字" % path)
    # 先做范围比较再使用：超大整数不会转成浮点，也就不会溢出
    if (isinstance(v, float) and not math.isfinite(v)) or not spec.lo <= v <= spec.hi:
        raise Invalid("%s 超出范围 [%s, %s]" % (path, spec.lo, spec.hi))
    return v


# ==============================================================================
# HTTP 服务：网页、管理 API、子服务器上报
#
# 资源保护：
#   * 全局并发连接上限（PROBE_MAX_CONN），超出时直接返回 503 并关闭
#   * 每个请求从开始等待到处理完成有总时限（空闲 + 处理），超时由后台线程强制断开，防止慢速请求长期占用
#   * 先认证、后读取请求体；认证失败立即响应并关闭连接
#   * 按来源 IP 统计认证失败次数，超过阈值后短时间内直接返回 429
# ==============================================================================

CSP = ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; "
       "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
NODE_PATH = re.compile(r"^/api/nodes/([A-Za-z0-9_-]{1,32})(/secret|/token)?$")
MAX_CONN = env_num("PROBE_MAX_CONN", 256)                 # 同时保持的连接数上限（子服务器各占一条长连接）
IDLE_TIMEOUT = env_num("PROBE_IDLE_TIMEOUT", 30)          # 长连接空闲多久后关闭（秒）
REQUEST_TIMEOUT = env_num("PROBE_REQUEST_TIMEOUT", 30)    # 单个请求从收到到处理完的最长时间（秒）
TRUST_PROXY = os.environ.get("PROBE_TRUST_PROXY") == "1"  # 在本机反向代理后面时，用 X-Forwarded-For 识别来源 IP


class FailLimiter:
    """按来源 IP 统计认证失败：1 分钟内失败 10 次后，该 IP 在窗口剩余时间内直接返回 429"""

    def __init__(self, limit=10, window=60):
        self.limit, self.window = limit, window
        self.lock = threading.Lock()
        self.fails = {}

    def blocked(self, ip):
        with self.lock:
            e = self.fails.get(ip)
            return bool(e) and e[1] >= self.limit and time.monotonic() - e[0] < self.window

    def fail(self, ip):
        now = time.monotonic()
        with self.lock:
            e = self.fails.get(ip)
            if not e or now - e[0] >= self.window:
                e = self.fails[ip] = [now, 0]
            e[1] += 1
            if len(self.fails) > 10000:
                self.fails = {k: v for k, v in self.fails.items() if now - v[0] < self.window}


class ProbeServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = True
    request_queue_size = 128

    def __init__(self, addr, handler):
        self.slots = threading.BoundedSemaphore(MAX_CONN)
        self.deadlines = {}
        self.dl_lock = threading.Lock()
        self.limiter = FailLimiter()
        super().__init__(addr, handler)
        threading.Thread(target=self._reap, name="reaper", daemon=True).start()

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            try:   # 不为它开线程：读掉已到达的数据（减少关闭时的 RST），回 503 后立即关闭
                request.setblocking(False)
                try:
                    request.recv(65536)
                except OSError:
                    pass
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def arm(self, handler, seconds):
        with self.dl_lock:
            self.deadlines[handler] = time.monotonic() + seconds

    def disarm(self, handler):
        with self.dl_lock:
            self.deadlines.pop(handler, None)

    def _reap(self):
        """超过总时限的连接直接断开，阻塞在读取上的处理线程会随之结束"""
        while True:
            time.sleep(1)
            now = time.monotonic()
            with self.dl_lock:
                late = [h for h, t in self.deadlines.items() if t < now]
                for h in late:
                    del self.deadlines[h]
            for h in late:
                try:
                    h.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], (ConnectionError, TimeoutError, socket.timeout, OSError)):
            return
        super().handle_error(request, client_address)


class ProbeHandler(BaseHTTPRequestHandler):
    server_version = "VPSProbe/" + VERSION
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = IDLE_TIMEOUT
    hub = None
    collector = None
    auth = None
    page = b""
    page_gz = b""
    source = b""            # 本文件的源码（子服务器安装时下载）及其 SHA-256
    source_sha = ""

    def log_message(self, fmt, *args):
        pass

    def handle_one_request(self):
        self.server.arm(self, IDLE_TIMEOUT + REQUEST_TIMEOUT)
        try:
            super().handle_one_request()
        finally:
            self.server.disarm(self)

    def client_ip(self):
        ip = self.client_address[0]
        if TRUST_PROXY and ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
            fwd = self.headers.get("X-Forwarded-For", "").split(",")[-1].strip()
            ip = fwd or ip
        return ip

    # ---- 路由 ----
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        url = urlparse(self.path)
        path, q = url.path, parse_qs(url.query)
        if path == "/healthz":
            return self._send(200, b"ok", "text/plain; charset=utf-8")
        if path == "/probe.py":     # 子服务器安装时下载，不需要登录（源码里不含任何密钥）
            return self._send(200, self.source, "text/x-python; charset=utf-8")
        if not self._authorized():
            return
        if path in ("/", "/index.html"):
            return self._send(200, self.page, "text/html; charset=utf-8", self.page_gz)
        if path == "/api/nodes":
            warnings = self.hub.warnings + self.collector.warnings
            return self._json({"manage": bool(self.auth), "version": VERSION, "warnings": warnings,
                               "nodes": self.hub.summaries()})
        if path in ("/api/stats", "/api/history"):
            node = self.hub.get(q.get("node", ["local"])[0])
            if node is None:
                return self._json({"error": "服务器不存在"}, 404)
            if path == "/api/history":
                return self._json(node.history("day" if q.get("range", [""])[0] == "day" else "live"))
            if node.local:
                self.collector.want_procs_until = time.time() + ACTIVE_WINDOW
            else:
                node.last_view = time.time()
            return self._json(dict(node.stats(), manage=bool(self.auth)))
        m = NODE_PATH.match(path)
        if m and m.group(2) == "/secret":
            if not self._can_manage():
                return
            node = self.hub.get(m.group(1))
            if node is None or node.local:
                return self._json({"error": "服务器不存在"}, 404)
            return self._json(self._secret(node))
        self._send(404, b"Not Found", "text/plain; charset=utf-8")

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/report":
            return self._report()
        if not self._authorized() or not self._can_manage():
            return
        body = self._read_body(16 * 1024)
        if body is None:
            return
        try:
            data = json.loads(body or b"{}")
            if not isinstance(data, dict):
                raise ValueError
        except ValueError:
            return self._json({"error": "请求格式错误"}, 400)
        m = NODE_PATH.match(path)
        try:
            if path == "/api/nodes":
                return self._json(self._secret(self.hub.add(data.get("name"), data.get("reset_day"))))
            if m and m.group(2) == "/token":
                return self._json(self._secret(self.hub.rotate(m.group(1), data.get("grace", 3600))))
            if m and not m.group(2):
                return self._json(self.hub.update(m.group(1), data.get("name"), data.get("reset_day")).meta())
            return self._json({"error": "Not Found"}, 404)
        except LookupError as e:
            return self._json({"error": str(e)}, 404)
        except StoreError as e:
            return self._json({"error": str(e)}, 500)
        except ValueError as e:
            return self._json({"error": str(e)}, 400)

    def do_DELETE(self):
        if not self._authorized() or not self._can_manage():
            return
        if self._read_body(16 * 1024) is None:
            return
        m = NODE_PATH.match(urlparse(self.path).path)
        if not m or m.group(2):
            return self._json({"error": "Not Found"}, 404)
        try:
            self.hub.remove(m.group(1))
        except LookupError as e:
            return self._json({"error": str(e)}, 404)
        except StoreError as e:
            return self._json({"error": str(e)}, 500)
        self._json({"ok": True})

    def _secret(self, node):
        """安装子服务器所需的信息：token + 本文件的 SHA-256"""
        return {"id": node.id, "name": node.name, "token": node.token, "sha256": self.source_sha, "version": VERSION}

    # ---- 子服务器上报 ----
    def _report(self):
        ip = self.client_ip()
        if self.server.limiter.blocked(ip):
            return self._reject(429, "认证失败次数过多，请稍后再试")
        auth = self.headers.get("Authorization", "")
        node = self.hub.by_token(auth[7:].strip()) if auth.startswith("Bearer ") else None
        if node is None:            # 先认证，不读取未认证请求的请求体
            self.server.limiter.fail(ip)
            return self._reject(401, "token 无效")
        now = time.monotonic()
        if now - node.last_report < 0.5:
            return self._reject(429, "上报过于频繁")
        node.last_report = now
        data = self._read_body(MAX_REPORT)
        if data is None:
            return
        try:
            if "gzip" in self.headers.get("Content-Encoding", ""):
                d = zlib.decompressobj(16 + zlib.MAX_WBITS)
                data = d.decompress(data, MAX_REPORT * 8)
                if d.unconsumed_tail:
                    raise ValueError("too large")
            report = validate(json.loads(data), REPORT_SCHEMA)
        except Invalid as e:
            return self._json({"error": "数据校验失败：%s" % e}, 422)
        except (ValueError, zlib.error, RecursionError):
            return self._json({"error": "数据格式错误"}, 400)
        node.ingest(report)
        self._json({"ok": True, "need_info": node.info is None, "reset_day": node.reset_day,
                    "want_procs": time.time() - node.last_view < ACTIVE_WINDOW})

    # ---- 工具 ----
    def _reject(self, code, msg):
        """拒绝请求并关闭连接（请求体没有读取，不能继续复用这条连接）"""
        self.close_connection = True
        self._json({"error": msg}, code)

    def _read_body(self, limit):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if n < 0 or n > limit:
            self._reject(413, "请求体过大")
            return None
        return self.rfile.read(n) if n else b""

    def _authorized(self):
        if not self.auth:
            return True
        ip = self.client_ip()
        if self.server.limiter.blocked(ip):
            self._reject(429, "认证失败次数过多，请稍后再试")
            return False
        got = self.headers.get("Authorization", "")
        if hmac.compare_digest(got.encode("utf-8"), self.auth):
            return True
        if got:
            self.server.limiter.fail(ip)
        self.close_connection = True
        body = "401 需要登录".encode("utf-8")
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="VPS Probe", charset="UTF-8"')
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        return False

    def _can_manage(self):
        if not self.auth:
            self._reject(403, "面板未设置访问密码，为安全起见不能管理服务器")
            return False
        # 要求 JSON 请求体：跨站页面无法在不经 CORS 预检的情况下发出这种请求，可防 CSRF
        ctype = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if self.command == "POST" and ctype != "application/json":
            self._reject(415, "需要 application/json")
            return False
        return True

    def _send(self, code, body, ctype, body_gz=None):
        gz = "gzip" in self.headers.get("Accept-Encoding", "")
        if gz and body_gz is None and len(body) > 1024:
            body_gz = gzip.compress(body, 6)
        if gz and body_gz is not None:
            body = body_gz
        else:
            gz = False
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Vary", "Accept-Encoding")
        if gz:
            self.send_header("Content-Encoding", "gzip")
        if self.close_connection:
            self.send_header("Connection", "close")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", CSP)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, code=200):
        try:
            body = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        except ValueError:
            code, body = 500, '{"error":"内部数据异常"}'.encode("utf-8")
        self._send(code, body, "application/json; charset=utf-8")


# ==============================================================================
# 子服务器模式：采样与上报分别在两个线程里进行
#
# * 采样线程按固定间隔采样，只把最新一份快照交给上报线程
# * 上报线程通过长连接 POST 给面板（gzip 后约 0.5 KB）；网络慢或面板不可达时不会拖慢采样
# * 不保留离线期间的历史：恢复连接后只上报最新数据，面板上这段时间显示为空白
# ==============================================================================

def is_loopback(host):
    return host in ("localhost", "::1") or host.startswith("127.")


class Agent:
    def __init__(self, master, token, collector, allow_http=False):
        u = urlparse(master.rstrip("/") + "/api/report")
        if u.scheme not in ("http", "https") or not u.hostname:
            sys.exit("错误：面板地址无效：%s" % master)
        if u.scheme == "http" and not allow_http and not is_loopback(u.hostname):
            sys.exit("错误：面板地址是 HTTP，token 和数据会明文传输。仅在可信内网中使用时，请加 --allow-http")
        self.conn_cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
        self.host, self.port, self.path = u.hostname, u.port, u.path
        self.master, self.token, self.collector = master, token, collector
        self.cv = threading.Condition()
        self.pending = None
        self.conn = None
        self.need_info = True
        self.info_at = 0.0
        self.fails = 0
        self.retry_at = 0.0
        self.err_logged = 0.0

    def tick(self):
        """采样线程：采样后替换掉还没发出去的旧快照"""
        snap, warm = self.collector.sample()
        if warm:
            with self.cv:
                self.pending = snap
                self.cv.notify()

    def report_loop(self, stop):
        while not stop.is_set():
            with self.cv:
                while self.pending is None and not stop.is_set():
                    self.cv.wait(1)
                snap, self.pending = self.pending, None
            if snap is None:
                continue
            wait = self.retry_at - time.monotonic()
            if wait > 0:
                stop.wait(wait)     # 退避期间的快照直接丢弃，恢复后只发最新的
                continue
            try:
                self.send(snap)
            except Exception as e:
                self._fail("上报出错：%r" % e)

    def send(self, snap):
        now = time.monotonic()
        if self.need_info or now - self.info_at > 600:
            self.info_at = now
        else:
            snap.pop("info", None)        # 静态信息 10 分钟发一次，省流量
        body = gzip.compress(json.dumps(snap, separators=(",", ":")).encode("utf-8"), 6)
        try:
            status, data = self._post(body)
        except (OSError, http.client.HTTPException) as e:
            return self._fail("无法连接面板 %s：%s" % (self.master, e))
        try:
            r = json.loads(data)
        except ValueError:
            r = {}
        if status == 401:
            self.retry_at = now + 60
            return self._fail("token 无效（这台服务器可能已在面板中删除或更换了 token），60 秒后重试")
        if status == 429:
            self.retry_at = now + 2
            return
        if status == 422:
            self.retry_at = now + 30
            return self._fail("面板拒绝了上报数据：%s" % r.get("error", ""))
        if status != 200:
            return self._fail("面板返回 HTTP %d" % status)
        if self.fails:
            log("已重新连接到面板")
            self.fails = 0
        self.need_info = bool(r.get("need_info"))
        if r.get("want_procs"):
            self.collector.want_procs_until = time.time() + ACTIVE_WINDOW
        rd = r.get("reset_day")
        if isinstance(rd, int) and 1 <= rd <= 28:
            self.collector.reset_day = rd

    def _post(self, body):
        headers = {"Content-Type": "application/json", "Content-Encoding": "gzip",
                   "Authorization": "Bearer " + self.token, "User-Agent": "VPSProbe-Agent/" + VERSION}
        for attempt in (1, 2):
            fresh = self.conn is None
            if fresh:
                self.conn = self.conn_cls(self.host, self.port, timeout=10)
            try:
                self.conn.request("POST", self.path, body, headers)
                resp = self.conn.getresponse()
                data = resp.read()
                if resp.will_close:
                    self._close()
                return resp.status, data
            except (OSError, http.client.HTTPException):
                self._close()
                if fresh or attempt == 2:     # 复用的旧连接可能已被面板关闭，换新连接重试一次
                    raise

    def _close(self):
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    def _fail(self, msg):
        self.fails += 1
        self.need_info = True
        now = time.monotonic()
        self.retry_at = max(self.retry_at, now + min(30, 2 ** min(self.fails, 5)))
        if self.fails == 1 or now - self.err_logged > 300:
            self.err_logged = now
            log(msg)


def run_agent(args):
    if not args.token:
        sys.exit("错误：子服务器模式需要 --token（在面板上添加服务器时生成）")
    collector = Collector(args.interval, args.data_dir, args.reset_day, args.ifaces, args.ifaces_exclude)
    agent = Agent(args.agent, args.token, collector, args.allow_http)
    collector.sample()  # 先采一次作为计算速率的基准
    stop = threading.Event()
    threading.Thread(target=agent.report_loop, args=(stop,), name="reporter", daemon=True).start()
    threading.Thread(target=run_every, args=(TRAFFIC_SAVE_EVERY, collector.save, stop), name="saver",
                     daemon=True).start()

    def on_term(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, on_term)
    log("VPS Probe v%s 子服务器模式启动，上报到 %s，间隔 %gs" % (VERSION, args.agent, args.interval))
    try:
        run_loop(args.interval, agent.tick, stop)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        collector.save()
        log("已退出")


# ==============================================================================
# 安装 / 升级 / 卸载 systemd 服务
#
# 升级流程：先做全部检查（参数、端口）再动现有服务；备份旧的代码、配置和服务文件；
# 写入新版本后重启并做健康检查（面板请求 /healthz，子服务器确认进程稳定运行），
# 失败则自动恢复旧版本并重新启动，首次安装失败则清理干净。
# ==============================================================================

SERVICE = """[Unit]
Description=VPS Probe ({role})
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/{name}.env
Environment=PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ExecStart={python} /opt/{name}/probe.py
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


# 由安装程序维护的配置项；其他 PROBE_* 配置项在升级时原样保留
MANAGED_KEYS = {"PROBE_HOST", "PROBE_PORT", "PROBE_USER", "PROBE_PASSWORD", "PROBE_RESET_DAY", "PROBE_INTERVAL",
                "PROBE_IFACES", "PROBE_AGENT", "PROBE_TOKEN", "PROBE_ALLOW_HTTP"}


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
    for k, v in old.items():        # 用户手动加的其他配置（如 PROBE_TRUST_PROXY）升级时保留
        if k.startswith("PROBE_") and k not in MANAGED_KEYS:
            cfg[k] = v
    try:
        ok = 1 <= float(interval) <= 10
    except ValueError:
        ok = False
    if not ok:
        raise ValueError("采样间隔必须在 1-10 秒之间")
    return cfg


def _systemctl(*a):
    return subprocess.run(("systemctl",) + a, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def _port_free(host, port):
    with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def _panel_ok(cfg):
    host = cfg.get("PROBE_HOST") or "0.0.0.0"
    host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    url = "http://%s:%s/healthz" % ("[%s]" % host if ":" in host else host, cfg.get("PROBE_PORT") or 8899)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=2) as r:
            return r.status == 200 and r.read() == b"ok"
    except (OSError, ValueError):
        return False


def _healthy(name, agent, cfg, timeout=15):
    """面板：/healthz 返回 ok；子服务器：启动 4 秒后进程仍在运行"""
    if agent:
        for wait in (4, 1):
            time.sleep(wait)
            if not _systemctl("is-active", "--quiet", name):
                return False
        return True
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(1)
        if _systemctl("is-active", "--quiet", name) and _panel_ok(cfg):
            return True
    return False


def _journal(name, since):
    return subprocess.run(["journalctl", "-u", name, "--since", since, "-o", "cat", "--no-pager"],
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True).stdout


def _local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))   # UDP connect 不会真的发包，只是让系统选出出口网卡
            return s.getsockname()[0]
    except OSError:
        return "服务器IP"


def cmd_install(args):
    if os.geteuid() != 0:
        sys.exit("错误：请用 root 运行（普通用户在命令前加 sudo）")
    if not shutil.which("systemctl"):
        sys.exit("错误：需要 systemd")
    agent = bool(args.agent)
    name = "vps-probe-agent" if agent else "vps-probe"
    envf, unit, home = "/etc/%s.env" % name, "/etc/systemd/system/%s.service" % name, "/opt/" + name
    dst = os.path.join(home, "probe.py")
    old_env = read_env(envf)
    try:
        cfg = install_config(args, old_env)
    except ValueError as e:
        sys.exit("错误：%s" % e)

    # 1. 预检查：在动现有服务之前完成
    was_active = os.path.exists(unit) and _systemctl("is-active", "--quiet", name)
    if not agent:
        port = int(cfg["PROBE_PORT"])
        ours = was_active and str(old_env.get("PROBE_PORT", "")) == str(port)
        if not ours and not _port_free(cfg["PROBE_HOST"], port):
            sys.exit("错误：端口 %d 已被占用，请用 --port 换一个（现有服务未做任何改动）" % port)
    with open(os.path.abspath(__file__), "rb") as f:
        code = f.read()

    # 2. 备份旧版本
    backups = {}
    for p in (dst, envf, unit):
        try:
            with open(p, "rb") as f:
                backups[p] = (f.read(), os.stat(p).st_mode & 0o777)
        except OSError:
            pass

    # 3. 写入新版本并重启
    since = time.strftime("%Y-%m-%d %H:%M:%S")
    env_text = "".join("%s=%s\n" % (k, env_quote(v)) for k, v in cfg.items())
    service = SERVICE.format(name=name, python=sys.executable, role="子服务器" if agent else "面板",
                             mem="48M" if agent else "128M", tasks=32 if agent else 320)
    try:
        write_atomic(dst, code, 0o755)
        write_atomic(envf, env_text.encode("utf-8"), 0o600)
        write_atomic(unit, service.encode("utf-8"), 0o644)
        _systemctl("daemon-reload")
        _systemctl("enable", name)
        _systemctl("restart", name)
        ok = _healthy(name, agent, cfg)
    except OSError as e:
        print("写入文件失败：%s" % e)
        ok = False
    recent = _journal(name, since)

    # 4. 失败回滚
    if not ok:
        print(recent.strip())
        if backups:
            for p, (data, mode) in backups.items():
                write_atomic(p, data, mode)
            _systemctl("daemon-reload")
            if not was_active:
                sys.exit("错误：新版本启动失败，已回滚到原来的代码和配置")
            _systemctl("restart", name)
            if _healthy(name, agent, read_env(envf)):
                sys.exit("错误：新版本启动失败，已回滚到原来的代码和配置，原服务已恢复运行")
            sys.exit("错误：新版本启动失败，已回滚到原来的代码和配置，但原服务也未能启动，请查看日志")
        _systemctl("disable", "--now", name)
        for p in (unit, envf):
            try:
                os.remove(p)
            except OSError:
                pass
        shutil.rmtree(home, ignore_errors=True)
        _systemctl("daemon-reload")
        sys.exit("错误：服务启动失败，已撤销本次安装")

    green = "\033[32m%s\033[0m"
    if agent:
        print(green % ("✔ 子服务器探针已安装，正在向 %s 上报" % cfg["PROBE_AGENT"]))
        bad = [l for l in recent.splitlines() if "无法连接面板" in l or "token 无效" in l]
        if bad:
            print("\033[33m  注意：%s\033[0m" % bad[-1])
        print("  查看日志：journalctl -u %s -f" % name)
    else:
        print(green % ("✔ VPS Probe 面板%s成功" % ("升级" if backups else "安装")))
        print("  访问地址：http://%s:%s" % (_local_ip(), cfg["PROBE_PORT"]))
        if cfg["PROBE_PASSWORD"]:
            print("  用户名：  %s\n  密码：    %s" % (cfg["PROBE_USER"], cfg["PROBE_PASSWORD"]))
        else:
            print("  登录认证：未开启（任何人都能查看面板，且不能在网页上添加服务器）")
        print("  公网使用请配置 HTTPS 反向代理：https://github.com/%s/blob/main/docs/guide.md" % REPO)
        print("  修改配置：%s（改完执行 systemctl restart %s）" % (envf, name))
    print("  卸载：    python3 %s uninstall" % dst)


def cmd_uninstall():
    if os.geteuid() != 0:
        sys.exit("错误：请用 root 运行（普通用户在命令前加 sudo）")
    # 从 /opt/vps-probe-agent/probe.py 运行只卸载子服务器，从一键脚本运行则全部卸载
    here = os.path.dirname(os.path.abspath(__file__))
    names = [n for n in ("vps-probe", "vps-probe-agent") if here == "/opt/" + n] or ["vps-probe", "vps-probe-agent"]
    found = False
    for name in names:
        unit = "/etc/systemd/system/%s.service" % name
        if not (os.path.exists(unit) or os.path.isdir("/opt/" + name)):
            continue
        found = True
        _systemctl("disable", "--now", name)
        for p in (unit, "/etc/%s.env" % name, "/var/lib/" + name):   # /var/lib/X 是指向 private/X 的符号链接
            if os.path.islink(p) or os.path.isfile(p):
                os.remove(p)
        for d in ("/opt/" + name, "/var/lib/private/" + name, "/var/lib/" + name):
            shutil.rmtree(d, ignore_errors=True)
        print("已卸载 %s" % name)
    _systemctl("daemon-reload")
    if not found:
        print("没有发现已安装的 VPS Probe")


# ==============================================================================
# 命令行入口：run（默认）/ install / uninstall
# ==============================================================================

def run_master(args):
    collector = Collector(args.interval, args.data_dir, args.reset_day, args.ifaces, args.ifaces_exclude)
    hub = Hub(args.data_dir, collector.info["hostname"], args.reset_day)
    collector.reset_day = hub.local.reset_day
    hub.local.ingest(collector.sample()[0], warm=False)

    def tick():
        collector.reset_day = hub.local.reset_day
        snap, warm = collector.sample()
        hub.local.ingest(snap, warm)

    stop = threading.Event()
    threading.Thread(target=run_loop, args=(args.interval, tick, stop), name="sampler", daemon=True).start()
    threading.Thread(target=run_every, args=(TRAFFIC_SAVE_EVERY, collector.save, stop), name="traffic-saver",
                     daemon=True).start()
    threading.Thread(target=run_every, args=(SAVE_EVERY, hub.save_history, stop), name="history-saver",
                     daemon=True).start()

    ProbeHandler.hub, ProbeHandler.collector = hub, collector
    if args.user or args.password:
        token = base64.b64encode(("%s:%s" % (args.user, args.password)).encode("utf-8"))
        ProbeHandler.auth = b"Basic " + token
    ProbeHandler.page = PAGE.encode("utf-8")
    ProbeHandler.page_gz = gzip.compress(ProbeHandler.page, 9)
    with open(os.path.abspath(__file__), "rb") as f:
        ProbeHandler.source = f.read()
    ProbeHandler.source_sha = hashlib.sha256(ProbeHandler.source).hexdigest()

    server_cls = ProbeServer
    if ":" in args.host:
        server_cls = type("ProbeServer6", (ProbeServer,), {"address_family": socket.AF_INET6})
    try:
        httpd = server_cls((args.host, args.port), ProbeHandler)
    except OSError as e:
        sys.exit("无法监听 %s:%d —— %s" % (args.host, args.port, e))

    def on_term(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, on_term)
    log("VPS Probe v%s 已启动 → http://%s:%d/  采样间隔 %gs，最多 %d 个连接，登录认证：%s" % (
        VERSION, args.host if ":" not in args.host else "[%s]" % args.host, args.port, args.interval,
        MAX_CONN, "已开启" if ProbeHandler.auth else "未开启"))
    if not ProbeHandler.auth:
        log("提示：未设置访问密码，任何人都能看到监控数据和进程命令行，并且无法在网页上添加服务器。")
    try:
        httpd.serve_forever(poll_interval=1)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        collector.save()
        hub.save_history()
        httpd.server_close()
        log("已退出")


def main():
    ap = argparse.ArgumentParser(description="VPS Probe %s - 轻量级 Linux 服务器探针" % VERSION)
    ap.add_argument("command", nargs="?", default="run", choices=("run", "install", "uninstall"),
                    help="run 直接运行（默认）/ install 安装或升级为系统服务 / uninstall 卸载")
    ap.add_argument("--version", action="version", version=VERSION)
    ap.add_argument("--host", help="监听地址，默认 0.0.0.0；放在反向代理后面时用 127.0.0.1")
    ap.add_argument("--port", type=int, help="监听端口，默认 8899")
    ap.add_argument("--user", help="登录用户名（安装时默认 admin）")
    ap.add_argument("--password", help="登录密码（安装时不指定则自动生成）")
    ap.add_argument("--no-auth", action="store_true", help="安装时不设登录密码")
    ap.add_argument("--interval", type=float, help="采样间隔（秒），默认 2")
    ap.add_argument("--reset-day", type=int, help="月流量重置日 1-28，默认每月 1 号")
    ap.add_argument("--ifaces", help="只统计这些网卡的流量，逗号分隔，支持通配符，如 eth0,ens*")
    ap.add_argument("--data-dir", help="数据保存目录，传空字符串则不保存")
    ap.add_argument("--agent", metavar="URL", help="子服务器模式：面板地址，如 https://probe.example.com")
    ap.add_argument("--token", help="子服务器模式：在面板上添加服务器时生成的 token")
    ap.add_argument("--allow-http", action="store_true", help="子服务器模式：允许面板地址使用 HTTP（仅限可信内网）")
    args = ap.parse_args()

    if not read_text("/proc/stat"):
        sys.exit("错误：找不到 /proc/stat，本探针只能运行在 Linux 上。")
    if args.command == "install":
        return cmd_install(args)
    if args.command == "uninstall":
        return cmd_uninstall()

    # 直接运行：命令行参数优先，其次是环境变量（systemd 服务通过 EnvironmentFile 传入）
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
        args.data_dir = env("STATE_DIRECTORY") or env("PROBE_DATA_DIR") or \
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    args.agent = args.agent or env("PROBE_AGENT", "")
    args.token = args.token or env("PROBE_TOKEN", "")
    args.allow_http = args.allow_http or env("PROBE_ALLOW_HTTP") == "1"
    if args.agent:
        run_agent(args)
    else:
        run_master(args)


# ==============================================================================
# 前端页面：HTML、CSS 和 JavaScript 全部内联，不加载任何外部资源
# ==============================================================================

PAGE = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>VPS Probe</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Crect width='24' height='24' rx='6' fill='%233b82f6'/%3E%3Cpath d='M20 12h-3l-2.5 6-5-12L7 12H4' fill='none' stroke='white' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
<script>try{var t=localStorage.getItem('probe-theme');document.documentElement.dataset.theme=(t==='light'||t==='dark')?t:(matchMedia('(prefers-color-scheme: light)').matches?'light':'dark')}catch(e){document.documentElement.dataset.theme='dark'}</script>
<style>
:root{
  color-scheme:dark;
  --bg:#090c13;--panel:#0f141e;--panel-2:#141b27;--track:#1b2331;
  --border:#1c2431;--border-strong:#2c3646;
  --text:#e7eaf0;--muted:#8d97a9;--faint:#5e697c;
  --grid:rgba(148,163,184,.08);--hover:rgba(148,163,184,.045);
  --tip:#0b1018;--seg:#0b1018;--seg-on:#1e2635;
  --shadow:0 1px 0 rgba(255,255,255,.025) inset,0 12px 32px -16px rgba(0,0,0,.7);
  --glow1:rgba(59,130,246,.13);--glow2:rgba(139,92,246,.08);
  --radius:14px;
}
:root[data-theme="light"]{
  color-scheme:light;
  --bg:#f3f5f9;--panel:#fff;--panel-2:#f6f8fb;--track:#eceff4;
  --border:#e2e6ed;--border-strong:#cdd4df;
  --text:#0f172a;--muted:#5a6577;--faint:#98a2b3;
  --grid:rgba(15,23,42,.06);--hover:rgba(15,23,42,.025);
  --tip:#fff;--seg:#eaedf2;--seg-on:#fff;
  --shadow:0 1px 2px rgba(15,23,42,.04),0 10px 28px -16px rgba(15,23,42,.16);
  --glow1:rgba(59,130,246,.07);--glow2:rgba(139,92,246,.05);
}
*{box-sizing:border-box}
[hidden]{display:none!important}
html,body{margin:0}
body{background:var(--bg);color:var(--text);min-height:100vh;
  font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei","Noto Sans CJK SC","Noto Sans SC",Roboto,"Helvetica Neue",Arial,sans-serif;
  -webkit-font-smoothing:antialiased;font-feature-settings:"tnum"}
body::before{content:"";position:fixed;inset:0;pointer-events:none;z-index:-1;
  background:radial-gradient(1000px 520px at 8% -12%,var(--glow1),transparent 62%),radial-gradient(900px 480px at 100% -8%,var(--glow2),transparent 60%)}
svg.i{fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;width:16px;height:16px;flex:none}
.wrap{max-width:1360px;margin:0 auto;padding:22px 24px 28px}
.muted{color:var(--muted)}
.mono,code,.code{font-family:ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace;font-size:12px}
code{background:var(--seg);border:1px solid var(--border);padding:1px 5px;border-radius:5px}

/* 顶栏 */
.top{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:20px}
.brand{display:flex;align-items:center;gap:14px;min-width:0;flex:1}
.logo{width:44px;height:44px;border-radius:12px;display:grid;place-items:center;flex:none;color:#fff;
  background:linear-gradient(135deg,#3b82f6 0%,#6366f1 55%,#8b5cf6 100%);box-shadow:0 8px 22px -8px rgba(79,70,229,.7)}
.logo svg.i{width:22px;height:22px;stroke-width:2.2}
.back{width:40px!important;height:40px!important;border-radius:11px!important}
.back svg.i{width:20px;height:20px}
.brand-text{min-width:0}
.host{margin:0;font-size:19px;font-weight:650;letter-spacing:.2px;line-height:1.3;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sub{color:var(--muted);font-size:12.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-height:19px}
.actions{display:flex;align-items:center;gap:8px}
.pill{display:inline-flex;align-items:center;gap:8px;height:32px;padding:0 12px;border-radius:999px;background:var(--panel);
  border:1px solid var(--border);font-size:12.5px;color:var(--muted);white-space:nowrap}
.dot{width:8px;height:8px;border-radius:50%;background:var(--faint);position:relative;flex:none}
.pill.online{color:var(--text)}
.pill.online .dot{background:#22c55e}
.pill.online .dot::after{content:"";position:absolute;inset:-4px;border-radius:50%;background:#22c55e;animation:ping 2s ease-out infinite}
.pill.partial{color:var(--text)}
.pill.partial .dot{background:#f59e0b}
.pill.offline{color:#ef4444;border-color:rgba(239,68,68,.35)}
.pill.offline .dot{background:#ef4444}
@keyframes ping{0%{transform:scale(.5);opacity:.55}100%{transform:scale(1.7);opacity:0}}
.icon-btn{width:32px;height:32px;border-radius:9px;border:1px solid var(--border);background:var(--panel);color:var(--muted);
  display:grid;place-items:center;cursor:pointer;padding:0;text-decoration:none;flex:none}
.icon-btn:hover{color:var(--text);border-color:var(--border-strong)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;height:32px;padding:0 13px;border-radius:9px;border:1px solid var(--border-strong);
  background:var(--panel);color:var(--text);font:inherit;font-size:12.5px;font-weight:550;cursor:pointer;white-space:nowrap}
.btn:hover{border-color:var(--faint)}
.btn:disabled{opacity:.55;cursor:default}
.btn.primary{background:#3b82f6;border-color:#3b82f6;color:#fff}
.btn.primary:hover{background:#2f74e6;border-color:#2f74e6}
.btn.danger{color:#ef4444;border-color:rgba(239,68,68,.45)}
.btn.danger:hover{background:rgba(239,68,68,.08)}
.btn.danger.solid{background:#ef4444;border-color:#ef4444;color:#fff}
.btn svg.i{width:14px;height:14px}
.btn-row{display:flex;gap:8px;flex-wrap:wrap}

/* 卡片 */
.card{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow);padding:16px 18px;min-width:0}
.ico{width:28px;height:28px;border-radius:8px;display:grid;place-items:center;color:var(--c);flex:none;
  background:color-mix(in srgb,var(--c) 15%,transparent)}
.ico svg.i{width:15px;height:15px}
.badge{font-size:11.5px;color:var(--muted);background:var(--panel-2);border:1px solid var(--border);padding:1px 9px;border-radius:999px;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:55%;flex:none}

/* 总览 */
.sumbar{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px}
.stat{display:flex;align-items:center;gap:14px;padding:15px 18px}
.stat .ico{width:38px;height:38px;border-radius:11px}
.stat .ico svg.i{width:18px;height:18px}
.stat div{min-width:0}
.stat small{display:block;font-size:12px;color:var(--muted)}
.stat b{display:block;font-size:19px;font-weight:650;line-height:1.35;white-space:nowrap}
.nodes{display:grid;grid-template-columns:repeat(auto-fill,minmax(310px,1fr));gap:16px}
.node{display:flex;flex-direction:column;gap:14px;color:inherit;text-decoration:none;transition:border-color .15s,transform .15s}
a.node:hover{border-color:var(--border-strong);transform:translateY(-2px)}
.node-head{display:flex;align-items:center;gap:10px;min-width:0}
.sdot{width:9px;height:9px;border-radius:50%;flex:none;background:var(--faint)}
.sdot.on{background:#22c55e;box-shadow:0 0 0 3px rgba(34,197,94,.18)}
.sdot.off{background:#ef4444;box-shadow:0 0 0 3px rgba(239,68,68,.16)}
.sdot.wait{background:#f59e0b;box-shadow:0 0 0 3px rgba(245,158,11,.16)}
.node-name{min-width:0;flex:1}
.node-name b{display:block;font-size:14.5px;font-weight:650;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.node-name span{display:block;font-size:12px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.meters{display:grid;gap:10px}
.meter{display:grid;grid-template-columns:30px minmax(0,1fr) 50px;align-items:center;gap:10px;font-size:12px}
.meter .ml{color:var(--muted)}
.meter .bar{width:auto}
.meter .mv{text-align:right;font-weight:600}
.node-stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}
.node-stats div{background:var(--panel-2);border:1px solid var(--border);border-radius:9px;padding:6px 10px;min-width:0}
.node-stats small{display:block;font-size:11px;color:var(--muted);white-space:nowrap}
.node-stats b{display:block;font-size:13px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.node-foot{display:flex;justify-content:space-between;gap:8px;font-size:11.5px;color:var(--faint);border-top:1px dashed var(--border);padding-top:10px;margin-top:auto}
.node.off .meters,.node.off .node-stats{opacity:.45}
.node.off .node-foot span:first-child{color:#ef4444}
.node-empty{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:4px;text-align:center;color:var(--muted);font-size:13px;padding:26px 0}
.node-empty span{color:#3b82f6;font-size:12.5px}
.node.add{border:1.5px dashed var(--border-strong);background:transparent;box-shadow:none;align-items:center;justify-content:center;
  gap:10px;color:var(--muted);min-height:236px;cursor:pointer;font:inherit;font-size:13.5px;font-weight:550}
.node.add:hover{color:var(--text);border-color:#3b82f6}
.node.add .plus{width:42px;height:42px;border-radius:12px;display:grid;place-items:center;color:#3b82f6;background:rgba(59,130,246,.13)}
.node.add .plus svg.i{width:20px;height:20px}

/* 详情：概览卡片 */
.kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px}
.kpi-head{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:14px}
.kpi-title{display:flex;align-items:center;gap:10px;font-weight:600;font-size:13.5px}
.kpi-body{display:flex;align-items:center;gap:16px}
.ring{position:relative;width:84px;height:84px;flex:none}
.ring svg{width:100%;height:100%;transform:rotate(-90deg);display:block}
.ring circle{fill:none;stroke-width:7}
.ring .bg{stroke:var(--track)}
.ring .fg{stroke-linecap:round;transition:stroke-dashoffset .8s cubic-bezier(.4,0,.2,1),stroke .4s}
.ring-val{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:19px;font-weight:650;letter-spacing:-.3px}
.ring-val small{font-size:11px;color:var(--muted);font-weight:500;margin:4px 0 0 1px}
.kv{margin:0;display:grid;gap:8px;flex:1;min-width:0}
.kv div{display:flex;justify-content:space-between;align-items:baseline;gap:10px;font-size:12.5px;min-width:0}
.kv dt{color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0}
.kv dd{margin:0;font-weight:560;white-space:nowrap}
.netbig{display:grid;gap:10px;flex:none;width:118px}
.rate{display:flex;align-items:center;gap:9px}
.rate .arr{width:26px;height:26px;border-radius:8px;display:grid;place-items:center;flex:none;color:var(--c);background:color-mix(in srgb,var(--c) 15%,transparent)}
.rate .arr svg.i{width:14px;height:14px;stroke-width:2.4}
.rate b{display:block;font-size:15.5px;font-weight:650;line-height:1.2;white-space:nowrap}
.rate small{display:block;font-size:11px;color:var(--muted);line-height:1.3}
.banner{border:1px solid rgba(239,68,68,.35);background:rgba(239,68,68,.08);color:#ef4444;border-radius:12px;padding:10px 14px;margin-bottom:16px;font-size:13px}
.banner.warn{border-color:rgba(245,158,11,.4);background:rgba(245,158,11,.08);color:#d97706}
.note{margin:10px 0 0;font-size:11.5px;color:var(--faint);line-height:1.6}
.warnbox{border:1px solid rgba(245,158,11,.4);background:rgba(245,158,11,.07);border-radius:10px;padding:12px 14px;margin-bottom:12px;font-size:12.5px}
.warnbox b{color:#d97706}
.warnbox p{margin:6px 0 10px;color:var(--muted);line-height:1.7}
.check{display:flex;align-items:flex-start;gap:8px;font-size:12.5px;line-height:1.6;cursor:pointer}
.check input{margin:3px 0 0;flex:none;accent-color:#3b82f6}
.waitcard{max-width:720px;margin:24px auto;padding:28px;text-align:center}
.waitcard .ico{width:48px;height:48px;border-radius:14px;margin:0 auto 12px}
.waitcard .ico svg.i{width:22px;height:22px}
.waitcard h3{margin:0 0 6px;font-size:17px}
.waitcard>p{margin:0 0 18px;font-size:13px}
.waitcmd{text-align:left}
.loading #detailBody{visibility:hidden}

/* 区块标题 & 分段按钮 */
.section-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:28px 2px 12px}
.section-head h2{margin:0;font-size:15px;font-weight:650}
.section-head .muted{font-size:12.5px}
.seg{display:inline-flex;background:var(--seg);border:1px solid var(--border);border-radius:10px;padding:3px;gap:2px;flex:none}
.seg button{border:0;background:transparent;color:var(--muted);font:inherit;font-size:12.5px;padding:4px 12px;border-radius:7px;cursor:pointer;white-space:nowrap}
.seg button:hover{color:var(--text)}
.seg button.on{background:var(--seg-on);color:var(--text);box-shadow:0 1px 2px rgba(0,0,0,.18),0 0 0 1px var(--border)}
.seg.sm button{font-size:12px;padding:3px 10px}

/* 图表 */
.charts{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}
.chart-head{display:flex;align-items:center;justify-content:space-between;gap:8px 16px;margin-bottom:10px;flex-wrap:wrap}
.chart-head h3{margin:0;font-size:13.5px;font-weight:600}
.legend{display:flex;gap:6px 14px;flex-wrap:wrap;font-size:12px;color:var(--muted)}
.legend span{display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
.legend i,.tip i,.sw{width:8px;height:8px;border-radius:2px;display:inline-block;flex:none}
.legend b{color:var(--text);font-weight:600}
.chart{position:relative;height:210px}
.chart canvas{position:absolute;left:0;top:0;display:block;cursor:crosshair}
.tip{position:absolute;pointer-events:none;opacity:0;transition:opacity .12s;background:var(--tip);border:1px solid var(--border-strong);
  border-radius:9px;padding:8px 10px;font-size:12px;box-shadow:0 10px 30px -10px rgba(0,0,0,.45);white-space:nowrap;z-index:2;min-width:150px}
.tip .tt{color:var(--muted);margin-bottom:5px;font-size:11.5px}
.tip .tr{display:flex;align-items:center;gap:7px;line-height:1.7}
.tip .tr b{margin-left:auto;padding-left:14px;font-weight:600}

/* 详情信息 */
.grid3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}
.card-head{display:flex;align-items:center;gap:10px;margin-bottom:14px;flex-wrap:wrap}
.card-head h3{margin:0;font-size:13.5px;font-weight:600}
.card-head .right{margin-left:auto}
.card-head .muted{font-size:12px}
.info{margin:0}
.info div{display:grid;grid-template-columns:84px minmax(0,1fr);gap:12px;padding:8px 0;border-top:1px dashed var(--border);font-size:12.5px}
.info div:first-child{border-top:0;padding-top:0}
.info dt{color:var(--muted)}
.info dd{margin:0;word-break:break-word}
.tiles{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}
.tile{background:var(--panel-2);border:1px solid var(--border);border-radius:10px;padding:9px 11px;min-width:0}
.tile .l{font-size:11.5px;color:var(--muted);display:flex;align-items:center;gap:6px;white-space:nowrap}
.tile .v{font-size:16px;font-weight:650;margin-top:2px;white-space:nowrap}
.sublabel{font-size:11.5px;color:var(--faint);margin:16px 0 8px;letter-spacing:.3px}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chip{font-size:12px;padding:3px 10px;border-radius:999px;background:var(--panel-2);border:1px solid var(--border);color:var(--muted);white-space:nowrap}
.chip b{color:var(--text);margin-left:6px;font-weight:600}
.tbl-wrap{overflow-x:auto}
.tbl{width:100%;border-collapse:collapse;font-size:12.5px}
.tbl th{font-weight:500;color:var(--faint);text-align:left;padding:7px 8px;border-bottom:1px solid var(--border);font-size:12px;white-space:nowrap}
.tbl td{padding:8px;border-bottom:1px solid var(--border);white-space:nowrap}
.tbl tbody tr:last-child td{border-bottom:0}
.tbl tbody tr:hover td{background:var(--hover)}
.tbl th:first-child,.tbl td:first-child{padding-left:0}
.tbl th:last-child,.tbl td:last-child{padding-right:0}
.tbl .r{text-align:right}
.tbl .empty{color:var(--faint);text-align:center;padding:22px 0}
.pn{width:100%;max-width:0}
.pn>div{display:flex;align-items:baseline;gap:10px;min-width:0}
.pname{font-weight:600;flex:none}
.cmd{color:var(--faint);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
.cellbar{display:flex;align-items:center;justify-content:flex-end;gap:10px}
.cellbar span{min-width:58px;text-align:right}
.bar{height:6px;border-radius:99px;background:var(--track);overflow:hidden;width:64px;flex:none}
.bar i{display:block;height:100%;border-radius:inherit;background:var(--c);max-width:100%}
.bar.lg{height:8px;width:auto}
.disk{padding:12px 0;border-top:1px dashed var(--border)}
.disk:first-child{border-top:0;padding-top:0}
.disk-top{display:flex;justify-content:space-between;align-items:baseline;gap:8px;font-size:12.5px;margin-bottom:8px}
.disk-top .mp{font-weight:600}
.disk-top .fs{color:var(--faint);font-size:11.5px;margin-left:8px}
.disk-top .pct{font-weight:600}
.disk-bot{display:flex;justify-content:space-between;gap:8px;font-size:11.5px;color:var(--muted);margin-top:7px}
.procs{margin-top:16px}
.foot{margin-top:22px;color:var(--faint);font-size:12px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:6px 16px}

/* 对话框 */
dialog{padding:0;border:1px solid var(--border-strong);border-radius:16px;background:var(--panel);color:var(--text);
  width:min(540px,calc(100vw - 32px));max-height:calc(100vh - 32px);box-shadow:0 30px 70px -20px rgba(0,0,0,.6)}
dialog::backdrop{background:rgba(3,6,12,.55);backdrop-filter:blur(3px)}
.dlg-head{display:flex;align-items:flex-start;gap:12px;padding:18px 20px 0}
.dlg-head h3{margin:0;font-size:16px;font-weight:650}
.dlg-head p{margin:4px 0 0;font-size:12.5px;color:var(--muted)}
.dlg-head .icon-btn{margin-left:auto;border:0;background:transparent}
.dlg-body{padding:16px 20px 4px}
.dlg-body>p{font-size:13px;margin:0 0 12px;line-height:1.7}
.dlg-foot{display:flex;justify-content:flex-end;gap:8px;padding:14px 20px 18px}
.field{display:grid;gap:6px;margin-bottom:16px;font-size:12.5px}
.field>span{color:var(--muted);font-weight:550}
.field small{color:var(--faint);font-size:11.5px}
.field input{height:38px;border-radius:9px;border:1px solid var(--border-strong);background:var(--panel-2);color:var(--text);
  padding:0 12px;font:inherit;font-size:13.5px;width:100%}
.field input:focus{outline:none;border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.2)}
.code{background:var(--seg);border:1px solid var(--border);border-radius:10px;padding:12px 14px;line-height:1.7;word-break:break-all;user-select:all}
.row-end{display:flex;justify-content:flex-end;margin-top:8px}
.hints{margin:12px 0 0;padding-left:18px;color:var(--muted);font-size:12.5px;line-height:1.9}
.hints .warn{color:#f59e0b}
.err{color:#ef4444;font-size:12.5px;margin:-4px 0 10px}

@media (max-width:1240px){.kpis,.sumbar{grid-template-columns:repeat(2,minmax(0,1fr))}.grid3{grid-template-columns:repeat(2,minmax(0,1fr))}.grid3>:first-child{grid-row:span 2}}
@media (max-width:900px){.charts{grid-template-columns:1fr}}
@media (max-width:760px){.grid3{grid-template-columns:1fr}.grid3>:first-child{grid-row:auto}}
@media (max-width:640px){
  .wrap{padding:14px 16px 24px}
  .kpis{grid-template-columns:1fr}
  .sumbar{gap:10px}
  .stat{padding:12px 14px;gap:10px}
  .stat .ico{width:32px;height:32px}
  .stat b{font-size:16px}
  .nodes{grid-template-columns:1fr}
  .hide-sm,.btn .t{display:none!important}
  body.ov #status{display:none}
  .cmd{display:none}
  .bar{width:40px}
  .cellbar span{min-width:0}
  .chart{height:180px}
  .section-head{margin-top:22px}
}
</style>
</head>
<body>
<div class="wrap">

<header class="top">
  <div class="brand">
    <a class="icon-btn back" id="backBtn" href="#/" title="返回服务器列表" aria-label="返回服务器列表" hidden><svg class="i" viewBox="0 0 24 24"><path d="m15 18-6-6 6-6"/></svg></a>
    <div class="logo" id="logo"><svg class="i" viewBox="0 0 24 24"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg></div>
    <div class="brand-text">
      <h1 class="host" id="title">VPS Probe</h1>
      <div class="sub" id="subtitle">正在连接…</div>
    </div>
  </div>
  <div class="actions">
    <span class="pill" id="status"><span class="dot"></span><span id="statusText">连接中</span></span>
    <span class="pill hide-sm" id="uptimePill" hidden><svg class="i" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg><span id="uptime">—</span></span>
    <button class="btn primary" id="addBtn" type="button" data-act="add" hidden><svg class="i" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg><span class="t">添加服务器</span></button>
    <button class="icon-btn" id="setBtn" type="button" data-act="settings" title="服务器设置" aria-label="服务器设置" hidden><svg class="i" viewBox="0 0 24 24"><path d="M21 4h-7M10 4H3M21 12h-9M8 12H3M21 20h-5M12 20H3M14 2v4M8 10v4M16 18v4"/></svg></button>
    <button class="icon-btn" id="themeBtn" type="button" title="切换深色 / 浅色主题" aria-label="切换主题"></button>
  </div>
</header>

<main id="vOverview" hidden>
  <div class="banner warn" id="ovBanner" hidden></div>
  <section class="sumbar">
    <article class="card stat"><span class="ico" style="--c:#6366f1"><svg class="i" viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="8" rx="2"/><rect x="2" y="13" width="20" height="8" rx="2"/><path d="M6 7h.01M6 17h.01"/></svg></span><div><small>在线服务器</small><b id="sOnline">—</b></div></article>
    <article class="card stat"><span class="ico" style="--c:#10b981"><svg class="i" viewBox="0 0 24 24"><path d="M12 5v14M5 12l7 7 7-7"/></svg></span><div><small>实时下行 · 合计</small><b id="sRx">—</b></div></article>
    <article class="card stat"><span class="ico" style="--c:#3b82f6"><svg class="i" viewBox="0 0 24 24"><path d="M12 19V5M5 12l7-7 7 7"/></svg></span><div><small>实时上行 · 合计</small><b id="sTx">—</b></div></article>
    <article class="card stat"><span class="ico" style="--c:#f59e0b"><svg class="i" viewBox="0 0 24 24"><path d="M3 3v18h18"/><path d="m7 15 4-4 3 3 5-6"/></svg></span><div><small>本周期流量 · 合计</small><b id="sTraffic">—</b></div></article>
  </section>
  <div class="section-head"><h2>服务器</h2><span class="muted" id="ovHint"></span></div>
  <section class="nodes" id="nodeGrid"></section>
</main>

<main id="vDetail" class="loading" hidden>
  <div class="banner" id="offBanner" hidden></div>
  <section class="card waitcard" id="waitCard" hidden>
    <span class="ico" style="--c:#f59e0b"><svg class="i" viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg></span>
    <h3>等待接入</h3>
    <p class="muted">这台服务器还没有上报过数据。在它上面以 root 身份执行下面的命令，几秒后就会自动显示监控数据。</p>
    <div class="waitcmd" id="waitCmd"></div>
  </section>

  <div id="detailBody">
  <section class="kpis">
    <article class="card kpi">
      <div class="kpi-head">
        <span class="kpi-title"><span class="ico" style="--c:#3b82f6"><svg class="i" viewBox="0 0 24 24"><rect x="5" y="5" width="14" height="14" rx="2"/><rect x="9" y="9" width="6" height="6" rx="1"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/></svg></span>CPU</span>
        <span class="badge" id="cpuCores">—</span>
      </div>
      <div class="kpi-body">
        <div class="ring" id="ringCpu"></div>
        <dl class="kv">
          <div><dt>负载</dt><dd id="cpuLoad">—</dd></div>
          <div><dt>用户 / 系统</dt><dd id="cpuUS">—</dd></div>
          <div><dt>等待 / 窃取</dt><dd id="cpuWS">—</dd></div>
        </dl>
      </div>
    </article>
    <article class="card kpi">
      <div class="kpi-head">
        <span class="kpi-title"><span class="ico" style="--c:#8b5cf6"><svg class="i" viewBox="0 0 24 24"><rect x="2" y="6" width="20" height="12" rx="2"/><path d="M6 10v4M10 10v4M14 10v4M18 10v4"/></svg></span>内存</span>
        <span class="badge" id="memTotal">—</span>
      </div>
      <div class="kpi-body">
        <div class="ring" id="ringMem"></div>
        <dl class="kv">
          <div><dt>已用</dt><dd id="memUsed">—</dd></div>
          <div><dt>缓存</dt><dd id="memCache">—</dd></div>
          <div><dt>Swap</dt><dd id="memSwap">—</dd></div>
        </dl>
      </div>
    </article>
    <article class="card kpi">
      <div class="kpi-head">
        <span class="kpi-title"><span class="ico" style="--c:#14b8a6"><svg class="i" viewBox="0 0 24 24"><path d="M22 12H2"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/><path d="M6 16h.01M10 16h.01"/></svg></span>磁盘</span>
        <span class="badge" id="diskBadge">—</span>
      </div>
      <div class="kpi-body">
        <div class="ring" id="ringDisk"></div>
        <dl class="kv">
          <div><dt>已用</dt><dd id="diskUsed">—</dd></div>
          <div><dt>可用</dt><dd id="diskFree">—</dd></div>
          <div><dt>读 / 写</dt><dd id="diskIO">—</dd></div>
        </dl>
      </div>
    </article>
    <article class="card kpi">
      <div class="kpi-head">
        <span class="kpi-title"><span class="ico" style="--c:#10b981"><svg class="i" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg></span>网络</span>
        <span class="badge" id="netBadge">—</span>
      </div>
      <div class="kpi-body">
        <div class="netbig">
          <div class="rate"><span class="arr" style="--c:#10b981"><svg class="i" viewBox="0 0 24 24"><path d="M12 5v14M5 12l7 7 7-7"/></svg></span><div><b id="netRx">—</b><small>下行</small></div></div>
          <div class="rate"><span class="arr" style="--c:#3b82f6"><svg class="i" viewBox="0 0 24 24"><path d="M12 19V5M5 12l7-7 7 7"/></svg></span><div><b id="netTx">—</b><small>上行</small></div></div>
        </div>
        <dl class="kv">
          <div><dt>本周期 ↓</dt><dd id="netCRx">—</dd></div>
          <div><dt>本周期 ↑</dt><dd id="netCTx">—</dd></div>
          <div><dt>TCP 连接</dt><dd id="netConn">—</dd></div>
        </dl>
      </div>
    </article>
  </section>

  <div class="section-head">
    <h2>性能趋势</h2>
    <div class="seg" id="rangeSeg"><button type="button" class="on" data-range="live">实时 · 10 分钟</button><button type="button" data-range="day">24 小时</button></div>
  </div>
  <section class="charts">
    <article class="card"><div class="chart-head"><h3>CPU 使用率</h3><div class="legend" id="lgCpu"></div></div><div class="chart" id="chCpu"></div></article>
    <article class="card"><div class="chart-head"><h3>内存</h3><div class="legend" id="lgMem"></div></div><div class="chart" id="chMem"></div></article>
    <article class="card"><div class="chart-head"><h3>网络流量</h3><div class="legend" id="lgNet"></div></div><div class="chart" id="chNet"></div></article>
    <article class="card"><div class="chart-head"><h3>磁盘 IO</h3><div class="legend" id="lgIo"></div></div><div class="chart" id="chIo"></div></article>
  </section>

  <div class="section-head"><h2>详细信息</h2></div>
  <section class="grid3">
    <article class="card">
      <div class="card-head"><h3>系统信息</h3></div>
      <dl class="info" id="sysinfo"></dl>
    </article>
    <article class="card">
      <div class="card-head"><h3>网络</h3><span class="right muted" id="cycleSince"></span></div>
      <div class="tiles">
        <div class="tile"><div class="l"><i class="sw" style="background:#10b981"></i>本周期下行</div><div class="v" id="tRx">—</div></div>
        <div class="tile"><div class="l"><i class="sw" style="background:#3b82f6"></i>本周期上行</div><div class="v" id="tTx">—</div></div>
        <div class="tile"><div class="l">本周期合计</div><div class="v" id="tSum">—</div></div>
      </div>
      <div class="sublabel">连接</div>
      <div class="chips">
        <span class="chip">TCP<b id="cTcp">—</b></span><span class="chip">已建立<b id="cEst">—</b></span><span class="chip">TIME_WAIT<b id="cTw">—</b></span><span class="chip">UDP<b id="cUdp">—</b></span>
      </div>
      <div class="sublabel">网卡</div>
      <div class="tbl-wrap"><table class="tbl"><thead><tr><th>接口</th><th class="r">下行</th><th class="r">上行</th><th class="r">开机以来 ↓ / ↑</th></tr></thead><tbody id="ifBody"></tbody></table></div>
      <p class="note" id="netNote"></p>
    </article>
    <article class="card">
      <div class="card-head"><h3>磁盘分区</h3></div>
      <div id="disks"></div>
    </article>
  </section>

  <section class="card procs">
    <div class="card-head">
      <h3>进程</h3><span class="muted" id="procSummary"></span>
      <div class="seg sm right" id="procSeg"><button type="button" class="on" data-sort="cpu">按 CPU</button><button type="button" data-sort="mem">按内存</button></div>
    </div>
    <div class="tbl-wrap"><table class="tbl"><thead><tr><th>PID</th><th>进程</th><th class="r">CPU</th><th class="r">内存</th><th class="r hide-sm">线程</th></tr></thead><tbody id="procBody"></tbody></table></div>
  </section>
  </div>
</main>

<footer class="foot"><span id="footL">VPS Probe</span><span id="footR"></span></footer>
</div>

<dialog id="dlg" aria-labelledby="dlgTitle"></dialog>

<script>
(function(){
'use strict';
const $ = id => document.getElementById(id);
const FIELDS = ['t','cpu','steal','iowait','mem','cache','swap','rx','tx','rd','wr'];
const COL = {cpu:'#3b82f6',steal:'#f43f5e',iowait:'#f59e0b',mem:'#8b5cf6',cache:'#06b6d4',swap:'#f59e0b',
             rx:'#10b981',tx:'#3b82f6',rd:'#f59e0b',wr:'#ec4899',disk:'#14b8a6',warn:'#f59e0b',crit:'#ef4444'};
const FONT = getComputedStyle(document.body).fontFamily;
const RING_C = 2 * Math.PI * 34;
// 基于 location.origin 拼接 API 地址：用 user:pass@host 打开面板时，相对地址会带上账号密码，fetch 会直接拒绝
const BASE = location.origin + location.pathname.replace(/[^/]*$/, '').replace(/\/$/, '');
const api = p => BASE + '/api/' + p;
const ICON = {
  sun:'<svg class="i" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>',
  moon:'<svg class="i" viewBox="0 0 24 24"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg>',
  copy:'<svg class="i" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
  x:'<svg class="i" viewBox="0 0 24 24"><path d="M18 6 6 18M6 6l12 12"/></svg>',
  plus:'<svg class="i" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>'
};
const state = {view:'', node:'', meta:null, manage:false, interval:2, memTotal:0, cores:1, range:'live', sort:'cpu', dayAt:0, last:null, loop:null};
let store = {live:blank(), day:blank()};
let PAL = {};

function blank(){ const o = {}; FIELDS.forEach(k => o[k] = []); return o; }

/* ---------- 格式化 ---------- */
const UNITS = ['B','KB','MB','GB','TB','PB'];
function fmtB(b){
  if (b == null || !isFinite(b)) return '—';
  let i = 0; b = Number(b);
  while (Math.abs(b) >= 1024 && i < UNITS.length - 1) { b /= 1024; i++; }
  return (i === 0 ? Math.round(b) : b.toFixed(b >= 100 ? 0 : 1)) + ' ' + UNITS[i];
}
const fmtR = b => fmtB(b) + '/s';
const fmtP = p => (p == null || !isFinite(p) ? '—' : Number(p).toFixed(1) + '%');
const fmtAxis = v => fmtB(v).replace('.0 ', ' ');
const pad = n => String(n).padStart(2, '0');
function fmtTime(t, mode){
  const d = new Date(t * 1000), hm = pad(d.getHours()) + ':' + pad(d.getMinutes());
  if (mode === 's') return hm + ':' + pad(d.getSeconds());
  if (mode === 'd') return pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + hm;
  return hm;
}
function fmtDate(t){ const d = new Date(t * 1000); return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()); }
function fmtDur(s){
  s = Math.max(0, Math.floor(s));
  const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  if (d) return d + ' 天 ' + h + ' 小时';
  if (h) return h + ' 小时 ' + m + ' 分';
  return m + ' 分 ' + (s % 60) + ' 秒';
}
function fmtAgo(t){
  const s = Math.max(0, Date.now() / 1000 - t);
  if (s < 60) return '刚刚';
  if (s < 3600) return Math.floor(s / 60) + ' 分钟前';
  if (s < 86400) return Math.floor(s / 3600) + ' 小时前';
  return Math.floor(s / 86400) + ' 天前';
}
const lvl = p => p >= 90 ? 'crit' : p >= 70 ? 'warn' : 'ok';
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function rgba(h, a){ const n = parseInt(h.slice(1), 16); return 'rgba(' + (n >> 16 & 255) + ',' + (n >> 8 & 255) + ',' + (n & 255) + ',' + a + ')'; }
function nice(max, base){
  let u = 1;
  if (base === 1024) while (max / u >= 1024) u *= 1024;
  const raw = max / u / 4, e = Math.pow(10, Math.floor(Math.log10(raw))), f = raw / e;
  const step = (f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10) * e * u;
  return [Math.ceil(max / step - 1e-9) * step, step];
}
function nearest(a, v, lo){
  const base = lo; let hi = a.length - 1;
  if (hi < lo) return -1;
  while (lo < hi) { const m = (lo + hi) >> 1; if (a[m] < v) lo = m + 1; else hi = m; }
  if (lo > base && Math.abs(a[lo - 1] - v) < Math.abs(a[lo] - v)) lo--;
  return lo;
}

/* ---------- 主题 ---------- */
function readPalette(){
  const cs = getComputedStyle(document.documentElement), g = k => cs.getPropertyValue(k).trim();
  PAL = {grid:g('--grid'), faint:g('--faint'), cross:g('--border-strong'), panel:g('--panel'), dark:document.documentElement.dataset.theme !== 'light'};
}
function applyTheme(t){
  document.documentElement.dataset.theme = t;
  $('themeBtn').innerHTML = t === 'dark' ? ICON.sun : ICON.moon;
  readPalette();
  Object.values(charts).forEach(c => c.draw());
}
$('themeBtn').addEventListener('click', () => {
  const t = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  try { localStorage.setItem('probe-theme', t); } catch (e) {}
  applyTheme(t);
});
try {
  matchMedia('(prefers-color-scheme: light)').addEventListener('change', e => {
    let saved = null; try { saved = localStorage.getItem('probe-theme'); } catch (_) {}
    if (!saved) applyTheme(e.matches ? 'light' : 'dark');
  });
} catch (e) {}

/* ---------- 折线图（原生 Canvas，无第三方依赖） ---------- */
class Chart {
  constructor(el, legend, o){
    this.el = el; this.lg = legend; this.o = o; this.d = null; this.hx = null; this.w = 0;
    this.cv = document.createElement('canvas'); this.ctx = this.cv.getContext('2d');
    this.tip = document.createElement('div'); this.tip.className = 'tip';
    el.append(this.cv, this.tip);
    const pos = e => { const r = this.cv.getBoundingClientRect(), p = e.touches ? e.touches[0] : e; this.hx = p.clientX - r.left; this.draw(); };
    const out = () => { this.hx = null; this.draw(); };
    this.cv.addEventListener('mousemove', pos);
    this.cv.addEventListener('mouseleave', out);
    this.cv.addEventListener('touchstart', pos, {passive:true});
    this.cv.addEventListener('touchmove', pos, {passive:true});
    this.cv.addEventListener('touchend', out);
    if (window.ResizeObserver) new ResizeObserver(() => this.resize()).observe(el);
    else addEventListener('resize', () => this.resize());
    this.resize();
  }
  resize(){
    const w = this.el.clientWidth, h = this.el.clientHeight, r = window.devicePixelRatio || 1;
    if (!w || !h) return;
    this.w = w; this.h = h;
    this.cv.width = Math.round(w * r); this.cv.height = Math.round(h * r);
    this.cv.style.width = w + 'px'; this.cv.style.height = h + 'px';
    this.ctx.setTransform(r, 0, 0, r, 0, 0);
    this.draw();
  }
  set(d, span, step, mode){
    this.d = d; this.span = span; this.step = step; this.mode = mode;
    const n = d.t.length, o = this.o;
    if (this.lg) this.lg.innerHTML = o.series.map(s => '<span><i style="background:' + COL[s.color] + '"></i>' + s.name + '<b>' + (n ? o.vfmt(d[s.key][n - 1]) : '—') + '</b></span>').join('');
    this.draw();
  }
  draw(){
    const {ctx, w, h, o, d} = this;
    if (!w || !d) return;
    ctx.clearRect(0, 0, w, h);
    const t = d.t, n = t.length;
    const t1 = n ? t[n - 1] : Date.now() / 1000, t0 = t1 - this.span;
    let i0 = 0; while (i0 < n && t[i0] < t0) i0++;

    let vmax = 0;
    for (const s of o.series) { const a = d[s.key]; for (let i = i0; i < n; i++) if (a[i] > vmax) vmax = a[i]; }
    let top, step;
    if (o.max) { top = o.max; step = o.max / 4; }
    else { const fl = typeof o.floor === 'function' ? o.floor() : (o.floor || 1); [top, step] = nice(Math.max(vmax * 1.15, fl), o.base); }
    const ticks = []; for (let k = 0; k * step <= top * 1.0001; k++) ticks.push(k * step);

    ctx.font = '11px ' + FONT;
    const labels = ticks.map(o.fmt);
    const L = Math.ceil(Math.max.apply(null, labels.map(s => ctx.measureText(s).width))) + 12, R = 6, T = 8, B = 24;
    const cw = w - L - R, ch = h - T - B;
    const X = v => L + (v - t0) / this.span * cw, Y = v => T + ch - v / top * ch;

    ctx.lineWidth = 1; ctx.strokeStyle = PAL.grid; ctx.fillStyle = PAL.faint;
    ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
    ticks.forEach((v, k) => {
      const y = Math.round(Y(v)) + .5;
      ctx.beginPath(); ctx.moveTo(L, y); ctx.lineTo(w - R, y); ctx.stroke();
      ctx.fillText(labels[k], L - 8, y);
    });
    ctx.textAlign = 'center'; ctx.textBaseline = 'alphabetic';
    const xs = this.span <= 900 ? 120 : 14400, tz = new Date().getTimezoneOffset() * 60;
    for (let v = Math.ceil((t0 - tz) / xs) * xs + tz; v <= t1; v += xs) {
      const x = X(v); if (x < L + 18 || x > w - R - 18) continue;
      ctx.fillText(fmtTime(v), x, h - 6);
    }

    if (i0 >= n) {
      ctx.textBaseline = 'middle'; ctx.font = '12px ' + FONT;
      ctx.fillText(this.mode === 'd' ? '数据收集中，探针运行一段时间后显示' : '等待数据…', L + cw / 2, T + ch / 2);
      this.tip.style.opacity = 0; return;
    }

    const gap = this.step * 3.5;
    ctx.save(); ctx.beginPath(); ctx.rect(L, T - 2, cw + 2, ch + 3); ctx.clip();
    for (const s of o.series) {
      const a = d[s.key], c = COL[s.color], segs = []; let seg = [];
      for (let i = i0; i < n; i++) {
        if (seg.length && t[i] - t[i - 1] > gap) { segs.push(seg); seg = []; }
        seg.push([X(t[i]), Y(a[i])]);
      }
      if (seg.length) segs.push(seg);
      for (const sg of segs) {
        if (s.fill && sg.length > 1) {
          const g = ctx.createLinearGradient(0, T, 0, T + ch);
          g.addColorStop(0, rgba(c, PAL.dark ? .30 : .20)); g.addColorStop(1, rgba(c, 0));
          ctx.beginPath(); ctx.moveTo(sg[0][0], T + ch);
          sg.forEach(p => ctx.lineTo(p[0], p[1]));
          ctx.lineTo(sg[sg.length - 1][0], T + ch); ctx.closePath();
          ctx.fillStyle = g; ctx.fill();
        }
        ctx.beginPath(); sg.forEach((p, k) => k ? ctx.lineTo(p[0], p[1]) : ctx.moveTo(p[0], p[1]));
        ctx.strokeStyle = c; ctx.lineWidth = s.fill ? 1.8 : 1.3; ctx.lineJoin = 'round'; ctx.lineCap = 'round'; ctx.stroke();
      }
    }
    ctx.restore();

    let hi = -1;
    if (this.hx != null && this.hx >= L && this.hx <= w - R) hi = nearest(t, t0 + (this.hx - L) / cw * this.span, i0);
    if (hi < 0) { this.tip.style.opacity = 0; return; }
    const x = Math.round(X(t[hi])) + .5;
    ctx.strokeStyle = PAL.cross; ctx.setLineDash([3, 3]);
    ctx.beginPath(); ctx.moveTo(x, T); ctx.lineTo(x, T + ch); ctx.stroke(); ctx.setLineDash([]);
    for (const s of o.series) {
      ctx.beginPath(); ctx.arc(x, Y(d[s.key][hi]), 3.5, 0, Math.PI * 2);
      ctx.fillStyle = COL[s.color]; ctx.fill(); ctx.lineWidth = 2; ctx.strokeStyle = PAL.panel; ctx.stroke();
    }
    this.tip.innerHTML = '<div class="tt">' + fmtTime(t[hi], this.mode) + '</div>' + o.series.map(s =>
      '<div class="tr"><i style="background:' + COL[s.color] + '"></i><span>' + s.name + '</span><b>' + o.vfmt(d[s.key][hi]) + '</b></div>').join('');
    const tw = this.tip.offsetWidth; let lx = x + 14;
    if (lx + tw > w) lx = x - 14 - tw;
    this.tip.style.left = Math.max(0, lx) + 'px'; this.tip.style.top = T + 'px'; this.tip.style.opacity = 1;
  }
}

/* ---------- 环形仪表 ---------- */
function mkRing(id, color){
  const el = $(id), c = RING_C.toFixed(2);
  el.innerHTML = '<svg viewBox="0 0 80 80"><circle class="bg" cx="40" cy="40" r="34"/><circle class="fg" cx="40" cy="40" r="34" stroke-dasharray="' + c + '" stroke-dashoffset="' + c + '" stroke="' + color + '"/></svg><div class="ring-val"><span>0</span><small>%</small></div>';
  return {fg:el.querySelector('.fg'), v:el.querySelector('span'), c:color};
}
function setRing(r, p){
  p = Math.max(0, Math.min(100, +p || 0));
  r.fg.style.strokeDashoffset = (RING_C * (1 - p / 100)).toFixed(2);
  const l = lvl(p); r.fg.style.stroke = l === 'ok' ? r.c : COL[l];
  r.v.textContent = p < 10 ? p.toFixed(1) : Math.round(p);
}
const rings = {cpu:mkRing('ringCpu', COL.cpu), mem:mkRing('ringMem', COL.mem), disk:mkRing('ringDisk', COL.disk)};

readPalette();
$('themeBtn').innerHTML = PAL.dark ? ICON.sun : ICON.moon;
const charts = {
  cpu: new Chart($('chCpu'), $('lgCpu'), {max:100, fmt:v => Math.round(v) + '%', vfmt:fmtP,
    series:[{key:'cpu', name:'使用率', color:'cpu', fill:1}, {key:'iowait', name:'IO 等待', color:'iowait'}, {key:'steal', name:'窃取', color:'steal'}]}),
  mem: new Chart($('chMem'), $('lgMem'), {base:1024, floor:() => state.memTotal || 1048576, fmt:fmtAxis, vfmt:v => fmtB(v),
    series:[{key:'mem', name:'已用', color:'mem', fill:1}, {key:'cache', name:'缓存', color:'cache'}, {key:'swap', name:'Swap', color:'swap'}]}),
  net: new Chart($('chNet'), $('lgNet'), {base:1024, floor:1024, fmt:v => fmtAxis(v) + '/s', vfmt:fmtR,
    series:[{key:'rx', name:'下行', color:'rx', fill:1}, {key:'tx', name:'上行', color:'tx', fill:1}]}),
  io: new Chart($('chIo'), $('lgIo'), {base:1024, floor:1024, fmt:v => fmtAxis(v) + '/s', vfmt:fmtR,
    series:[{key:'rd', name:'读取', color:'rd', fill:1}, {key:'wr', name:'写入', color:'wr', fill:1}]}),
};
function drawCharts(){
  const live = state.range === 'live';
  Object.values(charts).forEach(c => c.set(store[state.range], live ? 600 : 86400, live ? state.interval : 60, live ? 's' : 'd'));
}

/* ---------- 网络请求：每个请求都有超时，切换页面时可整体取消 ---------- */
async function getJSON(u, signal){
  const c = new AbortController(), timer = setTimeout(() => c.abort(), 10000);
  const relay = () => c.abort();
  if (signal) { if (signal.aborted) c.abort(); else signal.addEventListener('abort', relay); }
  try {
    const r = await fetch(u, {cache:'no-store', credentials:'same-origin', signal:c.signal});
    if (!r.ok) { const e = new Error('HTTP ' + r.status); e.status = r.status; throw e; }
    return await r.json();
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener('abort', relay);
  }
}
async function send(method, u, body){
  const c = new AbortController(), timer = setTimeout(() => c.abort(), 15000);
  try {
    const r = await fetch(u, {method:method, credentials:'same-origin', headers:{'Content-Type':'application/json'},
                              body:JSON.stringify(body || {}), signal:c.signal});
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
    return j;
  } catch (e) {
    throw e.name === 'AbortError' ? new Error('请求超时') : e;
  } finally { clearTimeout(timer); }
}
function setStatus(cls, text){ $('status').className = 'pill ' + cls; $('statusText').textContent = text; }

/* ---------- 轮询：同一时间只有一个有效轮询；页面不可见时暂停，省服务器资源 ---------- */
let loopId = 0, loopCtrl = null;
function stopLoop(){
  loopId++;
  if (loopCtrl) { loopCtrl.abort(); loopCtrl = null; }
}
function start(fn, iv){
  stopLoop();
  state.loop = [fn, iv];
  const id = loopId, ctrl = loopCtrl = new AbortController();
  let first = true;
  (async function run(){
    if (id !== loopId || (document.hidden && !first)) return;
    first = false;
    try { await fn(id, ctrl.signal); } catch (e) { if (e.name !== 'AbortError') console.error(e); }
    if (id === loopId) setTimeout(run, iv() * 1000);
  })();
}
function refresh(){ if (state.loop) start(state.loop[0], state.loop[1]); }

/* ---------- 总览 ---------- */
function meter(label, pct, value, title, color){
  const p = Math.max(0, Math.min(100, +pct || 0)), l = lvl(p);
  return '<div class="meter" title="' + esc(title) + '"><span class="ml">' + label + '</span><div class="bar"><i style="width:' + p.toFixed(1) + '%;--c:' +
    (l === 'ok' ? color : COL[l]) + '"></i></div><span class="mv">' + value + '</span></div>';
}
function nodeCard(n){
  const st = n.online ? 'on' : n.reported ? 'off' : 'wait', I = n.info || {};
  const sub = n.reported ? [I.os, I.virt].filter(Boolean).join(' · ') : '等待接入';
  let h = '<a class="card node ' + st + '" href="#/s/' + encodeURIComponent(n.id) + '"><div class="node-head"><span class="sdot ' + st + '"></span><div class="node-name"><b>' +
    esc(n.name) + '</b><span>' + esc(sub) + '</span></div>' + (n.local ? '<span class="badge">本机</span>' : '') + '</div>';
  if (!n.reported) return h + '<div class="node-empty">还没有收到这台服务器的数据<span>点击查看安装命令 →</span></div></a>';
  const on = n.online, mem = n.mem || [0, 0], memP = mem[1] ? mem[0] / mem[1] * 100 : 0, d = n.disk, cy = n.cycle || [0, 0];
  h += '<div class="meters">' +
    meter('CPU', on ? n.cpu : 0, on ? fmtP(n.cpu) : '—', '', COL.cpu) +
    meter('内存', memP, fmtP(memP), fmtB(mem[0]) + ' / ' + fmtB(mem[1]), COL.mem) +
    (d ? meter('磁盘', d[2], fmtP(d[2]), fmtB(d[0]) + ' / ' + fmtB(d[1]), COL.disk) : '') + '</div>';
  h += '<div class="node-stats"><div><small>↓ 下行</small><b>' + (on ? fmtR(n.rx) : '—') + '</b></div><div><small>↑ 上行</small><b>' + (on ? fmtR(n.tx) : '—') +
    '</b></div><div><small>本周期流量</small><b>' + fmtB(cy[0] + cy[1]) + '</b></div></div>';
  h += '<div class="node-foot"><span>' + (on ? '已运行 ' + fmtDur(n.uptime) : '离线 · ' + fmtAgo(n.last_seen)) + '</span><span>' +
    (I.cores ? Number(I.cores) + ' 核 · ' : '') + '负载 ' + Number(n.load || 0).toFixed(2) + '</span></div></a>';
  return h;
}
function renderOverview(r){
  state.manage = !!r.manage;
  const ns = r.nodes || [], on = ns.filter(n => n.online), warn = r.warnings || [];
  setStatus(on.length === ns.length ? 'online' : on.length ? 'partial' : 'offline', on.length + ' / ' + ns.length + ' 在线');
  $('subtitle').textContent = '服务器总览 · 共 ' + ns.length + ' 台';
  $('ovBanner').hidden = !warn.length;
  $('ovBanner').textContent = warn.join('；');
  $('sOnline').textContent = on.length + ' / ' + ns.length;
  $('sRx').textContent = fmtR(on.reduce((a, n) => a + (n.rx || 0), 0));
  $('sTx').textContent = fmtR(on.reduce((a, n) => a + (n.tx || 0), 0));
  $('sTraffic').textContent = fmtB(ns.reduce((a, n) => a + (n.cycle ? n.cycle[0] + n.cycle[1] : 0), 0));
  $('ovHint').textContent = state.manage ? '点击卡片查看详情' : '未设置访问密码，仅可查看';
  $('nodeGrid').innerHTML = ns.map(nodeCard).join('') +
    '<button type="button" class="card node add" data-act="add"><span class="plus">' + ICON.plus + '</span>添加服务器</button>';
  $('footL').textContent = 'VPS Probe v' + r.version + '  ·  单文件 · 零依赖';
  $('footR').textContent = '更新于 ' + fmtTime(Date.now() / 1000, 's');
}
async function pollNodes(id, signal){
  let r;
  try { r = await getJSON(api('nodes'), signal); }
  catch (e) { if (id === loopId) setStatus('offline', '连接中断'); return; }
  if (id === loopId && state.view === 'overview') renderOverview(r);
}

/* ---------- 单台服务器详情 ---------- */
function renderDetail(s){
  const nd = s.node;
  state.meta = nd; state.manage = !!s.manage;
  $('title').textContent = nd.name; document.title = nd.name + ' · VPS Probe';
  $('vDetail').classList.remove('loading');
  if (!s.info) {
    setStatus('partial', '等待接入');
    $('subtitle').textContent = '还没有收到这台服务器的数据';
    $('uptimePill').hidden = true; $('detailBody').hidden = true; $('offBanner').hidden = true; $('waitCard').hidden = false;
    $('footR').textContent = '添加于本面板，等待首次上报';
    renderWaiting(nd);
    return;
  }
  $('waitCard').hidden = true; $('detailBody').hidden = false; $('uptimePill').hidden = false;
  setStatus(nd.online ? 'online' : 'offline', nd.online ? '在线' : '离线');
  $('offBanner').hidden = nd.online;
  if (!nd.online) $('offBanner').textContent = '这台服务器已离线，最后上报于 ' + fmtDate(nd.last_seen) + '（' + fmtAgo(nd.last_seen) + '），下面显示的是最后一次的数据。';
  renderMetrics(s);
  if (nd.online) appendLive(s);
  if (state.range === 'live') drawCharts();
  else if (Date.now() - state.dayAt > 60000) loadHistory('day');
}

function renderMetrics(s){
  const I = s.info, nd = s.node, cpu = s.cpu, m = s.mem, n = s.net, c = s.conn;
  state.interval = s.probe.interval || 2; state.memTotal = m.total; state.cores = I.cores || 1;
  $('subtitle').textContent = [I.hostname !== nd.name ? I.hostname : '', I.os, I.kernel, I.arch, I.virt].filter(Boolean).join('  ·  ');
  $('uptime').textContent = '已运行 ' + fmtDur(s.uptime);

  setRing(rings.cpu, cpu.pct);
  $('cpuCores').textContent = I.cores + ' 核';
  $('cpuLoad').textContent = cpu.load.length ? cpu.load.map(x => Number(x).toFixed(2)).join(' / ') : '—';
  $('cpuUS').textContent = fmtP(cpu.user) + ' / ' + fmtP(cpu.system);
  $('cpuWS').textContent = fmtP(cpu.iowait) + ' / ' + fmtP(cpu.steal);

  setRing(rings.mem, m.total ? m.used / m.total * 100 : 0);
  $('memTotal').textContent = '共 ' + fmtB(m.total);
  $('memUsed').textContent = fmtB(m.used);
  $('memCache').textContent = fmtB(m.cache);
  $('memSwap').textContent = m.swap_total ? fmtB(m.swap_used) + ' / ' + fmtB(m.swap_total) : '未启用';

  const root = s.disks.find(d => d.mount === '/') || s.disks[0];
  if (root) {
    setRing(rings.disk, root.pct);
    $('diskBadge').textContent = root.mount + ' · 共 ' + fmtB(root.total);
    $('diskUsed').textContent = fmtB(root.used);
    $('diskFree').textContent = fmtB(root.free);
  }
  $('diskIO').textContent = fmtR(s.io.read) + ' / ' + fmtR(s.io.write);

  const main = n.ifaces.slice().sort((a, b) => (b.rx_total + b.tx_total) - (a.rx_total + a.tx_total))[0];
  $('netBadge').textContent = main ? main.name : '—';
  $('netRx').textContent = fmtR(n.rx);
  $('netTx').textContent = fmtR(n.tx);
  $('netCRx').textContent = fmtB(n.cycle_rx);
  $('netCTx').textContent = fmtB(n.cycle_tx);
  $('netConn').textContent = c.established + ' / ' + c.tcp;

  renderInfo(s); renderNet(s); renderDisks(s); renderProcs(s);
  $('footL').textContent = 'VPS Probe v' + I.version + '  ·  单文件 · 零依赖';
  $('footR').textContent = '采样间隔 ' + state.interval + 's  ·  更新于 ' + fmtTime(s.ts, 's');
}

function renderInfo(s){
  const I = s.info, p = s.proc;
  const rows = [
    ['主机名', I.hostname], ['操作系统', I.os], ['内核', I.kernel + ' (' + I.arch + ')'], ['虚拟化', I.virt],
    ['处理器', I.cpu_model], ['核心数', I.cores + ' 核'], ['启动时间', fmtDate(s.ts - s.uptime)],
    ['运行时长', fmtDur(s.uptime)], ['进程 / 线程', p.count + ' / ' + p.threads],
    ['探针', 'v' + I.version + ' · Python ' + I.python + ' · 占用 ' + fmtB(s.probe.rss)]
  ];
  $('sysinfo').innerHTML = rows.map(r => '<div><dt>' + r[0] + '</dt><dd>' + esc(r[1]) + '</dd></div>').join('');
}

function renderNet(s){
  const n = s.net, c = s.conn, pc = n.prev_cycle;
  $('cycleSince').textContent = '统计周期自 ' + n.cycle_start + ' 起' + (pc ? ' · 上周期 ' + fmtB(pc.rx + pc.tx) : '');
  $('tRx').textContent = fmtB(n.cycle_rx);
  $('tTx').textContent = fmtB(n.cycle_tx);
  $('tSum').textContent = fmtB(n.cycle_rx + n.cycle_tx);
  $('cTcp').textContent = c.tcp; $('cEst').textContent = c.established;
  $('cTw').textContent = c.time_wait; $('cUdp').textContent = c.udp;
  $('ifBody').innerHTML = n.ifaces.length ? n.ifaces.map(i =>
    '<tr><td class="mono">' + esc(i.name) + '</td><td class="r">' + fmtR(i.rx) + '</td><td class="r">' + fmtR(i.tx) +
    '</td><td class="r muted">' + fmtB(i.rx_total) + ' / ' + fmtB(i.tx_total) + '</td></tr>').join('')
    : '<tr><td colspan="4" class="empty">没有检测到网卡</td></tr>';
  $('netNote').textContent = '统计口径：' + (n.iface_rule || '统计所有物理网卡') + '。可通过 PROBE_IFACES 指定网卡；数据仅供参考，不等同于服务商计费。';
}

function renderDisks(s){
  $('disks').innerHTML = s.disks.length ? s.disks.map(d => {
    const pct = Number(d.pct) || 0, l = lvl(pct), c = l === 'ok' ? COL.disk : COL[l];
    return '<div class="disk"><div class="disk-top"><span><span class="mp">' + esc(d.mount) + '</span><span class="fs">' + esc(d.fs) + ' · ' + esc(d.device) +
      '</span></span><span class="pct">' + pct.toFixed(1) + '%</span></div><div class="bar lg"><i style="width:' + pct + '%;--c:' + c +
      '"></i></div><div class="disk-bot"><span>已用 ' + fmtB(d.used) + '</span><span>可用 ' + fmtB(d.free) + ' / 共 ' + fmtB(d.total) + '</span></div></div>';
  }).join('') : '<div class="muted">没有检测到磁盘分区</div>';
}

function cellbar(text, pct, color){
  return '<div class="cellbar"><span>' + text + '</span><div class="bar"><i style="width:' + Math.min(100, Math.max(0, pct || 0)).toFixed(1) + '%;--c:' + color + '"></i></div></div>';
}
function renderProcs(s){
  const p = s.proc;
  $('procSummary').textContent = '共 ' + p.count + ' 个进程 · ' + p.threads + ' 个线程' + (p.running != null ? ' · ' + p.running + ' 个运行中' : '');
  const rows = state.sort === 'mem' ? p.top_mem : p.top_cpu, tb = $('procBody');
  if (!rows) {
    tb.innerHTML = '<tr><td colspan="5" class="empty">' + (state.meta && !state.meta.online ? '服务器离线' : '正在采集进程信息…') + '</td></tr>';
    return;
  }
  tb.innerHTML = rows.map(r => {
    const mp = state.memTotal ? r.rss / state.memTotal * 100 : 0, cpu = Number(r.cpu) || 0;
    const cmd = r.cmd ? esc(r.cmd) : '[内核线程]';
    return '<tr><td class="mono muted">' + (Number(r.pid) || 0) + '</td><td class="pn"><div><span class="pname">' + esc(r.name) + '</span><span class="cmd" title="' + cmd + '">' + cmd +
      '</span></div></td><td class="r">' + cellbar(cpu.toFixed(1) + '%', cpu / state.cores, COL.cpu) +
      '</td><td class="r">' + cellbar(fmtB(r.rss), mp, COL.mem) + '</td><td class="r hide-sm muted">' + (Number(r.threads) || 0) + '</td></tr>';
  }).join('');
}

async function renderWaiting(nd){
  const box = $('waitCmd');
  if (!state.manage) { box.innerHTML = '<p class="muted" style="text-align:center">面板未设置访问密码，无法显示安装命令。</p>'; box.dataset.node = ''; return; }
  if (box.dataset.node === nd.id) return;
  box.dataset.node = nd.id; box.innerHTML = '';
  try {
    const info = await getJSON(api('nodes/' + encodeURIComponent(nd.id) + '/secret'));
    if (state.node === nd.id) box.innerHTML = installBlock(info);
  } catch (e) { box.dataset.node = ''; box.innerHTML = '<p class="muted">获取安装命令失败：' + esc(e.message) + '</p>'; }
}

let histCtrl = null;
async function loadHistory(r){
  const node = state.node;
  if (histCtrl) histCtrl.abort();
  const ctrl = histCtrl = new AbortController();
  try {
    const j = await getJSON(api('history?node=' + encodeURIComponent(node) + '&range=' + r), ctrl.signal), o = {};
    if (node !== state.node) return;
    FIELDS.forEach(k => o[k] = j[k] || []);
    store[r] = o;
    if (r === 'day') state.dayAt = Date.now();
  } catch (e) { if (e.name !== 'AbortError') console.warn('history', e); }
  if (r === state.range && node === state.node) drawCharts();
}
function appendLive(s){
  const d = store.live, t = Math.floor(s.ts);
  if (d.t.length && t <= d.t[d.t.length - 1]) return;
  const p = {t:t, cpu:s.cpu.pct, steal:s.cpu.steal, iowait:s.cpu.iowait, mem:s.mem.used, cache:s.mem.cache, swap:s.mem.swap_used,
             rx:s.net.rx, tx:s.net.tx, rd:s.io.read, wr:s.io.write};
  FIELDS.forEach(k => d[k].push(p[k]));
  while (d.t.length && d.t[0] < t - 600) FIELDS.forEach(k => d[k].shift());
}
async function pollDetail(id, signal){
  const node = state.node;
  let s;
  try { s = await getJSON(api('stats?node=' + encodeURIComponent(node)), signal); }
  catch (e) {
    if (id !== loopId || e.name === 'AbortError') return;
    if (e.status === 404) { location.hash = '#/'; return; }
    setStatus('offline', '连接中断'); return;
  }
  // 只渲染“当前轮询 + 当前选中的服务器”的响应，切换服务器后旧响应一律丢弃
  if (id !== loopId || node !== state.node || !s.node || s.node.id !== node) return;
  state.last = s;
  renderDetail(s);
}

/* ---------- 路由 ---------- */
function showView(detail){
  $('vOverview').hidden = detail; $('vDetail').hidden = !detail;
  document.body.classList.toggle('ov', !detail);
  $('backBtn').hidden = !detail; $('logo').hidden = detail;
  $('addBtn').hidden = detail; $('setBtn').hidden = !detail;
  if (!detail) $('uptimePill').hidden = true;
}
function openOverview(){
  stopLoop();
  state.view = 'overview'; state.node = ''; state.meta = null;
  showView(false);
  $('title').textContent = 'VPS Probe'; document.title = '服务器总览 · VPS Probe';
  start(pollNodes, () => 2);
}
function openDetail(id){
  stopLoop();                       // 立即让旧的轮询和在途请求失效
  if (state.node !== id) {
    store = {live:blank(), day:blank()}; state.dayAt = 0; state.last = null; state.meta = null;
    $('vDetail').classList.add('loading'); $('title').textContent = '加载中…'; $('subtitle').textContent = '';
    $('waitCmd').dataset.node = ''; $('procBody').innerHTML = '';
    scrollTo(0, 0);
  }
  state.view = 'detail'; state.node = id;
  showView(true);
  drawCharts();
  const gen = loopId;
  loadHistory('live').then(() => {
    if (state.node !== id || loopId !== gen) return;
    start(pollDetail, () => state.interval);
    if (state.range === 'day') loadHistory('day');
  });
}
function route(){
  closeDlg();
  const m = location.hash.match(/^#\/s\/([\w-]+)$/);
  if (m) openDetail(m[1]); else openOverview();
}

/* ---------- 安装命令 ---------- */
const PLAIN_HTTP = location.protocol === 'http:' && !/^(localhost|127\.|\[::1\])/.test(location.hostname);
function installCmd(info, plainHttp){
  // 从面板下载与面板相同的 probe.py，校验 SHA-256 后安装；HTTP 面板需要先确认是可信网络
  return 'd=$(mktemp -d) && curl -fsSL ' + BASE + '/probe.py -o $d/probe.py && echo "' + info.sha256 + '  $d/probe.py" | sha256sum -c --quiet - && python3 $d/probe.py install --agent=' +
    BASE + ' --token=' + info.token + (plainHttp ? ' --allow-http' : '') + '; rm -rf $d';
}
const uninstallCmd = () => 'python3 /opt/vps-probe-agent/probe.py uninstall';
function cmdBlock(cmd){
  return '<div class="code">' + esc(cmd) + '</div><div class="row-end"><button type="button" class="btn" data-act="copy" data-text="' + esc(cmd) + '">' + ICON.copy + '<span>复制命令</span></button></div>';
}
function installBlock(info){
  const hints = '<ul class="hints"><li>以 root 身份执行（普通用户先运行 <code>sudo -i</code>）；需要 Python 3.8+ 和 systemd</li>' +
    '<li>下载的文件会先做 SHA-256 校验，不一致不会执行</li><li>子服务器不需要开放端口，执行完几秒后就会出现在面板上</li></ul>';
  if (!PLAIN_HTTP) return cmdBlock(installCmd(info, false)) + hints;
  return '<div class="warnbox"><b>面板正在使用 HTTP</b><p>安装文件、token 和监控数据都会以明文传输。公网环境请先给面板配置 HTTPS（参考项目文档 docs/guide.md），再从 HTTPS 地址打开面板添加服务器。</p>' +
    '<label class="check"><input type="checkbox" data-trust> 面板与这台服务器之间是可信网络（内网 / 专线 / VPN），允许使用 HTTP</label></div>' +
    '<div class="trusted" hidden>' + cmdBlock(installCmd(info, true)) + hints + '</div>';
}
document.addEventListener('change', e => {
  if (!e.target.matches('[data-trust]')) return;
  const box = e.target.closest('.warnbox').nextElementSibling;
  if (box) box.hidden = !e.target.checked;
});

/* ---------- 对话框：添加 / 设置 / 更换 token / 删除。打开时绑定服务器，操作只作用于这台 ---------- */
const dlg = $('dlg');
let dlgNode = null;                 // 对话框打开时绑定的服务器 {id, name, local, reset_day}
function dlgHead(title, sub){
  return '<div class="dlg-head"><div><h3 id="dlgTitle">' + title + '</h3>' + (sub ? '<p>' + sub + '</p>' : '') +
    '</div><button type="button" class="icon-btn" data-act="close" aria-label="关闭">' + ICON.x + '</button></div>';
}
function openDlg(html){
  dlg.innerHTML = html;
  if (!dlg.open) dlg.showModal();
  const f = dlg.querySelector('input:not([type=checkbox])'); if (f) f.focus();
}
function closeDlg(){ if (dlg.open) dlg.close(); }
function showErr(msg){ const e = dlg.querySelector('.err'); if (e) { e.textContent = msg; e.hidden = false; } }
const fval = (f, n) => f.querySelector('[name="' + n + '"]').value;
const nodeUrl = (id, sub) => api('nodes/' + encodeURIComponent(id) + (sub || ''));

function dlgNoManage(){
  openDlg(dlgHead('需要先设置访问密码') + '<div class="dlg-body"><p class="muted">为了安全，面板没有设置访问密码时，不能在网页上添加或修改服务器。</p>' +
    '<p class="muted">在面板服务器上执行 <code>python3 /opt/vps-probe/probe.py install --password 新密码</code> 即可开启登录。</p></div>' +
    '<div class="dlg-foot"><button type="button" class="btn primary" data-act="close">知道了</button></div>');
}
function dlgAdd(){
  if (!state.manage) return dlgNoManage();
  openDlg(dlgHead('添加服务器', '添加后会生成一条安装命令，在要监控的服务器上执行即可。') +
    '<form data-act="create"><div class="dlg-body">' +
    '<label class="field"><span>名称</span><input name="name" maxlength="40" required autocomplete="off" placeholder="例如：香港 CN2 · 2C2G"></label>' +
    '<label class="field"><span>月流量重置日</span><input name="reset_day" type="number" min="1" max="28" value="1" required><small>每月几号开始重新统计流量，和服务商的账单日保持一致即可</small></label>' +
    '<div class="err" hidden></div></div><div class="dlg-foot"><button type="button" class="btn" data-act="close">取消</button><button type="submit" class="btn primary">添加</button></div></form>');
}
function dlgInstall(info, title){
  openDlg(dlgHead(title, '在这台服务器上执行：') + '<div class="dlg-body">' + installBlock(info) + '</div>' +
    '<div class="dlg-foot"><button type="button" class="btn primary" data-act="close">完成</button></div>');
}
function dlgSettings(){
  if (!state.manage) return dlgNoManage();
  if (!state.meta || state.meta.id !== state.node) return;
  const nd = dlgNode = Object.assign({}, state.meta);
  const grace = nd.token_grace_until > Date.now() / 1000 ? '<small>旧 token 在 ' + fmtDate(nd.token_grace_until) + ' 前仍然有效</small>' : '';
  openDlg(dlgHead('服务器设置', nd.local ? '本机（面板所在的服务器）' : '') +
    '<form data-act="save"><div class="dlg-body">' +
    '<label class="field"><span>名称</span><input name="name" maxlength="40" required autocomplete="off" value="' + esc(nd.name) + '"></label>' +
    '<label class="field"><span>月流量重置日</span><input name="reset_day" type="number" min="1" max="28" required value="' + (Number(nd.reset_day) || 1) + '"><small>修改后会从新的统计周期重新开始累计</small></label>' +
    (nd.local ? '' : '<div class="field"><span>子服务器</span><div class="btn-row"><button type="button" class="btn" data-act="showInstall">查看安装命令</button>' +
      '<button type="button" class="btn" data-act="askRotate">更换 token</button><button type="button" class="btn danger" data-act="askDelete">删除服务器</button></div>' + grace + '</div>') +
    '<div class="err" hidden></div></div><div class="dlg-foot"><button type="button" class="btn" data-act="close">取消</button><button type="submit" class="btn primary">保存</button></div></form>');
}
function dlgRotate(){
  const nd = dlgNode; if (!nd) return;
  openDlg(dlgHead('更换「' + esc(nd.name) + '」的 token', '更换后需要在这台服务器上重新执行安装命令，历史数据会保留。') +
    '<div class="dlg-body"><label class="check"><input type="checkbox" id="graceChk" checked> 旧 token 再保留 1 小时，期间新旧 token 都有效，便于平滑切换</label>' +
    '<p class="muted">如果 token 已经泄露，请取消勾选，旧 token 会立即失效。</p><div class="err" hidden></div></div>' +
    '<div class="dlg-foot"><button type="button" class="btn" data-act="close">取消</button><button type="button" class="btn primary" data-act="doRotate">更换</button></div>');
}
function dlgDelete(){
  const nd = dlgNode; if (!nd) return;
  openDlg(dlgHead('删除「' + esc(nd.name) + '」？', '面板上这台服务器的历史数据会一起删除，无法恢复。') +
    '<div class="dlg-body"><p class="muted">删除后这台服务器的上报会被拒绝。如需彻底卸载，请在它上面执行：</p>' + cmdBlock(uninstallCmd()) + '<div class="err" hidden></div></div>' +
    '<div class="dlg-foot"><button type="button" class="btn" data-act="close">取消</button><button type="button" class="btn danger solid" data-act="doDelete">确认删除</button></div>');
}
async function copyText(text, btn){
  let ok = false;
  try { await navigator.clipboard.writeText(text); ok = true; } catch (e) {}
  if (!ok) {   // HTTP 页面没有剪贴板 API，用老办法
    const ta = document.createElement('textarea');
    ta.value = text; ta.setAttribute('readonly', ''); ta.style.cssText = 'position:fixed;top:0;left:0;opacity:0';
    (btn.closest('dialog') || document.body).appendChild(ta); ta.select();
    try { ok = document.execCommand('copy'); } catch (e) {}
    ta.remove();
  }
  const sp = btn.querySelector('span');
  if (sp) { sp.textContent = ok ? '已复制' : '复制失败，请手动选择'; setTimeout(() => { sp.textContent = '复制命令'; }, 1600); }
}

const SUBMIT = {
  async create(f){
    const b = f.querySelector('[type=submit]'); b.disabled = true;
    try {
      const info = await send('POST', api('nodes'), {name:fval(f, 'name').trim(), reset_day:parseInt(fval(f, 'reset_day'), 10)});
      dlgInstall(info, '已添加「' + esc(info.name) + '」'); refresh();
    } catch (e) { showErr(e.message); b.disabled = false; }
  },
  async save(f){
    const b = f.querySelector('[type=submit]'), nd = dlgNode; b.disabled = true;
    try {
      await send('POST', nodeUrl(nd.id), {name:fval(f, 'name').trim(), reset_day:parseInt(fval(f, 'reset_day'), 10)});
      closeDlg(); refresh();
    } catch (e) { showErr(e.message); b.disabled = false; }
  }
};
const ACT = {
  close: closeDlg,
  add: dlgAdd,
  settings: dlgSettings,
  askDelete: dlgDelete,
  askRotate: dlgRotate,
  copy: b => copyText(b.dataset.text, b),
  async showInstall(b){
    const nd = dlgNode; b.disabled = true;
    try { dlgInstall(await getJSON(nodeUrl(nd.id, '/secret')), '「' + esc(nd.name) + '」的安装命令'); }
    catch (e) { showErr('获取失败：' + e.message); b.disabled = false; }
  },
  async doRotate(b){
    const nd = dlgNode; b.disabled = true;
    try {
      const info = await send('POST', nodeUrl(nd.id, '/token'), {grace: $('graceChk').checked ? 3600 : 0});
      dlgInstall(info, '已更换「' + esc(nd.name) + '」的 token');
    } catch (e) { showErr(e.message); b.disabled = false; }
  },
  async doDelete(b){
    const nd = dlgNode; b.disabled = true;
    try {
      await send('DELETE', nodeUrl(nd.id));
      closeDlg();
      if (state.node === nd.id) location.hash = '#/'; else refresh();
    } catch (e) { showErr(e.message); b.disabled = false; }
  }
};
document.addEventListener('click', e => {
  const b = e.target.closest('[data-act]');
  if (!b || b.tagName === 'FORM' || !ACT[b.dataset.act]) return;
  e.preventDefault(); ACT[b.dataset.act](b);
});
dlg.addEventListener('click', e => { if (e.target === dlg) closeDlg(); });
dlg.addEventListener('submit', e => { e.preventDefault(); const fn = SUBMIT[e.target.dataset.act]; if (fn) fn(e.target); });

/* ---------- 其他交互 ---------- */
function segSelect(seg, btn){ seg.querySelectorAll('button').forEach(b => b.classList.toggle('on', b === btn)); }
$('rangeSeg').addEventListener('click', e => {
  const b = e.target.closest('button'); if (!b) return;
  segSelect($('rangeSeg'), b); state.range = b.dataset.range;
  drawCharts();
  if (state.range === 'day' && Date.now() - state.dayAt > 60000) loadHistory('day');
});
$('procSeg').addEventListener('click', e => {
  const b = e.target.closest('button'); if (!b) return;
  segSelect($('procSeg'), b); state.sort = b.dataset.sort;
  if (state.last && state.last.info) renderProcs(state.last);
});
document.addEventListener('visibilitychange', () => {
  if (document.hidden) return;
  if (state.view === 'detail') { const id = state.node; loadHistory('live').then(() => { if (state.node === id) refresh(); }); }
  else refresh();
});
addEventListener('hashchange', route);
route();
})();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    main()
