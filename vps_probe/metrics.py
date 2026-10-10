"""系统指标读取：直接解析 /proc 与 /sys，不依赖任何第三方库"""
import fnmatch
import os
import platform
import socket
import subprocess
from datetime import date

from .config import VERSION
from .util import read_text


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
