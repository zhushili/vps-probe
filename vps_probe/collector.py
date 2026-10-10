"""本机采集器：定时采样，计算各项速率与月流量

流量统计（traffic.json）的恢复边界：
  * 每 TRAFFIC_SAVE_EVERY 秒和每次统计周期切换时写盘；断电时最多丢失最近一个间隔内的增量
  * 同一次开机内重启探针：从保存的网卡计数器接着算，停机期间的流量不会丢
  * 系统重启后网卡计数器归零，只能把开机以来的流量算作新增，上次保存之后、关机之前的部分无法找回
  * 停机跨越统计周期时，恢复的整段增量会计入新周期
  因此这里的流量只供参考，不等同于服务商的计费数据。
"""
import os
import threading
import time
from datetime import date

from .metrics import (cpu_usage, cycle_start, host_info, list_pids, make_iface_filter, read_conn,
    read_cpu_times, read_disk_io, read_disks, read_memory, read_net, whole_disks)
from .util import load_json_safe, log, read_text, save_json


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
