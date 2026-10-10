"""子服务器上报数据的校验：字段白名单 + 类型 + 取值范围

任何字段类型不对或超出范围，整份上报都会被拒绝（HTTP 422），不会进入聚合。
缺少的字段按默认值处理，以兼容不同版本的子服务器。
"""
import math


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
