"""面板数据：服务器列表（nodes.json）与每台服务器的实时 / 24 小时历史（history/<id>.bin）

* 服务器列表的修改与写盘串行执行；写盘失败时撤销内存中的修改并报错
* 历史数据用定长环形缓冲保存，按时间窗口淘汰，内存不随运行时间增长
* 24 小时历史按服务器分文件追加写入新增的点，写盘量和峰值内存都与服务器数量线性相关且很小
"""
import hmac
import math
import os
import secrets
import struct
import threading
import time
from array import array

from .config import DAY_POINTS, DAY_SPAN, FIELDS, LIVE_SPAN, MAX_NODES, NODE_ID_RE, TOKEN_RE
from .util import CorruptFile, load_json, load_json_safe, log, save_json, write_atomic


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
        self.secure = False           # 最近一次上报是否经过 HTTPS 反向代理

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
             "last_seen": int(self.last_seen), "reported": bool(s and info), "secure": self.secure}
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
