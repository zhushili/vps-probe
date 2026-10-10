"""子服务器模式：采样与上报分别在两个线程里进行

* 采样线程按固定间隔采样，只把最新一份快照交给上报线程
* 上报线程通过长连接 POST 给面板（gzip 后约 0.5 KB）；网络慢或面板不可达时不会拖慢采样
* 不保留离线期间的历史：恢复连接后只上报最新数据，面板上这段时间显示为空白
* 面板配置了 HTTPS 域名后会在响应里告知新地址，子服务器自动改用 HTTPS 上报，并记在数据目录里
"""
import gzip
import http.client
import json
import os
import signal
import sys
import threading
import time
from urllib.parse import urlparse

from .collector import Collector
from .config import ACTIVE_WINDOW, TRAFFIC_SAVE_EVERY, VERSION
from .util import load_json, log, run_every, run_loop, save_json, CorruptFile


def is_loopback(host):
    return host in ("localhost", "::1") or host.startswith("127.")


class Agent:
    def __init__(self, master, token, collector, allow_http=False, data_dir=""):
        self.token, self.collector = token, collector
        self.origin = master.rstrip("/")    # 配置文件里的面板地址
        self.saved = os.path.join(data_dir, "master.json") if data_dir else ""
        try:
            moved = (load_json(self.saved) or {}).get("master") if self.saved else None
        except CorruptFile:
            moved = None
        if isinstance(moved, str) and moved.startswith("https://"):
            master = moved                  # 之前收到过面板的 HTTPS 新地址
        u = urlparse(master.rstrip("/") + "/api/report")
        if u.scheme not in ("http", "https") or not u.hostname:
            sys.exit("错误：面板地址无效：%s" % master)
        if u.scheme == "http" and not allow_http and not is_loopback(u.hostname):
            sys.exit("错误：面板地址是 HTTP，token 和数据会明文传输。仅在可信内网中使用时，请加 --allow-http")
        self.conn = None
        self._use(master)
        self.cv = threading.Condition()
        self.pending = None
        self.need_info = True
        self.info_at = 0.0
        self.fails = 0
        self.retry_at = 0.0
        self.err_logged = 0.0

    def _use(self, master):
        u = urlparse(master.rstrip("/") + "/api/report")
        self.conn_cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
        self.host, self.port, self.path = u.hostname, u.port, u.path
        self.master = master.rstrip("/")
        self._close()

    def _maybe_move(self, url):
        """面板告知了 HTTPS 地址：先用新地址试发成功后再切换，并记下来，重启后继续使用"""
        if not isinstance(url, str) or not url.startswith("https://") or url.rstrip("/") == self.master:
            return
        old = (self.conn_cls, self.host, self.port, self.path, self.master)
        self._use(url)
        try:
            status, _ = self._post(b"")
        except (OSError, http.client.HTTPException):
            status = 0
        if status in (200, 400, 429):   # 新地址可达且是本面板（空请求体得到 400，刚上报过得到 429）
            log("面板已启用 HTTPS，改为通过 %s 上报" % self.master)
            if self.saved:
                try:
                    save_json(self.saved, {"master": self.master})
                except OSError as e:
                    log("保存面板新地址失败：%s" % e)
            return
        self._close()
        self.conn_cls, self.host, self.port, self.path, self.master = old

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
        self._maybe_move(r.get("master"))

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
        if self.master != self.origin and self.fails >= 10:
            # 面板的 HTTPS 地址连续失败（比如撤销了反向代理）：退回配置文件里的地址
            log("面板地址 %s 连续失败，改回 %s" % (self.master, self.origin))
            self._use(self.origin)
            if self.saved and os.path.exists(self.saved):
                os.remove(self.saved)
        now = time.monotonic()
        self.retry_at = max(self.retry_at, now + min(30, 2 ** min(self.fails, 5)))
        if self.fails == 1 or now - self.err_logged > 300:
            self.err_logged = now
            log(msg)


def run_agent(args):
    if not args.token:
        sys.exit("错误：子服务器模式需要 --token（在面板上添加服务器时生成）")
    collector = Collector(args.interval, args.data_dir, args.reset_day, args.ifaces, args.ifaces_exclude)
    agent = Agent(args.agent, args.token, collector, args.allow_http, args.data_dir)
    collector.sample()  # 先采一次作为计算速率的基准
    stop = threading.Event()
    threading.Thread(target=agent.report_loop, args=(stop,), name="reporter", daemon=True).start()
    threading.Thread(target=run_every, args=(TRAFFIC_SAVE_EVERY, collector.save, stop), name="saver",
                     daemon=True).start()

    def on_term(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, on_term)
    log("VPS Probe v%s 子服务器模式启动，上报到 %s，间隔 %gs" % (VERSION, agent.master, args.interval))
    try:
        run_loop(args.interval, agent.tick, stop)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        collector.save()
        log("已退出")
