"""面板模式：组装本机采集器、服务器列表和 HTTP 服务"""
import base64
import gzip
import os
import signal
import socket
import sys
import threading

from .bundle import make_bundle
from .collector import Collector
from .config import SAVE_EVERY, TRAFFIC_SAVE_EVERY, VERSION
from .server import DOMAIN, MAX_CONN, ProbeHandler, ProbeServer
from .store import Hub
from .util import log, run_every, run_loop
from .web import build_page

PKG_DIR = os.path.dirname(os.path.abspath(__file__))


def run_panel(args):
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
    ProbeHandler.page = build_page().encode("utf-8")
    ProbeHandler.page_gz = gzip.compress(ProbeHandler.page, 9)
    ProbeHandler.bundle, ProbeHandler.bundle_sha = make_bundle(PKG_DIR)

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
    log("VPS Probe v%s 已启动 → http://%s:%d/%s  采样间隔 %gs，最多 %d 个连接，登录认证：%s" % (
        VERSION, args.host if ":" not in args.host else "[%s]" % args.host, args.port,
        "（HTTPS：https://%s）" % DOMAIN if DOMAIN else "", args.interval, MAX_CONN,
        "已开启" if ProbeHandler.auth else "未开启"))
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
