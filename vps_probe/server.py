"""HTTP 服务：网页、管理 API、子服务器上报

资源保护：
  * 全局并发连接上限（PROBE_MAX_CONN），超出时直接返回 503 并关闭
  * 每个请求从开始等待到处理完成有总时限（空闲 + 处理），超时由后台线程强制断开，防止慢速请求长期占用
  * 先认证、后读取请求体；认证失败立即响应并关闭连接
  * 按来源 IP 统计认证失败次数，超过阈值后短时间内直接返回 429
"""
import gzip
import hmac
import json
import os
import re
import socket
import sys
import threading
import time
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .config import ACTIVE_WINDOW, MAX_REPORT, VERSION, env_num
from .schema import Invalid, REPORT_SCHEMA, validate
from .store import StoreError


CSP = ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; "
       "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
NODE_PATH = re.compile(r"^/api/nodes/([A-Za-z0-9_-]{1,32})(/secret|/token)?$")
MAX_CONN = env_num("PROBE_MAX_CONN", 256)                 # 同时保持的连接数上限（子服务器各占一条长连接）
IDLE_TIMEOUT = env_num("PROBE_IDLE_TIMEOUT", 30)          # 长连接空闲多久后关闭（秒）
REQUEST_TIMEOUT = env_num("PROBE_REQUEST_TIMEOUT", 30)    # 单个请求从收到到处理完的最长时间（秒）
TRUST_PROXY = os.environ.get("PROBE_TRUST_PROXY") == "1"  # 在本机反向代理后面时，用 X-Forwarded-For 识别来源 IP
DOMAIN = os.environ.get("PROBE_DOMAIN", "")              # 配置了 HTTPS 域名时，通知子服务器改用 https://域名 上报
LOOPBACK = ("127.0.0.1", "::1", "::ffff:127.0.0.1")


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
    bundle = b""            # 本程序的源码包（子服务器安装时下载）及其 SHA-256
    bundle_sha = ""

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
        if TRUST_PROXY and ip in LOOPBACK:
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
        if path == "/vps-probe.tar.gz":     # 子服务器安装时下载，不需要登录（源码里不含任何密钥）
            return self._send(200, self.bundle, "application/gzip")
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
        """安装子服务器所需的信息：token + 源码包的 SHA-256"""
        return {"id": node.id, "name": node.name, "token": node.token, "sha256": self.bundle_sha, "version": VERSION}

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
        node.secure = TRUST_PROXY and self.client_address[0] in LOOPBACK and \
            self.headers.get("X-Forwarded-Proto", "").lower() == "https"
        resp = {"ok": True, "need_info": node.info is None, "reset_day": node.reset_day,
                "want_procs": time.time() - node.last_view < ACTIVE_WINDOW}
        if DOMAIN:
            resp["master"] = "https://" + DOMAIN
        self._json(resp)

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
        gz = "gzip" in self.headers.get("Accept-Encoding", "") and not ctype.startswith("application/gzip")
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
