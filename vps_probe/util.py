"""工具函数：日志、文件读写（原子写入、损坏恢复）、定时任务"""
import json
import os
import sys
import tempfile
import time


def log(msg):
    print(time.strftime("[%Y-%m-%d %H:%M:%S] ") + msg, file=sys.stderr, flush=True)


def read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


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
