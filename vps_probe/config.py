"""配置常量：版本号、时间窗口、容量上限、安装路径"""
import os
import re

VERSION = "1.4.0"
REPO = "zhushili/vps-probe"

LIVE_SPAN = 600                 # 实时视图：最近 10 分钟
DAY_SPAN = 86400                # 24 小时视图
DAY_POINTS = 1440               # 24 小时视图每分钟 1 个点
ACTIVE_WINDOW = 30              # 最近 30 秒内有人在看详情，才扫描进程列表
MAX_NODES = 200                 # 面板最多管理的服务器数（含本机），容量实测见 docs/guide.md
MAX_REPORT = 256 * 1024         # 子服务器单次上报的最大体积（压缩后）
SAVE_EVERY = 300                # 24 小时历史写盘间隔（秒）
TRAFFIC_SAVE_EVERY = 60         # 流量统计写盘间隔（秒）

TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
NODE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")

# 历史数据点的字段顺序：时间戳 + 10 个指标
FIELDS = ("t", "cpu", "steal", "iowait", "mem", "cache", "swap", "rx", "tx", "rd", "wr")

# 安装位置：代码在 /opt/<服务名>/vps_probe，配置在 /etc/<服务名>.env，数据在 /var/lib/<服务名>
PANEL = "vps-probe"
AGENT = "vps-probe-agent"
SHIM = "/usr/local/bin/vps-probe"   # 管理命令，不带参数时打开菜单


def env_num(name, default, conv=int):
    try:
        return conv(os.environ.get(name) or default)
    except ValueError:
        return default
