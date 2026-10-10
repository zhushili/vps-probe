# 使用指南

## 工作方式

面板服务器运行 `probe.py`，提供网页并监控本机；其他服务器以子服务器模式运行同一个文件，主动把数据上报给面板，不需要开放端口。只有面板需要对外提供一个端口（默认 `8899`）。

## 安装与升级

```bash
curl -fsSL https://raw.githubusercontent.com/zhushili/vps-probe/main/install.sh | bash
```

- 安装文件从本仓库通过 HTTPS 下载；设置 `PROBE_REF=<提交>` 可以固定安装某个版本
- 重复执行即升级，没指定的参数沿用原配置，手动添加的 `PROBE_*` 配置也会保留
- 升级时先检查参数和端口，再备份旧的代码、配置和服务文件；新版本启动失败（面板 `/healthz` 不通或进程退出）会自动恢复旧版本，首次安装失败会清理干净
- 无法访问 GitHub 时，把 `probe.py` 复制到服务器上，执行 `sudo python3 probe.py install`

## HTTPS（公网使用必须配置）

面板使用 HTTP Basic 认证，子服务器使用 token；在 HTTP 下它们都是明文传输。公网使用时请让面板只监听本机，由反向代理提供 HTTPS：

```bash
curl -fsSL https://raw.githubusercontent.com/zhushili/vps-probe/main/install.sh | bash -s -- --host 127.0.0.1
echo 'PROBE_TRUST_PROXY="1"' >> /etc/vps-probe.env && systemctl restart vps-probe   # 用代理传来的真实 IP 做限流
```

**Caddy**（自动申请证书）：

```
probe.example.com {
    reverse_proxy 127.0.0.1:8899
}
```

**Nginx**：

```nginx
# http { } 中：limit_conn_zone $binary_remote_addr zone=probe_conn:10m;
server {
    listen 443 ssl;
    server_name probe.example.com;
    ssl_certificate     /etc/ssl/probe.crt;
    ssl_certificate_key /etc/ssl/probe.key;
    client_max_body_size 300k;
    limit_conn probe_conn 20;
    location / {
        proxy_pass http://127.0.0.1:8899;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 60s;
    }
}
```

每台子服务器会占用一条长连接，代理的连接上限需要大于子服务器数量。之后请**从 HTTPS 地址打开面板**再添加服务器，生成的命令会使用 HTTPS 地址。

## 添加子服务器

在面板中点「添加服务器」，到目标服务器上以 root 执行生成的命令。命令会从面板下载与面板相同的 `probe.py`，校验 SHA-256 后安装为 `vps-probe-agent` 服务。

面板是 HTTP 时，需要先确认「面板与这台服务器之间是可信网络（内网 / 专线 / VPN）」才会显示命令，命令里带有 `--allow-http`；子服务器在没有这个参数时会拒绝非本机的 HTTP 面板地址。

在服务器详情页的设置中可以**更换 token**：默认旧 token 再保留 1 小时，便于在子服务器上重新执行安装命令；token 泄露时可选择立即作废。历史数据不受影响。

## 配置项

面板：`/etc/vps-probe.env`；子服务器：`/etc/vps-probe-agent.env`。修改后执行 `systemctl restart vps-probe`（或 `vps-probe-agent`）。

| 变量 | 默认 | 说明 |
|---|---|---|
| `PROBE_HOST` / `PROBE_PORT` | `0.0.0.0` / `8899` | 监听地址和端口 |
| `PROBE_USER` / `PROBE_PASSWORD` | `admin` / 随机 | 登录账号；密码为空时只能查看，不能在网页上管理服务器 |
| `PROBE_RESET_DAY` | `1` | 本机的月流量重置日，也可以在网页上修改 |
| `PROBE_INTERVAL` | `2` | 采样间隔（1–10 秒） |
| `PROBE_IFACES` | 空 | 只统计这些网卡的流量，逗号分隔，支持通配符，如 `eth0,ens*` |
| `PROBE_IFACES_EXCLUDE` | 空 | 在默认规则之外再排除的网卡 |
| `PROBE_MAX_CONN` | `256` | 同时保持的连接数上限，需大于子服务器数量 |
| `PROBE_IDLE_TIMEOUT` / `PROBE_REQUEST_TIMEOUT` | `30` / `30` | 空闲连接关闭时间、单个请求的处理时限（秒） |
| `PROBE_TRUST_PROXY` | 空 | 设为 `1` 时，来自本机的请求按 `X-Forwarded-For` 识别来源 IP |
| `PROBE_AGENT` / `PROBE_TOKEN` | — | 子服务器：面板地址和 token |
| `PROBE_ALLOW_HTTP` | 空 | 子服务器：设为 `1` 允许 HTTP 面板地址（仅限可信内网） |

## 容量

在 Ubuntu 24.04 虚拟机上实测：每台子服务器每 2 秒上报一次，24 小时历史已满，同时有人在看总览、详情和 24 小时趋势。

| 服务器数 | 面板内存峰值（RSS） | CPU（单核占比） | 单次历史写盘 | 历史文件 | 重启加载 |
|---:|---:|---:|---:|---:|---:|
| 1 | 27.5 MiB | 0.3% | 0.004 s | 0 | 0.10 s |
| 10 | 30.3 MiB | 0.5% | 0.004 s | 0.6 MiB | 0.10 s |
| 50 | 45.3 MiB | 1.1% | 0.005 s | 3.2 MiB | 0.20 s |
| 100 | 53.2 MiB | 2.0% | 0.084 s | 6.5 MiB | 0.30 s |
| 200 | 68.0 MiB | 3.9% | 0.145 s | 13.1 MiB | 0.50 s |

- 面板最多管理 200 台服务器（含本机）。systemd 服务限制为 `MemoryMax=128M`、`TasksMax=320`
- 每台子服务器在面板上占用一条长连接和一个线程；连接上限默认 256（`PROBE_MAX_CONN`）
- 单机面板和子服务器各约 17 MB 内存（systemd 统计，RSS 约 27 MB）
- 子服务器每 2 秒上报一次，压缩后约 0.5 KB，约 1.4 GB/月流量；可调大 `PROBE_INTERVAL` 减少流量

## 数据保留

| 数据 | 精度 | 保留 | 存储 |
|---|---|---|---|
| 实时趋势 | 每个采样点（默认 2 秒） | 最近 10 分钟 | 仅内存 |
| 24 小时趋势 | 每分钟 1 个点（平均值） | 最近 24 小时 | `history/<id>.bin`，每 5 分钟追加写入 |
| 月流量 | 字节 | 当前周期 + 最近 12 个周期 | `traffic.json`（面板和每台子服务器各自保存） |

子服务器离线期间**不缓存**数据，恢复连接后只上报最新数据；面板异常退出最多丢失最近 5 分钟的 24 小时趋势。

## 流量统计口径

- 统计接收 + 发送字节之和。默认统计所有物理网卡，自动排除 `lo`、`docker*`、`veth*`、`br-*`、`tun*`、`wg*` 等虚拟网卡；bond、bridge、VLAN 等拓扑可能重复或遗漏，请用 `PROBE_IFACES` 指定
- 每分钟写盘一次，统计周期切换时立即保存
- 同一次开机内重启探针，停机期间的流量不会丢；断电或系统重启时，上次写盘之后的流量（最多约 1 分钟）无法找回
- 停机跨越统计周期时，恢复的整段增量会计入新周期
- 流量数据**仅供参考，不等同于服务商的计费数据**

## 安全

- 面板没有设置密码时只能查看，不能在网页上管理服务器
- 内置 HTTP 服务有连接数上限、请求时限、请求体大小限制和认证失败限流；公网长期使用仍建议放在 Caddy / Nginx 之后
- 页面会显示进程命令行，命令行里的敏感参数会被已登录的用户看到

## 卸载

```bash
curl -fsSL https://raw.githubusercontent.com/zhushili/vps-probe/main/install.sh | bash -s -- uninstall   # 面板和子服务器
python3 /opt/vps-probe-agent/probe.py uninstall                                                        # 只卸载子服务器
```
