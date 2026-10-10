# 使用指南

## 工作方式

面板服务器提供网页并监控本机；其他服务器以子服务器模式运行同一套程序，主动把数据上报给面板，不需要开放端口。代码安装在 `/opt/vps-probe`（子服务器为 `/opt/vps-probe-agent`），配置在 `/etc/vps-probe.env`，数据在 `/var/lib/vps-probe`。

## 管理菜单

```bash
curl -fsSL https://raw.githubusercontent.com/zhushili/vps-probe/main/install.sh | bash   # 首次安装
vps-probe                                                                                 # 安装后
```

菜单顶部显示面板和子服务器的运行状态，提供：安装面板 / 修改面板配置、安装子服务器、配置域名和 HTTPS、查看状态和登录信息、查看日志、重启服务、升级、卸载。

所有操作也都有对应的命令，适合脚本调用：

| 命令 | 说明 |
|---|---|
| `vps-probe install [--port 8899 --user admin --password xxx --reset-day 1]` | 安装或修改面板，没指定的参数沿用原配置 |
| `vps-probe install --domain probe.example.com` | 安装面板并配置 HTTPS |
| `vps-probe proxy --domain probe.example.com` | 配置域名和 HTTPS |
| `vps-probe proxy --lock` / `--remove` | 关闭面板的 HTTP 端口 / 撤销 HTTPS |
| `vps-probe status` | 查看状态、访问地址和登录信息 |
| `vps-probe upgrade` | 从 GitHub 升级到最新版本 |
| `vps-probe uninstall` | 卸载 |

首次安装时把 `vps-probe` 换成 `curl -fsSL .../install.sh | bash -s --`，例如 `... | bash -s -- install --domain probe.example.com`。

安装和升级时会先检查参数和端口，再备份旧的代码和配置；新版本启动失败会自动恢复旧版本，首次安装失败会清理干净。

## 域名和 HTTPS

面板使用 HTTP Basic 认证，子服务器使用 token，在 HTTP 下都是明文传输，公网使用请配置 HTTPS。准备一个解析到本机公网 IP 的域名，并在云厂商安全组放行 80、443 端口，然后在菜单中选择「配置域名和 HTTPS」，或执行 `vps-probe proxy --domain probe.example.com`：

1. 选择反向代理：已装 Nginx 时使用 Nginx + Certbot；否则系统软件源里有 Caddy 时（Ubuntu 23.04+、Debian 12+）安装 Caddy，证书自动申请和续期，没有则安装 Nginx + Certbot。也可以用 `--proxy caddy|nginx` 指定。80 / 443 端口被其他程序占用时会停止
2. 写入代理配置，放行 ufw / firewalld 防火墙的 80、443 端口，等待证书签发后在本机通过 HTTPS 自检；失败会撤销代理配置（本次才启动的代理服务也会停掉），面板保持原样
3. 面板记录域名，已连接的子服务器（1.4 及以后版本）收到 HTTPS 地址后自动切换
4. 配置前在线的子服务器都重新连上并改用 HTTPS 后，面板改为只监听 127.0.0.1，外部只能通过 HTTPS 访问。还有旧版本子服务器时会保留 HTTP 端口，升级它们后执行 `vps-probe proxy --lock`

生成的配置文件是 `/etc/caddy/vps-probe.caddy` 或 `/etc/nginx/conf.d/vps-probe.conf`。使用自己的反向代理时，转发到 `127.0.0.1:8899`，并在 `/etc/vps-probe.env` 中设置 `PROBE_TRUST_PROXY="1"` 和 `PROBE_HOST="127.0.0.1"`。

## 添加子服务器

在面板中点「添加服务器」，到目标服务器上以 root 执行生成的命令。命令会从面板下载与面板相同版本的源码包，校验 SHA-256 后安装为 `vps-probe-agent` 服务。

面板是 HTTP 时，需要先确认「面板与这台服务器之间是可信网络（内网 / 专线 / VPN）」才会显示命令，命令里带有 `--allow-http`；子服务器在没有这个参数时会拒绝非本机的 HTTP 面板地址。

在服务器详情页的设置中可以**更换 token**：默认旧 token 再保留 1 小时，便于在子服务器上重新执行安装命令；token 泄露时可选择立即作废。历史数据不受影响。

## 配置项

面板：`/etc/vps-probe.env`；子服务器：`/etc/vps-probe-agent.env`。一般通过菜单修改；手动修改后执行 `systemctl restart vps-probe`（或 `vps-probe-agent`），升级时会保留。

| 变量 | 默认 | 说明 |
|---|---|---|
| `PROBE_HOST` / `PROBE_PORT` | `0.0.0.0` / `8899` | 监听地址和端口 |
| `PROBE_USER` / `PROBE_PASSWORD` | `admin` / 随机 | 登录账号；密码为空时只能查看，不能在网页上管理服务器 |
| `PROBE_RESET_DAY` | `1` | 本机的月流量重置日，也可以在网页上修改 |
| `PROBE_INTERVAL` | `2` | 采样间隔（1–10 秒） |
| `PROBE_IFACES` | 空 | 只统计这些网卡的流量，逗号分隔，支持通配符，如 `eth0,ens*` |
| `PROBE_IFACES_EXCLUDE` | 空 | 在默认规则之外再排除的网卡 |
| `PROBE_DOMAIN` / `PROBE_PROXY` | 空 | HTTPS 域名和反向代理类型，由「配置域名和 HTTPS」写入 |
| `PROBE_TRUST_PROXY` | 空 | 设为 `1` 时，来自本机的请求按 `X-Forwarded-For` 识别来源 IP |
| `PROBE_MAX_CONN` | `256` | 同时保持的连接数上限，需大于子服务器数量 |
| `PROBE_IDLE_TIMEOUT` / `PROBE_REQUEST_TIMEOUT` | `30` / `30` | 空闲连接关闭时间、单个请求的处理时限（秒） |
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
- 内置 HTTP 服务有连接数上限、请求时限、请求体大小限制和认证失败限流；公网使用请配置 HTTPS
- 页面会显示进程命令行，命令行里的敏感参数会被已登录的用户看到

## 代码结构

只依赖 Python 标准库，代码在 `vps_probe/`，直接以 `python3 -m vps_probe` 运行，不需要构建：

| 模块 | 职责 | 模块 | 职责 |
|---|---|---|---|
| `config` | 配置常量 | `util` | 日志、可靠的文件读写、定时任务 |
| `metrics` | 读取 /proc 指标 | `collector` | 本机采集与流量统计 |
| `store` | 服务器列表与历史数据 | `schema` | 上报数据校验 |
| `server` | HTTP 服务 | `panel` / `agent` | 面板模式 / 子服务器模式 |
| `bundle` | 供子服务器下载的源码包 | `service` | systemd 安装、升级、回滚 |
| `proxy` | HTTPS 反向代理 | `upgrade` | 在线升级 |
| `menu` | 交互菜单 | `cli` | 命令行入口 |

网页在 `vps_probe/web/`：`index.html`、`style.css`，脚本按功能分为 `core.js`（格式化、请求、轮询）、`chart.js`、`overview.js`、`detail.js`、`dialogs.js`、`main.js`，启动时拼成一个页面。本地调试：`python3 -m vps_probe run --port 8899 --user admin --password dev`。
