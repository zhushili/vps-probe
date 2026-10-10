# VPS Probe

轻量级 Linux 服务器探针，单文件、零依赖，自带 Web 面板，支持多台服务器监控。

## 特性

- **轻量**：单个 Python 文件，仅依赖标准库，单机内存占用低于 30 MB
- **全面**：CPU、内存、磁盘、网络、连接数、进程，实时与 24 小时趋势
- **多服务器**：网页上添加，子服务器主动上报，无需开放端口
- **可靠**：升级失败自动回滚，配置损坏自动从备份恢复，子服务器安装文件校验 SHA-256

## 安装

需要 Linux、systemd 和 Python 3.8+（Ubuntu / Debian 自带），以 root 身份运行：

```bash
curl -fsSL https://raw.githubusercontent.com/zhushili/vps-probe/main/install.sh | bash
```

安装完成后会输出访问地址和登录密码，默认端口 `8899`。可选参数 `--port` `--user` `--password` `--reset-day`，例如 `| bash -s -- --port 9000`。再次运行即可升级。

**添加服务器**：在面板中点击「添加服务器」，到目标服务器上执行生成的命令。

**卸载**：`curl -fsSL https://raw.githubusercontent.com/zhushili/vps-probe/main/install.sh | bash -s -- uninstall`

公网使用请配置 HTTPS；配置项、容量和流量统计口径见 [使用指南](docs/guide.md)。

## License

[MIT](LICENSE)
