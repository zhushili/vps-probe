# VPS Probe

轻量级 Linux 服务器探针，零依赖，自带 Web 面板，支持多台服务器监控。

## 特性

- **轻量**：仅依赖 Python 标准库，单机内存占用低于 30 MB
- **全面**：CPU、内存、磁盘、网络、连接数、进程，实时与 24 小时趋势
- **多服务器**：网页上添加，子服务器主动上报，无需开放端口
- **省心**：管理菜单，自动配置域名和 HTTPS，升级失败自动回滚

## 安装

需要 Linux、systemd 和 Python 3.8+（Ubuntu / Debian 自带），以 root 身份运行，打开管理菜单：

```bash
curl -fsSL https://raw.githubusercontent.com/zhushili/vps-probe/main/install.sh | bash
```

在菜单中选择「安装面板」，完成后会显示访问地址和登录密码。之后随时运行 `vps-probe` 打开菜单，可以配置域名和 HTTPS、查看状态、升级和卸载。

也可以不经菜单直接安装：`| bash -s -- install --domain probe.example.com`，其中 `--domain` 可选，会自动配置 HTTPS 反向代理。

**添加服务器**：在面板中点击「添加服务器」，到目标服务器上执行生成的命令。

更多用法见 [使用指南](docs/guide.md)。

## License

[MIT](LICENSE)
