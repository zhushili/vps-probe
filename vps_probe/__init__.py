"""VPS Probe：轻量级 Linux 服务器探针，仅依赖 Python 标准库

模块：
  config     配置常量            util       日志、文件读写、定时任务
  metrics    读取 /proc 指标     collector  本机采集与流量统计
  store      服务器列表与历史    schema     上报数据校验
  server     HTTP 服务           panel      面板模式
  agent      子服务器模式        bundle     供子服务器下载的源码包
  service    systemd 安装管理    proxy      HTTPS 反向代理
  upgrade    在线升级            menu       交互菜单
  cli        命令行入口          web        前端页面
"""
