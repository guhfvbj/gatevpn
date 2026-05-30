# eianun 二改版本 🌐

基于 VPNGate + OpenVPN 的 Linux VPS 出站代理网关二改版。此版本已去除原项目广告入口，并新增“指定地区拉取节点”功能。

## 主要改动

- 名称统一改为 **eianun 二改版本**。
- 移除 Web UI 里的 VPS 推广广告和 README 中的推广徽章/链接。
- 新增后端节点地区过滤：可只保留指定国家/地区的 VPNGate 节点，不再默认把全部地区节点都写入节点池。
- Web 管理后台“管理员设置”新增 **拉取地区过滤** 输入框。
- 安装后的命令行工具改为 `eianun`，同时保留 `ml` 兼容别名。

## 快速安装

上传到你自己的 GitHub 仓库后，把下面命令里的 `eianun/eianun-vpngate` 换成你的仓库地址：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/eianun/eianun-vpngate/main/install.sh)
```

也可以在安装时指定仓库用户和仓库名：

```bash
bash install.sh your-github-user your-repo-name
```

## 指定地区拉取节点

支持国家简称、英文名、中文名，多个地区用逗号分隔。

示例：

```text
JP,日本
US,美国
KR,韩国
JP,日本,US,美国
```

设置方式：

1. Web 管理后台 → 管理员 → 管理员设置 → 拉取地区过滤。
2. 命令行执行：

```bash
eianun country
```

3. 环境变量方式，例如 `/etc/default/eianun-vpngate`：

```bash
VPNGATE_TARGET_COUNTRIES=JP,日本
```

留空表示拉取全部地区。

## 常用命令

```bash
eianun status      # 查看状态
eianun start       # 启动服务
eianun stop        # 停止服务
eianun restart     # 重启服务
eianun logs        # 查看日志
eianun web         # 修改网页绑定地址/安全后缀
eianun port        # 修改网页端口
eianun password    # 修改管理账号密码
eianun country     # 设置节点拉取地区
eianun update      # 从 GitHub 更新
eianun uninstall   # 卸载
```

兼容旧命令：`ml` 仍会指向 `eianun`。

## 架构

```text
[ 3x-ui / Xray ]
      │ HTTP / SOCKS5
      ▼
[ 本地代理服务器 :7928 ] --绑定 tun0--> [ OpenVPN / VPNGate 节点 ]
      │
      └─ SSH / Web UI 仍走物理网卡，避免 VPS 失联
```

## 文件说明

- `vpngate_manager.py`：主程序、Web UI、节点拉取/检测/连接逻辑。
- `vpn_utils.py`：IP 信息、延迟检测、OpenVPN 配置解析等工具函数。
- `proxy_server.py`：本地 HTTP/SOCKS5 代理服务。
- `install.sh`：一键安装和 CLI 工具生成脚本。
- `LICENSE`：原始许可证文件。
