# eianun 二改版本 🌐

基于 VPNGate + OpenVPN 的 Linux VPS 出站代理网关二改版。此版本已去除原项目广告入口，并新增“指定地区拉取节点”功能。

## 主要改动

- 名称统一改为 **eianun 二改版本**。
- 移除 Web UI 里的 VPS 推广广告和 README 中的推广徽章/链接。
- 新增后端节点地区过滤：可只保留指定国家/地区的 VPNGate 节点，不再默认把全部地区节点都写入节点池。
- Web 管理后台“管理员设置”新增 **拉取地区过滤** 输入框。
- 安装后的命令行工具改为 `eianun`，同时保留 `ml` 兼容别名。
- 安装脚本已适配主流 Linux 包管理器：APT、DNF、YUM、Pacman、Zypper。

## 支持系统

脚本会自动识别 `/etc/os-release` 和系统包管理器，并安装不同发行版对应的依赖包。

已做适配的发行版族：

- Debian / Ubuntu / Linux Mint 等 APT 系。
- CentOS / RHEL / Rocky Linux / AlmaLinux / Oracle Linux 等 YUM 或 DNF 系。
- Fedora 等 DNF 系。
- Arch Linux / Manjaro 等 Pacman 系。
- openSUSE / SUSE 等 Zypper 系。

注意：本项目仍依赖 **systemd** 管理后台服务。如果系统没有 `systemctl`，安装脚本会直接提示不支持。

## 快速安装

你的仓库地址是：`https://github.com/illria/gatevpn`

上传文件到该仓库后，使用下面命令安装：

```bash
curl -Ls https://raw.githubusercontent.com/illria/gatevpn/main/install.sh -o install.sh
sudo sh install.sh
```

Alpine Linux 也可以直接使用上面的 `sh` 命令；脚本会通过 `apk` 自动安装 OpenVPN、OpenRC、Python 等依赖。

也可以在安装时指定仓库用户和仓库名：

```bash
bash install.sh illria gatevpn
```

## 安装脚本依赖检测

安装脚本会自动执行：

1. 检测 root 权限。
2. 检测 systemd / `systemctl`。
3. 检测包管理器：`apt-get`、`dnf`、`yum`、`pacman`、`zypper`。
4. 根据发行版安装依赖：`openvpn`、`curl`、`git`、`ca-certificates`、`iptables`、`iproute/iproute2`、`procps/procps-ng`、`psmisc`、`python3/python`、`iputils/iputils-ping`。
5. 安装后再次检测必要工具：`openvpn`、`curl`、`git`、`systemctl`、`ip`、`ping`、`iptables`、`pkill`、`Python`。

RHEL / CentOS / Rocky / AlmaLinux 等系统会尝试自动安装 `epel-release`，方便安装 OpenVPN。如果你的镜像源没有 EPEL，需要先手动启用 EPEL。

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


### ✅ 已适配的 Linux 发行版 / 包管理器

安装脚本会自动识别并安装依赖：

| 系统类型 | 包管理器 | 服务管理器 |
|---|---|---|
| Debian / Ubuntu / Linux Mint | apt | systemd |
| CentOS / RHEL / AlmaLinux / Rocky / Fedora | yum / dnf | systemd |
| Arch / Manjaro | pacman | systemd |
| openSUSE / SUSE | zypper | systemd |
| Alpine Linux | apk | OpenRC |
| Gentoo | emerge | OpenRC / systemd |
| Void Linux | xbps | runit |

说明：脚本尽量覆盖主流 Linux，但“全部 Linux”里存在大量极简镜像、容器镜像、非标准服务管理器或缺少 TUN/OpenVPN 内核能力的环境。遇到这类系统时，脚本会提示缺失项，而不是静默失败。
