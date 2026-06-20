#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import os
import re
import select
import shlex
import signal
import socket
import subprocess
import sys
import threading
import time
import shutil
import urllib.parse
import urllib.request
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

API_URL = "https://www.vpngate.net/api/iphone/"
INSTALL_DIR = Path(os.environ.get("EIANUN_INSTALL_DIR", "/opt/eianun-vpngate"))
PYTHON_BIN = os.environ.get("PYTHON_BIN", sys.executable or "python3")
BENCHMARK_IP_URL = "http://api.ipify.org"
BENCHMARK_DOWNLOAD_URL = "http://speedtest.tele2.net/100KB.zip"
DEFAULT_NO_NODE_RETRY_SECONDS = 3600

CONFIG_ROOT = Path("/etc/eianun-vpngate")
INSTANCE_CONFIG_DIR = CONFIG_ROOT / "instances"
STATE_ROOT = Path("/var/lib/eianun-vpngate/instances")
RUN_ROOT = Path("/run/eianun-vpngate")
LOG_ROOT = Path("/var/log/eianun-vpngate")
SYSTEMD_TEMPLATE = Path("/etc/systemd/system/eianun-vpngate@.service")

COUNTRY_ALIASES = {
    "JP": {"jp", "japan", "日本", "日本国"},
    "KR": {"kr", "korea", "korea republic of", "republic of korea", "south korea", "韩国", "南韩"},
    "US": {"us", "usa", "united states", "united states of america", "美国"},
    "HK": {"hk", "hong kong", "香港"},
    "SG": {"sg", "singapore", "新加坡"},
    "TW": {"tw", "taiwan", "台湾"},
    "GB": {"gb", "uk", "united kingdom", "英国"},
}


class NoUsableNodes(RuntimeError):
    pass


def die(message: str, code: int = 1) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(code)


def run_cmd(cmd: list[str], *, check: bool = True, timeout: int | None = None, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=check, timeout=timeout, text=True, capture_output=capture)


def command_exists(name: str) -> bool:
    from shutil import which

    return which(name) is not None


def sanitize_instance_id(value: str) -> str:
    value = value.strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,30}", value):
        die("instance_id 只能包含小写字母、数字、下划线和短横线，并且必须以字母或数字开头")
    return value


def quote_env(value: Any) -> str:
    text = str(value)
    return "'" + text.replace("'", "'\"'\"'") + "'"


def parse_env_file(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    if not path.exists():
        die(f"实例配置不存在: {path}")
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        data[key] = value
    return data


def write_env_file(path: Path, values: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Eianun VPNGate multi-instance config", "# Managed by: en multi"]
    for key in sorted(values):
        lines.append(f"{key}={quote_env(values[key])}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o600)


def int_value(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return default


def float_value(value: Any, default: float = 0.0) -> float:
    try:
        return float(str(value).strip())
    except Exception:
        return default


def bool_value(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on", "y"}


@dataclass
class InstanceConfig:
    instance_id: str
    display_name: str
    node_sources: str
    country_filter: str
    ip_type_priority: str
    proxy_bind_host: str
    proxy_port: int
    web_panel_enabled: bool
    auto_test_workers: int
    auto_select_best_node: bool
    allow_active_switch: bool
    node_selection_mode: str
    benchmark_interval_seconds: int
    sticky_min_final_score: float
    sticky_max_proxy_latency_ms: int
    health_check_url: str
    openvpn_dev_name: str
    runtime_dir: Path
    log_file: Path
    pid_file: Path
    selected_node_file: Path
    generated_ovpn_file: Path
    state_file: Path
    nodes_file: Path
    benchmark_file: Path
    best_node_file: Path
    best_ovpn_file: Path
    namespace: str
    host_veth: str
    ns_veth: str
    host_veth_ip: str
    ns_veth_ip: str

    @classmethod
    def load(cls, instance_id: str) -> "InstanceConfig":
        instance_id = sanitize_instance_id(instance_id)
        env = parse_env_file(INSTANCE_CONFIG_DIR / f"{instance_id}.env")
        port = int_value(env.get("PROXY_PORT"), 0)
        if port <= 0 or port > 65535:
            die(f"{instance_id}: PROXY_PORT 无效")
        runtime_dir = Path(env.get("RUNTIME_DIR") or RUN_ROOT / instance_id)
        state_dir = STATE_ROOT / instance_id
        host_ip, ns_ip = instance_veth_ips(instance_id)
        return cls(
            instance_id=instance_id,
            display_name=env.get("DISPLAY_NAME") or f"VPNGate-{instance_id.upper()}",
            node_sources=env.get("NODE_SOURCES") or "vpngate",
            country_filter=env.get("COUNTRY_FILTER") or "",
            ip_type_priority=env.get("IP_TYPE_PRIORITY") or "all",
            proxy_bind_host=env.get("PROXY_BIND_HOST") or "127.0.0.1",
            proxy_port=port,
            web_panel_enabled=bool_value(env.get("WEB_PANEL_ENABLED"), False),
            auto_test_workers=max(1, int_value(env.get("AUTO_TEST_WORKERS"), 4)),
            auto_select_best_node=bool_value(env.get("AUTO_SELECT_BEST_NODE"), True),
            allow_active_switch=bool_value(env.get("ALLOW_ACTIVE_SWITCH"), True),
            node_selection_mode=(env.get("NODE_SELECTION_MODE") or "sticky").strip().lower(),
            benchmark_interval_seconds=max(0, int_value(env.get("BENCHMARK_INTERVAL_SECONDS"), 0)),
            sticky_min_final_score=float_value(env.get("STICKY_MIN_FINAL_SCORE"), 30.0),
            sticky_max_proxy_latency_ms=max(1, int_value(env.get("STICKY_MAX_PROXY_LATENCY_MS"), 3000)),
            health_check_url=env.get("HEALTH_CHECK_URL") or "https://api.ipify.org",
            openvpn_dev_name=env.get("OPENVPN_DEV_NAME") or f"tun-vg-{instance_id}",
            runtime_dir=runtime_dir,
            log_file=Path(env.get("LOG_FILE") or LOG_ROOT / f"{instance_id}.log"),
            pid_file=Path(env.get("PID_FILE") or runtime_dir / "manager.pid"),
            selected_node_file=Path(env.get("SELECTED_NODE_FILE") or state_dir / "selected_node.json"),
            generated_ovpn_file=Path(env.get("GENERATED_OVPN_FILE") or state_dir / "current.ovpn"),
            state_file=state_dir / "state.json",
            nodes_file=state_dir / "nodes.json",
            benchmark_file=state_dir / "benchmark.json",
            best_node_file=state_dir / "best_node.json",
            best_ovpn_file=state_dir / "best.ovpn",
            namespace=f"vg-{instance_id}",
            host_veth=f"vg{instance_id[:8]}h"[:15],
            ns_veth=f"vg{instance_id[:8]}n"[:15],
            host_veth_ip=host_ip,
            ns_veth_ip=ns_ip,
        )

    def ensure_dirs(self) -> None:
        for path in [self.runtime_dir, self.log_file.parent, self.state_file.parent, self.generated_ovpn_file.parent]:
            path.mkdir(parents=True, exist_ok=True)


def instance_veth_ips(instance_id: str) -> tuple[str, str]:
    digest = hashlib.sha1(instance_id.encode("utf-8")).digest()
    third = 64 + digest[0] % 128
    fourth_base = 4 + (digest[1] % 60) * 4
    return f"169.254.{third}.{fourth_base + 1}", f"169.254.{third}.{fourth_base + 2}"


def default_instance_values(
    instance_id: str,
    country: str,
    port: int,
    iptype: str,
    *,
    selection_mode: str = "sticky",
    benchmark_interval: int = 0,
    sticky_min_score: float = 30.0,
    sticky_max_latency: int = 3000,
) -> dict[str, Any]:
    return {
        "INSTANCE_ID": instance_id,
        "DISPLAY_NAME": f"VPNGate-{instance_id.upper()}-01",
        "NODE_SOURCES": "vpngate",
        "COUNTRY_FILTER": country,
        "IP_TYPE_PRIORITY": iptype,
        "PROXY_BIND_HOST": "127.0.0.1",
        "PROXY_PORT": port,
        "WEB_PANEL_ENABLED": "false",
        "AUTO_TEST_WORKERS": 4,
        "AUTO_SELECT_BEST_NODE": "true",
        "ALLOW_ACTIVE_SWITCH": "true",
        "NODE_SELECTION_MODE": selection_mode,
        "BENCHMARK_INTERVAL_SECONDS": benchmark_interval,
        "STICKY_MIN_FINAL_SCORE": sticky_min_score,
        "STICKY_MAX_PROXY_LATENCY_MS": sticky_max_latency,
        "HEALTH_CHECK_URL": "https://api.ipify.org",
        "OPENVPN_DEV_NAME": f"tun-vg-{instance_id}",
        "RUNTIME_DIR": str(RUN_ROOT / instance_id),
        "LOG_FILE": str(LOG_ROOT / f"{instance_id}.log"),
        "PID_FILE": str(RUN_ROOT / instance_id / "manager.pid"),
        "SELECTED_NODE_FILE": str(STATE_ROOT / instance_id / "selected_node.json"),
        "GENERATED_OVPN_FILE": str(STATE_ROOT / instance_id / "current.ovpn"),
    }


def write_systemd_template() -> None:
    SYSTEMD_TEMPLATE.write_text(
        f"""[Unit]
Description=Eianun VPNGate multi instance %i
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/eianun-vpngate/instances/%i.env
WorkingDirectory={INSTALL_DIR}
ExecStart={PYTHON_BIN} {INSTALL_DIR}/eianun_multi.py run %i
Restart=always
RestartSec=8
KillSignal=SIGTERM
TimeoutStopSec=25

[Install]
WantedBy=multi-user.target
""",
        encoding="utf-8",
    )
    try:
        run_cmd(["systemctl", "daemon-reload"], check=False)
    except Exception:
        pass


def init_multi() -> None:
    for path in [CONFIG_ROOT, INSTANCE_CONFIG_DIR, STATE_ROOT, RUN_ROOT, LOG_ROOT]:
        path.mkdir(parents=True, exist_ok=True)
    geteuid = getattr(os, "geteuid", lambda: 0)
    if geteuid() == 0:
        write_systemd_template()
    else:
        print("WARNING: 非 root 运行，已创建本地可写路径时不会安装 systemd template。")
    print("multi instance directories ready.")


def port_in_use(host: str, port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        return False
    except OSError:
        return True
    finally:
        sock.close()


def add_instance(args: argparse.Namespace) -> None:
    instance_id = sanitize_instance_id(args.instance_id)
    init_multi()
    path = INSTANCE_CONFIG_DIR / f"{instance_id}.env"
    if path.exists() and not args.force:
        die(f"实例已存在: {instance_id}，如需覆盖请加 --force")
    if port_in_use("127.0.0.1", args.port):
        die(f"端口已被占用: 127.0.0.1:{args.port}")
    values = default_instance_values(
        instance_id,
        args.country,
        args.port,
        args.iptype,
        selection_mode=args.selection_mode,
        benchmark_interval=args.benchmark_interval,
        sticky_min_score=args.sticky_min_score,
        sticky_max_latency=args.sticky_max_latency,
    )
    write_env_file(path, values)
    InstanceConfig.load(instance_id).ensure_dirs()
    print(f"created instance {instance_id}: 127.0.0.1:{args.port} country={args.country}")


def load_json(path: Path, default: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return default


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def public_ip_direct(timeout: int = 10) -> str:
    req = urllib.request.Request(BENCHMARK_IP_URL, headers={"User-Agent": "eianun-vpngate-multi"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace").strip()


def find_free_port(host: str = "127.0.0.1") -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def node_public_fields(node: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in node.items() if k != "config_text"}


def benchmark_results_sorted(cfg: InstanceConfig, *, usable_only: bool = False) -> list[dict[str, Any]]:
    data = load_json(cfg.benchmark_file, [])
    if isinstance(data, dict):
        results = data.get("results", [])
    else:
        results = data
    if not isinstance(results, list):
        return []
    ranked = [r for r in results if not usable_only or (r.get("connect_ok") and r.get("proxy_ok"))]
    ranked.sort(key=lambda r: float(r.get("final_score") or 0), reverse=True)
    return ranked


def benchmark_ranked_results(cfg: InstanceConfig) -> list[dict[str, Any]]:
    return benchmark_results_sorted(cfg, usable_only=True)


def compute_final_score(result: dict[str, Any]) -> float:
    if not result.get("connect_ok") or not result.get("proxy_ok"):
        return 0.0
    vpngate_score = max(0, int_value(result.get("vpngate_score")))
    vpngate_speed = max(0, int_value(result.get("vpngate_speed")))
    vpngate_ping = max(0, int_value(result.get("vpngate_ping"), 999999))
    connect_ms = max(1, int_value(result.get("connect_ms"), 999999))
    proxy_latency_ms = max(1, int_value(result.get("proxy_latency_ms"), 999999))
    score_part = min(vpngate_score / 10000.0, 100.0)
    speed_part = min(vpngate_speed / 1_000_000.0, 100.0)
    ping_part = max(0.0, 100.0 - (vpngate_ping / 5.0))
    connect_part = max(0.0, 100.0 - (connect_ms / 250.0))
    proxy_part = max(0.0, 100.0 - (proxy_latency_ms / 20.0))
    return round(score_part * 0.15 + speed_part * 0.25 + ping_part * 0.15 + connect_part * 0.2 + proxy_part * 0.25, 3)


def set_state(cfg: InstanceConfig, **items: Any) -> None:
    state = load_json(cfg.state_file, {})
    state.update(items)
    state["updated_at"] = time.time()
    write_json(cfg.state_file, state)


def log(cfg: InstanceConfig, message: str) -> None:
    cfg.log_file.parent.mkdir(parents=True, exist_ok=True)
    line = time.strftime("%Y-%m-%d %H:%M:%S") + " " + message
    print(line, flush=True)
    with cfg.log_file.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def country_tokens(value: str) -> set[str]:
    tokens: set[str] = set()
    for item in re.split(r"[,，;/\s]+", value or ""):
        item = item.strip().lower()
        if item:
            tokens.add(item)
            tokens.update(COUNTRY_ALIASES.get(item.upper(), set()))
    return tokens


def row_matches_country(row: dict[str, str], filter_text: str) -> bool:
    tokens = country_tokens(filter_text)
    if not tokens:
        return True
    row_values = {
        (row.get("CountryShort") or "").strip().lower(),
        (row.get("CountryLong") or "").strip().lower(),
    }
    for code, aliases in COUNTRY_ALIASES.items():
        if row.get("CountryShort", "").upper() == code:
            row_values.update(aliases)
    return bool(tokens & row_values)


def safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return value.strip("._") or "node"


def parse_remote(config_text: str, fallback_ip: str = "") -> tuple[str, int, str]:
    remote_host = fallback_ip
    remote_port = 0
    proto = "unknown"
    for raw_line in config_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        parts = line.split()
        if parts[0].lower() == "proto" and len(parts) >= 2:
            proto = parts[1].lower()
        elif parts[0].lower() == "remote" and len(parts) >= 3:
            remote_host = parts[1]
            remote_port = int(parts[2]) if parts[2].isdigit() else 0
    return remote_host, remote_port, proto


def fetch_vpngate_nodes(cfg: InstanceConfig) -> list[dict[str, Any]]:
    req = urllib.request.Request(API_URL, headers={"User-Agent": "eianun-vpngate-multi/1.0"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        text = resp.read().decode("utf-8", errors="replace")
    lines = [line for line in text.splitlines() if line and not line.startswith("*")]
    if lines and lines[0].startswith("#"):
        lines[0] = lines[0][1:]
    rows = list(csv.DictReader(lines))
    nodes: list[dict[str, Any]] = []
    for row in rows:
        encoded = row.get("OpenVPN_ConfigData_Base64", "")
        if not encoded or not row_matches_country(row, cfg.country_filter):
            continue
        try:
            config_text = base64.b64decode(encoded.encode("ascii"), validate=False).decode("utf-8", errors="replace")
        except Exception:
            continue
        remote_host, remote_port, proto = parse_remote(config_text, row.get("IP", ""))
        node_id = safe_name("_".join([row.get("CountryShort", "XX"), row.get("IP", remote_host), str(remote_port), proto]))
        nodes.append(
            {
                "id": node_id,
                "source": "vpngate",
                "country_short": row.get("CountryShort", ""),
                "country": row.get("CountryLong", ""),
                "ip": row.get("IP", ""),
                "host_name": row.get("HostName", ""),
                "score": int_value(row.get("Score")),
                "ping": int_value(row.get("Ping"), 999999),
                "speed": int_value(row.get("Speed")),
                "sessions": int_value(row.get("NumVpnSessions")),
                "uptime": int_value(row.get("Uptime")),
                "remote_host": remote_host,
                "remote_port": remote_port,
                "proto": proto,
                "config_text": config_text,
                "fetched_at": time.time(),
            }
        )
    nodes.sort(key=lambda n: (-int_value(n.get("score")), int_value(n.get("ping"), 999999), -int_value(n.get("speed"))))
    write_json(cfg.nodes_file, [{k: v for k, v in n.items() if k != "config_text"} for n in nodes])
    return nodes


def sanitize_openvpn_config(config_text: str, cfg: InstanceConfig) -> str:
    removed_prefixes = {
        "redirect-gateway",
        "route",
        "route-ipv6",
        "dhcp-option",
        "pull-filter",
        "dev",
        "dev-type",
        "up",
        "down",
        "route-up",
        "iproute",
        "script-security",
        "block-outside-dns",
    }
    kept: list[str] = []
    for raw in config_text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        stripped = raw.strip()
        if not stripped or stripped.startswith(("#", ";")):
            kept.append(raw)
            continue
        key = stripped.lower().split(None, 1)[0]
        if key in removed_prefixes:
            kept.append(f"# eianun multi removed unsafe directive: {stripped}")
            continue
        kept.append(raw)
    kept.extend(
        [
            "",
            "# Eianun multi-instance route isolation.",
            "route-nopull",
            "pull-filter ignore redirect-gateway",
            "pull-filter ignore dhcp-option",
            "pull-filter ignore route",
            "pull-filter ignore route-ipv6",
            f"dev {cfg.openvpn_dev_name}",
            "dev-type tun",
            "auth-nocache",
            "verb 3",
        ]
    )
    return "\n".join(kept).strip() + "\n"


def check_runtime_requirements() -> None:
    if not Path("/dev/net/tun").exists():
        die("/dev/net/tun 不存在，无法创建 OpenVPN TUN 设备")
    for cmd in ["openvpn", "ip", "iptables"]:
        if not command_exists(cmd):
            die(f"缺少依赖命令: {cmd}")


def netns_exists(ns: str) -> bool:
    return subprocess.run(["ip", "netns", "exec", ns, "true"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def cleanup_namespace(cfg: InstanceConfig) -> None:
    run_cmd(["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", f"{cfg.ns_veth_ip}/32", "-j", "MASQUERADE"], check=False)
    run_cmd(["ip", "netns", "pids", cfg.namespace], check=False, capture=True)
    run_cmd(["ip", "netns", "del", cfg.namespace], check=False)
    run_cmd(["ip", "link", "del", cfg.host_veth], check=False)


def setup_namespace(cfg: InstanceConfig) -> None:
    cleanup_namespace(cfg)
    run_cmd(["ip", "netns", "add", cfg.namespace])
    run_cmd(["ip", "link", "add", cfg.host_veth, "type", "veth", "peer", "name", cfg.ns_veth])
    run_cmd(["ip", "addr", "add", f"{cfg.host_veth_ip}/30", "dev", cfg.host_veth])
    run_cmd(["ip", "link", "set", cfg.host_veth, "up"])
    run_cmd(["ip", "link", "set", cfg.ns_veth, "netns", cfg.namespace])
    run_cmd(["ip", "netns", "exec", cfg.namespace, "ip", "addr", "add", f"{cfg.ns_veth_ip}/30", "dev", cfg.ns_veth])
    run_cmd(["ip", "netns", "exec", cfg.namespace, "ip", "link", "set", "lo", "up"])
    run_cmd(["ip", "netns", "exec", cfg.namespace, "ip", "link", "set", cfg.ns_veth, "up"])
    run_cmd(["ip", "netns", "exec", cfg.namespace, "ip", "route", "replace", "default", "via", cfg.host_veth_ip, "dev", cfg.ns_veth])
    run_cmd(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)
    nat_check = subprocess.run(["iptables", "-t", "nat", "-C", "POSTROUTING", "-s", f"{cfg.ns_veth_ip}/32", "-j", "MASQUERADE"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if nat_check.returncode != 0:
        run_cmd(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", f"{cfg.ns_veth_ip}/32", "-j", "MASQUERADE"], check=False)


def resolve_remote_for_route(host: str) -> str:
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        return socket.gethostbyname(host)


def openvpn_cmd(cfg: InstanceConfig) -> list[str]:
    return [
        "ip",
        "netns",
        "exec",
        cfg.namespace,
        "openvpn",
        "--config",
        str(cfg.generated_ovpn_file),
        "--dev",
        cfg.openvpn_dev_name,
        "--dev-type",
        "tun",
        "--route-nopull",
        "--pull-filter",
        "ignore",
        "redirect-gateway",
        "--pull-filter",
        "ignore",
        "dhcp-option",
        "--connect-retry-max",
        "1",
        "--connect-timeout",
        "20",
    ]


def wait_openvpn_ready(cfg: InstanceConfig, proc: subprocess.Popen[str], timeout: int = 45) -> bool:
    assert proc.stdout is not None
    started = time.time()
    while time.time() - started < timeout:
        line = proc.stdout.readline()
        if line:
            log(cfg, "[openvpn] " + line.rstrip())
            lower = line.lower()
            if "initialization sequence completed" in lower:
                return True
            if "auth_failed" in lower or "fatal error" in lower:
                return False
        elif proc.poll() is not None:
            return False
    return False


def start_openvpn(cfg: InstanceConfig, node: dict[str, Any], config_text: str | None = None, *, already_sanitized: bool = False) -> subprocess.Popen[str]:
    config_text = config_text if config_text is not None else str(node.get("config_text") or "")
    if not config_text:
        raise RuntimeError("节点缺少 OpenVPN 配置")
    cfg.generated_ovpn_file.write_text(config_text if already_sanitized else sanitize_openvpn_config(config_text, cfg), encoding="utf-8")
    remote_route_ip = ""
    try:
        remote_route_ip = resolve_remote_for_route(str(node.get("remote_host") or node.get("ip") or ""))
        if remote_route_ip:
            run_cmd(
                [
                    "ip",
                    "netns",
                    "exec",
                    cfg.namespace,
                    "ip",
                    "route",
                    "replace",
                    f"{remote_route_ip}/32",
                    "via",
                    cfg.host_veth_ip,
                    "dev",
                    cfg.ns_veth,
                ],
                check=False,
            )
    except Exception as exc:
        log(cfg, f"WARNING: failed to add OpenVPN server route: {exc}")
    proc = subprocess.Popen(openvpn_cmd(cfg), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
    if not wait_openvpn_ready(cfg, proc):
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        raise RuntimeError("OpenVPN 连接超时或失败")
    run_cmd(["ip", "netns", "exec", cfg.namespace, "ip", "route", "replace", "default", "dev", cfg.openvpn_dev_name], check=False)
    if remote_route_ip:
        run_cmd(["ip", "netns", "exec", cfg.namespace, "ip", "route", "replace", f"{remote_route_ip}/32", "via", cfg.host_veth_ip, "dev", cfg.ns_veth], check=False)
    log(cfg, f"OpenVPN connected: {node['id']} dev={cfg.openvpn_dev_name}")
    return proc


def start_proxy_in_namespace(cfg: InstanceConfig) -> subprocess.Popen[str]:
    env = os.environ.copy()
    env["PROXY_BIND_DEVICE"] = cfg.openvpn_dev_name
    cmd = [
        "ip",
        "netns",
        "exec",
        cfg.namespace,
        PYTHON_BIN,
        str(INSTALL_DIR / "proxy_server.py"),
        cfg.ns_veth_ip,
        str(cfg.proxy_port),
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", env=env)

    def reader() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            log(cfg, "[proxy] " + line.rstrip())

    threading.Thread(target=reader, daemon=True).start()
    time.sleep(1.0)
    if proc.poll() is not None:
        raise RuntimeError("代理端口启动失败")
    return proc


def terminate_process(proc: subprocess.Popen[str] | None, timeout: int = 8) -> None:
    if not proc or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass


class PortForwarder:
    def __init__(self, cfg: InstanceConfig) -> None:
        self.cfg = cfg
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.server: socket.socket | None = None

    def start(self) -> None:
        if port_in_use(self.cfg.proxy_bind_host, self.cfg.proxy_port):
            raise RuntimeError(f"端口已被占用: {self.cfg.proxy_bind_host}:{self.cfg.proxy_port}")
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        time.sleep(0.3)

    def run(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server = server
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.cfg.proxy_bind_host, self.cfg.proxy_port))
        server.listen(256)
        log(self.cfg, f"host forwarder listening on {self.cfg.proxy_bind_host}:{self.cfg.proxy_port} -> {self.cfg.ns_veth_ip}:{self.cfg.proxy_port}")
        while not self.stop_event.is_set():
            try:
                readable, _, _ = select.select([server], [], [], 0.5)
                if not readable:
                    continue
                client, _ = server.accept()
                threading.Thread(target=self.handle_client, args=(client,), daemon=True).start()
            except OSError:
                break

    def handle_client(self, client: socket.socket) -> None:
        upstream = None
        try:
            upstream = socket.create_connection((self.cfg.ns_veth_ip, self.cfg.proxy_port), timeout=8)
            relay_pair(client, upstream)
        except Exception as exc:
            log(self.cfg, f"forwarder connection failed: {exc}")
        finally:
            for sock in [client, upstream]:
                if sock:
                    try:
                        sock.close()
                    except OSError:
                        pass

    def stop(self) -> None:
        self.stop_event.set()
        if self.server:
            try:
                self.server.close()
            except OSError:
                pass


def relay_pair(left: socket.socket, right: socket.socket) -> None:
    sockets = [left, right]
    while True:
        readable, _, errored = select.select(sockets, [], sockets, 120)
        if errored:
            return
        for source in readable:
            data = source.recv(65536)
            if not data:
                return
            target = right if source is left else left
            target.sendall(data)


def http_get_via_socks5(host: str, port: int, url: str, timeout: int = 15) -> str:
    parsed = urllib.parse.urlparse(url)
    target_host = parsed.hostname or "api.ipify.org"
    target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        if sock.recv(2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 handshake failed")
        host_bytes = target_host.encode("idna")
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + target_port.to_bytes(2, "big"))
        resp = sock.recv(10)
        if len(resp) < 2 or resp[1] != 0:
            raise RuntimeError("SOCKS5 connect failed")
        request = f"GET {path} HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\nUser-Agent: eianun-vpngate-multi\r\n\r\n"
        sock.sendall(request.encode("ascii"))
        raw = b""
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            raw += chunk
        body = raw.split(b"\r\n\r\n", 1)[-1]
        return body.decode("utf-8", errors="replace").strip()
    finally:
        sock.close()


def benchmark_temp_config(cfg: InstanceConfig) -> InstanceConfig:
    temp_id = f"bm-{cfg.instance_id}"
    host_ip, ns_ip = instance_veth_ips(temp_id)
    port = find_free_port(cfg.proxy_bind_host)
    return replace(
        cfg,
        instance_id=temp_id,
        display_name=f"Benchmark-{cfg.instance_id}",
        proxy_port=port,
        runtime_dir=RUN_ROOT / temp_id,
        log_file=cfg.log_file,
        pid_file=RUN_ROOT / temp_id / "manager.pid",
        generated_ovpn_file=cfg.state_file.parent / "benchmark-current.ovpn",
        namespace=f"vg-{temp_id}"[:15],
        host_veth=f"vg{temp_id[:8]}h"[:15],
        ns_veth=f"vg{temp_id[:8]}n"[:15],
        host_veth_ip=host_ip,
        ns_veth_ip=ns_ip,
        openvpn_dev_name=f"tun-{temp_id}"[:15],
    )


def benchmark_one_node(cfg: InstanceConfig, base_cfg: InstanceConfig, node: dict[str, Any], direct_ip: str, *, download_test: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {
        "node_id": node.get("id"),
        "country_short": node.get("country_short"),
        "country": node.get("country"),
        "remote_host": node.get("remote_host"),
        "remote_port": node.get("remote_port"),
        "proto": node.get("proto"),
        "vpngate_score": node.get("score"),
        "vpngate_ping": node.get("ping"),
        "vpngate_speed": node.get("speed"),
        "connect_ok": False,
        "proxy_ok": False,
        "exit_ip": "",
        "connect_ms": None,
        "proxy_latency_ms": None,
        "download_bytes": None,
        "download_ms": None,
        "measured_at": iso_now(),
        "error": "",
        "final_score": 0.0,
    }
    openvpn_proc: subprocess.Popen[str] | None = None
    proxy_proc: subprocess.Popen[str] | None = None
    forwarder: PortForwarder | None = None
    try:
        cfg.ensure_dirs()
        setup_namespace(cfg)
        started = time.time()
        openvpn_proc = start_openvpn(cfg, node)
        result["connect_ms"] = int((time.time() - started) * 1000)
        result["connect_ok"] = True
        proxy_proc = start_proxy_in_namespace(cfg)
        forwarder = PortForwarder(cfg)
        forwarder.start()
        time.sleep(0.5)
        proxy_started = time.time()
        exit_ip = http_get_via_socks5(cfg.proxy_bind_host, cfg.proxy_port, BENCHMARK_IP_URL, timeout=15)
        result["proxy_latency_ms"] = int((time.time() - proxy_started) * 1000)
        result["exit_ip"] = exit_ip
        result["proxy_ok"] = bool(exit_ip and exit_ip != direct_ip)
        if not result["proxy_ok"]:
            result["error"] = f"出口 IP 未变化: direct={direct_ip or '-'} proxy={exit_ip or '-'}"
        if download_test and result["proxy_ok"]:
            dl_started = time.time()
            body = http_get_via_socks5(cfg.proxy_bind_host, cfg.proxy_port, BENCHMARK_DOWNLOAD_URL, timeout=20)
            result["download_ms"] = int((time.time() - dl_started) * 1000)
            result["download_bytes"] = len(body.encode("utf-8", errors="ignore"))
    except Exception as exc:
        result["error"] = str(exc)
        log(base_cfg, f"Benchmark failed {node.get('id')}: {exc}")
    finally:
        if forwarder:
            forwarder.stop()
        terminate_process(proxy_proc)
        terminate_process(openvpn_proc)
        cleanup_namespace(cfg)
        try:
            cfg.generated_ovpn_file.unlink()
        except FileNotFoundError:
            pass
    result["final_score"] = compute_final_score(result)
    return result


def benchmark_instance(cfg: InstanceConfig, *, download_test: bool = False) -> list[dict[str, Any]]:
    cfg.ensure_dirs()
    check_runtime_requirements()
    direct_ip = ""
    try:
        direct_ip = public_ip_direct()
    except Exception as exc:
        log(cfg, f"WARNING: failed to detect direct VPS IP: {exc}")
    nodes = fetch_vpngate_nodes(cfg)
    log(cfg, f"Benchmark {cfg.instance_id}: testing {len(nodes)} VPNGate nodes; direct_ip={direct_ip or '-'}")
    results: list[dict[str, Any]] = []
    temp_cfg = benchmark_temp_config(cfg)
    for index, node in enumerate(nodes, 1):
        log(cfg, f"Benchmark {cfg.instance_id}: [{index}/{len(nodes)}] {node.get('id')} {node.get('remote_host')}:{node.get('remote_port')}")
        result = benchmark_one_node(temp_cfg, cfg, node, direct_ip, download_test=download_test)
        results.append(result)
        write_json(cfg.benchmark_file, results)
    results.sort(key=lambda r: float(r.get("final_score") or 0), reverse=True)
    write_json(cfg.benchmark_file, results)
    set_state(cfg, benchmark_at=iso_now(), benchmark_nodes=len(results), benchmark_ok=sum(1 for r in results if r.get("connect_ok") and r.get("proxy_ok")))
    return results


def benchmark_command(args: argparse.Namespace) -> None:
    targets = iter_instances() if args.instance_id == "all" else [sanitize_instance_id(args.instance_id)]
    summary: list[dict[str, Any]] = []
    for iid in targets:
        try:
            cfg = InstanceConfig.load(iid)
            results = benchmark_instance(cfg, download_test=args.download_test)
            ok = sum(1 for r in results if r.get("connect_ok") and r.get("proxy_ok"))
            best = results[0] if results else {}
            summary.append({"instance": iid, "nodes": len(results), "ok": ok, "best": best.get("node_id"), "score": best.get("final_score")})
        except Exception as exc:
            summary.append({"instance": iid, "error": str(exc)})
            print(f"[{iid}] benchmark failed: {exc}", file=sys.stderr)
    print(json.dumps(summary if args.instance_id == "all" else summary[0], ensure_ascii=False, indent=2))


def best_command(args: argparse.Namespace) -> None:
    cfg = InstanceConfig.load(args.instance_id)
    results = benchmark_results_sorted(cfg)
    if not results:
        die(f"{cfg.instance_id}: 没有可用 benchmark 结果，请先运行 en multi benchmark {cfg.instance_id}")
    print(f"{'RANK':<5} {'NODE_ID':<32} {'EXIT_IP':<16} {'LAT_MS':<8} {'SPEED':<12} {'SCORE':<10} {'FINAL':<10}")
    for rank, item in enumerate(results[:10], 1):
        print(
            f"{rank:<5} {str(item.get('node_id','-'))[:31]:<32} {str(item.get('exit_ip','-')):<16} "
            f"{str(item.get('proxy_latency_ms','-')):<8} {str(item.get('vpngate_speed','-')):<12} "
            f"{str(item.get('vpngate_score','-')):<10} {str(item.get('final_score','-')):<10}"
        )


def fetch_node_config_by_id(cfg: InstanceConfig, node_id: str) -> dict[str, Any] | None:
    for node in fetch_vpngate_nodes(cfg):
        if node.get("id") == node_id:
            return node
    return None


def write_best_node(cfg: InstanceConfig, node: dict[str, Any], result: dict[str, Any]) -> None:
    sanitized = sanitize_openvpn_config(str(node["config_text"]), cfg)
    cfg.best_ovpn_file.write_text(sanitized, encoding="utf-8")
    best_data = node_public_fields(node)
    best_data.update(
        {
            "id": node.get("id"),
            "node_id": node.get("id"),
            "source": "benchmark",
            "selected_at": iso_now(),
            "benchmark_result": result,
            "best_ovpn": str(cfg.best_ovpn_file),
        }
    )
    write_json(cfg.best_node_file, best_data)


def current_sticky_result(cfg: InstanceConfig, results: list[dict[str, Any]]) -> dict[str, Any] | None:
    selected = load_json(cfg.selected_node_file, {})
    if not isinstance(selected, dict):
        selected = {}
    current_id = str(selected.get("id") or selected.get("node_id") or "")
    if not current_id:
        current_id = str(load_json(cfg.best_node_file, {}).get("node_id") or "")
    if not current_id:
        return None
    for item in results:
        if str(item.get("node_id") or "") != current_id:
            continue
        if not item.get("connect_ok") or not item.get("proxy_ok"):
            return None
        if float_value(item.get("final_score"), 0.0) < cfg.sticky_min_final_score:
            return None
        if int_value(item.get("proxy_latency_ms"), 999999) > cfg.sticky_max_proxy_latency_ms:
            return None
        return item
    return None


def select_result_for_policy(cfg: InstanceConfig, results: list[dict[str, Any]]) -> dict[str, Any]:
    ranked = [r for r in results if r.get("connect_ok") and r.get("proxy_ok")]
    ranked.sort(key=lambda r: float(r.get("final_score") or 0), reverse=True)
    if not ranked:
        raise RuntimeError("benchmark 未找到 connect_ok/proxy_ok 都通过的节点")
    mode = cfg.node_selection_mode if cfg.node_selection_mode in {"sticky", "benchmark"} else "sticky"
    if mode == "sticky":
        sticky = current_sticky_result(cfg, results)
        if sticky:
            return sticky
    return ranked[0]


def optimize_one(cfg: InstanceConfig, *, download_test: bool = False, restart: bool = True) -> dict[str, Any]:
    results = benchmark_instance(cfg, download_test=download_test)
    best_result = select_result_for_policy(cfg, results)
    node = fetch_node_config_by_id(cfg, str(best_result.get("node_id")))
    if not node:
        raise RuntimeError(f"无法重新获取最优节点配置: {best_result.get('node_id')}")
    write_best_node(cfg, node, best_result)
    set_state(
        cfg,
        best_node=node.get("id"),
        best_source="benchmark",
        best_selected_at=iso_now(),
        node_selection_mode=cfg.node_selection_mode,
        best_final_score=best_result.get("final_score"),
        best_exit_ip=best_result.get("exit_ip"),
        best_proxy_latency_ms=best_result.get("proxy_latency_ms"),
    )
    if restart:
        systemctl("restart", cfg.instance_id)
    return {"instance": cfg.instance_id, "best": node.get("id"), "exit_ip": best_result.get("exit_ip"), "final_score": best_result.get("final_score"), "restarted": restart}


def optimize_command(args: argparse.Namespace) -> None:
    targets = iter_instances() if args.instance_id == "all" else [sanitize_instance_id(args.instance_id)]
    summary: list[dict[str, Any]] = []
    for iid in targets:
        try:
            cfg = InstanceConfig.load(iid)
            summary.append(optimize_one(cfg, download_test=args.download_test, restart=not args.no_restart))
        except Exception as exc:
            summary.append({"instance": iid, "error": str(exc)})
            print(f"[{iid}] optimize failed: {exc}", file=sys.stderr)
    print(json.dumps(summary if args.instance_id == "all" else summary[0], ensure_ascii=False, indent=2))


def scheduled_optimize_loop(cfg: InstanceConfig, switch_event: threading.Event, stop_event: threading.Event) -> None:
    interval = cfg.benchmark_interval_seconds
    if interval <= 0:
        return
    log(cfg, f"Scheduled benchmark enabled: interval={interval}s mode={cfg.node_selection_mode}")
    while not stop_event.wait(interval):
        try:
            before = load_json(cfg.selected_node_file, {})
            before_id = str(before.get("id") or before.get("node_id") or "") if isinstance(before, dict) else ""
            result = optimize_one(cfg, download_test=False, restart=False)
            after_id = str(result.get("best") or "")
            log(cfg, f"Scheduled benchmark complete: selected={after_id} previous={before_id or '-'} score={result.get('final_score')}")
            if after_id and before_id and after_id != before_id:
                set_state(cfg, scheduled_switch_pending=True, scheduled_switch_to=after_id, scheduled_switch_at=iso_now())
                switch_event.set()
                return
        except Exception as exc:
            log(cfg, f"Scheduled benchmark failed: {exc}")
            set_state(cfg, scheduled_benchmark_error=str(exc), scheduled_benchmark_error_at=iso_now())


def no_node_retry_seconds(cfg: InstanceConfig) -> int:
    return cfg.benchmark_interval_seconds if cfg.benchmark_interval_seconds > 0 else DEFAULT_NO_NODE_RETRY_SECONDS


def wait_before_no_node_retry(cfg: InstanceConfig, stop_event: threading.Event, reason: str) -> bool:
    retry_seconds = no_node_retry_seconds(cfg)
    retry_at = time.time() + retry_seconds
    retry_at_text = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(retry_at))
    log(cfg, f"No usable node now; waiting {retry_seconds}s before pulling and benchmarking again: {reason}")
    set_state(
        cfg,
        status="waiting_for_nodes",
        error=reason,
        no_usable_nodes=True,
        next_retry_at=retry_at_text,
        retry_after_seconds=retry_seconds,
    )
    return stop_event.wait(retry_seconds)


def refresh_benchmark_before_retry(cfg: InstanceConfig) -> None:
    try:
        log(cfg, "Retry window reached; pulling VPNGate CSV and benchmarking before reconnect")
        optimize_one(cfg, download_test=False, restart=False)
    except Exception as exc:
        log(cfg, f"Retry benchmark did not find a usable node yet: {exc}")
        set_state(cfg, retry_benchmark_error=str(exc), retry_benchmark_error_at=iso_now())


def choose_and_connect(cfg: InstanceConfig) -> tuple[dict[str, Any], subprocess.Popen[str]]:
    errors: list[str] = []
    best = load_json(cfg.best_node_file, {})
    if isinstance(best, dict) and best and cfg.best_ovpn_file.exists():
        try:
            node = dict(best)
            node["id"] = node.get("id") or node.get("node_id")
            log(cfg, f"Trying pinned benchmark best node {node.get('id')} from {cfg.best_ovpn_file}")
            proc = start_openvpn(cfg, node, cfg.best_ovpn_file.read_text(encoding="utf-8", errors="replace"), already_sanitized=True)
            selected = node_public_fields(node)
            selected["selection_source"] = "benchmark_best"
            write_json(cfg.selected_node_file, selected)
            return node, proc
        except Exception as exc:
            errors.append(f"best {best.get('node_id') or best.get('id')}: {exc}")
            log(cfg, f"Pinned best node failed, trying benchmark ranking: {exc}")

    ranked = benchmark_ranked_results(cfg)
    if ranked:
        nodes_by_id = {str(n.get("id")): n for n in fetch_vpngate_nodes(cfg)}
        best_id = str(best.get("node_id") or best.get("id") or "")
        for rank, item in enumerate(ranked, 1):
            node_id = str(item.get("node_id") or "")
            if not node_id or node_id == best_id:
                continue
            node = nodes_by_id.get(node_id)
            if not node:
                errors.append(f"rank {rank} {node_id}: config not found")
                continue
            try:
                log(cfg, f"Trying benchmark ranked node #{rank} {node_id} final_score={item.get('final_score')}")
                proc = start_openvpn(cfg, node)
                selected = node_public_fields(node)
                selected.update({"selection_source": "benchmark_ranked", "benchmark_rank": rank, "benchmark_result": item})
                write_json(cfg.selected_node_file, selected)
                return node, proc
            except Exception as exc:
                errors.append(f"rank {rank} {node_id}: {exc}")
                log(cfg, f"Benchmark ranked node failed: #{rank} {node_id} {exc}")

    log(cfg, f"Fetching VPNGate nodes country_filter={cfg.country_filter or 'all'}")
    nodes = fetch_vpngate_nodes(cfg)
    log(cfg, f"VPNGate fetched/filtered nodes: {len(nodes)}")
    if not nodes:
        raise NoUsableNodes("没有可用 VPNGate 节点")
    for node in nodes[: max(1, cfg.auto_test_workers * 4)]:
        try:
            log(cfg, f"Trying node {node['id']} {node.get('country_short')} {node.get('remote_host')}:{node.get('remote_port')} score={node.get('score')} ping={node.get('ping')} speed={node.get('speed')}")
            proc = start_openvpn(cfg, node)
            selected = node_public_fields(node)
            selected["selection_source"] = "vpngate_default"
            write_json(cfg.selected_node_file, selected)
            return node, proc
        except Exception as exc:
            errors.append(f"{node.get('id')}: {exc}")
            log(cfg, f"Node failed: {node.get('id')} {exc}")
    raise NoUsableNodes("OpenVPN 连接失败: " + "; ".join(errors[-5:]))


def run_instance(args: argparse.Namespace) -> None:
    cfg = InstanceConfig.load(args.instance_id)
    cfg.ensure_dirs()
    cfg.pid_file.write_text(str(os.getpid()), encoding="utf-8")
    check_runtime_requirements()
    if cfg.proxy_bind_host != "127.0.0.1":
        log(cfg, f"WARNING: proxy_bind_host={cfg.proxy_bind_host}; 请使用防火墙限制访问")
    set_state(
        cfg,
        status="starting",
        instance_id=cfg.instance_id,
        proxy=f"{cfg.proxy_bind_host}:{cfg.proxy_port}",
        scheduled_switch_pending=False,
        scheduled_switch_to="",
    )
    openvpn_proc: subprocess.Popen[str] | None = None
    proxy_proc: subprocess.Popen[str] | None = None
    forwarder: PortForwarder | None = None
    stop_event = threading.Event()
    switch_event = threading.Event()

    def handle_signal(signum: int, frame: Any) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    try:
        while not stop_event.is_set():
            try:
                setup_namespace(cfg)
                node, openvpn_proc = choose_and_connect(cfg)
                break
            except NoUsableNodes as exc:
                cleanup_namespace(cfg)
                if wait_before_no_node_retry(cfg, stop_event, str(exc)):
                    raise SystemExit(0)
                refresh_benchmark_before_retry(cfg)
        else:
            raise SystemExit(0)
        if openvpn_proc is None:
            raise SystemExit(0)
        proxy_proc = start_proxy_in_namespace(cfg)
        forwarder = PortForwarder(cfg)
        forwarder.start()
        threading.Thread(target=scheduled_optimize_loop, args=(cfg, switch_event, stop_event), daemon=True).start()
        time.sleep(1)
        exit_ip = ""
        try:
            exit_ip = http_get_via_socks5(cfg.proxy_bind_host, cfg.proxy_port, cfg.health_check_url)
        except Exception as exc:
            log(cfg, f"出口 IP 检测失败: {exc}")
        log(cfg, f"Instance ready. selected={node['id']} exit_ip={exit_ip or '-'}")
        set_state(
            cfg,
            status="running",
            selected_node=node["id"],
            selection_source=load_json(cfg.selected_node_file, {}).get("selection_source", "unknown"),
            country=node.get("country"),
            country_short=node.get("country_short"),
            score=node.get("score"),
            ping=node.get("ping"),
            speed=node.get("speed"),
            exit_ip=exit_ip,
            proxy=f"{cfg.proxy_bind_host}:{cfg.proxy_port}",
        )
        while not stop_event.is_set():
            if switch_event.is_set():
                raise RuntimeError("定时测速选择了新的最优节点，触发实例重启以切换出口")
            if openvpn_proc.poll() is not None:
                raise RuntimeError("OpenVPN 进程已退出")
            if proxy_proc.poll() is not None:
                raise RuntimeError("代理进程已退出")
            time.sleep(2)
    except Exception as exc:
        log(cfg, f"FATAL: {exc}")
        set_state(cfg, status="failed", error=str(exc))
        raise
    finally:
        if forwarder:
            forwarder.stop()
        for proc in [proxy_proc, openvpn_proc]:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.kill()
        cleanup_namespace(cfg)
        set_state(cfg, status="stopped")
        try:
            cfg.pid_file.unlink()
        except FileNotFoundError:
            pass


def systemctl(action: str, instance_id: str | None = None) -> None:
    if instance_id:
        run_cmd(["systemctl", action, f"eianun-vpngate@{instance_id}.service"], check=False)
    else:
        run_cmd(["systemctl", action], check=False)


def service_is_active(instance_id: str) -> bool:
    try:
        res = subprocess.run(["systemctl", "is-active", "--quiet", f"eianun-vpngate@{instance_id}.service"])
        return res.returncode == 0
    except FileNotFoundError:
        return False


def iter_instances() -> list[str]:
    if not INSTANCE_CONFIG_DIR.exists():
        return []
    return sorted(p.stem for p in INSTANCE_CONFIG_DIR.glob("*.env"))


def list_instances(_: argparse.Namespace) -> None:
    ids = iter_instances()
    if not ids:
        print("No instances. Run: en multi add jp --country 'JP,日本' --port 7928 --iptype all")
        return
    print(f"{'ID':<8} {'PORT':<18} {'ACTIVE':<8} {'EXIT_IP':<16} {'COUNTRY':<10} {'PING':<8} {'SCORE':<10} NAME")
    for iid in ids:
        cfg = InstanceConfig.load(iid)
        state = load_json(cfg.state_file, {})
        active = "yes" if service_is_active(iid) else "no"
        print(
            f"{iid:<8} {cfg.proxy_bind_host + ':' + str(cfg.proxy_port):<18} {active:<8} "
            f"{str(state.get('exit_ip','-')):<16} {str(state.get('country_short') or cfg.country_filter or '-'):<10} "
            f"{str(state.get('ping','-')):<8} {str(state.get('score','-')):<10} {cfg.display_name}"
        )


def status_instance(args: argparse.Namespace) -> None:
    ids = [args.instance_id] if args.instance_id else iter_instances()
    for iid in ids:
        cfg = InstanceConfig.load(iid)
        state = load_json(cfg.state_file, {})
        selected = load_json(cfg.selected_node_file, {})
        if not isinstance(selected, dict):
            selected = {}
        ranked = benchmark_ranked_results(cfg)
        selected_id = selected.get("id", state.get("selected_node", "-"))
        selected_rank = "-"
        selected_benchmark = selected.get("benchmark_result") if isinstance(selected, dict) else None
        for rank, item in enumerate(ranked, 1):
            if item.get("node_id") == selected_id:
                selected_rank = rank
                selected_benchmark = item
                break
        if not isinstance(selected_benchmark, dict):
            selected_benchmark = {}
        print(f"[{iid}] {cfg.display_name}")
        print(f"  service: {'active' if service_is_active(iid) else 'inactive'}")
        print(f"  proxy: socks/http {cfg.proxy_bind_host}:{cfg.proxy_port}")
        print(f"  country_filter: {cfg.country_filter or 'all'}")
        print(f"  selection_policy: mode={cfg.node_selection_mode} interval={cfg.benchmark_interval_seconds}s sticky_min_score={cfg.sticky_min_final_score} sticky_max_latency={cfg.sticky_max_proxy_latency_ms}ms")
        print(f"  namespace: {cfg.namespace} dev={cfg.openvpn_dev_name}")
        print(f"  status: {state.get('status', '-')}")
        print(f"  exit_ip: {state.get('exit_ip', '-')}")
        print(f"  selected_node: {selected_id}")
        print(f"  selection_source: {selected.get('selection_source', state.get('selection_source', '-'))}")
        print(f"  node_country: {selected.get('country_short', state.get('country_short', '-'))} {selected.get('country', state.get('country', ''))}")
        print(f"  ping/speed/score: {selected.get('ping', state.get('ping', '-'))}/{selected.get('speed', state.get('speed', '-'))}/{selected.get('score', state.get('score', '-'))}")
        print(f"  benchmark_time: {state.get('benchmark_at', '-')}")
        print(f"  benchmark_rank: {selected_rank}")
        print(f"  benchmark_final_score: {selected_benchmark.get('final_score', state.get('best_final_score', '-'))}")
        print(f"  benchmark_proxy_latency_ms: {selected_benchmark.get('proxy_latency_ms', state.get('best_proxy_latency_ms', '-'))}")
        print(f"  benchmark_exit_ip: {selected_benchmark.get('exit_ip', state.get('best_exit_ip', '-'))}")
        if state.get("scheduled_switch_pending"):
            print(f"  scheduled_switch_pending: {state.get('scheduled_switch_to', '-')}")
        if state.get("scheduled_benchmark_error"):
            print(f"  scheduled_benchmark_error: {state.get('scheduled_benchmark_error')}")
        if state.get("error"):
            print(f"  error: {state['error']}")


def logs_instance(args: argparse.Namespace) -> None:
    cfg = InstanceConfig.load(args.instance_id)
    if args.follow:
        subprocess.run(["tail", "-n", str(args.lines), "-f", str(cfg.log_file)])
    else:
        subprocess.run(["tail", "-n", str(args.lines), str(cfg.log_file)])


def start_stop_restart(args: argparse.Namespace) -> None:
    if args.action in {"start", "restart"}:
        init_multi()
    systemctl(args.action, args.instance_id)


def delete_instance(args: argparse.Namespace) -> None:
    iid = sanitize_instance_id(args.instance_id)
    if service_is_active(iid) and not args.force:
        die("服务仍在运行，请先 en multi stop，或使用 --force")
    systemctl("stop", iid)
    for path in [INSTANCE_CONFIG_DIR / f"{iid}.env", STATE_ROOT / iid, RUN_ROOT / iid, LOG_ROOT / f"{iid}.log"]:
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()
    print(f"deleted instance {iid}")


def test_instance(args: argparse.Namespace) -> None:
    cfg = InstanceConfig.load(args.instance_id)
    started = time.time()
    ip = http_get_via_socks5(cfg.proxy_bind_host, cfg.proxy_port, cfg.health_check_url)
    latency = int((time.time() - started) * 1000)
    print(json.dumps({"ok": True, "instance": cfg.instance_id, "proxy": f"{cfg.proxy_bind_host}:{cfg.proxy_port}", "exit_ip": ip, "latency_ms": latency}, ensure_ascii=False, indent=2))


def switch_instance(args: argparse.Namespace) -> None:
    systemctl("restart", args.instance_id)


def config_instance(args: argparse.Namespace) -> None:
    cfg = InstanceConfig.load(args.instance_id)
    print((INSTANCE_CONFIG_DIR / f"{cfg.instance_id}.env").read_text(encoding="utf-8"))


def policy_instance(args: argparse.Namespace) -> None:
    iid = sanitize_instance_id(args.instance_id)
    path = INSTANCE_CONFIG_DIR / f"{iid}.env"
    values = parse_env_file(path)
    if args.selection_mode:
        values["NODE_SELECTION_MODE"] = args.selection_mode
    if args.benchmark_interval is not None:
        values["BENCHMARK_INTERVAL_SECONDS"] = max(0, args.benchmark_interval)
    if args.sticky_min_score is not None:
        values["STICKY_MIN_FINAL_SCORE"] = args.sticky_min_score
    if args.sticky_max_latency is not None:
        values["STICKY_MAX_PROXY_LATENCY_MS"] = max(1, args.sticky_max_latency)
    write_env_file(path, values)
    cfg = InstanceConfig.load(iid)
    print(
        json.dumps(
            {
                "instance": iid,
                "node_selection_mode": cfg.node_selection_mode,
                "benchmark_interval_seconds": cfg.benchmark_interval_seconds,
                "sticky_min_final_score": cfg.sticky_min_final_score,
                "sticky_max_proxy_latency_ms": cfg.sticky_max_proxy_latency_ms,
                "restart_required": service_is_active(iid),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


def ports(_: argparse.Namespace) -> None:
    for iid in iter_instances():
        cfg = InstanceConfig.load(iid)
        print(f"{iid:<8} {cfg.proxy_bind_host}:{cfg.proxy_port:<6} {'USED' if port_in_use(cfg.proxy_bind_host, cfg.proxy_port) else 'free'}")


def xray_snippet(_: argparse.Namespace) -> None:
    outbounds = []
    rules = []
    for iid in iter_instances():
        cfg = InstanceConfig.load(iid)
        outbounds.append(
            {
                "tag": f"vpngate-{iid}-out",
                "protocol": "socks",
                "settings": {"servers": [{"address": cfg.proxy_bind_host, "port": cfg.proxy_port}]},
            }
        )
        rules.append({"type": "field", "inboundTag": [f"vless-vpngate-{iid}"], "outboundTag": f"vpngate-{iid}-out"})
    print(json.dumps({"outbounds": outbounds, "routing_rules_example": rules}, ensure_ascii=False, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="eianun_multi.py")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init").set_defaults(func=lambda args: init_multi())
    add = sub.add_parser("add")
    add.add_argument("instance_id")
    add.add_argument("--country", required=True)
    add.add_argument("--port", type=int, required=True)
    add.add_argument("--iptype", default="all")
    add.add_argument("--selection-mode", choices=["sticky", "benchmark"], default="sticky")
    add.add_argument("--benchmark-interval", type=int, default=0, help="scheduled benchmark interval in seconds; 0 disables it")
    add.add_argument("--sticky-min-score", type=float, default=30.0)
    add.add_argument("--sticky-max-latency", type=int, default=3000)
    add.add_argument("--force", action="store_true")
    add.set_defaults(func=add_instance)
    sub.add_parser("list").set_defaults(func=list_instances)
    status = sub.add_parser("status")
    status.add_argument("instance_id", nargs="?")
    status.set_defaults(func=status_instance)
    logs = sub.add_parser("logs")
    logs.add_argument("instance_id")
    logs.add_argument("-n", "--lines", type=int, default=80)
    logs.add_argument("-f", "--follow", action="store_true", default=True)
    logs.set_defaults(func=logs_instance)
    for action in ["start", "stop", "restart"]:
        p = sub.add_parser(action)
        p.add_argument("instance_id")
        p.set_defaults(func=start_stop_restart, action=action)
    delete = sub.add_parser("delete")
    delete.add_argument("instance_id")
    delete.add_argument("--force", action="store_true")
    delete.set_defaults(func=delete_instance)
    test = sub.add_parser("test")
    test.add_argument("instance_id")
    test.set_defaults(func=test_instance)
    benchmark = sub.add_parser("benchmark")
    benchmark.add_argument("instance_id", help="instance_id or all")
    benchmark.add_argument("--download-test", action="store_true", help="also test a small HTTP download through the proxy")
    benchmark.set_defaults(func=benchmark_command)
    best = sub.add_parser("best")
    best.add_argument("instance_id")
    best.set_defaults(func=best_command)
    optimize = sub.add_parser("optimize")
    optimize.add_argument("instance_id", help="instance_id or all")
    optimize.add_argument("--download-test", action="store_true", help="also test a small HTTP download during benchmark")
    optimize.add_argument("--no-restart", action="store_true", help="write best_node.json and best.ovpn without restarting the instance")
    optimize.set_defaults(func=optimize_command)
    switch = sub.add_parser("switch")
    switch.add_argument("instance_id")
    switch.set_defaults(func=switch_instance)
    config = sub.add_parser("config")
    config.add_argument("instance_id")
    config.set_defaults(func=config_instance)
    policy = sub.add_parser("policy")
    policy.add_argument("instance_id")
    policy.add_argument("--selection-mode", choices=["sticky", "benchmark"])
    policy.add_argument("--benchmark-interval", type=int, help="scheduled benchmark interval in seconds; 0 disables it")
    policy.add_argument("--sticky-min-score", type=float)
    policy.add_argument("--sticky-max-latency", type=int)
    policy.set_defaults(func=policy_instance)
    sub.add_parser("ports").set_defaults(func=ports)
    sub.add_parser("xray-snippet").set_defaults(func=xray_snippet)
    run = sub.add_parser("run")
    run.add_argument("instance_id")
    run.set_defaults(func=run_instance)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
