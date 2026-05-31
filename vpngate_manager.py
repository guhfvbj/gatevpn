#!/usr/bin/env python3
from __future__ import annotations

import base64
import csv
import json
import os
import queue
import re
import select
import shlex
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import concurrent.futures
import sys
import uuid

# Force socket to resolve IPv4 only to avoid slow AAAA (IPv6) DNS resolution timeouts (e.g. in WSL)
_orig_getaddrinfo = socket.getaddrinfo
def _ipv4_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if family == 0:
        family = socket.AF_INET
    return _orig_getaddrinfo(host, port, family, type, proto, flags)
socket.getaddrinfo = _ipv4_getaddrinfo

import vpn_utils
import proxy_server

API_URL = "https://www.vpngate.net/api/iphone/"
VPNBOOK_OPENVPN_URL = os.environ.get("VPNBOOK_OPENVPN_URL", "https://www.vpnbook.com/freevpn/openvpn")
VPNBOOK_TEMPLATE_OVPN_URLS = os.environ.get(
    "VPNBOOK_TEMPLATE_OVPN_URLS",
    "https://raw.githubusercontent.com/Sadaqaty/VPNed-Wifi-Access-Point/refs/heads/main/vpnbook-openvpn-us16/vpnbook-us16-tcp443.ovpn"
)
_vpnbook_template_config_cache = ""
NODE_SOURCES_ENV = os.environ.get("NODE_SOURCES") or os.environ.get("VPN_NODE_SOURCES") or ""
# 默认启用 VPNGate + VPNBook；可在面板里调整为 vpngate / vpnbook / vpngate,vpnbook。
DEFAULT_NODE_SOURCES = os.environ.get("DEFAULT_NODE_SOURCES", "vpngate,vpnbook")
# VPNBook 的免费节点经常推送较激进的路由/认证参数；默认只抓取 TCP 443，避免一次性生成太多待测节点。
VPNBOOK_PROTOCOLS = os.environ.get("VPNBOOK_PROTOCOLS", "tcp443")
# VPNBook 自动检测默认关闭：混合来源时只把 VPNBook 放入节点池，不在启动阶段批量跑 OpenVPN 握手。
# 这样可以避免部分 VPS 在检测 VPNBook 节点时 SSH 卡死。需要时可以在面板单个检测/手动切换，或显式开启。
VPNBOOK_AUTO_TEST = os.environ.get("VPNBOOK_AUTO_TEST", "0").strip().lower() in {"1", "true", "yes", "on"}
VPNBOOK_ONLY_SAFE_AUTO_TEST_LIMIT = max(1, int(os.environ.get("VPNBOOK_ONLY_SAFE_AUTO_TEST_LIMIT", "1")))
# VPNBook 的 .ovpn 配置和服务端推送参数比较激进，单个“检测”也可能改系统路由拖死 SSH。
# 默认对 VPNBook 使用安全检测：只做 TCP/风控，不启动 OpenVPN 握手；真正连接时再启动 OpenVPN，且会禁止 OpenVPN 写系统路由。
VPNBOOK_SAFE_TEST_ONLY = os.environ.get("VPNBOOK_SAFE_TEST_ONLY", "1").strip().lower() in {"1", "true", "yes", "on"}
VPNBOOK_CONNECT_TIMEOUT_SECONDS = int(os.environ.get("VPNBOOK_CONNECT_TIMEOUT_SECONDS", "25"))
FETCH_INTERVAL_SECONDS = int(os.environ.get("FETCH_INTERVAL_SECONDS", "960"))
CHECK_INTERVAL_SECONDS = int(os.environ.get("CHECK_INTERVAL_SECONDS", "960"))
TARGET_VALID_NODES = int(os.environ.get("TARGET_VALID_NODES", "3"))
MAX_SCAN_ROWS = int(os.environ.get("MAX_SCAN_ROWS", "300"))
OPENVPN_TEST_TIMEOUT_SECONDS = int(os.environ.get("OPENVPN_TEST_TIMEOUT_SECONDS", "35"))
OPENVPN_CMD = os.environ.get("OPENVPN_CMD", "openvpn")
OPENVPN_AUTH_USER = os.environ.get("OPENVPN_AUTH_USER", "vpn")
OPENVPN_AUTH_PASS = os.environ.get("OPENVPN_AUTH_PASS", "vpn")
LOCAL_PROXY_HOST = os.environ.get("LOCAL_PROXY_HOST", "127.0.0.1")
LOCAL_PROXY_PORT = int(os.environ.get("LOCAL_PROXY_PORT", "7928"))
UI_HOST = os.environ.get("UI_HOST", "0.0.0.0")
UI_PORT = int(os.environ.get("UI_PORT", "8787"))
INVALID_BACKOFF_SECONDS = int(os.environ.get("INVALID_BACKOFF_SECONDS", str(30 * 60)))
# 1 = 手动选择某个地区节点后，故障转移只在同地区内切换；0 = 同地区无可用时允许跨地区兜底。
STRICT_COUNTRY_FAILOVER = os.environ.get("STRICT_COUNTRY_FAILOVER", "1").strip().lower() not in {"0", "false", "no", "off"}
TARGET_COUNTRIES_ENV = os.environ.get("VPNGATE_TARGET_COUNTRIES") or os.environ.get("TARGET_COUNTRIES") or os.environ.get("TARGET_COUNTRY") or ""
# 风控策略：默认“优先干净，但不断线”。
# strict   = 自动故障转移只选低风险干净 IP；没有干净节点就等待补充。
# balanced = 默认模式，先选干净 IP；如果同地区全是高欺诈值/代理节点，则选择综合风险最低的可用节点兜底。
# loose    = 自动故障转移只按连通性和延迟排序，风控仅作展示。
MAX_AUTO_FRAUD_SCORE = int(os.environ.get("MAX_AUTO_FRAUD_SCORE", "25"))
AUTO_RISK_MODE = os.environ.get("AUTO_RISK_MODE", "balanced").strip().lower()
if AUTO_RISK_MODE not in {"strict", "balanced", "loose"}:
    AUTO_RISK_MODE = "balanced"
AUTO_MIN_KEEP_RUNNING = os.environ.get("AUTO_MIN_KEEP_RUNNING", "1").strip().lower() not in {"0", "false", "no", "off"}
ALLOW_RISKY_IP_CONNECT = os.environ.get("ALLOW_RISKY_IP_CONNECT", "0").strip().lower() in {"1", "true", "yes", "on"}
ALLOW_MANUAL_RISKY_CONNECT = os.environ.get("ALLOW_MANUAL_RISKY_CONNECT", "1").strip().lower() not in {"0", "false", "no", "off"}
# 自动选择/故障转移的 IP 类型优先级。默认住宅 IP 优先，但不会把自动保活卡死；
# 没有首选类型时会按 住宅 -> 移动 -> 普通/未知 -> 机房 -> 代理/Tor 逐级兜底。
# 可用值：residential, mobile, normal, hosting, proxy, tor, unknown, all。
# 只有用户显式设置环境变量时才覆盖面板保存值。
TARGET_IP_TYPES_ENV = os.environ.get("TARGET_IP_TYPES") or os.environ.get("AUTO_IP_TYPES") or os.environ.get("TARGET_IP_TYPE") or ""
# 1 = 恢复旧逻辑，把 TARGET_IP_TYPES 当作硬过滤；0 = 默认，将其作为优先级，必要时兜底到代理 IP 保持运行。
STRICT_IP_TYPE_FILTER = os.environ.get("STRICT_IP_TYPE_FILTER", "0").strip().lower() in {"1", "true", "yes", "on"}

# 自动节点检测策略。默认会检测本轮拉取/缓存中的全部非活动节点，
# 但会限制并发数量，避免一次性拉起过多 OpenVPN 进程导致 VPS 卡死。
AUTO_TEST_ALL_NODES = os.environ.get("AUTO_TEST_ALL_NODES", "1").strip().lower() not in {"0", "false", "no", "off"}
AUTO_TEST_MAX_NODES = int(os.environ.get("AUTO_TEST_MAX_NODES", "0"))  # 0 = 不额外限制，最多受 MAX_SCAN_ROWS 影响
AUTO_TEST_WORKERS = max(1, int(os.environ.get("AUTO_TEST_WORKERS", "8")))
# 首次启动/更新时先同步检测少量节点，避免安装脚本和面板长时间停在 0/N。
# 剩余节点会转入后台继续检测，并在检测完成后参与自动优选。
AUTO_TEST_INITIAL_BATCH = max(1, int(os.environ.get("AUTO_TEST_INITIAL_BATCH", "8")))
OPENVPN_BATCH_TEST_TIMEOUT_SECONDS = int(os.environ.get("OPENVPN_BATCH_TEST_TIMEOUT_SECONDS", "12"))

# 自动优选策略：全部节点检测完成后，主动从已检测可用节点中按地区、IP类型、风控、延迟重新选择更优节点。
# 这不是只在断线时才切换；如果当前节点明显比候选节点差，也会自动换到更优节点。
# AUTO_SELECT_BEST_NODE 环境变量存在时优先级最高；未设置时可在 Web 面板里开关。
AUTO_SELECT_BEST_NODE_ENV = os.environ.get("AUTO_SELECT_BEST_NODE")
AUTO_SELECT_BEST_NODE = (AUTO_SELECT_BEST_NODE_ENV or "1").strip().lower() not in {"0", "false", "no", "off"}
AUTO_SELECT_COOLDOWN_SECONDS = int(os.environ.get("AUTO_SELECT_COOLDOWN_SECONDS", "600"))
AUTO_SWITCH_MIN_FRAUD_DELTA = int(os.environ.get("AUTO_SWITCH_MIN_FRAUD_DELTA", "20"))
AUTO_SWITCH_MIN_LATENCY_DELTA_MS = int(os.environ.get("AUTO_SWITCH_MIN_LATENCY_DELTA_MS", "300"))

ROOT_DIR = Path(sys.executable).resolve().parent if globals().get("__compiled__") else Path(__file__).resolve().parent
DATA_DIR = Path(os.environ["VPNGATE_DATA_DIR"]).resolve() if os.environ.get("VPNGATE_DATA_DIR") else ROOT_DIR / "vpngate_data"
CONFIG_DIR = DATA_DIR / "configs"
NODES_FILE = DATA_DIR / "nodes.json"
STATE_FILE = DATA_DIR / "state.json"
AUTH_FILE = DATA_DIR / "vpngate_auth.txt"

lock = threading.RLock()
active_sessions: dict[str, float] = {}
active_openvpn_process: subprocess.Popen[str] | None = None
active_openvpn_node_id = ""
is_connecting = True
last_active_ping_time = 0.0
last_active_latency = 0

def ensure_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    CONFIG_DIR.mkdir(exist_ok=True)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text(f"{OPENVPN_AUTH_USER}\n{OPENVPN_AUTH_PASS}\n", encoding="utf-8")
        try:
            AUTH_FILE.chmod(0o600)
        except OSError:
            pass

def write_json(path: Path, data: Any) -> None:
    with lock:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)

def read_json(path: Path, default: Any) -> Any:
    with lock:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default

import hashlib
import random

def generate_random_password() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        pwd = "".join(random.choices(chars, k=12))
        # Ensure it contains at least one lowercase, one uppercase, and one digit
        has_lower = any(c.islower() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        if has_lower and has_upper and has_digit:
            return pwd

def generate_random_username() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        uname = "".join(random.choices(chars, k=12))
        # Ensure it starts with a letter and contains at least one lowercase, one uppercase, and one digit
        if uname[0].isalpha():
            has_lower = any(c.islower() for c in uname)
            has_upper = any(c.isupper() for c in uname)
            has_digit = any(c.isdigit() for c in uname)
            if has_lower and has_upper and has_digit:
                return uname

def load_ui_config() -> dict[str, Any]:
    with lock:
        auth_file = DATA_DIR / "ui_auth.json"
        config = {
            "username": "",
            "secret_path": "EJsW2EeBo9lY",
            "password": "",
            "host": "0.0.0.0",
            "port": 8787,
            "target_countries": TARGET_COUNTRIES_ENV,
            "target_ip_types": TARGET_IP_TYPES_ENV or "residential",
            "auto_select_best_node": AUTO_SELECT_BEST_NODE,
            "node_sources": NODE_SOURCES_ENV or DEFAULT_NODE_SOURCES
        }
        updated = False
        if auth_file.exists():
            try:
                data = json.loads(auth_file.read_text(encoding="utf-8"))
                for key, val in data.items():
                    config[key] = val
            except Exception:
                pass
        if TARGET_COUNTRIES_ENV:
            config["target_countries"] = TARGET_COUNTRIES_ENV
        if TARGET_IP_TYPES_ENV:
            config["target_ip_types"] = TARGET_IP_TYPES_ENV
        if AUTO_SELECT_BEST_NODE_ENV is not None and AUTO_SELECT_BEST_NODE_ENV.strip():
            config["auto_select_best_node"] = AUTO_SELECT_BEST_NODE
        if NODE_SOURCES_ENV:
            config["node_sources"] = NODE_SOURCES_ENV
        
        if not config.get("username"):
            config["username"] = generate_random_username()
            updated = True
            
        if not config.get("password"):
            config["password"] = generate_random_password()
            updated = True
            
        if not auth_file.exists() or updated:
            try:
                DATA_DIR.mkdir(exist_ok=True, parents=True)
                auth_file.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass
                
        return config


def split_target_countries(value: Any) -> list[str]:
    if isinstance(value, list):
        raw = ",".join(str(item) for item in value)
    else:
        raw = str(value or "")
    return [item.strip() for item in re.split(r"[,，;；|/\s]+", raw) if item.strip()]

def normalize_country_token(value: Any) -> str:
    return re.sub(r"[^0-9a-z\u4e00-\u9fff]+", "", str(value or "").strip().lower())

def normalize_target_countries_input(value: Any) -> str:
    # Accept ISO country codes (JP/US/KR), English names, or Chinese names.
    # Keep the saved value readable while deduplicating normalized tokens.
    result: list[str] = []
    seen: set[str] = set()
    for item in split_target_countries(value):
        token = normalize_country_token(item)
        if token and token not in seen:
            result.append(item)
            seen.add(token)
    return ",".join(result)


def split_node_sources(value: Any) -> list[str]:
    raw = str(value or "")
    aliases = {
        "vpngate": "vpngate", "vpn_gate": "vpngate", "gate": "vpngate", "vg": "vpngate", "筑波": "vpngate",
        "vpnbook": "vpnbook", "book": "vpnbook", "vb": "vpnbook",
    }
    result: list[str] = []
    seen: set[str] = set()
    for part in re.split(r"[,，;；|/\s]+", raw):
        token = part.strip().lower().replace("-", "_")
        if not token:
            continue
        canonical = aliases.get(token, token)
        if canonical in {"all", "全部", "*"}:
            canonical = "vpngate,vpnbook"
        for item in str(canonical).split(","):
            item = item.strip()
            if item in {"vpngate", "vpnbook"} and item not in seen:
                result.append(item)
                seen.add(item)
    return result or ["vpngate", "vpnbook"]

def normalize_node_sources_input(value: Any) -> str:
    return ",".join(split_node_sources(value))

def get_node_sources() -> list[str]:
    cfg = load_ui_config()
    return split_node_sources(NODE_SOURCES_ENV or cfg.get("node_sources") or DEFAULT_NODE_SOURCES)

def node_sources_display(value: Any) -> str:
    labels = {"vpngate": "VPNGate", "vpnbook": "VPNBook"}
    return " + ".join(labels.get(x, x) for x in split_node_sources(value))

def get_target_countries() -> list[str]:
    cfg = load_ui_config()
    return split_target_countries(cfg.get("target_countries") or TARGET_COUNTRIES_ENV)

IP_TYPE_ALIASES: dict[str, tuple[str, ...]] = {
    "residential": ("residential", "住宅", "家宽", "原生", "home", "isp", "clean_residential"),
    "mobile": ("mobile", "移动", "手机", "蜂窝"),
    "normal": ("normal", "普通", "unknown", "未知", "空", "未识别", ""),
    "hosting": ("hosting", "datacenter", "data_center", "dc", "机房", "数据中心", "服务器", "vps", "cloud"),
    "proxy": ("proxy", "代理", "vpn"),
    "tor": ("tor", "洋葱"),
}

def normalize_ip_type_token(value: Any) -> str:
    token = str(value or "").strip().lower().replace(" ", "_").replace("-", "_")
    if token in {"all", "any", "全部", "不限", "任意", "*"}:
        return "all"
    for canonical, aliases in IP_TYPE_ALIASES.items():
        if token in {str(a).strip().lower().replace(" ", "_").replace("-", "_") for a in aliases}:
            return canonical
    return token

def split_target_ip_types(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        raw_parts = [str(x).strip() for x in value]
    else:
        raw_parts = re.split(r"[,，;；\s]+", str(value or ""))
    result: list[str] = []
    seen: set[str] = set()
    for part in raw_parts:
        token = normalize_ip_type_token(part)
        if not token:
            continue
        if token == "all":
            return []
        if token not in seen:
            result.append(token)
            seen.add(token)
    return result

def normalize_target_ip_types_input(value: Any) -> str:
    # Preserve explicit all/全部 so the UI can distinguish it from an empty default.
    if isinstance(value, str):
        raw_parts = re.split(r"[,，;；\s]+", value)
        if any(normalize_ip_type_token(part) == "all" for part in raw_parts if part.strip()):
            return "all"
    types = split_target_ip_types(value)
    return ",".join(types)

def get_target_ip_types() -> list[str]:
    cfg = load_ui_config()
    return split_target_ip_types(cfg.get("target_ip_types") or TARGET_IP_TYPES_ENV or "residential")

def ip_type_display(value: Any) -> str:
    token = normalize_ip_type_token(value)
    return {
        "residential": "住宅IP",
        "mobile": "移动IP",
        "normal": "普通/未知",
        "hosting": "机房IP",
        "proxy": "代理IP",
        "tor": "Tor出口",
    }.get(token, str(value or ""))


def parse_bool_setting(value: Any, default: bool = True) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on", "enable", "enabled", "开启"}:
        return True
    if text in {"0", "false", "no", "off", "disable", "disabled", "关闭"}:
        return False
    return default

def get_auto_select_best_node() -> bool:
    if AUTO_SELECT_BEST_NODE_ENV is not None and AUTO_SELECT_BEST_NODE_ENV.strip():
        return AUTO_SELECT_BEST_NODE
    cfg = load_ui_config()
    return parse_bool_setting(cfg.get("auto_select_best_node"), AUTO_SELECT_BEST_NODE)

def target_ip_types_display(value: Any) -> str:
    types = split_target_ip_types(value)
    if not types:
        return "全部类型"
    label = "、".join(ip_type_display(t) for t in types)
    if STRICT_IP_TYPE_FILTER:
        return f"{label}硬过滤"
    return f"{label}优先"

def node_matches_target_ip_types(node: dict[str, Any], target_types: list[str]) -> bool:
    if not target_types:
        return True
    ip_type = normalize_ip_type_token(node.get("ip_type") or "unknown")
    quality = normalize_ip_type_token(node.get("quality") or "")
    node_tokens = {ip_type, quality}
    if quality in {"clean_residential", "residential"}:
        node_tokens.add("residential")
    if quality in {"datacenter", "hosting"}:
        node_tokens.add("hosting")
    if not node_has_risk_data(node) and "normal" in target_types:
        node_tokens.add("normal")
    return any(t in node_tokens for t in target_types)

def row_country_tokens(row: dict[str, str]) -> set[str]:
    country_long = (row.get("CountryLong") or "").strip()
    country_short = (row.get("CountryShort") or "").strip()
    country_zh = vpn_utils.COUNTRY_TRANSLATIONS.get(country_long, vpn_utils.COUNTRY_TRANSLATIONS.get(country_long.strip(), country_long))
    tokens = {country_short, country_long, country_zh}
    # Common VPNGate/country aliases for convenience.
    alias_map = {
        "JP": ["Japan", "日本"],
        "KR": ["Korea Republic of", "Korea", "Republic of Korea", "韩国", "南韩"],
        "US": ["United States", "USA", "United States of America", "美国"],
        "GB": ["United Kingdom", "UK", "Great Britain", "英国"],
        "TW": ["Taiwan", "台湾", "台灣"],
        "HK": ["Hong Kong", "香港"],
        "SG": ["Singapore", "新加坡"],
        "TH": ["Thailand", "泰国", "泰國"],
        "VN": ["Viet Nam", "Vietnam", "越南"],
        "CN": ["China", "中国", "中國"],
        "DE": ["Germany", "德国", "德國"],
        "FR": ["France", "法国", "法國"],
        "NL": ["Netherlands", "荷兰", "荷蘭"],
        "CA": ["Canada", "加拿大"],
        "AU": ["Australia", "澳大利亚", "澳洲"],
        "RU": ["Russian Federation", "Russia", "Russian", "俄罗斯", "俄羅斯"],
        "PL": ["Poland", "波兰", "波蘭"],
    }
    for code, aliases in alias_map.items():
        if country_short.upper() == code or country_long in aliases or country_zh in aliases:
            tokens.add(code)
            tokens.update(aliases)
    return {normalize_country_token(token) for token in tokens if token}

def row_matches_target_countries(row: dict[str, str], targets: list[str]) -> bool:
    if not targets:
        return True
    row_tokens = row_country_tokens(row)
    for target in targets:
        token = normalize_country_token(target)
        if token and token in row_tokens:
            return True
    return False


def node_country_tokens(node: dict[str, Any]) -> set[str]:
    """Return normalized country tokens for a cached/tested node."""
    country_short = str(node.get("country_short") or "").strip()
    country = str(node.get("country") or "").strip()
    tokens = {country_short, country}
    reverse_translations = {normalize_country_token(v): k for k, v in vpn_utils.COUNTRY_TRANSLATIONS.items()}
    if normalize_country_token(country) in reverse_translations:
        tokens.add(reverse_translations[normalize_country_token(country)])
    alias_map = {
        "JP": ["Japan", "日本"],
        "KR": ["Korea Republic of", "Korea", "Republic of Korea", "韩国", "南韩"],
        "US": ["United States", "USA", "United States of America", "美国"],
        "GB": ["United Kingdom", "UK", "Great Britain", "英国"],
        "TW": ["Taiwan", "台湾", "台灣"],
        "HK": ["Hong Kong", "香港"],
        "SG": ["Singapore", "新加坡"],
        "TH": ["Thailand", "泰国", "泰國"],
        "VN": ["Viet Nam", "Vietnam", "越南"],
        "CN": ["China", "中国", "中國"],
        "DE": ["Germany", "德国", "德國"],
        "FR": ["France", "法国", "法國"],
        "NL": ["Netherlands", "荷兰", "荷蘭"],
        "CA": ["Canada", "加拿大"],
        "AU": ["Australia", "澳大利亚", "澳洲"],
        "RU": ["Russian Federation", "Russia", "Russian", "俄罗斯", "俄羅斯"],
        "PL": ["Poland", "波兰", "波蘭"],
    }
    for code, aliases in alias_map.items():
        normalized_aliases = {normalize_country_token(x) for x in aliases}
        if country_short.upper() == code or normalize_country_token(country) in normalized_aliases:
            tokens.add(code)
            tokens.update(aliases)
    return {normalize_country_token(token) for token in tokens if token}

def node_matches_target_countries(node: dict[str, Any], targets: list[str]) -> bool:
    if not targets:
        return True
    node_tokens = node_country_tokens(node)
    for target in targets:
        token = normalize_country_token(target)
        if token and token in node_tokens:
            return True
    return False

def node_has_risk_data(node: dict[str, Any]) -> bool:
    risk_level = str(node.get("risk_level") or "").lower()
    return bool(
        risk_level in {"clean", "low", "medium", "high", "blocked"}
        or node.get("risk_sources")
        or node.get("fraud_flags")
        or node.get("blacklist_hits")
    )

def node_fraud_score(node: dict[str, Any], unknown: int = 50) -> int:
    val = node.get("fraud_score")
    if val in (None, ""):
        return unknown
    return parse_int(val)

def node_is_clean_for_connect(node: dict[str, Any]) -> bool:
    if ALLOW_RISKY_IP_CONNECT:
        return True
    if not node_has_risk_data(node):
        return False
    if parse_int(node.get("blacklist_count")) > 0:
        return False
    if node_fraud_score(node, unknown=100) > MAX_AUTO_FRAUD_SCORE:
        return False
    if str(node.get("risk_level") or "").lower() in {"medium", "high", "blocked"}:
        return False
    if str(node.get("ip_type") or "").lower() in {"proxy", "hosting", "tor"}:
        return False
    return True

def node_ip_priority_rank(node: dict[str, Any]) -> int:
    """Lower is better. Prefer clean residential IPs; deprioritize risky or blacklisted IPs."""
    ip_type = str(node.get("ip_type") or "").strip().lower()
    quality = str(node.get("quality") or "").strip().lower()
    risk_level = str(node.get("risk_level") or "").strip().lower()
    blacklist_count = parse_int(node.get("blacklist_count"))
    fraud_score = node_fraud_score(node, unknown=50)

    if blacklist_count > 0 or risk_level in {"high", "blocked"}:
        return 99
    if fraud_score > MAX_AUTO_FRAUD_SCORE and not ALLOW_RISKY_IP_CONNECT:
        return 90
    if ip_type == "residential" and quality in {"clean_residential", "", "normal", "residential"} and risk_level in {"clean", ""}:
        return 0
    if ip_type == "residential":
        return 1
    if ip_type == "mobile" or quality == "mobile":
        return 2
    if quality in {"", "normal"} and ip_type in {"", "unknown"}:
        return 5
    if ip_type == "hosting" or quality in {"hosting", "datacenter"}:
        return 8
    if ip_type in {"proxy", "tor"} or quality in {"proxy", "risky"}:
        return 9
    return 6

def node_sort_key(node: dict[str, Any]) -> tuple[int, int, int, int, int]:
    return (
        node_ip_priority_rank(node),
        node_fraud_score(node, unknown=50),
        parse_int(node.get("latency_ms")) or 999999,
        parse_int(node.get("ping")) or 999999,
        -parse_int(node.get("score")),
    )

def node_auto_fallback_key(node: dict[str, Any]) -> tuple[int, int, int, int, int, int]:
    """Lower is better for emergency failover. Risk is a ranking factor, not a hard block."""
    risk_level = str(node.get("risk_level") or "unknown").lower()
    ip_type = normalize_ip_type_token(node.get("ip_type") or "unknown")
    blacklist_count = parse_int(node.get("blacklist_count"))
    fraud_score = node_fraud_score(node, unknown=80)

    risk_rank = 0
    if blacklist_count > 0:
        risk_rank += 80 + min(blacklist_count, 9)
    if risk_level == "blocked":
        risk_rank += 70
    elif risk_level == "high":
        risk_rank += 45
    elif risk_level == "medium":
        risk_rank += 25
    elif risk_level in {"unknown", ""}:
        risk_rank += 15
    if ip_type in {"proxy", "tor"}:
        risk_rank += 35
    elif ip_type in {"hosting", "datacenter"}:
        risk_rank += 20
    elif ip_type == "mobile":
        risk_rank += 5
    elif ip_type == "residential":
        risk_rank -= 10

    return (
        risk_rank,
        fraud_score,
        node_ip_priority_rank(node),
        parse_int(node.get("latency_ms")) or 999999,
        parse_int(node.get("ping")) or 999999,
        -parse_int(node.get("score")),
    )

DEFAULT_IP_TYPE_FALLBACK_ORDER = ["residential", "mobile", "normal", "hosting", "proxy", "tor"]

def ip_type_preference_order(preferred_types: list[str]) -> list[str]:
    """Return preferred IP type order with safe auto-fallback tiers appended.

    TARGET_IP_TYPES is treated as preference by default, not a hard filter. For example,
    residential means: residential first, then mobile, normal/unknown, hosting, proxy, tor.
    Set STRICT_IP_TYPE_FILTER=1 to restore hard filtering.
    """
    if not preferred_types:
        return list(DEFAULT_IP_TYPE_FALLBACK_ORDER)
    order: list[str] = []
    seen: set[str] = set()
    for item in preferred_types:
        token = normalize_ip_type_token(item)
        if token and token != "all" and token not in seen:
            order.append(token)
            seen.add(token)
    if STRICT_IP_TYPE_FILTER:
        return order
    for item in DEFAULT_IP_TYPE_FALLBACK_ORDER:
        if item not in seen:
            order.append(item)
            seen.add(item)
    return order

def tiered_ip_type_candidates(candidates: list[dict[str, Any]], preferred_types: list[str]) -> tuple[list[dict[str, Any]], str]:
    """Choose the first available IP-type tier, sorted by risk/latency.

    This prevents auto failover from stopping when a country has no residential IP, while still
    making proxy/Tor the last resort.
    """
    if not candidates:
        return [], "无候选节点"
    if not preferred_types:
        pool = list(candidates)
        pool.sort(key=node_auto_fallback_key)
        return pool, "全部类型按综合风险/延迟排序"

    if STRICT_IP_TYPE_FILTER:
        pool = [n for n in candidates if node_matches_target_ip_types(n, preferred_types)]
        pool.sort(key=node_auto_fallback_key)
        return pool, f"严格 IP 类型过滤：{target_ip_types_display(preferred_types)}"

    used_ids: set[str] = set()
    for ip_type in ip_type_preference_order(preferred_types):
        tier = []
        for node in candidates:
            node_key = str(node.get("id") or id(node))
            if node_key in used_ids:
                continue
            if node_matches_target_ip_types(node, [ip_type]):
                tier.append(node)
                used_ids.add(node_key)
        if tier:
            tier.sort(key=node_auto_fallback_key)
            return tier, f"IP 类型优先级命中：{ip_type_display(ip_type)}"

    pool = list(candidates)
    pool.sort(key=node_auto_fallback_key)
    return pool, "未识别 IP 类型，按综合风险/延迟兜底"

def choose_auto_failover_candidates(scoped_candidates: list[dict[str, Any]], all_candidates: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str]:
    """Pick automatic failover candidates.

    Country remains the main scope. IP type is a preference chain, not a dead-end filter:
    residential -> mobile -> normal/unknown -> hosting/datacenter -> proxy/Tor. Risk scoring
    is used for ranking. It only becomes a hard block when strict mode and keep-running are disabled.
    """
    target_ip_types = get_target_ip_types()
    ip_type_label = target_ip_types_display(target_ip_types)

    if STRICT_IP_TYPE_FILTER:
        scoped_pool = [n for n in scoped_candidates if node_matches_target_ip_types(n, target_ip_types)] if target_ip_types else list(scoped_candidates)
        all_pool = [n for n in all_candidates if node_matches_target_ip_types(n, target_ip_types)] if target_ip_types else list(all_candidates)
    else:
        scoped_pool = list(scoped_candidates)
        all_pool = list(all_candidates)

    clean_scoped = [n for n in scoped_pool if node_is_clean_for_connect(n)]
    clean_all = [n for n in all_pool if node_is_clean_for_connect(n)]

    if AUTO_RISK_MODE == "loose" or ALLOW_RISKY_IP_CONNECT:
        candidates, tier_reason = tiered_ip_type_candidates(scoped_pool, target_ip_types)
        if not candidates and not STRICT_COUNTRY_FAILOVER:
            candidates, tier_reason = tiered_ip_type_candidates(all_pool, target_ip_types)
            if candidates:
                return candidates, f"宽松模式跨地区兜底；{tier_reason}"
        if candidates:
            return candidates, f"宽松模式：{tier_reason}"
        return [], f"没有可用节点；IP 类型策略 {ip_type_label}"

    clean_candidates, clean_tier_reason = tiered_ip_type_candidates(clean_scoped, target_ip_types)
    if clean_candidates:
        clean_candidates.sort(key=node_sort_key)
        return clean_candidates, f"优先选择同地区干净节点；{clean_tier_reason}"

    if not STRICT_COUNTRY_FAILOVER:
        clean_cross, cross_reason = tiered_ip_type_candidates(clean_all, target_ip_types)
        if clean_cross:
            clean_cross.sort(key=node_sort_key)
            return clean_cross, f"同地区无干净节点，跨地区选择干净节点；{cross_reason}"

    if AUTO_RISK_MODE == "strict" and not AUTO_MIN_KEEP_RUNNING:
        return [], f"严格模式：没有符合阈值的干净节点；IP 类型策略 {ip_type_label}"

    fallback_pool = scoped_pool
    fallback_candidates, fallback_reason = tiered_ip_type_candidates(fallback_pool, target_ip_types)
    if fallback_candidates:
        return fallback_candidates, f"保活兜底：无干净 IP，按同地区 IP 类型优先级逐级选择；{fallback_reason}"

    if not STRICT_COUNTRY_FAILOVER:
        fallback_candidates, fallback_reason = tiered_ip_type_candidates(all_pool, target_ip_types)
        if fallback_candidates:
            return fallback_candidates, f"跨地区保活兜底：按 IP 类型优先级逐级选择；{fallback_reason}"

    return [], "没有可用节点；将继续后台拉取/检测"

def get_failover_targets(active_node: dict[str, Any] | None = None) -> list[str]:
    """Return the country scope used by auto failover.

    Priority:
    1) Explicit 拉取地区过滤 in settings/env;
    2) The country of the last manually connected node;
    3) The currently active node country.
    """
    configured = get_target_countries()
    if configured:
        return configured
    state = read_json(STATE_FILE, {})
    saved = state.get("failover_country_short") or state.get("failover_country") or ""
    if saved:
        return split_target_countries(saved)
    if active_node:
        country_short = active_node.get("country_short") or ""
        country = active_node.get("country") or ""
        return split_target_countries(country_short or country)
    return []

def set_failover_scope_from_node(node: dict[str, Any]) -> None:
    country_short = str(node.get("country_short") or "").strip()
    country = str(node.get("country") or "").strip()
    set_state(
        failover_country_short=country_short,
        failover_country=country,
        failover_country_display=country or country_short or "未固定",
        strict_country_failover=STRICT_COUNTRY_FAILOVER,
    )



def auto_selection_key_summary(node: dict[str, Any]) -> str:
    return (
        f"IP类型 {ip_type_display(node.get('ip_type') or node.get('quality') or 'unknown')} / "
        f"欺诈值 {node.get('fraud_score', '未知')} / "
        f"黑名单 {node.get('blacklist_count', 0)} / "
        f"延迟 {node.get('latency_ms') or node.get('ping') or '-'} ms"
    )

def should_switch_to_better_node(active_node: dict[str, Any] | None, best_node: dict[str, Any]) -> tuple[bool, str]:
    """Return whether an already-running connection should be replaced by a better tested node.

    The goal is to use full-node detection results, but avoid unstable constant switching.
    We switch when the candidate has a clearly better IP tier/risk score/fraud score,
    or a meaningfully lower latency.
    """
    if not active_node:
        return True, "当前没有活动节点"
    if best_node.get("id") == active_node.get("id"):
        return False, "当前节点已经是本轮优选节点"

    active_status = str(active_node.get("probe_status") or "").lower()
    if active_status not in {"available", ""}:
        return True, "当前活动节点状态异常"

    active_blacklist = parse_int(active_node.get("blacklist_count"))
    best_blacklist = parse_int(best_node.get("blacklist_count"))
    if best_blacklist < active_blacklist:
        return True, f"候选节点黑名单命中更少：{active_blacklist} -> {best_blacklist}"

    active_ip_rank = node_ip_priority_rank(active_node)
    best_ip_rank = node_ip_priority_rank(best_node)
    if best_ip_rank + 1 < active_ip_rank:
        return True, f"候选节点 IP 类型/风控等级明显更优：{auto_selection_key_summary(active_node)} -> {auto_selection_key_summary(best_node)}"

    active_fraud = node_fraud_score(active_node, unknown=80)
    best_fraud = node_fraud_score(best_node, unknown=80)
    if active_fraud - best_fraud >= AUTO_SWITCH_MIN_FRAUD_DELTA:
        return True, f"候选节点欺诈值明显更低：{active_fraud} -> {best_fraud}"

    active_risk = str(active_node.get("risk_level") or "unknown").lower()
    best_risk = str(best_node.get("risk_level") or "unknown").lower()
    risk_order = {"clean": 0, "low": 1, "unknown": 2, "medium": 3, "high": 4, "blocked": 5}
    if risk_order.get(best_risk, 2) + 1 < risk_order.get(active_risk, 2):
        return True, f"候选节点风险等级明显更低：{active_risk} -> {best_risk}"

    # Only use latency to switch when the risk/IP tier is not worse, and improvement is obvious.
    active_latency = parse_int(active_node.get("latency_ms")) or parse_int(active_node.get("ping")) or 999999
    best_latency = parse_int(best_node.get("latency_ms")) or parse_int(best_node.get("ping")) or 999999
    if best_ip_rank <= active_ip_rank and best_fraud <= active_fraud and active_latency - best_latency >= AUTO_SWITCH_MIN_LATENCY_DELTA_MS:
        return True, f"候选节点延迟明显更低：{active_latency} ms -> {best_latency} ms"

    return False, "候选节点没有明显优于当前活动节点，避免频繁跳节点"

def optimize_active_node_after_tests(reason: str = "") -> str:
    """After batch testing, actively select the best available node from all tested nodes.

    This closes the gap where the panel showed tested residential/mobile nodes but the service
    stayed on an older proxy/high-risk node until failure. Automatic selection still respects
    country scope and IP-type preference, but it is not a dead-end filter.
    """
    if not get_auto_select_best_node():
        return "自动优选已关闭"

    with lock:
        nodes = read_json(NODES_FILE, [])
        active_node = next((n for n in nodes if n.get("id") == active_openvpn_node_id or n.get("active")), None)
        available = [n for n in nodes if n.get("probe_status") == "available"]

    if not available:
        msg = "自动优选：暂无已检测可用节点"
        set_state(last_auto_select_message=msg)
        return msg

    failover_targets = get_failover_targets(active_node)
    scoped = [n for n in available if node_matches_target_countries(n, failover_targets)] if failover_targets else list(available)
    candidates, candidate_reason = choose_auto_failover_candidates(scoped, available)
    if not candidates:
        msg = f"自动优选：没有符合当前地区/IP策略的可用节点；{candidate_reason}"
        set_state(last_auto_select_message=msg)
        return msg

    best_node = candidates[0]
    should_switch, switch_reason = should_switch_to_better_node(active_node, best_node)
    if not should_switch:
        msg = f"自动优选：保持当前节点；{switch_reason}；策略：{candidate_reason}"
        set_state(last_auto_select_message=msg)
        return msg

    state = read_json(STATE_FILE, {})
    now = time.time()
    last_switch = float(state.get("last_auto_select_switch_at") or 0)
    if active_openvpn_running() and last_switch > 0 and now - last_switch < AUTO_SELECT_COOLDOWN_SECONDS:
        left = int(AUTO_SELECT_COOLDOWN_SECONDS - (now - last_switch))
        msg = f"自动优选：发现更优节点 {best_node.get('id')}，但冷却中，约 {left} 秒后再自动切换；原因：{switch_reason}"
        set_state(last_auto_select_message=msg)
        return msg

    clean_ok = node_is_clean_for_connect(best_node)
    msg = (
        f"自动优选：从全部已检测节点中选择 {best_node.get('id')}；"
        f"{auto_selection_key_summary(best_node)}；原因：{switch_reason}；策略：{candidate_reason}"
    )
    print(f"[自动优选] {msg}", flush=True)
    log_to_json("INFO", "VPN", msg)
    set_state(last_auto_select_message=msg, last_check_message=msg, last_auto_select_switch_at=now)
    try:
        return connect_node(best_node["id"], update_failover_scope=False, allow_auto_risky=not clean_ok)
    except Exception as e:
        err = f"自动优选切换失败：{e}"
        print(f"[自动优选] {err}", flush=True)
        log_to_json("WARNING", "VPN", err)
        set_state(last_auto_select_message=err, last_check_message=err)
        return err

def get_session_token(password: str, username: str = "admin") -> str:
    salt = "eianun_vpngate_secure_salt_2026"
    return hashlib.sha256((username + ":" + password + salt).encode("utf-8")).hexdigest()

def cleanup_old_logs(logs_dir: Path) -> None:
    try:
        now = time.time()
        three_days_sec = 3 * 24 * 60 * 60
        for path in logs_dir.glob("*.json"):
            match = re.match(r"^(\d{4}-\d{2}-\d{2})\.json$", path.name)
            if match:
                date_str = match.group(1)
                try:
                    file_time = time.mktime(time.strptime(date_str, "%Y-%m-%d"))
                    today_str = time.strftime("%Y-%m-%d", time.localtime())
                    today_time = time.mktime(time.strptime(today_str, "%Y-%m-%d"))
                    if today_time - file_time >= three_days_sec:
                        path.unlink()
                        print(f"[清理] 已删除3天前的旧日志文件: {path.name}", flush=True)
                except Exception:
                    if now - path.stat().st_mtime > three_days_sec:
                        path.unlink()
    except Exception as e:
        print(f"[清理错误] 清理旧日志失败: {e}", flush=True)

def log_to_json(level: str, module: str, message: str) -> None:
    try:
        logs_dir = DATA_DIR / "logs"
        logs_dir.mkdir(exist_ok=True, parents=True)
        date_str = time.strftime("%Y-%m-%d", time.localtime())
        log_file = logs_dir / f"{date_str}.json"
        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "level": level,
            "module": module,
            "message": message
        }
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        cleanup_old_logs(logs_dir)
    except Exception as e:
        print(f"[Log Error] Failed to write JSON log: {e}", flush=True)

def set_state(**updates: Any) -> None:
    state = get_state()
    state.update(updates)
    write_json(STATE_FILE, state)

def get_state() -> dict[str, Any]:
    global active_openvpn_node_id, is_connecting
    state = read_json(STATE_FILE, {})
    state["active_openvpn_node_id"] = active_openvpn_node_id
    state["is_connecting"] = is_connecting
    state.setdefault("api_url", API_URL)
    state.setdefault("target_valid_nodes", TARGET_VALID_NODES)
    state.setdefault("fetch_interval_seconds", FETCH_INTERVAL_SECONDS)
    state.setdefault("check_interval_seconds", CHECK_INTERVAL_SECONDS)
    state.setdefault("local_proxy", f"http://{LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}")
    state.setdefault("last_fetch_status", "not_started")
    state.setdefault("last_check_message", "")
    state.setdefault("blacklisted_nodes", 0)
    
    # Pre-populate settings inputs in UI
    ui_cfg = load_ui_config()
    state["username"] = ui_cfg.get("username", "admin")
    state["port"] = ui_cfg.get("port", 8787)
    state["secret_path"] = ui_cfg.get("secret_path", "EJsW2EeBo9lY")
    target_countries = normalize_target_countries_input(ui_cfg.get("target_countries") or TARGET_COUNTRIES_ENV)
    target_ip_types = normalize_target_ip_types_input(ui_cfg.get("target_ip_types") or TARGET_IP_TYPES_ENV or "residential")
    state["target_countries"] = target_countries
    state["target_countries_display"] = target_countries or "全部地区"
    state["target_ip_types"] = target_ip_types
    state["target_ip_types_display"] = target_ip_types_display(target_ip_types)
    state["node_sources"] = normalize_node_sources_input(ui_cfg.get("node_sources") or NODE_SOURCES_ENV or DEFAULT_NODE_SOURCES)
    state["node_sources_display"] = node_sources_display(state["node_sources"])
    state.setdefault("failover_country_short", "")
    state.setdefault("failover_country", "")
    state.setdefault("failover_country_display", target_countries or "未固定")
    state["strict_country_failover"] = STRICT_COUNTRY_FAILOVER
    state["max_auto_fraud_score"] = MAX_AUTO_FRAUD_SCORE
    state["auto_risk_mode"] = AUTO_RISK_MODE
    state["auto_min_keep_running"] = AUTO_MIN_KEEP_RUNNING
    state["strict_ip_type_filter"] = STRICT_IP_TYPE_FILTER
    state["allow_risky_ip_connect"] = ALLOW_RISKY_IP_CONNECT
    state["allow_manual_risky_connect"] = ALLOW_MANUAL_RISKY_CONNECT
    state["auto_test_all_nodes"] = AUTO_TEST_ALL_NODES
    state["auto_test_max_nodes"] = AUTO_TEST_MAX_NODES
    state["auto_test_workers"] = AUTO_TEST_WORKERS
    state["vpnbook_auto_test"] = VPNBOOK_AUTO_TEST
    state["vpnbook_protocols"] = VPNBOOK_PROTOCOLS
    state["openvpn_batch_test_timeout_seconds"] = OPENVPN_BATCH_TEST_TIMEOUT_SECONDS
    state["auto_select_best_node"] = get_auto_select_best_node()
    state["auto_select_cooldown_seconds"] = AUTO_SELECT_COOLDOWN_SECONDS
    state["auto_switch_min_fraud_delta"] = AUTO_SWITCH_MIN_FRAUD_DELTA
    state["auto_switch_min_latency_delta_ms"] = AUTO_SWITCH_MIN_LATENCY_DELTA_MS
    state.setdefault("auto_test_total", 0)
    state.setdefault("auto_test_done", 0)
    state.setdefault("last_auto_select_switch_at", 0)
    state.setdefault("last_auto_select_message", "")
    
    return state

def safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return value.strip("._") or "node"

def parse_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def resolve_ip_for_risk(host: str) -> str:
    host = str(host or "").strip()
    if not host:
        return ""
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    try:
        return socket.gethostbyname(host)
    except Exception:
        return host

def http_get_bytes(url: str, timeout: int = 15, accept: str = "*/*") -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 eianun-vpngate-manager/2.0",
            "Accept": accept,
            "Referer": VPNBOOK_OPENVPN_URL if "vpnbook.com" in url else API_URL,
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()

def fetch_api_text() -> str:
    return http_get_bytes(API_URL, timeout=12, accept="text/plain,*/*").decode("utf-8", errors="replace")

def parse_vpngate_rows(text: str) -> list[dict[str, str]]:
    lines = [line for line in text.splitlines() if line and not line.startswith("*")]
    if lines and lines[0].startswith("#"):
        lines[0] = lines[0][1:]
    return list(csv.DictReader(lines))

def decode_config(encoded: str) -> str:
    return base64.b64decode(encoded.encode("ascii"), validate=False).decode("utf-8", errors="replace")

def load_blacklist() -> dict[str, dict[str, Any]]:
    return {}

def mark_blacklisted(node: dict[str, Any], message: str) -> None:
    pass

def row_to_node(row: dict[str, str], config_text: str) -> dict[str, Any]:
    ip = row.get("IP", "")
    country_short = row.get("CountryShort", "")
    remote_host, remote_port, proto = vpn_utils.parse_remote(config_text, ip)
    node_id = safe_name("_".join([country_short or "XX", ip or remote_host, str(remote_port), proto]))
    config_path = CONFIG_DIR / f"{node_id}.ovpn"
    
    country_long = row.get("CountryLong", "")
    country_zh = vpn_utils.COUNTRY_TRANSLATIONS.get(country_long, vpn_utils.COUNTRY_TRANSLATIONS.get(country_long.strip(), country_long))
    return {
        "id": node_id,
        "source": "vpngate",
        "country": country_zh,
        "country_short": country_short,
        "host_name": row.get("HostName", ""),
        "auth_user": OPENVPN_AUTH_USER,
        "auth_pass": OPENVPN_AUTH_PASS,
        "ip": ip,
        "score": parse_int(row.get("Score")),
        "ping": parse_int(row.get("Ping")),
        "speed": parse_int(row.get("Speed")),
        "sessions": parse_int(row.get("NumVpnSessions")),
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "fraud_score": 0,
        "clean_score": 0,
        "risk_level": "unknown",
        "fraud_flags": [],
        "risk_sources": [],
        "blacklist_hits": [],
        "blacklist_count": 0,
        "ip_clean": False,
        "latency_ms": 0,
        "config_file": str(config_path),
        "config_text": config_text,
        "proto": proto,
        "remote_host": remote_host,
        "remote_port": remote_port,
        "fetched_at": time.time(),
        "probe_status": "not_checked",
        "probe_message": "",
        "probed_at": 0,
    }

def fetch_vpngate_candidates(target_countries: list[str], seen_keys: set[str]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    target_display = normalize_target_countries_input(target_countries) or "全部地区"
    has_cache = len(cached_nodes()) > 0
    max_attempts = 1 if has_cache else 2
    log_to_json("INFO", "Main", f"开始拉取 VPNGate API 节点，地区过滤: {target_display} (最大尝试次数: {max_attempts})...")
    for i in range(max_attempts):
        if i > 0:
            time.sleep(1.5)
        try:
            api_text = fetch_api_text()
            rows = parse_vpngate_rows(api_text)
            matched_rows = 0
            filtered_rows = 0
            for row in rows:
                if not row_matches_target_countries(row, target_countries):
                    filtered_rows += 1
                    continue
                matched_rows += 1
                if matched_rows > MAX_SCAN_ROWS:
                    break
                ip = row.get("IP", "")
                if not ip or ip in seen_keys:
                    continue
                encoded = row.get("OpenVPN_ConfigData_Base64", "")
                if not encoded:
                    continue
                config_text = decode_config(encoded)
                node = row_to_node(row, config_text)
                node["source"] = "vpngate"
                candidates.append(node)
                seen_keys.add(ip)
            if target_countries:
                log_to_json("INFO", "Main", f"VPNGate 地区过滤 {target_display}: 匹配 {matched_rows} 行，跳过 {filtered_rows} 行")
            break
        except Exception as e:
            print(f"[fetch_vpngate_candidates] Fetch {i+1} failed: {e}", flush=True)
            log_to_json("WARNING", "Main", f"第 {i+1} 次拉取 VPNGate 节点失败: {e}")
            if i == max_attempts - 1:
                log_to_json("ERROR", "Main", f"VPNGate 节点拉取失败: {e}")
    return candidates

VPNBOOK_COUNTRIES: dict[str, tuple[str, str]] = {
    "us": ("US", "United States"),
    "ca": ("CA", "Canada"),
    "uk": ("GB", "United Kingdom"),
    "gb": ("GB", "United Kingdom"),
    "de": ("DE", "Germany"),
    "fr": ("FR", "France"),
    "pl": ("PL", "Poland"),
}

def vpnbook_protocol_parts(proto_name: str) -> tuple[str, int, str]:
    token = str(proto_name or "").strip().lower().replace("_", "").replace("-", "")
    if token in {"tcp443", "443", "tcp"}:
        return "tcp", 443, "tcp443"
    if token in {"tcp80", "80"}:
        return "tcp", 80, "tcp80"
    if token in {"udp53", "53", "udp"}:
        return "udp", 53, "udp53"
    if token in {"udp25000", "25000"}:
        return "udp", 25000, "udp25000"
    m = re.match(r"^(tcp|udp)(\d+)$", token)
    if m:
        return m.group(1), int(m.group(2)), f"{m.group(1)}{m.group(2)}"
    return "tcp", 443, "tcp443"

def extract_vpnbook_credentials(page_text: str) -> tuple[str, str]:
    username = "vpnbook"
    password = ""
    text = re.sub(r"<[^>]+>", " ", page_text)
    text = re.sub(r"\s+", " ", text)
    m_user = re.search(r"Username\s*(vpnbook)", text, re.I) or re.search(r"用户名\s*(vpnbook)", text, re.I)
    if m_user:
        username = m_user.group(1).strip()
    m_pass = re.search(r"Password\s*([A-Za-z0-9]{4,32})", text, re.I) or re.search(r"密码\s*([A-Za-z0-9]{4,32})", text, re.I)
    if m_pass:
        password = m_pass.group(1).strip()
    return username, password

def fetch_vpnbook_page() -> str:
    for url in [VPNBOOK_OPENVPN_URL, "https://www.vpnbook.com/zh/freevpn/openvpn"]:
        try:
            return http_get_bytes(url, timeout=15, accept="text/html,*/*").decode("utf-8", errors="replace")
        except Exception as exc:
            log_to_json("WARNING", "VPNBook", f"读取 VPNBook 页面失败 {url}: {exc}")
    return ""

def parse_vpnbook_servers(page_text: str) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    seen: set[str] = set()
    for host in re.findall(r"\b((?:us|ca|uk|gb|de|fr|pl)\d+\.vpnbook\.com)\b", page_text, flags=re.I):
        host = host.lower()
        if host in seen:
            continue
        seen.add(host)
        prefix_match = re.match(r"([a-z]+)", host)
        prefix = prefix_match.group(1) if prefix_match else ""
        country_short, country_long = VPNBOOK_COUNTRIES.get(prefix, (prefix.upper() or "XX", prefix.upper() or "Unknown"))
        found.append({"host": host, "country_short": country_short, "country_long": country_long})
    return found

def looks_like_openvpn_config(text: str) -> bool:
    lower = (text or "").lower()
    return "client" in lower[:800] and "remote" in lower and ("<ca>" in lower or "-----begin certificate-----" in lower)

def sanitize_openvpn_config_for_eianun(config_text: str) -> str:
    """Remove local OpenVPN directives that can hijack the VPS default route or run scripts.

    Eianun uses --route-nopull/--route-noexec plus policy routing. Free templates, especially
    VPNBook templates copied from the web, often contain redirect-gateway, route or script hooks.
    Leaving those directives in the file can make a manual test or connect rewrite the host routing
    table and freeze SSH.
    """
    dangerous_prefixes = (
        "redirect-gateway",
        "route",
        "route-ipv6",
        "dhcp-option",
        "pull-filter",
        "up",
        "down",
        "route-up",
        "iproute",
        "script-security",
        "block-outside-dns",
    )
    kept: list[str] = []
    for raw in config_text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        stripped = raw.strip()
        lower = stripped.lower()
        if not stripped or stripped.startswith(("#", ";")):
            kept.append(raw)
            continue
        key = lower.split(None, 1)[0]
        if key in dangerous_prefixes:
            kept.append(f"# eianun removed unsafe directive: {stripped}")
            continue
        kept.append(raw)
    return "\n".join(kept).strip() + "\n"

def normalize_vpnbook_config_text(config_text: str, host: str, proto: str, port: int) -> str:
    text = sanitize_openvpn_config_for_eianun(config_text).replace("\r\n", "\n").replace("\r", "\n").strip() + "\n"
    text = re.sub(r"(?m)^proto\s+\S+", f"proto {proto}", text)
    if re.search(r"(?m)^remote\s+\S+\s+\d+(?:\s+\S+)?", text):
        text = re.sub(r"(?m)^remote\s+\S+\s+\d+(?:\s+\S+)?", f"remote {host} {port}", text, count=1)
    else:
        text = f"remote {host} {port}\n" + text
    if re.search(r"(?m)^auth-user-pass(?:\s+.+)?$", text):
        text = re.sub(r"(?m)^auth-user-pass(?:\s+.+)?$", "auth-user-pass", text, count=1)
    else:
        text = "auth-user-pass\n" + text
    return text

def fetch_vpnbook_template_config() -> str:
    global _vpnbook_template_config_cache
    if _vpnbook_template_config_cache:
        return _vpnbook_template_config_cache
    urls = [u.strip() for u in re.split(r"[,，;；\s]+", VPNBOOK_TEMPLATE_OVPN_URLS or "") if u.strip()]
    for url in urls:
        try:
            text = http_get_bytes(url, timeout=20, accept="application/x-openvpn-profile,text/plain,*/*").decode("utf-8", errors="replace")
            if looks_like_openvpn_config(text):
                _vpnbook_template_config_cache = text
                log_to_json("INFO", "VPNBook", f"已加载 VPNBook 模板配置: {url}")
                return text
            log_to_json("WARNING", "VPNBook", f"VPNBook 模板不像有效 OpenVPN 配置: {url}")
        except Exception as exc:
            log_to_json("WARNING", "VPNBook", f"加载 VPNBook 模板失败 {url}: {exc}")
    return ""

def try_download_vpnbook_config(host: str, proto_key: str) -> str:
    short_host = host.split(".")[0].lower()
    proto, port, normalized_proto_key = vpnbook_protocol_parts(proto_key)
    filename = f"vpnbook-{short_host}-{normalized_proto_key}.ovpn"
    quoted_host = urllib.parse.quote(short_host)
    quoted_proto = urllib.parse.quote(normalized_proto_key)
    # VPNBook 现在的页面是“选择服务器 + 协议后下载”，页面结构会变化；
    # 这里先尝试多个常见官方下载路径，失败时再用公开模板配置替换 remote/proto。
    urls = [
        f"https://www.vpnbook.com/freevpn/openvpn/{filename}",
        f"https://www.vpnbook.com/freevpn/openvpn/download/{filename}",
        f"https://www.vpnbook.com/free-openvpn-account/{filename}",
        f"https://www.vpnbook.com/free-openvpn-account/{filename}?download=1",
        f"https://www.vpnbook.com/openvpn/{filename}",
        f"https://www.vpnbook.com/{filename}",
        f"https://www.vpnbook.com/freevpn/openvpn/download?server={quoted_host}&protocol={quoted_proto}",
        f"https://www.vpnbook.com/freevpn/openvpn/download?server={quoted_host}.vpnbook.com&protocol={quoted_proto}",
        f"https://www.vpnbook.com/api/openvpn/config?server={quoted_host}&protocol={quoted_proto}",
    ]
    for url in urls:
        try:
            data = http_get_bytes(url, timeout=20, accept="application/x-openvpn-profile,text/plain,application/octet-stream,*/*")
            text = data.decode("utf-8", errors="replace")
            if looks_like_openvpn_config(text):
                return normalize_vpnbook_config_text(text, host, proto, port)
            if text.strip().lower().startswith("<!doctype") or "<html" in text[:500].lower():
                continue
        except Exception:
            continue

    template = fetch_vpnbook_template_config()
    if template:
        log_to_json("WARNING", "VPNBook", f"官方配置下载失败，使用 VPNBook 模板生成配置: {host} {normalized_proto_key}")
        return normalize_vpnbook_config_text(template, host, proto, port)
    return ""

def vpnbook_row_to_node(server: dict[str, str], proto_name: str, config_text: str, auth_user: str, auth_pass: str) -> dict[str, Any]:
    host = server["host"]
    proto, port, proto_key = vpnbook_protocol_parts(proto_name)
    country_short = server.get("country_short") or "XX"
    country_long = server.get("country_long") or country_short
    country_zh = vpn_utils.COUNTRY_TRANSLATIONS.get(country_long, country_long)
    # 确保 config 内写入当前选择的 remote/proto，并让 OpenVPN 使用统一认证文件。
    text = sanitize_openvpn_config_for_eianun(config_text)
    text = re.sub(r"(?m)^proto\s+\S+", f"proto {proto}", text)
    text = re.sub(r"(?m)^remote\s+\S+\s+\d+(?:\s+\S+)?", f"remote {host} {port}", text)
    if re.search(r"(?m)^auth-user-pass(?:\s+.+)?$", text):
        text = re.sub(r"(?m)^auth-user-pass(?:\s+.+)?$", "auth-user-pass", text)
    else:
        text = "auth-user-pass\n" + text
    remote_host, remote_port, parsed_proto = vpn_utils.parse_remote(text, host)
    node_id = safe_name("_".join(["VPNBOOK", country_short, host, str(remote_port or port), parsed_proto or proto]))
    config_path = CONFIG_DIR / f"{node_id}.ovpn"
    return {
        "id": node_id,
        "source": "vpnbook",
        "country": country_zh,
        "country_short": country_short,
        "host_name": host,
        "auth_user": auth_user or "vpnbook",
        "auth_pass": auth_pass,
        "ip": host,
        "score": 0,
        "ping": 0,
        "speed": 0,
        "sessions": 0,
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "fraud_score": 0,
        "clean_score": 0,
        "risk_level": "unknown",
        "fraud_flags": [],
        "risk_sources": [],
        "blacklist_hits": [],
        "blacklist_count": 0,
        "ip_clean": False,
        "latency_ms": 0,
        "config_file": str(config_path),
        "config_text": text,
        "proto": parsed_proto or proto,
        "remote_host": remote_host or host,
        "remote_port": remote_port or port,
        "fetched_at": time.time(),
        "probe_status": "not_checked",
        "probe_message": f"VPNBook source; auth user {auth_user}; password auto-fetched" if auth_pass else "VPNBook source; password fetch failed",
        "probed_at": 0,
    }

def fetch_vpnbook_candidates(target_countries: list[str], seen_keys: set[str]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    page = fetch_vpnbook_page()
    if not page:
        return candidates
    auth_user, auth_pass = extract_vpnbook_credentials(page)
    if not auth_pass:
        log_to_json("WARNING", "VPNBook", "未能从 VPNBook 页面解析到密码，VPNBook 节点可能无法通过认证")
    servers = parse_vpnbook_servers(page)
    protocols = [p for p in re.split(r"[,，;；\s]+", VPNBOOK_PROTOCOLS) if p.strip()] or ["tcp443"]
    target_display = normalize_target_countries_input(target_countries) or "全部地区"
    log_to_json("INFO", "VPNBook", f"解析到 VPNBook OpenVPN 服务器 {len(servers)} 个，地区过滤: {target_display}")
    for server in servers:
        pseudo_row = {"CountryShort": server.get("country_short", ""), "CountryLong": server.get("country_long", "")}
        if not row_matches_target_countries(pseudo_row, target_countries):
            continue
        for proto_name in protocols:
            proto, port, proto_key = vpnbook_protocol_parts(proto_name)
            key = f"vpnbook:{server['host']}:{proto_key}"
            if key in seen_keys:
                continue
            config_text = try_download_vpnbook_config(server["host"], proto_key)
            if not config_text:
                log_to_json("WARNING", "VPNBook", f"未能下载 VPNBook 配置: {server['host']} {proto_key}")
                continue
            node = vpnbook_row_to_node(server, proto_key, config_text, auth_user, auth_pass)
            candidates.append(node)
            seen_keys.add(key)
            if len(candidates) >= MAX_SCAN_ROWS:
                break
        if len(candidates) >= MAX_SCAN_ROWS:
            break
    log_to_json("INFO", "VPNBook", f"成功获取 VPNBook 候选节点 {len(candidates)} 个")
    return candidates

def fetch_candidates(target_override: list[str] | None = None) -> list[dict[str, Any]]:
    blacklist = load_blacklist()
    candidates: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    target_countries = target_override if target_override is not None else get_target_countries()
    target_display = normalize_target_countries_input(target_countries) or "全部地区"
    sources = get_node_sources()
    source_counts: dict[str, int] = {}
    for source in sources:
        before = len(candidates)
        try:
            if source == "vpngate":
                candidates.extend(fetch_vpngate_candidates(target_countries, seen_keys))
            elif source == "vpnbook":
                candidates.extend(fetch_vpnbook_candidates(target_countries, seen_keys))
        except Exception as exc:
            log_to_json("ERROR", "Main", f"节点来源 {source} 拉取失败: {exc}")
        source_counts[source] = len(candidates) - before
    set_state(
        last_fetch_at=time.time(),
        last_fetch_status="ok" if candidates else "empty",
        last_fetch_message=f"来源 {node_sources_display(','.join(sources))}，地区 {target_display}: fetched {len(candidates)} candidates. {source_counts}",
        blacklisted_nodes=len(blacklist),
        target_countries=normalize_target_countries_input(target_countries),
        target_countries_display=target_display,
        node_sources=normalize_node_sources_input(','.join(sources)),
        node_sources_display=node_sources_display(','.join(sources)),
    )
    log_to_json("INFO", "Main", f"成功获取候选节点 {len(candidates)} 个，来源 {source_counts}，地区 {target_display}")
    return candidates

def cached_nodes() -> list[dict[str, Any]]:
    return read_json(NODES_FILE, [])

_openvpn_version = None

def get_openvpn_version() -> float:
    global _openvpn_version
    if _openvpn_version is not None:
        return _openvpn_version
    try:
        cmd = shlex.split(OPENVPN_CMD, posix=False) or ["openvpn"]
        res = subprocess.run([cmd[0], "--version"], capture_output=True, text=True, timeout=2)
        match = re.search(r"OpenVPN\s+(\d+\.\d+)", res.stdout or res.stderr)
        if match:
            _openvpn_version = float(match.group(1))
            return _openvpn_version
    except Exception:
        pass
    _openvpn_version = 2.4
    return _openvpn_version

def auth_file_for_node(node: dict[str, Any] | None) -> Path:
    ensure_dirs()
    if not node:
        return AUTH_FILE
    user = str(node.get("auth_user") or OPENVPN_AUTH_USER or "vpn")
    pwd = str(node.get("auth_pass") or OPENVPN_AUTH_PASS or "vpn")
    node_id = safe_name(str(node.get("id") or node.get("remote_host") or "node"))
    path = CONFIG_DIR / f"{node_id}.auth"
    try:
        path.write_text(f"{user}\n{pwd}\n", encoding="utf-8")
        path.chmod(0o600)
    except Exception:
        return AUTH_FILE
    return path

def openvpn_command(config_file: str, route_nopull: bool, dev: str = "tun0", auth_file: str | Path | None = None) -> list[str]:
    command = shlex.split(OPENVPN_CMD, posix=False) or ["openvpn"]
    command.extend(
        [
            "--config",
            config_file,
            "--dev",
            dev,
            "--dev-type",
            "tun",
            "--pull-filter",
            "ignore",
            "route-ipv6",
            "--pull-filter",
            "ignore",
            "ifconfig-ipv6",
            "--pull-filter",
            "ignore",
            "redirect-gateway",
            "--pull-filter",
            "ignore",
            "route",
            "--pull-filter",
            "ignore",
            "dhcp-option",
            "--route-delay",
            "2",
            "--connect-retry-max",
            "1",
            "--connect-timeout",
            "15",
            "--auth-user-pass",
            str(auth_file or AUTH_FILE),
            "--auth-nocache",
        ]
    )
    
    version = get_openvpn_version()
    if version >= 2.5:
        command.extend(["--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])
    else:
        command.extend(["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])

    command.extend(["--verb", "3"])
    
    try:
        content = Path(config_file).read_text(encoding="utf-8", errors="replace")
        if vpn_utils.is_config_tcp(content):
            ptype, host, port = vpn_utils.get_upstream_proxy()
            if ptype == "socks" and host and port:
                command.extend(["--socks-proxy", host, str(port)])
            elif ptype == "http" and host and port:
                command.extend(["--http-proxy", host, str(port)])
    except Exception:
        pass
        
    if route_nopull:
        # route-nopull 只阻止服务端 push 的路由；部分 VPNBook 配置文件自身包含
        # redirect-gateway/route，仍可能改默认路由导致 SSH 断连。route-noexec 会让
        # OpenVPN 不执行任何路由添加，后续统一由本程序的策略路由接管。
        command.extend(["--route-nopull", "--route-noexec"])
    return command

def stop_process(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()

def kill_existing_openvpn_processes() -> None:
    if not sys.platform.startswith("linux"):
        return
    try:
        # Terminate existing openvpn processes managing tun0 or using our vpngate configuration
        subprocess.run(["pkill", "-f", "openvpn.*tun0"], capture_output=True, timeout=2)
        subprocess.run(["pkill", "-f", "openvpn.*vpngate_data"], capture_output=True, timeout=2)
        print("[Cleanup] Terminated existing Eianun免费聚合落地IP OpenVPN processes.", flush=True)
    except Exception as e:
        print(f"[Cleanup Error] Failed to kill existing OpenVPN processes: {e}", flush=True)

def update_handshake_status(line_lower: str) -> None:
    status_map = {
        "resolving": ("解析域名", "正在解析服务器域名与 IP 地址..."),
        "udp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tcp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tls: initial packet": ("证书握手", "已成功发送首包，正在与远程服务器建立 TLS 安全通道..."),
        "verify ok": ("证书校验", "服务器证书校验成功，正在进行身份验证..."),
        "peer connection initiated": ("协商加密", "控制通道已建立，已初始化与服务器的加密对等连接..."),
        "push_request": ("请求配置", "正在向服务器发送 PUSH_REQUEST 请求配置参数与 IP 分配..."),
        "push_reply": ("应用配置", "已接收服务器 PUSH_REPLY，获取到 IP 分配，正在准备配置网卡..."),
        "tun/tap device": ("创建网卡", "正在创建虚拟通道并打开 TUN 虚拟网卡设备..."),
        "do_ifconfig": ("网卡配置", "正在为虚拟网卡配置 IP 地址及相关网络属性..."),
    }
    for key, (short_status, detailed_desc) in status_map.items():
        if key in line_lower:
            set_state(active_node_latency=short_status, last_check_message=detailed_desc)
            break

def run_openvpn_until_ready(config_file: str, keep_alive: bool, route_nopull: bool, timeout: int | None = None, dev: str = "tun0", auth_file: str | Path | None = None) -> tuple[bool, str, subprocess.Popen[str] | None]:
    limit = timeout if timeout is not None else OPENVPN_TEST_TIMEOUT_SECONDS
    try:
        process = subprocess.Popen(
            openvpn_command(config_file, route_nopull, dev, auth_file=auth_file),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(ROOT_DIR),
        )
    except FileNotFoundError:
        return False, "openvpn command not found", None
    except OSError as exc:
        return False, f"openvpn start failed: {exc}", None

    lines: queue.Queue[str | None] = queue.Queue()
    startup_done = [False]

    def reader() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            if not startup_done[0]:
                lines.put(line.rstrip())
            else:
                if keep_alive:
                    print(f"[OpenVPN] {line.rstrip()}", flush=True)
        if not startup_done[0]:
            lines.put(None)

    threading.Thread(target=reader, daemon=True).start()
    started = time.time()
    tail: list[str] = []
    ok = False
    message = "OpenVPN did not complete initialization."
    while time.time() - started < limit:
        try:
            line = lines.get(timeout=0.5)
        except queue.Empty:
            if process.poll() is not None:
                break
            continue
        if line is None:
            break
        if line:
            tail.append(line)
            tail = tail[-8:]
            if keep_alive:
                print(f"[OpenVPN] {line}", flush=True)
        lower = line.lower()
        if keep_alive:
            update_handshake_status(lower)
        if "initialization sequence completed" in lower:
            ok = True
            message = f"OpenVPN connected in {int((time.time() - started) * 1000)} ms."
            break
        if "auth_failed" in lower or "authentication failed" in lower:
            message = "AUTH_FAILED"
            break
        if "cannot ioctl" in lower or "fatal error" in lower:
            message = line[-220:]
            break
    else:
        message = f"OpenVPN timeout after {limit}s."

    if not ok and tail:
        message = tail[-1][-220:]
    startup_done[0] = True
    if not keep_alive or not ok:
        stop_process(process)
        process = None
    return ok, message, process


def setup_policy_routing(interface: str = "tun0") -> None:
    try:
        subprocess.run(["ip", "rule", "del", "table", "100"], capture_output=True, timeout=2)
    except Exception:
        pass
    try:
        subprocess.run(["ip", "route", "flush", "table", "100"], capture_output=True, timeout=2)
    except Exception:
        pass
    
    success = False
    for attempt in range(1, 4):
        try:
            subprocess.run(["ip", "route", "add", "default", "dev", interface, "table", "100"], check=True, timeout=2)
            subprocess.run(["ip", "rule", "add", "oif", interface, "table", "100"], check=True, timeout=2)
            print(f"[policy_routing] Enabled policy routing for interface {interface} (attempt {attempt} success)", flush=True)
            success = True
            break
        except Exception as e:
            print(f"[policy_routing] Attempt {attempt} failed to enable policy routing: {e}", flush=True)
            time.sleep(1)
            
    if not success:
        print("[policy_routing] Failed to enable policy routing after 3 attempts", flush=True)

def cleanup_policy_routing() -> None:
    try:
        subprocess.run(["ip", "rule", "del", "table", "100"], capture_output=True, timeout=2)
        subprocess.run(["ip", "route", "flush", "table", "100"], capture_output=True, timeout=2)
        print("[policy_routing] Cleared policy routing table 100", flush=True)
    except Exception:
        pass

def stop_active_openvpn() -> None:
    global active_openvpn_process, active_openvpn_node_id
    cleanup_policy_routing()
    config_to_delete = None
    if active_openvpn_node_id:
        nodes = read_json(NODES_FILE, [])
        node = next((item for item in nodes if item.get("id") == active_openvpn_node_id), None)
        if node:
            config_to_delete = node.get("config_file")
            
    stop_process(active_openvpn_process)
    active_openvpn_process = None
    active_openvpn_node_id = ""
    kill_existing_openvpn_processes()
    
    if config_to_delete:
        try:
            path = Path(config_to_delete)
            if path.exists():
                path.unlink()
        except Exception:
            pass

def active_openvpn_running() -> bool:
    return active_openvpn_process is not None and active_openvpn_process.poll() is None

def sort_all_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    available_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "available" or n.get("active")],
        key=node_sort_key
    )
    untested_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "not_checked" and not n.get("active")],
        key=lambda n: (node_ip_priority_rank(n), -parse_int(n.get("score")), parse_int(n.get("ping")))
    )
    unavailable_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "unavailable" and not n.get("active")],
        key=lambda n: (node_ip_priority_rank(n), -parse_int(n.get("score")), -float(n.get("probed_at", 0)))
    )
    return available_nodes + untested_nodes + unavailable_nodes

active_test_indexes = set()
test_indexes_lock = threading.Lock()
auto_test_background_lock = threading.Lock()
auto_test_background_running = False

def get_free_test_index() -> int:
    with test_indexes_lock:
        for idx in range(2, 100):
            if idx not in active_test_indexes:
                active_test_indexes.add(idx)
                return idx
        return 99

def release_test_index(idx: int) -> None:
    with test_indexes_lock:
        active_test_indexes.discard(idx)

def safe_test_vpnbook_node_by_id(node_id: str, node: dict[str, Any]) -> dict[str, Any]:
    """Safe manual test for VPNBook nodes.

    VPNBook tests do not start OpenVPN by default because even a single handshake can run local
    routing directives from downloaded/template configs on some VPS images. This test verifies the
    server TCP port and performs IP risk enrichment, then lets manual switching do the real connect.
    """
    h = str(node.get("remote_host") or node.get("host_name") or node.get("ip") or "")
    p = parse_int(node.get("remote_port")) or 443
    fallback_ping = parse_int(node.get("ping"))
    latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)
    risk_ip = resolve_ip_for_risk(h)
    ok = latency > 0
    temp_node = {
        "id": node_id,
        "ip": risk_ip,
        "remote_host": h,
        "remote_port": p,
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "fraud_score": 0,
        "clean_score": 0,
        "risk_level": "unknown",
        "fraud_flags": [],
        "risk_sources": [],
        "blacklist_hits": [],
        "blacklist_count": 0,
        "ip_clean": False,
    }
    if risk_ip:
        vpn_utils.enrich_ip_info([temp_node])

    with lock:
        nodes = read_json(NODES_FILE, [])
        current = next((item for item in nodes if item.get("id") == node_id), None)
        if current:
            current["ip"] = risk_ip or current.get("ip") or h
            current["latency_ms"] = latency
            current["probe_status"] = "available" if ok else "unavailable"
            current["probe_message"] = (
                "VPNBook 安全检测通过：TCP 端口可达，已跳过 OpenVPN 握手以避免 VPS 路由/SSH 卡死；点击切换才会真正尝试连接。"
                if ok else
                "VPNBook 安全检测失败：TCP 端口不可达或超时；未启动 OpenVPN 握手。"
            )
            current["probed_at"] = time.time()
            for key in [
                "owner", "asn", "as_name", "location", "ip_type", "quality", "fraud_score",
                "clean_score", "risk_level", "fraud_flags", "risk_sources", "blacklist_hits",
                "blacklist_count", "ip_clean",
            ]:
                current[key] = temp_node.get(key, current.get(key))
            sorted_nodes = sort_all_nodes(nodes)
            write_json(NODES_FILE, sorted_nodes)
            return next((item for item in sorted_nodes if item.get("id") == node_id), current)
    return {}

def test_node_by_id(node_id: str) -> dict[str, Any]:
    with lock:
        nodes = read_json(NODES_FILE, [])
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")
        config_file = str(node["config_file"])
        config_text = node.get("config_text") or ""
        h = str(node.get("remote_host") or node.get("ip"))
        p = parse_int(node.get("remote_port"))
        fallback_ping = parse_int(node.get("ping"))
        node_source = str(node.get("source") or "").lower()

    if node_source == "vpnbook" and VPNBOOK_SAFE_TEST_ONLY:
        return safe_test_vpnbook_node_by_id(node_id, node)

    temp_path = Path(config_file)
    try:
        CONFIG_DIR.mkdir(exist_ok=True, parents=True)
        temp_path.write_text(sanitize_openvpn_config_for_eianun(config_text), encoding="utf-8")
    except Exception as e:
        raise RuntimeError(f"Failed to write temp config file: {e}")

    latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)
    
    idx = get_free_test_index()
    try:
        ok, message, _ = run_openvpn_until_ready(config_file, keep_alive=False, route_nopull=True, timeout=12, dev=f"tun{idx}", auth_file=auth_file_for_node(node))
    finally:
        release_test_index(idx)
    
    try:
        if temp_path.exists():
            temp_path.unlink()
    except Exception:
        pass

    risk_ip = resolve_ip_for_risk(h)
    temp_node = {
        "id": node_id,
        "ip": risk_ip,
        "remote_host": h,
        "remote_port": p,
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "fraud_score": 0,
        "clean_score": 0,
        "risk_level": "unknown",
        "fraud_flags": [],
        "risk_sources": [],
        "blacklist_hits": [],
        "blacklist_count": 0,
        "ip_clean": False,
    }
    if ok:
        vpn_utils.enrich_ip_info([temp_node])

    with lock:
        nodes = read_json(NODES_FILE, [])
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if node:
            node["latency_ms"] = latency
            node["probe_status"] = "available" if ok else "unavailable"
            node["probe_message"] = message
            node["probed_at"] = time.time()
            if ok:
                node["owner"] = temp_node["owner"]
                node["asn"] = temp_node["asn"]
                node["as_name"] = temp_node["as_name"]
                node["location"] = temp_node["location"]
                node["ip_type"] = temp_node["ip_type"]
                node["quality"] = temp_node["quality"]
                for risk_key in ["fraud_score", "clean_score", "risk_level", "fraud_flags", "risk_sources", "blacklist_hits", "blacklist_count", "ip_clean"]:
                    node[risk_key] = temp_node.get(risk_key, [] if risk_key.endswith("hits") or risk_key.endswith("flags") or risk_key.endswith("sources") else False if risk_key == "ip_clean" else 0)
            
            sorted_nodes = sort_all_nodes(nodes)
            write_json(NODES_FILE, sorted_nodes)
            res = next((item for item in sorted_nodes if item.get("id") == node_id), node)
            return res
        else:
            return {}

def update_node_result_in_store(result: dict[str, Any]) -> tuple[int, int]:
    """Write one tested node result immediately so UI progress and auto selection can see it."""
    with lock:
        current_nodes = read_json(NODES_FILE, [])
        rid = result.get("id")
        for n in current_nodes:
            if n.get("id") == rid:
                n.update(result)
                break
        sorted_nodes = sort_all_nodes(current_nodes)
        write_json(NODES_FILE, sorted_nodes)
        available_count = len([n for n in sorted_nodes if n.get("probe_status") == "available"])
        unavailable_count = len([n for n in sorted_nodes if n.get("probe_status") == "unavailable"])
    return available_count, unavailable_count


def test_multiple_nodes(node_ids: list[str], progress_prefix: str = "正在自动检测节点") -> list[dict[str, Any]]:
    with lock:
        nodes = read_json(NODES_FILE, [])
        requested = set(node_ids)
        to_test = [n for n in nodes if n.get("id") in requested]

    if not to_test:
        return []

    total = len(to_test)
    worker_count = min(AUTO_TEST_WORKERS, total)
    set_state(
        last_check_message=f"{progress_prefix} 0/{total}，并发 {worker_count}，请稍候...",
        auto_test_total=total,
        auto_test_done=0,
        auto_test_workers=worker_count,
    )
        
    def test_worker(n_info: dict[str, Any]) -> dict[str, Any]:
        node_id = n_info["id"]
        config_file = n_info["config_file"]
        config_text = n_info.get("config_text") or ""
        h = str(n_info.get("remote_host") or n_info.get("ip"))
        p = parse_int(n_info.get("remote_port"))
        fallback_ping = parse_int(n_info.get("ping"))
        
        temp_path = Path(config_file)
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            temp_path.write_text(config_text, encoding="utf-8")
        except Exception:
            pass
            
        latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)
        idx = get_free_test_index()
        try:
            ok, message, _ = run_openvpn_until_ready(
                config_file,
                keep_alive=False,
                route_nopull=True,
                timeout=OPENVPN_BATCH_TEST_TIMEOUT_SECONDS,
                dev=f"tun{idx}",
                auth_file=auth_file_for_node(n_info),
            )
        finally:
            release_test_index(idx)
        
        try:
            if temp_path.exists():
                temp_path.unlink()
        except Exception:
            pass
            
        temp_node = {
            "id": node_id,
            "latency_ms": latency,
            "probe_status": "available" if ok else "unavailable",
            "probe_message": message,
            "probed_at": time.time(),
            "owner": "",
            "asn": "",
            "as_name": "",
            "location": "",
            "ip_type": "",
            "quality": "",
            "fraud_score": 0,
            "clean_score": 0,
            "risk_level": "unknown",
            "fraud_flags": [],
            "risk_sources": [],
            "blacklist_hits": [],
            "blacklist_count": 0,
            "ip_clean": False,
        }
        if ok:
            ip_to_enrich = {
                "ip": resolve_ip_for_risk(h),
                "remote_host": h,
                "owner": "",
                "asn": "",
                "as_name": "",
                "location": "",
                "ip_type": "",
                "quality": "",
                "fraud_score": 0,
                "clean_score": 0,
                "risk_level": "unknown",
                "fraud_flags": [],
                "risk_sources": [],
                "blacklist_hits": [],
                "blacklist_count": 0,
                "ip_clean": False,
            }
            vpn_utils.enrich_ip_info([ip_to_enrich])
            temp_node.update(ip_to_enrich)
        return temp_node

    updated_nodes_map = {}
    completed = 0
    available_count = 0
    unavailable_count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {executor.submit(test_worker, n): n["id"] for n in to_test}
        for future in concurrent.futures.as_completed(futures):
            nid = futures[future]
            try:
                res = future.result()
                updated_nodes_map[nid] = res
            except Exception as e:
                res = {
                    "id": nid,
                    "probe_status": "unavailable",
                    "probe_message": f"Test exception: {e}",
                    "latency_ms": 0,
                    "probed_at": time.time(),
                    "fraud_score": 0,
                    "clean_score": 0,
                    "risk_level": "unknown",
                    "fraud_flags": [],
                    "risk_sources": [],
                    "blacklist_hits": [],
                    "blacklist_count": 0,
                    "ip_clean": False,
                }
                updated_nodes_map[nid] = res
            completed += 1
            # 逐个节点写入，避免面板长时间显示全部未检/0 进度。
            available_count, unavailable_count = update_node_result_in_store(res)
            set_state(
                last_check_message=f"{progress_prefix} {completed}/{total}，可用 {available_count} 个，不可用 {unavailable_count} 个...",
                auto_test_total=total,
                auto_test_done=completed,
                auto_test_workers=worker_count,
            )

    set_state(
        last_check_message=f"{progress_prefix}完成：共检测 {total} 个，可用 {available_count} 个，不可用 {unavailable_count} 个。",
        auto_test_total=total,
        auto_test_done=total,
        auto_test_workers=worker_count,
    )
    return list(updated_nodes_map.values())


def run_remaining_tests_background(node_ids: list[str]) -> None:
    global auto_test_background_running, is_connecting
    if not node_ids:
        return
    with auto_test_background_lock:
        if auto_test_background_running:
            return
        auto_test_background_running = True

    def worker() -> None:
        global auto_test_background_running, is_connecting
        try:
            set_state(
                last_check_message=f"首批节点检测完成，正在后台继续检测剩余 {len(node_ids)} 个节点...",
                background_auto_test_total=len(node_ids),
                background_auto_test_done=0,
            )
            test_multiple_nodes(node_ids, progress_prefix="正在后台检测剩余节点")
            set_state(last_check_message="后台节点检测完成，正在根据 IP 类型和质量重新优选节点...")
            # 后台检测完成后，如果还没有活动连接则立即故障转移；已有连接则按开关决定是否主动优选。
            try:
                is_connecting = False
                if not active_openvpn_running():
                    auto_switch_node()
                elif get_auto_select_best_node():
                    optimize_active_node_after_tests("background_batch_finished")
            except Exception as e:
                set_state(last_check_message=f"后台优选节点失败: {e}")
        finally:
            with auto_test_background_lock:
                auto_test_background_running = False

    threading.Thread(target=worker, daemon=True).start()

def auto_switch_node(attempt: int = 0) -> None:
    if attempt >= 3:
        print("[自动切换] 连续切换失败已达 3 次，停止切换以防止主线程死锁，将在后台重新加载节点...", flush=True)
        set_state(last_check_message="自动切换连续失败，将等待下一轮节点维护")
        return
        
    with lock:
        nodes = read_json(NODES_FILE, [])
        active_node = next((n for n in nodes if n.get("id") == active_openvpn_node_id or n.get("active")), None)
        failover_targets = get_failover_targets(active_node)
        all_candidates = [
            n for n in nodes 
            if n.get("probe_status") == "available" 
            and not n.get("active")
        ]
        scoped_candidates = [n for n in all_candidates if node_matches_target_countries(n, failover_targets)] if failover_targets else all_candidates
        candidates, candidate_reason = choose_auto_failover_candidates(scoped_candidates, all_candidates)
        scope_display = normalize_target_countries_input(failover_targets) if failover_targets else "全部地区"
        ip_type_scope_display = target_ip_types_display(get_target_ip_types())
        
    if candidates:
        next_node = candidates[0]
        clean_ok = node_is_clean_for_connect(next_node)
        ip_kind = f"干净度 {next_node.get('clean_score', 0)} / 欺诈值 {next_node.get('fraud_score', 0)} / 黑名单 {next_node.get('blacklist_count', 0)}"
        msg = f"当前连接已失效或代理连通性检测失败，正在按固定地区 {scope_display} / IP 类型 {ip_type_scope_display} 自动切换: {next_node['id']} ({ip_kind})；策略: {candidate_reason}"
        print(f"[自动切换] {msg}", flush=True)
        log_to_json("INFO", "VPN", msg)
        try:
            connect_node(next_node["id"], update_failover_scope=False, allow_auto_risky=not clean_ok)
        except Exception as e:
            err_msg = f"切换到备用节点 {next_node['id']} 失败: {e}，将尝试下一个..."
            print(f"[自动切换] {err_msg}", flush=True)
            log_to_json("WARNING", "VPN", err_msg)
            auto_switch_node(attempt + 1)
    else:
        if failover_targets:
            msg = f"固定地区 {scope_display} / IP 类型 {ip_type_scope_display} 当前没有可用备用节点，将清理当前连接并后台拉取同地区新节点..."
        else:
            msg = "没有可用的备选节点，将自动断开并清理当前连接状态，同时在后台异步获取新节点..."
        print(f"[自动切换] {msg}", flush=True)
        log_to_json("WARNING", "VPN", msg)
        stop_active_openvpn()
        with lock:
            nodes = read_json(NODES_FILE, [])
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, nodes)
        set_state(active_openvpn_node_id="", last_check_message=msg)
        
        def bg_fetch_and_switch():
            try:
                maintain_valid_nodes(force=False, target_override=failover_targets if failover_targets else None)
                auto_switch_node()
            except Exception as e:
                print(f"[自动切换后台补齐] 获取并测试节点失败: {e}", flush=True)
        
        threading.Thread(target=bg_fetch_and_switch, daemon=True).start()

def connect_node(node_id: str, update_failover_scope: bool = True, allow_manual_risky: bool = False, allow_auto_risky: bool = False) -> str:
    global active_openvpn_process, active_openvpn_node_id, is_connecting
    with lock:
        if is_connecting:
            print("[连接] 正在建立其他连接中，跳过此请求", flush=True)
            return "Already connecting"
        is_connecting = True
        active_openvpn_node_id = node_id
        set_state(active_openvpn_node_id=node_id, is_connecting=True, active_node_latency="正在连接", last_check_message="正在初始化连接配置...")
        
    try:
        log_to_json("INFO", "VPN", f"开始连接节点: {node_id}")
        nodes = read_json(NODES_FILE, [])
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")
        if not node_is_clean_for_connect(node):
            reason = f"该节点未通过干净 IP 优选阈值：欺诈值 {node.get('fraud_score', '未知')}，黑名单命中 {node.get('blacklist_count', 0)}，风险等级 {node.get('risk_level', 'unknown')}。"
            if not (allow_auto_risky or (ALLOW_MANUAL_RISKY_CONNECT and allow_manual_risky)):
                set_state(active_openvpn_node_id="", is_connecting=False, active_node_latency="已阻止", last_check_message=reason + " 如需手动强制切换可设置 ALLOW_MANUAL_RISKY_CONNECT=1。")
                with lock:
                    active_openvpn_node_id = ""
                raise RuntimeError(reason + " 自动默认会优先选干净 IP；手动切换可在面板确认后强制尝试。")
            if allow_auto_risky:
                warn_msg = reason + " 自动故障转移进入保活兜底模式：没有更干净的可用节点，先连接综合风险最低的可用节点，后续维护线程会继续寻找更干净节点。"
                print(f"[Auto Risk Fallback] {warn_msg}", flush=True)
            else:
                warn_msg = reason + " 已按手动确认继续尝试连接，自动故障转移会优先选择低风险干净 IP。"
                print(f"[Manual Override] {warn_msg}", flush=True)
            log_to_json("WARNING", "VPN", warn_msg)
            set_state(last_check_message=warn_msg)
        
        set_state(active_node_latency="清理连接", last_check_message="正在关闭与清理旧的 VPN 连接及网卡...")
        stop_active_openvpn()

        set_state(active_node_latency="写入配置", last_check_message="正在写入 OpenVPN 节点配置文件...")
        config_path = Path(node["config_file"])
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            config_path.write_text(sanitize_openvpn_config_for_eianun(node.get("config_text") or ""), encoding="utf-8")
        except Exception as e:
            raise RuntimeError(f"Failed to write configuration: {e}")

        set_state(active_node_latency="启动核心", last_check_message="正在启动 OpenVPN Core 核心服务并建立连接...")
        connect_timeout = VPNBOOK_CONNECT_TIMEOUT_SECONDS if str(node.get("source") or "").lower() == "vpnbook" else None
        ok, message, process = run_openvpn_until_ready(str(node["config_file"]), keep_alive=True, route_nopull=True, timeout=connect_timeout, auth_file=auth_file_for_node(node))
        if not ok or process is None:
            try:
                if config_path.exists():
                    config_path.unlink()
            except Exception:
                pass
            node["probe_status"] = "unavailable"
            node["probe_message"] = message
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, nodes)
            log_to_json("ERROR", "VPN", f"连接节点 {node_id} 失败: {message}")
            set_state(active_openvpn_node_id="", is_connecting=False, active_node_latency="无活动连接", last_check_message=f"连接失败: {message}")
            with lock:
                active_openvpn_node_id = ""
            raise RuntimeError(message)
            
        active_openvpn_process = process
        active_openvpn_node_id = node_id
        if update_failover_scope:
            set_failover_scope_from_node(node)
        
        set_state(active_node_latency="配置路由", last_check_message="正在配置策略路由规则与流量转发...")
        setup_policy_routing("tun0")
        
        global last_active_ping_time, last_active_latency
        last_active_ping_time = time.time()
        last_active_latency = 0
        
        set_state(active_node_latency="测试延迟", last_check_message="正在直连测试代理出口延迟与可用性...")
        try:
            ip = node.get("ip") or node.get("remote_host")
            port = parse_int(node.get("remote_port"))
            fallback = parse_int(node.get("ping"))
            latency = vpn_utils.ping_latency_ms(ip, port, fallback)
            if latency > 0:
                last_active_latency = latency
        except Exception:
            pass
            
        for item in nodes:
            item["active"] = item.get("id") == node_id
            if item["active"]:
                item["probe_message"] = f"Active node. HTTP proxy: http://{LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}"
        write_json(NODES_FILE, nodes)
        
        set_state(last_check_message="正在测试本地代理出站联通性与出口 IP...")
        res = check_proxy_health()
        if res["ok"]:
            set_state(
                proxy_ok=True,
                proxy_ip=res["ip"],
                proxy_latency_ms=res["latency_ms"],
                proxy_error=""
            )
        else:
            set_state(
                proxy_ok=False,
                proxy_ip="-",
                proxy_latency_ms=0,
                proxy_error=res.get("error", "未知错误")
            )
            
        latency_str = f"{last_active_latency} ms" if last_active_latency > 0 else "检测超时"
        set_state(active_openvpn_node_id=node_id, is_connecting=False, last_check_message=f"Connected {node_id}", active_node_latency=latency_str)
        log_to_json("INFO", "VPN", f"节点 {node_id} 连接成功，出口网卡 tun0 已启用")
        return f"Connected {node_id}"
    finally:
        with lock:
            is_connecting = False

def maintain_valid_nodes(force: bool = False, target_override: list[str] | None = None) -> str:
    global active_openvpn_process, active_openvpn_node_id, is_connecting
    ensure_dirs()
    is_connecting = True
    try:
        if force:
            with lock:
                stop_active_openvpn()
        elif not active_openvpn_running():
            has_active_id = False
            with lock:
                if active_openvpn_node_id:
                    has_active_id = True
                    stop_active_openvpn()
            if has_active_id:
                print("[维护线程] 检测到当前 OpenVPN 进程已意外退出，准备自动切换节点", flush=True)
                is_connecting = False
                auto_switch_node()
                is_connecting = True

        try:
            set_state(is_connecting=True, last_check_message="正在拉取最新的免费 VPN 节点列表...")
            candidates = fetch_candidates(target_override=target_override)
        except Exception as exc:
            vpn_utils.check_and_fix_dns()
            set_state(last_fetch_at=time.time(), last_fetch_status="error", last_fetch_message=str(exc))
            candidates = []

        if not candidates:
            is_connecting = False
            return "没有拉取到新节点"

        with lock:
            active_node = None
            if active_openvpn_node_id:
                current_nodes = read_json(NODES_FILE, [])
                active_node = next((n for n in current_nodes if n.get("id") == active_openvpn_node_id), None)
                
            merged: list[dict[str, Any]] = []
            seen_ids: set[str] = set()
            
            if active_node:
                merged.append(active_node)
                seen_ids.add(active_node["id"])
                
            for cand in candidates:
                if cand["id"] not in seen_ids:
                    merged.append(cand)
                    seen_ids.add(cand["id"])
                    
            if len(merged) > 1000:
                merged = merged[:1000]
                
            for n in merged:
                config_path = Path(n["config_file"])
                if not config_path.exists():
                    try:
                        config_path.write_text(n["config_text"], encoding="utf-8")
                    except Exception:
                        pass
                        
            write_json(NODES_FILE, merged)

        # 自动检测节点：VPNGate 可批量检测；VPNBook 默认不参与启动/后台批量 OpenVPN 检测。
        # 原因：部分 VPNBook 节点会在握手/推送路由阶段导致低配 VPS 网络栈或 SSH 卡死。
        # 混合来源时，VPNBook 只进入节点池供手动单个检测/强制切换；如果用户只选择 VPNBook，则只安全检测 1 个节点。
        with lock:
            current_nodes = read_json(NODES_FILE, [])
            raw_test_candidates = [n for n in current_nodes if not n.get("active")]
            selected_sources = get_node_sources()
            vpnbook_only = selected_sources == ["vpnbook"]
            skipped_vpnbook_auto = 0
            if VPNBOOK_AUTO_TEST:
                test_candidates = raw_test_candidates
            elif vpnbook_only:
                vpnbook_candidates = [n for n in raw_test_candidates if n.get("source") == "vpnbook"]
                test_candidates = vpnbook_candidates[:VPNBOOK_ONLY_SAFE_AUTO_TEST_LIMIT]
                skipped_vpnbook_auto = max(0, len(vpnbook_candidates) - len(test_candidates))
            else:
                test_candidates = [n for n in raw_test_candidates if n.get("source") != "vpnbook"]
                skipped_vpnbook_auto = len(raw_test_candidates) - len(test_candidates)

            if AUTO_TEST_ALL_NODES:
                to_test = test_candidates
                if AUTO_TEST_MAX_NODES > 0:
                    to_test = to_test[:AUTO_TEST_MAX_NODES]
            else:
                to_test = test_candidates[:10]
            total_candidates = len(raw_test_candidates)
            sync_count = min(len(to_test), AUTO_TEST_INITIAL_BATCH if AUTO_TEST_ALL_NODES else len(to_test))
            sync_test = to_test[:sync_count]
            rest_test = to_test[sync_count:]
            sync_test_ids = [n["id"] for n in sync_test]
            rest_test_ids = [n["id"] for n in rest_test]
            to_test_ids = sync_test_ids + rest_test_ids

        vpnbook_skip_note = f"，已跳过 VPNBook 自动批测 {skipped_vpnbook_auto} 个" if skipped_vpnbook_auto else ""
        print(f"[维护线程] 首批检测节点: {len(sync_test_ids)}/{len(to_test_ids)}，剩余 {len(rest_test_ids)} 个转后台{vpnbook_skip_note}，并发 {min(AUTO_TEST_WORKERS, max(1, len(sync_test_ids)))}", flush=True)
        set_state(
            is_connecting=True,
            last_check_message=f"正在检测首批节点 0/{len(sync_test_ids)}，剩余 {len(rest_test_ids)} 个将后台检测{vpnbook_skip_note}...",
            auto_test_total=len(sync_test_ids),
            auto_test_done=0,
            auto_test_workers=min(AUTO_TEST_WORKERS, max(1, len(sync_test_ids))) if sync_test_ids else 0,
            vpnbook_auto_skipped=skipped_vpnbook_auto,
        )
        if sync_test_ids:
            test_multiple_nodes(sync_test_ids, progress_prefix="正在检测首批节点")
        elif skipped_vpnbook_auto:
            set_state(last_check_message=f"VPNBook 节点已加入节点池，但默认不启动批量检测；请在面板单个检测，或设置 VPNBOOK_AUTO_TEST=1 后再启用自动检测。")
        
        is_connecting = False
        
        with lock:
            merged = read_json(NODES_FILE, [])
            available_candidates = [n for n in merged if n.get("probe_status") == "available"]

        if available_candidates:
            if not active_openvpn_running():
                auto_switch_node()
            elif get_auto_select_best_node():
                # 首批检测后，如果已有明显更优节点，也可以先优化一次。
                optimize_active_node_after_tests("initial_batch_finished")

        if rest_test_ids:
            run_remaining_tests_background(rest_test_ids)

        valid_nodes_count = len([n for n in merged if n.get("probe_status") == "available"])
        message = f"Fetched {len(candidates)} nodes. Tested {len(to_test_ids)} of {total_candidates} nodes. Auto select: {'on' if get_auto_select_best_node() else 'off'}."
        set_state(
            last_check_at=time.time(),
            last_check_message=message,
            active_openvpn_node_id=active_openvpn_node_id,
            valid_nodes=valid_nodes_count,
        )
        return message
    except Exception as e:
        is_connecting = False
        raise e


def collector_loop() -> None:
    while True:
        success = False
        try:
            res = maintain_valid_nodes(force=False)
            if "没有拉取到新节点" not in res:
                success = True
        except Exception as exc:
            set_state(last_check_at=time.time(), last_check_message=f"check error: {exc}")
            
        if not active_openvpn_running() and not success:
            sleep_time = 30
        else:
            sleep_time = CHECK_INTERVAL_SECONDS
            
        time.sleep(sleep_time)

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Eianun免费聚合落地IP - 安全登录</title>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #090d16;
      --bg-surface: rgba(15, 23, 42, 0.45);
      --border-color: rgba(255, 255, 255, 0.08);
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --primary: #6366f1;
      --primary-gradient: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
      --primary-hover: linear-gradient(135deg, #4f46e5 0%, #3730a3 100%);
      --success: #10b981;
      --danger: #f43f5e;
    }

    body {
      margin: 0;
      padding: 0;
      font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg-dark);
      background-image: 
        radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
        radial-gradient(at 100% 0%, rgba(16, 185, 129, 0.08) 0px, transparent 50%);
      height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      overflow: hidden;
    }

    .login-container {
      width: 100%;
      max-width: 400px;
      padding: 24px;
      box-sizing: border-box;
    }

    .login-card {
      background: var(--bg-surface);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid var(--border-color);
      border-radius: 20px;
      padding: 40px 32px;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
      text-align: center;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .brand-logo {
      width: 64px;
      height: 64px;
      background: rgba(99, 102, 241, 0.1);
      border: 1px solid rgba(99, 102, 241, 0.25);
      border-radius: 16px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 24px auto;
      color: var(--primary);
      position: relative;
    }

    .brand-logo::after {
      content: '';
      position: absolute;
      width: 100%;
      height: 100%;
      border-radius: 16px;
      border: 1px solid var(--success);
      opacity: 0.5;
      animation: ripple 2s infinite ease-out;
    }

    @keyframes ripple {
      0% { transform: scale(1); opacity: 0.5; }
      100% { transform: scale(1.3); opacity: 0; }
    }

    .login-title {
      font-size: 24px;
      font-weight: 700;
      color: var(--text-primary);
      margin: 0 0 8px 0;
      letter-spacing: 0.5px;
    }

    .login-subtitle {
      font-size: 14px;
      color: var(--text-secondary);
      margin: 0 0 32px 0;
    }

    .form-group {
      margin-bottom: 20px;
      text-align: left;
    }

    .form-label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      color: var(--text-secondary);
      margin-bottom: 8px;
      margin-left: 4px;
    }

    .input-wrapper {
      position: relative;
    }

    .input-field {
      width: 100%;
      height: 48px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 0 16px;
      box-sizing: border-box;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 15px;
      outline: none;
      transition: all 0.2s ease;
    }

    .input-field:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
      background: rgba(15, 23, 42, 0.6);
    }

    .error-message {
      color: var(--danger);
      font-size: 13px;
      margin-top: 8px;
      min-height: 18px;
      text-align: left;
      margin-left: 4px;
      display: none;
    }

    .login-btn {
      width: 100%;
      height: 48px;
      background: var(--primary-gradient);
      border: none;
      border-radius: 10px;
      color: white;
      font-family: inherit;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      box-shadow: 0 4px 12px rgba(99, 102, 241, 0.25);
    }

    .login-btn:hover {
      background: var(--primary-hover);
      transform: translateY(-1px);
      box-shadow: 0 6px 16px rgba(99, 102, 241, 0.35);
    }

    .login-btn:active {
      transform: translateY(1px);
    }

    .login-btn:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      transform: none !important;
    }


    .login-progress {
      display: none;
      margin-top: 16px;
      text-align: left;
    }

    .login-progress-text {
      font-size: 13px;
      color: var(--text-secondary);
      margin-bottom: 8px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .login-progress-track {
      height: 8px;
      border-radius: 999px;
      overflow: hidden;
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid rgba(255, 255, 255, 0.08);
    }

    .login-progress-bar {
      width: 0%;
      height: 100%;
      border-radius: 999px;
      background: var(--primary-gradient);
      transition: width 0.35s ease;
    }
  </style>
</head>
<body>
  <div class="login-container">
    <div class="login-card">
      <div class="brand-logo">
        <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
      </div>
      <h2 class="login-title">Eianun免费聚合落地IP</h2>
      <p class="login-subtitle">请输入您的管理账号和安全密码以继续</p>
      
      <form id="login_form" onsubmit="handleLogin(event)">
        <div class="form-group">
          <label class="form-label" for="username">管理账号</label>
          <div class="input-wrapper">
            <input type="text" id="username" class="input-field" placeholder="请输入管理账号" required autocomplete="username">
          </div>
        </div>
        <div class="form-group" style="margin-top: 16px;">
          <label class="form-label" for="password">安全密码</label>
          <div class="input-wrapper">
            <input type="password" id="password" class="input-field" placeholder="请输入安全密码" required autocomplete="current-password">
          </div>
          <div id="error_text" class="error-message"></div>
        </div>
        
        <button type="submit" id="submit_btn" class="login-btn">
          <span>登录</span>
        </button>

        <div id="login_progress" class="login-progress">
          <div class="login-progress-text">
            <span id="login_progress_text">正在准备登录...</span>
            <span id="login_progress_percent">0%</span>
          </div>
          <div class="login-progress-track"><div id="login_progress_bar" class="login-progress-bar"></div></div>
        </div>
      </form>
    </div>
  </div>

  <script>
    function setLoginProgress(text, percent) {
      const box = document.getElementById("login_progress");
      const textEl = document.getElementById("login_progress_text");
      const percentEl = document.getElementById("login_progress_percent");
      const bar = document.getElementById("login_progress_bar");
      box.style.display = "block";
      textEl.textContent = text;
      percentEl.textContent = `${percent}%`;
      bar.style.width = `${percent}%`;
    }

    function resetLoginButton() {
      const submitBtn = document.getElementById("submit_btn");
      submitBtn.disabled = false;
      submitBtn.querySelector("span").textContent = "登录";
    }

    async function handleLogin(e) {
      e.preventDefault();
      const uname = document.getElementById("username").value;
      const pwd = document.getElementById("password").value;
      const errorText = document.getElementById("error_text");
      const submitBtn = document.getElementById("submit_btn");
      
      errorText.style.display = "none";
      submitBtn.disabled = true;
      submitBtn.querySelector("span").textContent = "正在验证";
      setLoginProgress("1/3 正在验证账号密码...", 28);
      
      try {
        const response = await fetch("./api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: uname, password: pwd }),
          cache: "no-store"
        });
        setLoginProgress("2/3 正在建立管理会话...", 58);
        
        let data;
        try {
          data = await Promise.race([
            response.json(),
            new Promise((_, reject) => setTimeout(() => reject(new Error("login response parse timeout")), 3000))
          ]);
        } catch (parseErr) {
          if (response.ok) {
            // 兼容少数环境下登录响应正文被代理/浏览器卡住的情况：
            // 只要 HTTP 状态已经成功，Cookie 已经写入，就直接进入面板。
            data = { ok: true };
          } else {
            throw parseErr;
          }
        }
        if (response.ok && data.ok) {
          submitBtn.querySelector("span").textContent = "验证成功";
          setLoginProgress("3/3 登录成功，正在加载面板与节点状态...", 86);
          setTimeout(() => {
            setLoginProgress("正在进入控制面板，请稍候...", 100);
          }, 250);
          setTimeout(() => {
            window.location.replace(window.location.href.split("#")[0]);
          }, 650);
        } else {
          setLoginProgress("验证失败，请检查账号密码", 100);
          errorText.textContent = data.error || "账号或密码不正确，请重新输入";
          errorText.style.display = "block";
          resetLoginButton();
        }
      } catch (err) {
        setLoginProgress("连接服务器失败，请稍后重试", 100);
        errorText.textContent = "连接服务器失败，请稍后重试";
        errorText.style.display = "block";
        resetLoginButton();
      }
    }
  </script>
</body>
</html>
"""

INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Eianun免费聚合落地IP 节点池管理系统</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
    
    :root {
      --bg-dark: #0b0f19;
      --bg-surface: rgba(22, 30, 49, 0.6);
      --bg-surface-hover: rgba(30, 41, 67, 0.85);
      --border-color: rgba(255, 255, 255, 0.08);
      --border-color-hover: rgba(99, 102, 241, 0.35);
      --text-primary: #f3f4f6;
      --text-secondary: #9ca3af;
      --primary: #6366f1;
      --primary-gradient: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
      --primary-hover: linear-gradient(135deg, #4f46e5 0%, #3730a3 100%);
      --success: #10b981;
      --success-gradient: linear-gradient(135deg, #34d399 0%, #059669 100%);
      --danger: #f43f5e;
      --danger-gradient: linear-gradient(135deg, #fb7185 0%, #e11d48 100%);
      --warning: #f59e0b;
      --warning-gradient: linear-gradient(135deg, #fbbf24 0%, #d97706 100%);
      --active-row-bg: rgba(16, 185, 129, 0.06);
      --active-row-border: rgba(16, 185, 129, 0.25);
    }

    body {
      margin: 0;
      font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg-dark);
      background-image: 
        radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
        radial-gradient(at 100% 0%, rgba(16, 185, 129, 0.08) 0px, transparent 50%),
        radial-gradient(at 50% 100%, rgba(79, 70, 229, 0.05) 0px, transparent 50%);
      background-attachment: fixed;
      color: var(--text-primary);
      min-height: 100vh;
      -webkit-font-smoothing: antialiased;
    }

    header {
      padding: 16px 32px;
      background: rgba(11, 15, 25, 0.7);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border-bottom: 1px solid var(--border-color);
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 100;
    }

    .brand {
      display: flex;
      flex-direction: column;
    }

    h1 {
      font-size: 20px;
      font-weight: 700;
      margin: 0;
      background: linear-gradient(135deg, #a5b4fc 0%, #6366f1 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      letter-spacing: -0.5px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .status {
      font-size: 13px;
      color: var(--text-secondary);
      margin-top: 4px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--success);
      box-shadow: 0 0 10px var(--success);
      display: inline-block;
    }

    .btn-group {
      display: flex;
      gap: 12px;
    }

    button {
      height: 38px;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 16px;
      font-weight: 600;
      font-size: 13px;
      cursor: pointer;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      background: rgba(255, 255, 255, 0.04);
      color: var(--text-primary);
    }

    button:hover {
      background: rgba(255, 255, 255, 0.08);
      border-color: rgba(255, 255, 255, 0.15);
      transform: translateY(-1px);
    }

    .btn-primary {
      background: var(--primary-gradient);
      color: white;
      border: none;
      box-shadow: 0 4px 12px rgba(99, 102, 241, 0.2);
    }

    .btn-primary:hover {
      background: var(--primary-hover);
      box-shadow: 0 6px 16px rgba(99, 102, 241, 0.35);
    }

    .btn-danger {
      background: var(--danger-gradient);
      color: white;
      border: none;
      box-shadow: 0 4px 12px rgba(244, 63, 94, 0.2);
    }

    .btn-danger:hover {
      opacity: 0.95;
      box-shadow: 0 6px 16px rgba(244, 63, 94, 0.35);
    }

    button:disabled {
      opacity: 0.4;
      cursor: not-allowed;
      transform: none !important;
      box-shadow: none !important;
    }

    main {
      padding: 24px 32px;
      max-width: 1400px;
      margin: 0 auto;
    }

    .active-card {
      background: linear-gradient(135deg, rgba(99, 102, 241, 0.12) 0%, rgba(79, 70, 229, 0.04) 100%);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid rgba(99, 102, 241, 0.25);
      border-radius: 16px;
      padding: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 24px;
      box-shadow: 0 8px 32px rgba(99, 102, 241, 0.12);
      transition: all 0.3s ease;
      width: 100%;
      box-sizing: border-box;
    }
    
    .active-card-info {
      display: flex;
      align-items: center;
      gap: 20px;
      flex-wrap: wrap;
    }
    
    .active-card-details {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    
    .active-card-title {
      font-size: 14px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: #a5b4fc;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .active-card-value {
      font-size: 24px;
      font-weight: 700;
      color: var(--text-primary);
    }
    
    .active-card-meta {
      display: flex;
      gap: 16px;
      font-size: 13px;
      color: var(--text-secondary);
      flex-wrap: wrap;
    }

    .active-card-meta span strong {
      color: var(--text-primary);
    }

    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }

    .stat {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 20px;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
      overflow: hidden;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .stat:hover {
      background: var(--bg-surface-hover);
      border-color: var(--border-color-hover);
      transform: translateY(-2px);
      box-shadow: 0 8px 24px rgba(99, 102, 241, 0.1);
    }

    .stat-info {
      display: flex;
      flex-direction: column;
    }

    .stat strong {
      font-size: 32px;
      font-weight: 700;
      display: block;
      margin-bottom: 4px;
      background: linear-gradient(135deg, #ffffff 0%, #cbd5e1 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .stat span {
      font-size: 13px;
      color: var(--text-secondary);
      font-weight: 500;
    }

    .stat-icon-wrapper {
      width: 44px;
      height: 44px;
      border-radius: 10px;
      background: rgba(255, 255, 255, 0.04);
      display: flex;
      align-items: center;
      justify-content: center;
      border: 1px solid rgba(255, 255, 255, 0.06);
    }

    .stat-icon {
      width: 22px;
      height: 22px;
      color: var(--primary);
    }

    .stat:nth-child(2) .stat-icon { color: var(--warning); }
    .stat:nth-child(3) .stat-icon { color: var(--success); }


    .toolbar {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 24px;
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
      align-items: center;
    }

    .toolbar select {
      width: 180px;
      height: 42px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 12px;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      outline: none;
      transition: all 0.2s ease;
      cursor: pointer;
    }

    .toolbar select:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
      background: #0f172a;
    }

    .toolbar input {
      flex: 1;
      min-width: 250px;
      height: 42px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 16px;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      transition: all 0.2s ease;
    }

    .toolbar input:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
      background: rgba(15, 23, 42, 0.8);
    }

    .table-wrapper {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      overflow: hidden;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
    }

    .table-container {
      overflow-x: auto;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      min-width: 1000px;
    }

    th, td {
      padding: 14px 20px;
      border-bottom: 1px solid var(--border-color);
      font-size: 14px;
    }

    th {
      background: rgba(17, 24, 39, 0.4);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--text-secondary);
    }

    tr {
      transition: background 0.2s ease;
    }

    tr:hover {
      background: rgba(255, 255, 255, 0.015);
    }

    .active-row {
      background: var(--active-row-bg) !important;
      outline: 2px solid var(--success) !important;
      outline-offset: -2px;
      position: relative;
      z-index: 5;
    }

    .active-row td {
      border-bottom: 1px solid var(--active-row-border);
      border-top: 1px solid var(--active-row-border);
    }

    .badge {
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border: 1px solid transparent;
    }

    .badge-pulse {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: currentColor;
      animation: pulse 1.5s infinite;
      display: inline-block;
    }

    @keyframes pulse {
      0% { transform: scale(0.9); opacity: 1; }
      50% { transform: scale(1.6); opacity: 0.4; }
      100% { transform: scale(0.9); opacity: 1; }
    }

    @keyframes spin {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }

    .available {
      background: rgba(16, 185, 129, 0.1);
      color: #34d399;
      border-color: rgba(16, 185, 129, 0.2);
    }

    .unavailable {
      background: rgba(244, 63, 94, 0.1);
      color: #fb7185;
      border-color: rgba(244, 63, 94, 0.2);
    }

    .not_checked {
      background: rgba(245, 158, 11, 0.1);
      color: #fbbf24;
      border-color: rgba(245, 158, 11, 0.2);
    }

    .current-badge {
      background: rgba(99, 102, 241, 0.15);
      color: #818cf8;
      border-color: rgba(99, 102, 241, 0.3);
    }

    .table-actions {
      display: flex;
      gap: 8px;
    }

    .connect-btn {
      background: transparent;
      color: #818cf8;
      border: 1px solid rgba(99, 102, 241, 0.4);
      border-radius: 6px;
      padding: 0 12px;
      height: 30px;
      font-size: 12px;
      font-weight: 600;
      transition: all 0.2s ease;
      cursor: pointer;
    }

    .connect-btn:hover:not(:disabled) {
      background: var(--primary-gradient);
      color: white;
      border-color: transparent;
      box-shadow: 0 4px 10px rgba(99, 102, 241, 0.3);
    }

    .connect-btn:disabled {
      opacity: 0.3;
      cursor: not-allowed;
    }

    .test-btn {
      background: transparent;
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.4);
      border-radius: 6px;
      padding: 0 12px;
      height: 30px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .test-btn:hover:not(:disabled) {
      background: var(--success-gradient);
      color: white;
      border-color: transparent;
      box-shadow: 0 4px 10px rgba(16, 185, 129, 0.3);
    }

    .test-btn:disabled {
      opacity: 0.4;
      cursor: not-allowed;
    }

    .mono {
      font-family: 'JetBrains Mono', Consolas, monospace;
      font-size: 13px;
      color: #e2e8f0;
    }

    .latency-val {
      font-weight: 600;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 12px;
    }

    .latency-good {
      background: rgba(16, 185, 129, 0.1);
      color: #34d399;
    }
    
    .latency-medium {
      background: rgba(245, 158, 11, 0.1);
      color: #fbbf24;
    }
    
    .latency-poor {
      background: rgba(244, 63, 94, 0.1);
      color: #fb7185;
    }

    @media (max-width: 768px) {
      header {
        flex-direction: column;
        align-items: flex-start;
        padding: 16px 20px;
      }
      .btn-group {
        width: 100%;
        margin-top: 12px;
      }
      .btn-group button {
        flex: 1;
      }
      main {
        padding: 16px 20px;
      }
      .active-card {
        flex-direction: column;
        align-items: flex-start;
        gap: 16px;
      }
      .active-card button {
        width: 100%;
      }
    }
    
    /* Admin dropdown styles */
    .dropdown {
      position: relative;
      display: inline-block;
    }
    .dropdown-content {
      display: none;
      position: absolute;
      right: 0;
      margin-top: 6px;
      min-width: 140px;
      background: rgba(22, 30, 49, 0.95);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
      z-index: 1000;
      overflow: hidden;
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
    }
    .dropdown-content a {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 10px 16px;
      color: var(--text-primary);
      text-decoration: none;
      font-size: 13px;
      font-weight: 500;
      transition: background 0.2s;
    }
    .dropdown-content a:hover {
      background: rgba(255,255,255,0.08);
    }
    
    /* Modal styles */
    .modal {
      display: none;
      position: fixed;
      z-index: 10000;
      left: 0;
      top: 0;
      width: 100%;
      height: 100%;
      overflow: auto;
      background-color: rgba(9, 13, 22, 0.7);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
      align-items: center;
      justify-content: center;
    }
    .modal-content {
      background: rgba(22, 30, 49, 0.9);
      border: 1px solid var(--border-color);
      border-radius: 20px;
      width: 90%;
      max-width: 480px;
      padding: 32px;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.5);
      position: relative;
      box-sizing: border-box;
      animation: modalFadeIn 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }
    @keyframes modalFadeIn {
      from { transform: scale(0.95); opacity: 0; }
      to { transform: scale(1); opacity: 1; }
    }
    
    /* Inputs in settings */
    .form-group {
      margin-bottom: 20px;
      text-align: left;
    }
    .form-label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      color: var(--text-secondary);
      margin-bottom: 8px;
      margin-left: 4px;
    }
    .input-field {
      width: 100%;
      height: 40px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 12px;
      box-sizing: border-box;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      outline: none;
      transition: all 0.2s ease;
    }
    .input-field:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
      background: rgba(15, 23, 42, 0.6);
    }


    .page-loading {
      position: fixed;
      inset: 0;
      z-index: 20000;
      display: flex;
      align-items: center;
      justify-content: center;
      background: rgba(9, 13, 22, 0.72);
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
    }

    .page-loading-card {
      width: min(420px, calc(100vw - 48px));
      background: rgba(22, 30, 49, 0.92);
      border: 1px solid var(--border-color);
      border-radius: 18px;
      padding: 24px;
      box-shadow: 0 18px 48px rgba(0, 0, 0, 0.38);
    }

    .page-loading-title {
      font-size: 18px;
      font-weight: 700;
      color: var(--text-primary);
      margin-bottom: 8px;
    }

    .page-loading-desc {
      font-size: 13px;
      color: var(--text-secondary);
      margin-bottom: 16px;
      line-height: 1.5;
    }

    .page-loading-track {
      height: 9px;
      border-radius: 999px;
      background: rgba(255, 255, 255, 0.06);
      overflow: hidden;
      border: 1px solid rgba(255, 255, 255, 0.08);
    }

    .page-loading-bar {
      width: 0%;
      height: 100%;
      border-radius: 999px;
      background: var(--primary-gradient);
      transition: width 0.35s ease;
    }

    .page-loading-meta {
      margin-top: 10px;
      font-size: 12px;
      color: var(--text-secondary);
      display: flex;
      justify-content: space-between;
      gap: 12px;
    }
  </style>
</head>
<body>

<div id="page_loading" class="page-loading">
  <div class="page-loading-card">
    <div class="page-loading-title">正在加载控制面板</div>
    <div id="page_loading_desc" class="page-loading-desc">正在连接后端服务并读取节点状态...</div>
    <div class="page-loading-track"><div id="page_loading_bar" class="page-loading-bar"></div></div>
    <div class="page-loading-meta"><span id="page_loading_step">初始化</span><span id="page_loading_percent">0%</span></div>
  </div>
</div>
<header>
  <div class="brand">
    <h1>
      <svg xmlns="http://www.w3.org/2000/svg" style="width:24px; height:24px; color:#818cf8;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
      Eianun免费聚合落地IP 节点管理系统
    </h1>
    <div id="status" class="status"><span class="status-dot"></span>服务加载中...</div>
  </div>
  <div class="btn-group">
    <button id="refresh" class="btn-primary" style="background: var(--success-gradient);">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18.5" /></svg>
      更新节点
    </button>
    <button id="check" class="btn-primary">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18.5" /></svg>
      立即检测补齐
    </button>
    <div class="dropdown">
      <button id="admin_btn" class="btn-primary" style="background: rgba(255, 255, 255, 0.08); border: 1px solid var(--border-color); color: var(--text-primary);">
        <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>
        管理员
        <svg xmlns="http://www.w3.org/2000/svg" style="width:12px; height:12px; margin-left: 2px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="3"><path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7" /></svg>
      </button>
      <div id="admin_dropdown" class="dropdown-content">
        <a href="javascript:void(0)" onclick="openSettingsModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
          面板设置
        </a>
        <a href="javascript:void(0)" onclick="logoutAdmin()" style="color: var(--danger); border-top: 1px solid rgba(255,255,255,0.05);">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" /></svg>
          退出
        </a>
      </div>
    </div>
  </div>
</header>
<main>

  <!-- 当前连接活动节点卡片 -->
  <section class="active-node-section" id="active_node_card" style="margin-bottom: 24px;">
    <!-- Rendered dynamically by render() -->
  </section>

  <section class="stats">
    <div class="stat">
      <div class="stat-info">
        <strong id="total">0</strong>
        <span>可用节点池</span>
      </div>
      <div class="stat-icon-wrapper">
        <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
      </div>
    </div>
    <div class="stat">
      <div class="stat-info">
        <strong id="target">3</strong>
        <span>目标储备数</span>
      </div>
      <div class="stat-icon-wrapper">
        <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
      </div>
    </div>
    <div class="stat">
      <div class="stat-info">
        <strong id="active">0</strong>
        <span>已激活连接</span>
      </div>
      <div class="stat-icon-wrapper">
        <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
      </div>
    </div>
  </section>

  <section class="proxy-test-section" style="margin-bottom: 24px;">
    <div class="stat" style="display: flex; flex-direction: row; justify-content: space-between; align-items: center; width: 100%; box-sizing: border-box; flex-wrap: wrap; gap: 16px;">
      <div style="display: flex; align-items: center; gap: 16px; flex-wrap: wrap;">
        <div class="stat-icon-wrapper" style="background: rgba(99, 102, 241, 0.1); border-color: rgba(99, 102, 241, 0.2);">
          <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="color: var(--primary);"><path stroke-linecap="round" stroke-linejoin="round" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071a10.5 10.5 0 0114.14 0M1.414 8.05a16 16 0 0121.172 0" /></svg>
        </div>
        <div>
          <h3 style="margin: 0 0 4px 0; font-size: 16px; font-weight: 600; color: var(--text-primary);">本地代理出口检测 (Port 7928)</h3>
          <p style="margin: 0; font-size: 13px; color: var(--text-secondary);">
            测试本地 HTTP/SOCKS5 代理是否成功通过当前 VPN 节点出站，并获取实际出口公网 IP 和延迟。
          </p>
        </div>
      </div>
      <div style="display: flex; align-items: center; gap: 16px; flex-wrap: wrap; margin-left: auto;">
        <div id="proxy_test_result" style="text-align: right;">
          <div style="font-size: 14px; font-weight: 500; color: var(--text-secondary);">
            测试状态: <span id="proxy_status_badge" class="badge not_checked" style="margin-left: 4px;">未检测</span>
          </div>
          <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">
            出口 IP: <span id="proxy_ip_val" class="mono" style="font-weight: 600; color: var(--text-primary);">-</span> 
            <span id="proxy_latency_val" style="margin-left: 8px;"></span>
          </div>
        </div>
        <button id="btn_test_proxy" class="btn-primary" style="height: 40px; padding: 0 16px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
          测试代理
        </button>
      </div>
    </div>
  </section>

  <section class="toolbar">
    <select id="country_filter">
      <option value="">所有国家</option>
    </select>
    <select id="ip_type_filter">
      <option value="">所有IP类型</option>
      <option value="residential">住宅IP</option>
      <option value="mobile">移动IP</option>
      <option value="normal">普通/未知</option>
      <option value="hosting">机房IP</option>
      <option value="proxy">代理IP</option>
    </select>
    <input id="search" placeholder="输入国家、位置、IP、ASN、运营主体等过滤节点..." />
    <button id="btn_batch_test" class="btn-primary" style="height: 42px; padding: 0 20px; font-weight: 600; background: var(--primary-gradient);">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
      批量测试本页
    </button>
  </section>
  <div class="table-wrapper">
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th style="width: 110px;">状态</th>
            <th style="width: 100px;">延迟</th>
            <th style="width: 220px;">IP 地址 : 端口</th>
            <th>物理位置</th>
            <th style="width: 100px;">ASN</th>
            <th>运营主体 / ISP</th>
            <th style="width: 110px;">网络质量</th>
            <th style="width: 110px;">IP 类型</th>
            <th style="width: 100px;">欺诈值</th>
            <th style="width: 110px;">黑名单</th>
            <th style="width: 160px;">操作</th>
          </tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
    
    <!-- 分页控制栏 -->
    <div class="pagination-container" style="padding: 16px; display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--border-color); flex-wrap: wrap; gap: 12px;">
      <div style="font-size: 13px; color: var(--text-secondary);">
        显示第 <span id="page_start" style="color: var(--text-primary); font-weight:600;">0</span> - <span id="page_end" style="color: var(--text-primary); font-weight:600;">0</span> 条，共 <span id="filtered_count" style="color: var(--text-primary); font-weight:600;">0</span> 条备选节点
      </div>
      <div style="display: flex; gap: 8px; align-items: center;">
        <button id="btn_first_page" class="connect-btn" style="height: 32px; padding: 0 10px;">首页</button>
        <button id="btn_prev_page" class="connect-btn" style="height: 32px; padding: 0 10px;">上一页</button>
        <span style="font-size: 13px; color: var(--text-secondary); margin: 0 8px;">
          页码 <strong id="current_page_val" style="color: var(--primary);">1</strong> / <strong id="total_pages_val">1</strong>
        </span>
        <button id="btn_next_page" class="connect-btn" style="height: 32px; padding: 0 10px;">下一页</button>
        <button id="btn_last_page" class="connect-btn" style="height: 32px; padding: 0 10px;">尾页</button>
      </div>
    </div>
  </div>

  <!-- Settings Modal -->
  <div id="settings_modal" class="modal">
    <div class="modal-content">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
          面板设置（账号 / 密码 / 端口 / 来源 / 地区）
        </h3>
        <button type="button" onclick="closeSettingsModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>
      
      <div id="settings_error" style="color: var(--danger); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.2); border-radius: 6px; display: none;"></div>
      <div id="settings_success" style="color: var(--success); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; display: none;"></div>

      <form id="settings_form" onsubmit="saveSettings(event)">
        <div style="border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 16px; margin-bottom: 16px;">
          <div style="font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-secondary); font-weight: 600; margin-bottom: 12px;">面板访问与节点拉取配置</div>
          
          <div class="form-group" style="margin-bottom: 12px;">
            <label class="form-label" for="settings_port">网页端口</label>
            <input type="number" id="settings_port" class="input-field" required min="1" max="65535" placeholder="8787">
          </div>
          
          <div class="form-group" style="margin-bottom: 12px;">
            <label class="form-label" for="settings_suffix">登录安全后缀 (仅字母数字)</label>
            <input type="text" id="settings_suffix" class="input-field" required pattern="[A-Za-z0-9]+" placeholder="EJsW2EeBo9lY">
          </div>

          <div class="form-group" style="margin-bottom: 12px;">
            <label class="form-label" for="settings_target_countries">拉取地区过滤 (留空 = 全部地区)</label>
            <input type="text" id="settings_target_countries" class="input-field" placeholder="例如：JP,日本,US,美国,GB,英国">
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 6px; line-height: 1.4;">支持国家简称、英文名或中文名，多个地区用逗号分隔。保存后会按指定地区重新拉取节点。</div>
          </div>

          <div class="form-group" style="margin-bottom: 12px;">
            <label class="form-label" for="settings_node_sources">节点来源</label>
            <select id="settings_node_sources" class="input-field">
              <option value="vpngate,vpnbook">VPNGate + VPNBook（推荐）</option>
              <option value="vpngate">仅 VPNGate</option>
              <option value="vpnbook">仅 VPNBook</option>
            </select>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 6px; line-height: 1.4;">VPNBook 当前页面列出 US/CA/UK/DE/FR 等 OpenVPN 服务器，密码会自动从官网页面读取；如果官网改版导致配置下载失败，会自动跳过该来源。</div>
          </div>

          <div class="form-group" style="margin-bottom: 12px;">
            <label class="form-label" for="settings_target_ip_types">自动选择 IP 类型优先级</label>
            <select id="settings_target_ip_types" class="input-field">
              <option value="residential">住宅优先（推荐）</option>
              <option value="mobile,residential">移动优先</option>
              <option value="normal,residential,mobile">普通/未知优先</option>
              <option value="all">不限类型</option>
            </select>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 6px; line-height: 1.4;">这是优先级，不是硬过滤。自动故障转移会先按所选类型找节点；没有合适节点时再逐级兜底，代理/Tor 默认排在最后，避免服务停摆。手动切换仍可确认后强制尝试。</div>
          </div>

          <div class="form-group" style="margin-bottom: 12px;">
            <label class="form-label" for="settings_auto_select_best_node">检测完成后自动优选节点</label>
            <select id="settings_auto_select_best_node" class="input-field">
              <option value="1">开启：检测后主动切到更优节点（推荐）</option>
              <option value="0">关闭：只在断线/失效时故障转移</option>
            </select>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 6px; line-height: 1.4;">对应 AUTO_SELECT_BEST_NODE。关闭后不会因为检测到住宅/移动等更优节点而主动跳转，但节点失效时仍会自动故障转移。</div>
          </div>

          <div class="form-group" style="margin-bottom: 12px;">
            <label class="form-label" for="settings_new_username">新管理账号 (留空则不修改)</label>
            <input type="text" id="settings_new_username" class="input-field" placeholder="留空则不修改">
          </div>
          
          <div class="form-group">
            <label class="form-label" for="settings_new_password">新安全密码 (留空则不修改)</label>
            <input type="password" id="settings_new_password" class="input-field" placeholder="留空则不修改">
          </div>
        </div>
        
        <div style="margin-bottom: 24px;">
          <div style="font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-secondary); font-weight: 600; margin-bottom: 12px;">安全验证 (必须输入当前账号密码)</div>
          
          <div class="form-group" style="margin-bottom: 12px;">
            <label class="form-label" for="settings_curr_username">当前管理账号</label>
            <input type="text" id="settings_curr_username" class="input-field" required placeholder="请输入当前管理账号">
          </div>
          
          <div class="form-group">
            <label class="form-label" for="settings_curr_password">当前安全密码</label>
            <input type="password" id="settings_curr_password" class="input-field" required placeholder="请输入当前安全密码">
          </div>
        </div>
        
        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button type="button" onclick="closeSettingsModal()" style="height: 40px; padding: 0 16px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">取消</button>
          <button type="submit" id="settings_submit_btn" class="btn-primary" style="height: 40px; padding: 0 20px; font-weight: 600; border-radius: 8px;">保存修改</button>
        </div>
      </form>
    </div>
  </div>
</main>
<script>
let nodes=[], state={}, testingNodeIds = new Set();
let currentPage = 1;
const pageSize = 11;
let currentPageNodes = [];

const $=id=>document.getElementById(id);
const esc=s=>String(s||"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));
const base=p=>(p||"").split(/[\\/]/).pop();
function time(ts){return ts?new Date(ts*1000).toLocaleString():"从未"}
function speed(v){return v?`${(v*8/1000/1000).toFixed(1)} Mbps`:"-"}

const translateQuality = q => {
  const dict = {"clean_residential": "干净住宅", "normal": "普通", "proxy": "代理", "datacenter": "数据中心", "mobile": "移动端", "risky": "高风险"};
  return dict[q] || q || "-";
};

const translateIpType = t => {
  const dict = {"residential": "住宅 IP", "hosting": "机房 IP", "mobile": "移动网", "proxy": "代理 IP", "tor": "Tor 出口"};
  return dict[t] || t || "-";
};

const translateRiskLevel = r => {
  const dict = {"clean": "干净", "low": "低风险", "medium": "中风险", "high": "高风险", "unknown": "未检测"};
  return dict[r] || r || "未检测";
};

function isCleanNode(n) {
  if (state.allow_risky_ip_connect) return true;
  const riskLevel = String(n.risk_level || "unknown").toLowerCase();
  const ipType = String(n.ip_type || "").toLowerCase();
  const fraudScore = Number(n.fraud_score ?? 100);
  const maxScore = Number(state.max_auto_fraud_score ?? 25);
  const blacklistCount = Number(n.blacklist_count || 0);
  if (riskLevel === "unknown" || !n.risk_sources) return false;
  if (blacklistCount > 0) return false;
  if (fraudScore > maxScore) return false;
  if (["medium", "high", "blocked"].includes(riskLevel)) return false;
  if (["proxy", "hosting", "tor"].includes(ipType)) return false;
  return true;
}

function riskBadge(n) {
  const score = Number(n.fraud_score ?? 0);
  const clean = Number(n.clean_score ?? Math.max(0, 100 - score));
  const level = String(n.risk_level || "unknown").toLowerCase();
  const hits = Number(n.blacklist_count || 0);
  const title = [
    `风险等级: ${translateRiskLevel(level)}`,
    `干净度: ${clean}`,
    `欺诈值: ${score}`,
    `检测源: ${(n.risk_sources || []).join(", ") || "未检测"}`,
    `风险标记: ${(n.fraud_flags || []).join(", ") || "无"}`
  ].join("\n");
  let cls = "not_checked";
  if (hits > 0 || level === "high") cls = "unavailable";
  else if (level === "clean") cls = "available";
  else if (level === "low") cls = "not_checked";
  else if (level === "medium") cls = "unavailable";
  return `<span class="badge ${cls}" title="${esc(title)}">${score}</span>`;
}

const translateCountry = c => {
  const dict = {
    "Japan": "日本",
    "Korea Republic of": "韩国",
    "Korea": "韩国",
    "Republic of Korea": "韩国",
    "Thailand": "泰国",
    "United States": "美国",
    "United Kingdom": "英国",
    "Russian Federation": "俄罗斯",
    "Russian": "俄罗斯",
    "Viet Nam": "越南",
    "Vietnam": "越南",
    "China": "中国",
    "Taiwan": "台湾",
    "Taiwan Province of China": "台湾",
    "Hong Kong": "香港",
    "Singapore": "新加坡",
    "Malaysia": "马来西亚",
    "Indonesia": "印度尼西亚",
    "India": "印度",
    "Philippines": "菲律宾",
    "Australia": "澳大利亚",
    "New Zealand": "新西兰",
    "Canada": "加拿大",
    "Ukraine": "乌克兰",
    "France": "法国",
    "Germany": "德国",
    "Netherlands": "荷兰",
    "Sweden": "瑞典",
    "Norway": "挪威",
    "Spain": "西班牙",
    "Turkey": "土耳其",
    "South Africa": "南非",
    "Brazil": "巴西",
    "Argentina": "阿根廷",
    "Chile": "智利",
    "Mexico": "墨西哥",
    "Egypt": "埃及",
    "Romania": "罗马尼亚",
    "Poland": "波兰",
    "Kazakhstan": "哈萨克斯坦",
    "Georgia": "格鲁吉亚",
    "Mongolia": "蒙古",
    "Saudi Arabia": "沙特阿拉伯",
    "Iran": "伊朗",
    "Iraq": "伊拉克",
    "Colombia": "哥伦比亚",
    "Cambodia": "柬埔寨",
    "Ireland": "爱尔兰",
    "Italy": "意大利",
    "Switzerland": "瑞士",
    "Belgium": "比利时",
    "Austria": "奥地利",
    "Denmark": "丹麦",
    "Finland": "芬兰",
    "Portugal": "葡萄牙",
    "Greece": "希腊",
    "Czech Republic": "捷克",
    "Hungary": "匈牙利",
    "Israel": "以色列",
    "United Arab Emirates": "阿联酋",
    "UAE": "阿联酋",
    "Macao": "澳门",
    "Macau": "澳门",
    "Iceland": "冰岛",
    "Luxembourg": "卢森堡"
  };
  return dict[c] || c || "-";
};

const translateStatus = s => {
  const dict = {"available": "可用", "unavailable": "不可用", "not_checked": "待检测"};
  return dict[s] || s || "待检测";
};

function getLatencyClass(ms) {
  if (!ms) return '';
  if (ms < 50) return 'latency-good';
  if (ms < 150) return 'latency-medium';
  return 'latency-poor';
}

function updateCountryFilter() {
  const select = $("country_filter");
  const selectedValue = select.value;
  const countries = Array.from(new Set(nodes.map(n => n.country).filter(Boolean))).sort();
  
  const currentOptions = Array.from(select.options).map(o => o.value).filter(Boolean);
  if (JSON.stringify(countries) === JSON.stringify(currentOptions)) {
    return;
  }
  
  select.innerHTML = '<option value="">所有国家</option>' + 
    countries.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join("");
  
  if (countries.includes(selectedValue)) {
    select.value = selectedValue;
  } else {
    select.value = "";
  }
}

function canonicalIpType(v) {
  const raw = String(v || "").toLowerCase().replace(/[\s-]+/g, "_");
  if (["clean_residential", "residential", "home", "isp", "住宅", "家宽"].includes(raw)) return "residential";
  if (["mobile", "移动"].includes(raw)) return "mobile";
  if (["hosting", "datacenter", "data_center", "dc", "vps", "cloud", "机房", "数据中心"].includes(raw)) return "hosting";
  if (["proxy", "vpn", "代理"].includes(raw)) return "proxy";
  if (["tor"].includes(raw)) return "tor";
  return "normal";
}

function getFilteredNodes() {
  const q = $("search").value.toLowerCase();
  const selectedCountry = $("country_filter").value;
  const selectedIpType = $("ip_type_filter").value;
  return nodes.filter(n => {
    if (selectedCountry && n.country !== selectedCountry) {
      return false;
    }
    if (selectedIpType && ![canonicalIpType(n.ip_type), canonicalIpType(n.quality)].includes(selectedIpType)) {
      return false;
    }
    const searchStr = [
      n.country, n.country_short, n.ip, n.remote_host, n.proto,
      translateQuality(n.quality), translateIpType(n.ip_type), translateRiskLevel(n.risk_level),
      n.source, n.location, n.owner, n.as_name, n.fraud_score, n.clean_score,
      (n.fraud_flags || []).join(" "), (n.blacklist_hits || []).join(" ")
    ].join(" ").toLowerCase();
    return searchStr.includes(q);
  });
}

function stableSortNodes() {
  nodes.sort((a, b) => {
    if ((b.score || 0) !== (a.score || 0)) {
      return (b.score || 0) - (a.score || 0);
    }
    return a.id.localeCompare(b.id);
  });
}

function render(){
  const activeNodeId = state.active_openvpn_node_id;
  const activeNode = nodes.find(n => n.active || n.id === activeNodeId);
  
  // Render separated Active Node Card
  const activeCardContainer = $("active_node_card");
  if (state.is_connecting) {
    activeCardContainer.innerHTML = `
      <div class="active-card" style="background: var(--bg-surface); border-color: var(--warning); box-shadow: 0 0 15px rgba(245, 158, 11, 0.15);">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(245, 158, 11, 0.15); border-color: rgba(245, 158, 11, 0.3); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: #f59e0b; width: 24px; height: 24px; animation: spin 2s linear infinite;"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title" style="color: var(--text-primary);">
              <span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; border-color: rgba(245, 158, 11, 0.3);"><span class="badge-pulse" style="background: #f59e0b;"></span>正在连接</span>
              <strong>${esc(state.active_node_latency || '正在连接...')}</strong>
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              ${esc(state.last_check_message || '正在与 VPN 节点建立加密隧道，请稍候...')}
            </div>
          </div>
        </div>
      </div>
    `;
  } else if (activeNode) {
    const latencyClass = getLatencyClass(activeNode.latency_ms);
    const latencyText = activeNode.latency_ms ? `<span class="latency-val ${latencyClass}">${activeNode.latency_ms} ms</span>` : "-";
    const displayLocation = activeNode.location || translateCountry(activeNode.country) || "-";
    activeCardContainer.innerHTML = `
      <div class="active-card">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(16, 185, 129, 0.15); border-color: rgba(16, 185, 129, 0.3); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: #34d399; width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title">
              <span class="badge available"><span class="badge-pulse"></span>已连接</span>
              <strong>${esc(translateCountry(activeNode.country))} 节点</strong>
            </div>
            <div class="active-card-value mono" style="font-size: 20px; margin-top: 2px;">
              ${esc(activeNode.ip || activeNode.remote_host)}:${activeNode.remote_port || ""}
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              <span>物理位置: <strong>${esc(displayLocation)}</strong></span>
              <span style="margin-left: 12px;">延时: <strong>${latencyText}</strong></span>
              <span style="margin-left: 12px;">运营主体: <strong>${esc(activeNode.owner || activeNode.as_name || "-")}</strong></span>
              <span style="margin-left: 12px;">IP 类型: <strong>${esc(translateIpType(activeNode.ip_type))}</strong></span>
              <span style="margin-left: 12px;">风控: <strong>${esc(translateRiskLevel(activeNode.risk_level))}</strong> / 欺诈值 <strong>${esc(activeNode.fraud_score ?? "-")}</strong></span>
            </div>
          </div>
        </div>
        <button class="btn-danger" style="height: 38px; padding: 0 16px; border-radius: 8px;" onclick="disconnectNode()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
          断开连接
        </button>
      </div>
    `;
  } else {
    activeCardContainer.innerHTML = `
      <div class="active-card" style="background: var(--bg-surface); border-color: var(--border-color); box-shadow: none;">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(244, 63, 94, 0.1); border-color: rgba(244, 63, 94, 0.2); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: var(--danger); width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title" style="color: var(--text-secondary);">
              <span class="badge unavailable" style="padding: 2px 8px;">未连接</span> 当前未连接 VPN 节点
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              在下方列表中选择一个可用备用节点并点击 “切换” 按钮开始连接。
            </div>
          </div>
        </div>
      </div>
    `;
  }

  const shown = getFilteredNodes();
  
  $("total").textContent=nodes.length; 
  $("target").textContent=state.target_valid_nodes||3;
  $("active").textContent=activeNode?1:0; 
  
  const statusMessage = state.last_check_message || "";
  const activeNodeInfo = activeNode ? `<span class="badge available" style="margin-left:8px; padding:2px 8px;">${esc(translateCountry(activeNode.country))} (${activeNode.id})</span>` : `<span class="badge unavailable" style="margin-left:8px; padding:2px 8px;">无</span>`;
  const targetInfo = state.target_countries_display || state.target_countries || "全部地区";
  const ipTypeInfo = state.target_ip_types_display || "住宅IP";
  const failoverInfo = state.failover_country_display || targetInfo || "未固定";
  const sourceInfo = state.node_sources_display || state.node_sources || "VPNGate + VPNBook";
  $("status").innerHTML=`<span class="status-dot"></span>HTTP 代理本地接口：http://127.0.0.1:7928 | 来源：${esc(sourceInfo)} | 拉取地区：${esc(targetInfo)} | 自动IP优先级：${esc(ipTypeInfo)} | 故障转移地区：${esc(failoverInfo)} | 活动节点：${activeNodeInfo} | 状态：${statusMessage}`;
  
  // Update proxy test status card based on background checks
  const pBadge = $("proxy_status_badge");
  const pIpVal = $("proxy_ip_val");
  const pLatVal = $("proxy_latency_val");
  const pBtn = $("btn_test_proxy");
  
  if (state.is_connecting) {
    pBadge.className = "badge";
    pBadge.style.background = "rgba(245, 158, 11, 0.15)";
    pBadge.style.color = "#f59e0b";
    pBadge.style.borderColor = "rgba(245, 158, 11, 0.3)";
    pBadge.innerHTML = `<span class="badge-pulse" style="background: #f59e0b;"></span>正在连接`;
    pIpVal.textContent = state.active_node_latency || "正在连接...";
    pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message || "正在与 VPN 节点建立加密隧道，请稍候...")}</span>`;
    pBtn.disabled = true;
    pBtn.style.opacity = "0.5";
    pBtn.style.cursor = "not-allowed";
  } else {
    pBtn.disabled = false;
    pBtn.style.opacity = "";
    pBtn.style.cursor = "";
    pBadge.style.background = "";
    pBadge.style.color = "";
    pBadge.style.borderColor = "";
    if (state.proxy_ok !== undefined) {
      if (state.proxy_ok) {
        pBadge.className = "badge available";
        pBadge.textContent = "可用";
        pIpVal.textContent = state.proxy_ip || "-";
        const latencyClass = getLatencyClass(state.proxy_latency_ms);
        pLatVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${state.proxy_latency_ms} ms</span>`;
      } else {
        pBadge.className = "badge unavailable";
        pBadge.textContent = "不可用";
        pIpVal.textContent = "-";
        if (state.last_check_message) {
          pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message)}</span>`;
        } else {
          pLatVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;" title="${esc(state.proxy_error)}">${esc(state.proxy_error || "连接失败")}</span>`;
        }
      }
    } else {
      pBadge.className = "badge not_checked";
      pBadge.textContent = "未检测";
      pIpVal.textContent = "-";
      if (state.last_check_message) {
        pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message)}</span>`;
      } else {
        pLatVal.innerHTML = "";
      }
    }
  }

  // Pagination calculation
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  if (currentPage > totalPages) currentPage = totalPages;
  if (currentPage < 1) currentPage = 1;
  
  const startIndex = (currentPage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, shown.length);
  currentPageNodes = shown.slice(startIndex, endIndex);

  // Render table rows
  if (currentPageNodes.length === 0) {
    $("rows").innerHTML = `<tr><td colspan="11" style="text-align: center; color: var(--text-secondary); padding: 40px 0;">未找到符合过滤条件的备选节点。</td></tr>`;
  } else {
    $("rows").innerHTML=currentPageNodes.map(n=>{
      const isCurrentlyActive = activeNode && n.id === activeNode.id;
      const rowClass = isCurrentlyActive ? 'class="active-row"' : '';
      
      const badgeClass = isCurrentlyActive ? 'available' : (n.probe_status || 'not_checked');
      const badgeText = isCurrentlyActive ? '<span class="badge-pulse"></span>已连接' : translateStatus(n.probe_status);
      const latencyClass = getLatencyClass(n.latency_ms);
      const latencyText = n.latency_ms ? `<span class="latency-val ${latencyClass}">${n.latency_ms} ms</span>` : "-";
      const displayLocation = n.location || translateCountry(n.country) || "-";
      
      const isTesting = testingNodeIds.has(n.id);
      const testSpinner = `<svg style="animation: spin 1s linear infinite; width: 12px; height: 12px; display: inline-block; margin-right: 4px; vertical-align: middle;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>`;
      const testBtnText = isTesting ? `${testSpinner}检测中` : '检测';
      const testBtn = `<button class="test-btn" data-node-id="${esc(n.id)}" ${isTesting ? 'disabled' : ''} onclick="testNode(this, '${esc(n.id)}', event)">${testBtnText}</button>`;
      
      // Always keep the manual switch button visible.
      // If the node has not been tested, clicking "切换" will guide the user to run detection first.
      const isUnavailable = n.probe_status === "unavailable";
      const riskSources = Array.isArray(n.risk_sources) ? n.risk_sources : [];
      const riskLevel = String(n.risk_level || "unknown").toLowerCase();
      const isUnknown = n.probe_status !== "available" || riskLevel === "unknown" || riskSources.length === 0;
      const cleanOk = isCleanNode(n);
      let switchTitle = "切换到该节点";
      if (state.is_connecting) switchTitle = "当前正在连接其它节点，请稍候";
      else if (isUnavailable) switchTitle = "该节点当前检测为不可用，可先重新检测";
      else if (isUnknown) switchTitle = "该节点尚未完成可用性和 IP 风控检测，点击后可先检测再切换";
      else if (!cleanOk) switchTitle = `IP 风控未通过：${translateRiskLevel(n.risk_level)}，欺诈值 ${n.fraud_score ?? "未知"}，黑名单 ${n.blacklist_count || 0}；手动确认后仍可尝试`;
      const connectBtn = isCurrentlyActive 
        ? `<button class="connect-btn" disabled style="background: var(--success-gradient); color: white; cursor: default; opacity: 1;">已连接</button>`
        : `<button class="connect-btn" title="${esc(switchTitle)}" ${state.is_connecting ? 'disabled style="opacity:0.45; cursor:not-allowed;"' : ''} onclick="handleSwitchClick('${esc(n.id)}')">切换</button>`;
      
      return `<tr ${rowClass}>
        <td><span class="badge ${badgeClass}">${badgeText}</span></td>
        <td>${latencyText}</td>
        <td class="mono">${esc(n.ip||n.remote_host)}:${n.remote_port||""}<br><span style="font-size:11px; color:var(--text-secondary);">来源：${esc((n.source || "vpngate").toUpperCase())}</span></td>
        <td>${esc(displayLocation)}</td>
        <td class="mono" style="font-size:12px; color:var(--text-secondary);">${esc(n.asn||"-")}</td>
        <td>${esc(n.owner||n.as_name||"-")}</td>
        <td>${esc(translateQuality(n.quality))}</td>
        <td>${esc(translateIpType(n.ip_type))}</td>
        <td>${riskBadge(n)}</td>
        <td><span class="badge ${Number(n.blacklist_count || 0) > 0 ? 'unavailable' : (n.risk_level === 'unknown' ? 'not_checked' : 'available')}" title="${esc((n.blacklist_hits || []).join(', ') || '无命中')}">${Number(n.blacklist_count || 0) > 0 ? '命中 ' + Number(n.blacklist_count || 0) : (n.risk_level === 'unknown' ? '未检' : '干净')}</span></td>
        <td>
          <div class="table-actions">
            ${testBtn}
            ${connectBtn}
          </div>
        </td>
      </tr>`;
    }).join("");
  }

  // Render pagination controls
  $("page_start").textContent = shown.length > 0 ? startIndex + 1 : 0;
  $("page_end").textContent = endIndex;
  $("filtered_count").textContent = shown.length;
  $("current_page_val").textContent = currentPage;
  $("total_pages_val").textContent = totalPages;
  
  $("btn_first_page").disabled = currentPage === 1;
  $("btn_prev_page").disabled = currentPage === 1;
  $("btn_next_page").disabled = currentPage === totalPages;
  $("btn_last_page").disabled = currentPage === totalPages;
}

// Hook up page buttons events
$("btn_first_page").onclick = () => { currentPage = 1; render(); };
$("btn_prev_page").onclick = () => { if (currentPage > 1) { currentPage--; render(); } };
$("btn_next_page").onclick = () => {
  const shown = getFilteredNodes();
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  if (currentPage < totalPages) { currentPage++; render(); }
};
$("btn_last_page").onclick = () => {
  const shown = getFilteredNodes();
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  currentPage = totalPages;
  render();
};

async function testNode(btn, id, event, options){
  if (event) event.stopPropagation();
  const opts = options || {};
  testingNodeIds.add(id);
  render();
  let updatedNode = null;
  
  try {
    const response = await fetch("./api/test_node", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id })
    });
    const result = await response.json();
    if (result.ok && result.node) {
      const idx = nodes.findIndex(n => n.id === id);
      if (idx !== -1) {
        nodes[idx] = result.node;
      }
      updatedNode = result.node;
    } else if (!opts.quiet) {
      alert("检测失败: " + (result.error || "未知错误"));
    }
  } catch (e) {
    if (!opts.quiet) alert("检测请求失败，请稍后重试");
  } finally {
    testingNodeIds.delete(id);
    render();
  }
  return updatedNode || nodes.find(n => n.id === id) || null;
}

function switchBlockReason(n) {
  if (!n) return "节点不存在";
  const riskLevel = String(n.risk_level || "unknown").toLowerCase();
  const riskSources = Array.isArray(n.risk_sources) ? n.risk_sources : [];
  if (n.probe_status !== "available") return "该节点还没有通过 OpenVPN 可用性检测";
  if (riskLevel === "unknown" || riskSources.length === 0) return "该节点还没有完成 IP 风控检测";
  if (Number(n.blacklist_count || 0) > 0) return `黑名单命中 ${n.blacklist_count || 0} 个: ${(n.blacklist_hits || []).join(", ")}`;
  if (Number(n.fraud_score ?? 100) > Number(state.max_auto_fraud_score ?? 25)) return `欺诈值 ${n.fraud_score ?? "未知"} 高于阈值 ${state.max_auto_fraud_score ?? 25}`;
  if (["medium", "high", "blocked"].includes(riskLevel)) return `风险等级为 ${translateRiskLevel(riskLevel)}`;
  if (["proxy", "hosting", "tor"].includes(String(n.ip_type || "").toLowerCase())) return `IP 类型为 ${translateIpType(n.ip_type)}，风险较高，自动切换会把它放在最后兜底`;
  return "";
}

async function handleSwitchClick(id) {
  if (state.is_connecting) return;
  let n = nodes.find(item => item.id === id);
  if (!n) {
    alert("节点不存在或列表已刷新，请重新加载后再试");
    return;
  }
  if (n.active || n.id === state.active_openvpn_node_id) return;

  const riskLevel = String(n.risk_level || "unknown").toLowerCase();
  const riskSources = Array.isArray(n.risk_sources) ? n.risk_sources : [];
  const needDetect = n.probe_status !== "available" || riskLevel === "unknown" || riskSources.length === 0;

  // 免费节点质量波动较大：检测与风控用于“自动优选”，但手动切换不做硬拦截。
  // 点确定 = 先检测再判断；点取消 = 直接尝试手动强制切换。
  if (n.probe_status === "unavailable") {
    const retry = confirm("该节点上次检测为不可用。\n\n点“确定”：重新检测，检测后再切换。\n点“取消”：不检测，直接尝试手动切换。\n\n节点: " + (n.ip || n.remote_host));
    if (retry) {
      n = await testNode(null, id, null, {quiet: false});
      if (!n) return;
    } else {
      connectNode(id, true);
      return;
    }
  } else if (needDetect) {
    const runDetect = confirm("该节点尚未完成可用性/IP 风控检测。\n\n点“确定”：先检测，检测后自动决定是否建议。\n点“取消”：跳过检测，直接尝试手动切换。");
    if (runDetect) {
      n = await testNode(null, id, null, {quiet: false});
      if (!n) return;
    } else {
      connectNode(id, true);
      return;
    }
  }

  if (!isCleanNode(n)) {
    const reason = switchBlockReason(n) || "该节点不符合自动优选规则";
    const force = confirm(
      "该节点不符合自动优选/干净 IP 规则：\n" + reason +
      "\n\n说明：自动故障转移仍会优先选择低风险、低欺诈值、无黑名单节点。" +
      "\n但免费 VPNGate 节点质量参差不齐，你可以手动强制尝试。" +
      "\n\n是否仍然手动切换到这个节点？"
    );
    if (!force) return;
    connectNode(id, true);
    return;
  }

  connectNode(id, false);
}

let pollInterval = null;

function startConnectionPolling() {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(async () => {
    try {
      const resp = await fetch("./api/nodes");
      const data = await resp.json();
      nodes = data.nodes || [];
      state = data.state || {};
      stableSortNodes();
      render();
      
      if (!state.is_connecting) {
        clearInterval(pollInterval);
        pollInterval = null;
        try {
          await fetch("./api/test_proxy", { method: "POST" });
        } catch(pe){}
        load();
      }
    } catch(pe) {
      clearInterval(pollInterval);
      pollInterval = null;
      load();
    }
  }, 1000);
}

async function connectNode(id, allowRisky){
  allowRisky = !!allowRisky;
  state.is_connecting = true;
  state.active_openvpn_node_id = id;
  state.active_node_latency = "正在连接";
  state.last_check_message = "正在发送连接请求...";
  render();
  
  startConnectionPolling();
  
  try {
    const r = await fetch("./api/connect",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({id, allow_risky: allowRisky})
    });
    const result = await r.json();
    if (!result.ok) {
      alert("连接失败: " + (result.error || "未知错误"));
      if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
      }
      state.is_connecting = false;
      render();
      return;
    }
  } catch(e) {
    alert("连接请求错误");
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
    state.is_connecting = false;
    render();
  }
}

async function disconnectNode(){
  if (!confirm("确定要断开当前的 VPN 连接吗？")) return;
  try {
    const response = await fetch("./api/disconnect", { method: "POST" });
    const result = await response.json();
    if (result.ok) {
      try {
        await fetch("./api/test_proxy", { method: "POST" });
      } catch(pe){}
      load();
    } else {
      alert("断开连接失败: " + (result.error || "未知错误"));
    }
  } catch (e) {
    alert("请求断开连接失败");
  }
}

// Batch test button implementation
$("btn_batch_test").onclick = async () => {
  const pageNodes = currentPageNodes || [];
  if (pageNodes.length === 0) {
    alert("当前页面没有可供测试的备选节点");
    return;
  }
  
  const btn = $("btn_batch_test");
  btn.disabled = true;
  btn.innerHTML = `<svg style="animation: spin 1s linear infinite; width: 14px; height: 14px; display: inline-block; margin-right: 6px; vertical-align: middle;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>测试中...`;
  
  pageNodes.forEach(n => testingNodeIds.add(n.id));
  render();
  
  const testPromises = pageNodes.map(async (n) => {
    const id = n.id;
    try {
      const response = await fetch("./api/test_node", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id })
      });
      const result = await response.json();
      if (result.ok && result.node) {
        const idx = nodes.findIndex(item => item.id === id);
        if (idx !== -1) {
          nodes[idx] = result.node;
        }
      }
    } catch (e) {
    } finally {
      testingNodeIds.delete(id);
      render();
    }
  });
  
  try {
    await Promise.all(testPromises);
  } catch (e) {
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg> 批量测试本页`;
  }
};

function setPageLoading(text, percent, step) {
  const box = $("page_loading");
  const desc = $("page_loading_desc");
  const bar = $("page_loading_bar");
  const pct = $("page_loading_percent");
  const stepEl = $("page_loading_step");
  if (!box || !desc || !bar || !pct || !stepEl) return;
  box.style.display = "flex";
  desc.textContent = text;
  bar.style.width = `${percent}%`;
  pct.textContent = `${percent}%`;
  stepEl.textContent = step || "加载中";
}

function hidePageLoading() {
  const box = $("page_loading");
  if (box) box.style.display = "none";
}

async function load(){
  setPageLoading("正在连接后端服务...", 20, "连接服务");
  try {
    const r=await fetch("./api/nodes");
    setPageLoading("正在读取节点池和系统状态...", 55, "读取数据");
    const d=await r.json();
    nodes=d.nodes||[];
    state=d.state||{};
    setPageLoading("正在渲染控制面板...", 82, "渲染页面");
    stableSortNodes();
    updateCountryFilter();
    render();

    if (state.is_connecting) {
      setPageLoading("后端正在连接节点，面板将持续刷新状态...", 95, "连接节点");
      startConnectionPolling();
    } else {
      setPageLoading("加载完成", 100, "完成");
    }
    setTimeout(hidePageLoading, 350);
  } catch (e) {
    setPageLoading("面板加载失败：无法连接后端接口。请稍后刷新，或使用 en logs 查看服务日志。", 100, "加载失败");
    console.error(e);
  }
}

$("search").oninput=()=>{ currentPage = 1; render(); };
$("country_filter").onchange=()=>{ currentPage = 1; render(); };
$("ip_type_filter").onchange=()=>{ currentPage = 1; render(); };

$("refresh").onclick=async()=>{ 
  $("refresh").disabled=true; 
  $("refresh").textContent="正在后台更新..."; 
  try{await fetch("./api/refresh_nodes",{method:"POST"}); await load();} 
  catch(e){}
  setTimeout(()=>{
    $("refresh").disabled=false; 
    $("refresh").textContent="更新节点";
  }, 3000);
};
$("check").onclick=async()=>{ 
  $("check").disabled=true; 
  $("check").textContent="检测中..."; 
  try{await fetch("./api/check",{method:"POST"}); await load();} 
  finally{$("check").disabled=false; $("check").textContent="立即检测补齐";}
};
$("btn_test_proxy").onclick = async () => {
  const btn = $("btn_test_proxy");
  const badge = $("proxy_status_badge");
  const ipVal = $("proxy_ip_val");
  const latVal = $("proxy_latency_val");
  
  btn.disabled = true;
  btn.innerHTML = `<span class="badge-pulse"></span>测试中...`;
  badge.className = "badge not_checked";
  badge.textContent = "检测中...";
  ipVal.textContent = "-";
  latVal.textContent = "";
  
  try {
    const response = await fetch("./api/test_proxy", { method: "POST" });
    const result = await response.json();
    if (result.ok) {
      badge.className = "badge available";
      badge.textContent = "可用";
      ipVal.textContent = result.ip || "-";
      
      const latencyClass = getLatencyClass(result.latency_ms);
      latVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${result.latency_ms} ms</span>`;
    } else {
      badge.className = "badge unavailable";
      badge.textContent = "不可用";
      ipVal.textContent = "-";
      latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;" title="${esc(result.error)}">连接失败</span>`;
    }
  } catch (e) {
    badge.className = "badge unavailable";
    badge.textContent = "网络错误";
    ipVal.textContent = "-";
    latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;">请求出错</span>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg> 测试代理`;
  }
};

// Admin dropdown toggle
const adminBtn = $("admin_btn");
const adminDropdown = $("admin_dropdown");
if (adminBtn && adminDropdown) {
  adminBtn.onclick = (e) => {
    e.stopPropagation();
    const isShow = adminDropdown.style.display === "block";
    adminDropdown.style.display = isShow ? "none" : "block";
  };
  document.addEventListener("click", () => {
    adminDropdown.style.display = "none";
  });
}

function openSettingsModal() {
  $("settings_error").style.display = "none";
  $("settings_success").style.display = "none";
  $("settings_form").reset();
  
  if (state) {
    $("settings_port").value = state.port || 8787;
    $("settings_suffix").value = state.secret_path || "EJsW2EeBo9lY";
    $("settings_target_countries").value = state.target_countries || "";
    $("settings_node_sources").value = state.node_sources || "vpngate,vpnbook";
    const ipTypeValue = state.target_ip_types || "residential";
    const legacyIpTypeMap = {
      "residential,mobile": "residential",
      "residential,normal,mobile": "residential"
    };
    $("settings_target_ip_types").value = legacyIpTypeMap[ipTypeValue] || ipTypeValue;
    $("settings_auto_select_best_node").value = state.auto_select_best_node ? "1" : "0";
  }
  
  $("settings_modal").style.display = "flex";
  $("admin_dropdown").style.display = "none";
}

function closeSettingsModal() {
  $("settings_modal").style.display = "none";
}

async function saveSettings(e) {
  e.preventDefault();
  const errorDivEl = $("settings_error");
  const successDiv = $("settings_success");
  const submitBtn = $("settings_submit_btn");
  
  errorDivEl.style.display = "none";
  successDiv.style.display = "none";
  
  const port = parseInt($("settings_port").value);
  const suffix = $("settings_suffix").value.trim();
  const targetCountries = $("settings_target_countries").value.trim();
  const nodeSources = $("settings_node_sources").value.trim();
  const targetIpTypes = $("settings_target_ip_types").value.trim();
  const autoSelectBestNode = $("settings_auto_select_best_node").value === "1";
  const newUsername = $("settings_new_username").value.trim();
  const newPassword = $("settings_new_password").value.trim();
  const currUsername = $("settings_curr_username").value.trim();
  const currPassword = $("settings_curr_password").value.trim();
  
  if (isNaN(port) || port < 1 || port > 65535) {
    errorDivEl.textContent = "端口范围必须在 1 至 65535 之间";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (!/^[A-Za-z0-9]+$/.test(suffix)) {
    errorDivEl.textContent = "登录安全后缀仅能由英文字母和数字组成";
    errorDivEl.style.display = "block";
    return;
  }
  
  submitBtn.disabled = true;
  submitBtn.textContent = "正在保存...";
  
  try {
    const res = await fetch("./api/update_settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        port: port,
        secret_path: suffix,
        target_countries: targetCountries,
        node_sources: nodeSources,
        target_ip_types: targetIpTypes,
        auto_select_best_node: autoSelectBestNode,
        new_username: newUsername,
        new_password: newPassword,
        curr_username: currUsername,
        curr_password: currPassword
      })
    });
    
    const data = await res.json();
    if (res.ok && data.ok) {
      successDiv.textContent = "保存成功！页面将在 4 秒内自动跳转至新地址...";
      successDiv.style.display = "block";
      
      const inputs = $("settings_form").querySelectorAll("input, select, button");
      inputs.forEach(el => el.disabled = true);
      
      setTimeout(() => {
        const protocol = window.location.protocol;
        const host = window.location.hostname;
        window.location.href = `${protocol}//${host}:${port}/${suffix}/`;
      }, 4000);
    } else {
      errorDivEl.textContent = data.error || "保存失败，请检查输入";
      errorDivEl.style.display = "block";
      submitBtn.disabled = false;
      submitBtn.textContent = "保存修改";
    }
  } catch (err) {
    errorDivEl.textContent = "连接服务器失败，请稍后重试";
    errorDivEl.style.display = "block";
    submitBtn.disabled = false;
    submitBtn.textContent = "保存修改";
  }
}

async function logoutAdmin() {
  try {
    const res = await fetch("./api/logout", { method: "POST" });
    if (res.ok) {
      window.location.reload();
    }
  } catch (err) {
    console.error("退出登录失败", err);
    window.location.reload();
  }
}

// 页面加载时自动初始化数据
load();

// 每 10 秒在前台空闲时自动更新节点与状态，无需手动刷新页面
setInterval(async () => {
  if (typeof state !== "undefined" && (!testingNodeIds || !testingNodeIds.size) && document.visibilityState === "visible") {
    try {
      const r = await fetch("./api/nodes");
      const d = await r.json();
      nodes = d.nodes || [];
      state = d.state || {};
      stableSortNodes();
      render();
    } catch(e) {}
  }
}, 10000);
</script>
</body></html>"""

def check_proxy_health() -> dict[str, Any]:
    # 1. 检测代理服务端口是否在监听
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.5)
    try:
        s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
        s.close()
    except Exception as e:
        return {
            "ok": False,
            "error": f"代理服务未运行 (端口 {LOCAL_PROXY_PORT} 连接失败，原因: {e})"
        }

    # 2. 检测虚拟网卡 tun0 是否存在 (Linux 下)
    tun_path = Path("/sys/class/net/tun0")
    if sys.platform.startswith("linux") and not tun_path.exists():
        return {
            "ok": False,
            "error": "VPN 虚拟网卡 (tun0) 未启用，请确保当前已成功连接 VPN 节点"
        }

    # 3. 使用 curl 通过本地 SOCKS5 代理接口测试 IP 与实际延迟
    cmd = [
        "curl", "-4", "-s",
        "-w", "\n%{time_total} %{http_code}",
        "-x", f"socks5h://127.0.0.1:{LOCAL_PROXY_PORT}",
        "http://ip.sb",
        "--max-time", "5"
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
        if res.returncode == 0:
            lines = res.stdout.strip().splitlines()
            if len(lines) >= 2:
                ip = lines[0].strip()
                time_info = lines[1].strip().split()
                if len(time_info) == 2:
                    total_time_str, http_code = time_info
                    if http_code == "200" and ip:
                        latency_ms = int(float(total_time_str) * 1000)
                        return {"ok": True, "ip": ip, "latency_ms": latency_ms}
        
        # 如果 ip.sb 失败，使用备用地址 http://api.ipify.org
        cmd[7] = "http://api.ipify.org"
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
        if res.returncode == 0:
            lines = res.stdout.strip().splitlines()
            if len(lines) >= 2:
                ip = lines[0].strip()
                time_info = lines[1].strip().split()
                if len(time_info) == 2:
                    total_time_str, http_code = time_info
                    if http_code == "200" and ip:
                        latency_ms = int(float(total_time_str) * 1000)
                        return {"ok": True, "ip": ip, "latency_ms": latency_ms}
                        
        return {"ok": False, "error": f"出口连接测试失败 (curl 返回码: {res.returncode}, stderr: {res.stderr.strip()})"}
    except Exception as e:
        return {"ok": False, "error": f"出口连接测试异常: {e}"}

def background_proxy_checker() -> None:
    time.sleep(2)
    while True:
        try:
            if is_connecting:
                time.sleep(5)
                continue

            res = check_proxy_health()
            if res["ok"]:
                set_state(
                    proxy_ok=True,
                    proxy_ip=res["ip"],
                    proxy_latency_ms=res["latency_ms"],
                    proxy_error=""
                )
                log_to_json("INFO", "Proxy", f"代理可用，IP: {res['ip']}, 延迟: {res['latency_ms']} ms")
            else:
                error_msg = res.get("error", "未知错误")
                if active_openvpn_node_id:
                    print(f"[警告] 7928 端口本地代理当前不可用！原因: {error_msg}", flush=True)
                    log_to_json("WARNING", "Proxy", f"代理不可用: {error_msg}")
                set_state(
                    proxy_ok=False,
                    proxy_ip="-",
                    proxy_latency_ms=0,
                    proxy_error=error_msg
                )

                # If we intended to have an active VPN node but proxy failed, trigger auto-switch
                if active_openvpn_node_id:
                    with lock:
                        nodes = read_json(NODES_FILE, [])
                        active_node = next((n for n in nodes if n.get("id") == active_openvpn_node_id), None)
                        if active_node:
                            mark_blacklisted(active_node, f"代理连通性检测失败: {error_msg}")
                            active_node["probe_status"] = "unavailable"
                            write_json(NODES_FILE, nodes)
                    
                    auto_switch_node()
        except Exception as e:
            print(f"[错误] 代理后台检测发生异常: {e}", flush=True)
            log_to_json("ERROR", "Proxy", f"检测守护线程发生异常: {e}")
        time.sleep(30)

def active_node_pinger() -> None:
    global active_openvpn_node_id, is_connecting
    while True:
        try:
            if active_openvpn_running() and active_openvpn_node_id:
                nodes = read_json(NODES_FILE, [])
                node = next((n for n in nodes if n.get("id") == active_openvpn_node_id), None)
                if node:
                    ip = node.get("ip") or node.get("remote_host")
                    port = parse_int(node.get("remote_port"))
                    fallback = parse_int(node.get("ping"))
                    if ip:
                        latency = vpn_utils.ping_latency_ms(ip, port, fallback)
                        if latency > 0:
                            set_state(active_node_latency=f"{latency} ms")
                        else:
                            set_state(active_node_latency="检测超时")
                    else:
                        set_state(active_node_latency="检测超时")
                else:
                    set_state(active_node_latency="检测超时")
            elif is_connecting:
                set_state(active_node_latency="测试中...")
            else:
                set_state(active_node_latency="无活动连接")
        except Exception as e:
            print(f"[ERROR] active_node_pinger error: {e}", flush=True)
        time.sleep(10)


class Handler(BaseHTTPRequestHandler):
    def get_secret_path(self) -> str:
        auth_file = DATA_DIR / "ui_auth.json"
        if not auth_file.exists():
            try:
                DATA_DIR.mkdir(exist_ok=True)
                auth_file.write_text(json.dumps({"secret_path": "EJsW2EeBo9lY"}), encoding="utf-8")
            except Exception:
                pass
            return "EJsW2EeBo9lY"
        try:
            creds = json.loads(auth_file.read_text(encoding="utf-8"))
            if "secret_path" in creds:
                return creds["secret_path"]
            elif "password" in creds:
                secret_path = creds["password"]
                try:
                    auth_file.write_text(json.dumps({"secret_path": secret_path}), encoding="utf-8")
                except Exception:
                    pass
                return secret_path
            return "EJsW2EeBo9lY"
        except Exception:
            return "EJsW2EeBo9lY"

    def is_authorized(self) -> bool:
        ui_cfg = load_ui_config()
        pwd = ui_cfg.get("password")
        if not pwd:
            return True
        
        cookie_header = self.headers.get("Cookie", "")
        cookies = {}
        if cookie_header:
            for item in cookie_header.split(";"):
                item = item.strip()
                if "=" in item:
                    k, v = item.split("=", 1)
                    cookies[k.strip()] = v.strip()
        
        session_token = cookies.get("session")
        if not session_token:
            return False
            
        with lock:
            exp_time = active_sessions.get(session_token)
            if exp_time is not None and exp_time > time.time():
                return True
        return False

    def validate_path(self) -> str:
        secret_path = self.get_secret_path()
        if not secret_path:
            return self.path
        if self.path == f"/{secret_path}":
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", f"/{secret_path}/")
            self.end_headers()
            return ""
        prefix = f"/{secret_path}/"
        if self.path.startswith(prefix):
            return "/" + self.path[len(prefix):]
        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()
        return ""

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[{self.log_date_time_string()}] {format % args}", flush=True)

    def send_bytes(self, body: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_bytes(json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", status)

    def do_GET(self) -> None:
        effective_path = self.validate_path()
        if effective_path == "": return
        
        if not self.is_authorized():
            if effective_path in ("/", "/index.html"):
                self.send_bytes(LOGIN_HTML.encode("utf-8"), "text/html; charset=utf-8")
                return
            else:
                self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return
                
        if effective_path in ("/", "/index.html"):
            self.send_bytes(INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")
        elif effective_path == "/api/nodes":
            global last_active_ping_time, last_active_latency, active_openvpn_node_id
            nodes = read_json(NODES_FILE, [])
            active_node = next((n for n in nodes if active_openvpn_node_id and n.get("id") == active_openvpn_node_id), None)
            for n in nodes:
                n["active"] = (active_openvpn_node_id and n.get("id") == active_openvpn_node_id)
            if active_node:
                ip = active_node.get("ip") or active_node.get("remote_host")
                if ip:
                    now = time.time()
                    if now - last_active_ping_time > 15.0:
                        last_active_ping_time = now
                        def bg_ping(ip_addr: str, port: int, fallback: int) -> None:
                            global last_active_latency
                            try:
                                latency = vpn_utils.ping_latency_ms(ip_addr, port, fallback)
                                if latency > 0:
                                    last_active_latency = latency
                            except Exception:
                                pass
                        threading.Thread(
                            target=bg_ping, 
                            args=(ip, parse_int(active_node.get("remote_port")), parse_int(active_node.get("ping"))),
                            daemon=True
                        ).start()
                    if last_active_latency > 0:
                        active_node["latency_ms"] = last_active_latency
            stripped_nodes = []
            for n in nodes:
                stripped = n.copy()
                if "config_text" in stripped:
                    del stripped["config_text"]
                stripped_nodes.append(stripped)
            self.send_json({"nodes": stripped_nodes, "state": get_state()})
        elif effective_path.startswith("/configs/"):
            filename = urllib.parse.unquote(effective_path.removeprefix("/configs/"))
            with lock:
                nodes = read_json(NODES_FILE, [])
                node = next((n for n in nodes if Path(n.get("config_file", "")).name == filename), None)
            if node and node.get("config_text"):
                self.send_bytes(node["config_text"].encode("utf-8"), "application/x-openvpn-profile")
            else:
                self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        effective_path = self.validate_path()
        if effective_path == "": return
        
        if effective_path == "/api/login":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                input_pwd = str(payload.get("password") or "")
                input_uname = str(payload.get("username") or "")
                
                ui_cfg = load_ui_config()
                expected_pwd = ui_cfg.get("password", "")
                expected_uname = ui_cfg.get("username", "admin")
                
                if expected_pwd and input_pwd == expected_pwd and input_uname == expected_uname:
                    token = uuid.uuid4().hex
                    with lock:
                        active_sessions[token] = time.time() + 30 * 24 * 3600
                    body = json.dumps({"ok": True}, ensure_ascii=False).encode("utf-8")
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Connection", "close")
                    secret_path = self.get_secret_path()
                    cookie_path = f"/{secret_path}/" if secret_path else "/"
                    self.send_header("Set-Cookie", f"session={token}; Path={cookie_path}; HttpOnly; SameSite=Lax; Max-Age=2592000")
                    self.end_headers()
                    self.wfile.write(body)
                    self.close_connection = True
                else:
                    self.send_json({"ok": False, "error": "用户名或密码不正确，请重新输入"}, HTTPStatus.FORBIDDEN)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/logout":
            try:
                cookie_header = self.headers.get("Cookie", "")
                cookies = {}
                if cookie_header:
                    for item in cookie_header.split(";"):
                        item = item.strip()
                        if "=" in item:
                            k, v = item.split("=", 1)
                            cookies[k.strip()] = v.strip()
                session_token = cookies.get("session")
                if session_token:
                    with lock:
                        active_sessions.pop(session_token, None)
                secret_path = self.get_secret_path()
                cookie_path = f"/{secret_path}/" if secret_path else "/"
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Set-Cookie", f"session=; Path={cookie_path}; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
                self.end_headers()
                self.wfile.write(json.dumps({"ok": True}).encode("utf-8"))
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if not self.is_authorized():
            self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return

        if effective_path == "/api/update_settings":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                
                curr_username = str(payload.get("curr_username") or "")
                curr_password = str(payload.get("curr_password") or "")
                
                new_port = payload.get("port")
                new_suffix = str(payload.get("secret_path") or "").strip()
                new_target_countries = normalize_target_countries_input(payload.get("target_countries") or "")
                new_node_sources = normalize_node_sources_input(payload.get("node_sources") or NODE_SOURCES_ENV or DEFAULT_NODE_SOURCES)
                new_target_ip_types = normalize_target_ip_types_input(payload.get("target_ip_types") or TARGET_IP_TYPES_ENV or "residential")
                new_auto_select_best_node = parse_bool_setting(payload.get("auto_select_best_node"), True)
                new_username = str(payload.get("new_username") or "").strip()
                new_password = str(payload.get("new_password") or "").strip()
                
                if not curr_username or not curr_password:
                    self.send_json({"ok": False, "error": "请输入当前账号和密码进行安全验证"}, HTTPStatus.FORBIDDEN)
                    return
                
                ui_cfg = load_ui_config()
                expected_uname = ui_cfg.get("username", "admin")
                expected_pwd = ui_cfg.get("password", "")
                
                if curr_username != expected_uname or curr_password != expected_pwd:
                    self.send_json({"ok": False, "error": "当前账号或密码不正确"}, HTTPStatus.FORBIDDEN)
                    return
                
                try:
                    new_port_int = int(new_port)
                    if not (1 <= new_port_int <= 65535):
                        raise ValueError()
                except (TypeError, ValueError):
                    self.send_json({"ok": False, "error": "端口范围必须是 1 至 65535"}, HTTPStatus.BAD_REQUEST)
                    return
                
                if not new_suffix or not re.match(r"^[A-Za-z0-9]+$", new_suffix):
                    self.send_json({"ok": False, "error": "安全后缀仅能由英文字母和数字组成"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg["port"] = new_port_int
                ui_cfg["secret_path"] = new_suffix
                ui_cfg["target_countries"] = new_target_countries
                ui_cfg["node_sources"] = new_node_sources
                ui_cfg["target_ip_types"] = new_target_ip_types
                ui_cfg["auto_select_best_node"] = new_auto_select_best_node
                if new_username:
                    ui_cfg["username"] = new_username
                if new_password:
                    ui_cfg["password"] = new_password
                
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                
                self.send_json({"ok": True, "message": "配置更新成功，系统将在 2 秒内重启..."})
                
                def restart_server():
                    time.sleep(2)
                    print("[系统] 管理后台配置更新，进程即将退出以触发自动重启...", flush=True)
                    os._exit(0)
                
                threading.Thread(target=restart_server, daemon=True).start()
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/check":
            try:
                threading.Thread(target=maintain_valid_nodes, kwargs={"force": True}, daemon=True).start()
                self.send_json({"ok": True, "message": "已在后台启动完整节点检测流程，面板会持续刷新检测进度"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/refresh_nodes":
            try:
                threading.Thread(target=maintain_valid_nodes, args=(False,), daemon=True).start()
                self.send_json({"ok": True, "message": "已在后台启动节点更新流程"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_nodes":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                node_ids = payload.get("ids", [])
                tested_nodes = test_multiple_nodes(node_ids)
                self.send_json({"ok": True, "nodes": tested_nodes})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/disconnect":
            try:
                stop_active_openvpn()
                with lock:
                    nodes = read_json(NODES_FILE, [])
                    for item in nodes:
                        item["active"] = False
                    write_json(NODES_FILE, nodes)
                global last_active_ping_time, last_active_latency
                last_active_ping_time = 0.0
                last_active_latency = 0
                set_state(active_openvpn_node_id="", last_check_message="手动断开连接", active_node_latency="无活动连接", failover_country_short="", failover_country="", failover_country_display="未固定")
                self.send_json({"ok": True})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/connect":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                allow_risky = str(payload.get("allow_risky") or "").lower() in {"1", "true", "yes", "on"}
                self.send_json({"ok": True, "message": connect_node(str(payload.get("id") or ""), allow_manual_risky=allow_risky)})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_node":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                node_id = str(payload.get("id") or "")
                updated_node = test_node_by_id(node_id)
                self.send_json({"ok": True, "node": updated_node})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_proxy":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                if length > 0:
                    self.rfile.read(length)
                result = check_proxy_health()
                if result["ok"]:
                    set_state(
                        proxy_ok=True,
                        proxy_ip=result["ip"],
                        proxy_latency_ms=result["latency_ms"],
                        proxy_error=""
                    )
                else:
                    set_state(
                        proxy_ok=False,
                        proxy_ip="-",
                        proxy_latency_ms=0,
                        proxy_error=result.get("error", "未知错误")
                    )
                self.send_json(result)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

class Tee:
    def __init__(self, file_path: str):
        Path(file_path).parent.mkdir(exist_ok=True, parents=True)
        self.file = open(file_path, "a", encoding="utf-8")
        self.stdout = sys.stdout

    def write(self, data: str) -> None:
        self.stdout.write(data)
        self.file.write(data)
        self.file.flush()

    def flush(self) -> None:
        self.stdout.flush()
        self.file.flush()

def main() -> None:
    ensure_dirs()
    kill_existing_openvpn_processes()
    
    log_file = DATA_DIR / "vpngate.log"
    tee = Tee(str(log_file))
    sys.stdout = tee
    sys.stderr = tee

    write_json(
        STATE_FILE,
        {
            "api_url": API_URL,
            "target_valid_nodes": TARGET_VALID_NODES,
            "fetch_interval_seconds": FETCH_INTERVAL_SECONDS,
            "check_interval_seconds": CHECK_INTERVAL_SECONDS,
            "local_proxy": f"http://{LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}",
            "active_openvpn_node_id": "",
            "last_fetch_status": "starting",
            "last_check_message": "服务已启动，正在初始化网络并获取候选 VPN 节点...",
            "is_connecting": True,
            "active_node_latency": "正在准备",
            "blacklisted_nodes": 0,
            "target_countries": normalize_target_countries_input(load_ui_config().get("target_countries") or TARGET_COUNTRIES_ENV),
            "target_countries_display": normalize_target_countries_input(load_ui_config().get("target_countries") or TARGET_COUNTRIES_ENV) or "全部地区",
            "target_ip_types": normalize_target_ip_types_input(load_ui_config().get("target_ip_types") or TARGET_IP_TYPES_ENV or "residential"),
            "target_ip_types_display": target_ip_types_display(load_ui_config().get("target_ip_types") or TARGET_IP_TYPES_ENV or "residential"),
        },
    )
    threading.Thread(target=proxy_server.start_proxy_server, args=(LOCAL_PROXY_HOST, LOCAL_PROXY_PORT), daemon=True).start()
    
    # Wait for the gateway to officially start
    print("[网关] 正在启动代理网关...", flush=True)
    gateway_ready = False
    for _ in range(30):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(0.5)
            s.connect((LOCAL_PROXY_HOST, LOCAL_PROXY_PORT))
            gateway_ready = True
            break
        except Exception:
            time.sleep(0.5)
        finally:
            try:
                s.close()
            except Exception:
                pass
            
    if gateway_ready:
        print("[网关] 代理网关已成功启动监听，启动同步与检测脚本...", flush=True)
    else:
        print("[警告] 代理网关启动超时，继续执行脚本...", flush=True)

    threading.Thread(target=collector_loop, daemon=True).start()
    threading.Thread(target=background_proxy_checker, daemon=True).start()
    threading.Thread(target=active_node_pinger, daemon=True).start()
    
    ui_cfg = load_ui_config()
    ui_host = ui_cfg.get("host", UI_HOST)
    ui_port = int(ui_cfg.get("port", UI_PORT))
    
    print(f"UI: http://{ui_host}:{ui_port}/", flush=True)
    print(f"Proxy: http://{LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}", flush=True)
    ThreadingHTTPServer((ui_host, ui_port), Handler).serve_forever()

if __name__ == "__main__":
    main()