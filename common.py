#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gate.py / ovpn.py / pool.py 共用工具 (只用标准库)

- 日志与退出:   make_logger
- 环境变量:     env_str / env_int / env_float / env_flag   (空字符串视为未设置)
- HTTP:         http_fetch / http_get
- VPN Gate:     fetch_vpngate_rows / parse_remote / classify_host
- 输出:         write_text / write_json / yaml_str
"""

import base64
import csv
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

# 任何控制台编码下中文日志都不崩
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# ---------------------------------------------------------------- 环境变量
# GitHub Actions 里未配置的 secret 会变成空字符串, 所以空串一律当作未设置。

def env_str(name, default=""):
    return os.environ.get(name, "").strip() or default


def env_int(name, default):
    value = env_str(name)
    return int(value) if value else default


def env_float(name, default):
    value = env_str(name)
    return float(value) if value else default


def env_flag(name, default=True):
    value = env_str(name)
    return default if not value else value.lower() not in ("0", "false", "no", "off")


# ---------------------------------------------------------------- 常量
BEIJING = timezone(timedelta(hours=8))
REPO_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = env_str("OUT_DIR", os.path.join(REPO_DIR, "site"))
REFRESH_TEXT = "每小时"          # 与 gate.yml / ovpn.yml 的 cron 保持一致
UA = "Mozilla/5.0 (compatible; gatetool)"
HTTP_TIMEOUT = env_int("HTTP_TIMEOUT", 60)

VPNGATE_API = env_str("VPNGATE_API", "http://www.vpngate.net/api/iphone/")
VPNGATE_MIRROR = env_str(
    "VPNGATE_MIRROR",
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
)

# 机房 / 住宅排序: 住宅最前
TYPE_RANK = {"residential": 0, "datacenter": 1, "unknown": 2}

# 住宅节点超过此数量时, 订阅里默认剔除机房节点
EXCLUDE_DC = env_flag("EXCLUDE_DC", True)
MIN_ISP = env_int("MIN_ISP", 20)


# ---------------------------------------------------------------- 节点命名 (所有输出文件共用)
# 规则: 地区-类型-序号-协议, 例: 日本-住宅-01-sstp / 日本-住宅-01-ovpn / IPv4优选-01-pool
TYPE_ORDER = ("residential", "datacenter", "unknown")
TYPE_LABEL = {"residential": "住宅", "datacenter": "机房", "unknown": "未识别"}

# ISO 国家码 -> 中文名 (未收录则回退国家码 / 英文原名)
COUNTRY_ZH = {
    "JP": "日本", "KR": "韩国", "US": "美国", "CA": "加拿大", "RU": "俄罗斯",
    "RO": "罗马尼亚", "TH": "泰国", "VN": "越南", "DE": "德国", "FR": "法国",
    "GB": "英国", "UK": "英国", "SG": "新加坡", "TW": "台湾", "HK": "香港",
    "CN": "中国", "AU": "澳大利亚", "NL": "荷兰", "SE": "瑞典", "CH": "瑞士",
    "IT": "意大利", "ES": "西班牙", "PL": "波兰", "IN": "印度", "BR": "巴西",
    "MX": "墨西哥", "ID": "印度尼西亚", "MY": "马来西亚", "PH": "菲律宾",
    "TR": "土耳其", "UA": "乌克兰", "CZ": "捷克", "GR": "希腊", "PT": "葡萄牙",
    "FI": "芬兰", "NO": "挪威", "DK": "丹麦", "IE": "爱尔兰", "BE": "比利时",
    "AT": "奥地利", "HU": "匈牙利", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚",
    "NZ": "新西兰", "ZA": "南非", "IL": "以色列", "AE": "阿联酋", "SA": "沙特",
    "EG": "埃及", "HR": "克罗地亚", "BY": "白俄罗斯", "GD": "格林纳达",
    "LV": "拉脱维亚", "EE": "爱沙尼亚", "LT": "立陶宛", "SK": "斯洛伐克",
    "SI": "斯洛文尼亚", "BG": "保加利亚", "RS": "塞尔维亚", "GE": "格鲁吉亚",
    "MD": "摩尔多瓦", "AM": "亚美尼亚", "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦",
    "MN": "蒙古", "NP": "尼泊尔", "LK": "斯里兰卡", "MM": "缅甸",
}


def country_label(code, name=""):
    """国家显示名: 中文名 > 国家码 > 英文原名。"""
    code = (code or "").strip().upper()
    return COUNTRY_ZH.get(code) or (code if code and code != "?" else (name or "未知"))


def node_name(region, ip_type, index, proto):
    """统一的节点名: 地区-类型-序号-协议。"""
    return f"{region}-{TYPE_LABEL.get(ip_type, TYPE_LABEL['unknown'])}-{index:02d}-{proto}"


# ---------------------------------------------------------------- 日志
def make_logger(tag):
    """返回 (log, die)。die 打印到 stderr 并以退出码 1 结束。"""
    def log(msg=""):
        print(f"[{tag}] {msg}", flush=True)

    def die(msg):
        print(f"[{tag}] 失败: {msg}", file=sys.stderr, flush=True)
        sys.exit(1)

    return log, die


def now_bj(fmt="%Y-%m-%d %H:%M"):
    return datetime.now(BEIJING).strftime(fmt)


# ---------------------------------------------------------------- HTTP
def http_fetch(url, timeout=30):
    """返回 (状态码, 正文)。HTTP 错误码不抛异常; 网络错误 / 超时照常抛出。"""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, ""


def http_get(url, timeout=30):
    status, body = http_fetch(url, timeout)
    if status != 200:
        raise RuntimeError(f"HTTP {status}")
    return body


# ---------------------------------------------------------------- 输出
def write_text(path, text):
    """原子写入: 先写临时文件再替换, 中途失败不会留下半截文件。"""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    os.replace(tmp, path)


def write_json(path, data, indent=1):
    write_text(path, json.dumps(data, ensure_ascii=False, indent=indent))


def yaml_str(value):
    """YAML 字符串字面量。JSON 双引号字符串是合法 YAML, 能正确转义引号和反斜杠。"""
    return json.dumps(str(value), ensure_ascii=False)


# ---------------------------------------------------------------- 清洗
def clean_country(name):
    """国家名来自第三方数据, 去掉会破坏订阅格式的控制字符和 # $。"""
    return re.sub(r"[\x00-\x1f#$]", " ", name or "").strip()


def clean_code(code):
    return re.sub(r"[^A-Za-z]", "", code or "")[:3].upper()


_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_PRIVATE_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home", ".corp")


def is_public_host(host):
    """公网 IP 或像样的公网域名。拒绝内网/回环/链路本地地址, 防止 Actions 去探测内网。"""
    host = (host or "").strip().lower()
    if not host or len(host) > 253:
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        pass
    if not _HOST_RE.match(host) or host.endswith(_PRIVATE_SUFFIXES):
        return False
    return not host.rsplit(".", 1)[1].isdigit()


# ---------------------------------------------------------------- VPN Gate 解析
_CSV_FALLBACK = {"hostname": 0, "ip": 1, "countrylong": 5, "countryshort": 6}
_REMOTE_RE = re.compile(r"^remote\s+(\S+)\s+(\d+)", re.M)
_PROTO_RE = re.compile(r"^proto\s+(\S+)", re.M)
_RESIDENTIAL_RE = re.compile(r"^(?:vpn\d{5,}|vpnv\d+)")


def _make_row(host, ip, country_long, country_short, config_b64):
    return {
        "host": host.strip(),
        "ip": ip.strip(),
        "country_long": country_long.strip(),
        "country_short": country_short.strip(),
        "config_b64": config_b64.strip(),
    }


def parse_csv_rows(text):
    """解析官方 CSV。按列名定位, 列名缺失时回退到固定位置。"""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    start = next((i for i, ln in enumerate(lines) if ln.lstrip("#").startswith("HostName")), None)
    if start is None:
        raise RuntimeError("找不到 CSV 表头行 (HostName)")
    header = [h.strip().lstrip("*").lower() for h in lines[start].lstrip("#").split(",")]
    col = {k: header.index(k) if k in header else d for k, d in _CSV_FALLBACK.items()}
    cfg_col = next((i for i, h in enumerate(header) if h == "openvpn_configdata_base64"), None)
    if cfg_col is None:
        cfg_col = next((i for i, h in enumerate(header) if "base64" in h), len(header) - 1)
    col["cfg"] = cfg_col

    rows = []
    for fields in csv.reader(lines[start + 1:]):
        if len(fields) < 7 or max(col.values()) >= len(fields):
            continue
        rows.append(_make_row(fields[col["hostname"]], fields[col["ip"]],
                              fields[col["countrylong"]], fields[col["countryshort"]],
                              fields[col["cfg"]]))
    return rows


def parse_mirror_rows(data):
    """解析 GitHub 镜像 JSON: [{"servers": [{hostname, ip, countrylong, countryshort,
    openvpn_configdata_base64}]}], 也兼容直接给节点数组。"""
    servers = []
    for item in data if isinstance(data, list) else [data]:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("servers"), list):
            servers.extend(item["servers"])
        else:
            servers.append(item)

    rows = []
    for s in servers:
        if not isinstance(s, dict):
            continue
        host = str(s.get("hostname") or s.get("host") or "").strip()
        ip = str(s.get("ip") or "").strip()
        if not host or not ip:
            continue
        rows.append(_make_row(
            host, ip,
            str(s.get("countrylong") or s.get("country_long") or s.get("country") or ""),
            str(s.get("countryshort") or s.get("country_short") or ""),
            str(s.get("openvpn_configdata_base64") or s.get("config_b64") or ""),
        ))
    return rows


def fetch_vpngate_rows(log):
    """返回 (rows, source)。官方 API 失败时回退镜像; 两者都失败抛 RuntimeError。"""
    attempts = (
        ("官方 API", "vpngate.net/api/iphone", VPNGATE_API, parse_csv_rows),
        ("回退镜像", "github-mirror", VPNGATE_MIRROR, lambda t: parse_mirror_rows(json.loads(t))),
    )
    errors = []
    for label, source, url, parse in attempts:
        try:
            log(f"拉取{label}: {url}")
            rows = parse(http_get(url, HTTP_TIMEOUT))
            if not rows:
                raise RuntimeError("返回 0 行数据")
            log(f"{label}: 拿到 {len(rows)} 个原始节点")
            return rows, source
        except Exception as exc:
            log(f"{label}: 失败 - {exc}")
            errors.append(f"{label}: {exc}")
    raise RuntimeError("; ".join(errors))


def decode_config(b64):
    """解码 OpenVPN 配置, 失败返回空串。"""
    try:
        raw = base64.b64decode(b64 + "=" * (-len(b64) % 4))
        return raw.decode("utf-8", "replace").replace("\r\n", "\n")
    except Exception:
        return ""


def parse_remote(cfg):
    """从 OpenVPN 配置取 (host, port, proto)。proto 归一为 tcp / udp, 无法识别返回 None。"""
    m = _REMOTE_RE.search(cfg)
    if not m:
        return None
    port = int(m.group(2))
    if not 0 < port < 65536:
        return None
    pm = _PROTO_RE.search(cfg)
    proto = pm.group(1).lower() if pm else "udp"
    if proto.startswith("tcp"):
        return m.group(1), port, "tcp"
    if proto.startswith("udp"):
        return m.group(1), port, "udp"
    return None


def classify_host(vg_host):
    """按 VPN Gate 主机名估算类型: public-vpn-* 为机房, vpn+长数字为住宅。"""
    host = (vg_host or "").lower()
    if host.startswith("public-vpn"):
        return "datacenter"
    if _RESIDENTIAL_RE.match(host):
        return "residential"
    return "unknown"


def type_rank(ip_type):
    return TYPE_RANK.get(ip_type, TYPE_RANK["unknown"])


def drop_datacenter(isp_count):
    """住宅节点足够多时, 订阅里剔除机房节点。"""
    return EXCLUDE_DC and isp_count > MIN_ISP
