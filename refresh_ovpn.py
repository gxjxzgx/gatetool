#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN Gate OpenVPN 节点自动提取。

数据源 : http://www.vpngate.net/api/iphone/ (官方 CSV, 含 OpenVPN 配置 base64)
流程   : 拉取 API -> 解码每个服务器的 OpenVPN 配置 -> 提取 remote 地址/端口/协议
          -> 并发 TCP 检查端口可达性
          -> 家宽(ISP)节点够多时剔除数据中心节点, 不够则连数据中心一起输出
          -> 生成 ovpn.yaml (Clash 订阅) + ovpn.json (监控页数据)

只用标准库, 无第三方依赖。

环境变量:
  OVPN_CHECK_TIMEOUT  选填, 单节点 TCP 检查超时秒数, 默认 5
  OVPN_WORKERS        选填, 并发线程数, 默认 32
  OVPN_MAX            选填, 最多保留 N 个 (0 = 全部), 默认 0 (按延迟优先截断)
  OVPN_KEEP_UDP       选填, UDP 节点无法做 TCP 检查, 1=不检查直接保留, 0=丢弃, 默认 1
  OVPN_EXCLUDE_DC     选填, 1=ISP 节点足够时不输出数据中心节点 (public-vpn 前缀), 0=始终保留, 默认 1
  OVPN_MIN_ISP        选填, ISP(家宽) 节点数 > 此值才剔除数据中心; 否则数据中心一并输出, 默认 20
  OUT_DIR             选填, 输出目录, 默认脚本所在目录
  VPNGATE_API         选填, 官方 API 地址
  VPNGATE_MIRROR      选填, 官方失败时的回退镜像
"""

import base64
import csv
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta

VPNGATE_API = os.environ.get("VPNGATE_API", "http://www.vpngate.net/api/iphone/")
VPNGATE_MIRROR = os.environ.get(
    "VPNGATE_MIRROR",
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
)
BEIJING = timezone(timedelta(hours=8))
HTTP_TIMEOUT = 30

REMOTE_RE = re.compile(r"^remote\s+(\S+)\s+(\d+)", re.M)
PROTO_RE = re.compile(r"^proto\s+(\S+)", re.M)
# 配置内容来自第三方, 写入 YAML/HTML 前必须校验
HOST_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


def valid_host(h):
    if not h or len(h) > 253:
        return False
    if HOST_RE.match(h):
        return True
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False

def log(msg):
    print(f"[ovpn] {msg}", flush=True)


def die(msg):
    print(f"[ovpn] 致命错误: {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def http_get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; openvp-ovpn)"})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
        return r.read().decode("utf-8", "replace")


def parse_csv_rows(text):
    lines = [ln for ln in text.splitlines() if ln.strip()]
    hi = next((i for i, ln in enumerate(lines) if ln.lstrip("#").startswith("HostName")), None)
    if hi is None:
        raise RuntimeError("找不到 CSV 表头行 (HostName)")
    header = lines[hi].lstrip("#").split(",")
    idx = {h.strip().lstrip("*").lower(): i for i, h in enumerate(header)}
    rows = []
    for row in csv.reader(lines[hi + 1:]):
        try:
            rows.append({
                "host": row[idx["hostname"]],
                "ip": row[idx["ip"]],
                "country_long": row[idx["countrylong"]],
                "country_short": row[idx["countryshort"]],
                "config_b64": row[idx["openvpn_configdata_base64"]],
            })
        except (IndexError, KeyError):
            continue
    return rows


def parse_mirror_rows(data):
    items = data if isinstance(data, list) else [data]
    servers = []
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("servers"), list):
            servers.extend(item["servers"])
        elif isinstance(item, dict):
            servers.append(item)
    rows = []
    for s in servers:
        host = str(s.get("hostname") or s.get("host") or "").strip()
        ip = str(s.get("ip") or "").strip()
        if not host or not ip:
            continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": str(s.get("countrylong") or s.get("country_long") or s.get("country") or ""),
            "country_short": str(s.get("countryshort") or s.get("country_short") or ""),
            "config_b64": str(s.get("openvpn_configdata_base64") or s.get("config_b64") or ""),
        })
    return rows


def fetch_rows():
    try:
        log(f"拉取官方 API: {VPNGATE_API}")
        rows = parse_csv_rows(http_get(VPNGATE_API))
        if rows:
            log(f"官方 API 拿到 {len(rows)} 行")
            return rows
        raise RuntimeError("官方 API 返回 0 行")
    except Exception as exc:
        log(f"官方 API 失败: {exc}, 尝试回退镜像")
    try:
        rows = parse_mirror_rows(json.loads(http_get(VPNGATE_MIRROR)))
        if rows:
            log(f"回退镜像拿到 {len(rows)} 行")
            return rows
        raise RuntimeError("回退镜像返回 0 行")
    except Exception as exc:
        die(f"官方 API 与回退镜像均失败: {exc}")


def extract_nodes(rows):
    nodes, seen = [], set()
    for r in rows:
        b64 = (r.get("config_b64") or "").strip()
        if not b64:
            continue
        try:
            cfg = base64.b64decode(b64, validate=False).decode("utf-8", "replace")
        except Exception:
            continue
        m = REMOTE_RE.search(cfg)
        if not m:
            continue
        rh, rp = m.group(1), int(m.group(2))
        if not valid_host(rh) or not (0 < rp < 65536):
            continue
        pm = PROTO_RE.search(cfg)
        proto = pm.group(1).lower() if pm else "udp"
        proto = "tcp" if proto.startswith("tcp") else "udp" if proto.startswith("udp") else None
        if proto is None:
            continue
        key = (rh.lower(), rp, proto)
        if key in seen:
            continue
        seen.add(key)
        nodes.append({
            "country_long": r.get("country_long", ""),
            "country_short": r.get("country_short", ""),
            "vg_host": r.get("host", ""),
            "remote_host": rh,
            "remote_port": rp,
            "proto": proto,
            "config": cfg,
        })
    return nodes


def tcp_ok(node, timeout):
    t0 = time.time()
    try:
        with socket.create_connection((node["remote_host"], node["remote_port"]), timeout=timeout):
            return True, int((time.time() - t0) * 1000)
    except Exception:
        return False, None


def check_nodes(nodes, timeout, workers, keep_udp=True):
    """TCP 节点做连接检查; UDP 节点无法用 TCP 探测, 按 keep_udp 直接保留或丢弃。"""
    alive = []
    tcp_nodes = []
    for n in nodes:
        if n["proto"] == "tcp":
            tcp_nodes.append(n)
        elif keep_udp:
            n["latency_ms"] = None
            alive.append(n)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(tcp_ok, n, timeout): n for n in tcp_nodes}
        for fut in as_completed(futs):
            ok, ms = fut.result()
            if ok:
                n = futs[fut]
                n["latency_ms"] = ms
                alive.append(n)
    return alive


def sort_by_country(nodes):
    return sorted(nodes, key=lambda n: (n["country_short"], n["remote_host"], n["remote_port"]))


def classify_ip_type(vg_host):
    """按 VPN Gate 主机名前缀估算 IP 类型 (与 gate 的第三层启发规则一致)。"""
    h = (vg_host or "").lower()
    if h.startswith("public-vpn"):
        return "datacenter"
    if re.match(r"^vpn\d+", h):
        return "residential"
    return "unknown"


def pem_block(cfg, tag):
    m = re.search(rf"<{tag}>(.*?)</{tag}>", cfg, re.S)
    if not m:
        return ""
    return m.group(1).replace("\r\n", "\n").strip()


def cfg_directive(cfg, name, default):
    m = re.search(rf"^{name}\s+(\S+)", cfg, re.M)
    return m.group(1) if m else default


IP_TYPE_LABEL = {
    "residential": ("🏠", "家宽"),
    "datacenter": ("🏢", "机房"),
    "unknown": ("🌐", "未识别"),
}


def write_clash_yaml(nodes, out_dir):
    """生成 Clash 可直接用的 ovpn.yaml (proxies 列表)。
    证书全网通用: 取第一个带完整证书的节点, 用 YAML 锚点定义, 其余引用。"""
    os.makedirs(out_dir, exist_ok=True)
    ca = cert = key = ""
    for n in nodes:
        ca, cert, key = (pem_block(n["config"], t) for t in ("ca", "cert", "key"))
        if ca and cert and key:
            break
    else:
        die("所有节点都缺少 ca/cert/key, 拒绝生成 ovpn.yaml")

    def indented(pem):
        return "\n".join("      " + ln for ln in pem.splitlines())

    counters = {}
    out = ["proxies:"]
    for i, n in enumerate(nodes):
        cs = re.sub(r"\W+", "", n["country_short"]) or "XX"
        icon, label = IP_TYPE_LABEL[classify_ip_type(n.get("vg_host", ""))]
        ck = (cs, label)
        counters[ck] = counters.get(ck, 0) + 1
        name = f"{icon} {cs}-{label}-{counters[ck]:02d}"
        cfg = n["config"]
        cipher = cfg_directive(cfg, "cipher", "AES-128-CBC")
        auth = cfg_directive(cfg, "auth", "SHA1")
        if not TOKEN_RE.match(cipher):
            cipher = "AES-128-CBC"
        if not TOKEN_RE.match(auth):
            auth = "SHA1"
        udp = n["proto"] == "udp"
        out.append(f'  - name: "{name}"')
        out.append("    type: openvpn")
        out.append(f"    server: \"{n['remote_host']}\"")
        out.append(f"    port: {n['remote_port']}")
        out.append(f"    proto: {n['proto']}")
        out.append("    username: vpn")
        out.append("    password: vpn")
        out.append(f"    cipher: {cipher}")
        out.append(f"    auth: {auth}")
        out.append(f"    udp: {'true' if udp else 'false'}")
        out.append("    handshake-timeout: 30")
        out.append("    remote-dns-resolve: true")
        out.append("    dns: [ 8.8.8.8, 1.1.1.1 ]")
        if i == 0:
            out.append("    ca: &jkca |-")
            out.append(indented(ca))
            out.append("    cert: &jkcert |-")
            out.append(indented(cert))
            out.append("    key: &jkkey |-")
            out.append(indented(key))
        else:
            out.append("    ca: *jkca")
            out.append("    cert: *jkcert")
            out.append("    key: *jkkey")
    path = os.path.join(out_dir, "ovpn.yaml")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    os.replace(tmp, path)
    return path


def write_outputs(nodes, out_dir, checked=None):
    """只生成 ovpn.yaml (订阅) + ovpn.json (监控页数据)。"""
    os.makedirs(out_dir, exist_ok=True)
    now = datetime.now(BEIJING).strftime("%Y-%m-%d %H:%M")
    yaml_path = write_clash_yaml(nodes, out_dir)
    # 监控页用的结构化数据
    countries = {}
    for n in nodes:
        cs = n["country_short"]
        if cs not in countries:
            countries[cs] = {"long": n["country_long"], "count": 0}
        countries[cs]["count"] += 1
    json_path = os.path.join(out_dir, "ovpn.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "updated_at": now,
                "total": len(nodes),
                "checked": checked if checked is not None else len(nodes),
                "countries": countries,
                "entries": [
                    {
                        "country_long": n["country_long"],
                        "country_short": n["country_short"],
                        "host": n["remote_host"],
                        "port": n["remote_port"],
                        "proto": n["proto"],
                        "latency_ms": n.get("latency_ms"),
                        "ip_type": classify_ip_type(n.get("vg_host", "")),
                    }
                    for n in nodes
                ],
            },
            f, ensure_ascii=False, indent=1,
        )
    return yaml_path, json_path


def main():
    timeout = float(os.environ.get("OVPN_CHECK_TIMEOUT", "5"))
    workers = int(os.environ.get("OVPN_WORKERS", "32"))
    max_n = int(os.environ.get("OVPN_MAX", "0"))
    keep_udp = os.environ.get("OVPN_KEEP_UDP", "1") != "0"
    exclude_dc = os.environ.get("OVPN_EXCLUDE_DC", "1") != "0"
    min_isp = int(os.environ.get("OVPN_MIN_ISP", "20"))
    out_dir = os.environ.get("OUT_DIR", os.path.dirname(os.path.abspath(__file__)))

    log("== 1/3 拉取 VPN Gate 数据 ==")
    rows = fetch_rows()

    log("== 2/3 提取 OpenVPN 配置 ==")
    nodes = extract_nodes(rows)
    log(f"提取到 {len(nodes)} 个节点")
    if not nodes:
        die("没有提取到任何 OpenVPN 节点, 拒绝提交空结果")

    log(f"== 3/3 TCP 可达检查 (超时 {timeout}s, 并发 {workers}) ==")
    alive = check_nodes(nodes, timeout, workers, keep_udp)
    log(f"保留: {len(alive)}/{len(nodes)} (含未检查的 UDP 节点)" if keep_udp else f"可达: {len(alive)}/{len(nodes)}")
    isp_n = sum(1 for n in alive if classify_ip_type(n.get("vg_host", "")) == "residential")
    dc_n = sum(1 for n in alive if classify_ip_type(n.get("vg_host", "")) == "datacenter")
    if exclude_dc and isp_n > min_isp:
        alive = [n for n in alive if classify_ip_type(n.get("vg_host", "")) != "datacenter"]
        log(f"ISP(家宽) 节点 {isp_n} 个 (> {min_isp}), 剔除数据中心节点 {dc_n} 个, 输出 {len(alive)} 个")
    else:
        log(f"ISP(家宽) 节点 {isp_n} 个 (未超过 {min_isp}) 或未启用剔除, 数据中心节点 {dc_n} 个一并输出, 共 {len(alive)} 个")
    if not alive:
        die("检查后剩余 0 个可用节点, 拒绝提交空结果")
    if max_n > 0:
        # 先按延迟截断 (UDP 无延迟排最后), 再回到按国家排序
        alive.sort(key=lambda n: (n.get("latency_ms") is None, n.get("latency_ms") or 0))
        alive = alive[:max_n]
    alive = sort_by_country(alive)

    yaml_path, json_path = write_outputs(alive, out_dir, checked=len(nodes))
    log(f"已写入 {yaml_path} / {json_path} ({len(alive)} 个节点)")


if __name__ == "__main__":
    main()