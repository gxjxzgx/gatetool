#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ovpn.py —— VPN Gate OpenVPN 节点提取 + TCP 存活检查 (工作流: ovpn.yml)

流程:
  1. 拉取 VPN Gate 数据 (官方 CSV, 失败时回退 GitHub 镜像)
  2. 解码每个服务器的 OpenVPN 配置, 提取 remote 地址 / 端口 / 协议 (只接受公网地址)
  3. 并发 TCP 连通检查; UDP 无法用 TCP 探测, 按 KEEP_UDP 保留或丢弃
  4. 输出到 OUT_DIR:
       ovpn.json   网页数据 (公开, 含全部可用节点, 住宅 > 机房 > 未识别)
       ovpn.yaml   Clash 订阅 (私有, 上传到 Worker)
     住宅节点超过 MIN_ISP 个时, 机房节点只留在 ovpn.json, 不进 ovpn.yaml。

退出码: 0 正常; 1 硬性失败 (数据源全挂 / 没有提取到节点 / 全部不可达 / 程序异常)。
        任何情况都不会用空结果覆盖线上旧数据。

环境变量:
  WORKERS / TIMEOUT   检测并发 (默认 32) / 单节点 TCP 超时秒数 (默认 5)
  KEEP_UDP            UDP 节点: 1=不检查直接保留, 0=丢弃 (默认 1; 工作流里设为 0)
  MAX_YAML            ovpn.yaml 最多保留 N 个, 0=全部 (按延迟优先截断; 网页仍显示全部)
  EXCLUDE_DC / MIN_ISP  机房节点排除开关 (默认 1) / 住宅数量阈值 (默认 20)
  OUT_DIR             输出目录
  VPNGATE_API / VPNGATE_MIRROR   数据源地址
"""

import os
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor

from common import (
    OUT_DIR, classify_host, country_label, decode_config, drop_datacenter, env_flag, env_float,
    env_int, fetch_vpngate_rows, is_public_host, make_logger, node_name, now_bj, parse_remote,
    type_rank, write_json, write_text, yaml_str,
)

log, die = make_logger("ovpn")

# ---------------------------------------------------------------- 配置
WORKERS = max(1, env_int("WORKERS", 32))
TIMEOUT = env_float("TIMEOUT", 5)
MAX_YAML = env_int("MAX_YAML", 0)
KEEP_UDP = env_flag("KEEP_UDP", True)

# 配置内容来自第三方, 写入 YAML 前必须校验
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


# ---------------------------------------------------------------- 提取
def extract_nodes(rows):
    nodes, seen = [], set()
    for r in rows:
        cfg = decode_config(r["config_b64"])
        remote = parse_remote(cfg)
        if not remote:
            continue
        host, port, proto = remote
        if not is_public_host(host):
            continue
        key = (host.lower(), port, proto)
        if key in seen:
            continue
        seen.add(key)
        nodes.append({
            "country_long": r["country_long"],
            "country_short": r["country_short"],
            "remote_host": host,
            "remote_port": port,
            "proto": proto,
            "ip_type": classify_host(r["host"]),
            "latency_ms": None,
            "config": cfg,
        })
    return nodes


# ---------------------------------------------------------------- 检查
def tcp_latency(node):
    """TCP 连接耗时 (毫秒), 连不上返回 None。"""
    t0 = time.monotonic()
    try:
        with socket.create_connection((node["remote_host"], node["remote_port"]), timeout=TIMEOUT):
            return round((time.monotonic() - t0) * 1000)
    except OSError:
        return None


def check_nodes(nodes):
    """TCP 节点做连接检查; UDP 节点按 KEEP_UDP 直接保留或丢弃。"""
    tcp_nodes = [n for n in nodes if n["proto"] == "tcp"]
    alive = [] if not KEEP_UDP else [n for n in nodes if n["proto"] == "udp"]
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for node, ms in zip(tcp_nodes, pool.map(tcp_latency, tcp_nodes)):
            if ms is not None:
                node["latency_ms"] = ms
                alive.append(node)
    return alive


def sort_nodes(nodes):
    """国家码 → 住宅 > 机房 > 未识别 → 地址。"""
    return sorted(nodes, key=lambda n: (
        n["country_short"], type_rank(n["ip_type"]), n["remote_host"], n["remote_port"],
    ))


# ---------------------------------------------------------------- 输出
def pem_block(cfg, tag):
    m = re.search(rf"<{tag}>(.*?)</{tag}>", cfg, re.S)
    return m.group(1).strip() if m else ""


def cfg_directive(cfg, name, default):
    m = re.search(rf"^{name}\s+(\S+)", cfg, re.M)
    value = m.group(1) if m else default
    return value if TOKEN_RE.match(value) else default


def build_clash_yaml(nodes):
    """Clash proxies 列表。名字: 国家-类型-序号-ovpn (与 sstp 同一规则)。证书全网通用: 取第一个带完整证书的节点, 用 YAML 锚点定义, 其余引用。"""
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
        region = country_label(n["country_short"], n["country_long"])
        group = (region, n["ip_type"])
        counters[group] = counters.get(group, 0) + 1
        name = node_name(region, n["ip_type"], counters[group], "ovpn")
        cfg = n["config"]
        out += [
            f"  - name: {yaml_str(name)}",
            "    type: openvpn",
            f"    server: {yaml_str(n['remote_host'])}",
            f"    port: {n['remote_port']}",
            f"    proto: {n['proto']}",
            "    username: vpn",
            "    password: vpn",
            f"    cipher: {cfg_directive(cfg, 'cipher', 'AES-128-CBC')}",
            f"    auth: {cfg_directive(cfg, 'auth', 'SHA1')}",
            f"    udp: {'true' if n['proto'] == 'udp' else 'false'}",
            "    handshake-timeout: 30",
            "    remote-dns-resolve: true",
            "    dns: [ 8.8.8.8, 1.1.1.1 ]",
        ]
        if i == 0:
            out += ["    ca: &jkca |-", indented(ca),
                    "    cert: &jkcert |-", indented(cert),
                    "    key: &jkkey |-", indented(key)]
        else:
            out += ["    ca: *jkca", "    cert: *jkcert", "    key: *jkkey"]
    return "\n".join(out) + "\n"


def build_json(nodes, checked):
    countries = {}
    for n in nodes:
        grp = countries.setdefault(n["country_short"], {"long": n["country_long"], "count": 0})
        grp["count"] += 1
    return {
        "updated_at": now_bj(),
        "total": len(nodes),
        "checked": checked,
        "countries": countries,
        "entries": [{
            "country_long": n["country_long"],
            "country_short": n["country_short"],
            "host": n["remote_host"],
            "port": n["remote_port"],
            "proto": n["proto"],
            "latency_ms": n["latency_ms"],
            "ip_type": n["ip_type"],
        } for n in nodes],
    }


# ---------------------------------------------------------------- main
def main():
    log("== 1/4 拉取 VPN Gate 数据 ==")
    try:
        rows, _source = fetch_vpngate_rows(log)
    except RuntimeError as exc:
        die(f"所有数据源都不可用: {exc}")

    log("== 2/4 提取 OpenVPN 配置 ==")
    nodes = extract_nodes(rows)
    log(f"提取到 {len(nodes)} 个公网节点")
    if not nodes:
        die("没有提取到任何 OpenVPN 节点, 拒绝提交空结果")

    log(f"== 3/4 TCP 可达检查 (超时 {TIMEOUT:g}s, 并发 {WORKERS}) ==")
    alive = check_nodes(nodes)
    log(f"保留 {len(alive)}/{len(nodes)}" + (" (含未检查的 UDP 节点)" if KEEP_UDP else ""))
    if not alive:
        die("检查后剩余 0 个可用节点, 拒绝提交空结果")

    log("== 4/4 生成输出文件 ==")
    isp_n = sum(1 for n in alive if n["ip_type"] == "residential")
    dc_n = sum(1 for n in alive if n["ip_type"] == "datacenter")
    yaml_nodes = list(alive)
    if drop_datacenter(isp_n):
        yaml_nodes = [n for n in alive if n["ip_type"] != "datacenter"]
        log(f"家宽 {isp_n} 个, 机房 {dc_n} 个只在网页显示, 不写入 ovpn.yaml (写入 {len(yaml_nodes)} 个)")
    else:
        log(f"家宽 {isp_n} 个 (未超过阈值或未启用排除), 机房 {dc_n} 个一并写入")
    if MAX_YAML > 0:
        # 只截断订阅: 延迟优先 (UDP 无延迟排最后)
        yaml_nodes.sort(key=lambda n: (n["latency_ms"] is None, n["latency_ms"] or 0))
        yaml_nodes = yaml_nodes[:MAX_YAML]

    alive, yaml_nodes = sort_nodes(alive), sort_nodes(yaml_nodes)
    yaml_path = os.path.join(OUT_DIR, "ovpn.yaml")
    json_path = os.path.join(OUT_DIR, "ovpn.json")
    write_text(yaml_path, build_clash_yaml(yaml_nodes))
    write_json(json_path, build_json(alive, checked=len(nodes)))
    log(f"生成 {yaml_path} ({len(yaml_nodes)} 个节点)")
    log(f"生成 {json_path} ({len(alive)} 个节点)")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")
