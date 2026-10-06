#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pool.py —— Cloudflare 边缘优选池刷新 (工作流: pool.yml)

流程:
  1. 拉取 Cloudflare 官方 IP 段 (ips-v4 / ips-v6)
  2. 随机采样, 并发测 443 端口 TLS 握手延迟 (SNI = 自己的域名, 握手成功即证明是可用边缘)
  3. 按延迟取最快的 POOL_SIZE 个
  4. 输出到 OUT_DIR:
       pool.json   网页数据 (公开)
       pool.txt    vless 订阅, 每个池子 IP 一条直连节点 (私有; 需要 EDT_UUID)
       pool.yaml   Clash 订阅 (私有; 需要 EDT_UUID)

用法:
  python pool.py            刷新池子
  python pool.py --check    只判断本次是否需要刷新, 向 stdout 输出 run=true / run=false
                            (供 pool.yml 写入 $GITHUB_OUTPUT)

刷新条件: 手动触发 / 线上没有数据 / 数据超过 8 天 / 周日(北京时间)且距上次刷新超过 20 小时。

退出码: 0 正常; 1 硬性失败 (缺少 EDT_DOMAIN / 拉不到 IP 段 / 可用 IP 少于 MIN_KEEP / 程序异常)。

环境变量:
  EDT_DOMAIN    必填, 你托管在 Cloudflare 的域名, 用作 TLS SNI
  EDT_UUID      选填, 设置后额外生成 pool.txt / pool.yaml
  POOL_SIZE     保留最快的前 N 个, 默认 40
  SAMPLE_SIZE   每轮采样 IP 数, 默认 300
  TIMEOUT       单 IP 连接 + 握手超时秒数, 默认 8
  WORKERS       并发线程数, 默认 32; 设为 1 则串行
  MIN_KEEP      可用 IP 少于此数则报错退出 (防止提交坏池子), 默认 10
  V6_RATIO      采样中 IPv6 占比, 默认 0 (只采 IPv4)
  SUB_PATH      覆盖默认 WS 路径 (默认: /随机伪装路径/proxyip=池子IP)
  SUB_FP        TLS 指纹, 默认 chrome
  SUB_PREFIX    订阅节点名前缀; 为空则按 IP 类型自动命名 (IPv4优选 / IPv6优选)
  OUT_DIR       输出目录
"""

import ipaddress
import json
import os
import random
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.parse import quote

from common import (
    BEIJING, OUT_DIR, env_float, env_int, env_str, http_get, make_logger, now_bj,
    write_json, write_text, yaml_str,
)

log, die = make_logger("pool")

# ---------------------------------------------------------------- 配置
CF_SOURCES = ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6")

# 随机伪装路径词表 (模仿真实网站路径, 后接 /proxyip=池子IP)
CAMO_WORDS = (
    "act", "api", "app", "assets", "channel", "classify", "comic", "details", "doc", "docs",
    "download", "favorite", "forum", "jump", "knowledge", "list", "magnet", "out", "pdf",
    "project", "service", "static", "store", "video", "view", "search", "index", "home",
    "page", "item", "feed",
)

# 只验证「握手能成功」, 不校验证书 (测的是连通性和延迟); 上下文线程安全, 全局共用一个
TLS_CTX = ssl.create_default_context()
TLS_CTX.check_hostname = False
TLS_CTX.verify_mode = ssl.CERT_NONE

MAX_AGE_H = 8 * 24       # 超过 8 天无论如何都刷新
SUNDAY_AGE_H = 20        # 周日只要距上次刷新超过 20 小时就刷新


# ---------------------------------------------------------------- 是否需要刷新
def pool_age_hours():
    """线上 pool.json 距今多少小时, 读不到返回 None。"""
    try:
        with open(os.path.join(OUT_DIR, "pool.json"), encoding="utf-8") as fh:
            updated = datetime.strptime(json.load(fh)["updated_at"], "%Y-%m-%d %H:%M")
        return (datetime.now(BEIJING) - updated.replace(tzinfo=BEIJING)).total_seconds() / 3600
    except Exception:
        return None


def need_refresh():
    if os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch":
        return True
    age = pool_age_hours()
    if age is None or age > MAX_AGE_H:
        return True
    # 北京时间周日; 用「距上次刷新 > 20h」而不是固定小时, 定时任务延迟也不会错过
    return datetime.now(BEIJING).weekday() == 6 and age > SUNDAY_AGE_H


# ---------------------------------------------------------------- 采样与探测
def fetch_cidrs(url):
    nets = []
    for line in http_get(url).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            nets.append(ipaddress.ip_network(line))
        except ValueError:
            log(f"警告: 跳过无法解析的行: {line}")
    return nets


def random_host(net):
    """网段内随机取一个主机地址 (避开网络地址和广播地址)。"""
    base = int(net.network_address)
    lo, hi = base + 1, base + net.num_addresses - 2
    if hi < lo:
        return net.network_address
    return type(net.network_address)(random.randint(lo, hi))   # 按网段自身的地址族构造


def sample_ips(nets, count, v6_ratio):
    """v4 / v6 按比例分配 (v6 地址空间巨大, 不能混在一起按地址数加权); 族内按网段大小加权。"""
    v4 = [n for n in nets if n.version == 4]
    v6 = [n for n in nets if n.version == 6]
    v6_count = round(count * v6_ratio) if v6 else 0
    picked = set()
    for part, c in ((v4, count - v6_count), (v6, v6_count)):
        if part and c > 0:
            weights = [n.num_addresses for n in part]
            picked.update(str(random_host(net)) for net in random.choices(part, weights=weights, k=c))
    return sorted(picked)


def probe(ip, sni, timeout):
    """对单个 IP 做 TCP + TLS 握手, 返回延迟毫秒, 失败返回 None。"""
    t0 = time.monotonic()
    try:
        with socket.create_connection((ip, 443), timeout=timeout) as sock:
            with TLS_CTX.wrap_socket(sock, server_hostname=sni):
                return round((time.monotonic() - t0) * 1000, 1)
    except Exception:
        return None


def probe_all(ips, sni, timeout, workers):
    ok = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for done, (ip, ms) in enumerate(zip(ips, pool.map(lambda x: probe(x, sni, timeout), ips)), 1):
            if ms is not None:
                ok.append((ip, ms))
            if done % 50 == 0:
                log(f"  进度 {done}/{len(ips)}, 可用 {len(ok)}")
    return sorted(ok, key=lambda x: x[1])


# ---------------------------------------------------------------- 订阅生成
def camo_path():
    parts = random.sample(CAMO_WORDS, random.randint(1, 3))
    return "/" + "/".join(p + ".html" if random.random() < 0.25 else p for p in parts)


def build_nodes(picked):
    """返回 [(名字, IP, ws_path)]。名字按 IP 类型编号, 与 worker 别名规则一致。"""
    path_override = env_str("SUB_PATH")
    prefix = env_str("SUB_PREFIX")
    proxy_ips = ",".join(ip for ip, _ in random.sample(picked, min(8, len(picked))))
    counters, nodes = {}, []
    for ip, _ in picked:
        label = prefix or ("IPv6优选" if ":" in ip else "IPv4优选")
        counters[label] = counters.get(label, 0) + 1
        nodes.append((f"{label}-{counters[label]:02d}", ip, path_override or f"{camo_path()}/proxyip={proxy_ips}"))
    return nodes


def build_links_text(nodes, uuid, sni, fp, updated):
    lines = [
        "# Cloudflare 边缘优选订阅 (vless:// 明文, 自动刷新)",
        f"# 更新时间: {updated} (北京时间)",
        f"# 每个池子 IP 一条直连节点, SNI={sni}, 共 {len(nodes)} 个",
    ]
    for name, ip, ws_path in nodes:
        host = f"[{ip}]" if ":" in ip else ip
        lines.append(
            f"vless://{uuid}@{host}:443?encryption=none&security=tls"
            f"&type=ws&host={sni}&fp={fp}&sni={sni}"
            f"&path={quote(ws_path, safe='')}#{quote(name, safe='')}"
        )
    return "\n".join(lines) + "\n"


def build_clash_text(nodes, uuid, sni, fp, updated):
    lines = [
        "# Cloudflare 边缘优选 Clash 订阅 (自动刷新)",
        f"# 更新时间: {updated} (北京时间)",
        "proxies:",
    ]
    for name, ip, ws_path in nodes:
        lines += [
            f"  - name: {yaml_str(name)}",
            "    type: vless",
            f"    server: {yaml_str(ip)}",
            "    port: 443",
            f"    uuid: {yaml_str(uuid)}",
            "    tls: true",
            f"    servername: {yaml_str(sni)}",
            f"    client-fingerprint: {yaml_str(fp)}",
            "    network: ws",
            "    ws-opts:",
            f"      path: {yaml_str(ws_path)}",
            "      headers:",
            f"        Host: {yaml_str(sni)}",
            "    udp: true",
            "    ech-opts:",
            "      enable: true",
            "      query-server-name: cloudflare-ech.com",
        ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- main
def main():
    sni = env_str("EDT_DOMAIN")
    if not sni:
        die("缺少环境变量 EDT_DOMAIN (你的 Cloudflare 域名, 用作 TLS SNI 测试)")
    pool_size = env_int("POOL_SIZE", 40)
    sample_size = env_int("SAMPLE_SIZE", 300)
    timeout = env_float("TIMEOUT", 8)
    workers = env_int("WORKERS", 32)
    min_keep = env_int("MIN_KEEP", 10)
    v6_ratio = env_float("V6_RATIO", 0)

    log("== 1/4 拉取 Cloudflare 官方 IP 段 ==")
    try:
        nets = [net for url in CF_SOURCES for net in fetch_cidrs(url)]
    except Exception as exc:
        die(f"拉取官方 IP 段失败: {exc}")
    if not nets:
        die("官方 IP 段为空")
    v4 = sum(1 for n in nets if n.version == 4)
    log(f"拿到 {len(nets)} 个网段 (v4: {v4}, v6: {len(nets) - v4})")

    log(f"== 2/4 随机采样 {sample_size} 个 IP ==")
    ips = sample_ips(nets, sample_size, v6_ratio)
    log(f"去重后 {len(ips)} 个")

    log(f"== 3/4 测 TLS 握手 (超时 {timeout:g}s, 并发 {workers}) ==")
    ok = probe_all(ips, sni, timeout, workers)
    log(f"测完: 可用 {len(ok)}/{len(ips)}")
    if len(ok) < min_keep:
        die(f"可用 IP 只有 {len(ok)} 个, 少于 MIN_KEEP={min_keep}, 拒绝提交坏池子")

    picked = ok[:pool_size]
    log(f"== 4/4 取最快 {len(picked)} 个写入池子 ==")
    for ip, ms in picked:
        log(f"  {ip}:443  {ms}ms")

    updated = now_bj()
    json_path = os.path.join(OUT_DIR, "pool.json")
    write_json(json_path, {
        "updated_at": updated,
        "source": list(CF_SOURCES),
        "sampled": len(ips),
        "reachable": len(ok),
        "entries": [{"ip": ip, "port": 443, "latency_ms": ms} for ip, ms in picked],
    }, indent=2)
    log(f"生成 {json_path}")

    uuid = env_str("EDT_UUID")
    if not uuid:
        log("未设置 EDT_UUID, 跳过 pool.txt / pool.yaml")
        return
    fp = env_str("SUB_FP", "chrome")
    nodes = build_nodes(picked)
    txt_path = os.path.join(OUT_DIR, "pool.txt")
    yaml_path = os.path.join(OUT_DIR, "pool.yaml")
    write_text(txt_path, build_links_text(nodes, uuid, sni, fp, updated))
    write_text(yaml_path, build_clash_text(nodes, uuid, sni, fp, updated))
    log(f"生成 {txt_path} / {yaml_path} ({len(nodes)} 个节点)")


if __name__ == "__main__":
    if "--check" in sys.argv[1:]:
        print("run=" + ("true" if need_refresh() else "false"))
        sys.exit(0)
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")
