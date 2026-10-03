#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare 边缘优选池自动刷新。

数据源 : Cloudflare 官方公布的 IP 段
          https://www.cloudflare.com/ips-v4
          https://www.cloudflare.com/ips-v6
流程   : 拉取 IP 段 -> 随机采样 -> 并发测 443 端口 TLS 握手延迟
          (SNI = 自己的域名, 握手成功即证明该 IP 是可用 CF 边缘)
          -> 按延迟排序取前 POOL_SIZE 个 -> 写入 pool.json (监控页用)
          -> 生成 pool.txt (vless 明文订阅) / pool.yaml (Clash 订阅)

只用标准库, 无第三方依赖。

环境变量:
  EDT_DOMAIN   必填, 你自己的域名(已托管在 Cloudflare), 用作 TLS SNI 测试
  POOL_SIZE    选填, 保留最快的前 N 个, 默认 40
  SAMPLE_SIZE  选填, 每轮采样的 IP 数量, 默认 300
  TIMEOUT      选填, 单 IP 连接/握手超时秒数, 默认 8
  MIN_KEEP     选填, 可用 IP 少于此数则报错退出(防止提交坏池子), 默认 10
  WORKERS      选填, 并发线程数, 默认 32; 设为 1 则串行(网络受限环境用)
  V6_RATIO     选填, 采样中 IPv6 占比, 默认 0 (只采 IPv4; 设为如 0.15 则混采)
  OUT_DIR      选填, 输出目录, 默认脚本所在目录
  EDT_UUID     选填, 你的 edgetunnel UUID; 设置后额外生成 pool.txt
               (vless 订阅, 每个池子 IP 一条直连节点)
  SUB_PATH     选填, 覆盖默认的 WS 路径格式 (默认: /随机伪装路径/proxyip=池子IP)
  SUB_FP       选填, TLS fingerprint, 默认 chrome
  SUB_PREFIX   选填, 订阅节点名前缀; 为空则按 IP 类型自动命名
               (IPv4 -> IPv4优选, IPv6 -> IPv6优选, 与 worker 别名规则一致)
"""

import concurrent.futures as futures
import ipaddress
import json
import os
import random
import socket
import ssl
import sys
import time
import urllib.request
from urllib.parse import quote
from datetime import datetime, timezone, timedelta

IPV4_URL = "https://www.cloudflare.com/ips-v4"
IPV6_URL = "https://www.cloudflare.com/ips-v6"
BEIJING = timezone(timedelta(hours=8))


def log(msg):
    print(msg, flush=True)


def die(msg):
    log(f"[失败] {msg}")
    sys.exit(1)


def fetch_cidrs(url, timeout=30):
    """拉取官方 IP 段列表, 返回 ipaddress 网络对象列表。"""
    req = urllib.request.Request(url, headers={"User-Agent": "cf-edge-pool/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        text = r.read().decode("utf-8")
    nets = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            nets.append(ipaddress.ip_network(line))
        except ValueError:
            log(f"[警告] 跳过无法解析的行: {line}")
    return nets


def sample_ips(nets, count, v6_ratio=0.15):
    """从各网段随机采样。v4/v6 按比例分配(v6 网段地址空间巨大,
    不能按地址数加权, 否则几乎全采到 v6)。返回去重后的 IP 字符串列表。"""
    v4_nets = [n for n in nets if n.version == 4]
    v6_nets = [n for n in nets if n.version == 6]
    v6_count = round(count * v6_ratio) if v6_nets else 0
    v4_count = count - v6_count
    picked = set()
    for nets_part, c in ((v4_nets, v4_count), (v6_nets, v6_count)):
        if not nets_part or c <= 0:
            continue
        weights = [n.num_addresses for n in nets_part]
        total = sum(weights)
        for _ in range(c):
            r = random.uniform(0, total)
            acc = 0
            for net, w in zip(nets_part, weights):
                acc += w
                if r <= acc:
                    base = int(net.network_address)
                    lo = base + 1
                    hi = base + net.num_addresses - 2
                    ip = (net.network_address if hi < lo
                          else ipaddress.ip_address(random.randint(lo, hi)))
                    picked.add(str(ip))
                    break
    return sorted(picked)


def test_one(ip, sni, timeout):
    """对单个 IP 做 TCP+TLS 握手, 返回 (ip, 延迟毫秒或 None)。"""
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((ip, 443), timeout=timeout)
        # 只验证"握手能成功", 不校验证书(测的是连通性和延迟)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls = ctx.wrap_socket(sock, server_hostname=sni)
        tls.do_handshake()
        tls.close()
        ms = (time.monotonic() - t0) * 1000
        return ip, round(ms, 1)
    except Exception:
        return ip, None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


# 随机伪装路径词表 (模仿真实网站路径, 后接 /proxyip=池子IP)
_CAMO_WORDS = ["act", "api", "app", "assets", "channel", "classify", "comic",
               "details", "doc", "docs", "download", "favorite", "forum",
               "jump", "knowledge", "list", "magnet", "out", "pdf", "project",
               "service", "static", "store", "video", "view", "search",
               "index", "home", "page", "item", "feed"]


def _random_camo_path():
    n = random.randint(1, 3)
    parts = random.sample(_CAMO_WORDS, n)
    parts = [p + ".html" if random.random() < 0.25 else p for p in parts]
    return "/" + "/".join(parts)


def main():
    sni = os.environ.get("EDT_DOMAIN", "").strip()
    if not sni:
        die("缺少环境变量 EDT_DOMAIN (你的 Cloudflare 域名, 用作 TLS SNI 测试)")
    pool_size = int(os.environ.get("POOL_SIZE", "40"))
    sample_size = int(os.environ.get("SAMPLE_SIZE", "300"))
    timeout = float(os.environ.get("TIMEOUT", "8"))
    min_keep = int(os.environ.get("MIN_KEEP", "10"))
    workers = int(os.environ.get("WORKERS", "32"))
    v6_ratio = float(os.environ.get("V6_RATIO", "0"))
    out_dir = os.environ.get("OUT_DIR", os.path.dirname(os.path.abspath(__file__)))
    os.makedirs(out_dir, exist_ok=True)

    log("== 1/4 拉取 Cloudflare 官方 IP 段 ==")
    try:
        nets = fetch_cidrs(IPV4_URL) + fetch_cidrs(IPV6_URL)
    except Exception as exc:
        die(f"拉取官方 IP 段失败: {exc}")
    if not nets:
        die("官方 IP 段为空")
    v4 = sum(1 for n in nets if n.version == 4)
    log(f"拿到 {len(nets)} 个网段 (v4: {v4}, v6: {len(nets) - v4})")

    log(f"== 2/4 随机采样 {sample_size} 个 IP ==")
    ips = sample_ips(nets, sample_size, v6_ratio)
    log(f"去重后 {len(ips)} 个")

    log(f"== 3/4 测 TLS 握手 (SNI 已设置, 超时 {timeout}s, 并发 {workers}) ==")
    ok = []
    if workers <= 1:
        for i, ip in enumerate(ips, 1):
            _, ms = test_one(ip, sni, timeout)
            if ms is not None:
                ok.append((ip, ms))
            if i % 20 == 0:
                log(f"  进度 {i}/{len(ips)}, 可用 {len(ok)}")
    else:
        with futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(test_one, ip, sni, timeout): ip for ip in ips}
            done = 0
            for fut in futures.as_completed(futs):
                done += 1
                ip, ms = fut.result()
                if ms is not None:
                    ok.append((ip, ms))
                if done % 50 == 0:
                    log(f"  进度 {done}/{len(ips)}, 可用 {len(ok)}")
    ok.sort(key=lambda x: x[1])
    log(f"测完: 可用 {len(ok)}/{len(ips)}")

    if len(ok) < min_keep:
        die(f"可用 IP 只有 {len(ok)} 个, 少于 MIN_KEEP={min_keep}, 拒绝提交坏池子")

    picked = ok[:pool_size]
    log(f"== 4/4 取最快 {len(picked)} 个写入池子 ==")
    for ip, ms in picked:
        log(f"  {ip}:443  {ms}ms")

    now = datetime.now(BEIJING).strftime("%Y-%m-%d %H:%M")
    # pool.json 只供监控页用, 不对外发布下载
    json_path = os.path.join(out_dir, "pool.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "updated_at": now,
                "source": ["https://www.cloudflare.com/ips-v4",
                           "https://www.cloudflare.com/ips-v6"],
                "sampled": len(ips),
                "reachable": len(ok),
                "entries": [
                    {"ip": ip, "port": 443, "latency_ms": ms} for ip, ms in picked
                ],
            },
            f, ensure_ascii=False, indent=2,
        )
    log(f"已写入 {json_path} (仅供监控页)")

    # 5/4 可选: 生成 vless 订阅 (每个池子 IP 一条直连节点)
    #   pool.txt 明文链接 (连接格式), pool.yaml Clash 订阅 (proxies 列表)
    uuid = os.environ.get("EDT_UUID", "").strip()
    if uuid and uuid != "REPLACE_WITH_YOUR_EDT_UUID":
        sub_path_override = os.environ.get("SUB_PATH", "").strip()
        fp = os.environ.get("SUB_FP", "chrome")
        prefix = os.environ.get("SUB_PREFIX", "").strip()
        counters = {}
        proxy_ips = ",".join(ip for ip, _ in random.sample(picked, min(8, len(picked))))
        nodes = []  # (name, ip, ws_path)
        link_lines = []
        for ip, _ in picked:
            host = f"[{ip}]" if ":" in ip else ip
            label = prefix or ("IPv6优选" if ":" in ip else "IPv4优选")
            counters[label] = counters.get(label, 0) + 1
            name = f"{label}-{counters[label]:02d}"
            ws_path = sub_path_override or f"{_random_camo_path()}/proxyip={proxy_ips}"
            nodes.append((name, ip, ws_path))
            link_lines.append(
                f"vless://{uuid}@{host}:443?encryption=none&security=tls"
                f"&type=ws&host={sni}&fp={fp}&sni={sni}"
                f"&path={quote(ws_path, safe='')}#{quote(name, safe='')}"
            )
        sub_path = os.path.join(out_dir, "pool.txt")
        with open(sub_path, "w", encoding="utf-8") as f:
            f.write("# Cloudflare 边缘优选订阅 (vless:// 明文, 自动刷新)\n")
            f.write(f"# 更新时间: {now} (北京时间)\n")
            f.write(f"# 每个池子 IP 一条直连节点, SNI={sni}, 共 {len(picked)} 个\n")
            f.write("\n".join(link_lines) + "\n")
        clash_path = os.path.join(out_dir, "pool.yaml")
        with open(clash_path, "w", encoding="utf-8") as f:
            f.write("# Cloudflare 边缘优选 Clash 订阅 (自动刷新)\n")
            f.write(f"# 更新时间: {now} (北京时间)\n")
            f.write("proxies:\n")
            for name, ip, ws_path in nodes:
                f.write(f"  - name: \"{name}\"\n")
                f.write("    type: vless\n")
                f.write(f"    server: {ip}\n")
                f.write("    port: 443\n")
                f.write(f"    uuid: {uuid}\n")
                f.write("    tls: true\n")
                f.write(f"    servername: {sni}\n")
                f.write("    client-fingerprint: chrome\n")
                f.write("    network: ws\n")
                f.write("    ws-opts:\n")
                f.write(f"      path: \"{ws_path}\"\n")
                f.write("      headers:\n")
                f.write(f"        Host: {sni}\n")
                f.write("    udp: true\n")
                f.write("    ech-opts:\n")
                f.write("      enable: true\n")
                f.write("      query-server-name: cloudflare-ech.com\n")
        log(f"已写入 {sub_path} / {clash_path} ({len(picked)} 个节点)")
    else:
        log("未设置 EDT_UUID, 跳过 pool.txt/pool.yaml 生成")


if __name__ == "__main__":
    main()
