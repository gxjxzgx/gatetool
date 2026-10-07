#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gate.py —— VPN Gate SSTP 节点检测 (工作流: gate.yml)

流程:
  1. 拉取 VPN Gate 原始节点 (官方 CSV, 失败时回退 GitHub 镜像)
  2. 只保留带 TCP 入口的中继 = SSTP 可用节点, 按 host+port 去重
  3. 并发调用检测服务 (CHECK_WORKER, 以返回 JSON 的 success 为准)
  4. 对可用节点做「转换后的 vless 延迟测速」: 像真实客户端一样连 EDT_DOMAIN 的 WebSocket
     (path 带 SSTP 链式代理), 发 VLESS 请求并经 SSTP 链访问测试地址, 记录往返耗时 vless_ms
  5. 按国家分组, 住宅 > 机房 > 未识别, 同类按 vless 延迟升序 (测速失败的排在后面)
  6. 输出到 OUT_DIR:
       sstp.json         网页数据 (公开, 含全部可用节点)
       sstp.txt          vless:// 订阅     (私有, 上传到 Worker)
       sstp.yaml         Clash / Mihomo    (私有)
       sstp-chains.txt   edgetunnel 链式代理清单 (公开)
       sstp-hosts.txt    edgetunnel「自定义优选IP」清单 (公开)
     住宅节点超过 MIN_ISP 个时, 机房节点只留在 sstp.json, 不进订阅 / 清单。

退出码: 0 正常; 1 硬性失败 (数据源全挂 / 解析不出节点 / 没有任何可用节点 / 程序异常)。
        任何情况都不会用空结果覆盖线上旧数据。

环境变量:
  EDT_UUID / EDT_DOMAIN   必填, edgetunnel 的 UUID 与域名
  EDT_FINGERPRINT         TLS 指纹, 默认 chrome
  CHECK_WORKER            必填, 检测服务地址前缀, 只在 gate.yml 里设置, 例:
                          https://check.socks5.cmliussss.net/check?sstp=vpn:vpn@
  WORKERS / TIMEOUT       检测并发 (默认 32) / 单请求超时秒数 (默认 90)
  VLESS_TEST              vless 延迟测速开关 (默认 1)
  VLESS_WORKERS           测速并发 (默认 16) / VLESS_TIMEOUT 单节点超时秒数 (默认 15)
  VLESS_TEST_URL          测速地址, 只支持 http:// (默认 http://cp.cloudflare.com/generate_204)
  VLESS_CONNECT           host:port, 覆盖实际连接地址 (如指定一个优选 IP), SNI / Host 仍为 EDT_DOMAIN
  MAX_CHECK_NODES         只检测前 N 个节点, 0=不限 (本地测试用)
  EXCLUDE_DC / MIN_ISP    机房节点排除开关 (默认 1) / 住宅数量阈值 (默认 20)
  OUT_DIR / SITE_URL      输出目录 / 站点根地址 (用于文件头部的固定地址注释)
  EDGE_HOSTS              逗号分隔的入口地址池, 覆盖内置列表
  SUB_URL                 可选, 写入 sstp.txt 头部的订阅地址
"""

import base64
import json
import os
import re
import socket
import ssl
import struct
import time
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote, urlsplit

from common import (
    OUT_DIR, REFRESH_TEXT, TYPE_ORDER, classify_host, clean_code, clean_country, country_label,
    decode_config, drop_datacenter, env_flag, env_float, env_int, env_str, fetch_vpngate_rows,
    http_fetch,
    make_logger, node_name, now_bj, parse_remote, type_rank, write_json, write_text,
)

log, die = make_logger("gate")

# ---------------------------------------------------------------- 配置
CHECK_WORKER = env_str("CHECK_WORKER")          # 不设默认值: 只在工作流里配置
WORKERS = max(1, env_int("WORKERS", 32))
TIMEOUT = env_float("TIMEOUT", 90)
MAX_CHECK_NODES = env_int("MAX_CHECK_NODES", 0)

VLESS_TEST = env_flag("VLESS_TEST", True)
VLESS_WORKERS = max(1, env_int("VLESS_WORKERS", 16))
VLESS_TIMEOUT = env_float("VLESS_TIMEOUT", 15)
VLESS_TEST_URL = env_str("VLESS_TEST_URL", "http://cp.cloudflare.com/generate_204")
VLESS_CONNECT = env_str("VLESS_CONNECT")

EDT_UUID = env_str("EDT_UUID")
EDT_DOMAIN = env_str("EDT_DOMAIN")
EDT_FINGERPRINT = env_str("EDT_FINGERPRINT", "chrome")

SITE_URL = env_str("SITE_URL").rstrip("/")


def site_file(name):
    return f"{SITE_URL}/{name}" if SITE_URL else name


# 出口数据中心关键词 (判断是否住宅 IP, 页面标注为估算)
DATA_CENTER_KEYWORDS = (
    "GOOGLE", "AMAZON", "AWS", "MICROSOFT", "OVH", "HETZNER", "DIGITALOCEAN",
    "AKAMAI", "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR",
    "HURRICANE", "TENCENT", "ALIBABA", "ALIYUN", "LEASWEB",
)
# 常见住宅宽带运营商关键词
RESIDENTIAL_KEYWORDS = (
    "NTT EAST", "NTT WEST", "NTT COMMUNICATIONS", "NTT BROADBAND", "KDDI", "DOCOMO",
    "SOFTBANK", "AU COMMUNICATIONS", "J:COM", "JCOM", "OCN", "BIGLOBE",
    "IIJ", "SEIKO", "CLEVER-NET", "AT&T", "COMCAST", "XFINITY", "VERIZON",
    "TELUS", "ROGERS", "BELL CANADA", "VODAFONE", "ORANGE", "DEUTSCHE TELEKOM",
    "BREEZE", "TIM S.P.A", "LIBERO", "FASTWEB", "FREE FRANCE", "BT OPEN",
)


def _keyword_re(words):
    """关键词匹配: 前面必须是词边界 (AWS 不会命中 LAWSON); 短关键词 (≤4 字符, 如 AWS / OVH / OCN)
    后面也要求词边界, 长关键词允许带后缀 (CLOUDFLARE 要能命中真实的 org 名 CLOUDFLARENET)。"""
    parts = [re.escape(w) + (r"(?![A-Z0-9])" if len(w) <= 4 else "") for w in words]
    return re.compile(r"(?<![A-Z0-9])(?:" + "|".join(parts) + ")")


DC_RE = _keyword_re(DATA_CENTER_KEYWORDS)
ISP_RE = _keyword_re(RESIDENTIAL_KEYWORDS)


# 入口地址池: 客户端直连 Cloudflare 的优选域名, 循环分配给每个节点 (端口统一 443)
EDGE_HOSTS_DEFAULT = (
    "www.mastervolt.com", "securecircle.com", "prizepicks.com", "jobsdb.com", "www.wto.org",
    "www.udacity.com", "thebeat.gehealthcare.com", "ex.warspite.dpdns.org", "mfa.gov.ua",
    "www.vmware.com", "academy.7shifts.com", "guide.for.edu.sg", "linear.app", "ikankeji.com",
    "login.rockwellautomation.com", "stores.staples.com", "53.fs1.hubspotusercontent-na1.net",
    "www.crazygames.fr", "www.sofi.com", "m.iyf.tv", "www.sloomb.com", "cdn.204910.best",
    "cf.nyanya.moe", "www.carousell.sg", "eii.at", "www.giannidelprete.it", "www.blibli.com",
    "auto.dolby.dpdns.org", "cf.877774.xyz", "funko.com", "kickstarter.com", "www.shopify.com",
    "serviceshub.samsclub.com", "fn.130519.xyz", "ahrefs.com", "markmonitor.com",
    "saas.072159.xyz", "www.deepl.com", "www.dbs.com.sg", "www.akasantech.com",
    "www.leics.police.uk", "coreweave.com", "staticdelivery.nexusmods.com", "www.jp.pima.gov",
    "api.gzcrtw.com", "www.mfyx.cn", "www.zendesk.com", "kniu.cc", "www.5199dy.com",
    "dongbanghong.com", "cdn.667891.xyz", "cdn.7zz.cn", "uspto.gov", "cf.itv888.cn",
    "wppaunz.com", "spring.io", "www.wuduanyun.com", "cf.468123.xyz", "www.bis.gov",
    "versantstore.pearson.com", "cloudflare.idc.rocks", "www.galgamex.net", "saas.sin.fan",
    "www.sage.com", "cf.3666888.xyz", "cf.xreak.top", "224322.xyz", "openai.com",
    "cdn.jwcmdr.top", "tt.78607323.xyz", "cf.1o.ee", "egov.uscis.gov", "www.xflash.vip",
    "vps.cheng2001.top", "ali.nonull.pp.ua", "baota.us.kg", "garuda-indonesia.com",
    "chrono24.com", "www.visa.com.hk", "cf.vvhan.com", "w3.org", "clickhouse.com",
    "www.redboxtools.com", "networksolutions.com", "shabak.gov.il",
)


# ---------------------------------------------------------------- 1~2. 筛选 SSTP 节点
def to_sstp_nodes(rows):
    """只保留带 TCP 入口的中继 (UDP-only 无法走 SSTP), 按 host+port 去重。"""
    nodes, seen = [], set()
    for r in rows:
        remote = parse_remote(decode_config(r["config_b64"]))
        if not remote or remote[2] != "tcp":
            continue
        host = r["host"] if r["host"].endswith(".opengw.net") else f"{r['host']}.opengw.net"
        if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host):
            continue
        key = (host.lower(), remote[1])
        if key in seen:
            continue
        seen.add(key)
        nodes.append({
            "host": host,
            "port": remote[1],
            "ip": r["ip"],
            "country": clean_country(r["country_long"]),
            "country_code": clean_code(r["country_short"]),
        })
    return nodes


# ---------------------------------------------------------------- 3. Worker 检测
def classify_network(host, exit_org, is_datacenter=None):
    """住宅 / 机房分类, 按可信度: Worker 的 is_datacenter 标志 > 出口 ASN 关键词 > 主机名前缀 (估算)。"""
    if is_datacenter is True:
        return "datacenter"
    if is_datacenter is False:
        return "residential"
    org = (exit_org or "").upper()
    if org:
        if DC_RE.search(org):
            return "datacenter"
        if ISP_RE.search(org):
            return "residential"
    return classify_host(host)


def check_node(node):
    """检测单个节点。网络错误 / 非 200 / 坏 JSON 都不抛异常, 记为 success=False 并标 worker_error。"""
    out = {
        **node,
        "protocol": "sstp",
        "link": f"sstp://vpn:vpn@{node['host']}:{node['port']}",
        "status": "failed",
        "success": False,
        "checked_at": now_bj(),
        "exit": None,
        "residential": "unknown",
    }
    url = CHECK_WORKER + quote(f"{node['host']}:{node['port']}", safe="")
    try:
        status, body = http_fetch(url, TIMEOUT)
        if status != 200:
            return {**out, "error": f"HTTP {status}", "worker_error": True}
        j = json.loads(body)
    except Exception as exc:
        return {**out, "error": f"{type(exc).__name__}: {exc}", "worker_error": True}

    ok = bool(j.get("success"))
    out.update(
        success=ok,
        status="success" if ok else "failed",
        latency_ms=j.get("responseTime"),
        colo=j.get("colo"),
        error=None if ok else (j.get("error") or j.get("message") or "check failed"),
    )
    info = j.get("exit") or {}
    if info:
        asn = info.get("asn") or {}
        loc = info.get("location") or {}
        org = asn.get("org") or asn.get("name") or ""
        out["exit"] = {
            "ip": info.get("ip"),
            "country": info.get("country") or loc.get("country"),
            "country_code": info.get("country_code") or loc.get("country_code"),
            "city": info.get("city") or loc.get("city"),
            "continent": info.get("continent") or loc.get("continent"),
            "asn": asn.get("asn"),
            "org": org,
            "type": asn.get("type"),
            "is_datacenter": info.get("is_datacenter"),
        }
        out["residential"] = classify_network(node["host"], org, info.get("is_datacenter"))
    else:
        out["residential"] = classify_network(node["host"], None, None)
    return out


# ---------------------------------------------------------------- 4. vless 延迟测速
def b64_secret_encode(plaintext, secret):
    """复刻 edgetunnel 的 base64SecretEncode: UTF-8 循环密钥 XOR + 标准 base64。"""
    data, key = plaintext.encode("utf-8"), secret.encode("utf-8")
    return base64.b64encode(bytes(b ^ key[i % len(key)] for i, b in enumerate(data))).decode("ascii")


def chain_path(node):
    """把 SSTP 节点编码成 edgetunnel 的 ws path (未做 URL 转义)。"""
    chain = {"type": "sstp", "username": "vpn", "password": "vpn", "hostname": node["host"], "port": node["port"]}
    return "/video/" + b64_secret_encode(json.dumps(chain, separators=(",", ":")), EDT_UUID)


# 默认校验证书: EDT_DOMAIN 应有有效证书 (Cloudflare 橙云即可)
TLS_CTX = ssl.create_default_context()
MAX_FRAME = 1 << 20


def vless_request(host, port, payload):
    """VLESS 请求头 (version 0, 无 addons, TCP, 域名地址) + 首包数据。"""
    addr = host.encode("ascii")
    return (b"\x00" + uuid.UUID(EDT_UUID).bytes + b"\x00" + b"\x01" + struct.pack(">H", port)
            + b"\x02" + bytes([len(addr)]) + addr + payload)


def ws_connect(sock, rfile, host, path):
    """WebSocket 升级握手, 非 101 抛异常。"""
    key = base64.b64encode(os.urandom(16)).decode()
    sock.sendall((
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n"
        f"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode())
    parts = rfile.readline(1024).split()
    if parts[1:2] != [b"101"]:
        raise ConnectionError(f"WebSocket 升级失败: {b' '.join(parts[:3])!r}")
    for _ in range(64):                                   # 丢弃响应头
        if rfile.readline(4096) in (b"\r\n", b"\n", b""):
            break


def ws_send(sock, payload):
    """发一个二进制帧。客户端帧必须带掩码。"""
    n = len(payload)
    head = bytearray([0x82])                              # FIN + binary
    if n < 126:
        head.append(0x80 | n)
    elif n < 65536:
        head += bytes([0x80 | 126]) + struct.pack(">H", n)
    else:
        head += bytes([0x80 | 127]) + struct.pack(">Q", n)
    mask = os.urandom(4)
    sock.sendall(bytes(head) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))


def _read_exact(rfile, n):
    data = rfile.read(n)
    if len(data) != n:
        raise EOFError("连接被对端关闭")
    return data


def ws_recv(rfile):
    """读一帧, 返回 (opcode, payload)。"""
    b0, b1 = _read_exact(rfile, 2)
    n = b1 & 0x7F
    if n == 126:
        n = struct.unpack(">H", _read_exact(rfile, 2))[0]
    elif n == 127:
        n = struct.unpack(">Q", _read_exact(rfile, 8))[0]
    if n > MAX_FRAME:
        raise ValueError("帧过大")
    mask = _read_exact(rfile, 4) if b1 & 0x80 else None
    data = _read_exact(rfile, n)
    if mask:
        data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    return b0 & 0x0F, data


def connect_addr():
    """实际 TCP 连接地址: 默认 EDT_DOMAIN:443, 可用 VLESS_CONNECT 指定 (如优选 IP)。"""
    if not VLESS_CONNECT:
        return EDT_DOMAIN, 443
    host, sep, port = VLESS_CONNECT.rpartition(":")
    return (host.strip("[]"), int(port)) if sep and port.isdigit() else (VLESS_CONNECT.strip("[]"), 443)


def vless_probe(node):
    """转换后的 vless 节点延迟 (毫秒), 失败返回 None。

    与客户端的真实路径一致: TLS → WebSocket (path 带 SSTP 链式代理) → VLESS 请求 →
    经 SSTP 链访问 VLESS_TEST_URL → 收到 HTTP 状态行。计时从发起 TCP 连接开始, 相当于
    Clash 的「延迟测试」。
    """
    target = urlsplit(VLESS_TEST_URL)
    host, port = target.hostname, target.port or 80
    http_req = (f"GET {target.path or '/'}{'?' + target.query if target.query else ''} HTTP/1.1\r\n"
                f"Host: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n").encode()
    t0 = time.monotonic()
    deadline = t0 + VLESS_TIMEOUT
    try:
        with socket.create_connection(connect_addr(), timeout=VLESS_TIMEOUT) as raw:
            with TLS_CTX.wrap_socket(raw, server_hostname=EDT_DOMAIN) as sock:
                rfile = sock.makefile("rb")
                ws_connect(sock, rfile, EDT_DOMAIN, chain_path(node))
                ws_send(sock, vless_request(host, port, http_req))
                buf = b""
                while time.monotonic() < deadline and len(buf) <= 65536:
                    sock.settimeout(max(0.2, deadline - time.monotonic()))
                    opcode, data = ws_recv(rfile)
                    if opcode == 8:                       # 对端关闭 = 链路不通
                        return None
                    if opcode not in (0, 1, 2):          # ping / pong 等控制帧忽略
                        continue
                    buf += data
                    if len(buf) < 2 or len(buf) < 2 + buf[1]:
                        continue                          # VLESS 响应头 (version + addons) 还没收全
                    status_line, sep, _ = buf[2 + buf[1]:].partition(b"\r\n")
                    if not sep:
                        continue
                    parts = status_line.split()
                    ok = (buf[0] == 0 and len(parts) >= 2 and parts[0].startswith(b"HTTP/")
                          and parts[1].isdigit() and 200 <= int(parts[1]) < 400)
                    return round((time.monotonic() - t0) * 1000) if ok else None
    except Exception:
        return None
    return None


def probe_vless_all(nodes):
    """并发测速, 结果写入每个节点的 vless_ms (失败为 None), 返回成功个数。"""
    with ThreadPoolExecutor(max_workers=VLESS_WORKERS) as pool:
        for node, ms in zip(nodes, pool.map(vless_probe, nodes)):
            node["vless_ms"] = ms
    return sum(1 for n in nodes if n["vless_ms"] is not None)


# ---------------------------------------------------------------- 5. 分组 / 排序
def node_type(node):
    t = node.get("residential")
    return t if t in ("residential", "datacenter") else "unknown"


def node_sort_key(node):
    """住宅 > 机房 > 未识别; 同类内 vless 延迟升序 (没测出来的在后), 再按检测服务延迟。"""
    vless, lat = node.get("vless_ms"), node.get("latency_ms")
    return (type_rank(node_type(node)), vless is None, vless or 0,
            lat is None, lat or 0, node.get("host") or "")


def fill_counts(grp):
    kinds = Counter(node_type(n) for n in grp["nodes"])
    grp["count"] = len(grp["nodes"])
    grp["residential"] = kinds["residential"]
    grp["datacenter"] = kinds["datacenter"]


def build_data(results, raw_count, sstp_count, source):
    available = [r for r in results if r["success"]]
    countries = {}
    for n in available:
        grp = countries.setdefault(n["country"] or "未知", {"code": n["country_code"] or "?", "nodes": []})
        grp["nodes"].append(n)
    for grp in countries.values():
        grp["nodes"].sort(key=node_sort_key)
        fill_counts(grp)

    kinds = Counter(node_type(n) for n in available)
    return {
        "generated_at": now_bj("%Y-%m-%d %H:%M:%S"),
        "source": source,
        "worker": CHECK_WORKER,
        "stats": {
            "raw_nodes": raw_count,
            "sstp_nodes": sstp_count,
            "checked": len(results),
            "success": len(available),
            "failed": len(results) - len(available),
            "vless_tested": sum(1 for n in available if "vless_ms" in n),
            "vless_ok": sum(1 for n in available if n.get("vless_ms") is not None),
            "countries": len(countries),
            "residential_est": kinds["residential"],
            "datacenter_est": kinds["datacenter"],
        },
        "countries": countries,
    }


def subscription_view(data):
    """写订阅 / 清单用的视图: 住宅足够多时去掉机房节点 (sstp.json 不受影响)。"""
    if not drop_datacenter(data["stats"]["residential_est"]):
        return data
    countries = {}
    for name, grp in data["countries"].items():
        nodes = [n for n in grp["nodes"] if node_type(n) != "datacenter"]
        if nodes:
            g = {**grp, "nodes": nodes}
            fill_counts(g)
            countries[name] = g
    return {**data, "countries": countries}


# ---------------------------------------------------------------- 6. 文本生成
def merged_countries(data):
    """按中文国名合并 (GB 与 UK 都叫英国, 编号连续), 返回 [(国名, 国家码, 排序后节点)], 节点多的国家在前。"""
    merged = {}
    for cname, grp in data["countries"].items():
        label = country_label(grp.get("code"), cname)
        m = merged.setdefault(label, {"codes": set(), "nodes": []})
        m["codes"].add(str(grp.get("code") or "?").upper())
        m["nodes"].extend(grp["nodes"])
    result = [(label, "/".join(sorted(m["codes"])), sorted(m["nodes"], key=node_sort_key))
              for label, m in merged.items()]
    return sorted(result, key=lambda x: (-len(x[2]), x[1]))


def iter_by_type(data):
    """每个国家产出 (标题注释, [(名字, 节点), ...])。所有 sstp 文件共用这一套名字: 国家-类型-序号-sstp。"""
    for label, codes, nodes in merged_countries(data):
        kinds = Counter(node_type(n) for n in nodes)
        title = (f"# ---- {label} {codes} · {len(nodes)} 节点 "
                 f"(住宅 {kinds['residential']} / 机房 {kinds['datacenter']} / 未识别 {kinds['unknown']}) ----")
        items = []
        for kind in TYPE_ORDER:
            same = [n for n in nodes if node_type(n) == kind]
            items.extend((node_name(label, kind, i, "sstp"), n) for i, n in enumerate(same, 1))
        yield title, items


def iter_named(data):
    """sub / clash 用: 与 chains / hosts 完全相同的名字和顺序, 只是不带分组标题。"""
    for _, items in iter_by_type(data):
        yield from items


def sstp_link(n):
    return f"$sstp://vpn:vpn@{n['host']}:{n['port']}"


def build_chains_text(data):
    lines = [
        "# VPN Gate SSTP 节点 -> edgetunnel 链式代理清单",
        f"# 自动更新: {data['generated_at']} ({REFRESH_TEXT}重新检测)",
        f"# 固定地址: {env_str('CHAIN_URL', site_file('sstp-chains.txt'))}",
        "#",
        "# 用法: 在 edgetunnel 节点备注里直接粘贴下面任意一行 (名字与指令连写)",
        "# 例: 日本-住宅-01-sstp$sstp://vpn:vpn@vpnxxx.opengw.net:443",
        f"# 名字保持不变, 只有 $sstp:// 后面的地址{REFRESH_TEXT}自动更换",
        "# 账号密码固定 vpn:vpn ; 端口必须保留",
        "# ========================================================",
    ]
    for title, items in iter_by_type(data):
        lines += ["", title, *(f"{name}{sstp_link(n)}" for name, n in items)]
    return "\n".join(lines) + "\n"


def build_hosts_text(data):
    entries = [e.strip() for e in env_str("HOSTS_ENTRY", env_str("EDGE_HOSTS")).split(",") if e.strip()]
    entries = [e if ":" in e else f"{e}:443" for e in entries] or [f"{h}:443" for h in EDGE_HOSTS_DEFAULT]
    lines = [
        "# edgetunnel「自定义优选IP」清单 (整段复制, 追加到后台现有内容后面)",
        f"# 自动更新: {data['generated_at']} ({REFRESH_TEXT}重新检测)",
        f"# 固定地址: {env_str('HOSTS_URL', site_file('sstp-hosts.txt'))}",
        "# 每行 = 入口地址#名字$sstp://vpn:vpn@节点:端口",
        "# 入口循环分配",
        "# 名字 = 国家-住宅/机房-编号, 直接区分住宅与机房",
        f"# 名字固定; 只有 $sstp:// 后面的节点地址{REFRESH_TEXT}自动更换",
        "# 账号密码固定 vpn:vpn ; 节点端口必须保留",
        "# ========================================================",
    ]
    idx = 0
    for title, items in iter_by_type(data):
        lines += ["", title]
        for name, n in items:
            lines.append(f"{entries[idx % len(entries)]}#{name}{sstp_link(n)}")
            idx += 1
    return "\n".join(lines) + "\n"


def build_sub_text(data):
    lines = [
        "# edgetunnel 完整订阅 (vless://) —— 填进后台「订阅链接」URL",
        f"# 自动更新: {data['generated_at']} ({REFRESH_TEXT}重新检测)",
    ]
    if env_str("SUB_URL"):
        lines.append(f"# 固定地址: {env_str('SUB_URL')}")
    lines += [
        f"# 节点域名: {EDT_DOMAIN} (传输 ws / TLS / fingerprint {EDT_FINGERPRINT})",
        f"# 名字固定; $sstp:// 链式代理(编码在 path){REFRESH_TEXT}自动更换",
        "# 账号密码固定 vpn:vpn ; 节点端口已编码进 path",
        "# ========================================================",
    ]
    for name, n in iter_named(data):
        lines.append(
            f"vless://{EDT_UUID}@{EDT_DOMAIN}:443?security=tls&type=ws"
            f"&host={EDT_DOMAIN}&fp={EDT_FINGERPRINT}&sni={EDT_DOMAIN}"
            f"&path={quote(chain_path(n), safe='')}&encryption=none&alpn=#{quote(name, safe='')}"
        )
    return "\n".join(lines) + "\n"


def build_clash_text(data):
    """Clash / Mihomo 配置。节点用 JSON 写法 (JSON 是合法 YAML), 免去特殊字符转义问题。"""
    names, items = [], []
    for name, n in iter_named(data):
        names.append(name)
        items.append("  - " + json.dumps({
            "name": name,
            "type": "vless",
            "server": EDT_DOMAIN,
            "port": 443,
            "uuid": EDT_UUID,
            "udp": True,
            "tls": True,
            "network": "ws",
            "servername": EDT_DOMAIN,
            "client-fingerprint": EDT_FINGERPRINT,
            "ws-opts": {"path": chain_path(n), "headers": {"Host": EDT_DOMAIN}},
        }, ensure_ascii=False))

    auto = {
        "name": "自动", "type": "url-test", "proxies": names or ["DIRECT"],
        "url": "https://www.gstatic.com/generate_204", "interval": 300, "tolerance": 100,
    }
    main_group = {"name": "PROXY", "type": "select", "proxies": ["自动", *names, "DIRECT"]}
    lines = [
        f"# 自动更新: {data['generated_at']} ({REFRESH_TEXT}重新检测)",
        "mixed-port: 7890",
        "mode: rule",
        "log-level: info",
        "dns:",
        "  enable: true",
        "  nameserver: [223.5.5.5, 119.29.29.29]",
        "proxies:",
        *items,
        "proxy-groups:",
        "  - " + json.dumps(main_group, ensure_ascii=False),
        "  - " + json.dumps(auto, ensure_ascii=False),
        "rules:",
        "  - GEOIP,CN,DIRECT",
        "  - MATCH,PROXY",
    ]
    return "\n".join(lines) + "\n"


def write_outputs(data):
    sub = subscription_view(data)
    files = (
        ("sstp.json", None),
        ("sstp-chains.txt", build_chains_text(sub)),
        ("sstp-hosts.txt", build_hosts_text(sub)),
        ("sstp.txt", build_sub_text(sub)),
        ("sstp.yaml", build_clash_text(sub)),
    )
    paths = []
    for name, text in files:
        path = os.path.join(OUT_DIR, name)
        if text is None:
            write_json(path, data)
        else:
            write_text(path, text)
        paths.append(path)
    return paths


# ---------------------------------------------------------------- main
def main():
    if not EDT_UUID or not EDT_DOMAIN:
        die("缺少环境变量 EDT_UUID / EDT_DOMAIN (检查 GitHub Secrets 是否已配置)")
    if not CHECK_WORKER:
        die("缺少环境变量 CHECK_WORKER (检测服务地址前缀, 在 gate.yml 的 env 里设置)")
    try:
        uuid.UUID(EDT_UUID)
    except ValueError:
        die("EDT_UUID 不是合法的 UUID, 无法生成 / 测试 vless 节点")
    if VLESS_TEST and urlsplit(VLESS_TEST_URL).scheme != "http":
        die(f"VLESS_TEST_URL 只支持 http:// 地址, 当前: {VLESS_TEST_URL}")

    log("== 1/5 拉取 VPN Gate 数据 ==")
    try:
        rows, source = fetch_vpngate_rows(log)
    except RuntimeError as exc:
        die(f"所有数据源都不可用: {exc}")

    log("== 2/5 筛选 SSTP(TCP) 节点 ==")
    nodes = to_sstp_nodes(rows)
    if not nodes:
        die(f"从 {len(rows)} 个原始节点中没有解析出任何 SSTP(TCP) 节点, 数据格式可能已变化")
    sstp_count = len(nodes)
    if MAX_CHECK_NODES > 0:
        nodes = nodes[:MAX_CHECK_NODES]
    log(f"原始 {len(rows)} -> SSTP 去重后 {sstp_count}, 本次检测 {len(nodes)}")

    log(f"== 3/5 检测服务检测 (并发 {WORKERS}, 单请求超时 {TIMEOUT:g}s) ==")
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        results = list(pool.map(check_node, nodes))
    success = [r for r in results if r["success"]]
    worker_errors = [r for r in results if r.get("worker_error")]
    log(f"成功 {len(success)} / 失败 {len(results) - len(success)}"
        + (f" (Worker 异常 {len(worker_errors)})" if worker_errors else "")
        + f", 耗时 {time.time() - t0:.1f}s")
    if not success:
        reason = "Worker 全部请求异常, 检测服务不可用" if len(worker_errors) == len(results) \
            else "没有任何可用节点 (检测均返回 success=false)"
        die(f"{reason}; 不生成空结果, 保留线上旧数据")

    if VLESS_TEST:
        log(f"== 4/5 vless 延迟测速 (并发 {VLESS_WORKERS}, 超时 {VLESS_TIMEOUT:g}s, 目标 {VLESS_TEST_URL}) ==")
        t1 = time.time()
        vless_ok = probe_vless_all(success)
        log(f"vless 可用 {vless_ok}/{len(success)}, 耗时 {time.time() - t1:.1f}s")
        if not vless_ok:
            log("警告: 所有节点 vless 测速都失败, 请检查 EDT_DOMAIN / EDT_UUID 与 edgetunnel 是否正常; 页面延迟将显示 -")
    else:
        log("== 4/5 vless 延迟测速: 已关闭 (VLESS_TEST=0) ==")

    log("== 5/5 生成输出文件 ==")
    data = build_data(results, len(rows), sstp_count, source)
    st = data["stats"]
    if drop_datacenter(st["residential_est"]):
        log(f"住宅 {st['residential_est']} 个, 机房 {st['datacenter_est']} 个只在网页显示, 不写入订阅 / 清单")
    else:
        log(f"住宅 {st['residential_est']} 个 (未超过阈值或未启用排除), 机房 {st['datacenter_est']} 个一并写入")
    for path in write_outputs(data):
        log(f"生成 {path}")
    log(f"完成: 可用 {st['success']} 个节点, {st['countries']} 个国家")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")
