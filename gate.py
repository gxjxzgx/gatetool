#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gate.py —— VPN Gate SSTP 节点检测 (工作流: gate.yml)

流程:
  1. 拉取 VPN Gate 原始节点 (官方 CSV, 失败时回退 GitHub 镜像)
  2. 只保留带 TCP 入口的中继 = SSTP 可用节点, 按 host+port 去重
  3. 并发调用 Cloudflare Worker 检测 (以返回 JSON 的 success 为准)
  4. 按国家分组, 住宅 > 机房 > 未识别, 同类按延迟升序
  5. 输出到 OUT_DIR:
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
  CHECK_WORKER            检测 Worker 地址前缀
  WORKERS / TIMEOUT       检测并发 (默认 32) / 单请求超时秒数 (默认 90)
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
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

from common import (
    OUT_DIR, REFRESH_TEXT, classify_host, clean_code, clean_country, decode_config,
    drop_datacenter, env_float, env_int, env_str, fetch_vpngate_rows, http_fetch,
    make_logger, now_bj, parse_remote, type_rank, write_json, write_text,
)

log, die = make_logger("gate")

# ---------------------------------------------------------------- 配置
CHECK_WORKER = env_str("CHECK_WORKER")
WORKERS = max(1, env_int("WORKERS", 32))
TIMEOUT = env_float("TIMEOUT", 90)
MAX_CHECK_NODES = env_int("MAX_CHECK_NODES", 0)

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

TYPE_GROUPS = (("住宅", "residential"), ("机房", "datacenter"), ("未识别", "unknown"))


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
        org = asn.get("org") or asn.get("name") or ""
        out["exit"] = {
            "ip": info.get("ip"),
            "country": info.get("country"),
            "country_code": info.get("country_code"),
            "city": info.get("city"),
            "continent": info.get("continent"),
            "asn": asn.get("asn"),
            "org": org,
            "type": asn.get("type"),
            "is_datacenter": info.get("is_datacenter"),
        }
        out["residential"] = classify_network(node["host"], org, info.get("is_datacenter"))
    else:
        out["residential"] = classify_network(node["host"], None, None)
    return out


# ---------------------------------------------------------------- 4. 分组 / 排序
def node_type(node):
    t = node.get("residential")
    return t if t in ("residential", "datacenter") else "unknown"


def node_sort_key(node):
    """住宅 > 机房 > 未识别, 同类内延迟升序。"""
    lat = node.get("latency_ms")
    return type_rank(node_type(node)), lat is None, lat or 0, node.get("host") or ""


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


# ---------------------------------------------------------------- 5. 文本生成
def country_label(code, cname):
    code = str(code or "?").upper()
    return COUNTRY_ZH.get(code) or (code if code != "?" else cname)


def sorted_countries(data):
    """国家按节点数降序, 同数量按国家码排序。"""
    return sorted(data["countries"].items(), key=lambda kv: (-kv[1]["count"], str(kv[1].get("code") or kv[0])))


def iter_named(data):
    """按「国家 → 排序后节点」产出 (名字, 节点); 不同国家码映射到同一中文名时自动避免重名。"""
    used = set()
    for cname, grp in sorted_countries(data):
        zh = country_label(grp.get("code"), cname)
        for i, n in enumerate(sorted(grp["nodes"], key=node_sort_key), 1):
            name, k = f"{zh}-{i:02d}-sstp", 2
            while name in used:
                name, k = f"{zh}-{i:02d}-{k}-sstp", k + 1
            used.add(name)
            yield name, n


def iter_by_type(data):
    """chains / hosts 用: 每个国家产出 (标题注释, [(名字, 节点), ...]), 名字带 住宅/机房/未识别 与分类内序号。"""
    for cname, grp in sorted_countries(data):
        code = str(grp.get("code") or "?").upper()
        zh = country_label(code, cname)
        nodes = sorted(grp["nodes"], key=node_sort_key)
        unknown = grp["count"] - grp["residential"] - grp["datacenter"]
        title = (f"# ---- {zh} {code} · {grp['count']} 节点 "
                 f"(住宅 {grp['residential']} / 机房 {grp['datacenter']} / 未识别 {unknown}) ----")
        items = []
        for label, kind in TYPE_GROUPS:
            same = [n for n in nodes if node_type(n) == kind]
            items.extend((f"{zh}-{label}-{i:02d}-sstp", n) for i, n in enumerate(same, 1))
        yield title, items


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


def b64_secret_encode(plaintext, secret):
    """复刻 edgetunnel 的 base64SecretEncode: UTF-8 循环密钥 XOR + 标准 base64。"""
    data, key = plaintext.encode("utf-8"), secret.encode("utf-8")
    return base64.b64encode(bytes(b ^ key[i % len(key)] for i, b in enumerate(data))).decode("ascii")


def chain_path(node):
    """把 SSTP 节点编码成 edgetunnel 的 ws path (未做 URL 转义)。"""
    chain = {"type": "sstp", "username": "vpn", "password": "vpn", "hostname": node["host"], "port": node["port"]}
    return "/video/" + b64_secret_encode(json.dumps(chain, separators=(",", ":")), EDT_UUID)


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

    log("== 1/4 拉取 VPN Gate 数据 ==")
    try:
        rows, source = fetch_vpngate_rows(log)
    except RuntimeError as exc:
        die(f"所有数据源都不可用: {exc}")

    log("== 2/4 筛选 SSTP(TCP) 节点 ==")
    nodes = to_sstp_nodes(rows)
    if not nodes:
        die(f"从 {len(rows)} 个原始节点中没有解析出任何 SSTP(TCP) 节点, 数据格式可能已变化")
    sstp_count = len(nodes)
    if MAX_CHECK_NODES > 0:
        nodes = nodes[:MAX_CHECK_NODES]
    log(f"原始 {len(rows)} -> SSTP 去重后 {sstp_count}, 本次检测 {len(nodes)}")

    log(f"== 3/4 Worker 检测 (并发 {WORKERS}, 单请求超时 {TIMEOUT:g}s) ==")
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

    log("== 4/4 生成输出文件 ==")
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
