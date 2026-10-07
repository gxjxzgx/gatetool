# gate

三条独立的自动刷新流水线, 共用一个 GitHub Pages 站点和**一个监控页**(`index.html`)。
脚本名与工作流同名: `gate.yml` → `gate.py`, `ovpn.yml` → `ovpn.py`, `pool.yml` → `pool.py`。
三个脚本共用 `common.py` (日志、环境变量、HTTP、VPN Gate 解析、原子写文件), **只用 Python 标准库, 无需安装依赖**。

数据文件命名规则: `<名称>.<格式>` (名称 = sstp / ovpn / pool)。

| 工作流 | 脚本 | 频率 | 输出 |
|---|---|---|---|
| `gate.yml` | `gate.py` | 每小时 | `sstp.json`(含机房节点) `sstp-chains.txt` `sstp-hosts.txt` 发布到 Pages; `sstp.txt`(vless 订阅) `sstp.yaml`(Clash) 上传私有 Worker。住宅节点 > 20 个时, 订阅/清单不含机房节点 |
| `ovpn.yml` | `ovpn.py` | 每小时 | `ovpn.json`(Pages, 含机房节点); `ovpn.yaml`(Clash, 私有 Worker; 住宅节点 > 20 个时不含机房节点) |
| `pool.yml` | `pool.py` | 每天检查, 周日(北京时间)刷新 | `pool.json`(Pages); `pool.txt`(vless 订阅) `pool.yaml`(Clash) 上传私有 Worker |

数据文件只在工作流运行时生成并发布, 不提交到仓库。

> 刷新频率改动时, 同步修改 `common.py` 里的 `REFRESH_TEXT` (它会写进订阅文件头部的说明文字)。

## SSTP 检测与 vless 延迟测速

`gate.py` 分两步:

1. **可用性**: 调用检测服务 (`CHECK_WORKER`, 即 [CF-Workers-CheckSocks5](https://github.com/cmliu/CF-Workers-CheckSocks5)
   的 `/check?sstp=账号:密码@主机:端口`) 判定节点能否经 SSTP 连出, 同时取得出口 IP / 运营商, 用于住宅 / 机房估算。
2. **vless 延迟**: 对可用节点做「转换后的 vless 延迟测速」。脚本像真实客户端一样连 `EDT_DOMAIN` 的
   WebSocket (path 带 SSTP 链式代理, 与 `sstp.txt` 里的节点完全一致), 发 VLESS 请求并经 SSTP 链访问
   `VLESS_TEST_URL`, 记录从发起连接到收到 HTTP 响应的耗时, 写入 `sstp.json` 的 `vless_ms`。

- 监控页的「vless 延迟」列显示 `vless_ms`, 「-」表示测速失败 (节点仍保留, 只是排在后面)。
- 订阅 / 清单里同一类型内按 `vless_ms` 升序排列, 序号随之变化。
- 测速需要 `EDT_UUID` 是合法 UUID, 且 `EDT_DOMAIN` 有有效证书 (脚本会校验证书)。
- 测速在 Actions 里完成, **UUID 不会进入公开页面**; 页面只读 `sstp.json` 里的延迟数字。
- 如果所有节点测速都失败, 日志会给出警告, 请检查 `EDT_DOMAIN` / `EDT_UUID` 与 edgetunnel 是否正常。

## 节点命名

所有输出文件使用同一条规则: **`地区-类型-序号-协议`**。

| 文件 | 示例 |
|---|---|
| `sstp-chains.txt` `sstp-hosts.txt` `sstp.txt` `sstp.yaml` | `日本-住宅-01-sstp` `日本-机房-01-sstp` `日本-未识别-01-sstp` |
| `ovpn.yaml` | `日本-住宅-01-ovpn` `日本-机房-01-ovpn` |
| `pool.txt` `pool.yaml` | `IPv4优选-01` `IPv6优选-01` (无国家 / 类型, 不加协议后缀) |

- 类型只有三种: 住宅 / 机房 / 未识别 (按出口运营商或主机名估算, 仅供参考)。
- 地区用中文国名 (对照表见 `common.py` 的 `COUNTRY_ZH`, 未收录的显示国家码); 国家码不同但中文名相同的 (如 GB 与 UK 都是"英国") 合并后连续编号, 不会重名。
- 序号在「同一地区 + 同一类型」内从 01 开始, 按住宅 → 机房 → 未识别排列, 同类内延迟从低到高。
- 同一个 sstp 节点在 4 个 sstp 文件里名字、顺序完全相同。
- 修改规则只需改 `common.py` 的 `node_name()` 和 `TYPE_LABEL`。
- 设置了 `SUB_PREFIX` 时, pool 节点名变为 `<前缀>-01`。
- 节点名里不使用 emoji / 图标。

## 目录

```
common.py              共用工具
gate.py / ovpn.py / pool.py
tools/prepare_site.sh  从线上取回旧数据文件 (取回后会校验内容)
tools/upload_private.sh  把私有订阅上传到 Worker, 并确保不留在站点目录
web/index.html         监控页
worker/                私有订阅托管 Worker
.github/workflows/     三个工作流
```

## 站点

`https://<用户>.github.io/<仓库>/` 打开 `index.html`, 一页显示三块: 优选池 / OpenVPN / SSTP。
页面读取同目录的 `pool.json` `ovpn.json` `sstp.json`。OpenVPN 与 SSTP 列表均按 住宅 → 机房 → 未识别 排序。
页面每 5 分钟自动刷新, 刷新时会保留你已展开的国家分组。

## 为什么每个工作流都先恢复站点

Pages 每次部署都是整站替换。每个工作流开头运行 `tools/prepare_site.sh`,
把线上已有的数据文件取回 `site/` (内容无效的文件会丢弃, 不会被重新部署), 只刷新自己负责的部分, 再整站部署,
三个工作流互不覆盖。三者共用并发组 `site-publish`, 串行执行。

## 部署

1. Settings → Actions → General → Workflow permissions 选 **Read and write permissions**。
2. Settings → Secrets and variables → Actions 添加 secrets: `EDT_DOMAIN`、`EDT_UUID`。
3. 用自定义域名时, 在 Variables 里加 `PAGES_URL` (站点根地址, 不带末尾 `/`)。
4. 在 GitHub 网页上手动创建 `.github/workflows/` 下三个 yml (API 推不了 workflows 文件)。
5. Actions 页依次手动运行 `CF Edge Pool Refresh`、`OpenVPN Refresh`、`Gate SSTP Check` 各一次。

## 环境变量

三个脚本使用同一套命名, 工作流里按需覆盖。空字符串视为未设置 (GitHub 里没配的 secret 就是空字符串)。

| 变量 | 脚本 | 默认 | 说明 |
|---|---|---|---|
| `OUT_DIR` | 全部 | `site` | 输出目录 |
| `WORKERS` | 全部 | 32 | 并发数 (pool 设为 1 则串行) |
| `TIMEOUT` | 全部 | gate 90 / ovpn 5 / pool 8 | 单次检测超时秒数 |
| `EXCLUDE_DC` / `MIN_ISP` | gate, ovpn | 1 / 20 | 住宅节点超过阈值时, 订阅里剔除机房节点 |
| `EDT_UUID` / `EDT_DOMAIN` | gate, pool | — | gate 必填两个; pool 必填 `EDT_DOMAIN`, `EDT_UUID` 可选 |
| `EDT_FINGERPRINT` / `SUB_FP` | gate / pool | chrome | TLS 指纹 |
| `CHECK_WORKER` | gate | **无默认值, 必填** | 检测服务地址前缀, 只在 `gate.yml` 里设置 (当前 `https://check.socks5.cmliussss.net/check?sstp=vpn:vpn@`) |
| `VLESS_TEST` | gate | 1 | vless 延迟测速开关 |
| `VLESS_WORKERS` / `VLESS_TIMEOUT` | gate | 16 / 15 | 测速并发 / 单节点超时秒数 |
| `VLESS_TEST_URL` | gate | `http://cp.cloudflare.com/generate_204` | 测速地址, 只支持 http:// |
| `VLESS_CONNECT` | gate | `EDT_DOMAIN:443` | 覆盖实际连接地址 (如指定优选 IP), SNI / Host 仍为 `EDT_DOMAIN` |
| `MAX_CHECK_NODES` | gate | 0 | 只检测前 N 个, 本地测试用 |
| `EDGE_HOSTS` | gate | 内置 85 个 | 逗号分隔的入口地址池 |
| `KEEP_UDP` / `MAX_YAML` | ovpn | 1 / 0 | 是否保留无法检测的 UDP 节点 / yaml 最多保留数 |
| `POOL_SIZE` / `SAMPLE_SIZE` / `MIN_KEEP` / `V6_RATIO` | pool | 40 / 300 / 10 / 0 | 池大小 / 采样数 / 最少可用数 / IPv6 占比 |
| `SUB_PATH` / `SUB_PREFIX` | pool | — | 覆盖 WS 路径 / 节点名前缀 |
| `VPNGATE_API` / `VPNGATE_MIRROR` | gate, ovpn | 官方 / GitHub 镜像 | 数据源 |

本地试跑示例: `OUT_DIR=/tmp/site EDT_UUID=x EDT_DOMAIN=example.com MAX_CHECK_NODES=20 python gate.py`

## 失败保护

三个脚本都遵循同一条规则: **宁可失败, 也不用空结果覆盖线上旧数据**。

- 数据源全挂、解析不出节点、检测后没有任何可用节点 → 退出码 1, 工作流停止, 不上传不部署。
- 文件先写临时文件再原子替换, 中途失败不留下半截文件。
- 私有订阅上传失败 → 工作流报错且不部署; 上传后再次确认站点目录里没有私有文件。

---

## 订阅放私有 Worker (不进 Pages / Actions 产物)

含 UUID 的 4 个文件以及 `ovpn.yaml` 由工作流上传到你自己的 Cloudflare Worker (KV), 站点上不发布。

1. **先在 edgetunnel 后台换一个新 UUID**, 同步更新 secret `EDT_UUID`。
2. Cloudflare 控制台: 新建 KV 命名空间, 记下 id, 填进 `worker/wrangler.toml`
   (或在 Worker 设置里绑定, 绑定名必须是 `SUBS`)。
3. 部署 `worker/worker.js` 为一个 Worker (控制台粘贴代码即可), 并绑定自定义域名
   (国内直连 workers.dev 常常不通, 建议用你自己的域名)。
4. 在 Worker 设置里添加一个 **Secret**: `ACCESS_TOKEN`, 用 `openssl rand -hex 16` 生成。
   它同时是上传密钥 (`Authorization: Bearer`) 和订阅访问令牌 (URL 路径)。**必须配置**, 未配置时上传会被拒绝 (HTTP 500)。
5. 仓库 Secrets 添加: `WORKER_URL` (如 `https://sub.example.com`)、`ACCESS_TOKEN` (同上)。
6. (可选) 让 Worker 主域名直接显示监控页: 在 Worker 设置 → Variables 添加普通变量 `PAGES_URL`
   (即 Pages 站点根地址, 不带末尾 `/`)。之后 `<WORKER_URL>/` 就是监控页, 并转发
   `pool.json` `ovpn.json` `sstp.json` `sstp-chains.txt` `sstp-hosts.txt`。
7. 三个工作流各手动运行一次。订阅地址: `<WORKER_URL>/<ACCESS_TOKEN>/sstp.txt`、
   `pool.txt`、`sstp.yaml`、`pool.yaml`、`ovpn.yaml`。

上传失败时工作流会报错并且不部署, 旧数据保持不变。
