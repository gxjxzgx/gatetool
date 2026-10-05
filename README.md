# gate

三条独立的自动刷新流水线, 共用一个 GitHub Pages 站点和**一个监控页**(`index.html`)。
数据文件命名规则: `<名称>.<格式>` (名称 = sstp / ovpn / pool; sstp 由 `gate.yml` + `vpngate.py` 生成)。

| 工作流 | 脚本 | 频率 | 输出 (站点根目录) |
|---|---|---|---|
| `gate.yml` | `vpngate.py` | 每 3 小时 | `sstp.json`(含机房节点) `sstp.txt`(vless 订阅) `sstp.yaml`(Clash) `sstp-chains.txt` `sstp-hosts.txt` (后四者在住宅节点 > 20 个时不含机房节点) |
| `ovpn.yml` | `refresh_ovpn.py` | 每 3 小时 | `ovpn.json`(Pages, 含机房节点) `ovpn.yaml`(Clash, 私有 Worker; 住宅节点 > 20 个时不含机房节点) |
| `pool.yml` | `refresh_pool.py` | 每天检查, 周日 11:00(北京)刷新 | `pool.json` `pool.txt`(vless 订阅) `pool.yaml`(Clash) |

数据文件只在工作流运行时生成并发布到 Pages, 不提交到仓库。

## 站点

`https://<用户>.github.io/<仓库>/` 打开 `index.html`, 一页显示三块: 优选池 / OpenVPN / SSTP。
页面读取同目录的 `pool.json` `ovpn.json` `sstp.json`。OpenVPN 与 SSTP 列表均按 住宅 → 机房 → 未识别 排序。

## 为什么每个工作流都先恢复站点

Pages 每次部署都是整站替换。每个工作流开头运行 `tools/prepare_site.sh`,
把线上已有的数据文件取回 `site/`, 只刷新自己负责的部分, 再整站部署,
三个工作流互不覆盖。三者共用并发组 `site-publish`, 串行执行。

## 部署

1. Settings → Actions → General → Workflow permissions 选 **Read and write permissions**。
2. Settings → Secrets and variables → Actions 添加 secrets: `EDT_DOMAIN`、`EDT_UUID`。
3. 用自定义域名时, 在 Variables 里加 `PAGES_URL` (站点根地址, 不带末尾 `/`)。
4. 在 GitHub 网页上手动创建 `.github/workflows/` 下三个 yml (API 推不了 workflows 文件)。
5. Actions 页依次手动运行 `CF Edge Pool Refresh`、`OpenVPN Refresh`、`Gate SSTP Check` 各一次。

---

## 方案 B: 订阅放私有 Worker (不进 Pages / Actions 产物)

含 UUID 的 4 个文件以及 `ovpn.yaml` 由工作流上传到你自己的 Cloudflare Worker (KV), 站点上不发布。

1. **先在 edgetunnel 后台换一个新 UUID**, 同步更新 secret `EDT_UUID`。
2. Cloudflare 控制台: 新建 KV 命名空间, 记下 id, 填进 `worker/wrangler.toml`
   (或在 Worker 设置里绑定, 绑定名必须是 `SUBS`)。
3. 部署 `worker/worker.js` 为一个 Worker (控制台粘贴代码即可), 并绑定自定义域名
   (国内直连 workers.dev 常常不通, 建议用你自己的域名)。
4. 在 Worker 设置里添加一个 **Secret**: `ACCESS_TOKEN`, 用 `openssl rand -hex 16` 生成。
   它同时是上传密钥 (`Authorization: Bearer`) 和订阅访问令牌 (URL 路径), 不再需要 `UPLOAD_KEY`。
5. 仓库 Secrets 添加: `WORKER_URL` (如 `https://sub.example.com`)、`ACCESS_TOKEN` (同上)。
   若之前配置过 `UPLOAD_KEY`, 可在 Worker 和仓库里删除。
6. (可选) 让 Worker 主域名直接显示监控页: 在 Worker 设置 → Variables 添加普通变量 `PAGES_URL`
   (即 Pages 站点根地址, 不带末尾 `/`)。之后 `<WORKER_URL>/` 就是监控页, 并转发
   `pool.json` `ovpn.json` `sstp.json` `sstp-chains.txt` `sstp-hosts.txt`。
7. 三个工作流各手动运行一次。订阅地址: `<WORKER_URL>/<ACCESS_TOKEN>/sstp.txt`、
   `pool.txt`、`sstp.yaml`、`pool.yaml`、`ovpn.yaml`。

上传失败时工作流会报错并且不部署, 旧数据保持不变。
