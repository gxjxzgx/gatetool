# openvp (合并版)

三条独立的自动刷新流水线, 共用一个 GitHub Pages 站点和**一个监控页**(`index.html`)。
数据文件命名规则: `<工作流名>.<格式>`。

| 工作流 | 脚本 | 频率 | 输出 (站点根目录) |
|---|---|---|---|
| `gate.yml` | `vpngate.py` | 每 30 分钟 | `gate.json` `gate.txt`(vless 订阅) `gate.yaml`(Clash) `gate-chains.txt` `gate-hosts.txt` |
| `ovpn.yml` | `refresh_ovpn.py` | 每 3 小时 | `ovpn.json` `ovpn.yaml` |
| `pool.yml` | `refresh_pool.py` | 每天检查, 周日 11:00(北京)刷新 | `pool.json` `pool.txt`(vless 订阅) `pool.yaml`(Clash) |

数据文件只在工作流运行时生成并发布到 Pages, 不提交到仓库。

## 站点

`https://<用户>.github.io/<仓库>/` 打开 `index.html`, 一页显示三块: 优选池 / OpenVPN / SSTP。
页面读取同目录的 `pool.json` `ovpn.json` `gate.json`。

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
