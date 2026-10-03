#!/usr/bin/env bash
# 三个工作流共用: 把已发布 Pages 上的数据文件取回 site/, 再放入网页。
# 各工作流只刷新自己负责的文件, 其余沿用线上旧版, 整站部署也不会丢数据。
# 文件名规则: <工作流名>.<格式>  (gate / ovpn / pool)
set -u

owner="${GITHUB_REPOSITORY_OWNER:-owner}"
repo="${GITHUB_REPOSITORY:-owner/repo}"
base="${PAGES_URL:-https://${owner,,}.github.io/${repo#*/}}"
base="${base%/}"

mkdir -p site

# 含 UUID 的 pool.txt/pool.yaml/gate.txt/gate.yaml 不在 Pages 上, 由私有 Worker 保存, 这里不恢复
FILES="pool.json
ovpn.json ovpn.yaml
gate.json gate-chains.txt gate-hosts.txt"

for f in $FILES; do
  if curl -fsS --retry 2 --max-time 30 -o "site/$f.tmp" "$base/$f"; then
    mv "site/$f.tmp" "site/$f"; echo "已恢复: $f"
  else
    rm -f "site/$f.tmp"; echo "无旧文件: $f"
  fi
done

cp web/index.html site/index.html

# 后续步骤可用 $SITE_URL (gate 脚本用它生成"固定地址"注释)
[ -n "${GITHUB_ENV:-}" ] && echo "SITE_URL=$base" >> "$GITHUB_ENV"
exit 0
