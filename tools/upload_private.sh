#!/usr/bin/env bash
# 把含 UUID 的订阅上传到私有 Worker (KV), 然后从 site/ 删除, 不发布到 Pages。
# 需要环境变量: WORKER_URL (如 https://sub.example.com, 不带末尾 /), ACCESS_TOKEN
set -eu
: "${WORKER_URL:?请设置 secret WORKER_URL}"
: "${ACCESS_TOKEN:?请设置 secret ACCESS_TOKEN}"
WORKER_URL="${WORKER_URL%/}"

for f in pool.txt pool.yaml gate.txt gate.yaml ovpn.yaml; do
  if [ -f "site/$f" ]; then
    curl -fsS --retry 2 --max-time 60 -X PUT \
      -H "Authorization: Bearer $ACCESS_TOKEN" \
      --data-binary "@site/$f" "$WORKER_URL/upload/$f" >/dev/null
    echo "已上传到 Worker: $f"
    rm -f "site/$f"
  fi
done
# 双保险: 根目录不允许残留私有订阅文件
for f in pool.txt pool.yaml gate.txt gate.yaml ovpn.yaml; do
  [ -f "site/$f" ] && { echo "错误: site/$f 仍在站点目录" >&2; exit 1; }
done
exit 0
