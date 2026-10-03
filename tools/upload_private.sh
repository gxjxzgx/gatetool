#!/usr/bin/env bash
# 把私有订阅 (含 UUID 的 pool/gate, 以及 ovpn.yaml) 上传到私有 Worker (KV), 然后从 site/ 删除, 不发布到 Pages。
# 需要环境变量: WORKER_URL (如 https://sub.example.com, 不带末尾 /), ACCESS_TOKEN
set -eu
: "${WORKER_URL:?请设置 secret WORKER_URL}"
: "${ACCESS_TOKEN:?请设置 secret ACCESS_TOKEN}"

# 去掉 secret 里误带的空白/换行 (复制粘贴常见问题)
WORKER_URL="$(printf '%s' "$WORKER_URL" | tr -d '[:space:]')"
WORKER_URL="${WORKER_URL%/}"
ACCESS_TOKEN="$(printf '%s' "$ACCESS_TOKEN" | tr -d '[:space:]')"
FILES="pool.txt pool.yaml gate.txt gate.yaml ovpn.yaml"

resp="$(mktemp)"
for f in $FILES; do
  [ -f "site/$f" ] || continue
  code="$(curl -sS --retry 2 --max-time 60 -X PUT \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    --data-binary "@site/$f" \
    -o "$resp" -w '%{http_code}' "$WORKER_URL/upload/$f" || echo 000)"
  if [ "$code" != "200" ]; then
    body="$(head -c 300 "$resp" | tr '\n' ' ')"
    echo "错误: 上传 $f 失败, HTTP $code, 响应: $body" >&2
    case "$code" in
      403)
        if printf '%s' "$body" | grep -q 'forbidden'; then
          echo "提示: Worker 已收到请求但令牌不匹配。检查 Worker 的 ACCESS_TOKEN 与仓库 secret ACCESS_TOKEN 是否同值, 以及 Worker 是否已部署新版 worker.js。" >&2
        else
          echo "提示: 响应不是 Worker 的 forbidden, 可能被 Cloudflare 安全规则 (WAF/Bot Fight Mode) 拦截, 请放行 /upload/*。" >&2
        fi ;;
      404) echo "提示: 路径或文件名不被 Worker 接受, 确认 Worker 是新版 (白名单含 $f) 且 WORKER_URL 正确。" >&2 ;;
      400) echo "提示: Worker 拒绝了文件名或内容 (为空或超过 5MB)。" >&2 ;;
      000) echo "提示: 连接 Worker 失败, 检查 WORKER_URL 域名是否可从 GitHub 访问。" >&2 ;;
    esac
    rm -f "$resp"
    exit 1
  fi
  echo "已上传到 Worker: $f"
  rm -f "site/$f"
done
rm -f "$resp"

# 双保险: 根目录不允许残留私有订阅文件
for f in $FILES; do
  if [ -f "site/$f" ]; then echo "错误: site/$f 仍在站点目录" >&2; exit 1; fi
done
exit 0
