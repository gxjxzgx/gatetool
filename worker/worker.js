// 私有订阅托管 Worker (KV 绑定名: SUBS)
//   PUT  /upload/<文件名>        Authorization: Bearer <UPLOAD_KEY>   -> 写入 KV (GitHub Actions 调用)
//   GET  /<ACCESS_TOKEN>/<文件名>                                      -> 客户端订阅地址
// 变量/密钥 (Worker 设置里添加为 Secret): UPLOAD_KEY, ACCESS_TOKEN

const FILES = {
  "pool.txt": "text/plain; charset=utf-8",
  "pool.yaml": "text/yaml; charset=utf-8",
  "gate.txt": "text/plain; charset=utf-8",
  "gate.yaml": "text/yaml; charset=utf-8",
};
const MAX_BYTES = 5_000_000;

// 常量时间比较 (先做 SHA-256, 避免长度/内容泄露)
async function safeEqual(a, b) {
  if (!a || !b) return false;
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  const x = new Uint8Array(ha), y = new Uint8Array(hb);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

const text = (body, status = 200, extra = {}) =>
  new Response(body, { status, headers: { "cache-control": "no-store", ...extra } });

export default {
  async fetch(req, env) {
    const parts = new URL(req.url).pathname.split("/").filter(Boolean).map(decodeURIComponent);

    if (req.method === "PUT" && parts.length === 2 && parts[0] === "upload") {
      if (!(await safeEqual(req.headers.get("Authorization") || "", "Bearer " + (env.UPLOAD_KEY || "")))) {
        return text("forbidden", 403);
      }
      const name = parts[1];
      if (!Object.prototype.hasOwnProperty.call(FILES, name)) return text("bad file name", 400);
      const body = await req.text();
      if (!body || body.length > MAX_BYTES) return text("bad body", 400);
      await env.SUBS.put(name, body);
      return text("ok");
    }

    if (req.method === "GET" && parts.length === 2 && Object.prototype.hasOwnProperty.call(FILES, parts[1])) {
      if (await safeEqual(parts[0], env.ACCESS_TOKEN || "")) {
        const v = await env.SUBS.get(parts[1]);
        if (v !== null) return text(v, 200, { "content-type": FILES[parts[1]] });
      }
    }
    return text("not found", 404);   // 令牌错/文件不存在一律 404, 不暴露区别
  },
};
