// 私有订阅托管 Worker (KV 绑定名: SUBS)
//   PUT  /upload/<文件名>        Authorization: Bearer <ACCESS_TOKEN>  -> 写入 KV (GitHub Actions 调用)
//   GET  /<ACCESS_TOKEN>/<文件名>                                       -> 客户端订阅地址
//   GET  /  及  /pool.json /ovpn.json /gate.json /gate-chains.txt /gate-hosts.txt
//        -> 从 GitHub Pages 转发 (监控页 + 公开数据), 需要变量 PAGES_URL
// 变量/密钥 (Worker 设置里添加):
//   Secret   ACCESS_TOKEN  (上传与订阅共用这一个)
//   Variable PAGES_URL     (Pages 站点根地址, 如 https://user.github.io/repo, 不带末尾 /; 普通文本变量即可)

const FILES = {
  "pool.txt": "text/plain; charset=utf-8",
  "pool.yaml": "text/yaml; charset=utf-8",
  "gate.txt": "text/plain; charset=utf-8",
  "gate.yaml": "text/yaml; charset=utf-8",
  "ovpn.yaml": "text/yaml; charset=utf-8",
};
const MAX_BYTES = 5_000_000;

// 公开页面/数据: 路径 -> Pages 上的文件名 (这些文件本来就公开在 Pages 上)
const PUBLIC = {
  "": "index.html",
  "index.html": "index.html",
  "pool.json": "pool.json",
  "ovpn.json": "ovpn.json",
  "gate.json": "gate.json",
  "gate-chains.txt": "gate-chains.txt",
  "gate-hosts.txt": "gate-hosts.txt",
};
const PUBLIC_TYPES = {
  html: "text/html; charset=utf-8",
  json: "application/json; charset=utf-8",
  txt: "text/plain; charset=utf-8",
};

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
      if (!(await safeEqual(req.headers.get("Authorization") || "", "Bearer " + (env.ACCESS_TOKEN || "")))) {
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
    // 监控页 + 公开数据: 从 Pages 转发
    if ((req.method === "GET" || req.method === "HEAD") && parts.length <= 1) {
      const key = parts[0] || "";
      if (Object.prototype.hasOwnProperty.call(PUBLIC, key) && env.PAGES_URL) {
        const file = PUBLIC[key];
        const base = env.PAGES_URL.replace(/\/+$/, "");
        const up = await fetch(base + "/" + file, { cf: { cacheTtl: 60, cacheEverything: true } });
        if (!up.ok) return text("upstream error", 502);
        const ext = file.split(".").pop();
        return new Response(req.method === "HEAD" ? null : up.body, {
          status: 200,
          headers: { "content-type": PUBLIC_TYPES[ext], "cache-control": "public, max-age=60" },
        });
      }
    }
    return text("not found", 404);   // 令牌错/文件不存在一律 404, 不暴露区别
  },
};
