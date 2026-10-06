// 私有订阅托管 Worker (KV 绑定名: SUBS)
//   PUT  /upload/<文件名>        Authorization: Bearer <ACCESS_TOKEN>  -> 写入 KV (GitHub Actions 调用)
//   GET  /<ACCESS_TOKEN>/<文件名>                                       -> 客户端订阅地址
//   GET  /  及  /pool.json /ovpn.json /sstp.json /sstp-chains.txt /sstp-hosts.txt
//        -> 从 GitHub Pages 转发 (监控页 + 公开数据), 需要变量 PAGES_URL
// 变量 / 密钥 (Worker 设置里添加):
//   Secret   ACCESS_TOKEN  (上传与订阅共用这一个, 必填)
//   Variable PAGES_URL     (Pages 站点根地址, 如 https://user.github.io/repo, 不带末尾 /; 普通文本变量即可)

// 私有文件: 文件名 -> Content-Type
const FILES = {
  "pool.txt": "text/plain; charset=utf-8",
  "pool.yaml": "text/yaml; charset=utf-8",
  "sstp.txt": "text/plain; charset=utf-8",
  "sstp.yaml": "text/yaml; charset=utf-8",
  "ovpn.yaml": "text/yaml; charset=utf-8",
};
const MAX_BYTES = 5_000_000;

// 公开页面 / 数据: 路径 -> Pages 上的文件名 (这些文件本来就公开在 Pages 上)
const PUBLIC = {
  "": "index.html",
  "index.html": "index.html",
  "pool.json": "pool.json",
  "ovpn.json": "ovpn.json",
  "sstp.json": "sstp.json",
  "sstp-chains.txt": "sstp-chains.txt",
  "sstp-hosts.txt": "sstp-hosts.txt",
};
const PUBLIC_TYPES = {
  html: "text/html; charset=utf-8",
  json: "application/json; charset=utf-8",
  txt: "text/plain; charset=utf-8",
};

const has = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

const reply = (body, status = 200, extra = {}) =>
  new Response(body, { status, headers: { "cache-control": "no-store", ...extra } });

// 常量时间比较 (先做 SHA-256, 避免长度 / 内容泄露)
async function safeEqual(a, b) {
  if (!a || !b) return false;
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  const x = new Uint8Array(ha);
  const y = new Uint8Array(hb);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

// 路径拆段并解码; 出现非法的 % 编码时返回 null, 避免抛 URIError 变成 500
function pathParts(req) {
  try {
    return new URL(req.url).pathname.split("/").filter(Boolean).map(decodeURIComponent);
  } catch {
    return null;
  }
}

// 上传: 校验令牌 -> 文件名白名单 -> 体积 (按字节) -> 写入 KV
async function handleUpload(req, env, name) {
  if (!env.ACCESS_TOKEN) return reply("ACCESS_TOKEN not configured", 500);   // 没配令牌时不允许上传
  if (!(await safeEqual(req.headers.get("Authorization") || "", "Bearer " + env.ACCESS_TOKEN))) {
    return reply("forbidden", 403);
  }
  if (!has(FILES, name)) return reply("bad file name", 400);
  if (Number(req.headers.get("content-length") || 0) > MAX_BYTES) return reply("too large", 413);
  const buf = await req.arrayBuffer();          // 以字节计, 不会被多字节字符低估
  if (!buf.byteLength || buf.byteLength > MAX_BYTES) return reply("bad body", 400);
  await env.SUBS.put(name, new TextDecoder().decode(buf));
  return reply("ok");
}

// 公开数据: 从 Pages 转发
async function handlePublic(req, env, key) {
  const file = PUBLIC[key];
  const base = env.PAGES_URL.replace(/\/+$/, "");
  const up = await fetch(base + "/" + file, { cf: { cacheTtl: 60, cacheEverything: true } });
  if (!up.ok) return reply("upstream error", 502);
  return new Response(req.method === "HEAD" ? null : up.body, {
    status: 200,
    headers: {
      "content-type": PUBLIC_TYPES[file.split(".").pop()],
      "cache-control": "public, max-age=60",
    },
  });
}

export default {
  async fetch(req, env) {
    const parts = pathParts(req);
    if (!parts) return reply("bad request", 400);

    if (req.method === "PUT" && parts.length === 2 && parts[0] === "upload") {
      return handleUpload(req, env, parts[1]);
    }

    // 私有订阅: /<令牌>/<文件名>  (safeEqual 对空令牌恒为 false, 没配令牌时这条路径自然不可用)
    if (req.method === "GET" && parts.length === 2 && has(FILES, parts[1])) {
      if (await safeEqual(parts[0], env.ACCESS_TOKEN)) {
        const value = await env.SUBS.get(parts[1]);
        if (value !== null) return reply(value, 200, { "content-type": FILES[parts[1]] });
      }
    }

    // 监控页 + 公开数据
    if ((req.method === "GET" || req.method === "HEAD") && parts.length <= 1) {
      const key = parts[0] || "";
      if (has(PUBLIC, key) && env.PAGES_URL) return handlePublic(req, env, key);
    }

    return reply("not found", 404);   // 令牌错 / 文件不存在一律 404, 不暴露区别
  },
};
