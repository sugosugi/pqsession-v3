// pqsession 中继服务器 v3：仍是“哑管道”，只在两端之间转发不透明密文。
// 它永远看不到私钥、会话密钥或明文；端到端加密由浏览器完成。
//
// 运行：  npm install && npm run vendor   然后   npm start   （默认监听 0.0.0.0:8080）
// 自检：  node server.js --check                （不启动服务：校验前端 CSP 哈希、本地算法库、配置）
// 固定库：npm run vendor                         （把 ML-KEM / hash-wasm 下载到 ./vendor 并记录 SHA-256）
//
// v3 相对 v2 的加固（端到端协议的变化见 pqsession-net.html 与 SECURITY.md）：
//   1. 修复 X-Forwarded-For 伪造：旧版取 XFF 最左边的值当客户端 IP，而最左值由客户端随意填写，
//      置于反向代理后（TRUST_PROXY=1）时任何人都能每次换一个“IP”，每 IP 并发上限形同虚设。
//      现在只信任从右数第 TRUST_PROXY_HOPS 个值（你在中继前部署的可信代理层数，默认 1）。
//   2. IPv6 按 /64 前缀合并计数：一个 IPv6 用户通常手握 2^64 个地址，逐地址计数挡不住任何人。
//   3. 每 IP（前缀）新建连接速率限制（CONN_RATE_PER_IP / CONN_BURST_PER_IP），防握手洪水。
//   4. 算法库“失败即关闭”：vendor/ 不齐全或与 vendor/manifest.json 记录的哈希不符时拒绝启动；
//      页面也不再有 esm.sh 退路 —— 运行时任何时候都不加载第三方代码。
//   5. CSP 收紧：script-src 去掉 blob:（语音 AudioWorklet 改为同源文件 /vc-worklet.js）；
//      style-src 去掉 'unsafe-inline'（改用 <style> 哈希）；启用 Trusted Types；
//      connect-src 从“任意 ws:/wss:”收紧为本站（及 RELAY_ORIGINS 显式列出的中继）。
//   6. 原生 TLS 默认优先协商 X25519MLKEM768 混合密钥交换（抗“先存后解”），并只保留 ECDHE+AEAD 套件。
//   7. 房间号格式校验（32 位十六进制）；每条连接只能入房一次。
//
// 注意：'ws' 仅在作为主服务器运行时动态加载（见文件末尾），
// 这样在不安装 ws 的环境里也能 import 本文件来单元测试纯逻辑（makeHub 等）。
import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import fs from "node:fs";
import path from "node:path";
import url from "node:url";
import crypto from "node:crypto";

function envInt(v, d) {
  if (v === undefined || v === null || v === "") return d;
  const n = parseInt(v, 10);
  return Number.isFinite(n) && n >= 0 ? n : d;
}
function envBool(v) { return /^(1|true|yes|on)$/i.test(String(v || "")); }
function envList(v) { return String(v || "").split(",").map((s) => s.trim()).filter(Boolean); }

export const ROOT = path.dirname(url.fileURLToPath(import.meta.url));
export const HTML_FILE = "pqsession-net.html";
export const VENDOR_FILES = ["ml-kem.mjs", "hash-wasm.mjs"];   // 与前端 loadLib() 的本地路径一一对应
export const WORKLET_FILE = "vc-worklet.js";                   // 语音 AudioWorklet（同源提供，CSP 因此无需 blob:）
export const ROOM_RE = /^[0-9a-f]{32}$/;                       // v3 前端发来的房间号：Argon2id 派生的 128 位标识

export function readConfig(env = process.env) {
  return {
    PORT: env.PORT || 8080,
    HOST: env.HOST || "0.0.0.0",
    MAX_ROOM: 2,                                                   // 1 对 1：每房间最多 2 人
    MAX_PAYLOAD: envInt(env.MAX_PAYLOAD, 4 * 1024 * 1024),         // 单帧上限（前端每块约 0.7 MiB）
    MSG_RATE: envInt(env.MSG_RATE, 2000),                          // 每连接消息条数：令牌/秒
    MSG_BURST: envInt(env.MSG_BURST, 4000),                        // 突发桶容量
    BYTES_RATE: envInt(env.BYTES_RATE, 32 * 1024 * 1024),          // 每连接字节整形：字节/秒（0=不限）
    BYTES_BURST: envInt(env.BYTES_BURST, 96 * 1024 * 1024),        // 字节突发桶
    BP_HIGH: envInt(env.BP_HIGH, 8 * 1024 * 1024),                 // 背压高水位：对端发送缓冲超过即暂停来源
    BP_LOW: envInt(env.BP_LOW, 1 * 1024 * 1024),                   // 背压低水位：降到以下才恢复
    BP_STALL_MS: envInt(env.BP_STALL_MS, 60000),                   // 对端持续不读超过此时长即判僵死踢出
    MAX_CONN_IP: envInt(env.MAX_CONN_PER_IP, 64),                  // 每 IP 并发连接上限（0=不限）
    MAX_CONN: envInt(env.MAX_CONN, 4096),                          // 全局并发连接上限（0=不限）
    JOIN_TIMEOUT_MS: envInt(env.JOIN_TIMEOUT_MS, 30000),           // 连接后迟迟不 join 的清理时限（0=不限）
    HEARTBEAT_MS: envInt(env.HEARTBEAT_MS, 30000),                 // 心跳间隔（0=关闭）
    TRUST_PROXY: envBool(env.TRUST_PROXY),                         // 置于反向代理后才开：信任 X-Forwarded-*
    TRUST_PROXY_HOPS: Math.max(1, envInt(env.TRUST_PROXY_HOPS, 1)), // 中继前面的可信代理层数（决定取 XFF 从右数第几个）
    CONN_RATE: envInt(env.CONN_RATE_PER_IP, 5),                    // 每 IP（IPv6 按 /64）新建连接：令牌/秒（0=不限）
    CONN_BURST: envInt(env.CONN_BURST_PER_IP, 30),                 // 新建连接突发桶
    ALLOWED_ORIGINS: envList(env.ALLOWED_ORIGINS),                 // 空=仅同源；"*"=任意；否则同源+列表
    RELAY_ORIGINS: envList(env.RELAY_ORIGINS),                     // 本站页面还允许连接的其他中继（写入 CSP connect-src）
    TLS_CERT: env.TLS_CERT || "",
    TLS_KEY: env.TLS_KEY || "",
    TLS_PQ: env.TLS_PQ === undefined || env.TLS_PQ === "" ? true : envBool(env.TLS_PQ), // 优先 X25519MLKEM768
    TLS_MIN: String(env.TLS_MIN || "") === "1.3" ? "TLSv1.3" : "TLSv1.2",
    VENDOR_DIR: env.VENDOR_DIR || path.join(ROOT, "vendor"),
  };
}

/* ---------------------------------------------------------------------------
 * 纯中继逻辑（不依赖 ws，便于单元测试）
 * client 只需具备 .send(string[, cb]) 方法与可写的 .room 字段；
 * 若具备 .bufferedAmount / .pause() / .resume()（ws 8.12+）则自动启用背压。
 * 关键不变量：relay() 不解析 d，只按房间把它原样转发给“另一端”。
 * ------------------------------------------------------------------------- */
export function makeHub({ maxRoom = 2, bpHigh = 8 * 1024 * 1024, bpLow = 1024 * 1024, now = Date.now } = {}) {
  const rooms = new Map();                       // room -> Set<client>
  const peersOf = (room) => rooms.get(room) || new Set();

  function safeSend(client, obj) { try { client.send(JSON.stringify(obj)); } catch {} }
  function bufferedOf(c) { return typeof c.bufferedAmount === "number" ? c.bufferedAmount : 0; }

  // 暂停 / 恢复读取。多个原因（背压 bp、整形 shape）可同时成立，全部解除才真正恢复。
  function hold(c, reason) {
    if (!c.holds) c.holds = new Set();
    c.holds.add(reason);
    if (c.hubPaused) return;
    c.hubPaused = true;
    try {
      if (typeof c.pause === "function") c.pause();
      else if (c._socket && typeof c._socket.pause === "function") c._socket.pause();
    } catch {}
  }
  function release(c, reason) {
    if (!c.holds) return;
    c.holds.delete(reason);
    if (c.holds.size > 0 || !c.hubPaused) return;
    c.hubPaused = false;
    try {
      if (typeof c.resume === "function") c.resume();
      else if (c._socket && typeof c._socket.resume === "function") c._socket.resume();
    } catch {}
  }

  // 背压：client 正在把数据发给 p，而 p 的发送缓冲已过高水位 → 暂停 client 的读取，等 p 排空。
  function waitOn(client, p) {
    if (!p.bpWaiters) p.bpWaiters = new Set();
    p.bpWaiters.add(client);
    if (typeof client.bpSince !== "number") client.bpSince = now();
    client.bpWaitOn = p;
    hold(client, "bp");
  }
  function releaseWaiters(p) {
    if (!p.bpWaiters) return;
    for (const c of p.bpWaiters) { c.bpWaitOn = null; c.bpSince = null; release(c, "bp"); }
    p.bpWaiters.clear();
  }
  // 发送回调：p 的一帧已写出；若缓冲已降到低水位，恢复所有在等 p 的来源。
  function onDrain(p) {
    if (!p.bpWaiters || p.bpWaiters.size === 0) return;
    if (bufferedOf(p) > bpLow) return;
    releaseWaiters(p);
  }

  function join(client, room) {
    // v3：只接受 32 位小写十六进制房间号（前端由房间口令经 Argon2id + HKDF 派生）。
    // 不再截断任意字符串当房间名，中继因此也不会被当成通用的任意主题转发器。
    if (typeof room !== "string" || !ROOM_RE.test(room)) return { ok: false, reason: "bad-room" };
    if (client.room) leave(client);
    const set = rooms.get(room) || new Set();
    if (set.size >= maxRoom) return { ok: false, reason: "full" };
    set.add(client); rooms.set(room, set); client.room = room;
    for (const p of set) if (p !== client) safeSend(p, { t: "peer", event: "join", n: set.size });
    return { ok: true, n: set.size };
  }

  function leave(client) {
    // 无论是否在房间内，都先解开与背压相关的所有牵连
    releaseWaiters(client);
    if (client.bpWaitOn && client.bpWaitOn.bpWaiters) client.bpWaitOn.bpWaiters.delete(client);
    client.bpWaitOn = null; client.bpSince = null;
    const room = client.room; if (!room) return;
    const set = rooms.get(room);
    if (set) {
      set.delete(client);
      for (const p of set) safeSend(p, { t: "peer", event: "leave", n: set.size });
      if (set.size === 0) rooms.delete(room);
    }
    client.room = null;
  }

  // 把 d 原样转发给同房间的其他人；服务器不读取、不存储 d。
  function relay(client, d) {
    const set = rooms.get(client.room); if (!set) return 0;
    const payload = JSON.stringify({ t: "sig", d });
    let n = 0;
    for (const p of set) {
      if (p === client) continue;
      n++;
      try { p.send(payload, () => onDrain(p)); } catch { continue; }
      if (bufferedOf(p) > bpHigh) waitOn(client, p);
    }
    return n;
  }

  return { join, leave, relay, rooms, peersOf, hold, release };
}

/* ---------------------------------------------------------------------------
 * 消息条数限流（令牌桶，每连接一个；便于单元测试）。
 * take(now) 在桶内有令牌时消耗 1 个并返回 true，否则返回 false（超额消息直接丢弃）。
 * ------------------------------------------------------------------------- */
export function makeRateLimiter({ ratePerSec = 2000, burst = 4000 } = {}) {
  let tokens = burst;
  let last = Date.now();
  return {
    take(now = Date.now()) {
      const dt = Math.max(0, now - last) / 1000;
      last = now;
      tokens = Math.min(burst, tokens + dt * ratePerSec);
      if (tokens >= 1) { tokens -= 1; return true; }
      return false;
    },
  };
}

/* ---------------------------------------------------------------------------
 * 字节整形（令牌桶允许透支）：consume(n) 返回“需要暂停读取多少毫秒才能把透支补回来”，
 * 0 表示无需暂停。与丢帧不同，整形不会让合法的大文件传输失败，只是把速率压到上限。
 * ------------------------------------------------------------------------- */
export function makeByteShaper({ bytesPerSec = 0, burst = 0 } = {}) {
  let tokens = burst;
  let last = Date.now();
  return {
    consume(n, now = Date.now()) {
      if (bytesPerSec <= 0) return 0;
      const dt = Math.max(0, now - last) / 1000;
      last = now;
      tokens = Math.min(burst, tokens + dt * bytesPerSec) - n;
      if (tokens >= 0) return 0;
      return Math.ceil((-tokens / bytesPerSec) * 1000);
    },
  };
}

/* ---------------------------------------------------------------------------
 * 按键（IP 前缀）的令牌桶：限制每个来源“新建连接”的速率（防 WebSocket 握手洪水）。
 * 桶数有上限（满了淘汰最久未用的），sweep() 回收已回满的桶，内存不随攻击者地址数无限增长。
 * ------------------------------------------------------------------------- */
export function makeKeyedLimiter({ ratePerSec = 5, burst = 30, maxKeys = 50000 } = {}) {
  const m = new Map();                                   // key -> { tokens, last }
  function refill(b, t) {
    const dt = Math.max(0, t - b.last) / 1000; b.last = t;
    b.tokens = Math.min(burst, b.tokens + dt * ratePerSec);
  }
  return {
    take(key, t = Date.now()) {
      if (ratePerSec <= 0) return true;
      let b = m.get(key);
      if (b) { m.delete(key); refill(b, t); }            // 重新插入 = 移到“最近使用”末尾
      else { b = { tokens: burst, last: t }; if (m.size >= maxKeys) m.delete(m.keys().next().value); }
      m.set(key, b);
      if (b.tokens >= 1) { b.tokens -= 1; return true; }
      return false;
    },
    sweep(t = Date.now()) {
      for (const [k, b] of m) { refill(b, t); if (b.tokens >= burst) m.delete(k); }
    },
    get size() { return m.size; },
  };
}

/* ---------------------------------------------------------------------------
 * 心跳清扫（纯逻辑，便于单元测试）：
 *   • 上一轮未回 pong 的连接直接终止；其余标记为“待回应”并发送 ping。
 *   • 背压僵死：某连接被对端拖住（bpSince）超过 stallMs，说明对端长时间不读 → 终止对端，
 *     它的 close 会触发 leave() 并释放来源。防止半开 / 僵尸连接长期占用 1 对 1 房间。
 * client 只需具备 isAlive 字段与 ping()/terminate() 方法。
 * ------------------------------------------------------------------------- */
export function heartbeatSweep(clients, { now = Date.now(), stallMs = 0 } = {}) {
  let pinged = 0, killed = 0, stalled = 0;
  const stalledPeers = new Set();
  if (stallMs > 0) {
    for (const c of clients) {
      if (typeof c.bpSince === "number" && c.bpWaitOn && now - c.bpSince > stallMs) stalledPeers.add(c.bpWaitOn);
    }
  }
  for (const c of clients) {
    if (stalledPeers.has(c)) { stalled++; try { c.terminate(); } catch {} continue; }
    // 被本中继主动暂停读取的连接（背压 / 整形）读不到 pong，不能据此判死；它恢复后再照常心跳。
    if (c.hubPaused) { c.isAlive = true; continue; }
    if (c.isAlive === false) { killed++; try { c.terminate(); } catch {} continue; }
    c.isAlive = false; pinged++; try { c.ping(); } catch {}
  }
  return stallMs > 0 ? { pinged, killed, stalled } : { pinged, killed };   // 旧签名返回值形状不变
}

/* ---------------------------------------------------------------------------
 * Origin 策略（纯逻辑，便于单元测试）。
 *   allowed 为空  → 仅允许 Origin 的 host 与本次请求的 Host 一致（同源托管的默认拓扑）；
 *   含 "*"       → 允许任意 Origin（旧版默认行为，需显式打开）；
 *   否则          → 同源 或 列表内的精确 origin（如 https://chat.example.com）。
 * 没有 Origin 头的连接（非浏览器客户端）在非 "*" 模式下一律拒绝。
 * 这不是保密边界（Origin 可被非浏览器伪造），它挡的是“别的网站在用户浏览器里悄悄用你的中继”。
 * ------------------------------------------------------------------------- */
export function makeOriginPolicy(allowed = [], { trustProxy = false } = {}) {
  const any = allowed.includes("*");
  const list = allowed.filter((o) => o !== "*").map(normalizeOrigin).filter(Boolean);
  return function originAllowed(req) {
    if (any) return true;
    const o = req.headers && req.headers["origin"];
    if (typeof o !== "string" || !o || o === "null") return false;
    let u;
    try { u = new URL(o); } catch { return false; }
    if (u.protocol !== "http:" && u.protocol !== "https:") return false;
    if (list.includes(u.origin.toLowerCase())) return true;
    const reqHost = requestHost(req, trustProxy);
    return !!reqHost && u.host.toLowerCase() === reqHost.toLowerCase();
  };
}
export function normalizeOrigin(s) {
  try { return new URL(String(s).trim()).origin.toLowerCase(); } catch { return ""; }
}
export function requestHost(req, trustProxy) {
  const h = req.headers || {};
  if (trustProxy) {
    const xfh = String(h["x-forwarded-host"] || "").split(",")[0].trim();
    if (xfh) return xfh;
  }
  return String(h["host"] || "").trim();
}

// 规范化 IP 文本：去掉 IPv4 映射前缀（::ffff:1.2.3.4）、方括号与端口。
export function normalizeIp(s) {
  let ip = String(s || "").trim();
  if (!ip) return "";
  const br = ip.match(/^\[([^\]]+)\](?::\d+)?$/);                 // [v6]:port
  if (br) ip = br[1];
  else if (/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(ip)) ip = ip.replace(/:\d+$/, "");   // v4:port
  ip = ip.toLowerCase();
  const mapped = ip.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  return mapped ? mapped[1] : ip;
}

// 限流 / 计数用的键：IPv4 用完整地址；IPv6 取 /64 前缀（家庭宽带与云主机通常整段分给一个用户）。
export function ipKey(ip) {
  ip = normalizeIp(ip);
  if (!ip.includes(":")) return ip || "unknown";
  const [head, tail] = ip.split("::");
  const h = head ? head.split(":") : [];
  let groups;
  if (tail === undefined) groups = h;
  else { const t = tail ? tail.split(":") : []; groups = [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill("0"), ...t]; }
  if (groups.length !== 8 || !groups.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return ip;   // 内嵌 IPv4 等少见写法：原样
  return groups.slice(0, 4).map((g) => parseInt(g, 16).toString(16)).join(":") + "::/64";
}

// 客户端 IP。每一层代理都把“它看到的对端地址”追加到 X-Forwarded-For 末尾，
// 因此最左边的值是客户端自己随便写的，不可信；只有从右数第 hops 个值是最外层可信代理亲眼看到的地址。
// XFF 条目比可信层数还少（请求绕过了外层代理）时退回 socket 地址：所有这类请求共享一个计数，宁严勿松。
export function clientIp(req, trustProxy, hops = 1) {
  const sock = normalizeIp((req.socket && req.socket.remoteAddress) || "") || "unknown";
  if (!trustProxy) return sock;
  const list = String((req.headers && req.headers["x-forwarded-for"]) || "").split(",").map((x) => x.trim()).filter(Boolean);
  if (list.length < hops) return sock;
  return normalizeIp(list[list.length - hops]) || sock;
}

/* ---------------------------------------------------------------------------
 * 每连接消息处理（纯逻辑，便于单元测试）。
 * ws 只需是 EventEmitter 风格对象：on("message"|"pong"|"close"|"error")、send()、close()。
 * 所有输入都视为敌对：非对象 JSON（含 null）、非文本帧、缺字段一律静默丢弃，绝不抛出。
 * ------------------------------------------------------------------------- */
export function makeConnectionHandler({ hub, cfg, now = Date.now, setTimer = setTimeout, clearTimer = clearTimeout }) {
  return function onConnection(ws) {
    ws.room = null; ws.isAlive = true;
    const msgBucket = makeRateLimiter({ ratePerSec: cfg.MSG_RATE, burst: cfg.MSG_BURST });
    const shaper = makeByteShaper({ bytesPerSec: cfg.BYTES_RATE, burst: cfg.BYTES_BURST });
    let shapeTimer = null;
    const joinTimer = cfg.JOIN_TIMEOUT_MS > 0
      ? setTimer(() => { if (!ws.room) { try { ws.close(1008, "join timeout"); } catch {} } }, cfg.JOIN_TIMEOUT_MS)
      : null;

    ws.on("pong", () => { ws.isAlive = true; });

    ws.on("message", (raw, isBinary) => {
      if (isBinary) return;                                   // 协议只用文本 JSON 帧
      const len = typeof raw === "string" ? Buffer.byteLength(raw) : (raw && raw.length) || 0;
      const t = now();
      if (!msgBucket.take(t)) return;                          // 消息洪水：丢弃
      const wait = shaper.consume(len, t);                     // 字节整形：暂停读取，不丢帧
      if (wait > 0 && !shapeTimer) {
        hub.hold(ws, "shape");
        shapeTimer = setTimer(() => { shapeTimer = null; hub.release(ws, "shape"); }, wait);
      }
      let msg;
      try { msg = JSON.parse(typeof raw === "string" ? raw : raw.toString("utf8")); } catch { return; }
      if (msg === null || typeof msg !== "object" || Array.isArray(msg)) return;   // v1 崩溃点：null.t
      if (msg.t === "join") {
        if (ws.room) return;                                   // v3：每条连接只能入房一次（换房间需重连，受连接速率限制）
        const r = hub.join(ws, msg.room);
        if (!r.ok) { if (r.reason === "full") { try { ws.send(JSON.stringify({ t: "full" })); } catch {} } return; }
        try { ws.send(JSON.stringify({ t: "joined", n: r.n })); } catch {}
        return;
      }
      if (msg.t === "sig") {
        if (!ws.room || msg.d === undefined) return;
        hub.relay(ws, msg.d);
      }
    });

    const cleanup = () => {
      if (joinTimer) clearTimer(joinTimer);
      if (shapeTimer) { clearTimer(shapeTimer); shapeTimer = null; }
      hub.leave(ws);
    };
    ws.on("close", cleanup);
    ws.on("error", cleanup);
  };
}

/* ---------------------------------------------------------------------------
 * 内容安全策略与静态资源。
 *   • 内联脚本与 <style> 的哈希都从实际 HTML 计算（与浏览器算法一致：标签之间的原始文本做 SHA-256）。
 *   • 页内 <meta> CSP 必须包含同样的哈希（浏览器取二者交集），不一致则拒绝启动；
 *     script-src 或 style-src 出现 'unsafe-inline' 同样拒绝启动。
 *   • 标记里不允许 style="…" 与 on*="…" 内联属性（它们需要 'unsafe-inline' 才能生效）。
 *   • 本地 vendor/ 必须齐全且与 manifest.json 记录的 SHA-256 一致，否则拒绝启动（页面也没有第三方 CDN 退路）。
 *   • 语音 AudioWorklet 由同源 /vc-worklet.js 提供，因此 script-src 不需要 blob:。
 *   • connect-src 只放行本站（按请求 Host 显式写出 ws(s)://host，兼容老 WebKit）与 RELAY_ORIGINS。
 *   • frame-ancestors 只能由响应头设置（防第三方 iframe 嵌套 → 点击劫持 / 诱导误确认指纹）。
 * ------------------------------------------------------------------------- */
const sha256b64 = (text) => "sha256-" + crypto.createHash("sha256").update(text, "utf8").digest("base64");
export function inlineScriptHashes(html) {
  const re = /<script\b[^>]*>([\s\S]*?)<\/script>/gi;
  const out = []; let m;
  while ((m = re.exec(html))) out.push(sha256b64(m[1]));
  return out;
}
export function inlineStyleHashes(html) {
  const re = /<style\b[^>]*>([\s\S]*?)<\/style>/gi;
  const out = []; let m;
  while ((m = re.exec(html))) out.push(sha256b64(m[1]));
  return out;
}
export function metaCspOf(html) {
  // content 里会出现单引号（'none'、'sha256-…'），因此按开头引号配对匹配
  const m = html.match(/<meta\s+http-equiv=(["'])Content-Security-Policy\1\s+content=(["'])([\s\S]*?)\2/i);
  return m ? m[3] : null;
}
// 标记（去掉 <script>/<style> 内容后）里的内联样式 / 事件处理属性：CSP 不放行 'unsafe-inline'，它们会失效或被拦。
export function inlineAttrViolations(html) {
  const markup = html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "").replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, "");
  const out = [];
  const re = /<[a-z][^>]*?\s(style|on[a-z]+)\s*=/gi; let m;
  while ((m = re.exec(markup))) out.push(m[1].toLowerCase());
  return out;
}
export function normalizeWsOrigin(s) {
  try { const u = new URL(String(s).trim()); return (u.protocol === "ws:" || u.protocol === "wss:") ? `${u.protocol}//${u.host}`.toLowerCase() : ""; }
  catch { return ""; }
}
const HOST_RE = /^(?:[a-z0-9-]+\.)*[a-z0-9-]+(?::\d{1,5})?$|^\[[0-9a-f:.]+\](?::\d{1,5})?$/i;
export function buildCsp({ scriptHashes = [], styleHashes = [], connect = [] } = {}) {
  const script = ["'self'", "'wasm-unsafe-eval'"];            // wasm-unsafe-eval：hash-wasm 的 Argon2id 需要编译内嵌 WASM
  for (const h of scriptHashes) script.push(`'${h}'`);
  const style = styleHashes.length ? styleHashes.map((h) => `'${h}'`) : ["'none'"];
  return [
    "default-src 'none'",
    `script-src ${script.join(" ")}`,
    `style-src ${style.join(" ")}`,
    "img-src data:",
    `connect-src ${["'self'", ...connect].join(" ")}`,
    "media-src 'none'",
    "object-src 'none'",
    "worker-src 'none'",
    "frame-src 'none'",
    "manifest-src 'none'",
    "font-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "require-trusted-types-for 'script'",                       // 任何字符串流入 DOM 注入类接口（innerHTML 等）一律抛错
    "trusted-types 'none'",
  ].join("; ");
}
// 本次请求可用的 connect-src：本站 ws(s)://host（'self' 在新浏览器里已覆盖，显式写出兼容老 WebKit）+ RELAY_ORIGINS
export function connectSources(req, { trustProxy = false, overTls = false, relayOrigins = [] } = {}) {
  const out = [];
  const host = requestHost(req, trustProxy).toLowerCase();
  if (HOST_RE.test(host)) { out.push(`wss://${host}`); if (!overTls) out.push(`ws://${host}`); }
  for (const o of relayOrigins) { const n = normalizeWsOrigin(o); if (n && !out.includes(n)) out.push(n); }
  return out;
}

// 启动期准备：读取并冻结静态资源（之后只从内存提供，磁盘被改也不会“边改边发”），返回诊断信息。
export function prepareAssets({ root = ROOT, vendorDir = path.join(ROOT, "vendor") } = {}) {
  const errors = [], warnings = [], info = [];
  const assets = new Map();
  const htmlPath = path.join(root, HTML_FILE);
  const fail = { errors, warnings, info, assets, csp: "", cspParts: { scriptHashes: [], styleHashes: [] }, hashes: [], styleHashes: [], vendorComplete: false };
  let html;
  try { html = fs.readFileSync(htmlPath); } catch (e) { errors.push(`读不到前端文件 ${htmlPath}: ${e.message}`); return fail; }
  const htmlText = html.toString("utf8");
  const hashes = inlineScriptHashes(htmlText);
  const styleHashes = inlineStyleHashes(htmlText);
  if (hashes.length === 0) warnings.push("前端 HTML 里没有找到内联 <script>，CSP 将不含脚本哈希。");
  const meta = metaCspOf(htmlText);
  if (meta === null) {
    warnings.push("前端 HTML 缺少 <meta http-equiv=\"Content-Security-Policy\">，file:// 直接打开时将没有 CSP 防护。");
  } else {
    for (const h of hashes) if (!meta.includes(h)) errors.push(`前端 <meta> CSP 未包含内联脚本的当前哈希 '${h}'。你改动了内联脚本但没有更新 <meta>（可运行 npm run csp 自动更新）。请不要用 'unsafe-inline' 代替。`);
    for (const h of styleHashes) if (!meta.includes(h)) errors.push(`前端 <meta> CSP 未包含 <style> 的当前哈希 '${h}'。你改动了样式但没有更新 <meta>（可运行 npm run csp 自动更新）。`);
    const directive = (name) => meta.split(";").find((d) => new RegExp(`^\\s*${name}\\b`).test(d)) || "";
    if (/unsafe-inline/.test(directive("script-src"))) errors.push("前端 <meta> CSP 的 script-src 含 'unsafe-inline'，这会瓦解注入防护，拒绝启动。");
    if (/unsafe-inline/.test(directive("style-src"))) errors.push("前端 <meta> CSP 的 style-src 含 'unsafe-inline'（v3 起改用 <style> 哈希），拒绝启动。");
  }
  const attrs = inlineAttrViolations(htmlText);
  if (attrs.length) errors.push(`前端标记里有 ${attrs.length} 处内联属性（${[...new Set(attrs)].join(", ")}）：CSP 不放行 'unsafe-inline'，请改用 CSS 类 / addEventListener。`);
  assets.set("/", { body: html, type: "text/html; charset=utf-8" });
  assets.set("/" + HTML_FILE, { body: html, type: "text/html; charset=utf-8" });
  for (const h of hashes) info.push(`内联脚本哈希 ${h}`);
  for (const h of styleHashes) info.push(`内联样式哈希 ${h}`);

  const wlPath = path.join(root, WORKLET_FILE);
  try {
    const wl = fs.readFileSync(wlPath);
    assets.set("/" + WORKLET_FILE, { body: wl, type: "text/javascript; charset=utf-8" });
  } catch (e) { errors.push(`读不到语音模块 ${wlPath}: ${e.message}`); }

  // 本地算法库：存在性 → 形状粗检 → 与 manifest.json 记录的 SHA-256 比对（记录缺失只警告，不符即报错）
  let manifest = null;
  try { manifest = JSON.parse(fs.readFileSync(path.join(vendorDir, "manifest.json"), "utf8")); } catch {}
  const present = [], missing = [];
  for (const name of VENDOR_FILES) {
    const p = path.join(vendorDir, name);
    let body;
    try { body = fs.readFileSync(p); } catch { missing.push(name); continue; }
    const sha = crypto.createHash("sha256").update(body).digest("hex");
    if (body.length < 1000 || /^\s*</.test(body.subarray(0, 64).toString("utf8"))) {
      errors.push(`vendor/${name} 看起来不是 JS 模块（太小或像 HTML 错误页），拒绝提供。`);
      continue;
    }
    const rec = manifest && manifest.files && manifest.files[name];
    if (manifest && (!rec || rec.sha256 !== sha)) {
      errors.push(`vendor/${name} 的 SHA-256（${sha}）与 vendor/manifest.json 的记录不一致：文件在固定之后被改动过，拒绝提供。`);
      continue;
    }
    assets.set("/vendor/" + name, { body, type: "text/javascript; charset=utf-8" });
    present.push(name); info.push(`本地算法库 vendor/${name}  ${body.length} 字节  sha256=${sha}`);
  }
  if (present.length && !manifest) warnings.push("vendor/ 下没有 manifest.json，无法核对算法库是否被改动过；请重新执行 npm run vendor。");
  const vendorComplete = present.length === VENDOR_FILES.length;
  if (vendorComplete) {
    info.push(manifest ? "本地算法库齐全且与 vendor/manifest.json 记录的 SHA-256 一致：CSP 不含任何第三方源，运行时不加载第三方代码。"
                       : "本地算法库齐全（但缺 manifest.json，未能核对哈希）：CSP 不含任何第三方源。");
  } else {
    errors.push(`本地算法库不齐全（缺 ${missing.join(", ") || "校验未通过的文件"}）。v3 失败即关闭、没有第三方 CDN 退路：请先执行 npm run vendor 把 ML-KEM / Argon2id 固定到本地。`);
  }
  const cspParts = { scriptHashes: hashes, styleHashes };
  const csp = buildCsp(cspParts);
  return { errors, warnings, info, assets, csp, cspParts, hashes, styleHashes, vendorComplete };
}

export function isOverTls(req, { trustProxy = false, nativeTls = false } = {}) {
  return nativeTls || (trustProxy && /^https$/i.test(String((req.headers && req.headers["x-forwarded-proto"]) || "").split(",")[0].trim()));
}

export function securityHeaders(req, { cspParts, csp, relayOrigins = [], trustProxy = false, nativeTls = false } = {}) {
  const overTls = isOverTls(req, { trustProxy, nativeTls });
  const policy = cspParts ? buildCsp({ ...cspParts, connect: connectSources(req, { trustProxy, overTls, relayOrigins }) }) : csp;
  const h = {
    "content-security-policy": policy,
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "origin-agent-cluster": "?1",
    "x-dns-prefetch-control": "off",
    "x-permitted-cross-domain-policies": "none",
    "permissions-policy":
      // 语音通话需要：仅向本源开放 microphone 与 autoplay；其余强能力 API 一律锁死。
      "accelerometer=(), autoplay=(self), bluetooth=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), " +
      "hid=(), idle-detection=(), magnetometer=(), microphone=(self), midi=(), payment=(), publickey-credentials-get=(), " +
      "screen-wake-lock=(), serial=(), usb=(), xr-spatial-tracking=()",
  };
  if (overTls) h["strict-transport-security"] = "max-age=31536000; includeSubDomains";
  return h;
}

export function makeStaticHandler({ assets, cspParts, csp, relayOrigins = [], trustProxy = false, nativeTls = false }) {
  return function serveStatic(req, res) {
    const sec = securityHeaders(req, { cspParts, csp, relayOrigins, trustProxy, nativeTls });
    const method = req.method || "GET";
    if (method !== "GET" && method !== "HEAD") {
      res.writeHead(405, { allow: "GET, HEAD", "content-length": 0, ...sec }); res.end(); return;
    }
    const p = (req.url || "/").split("?")[0];
    const asset = assets.get(p);
    if (!asset) {
      const body = "not found";
      res.writeHead(404, { "content-type": "text/plain; charset=utf-8", "content-length": Buffer.byteLength(body), "cache-control": "no-store", ...sec });
      res.end(method === "HEAD" ? undefined : body); return;
    }
    res.writeHead(200, {
      "content-type": asset.type,
      "content-length": asset.body.length,
      "cache-control": "no-store",
      ...sec,
    });
    res.end(method === "HEAD" ? undefined : asset.body);
  };
}

/* ---------------------------------------------------------------------------
 * 启动 / 自检（仅当直接运行本文件时；import 时不启动，便于测试纯逻辑）。
 * ------------------------------------------------------------------------- */
function isLoopback(host) { return /^(127\.|::1$|localhost$)/.test(String(host)); }

// TLS：只保留 ECDHE + AEAD（TLS 1.2）与 TLS 1.3 套件；优先协商 X25519MLKEM768 混合密钥交换。
// 中继看不到明文，但传输层承载的是房间号、信封密文与时序：抗量子的 TLS 让“先存后解”的
// 攻击者即使将来拥有量子计算机，也拿不到这层元数据。OpenSSL < 3.5 的 Node 不支持混合组，自动退回经典组。
export const TLS_CIPHERS = [
  "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256",
  "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-GCM-SHA384",
  "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-CHACHA20-POLY1305",
  "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256",
].join(":");
export const TLS_GROUPS_PQ = "X25519MLKEM768:X25519:P-256:P-384";
export const TLS_GROUPS_CLASSIC = "X25519:P-256:P-384";
export function tlsGroups(wantPq = true) {
  if (wantPq) { try { tls.createSecureContext({ ecdhCurve: TLS_GROUPS_PQ }); return { groups: TLS_GROUPS_PQ, pq: true }; } catch {} }
  return { groups: TLS_GROUPS_CLASSIC, pq: false };
}

export function runCheck(cfg = readConfig(), { log = console } = {}) {
  const prep = prepareAssets({ vendorDir: cfg.VENDOR_DIR });
  for (const s of prep.info) log.log("[信息] " + s);
  for (const s of prep.warnings) log.warn("[警告] " + s);
  for (const s of prep.errors) log.error("[错误] " + s);
  log.log("[信息] 响应头 CSP（connect-src 按请求 Host 追加本站 ws(s)://）= " + prep.csp);
  const nativeTls = !!(cfg.TLS_CERT && cfg.TLS_KEY);
  if (!nativeTls && !cfg.TRUST_PROXY && !isLoopback(cfg.HOST)) {
    log.warn("[警告] 以纯 HTTP 监听非回环地址且未设置 TRUST_PROXY：浏览器在 http:// 下不提供 Web Crypto 与麦克风，本页无法工作；" +
      "请用 TLS_CERT/TLS_KEY 开启原生 TLS，或置于 TLS 反向代理之后并设置 TRUST_PROXY=1。");
  }
  if (nativeTls) {
    const g = tlsGroups(cfg.TLS_PQ);
    log.log(`[信息] TLS 密钥交换组：${g.groups}${g.pq ? "（优先 X25519MLKEM768 混合，抗量子）" : cfg.TLS_PQ ? "（此 Node/OpenSSL 不支持 ML-KEM 混合组，已退回经典组；升级到带 OpenSSL 3.5+ 的 Node 22.20+/24 可启用）" : "（TLS_PQ=0 已关闭混合组）"}`);
  }
  if (cfg.TRUST_PROXY) log.log(`[信息] TRUST_PROXY=1：客户端 IP 取 X-Forwarded-For 从右数第 ${cfg.TRUST_PROXY_HOPS} 个值（=你部署的可信代理层数）。`);
  if (cfg.ALLOWED_ORIGINS.includes("*")) log.warn("[警告] ALLOWED_ORIGINS=*：任何网站的页面都可以在用户浏览器里连接本中继。");
  for (const o of cfg.RELAY_ORIGINS) if (!normalizeWsOrigin(o)) log.warn(`[警告] RELAY_ORIGINS 里的 ${o} 不是 ws:// 或 wss:// 地址，已忽略。`);
  return { ok: prep.errors.length === 0, prep };
}

async function startServer(cfg = readConfig()) {
  const { WebSocketServer } = await import("ws");             // 仅运行时需要
  const { ok, prep } = runCheck(cfg);
  if (!ok) { console.error("启动中止：请先修复上面的 [错误]。"); process.exit(1); }

  const nativeTls = !!(cfg.TLS_CERT && cfg.TLS_KEY);
  const handler = makeStaticHandler({ assets: prep.assets, cspParts: prep.cspParts, relayOrigins: cfg.RELAY_ORIGINS, trustProxy: cfg.TRUST_PROXY, nativeTls });
  const serverOpts = { maxHeaderSize: 16 * 1024 };
  const groups = tlsGroups(cfg.TLS_PQ);
  const server = nativeTls
    ? https.createServer({
        ...serverOpts, cert: fs.readFileSync(cfg.TLS_CERT), key: fs.readFileSync(cfg.TLS_KEY),
        minVersion: cfg.TLS_MIN, ciphers: TLS_CIPHERS, honorCipherOrder: true, ecdhCurve: groups.groups,
      }, handler)
    : http.createServer(serverOpts, handler);
  server.headersTimeout = 15000;
  server.requestTimeout = 30000;
  server.keepAliveTimeout = 5000;
  server.maxHeadersCount = 100;
  server.maxRequestsPerSocket = 1000;
  server.on("clientError", (_err, socket) => { try { socket.destroy(); } catch {} });

  const hub = makeHub({ maxRoom: cfg.MAX_ROOM, bpHigh: cfg.BP_HIGH, bpLow: cfg.BP_LOW });
  const wss = new WebSocketServer({
    noServer: true,                 // 准入检查在 upgrade 阶段完成，握手前就拒绝
    maxPayload: cfg.MAX_PAYLOAD,
    perMessageDeflate: false,       // 密文不可压缩；避免 zlib 内存放大与压缩侧信道
    clientTracking: true,
  });
  wss.on("error", () => {});
  wss.on("connection", makeConnectionHandler({ hub, cfg }));

  const originAllowed = makeOriginPolicy(cfg.ALLOWED_ORIGINS, { trustProxy: cfg.TRUST_PROXY });
  const connLimiter = makeKeyedLimiter({ ratePerSec: cfg.CONN_RATE, burst: cfg.CONN_BURST });
  const ipConns = new Map();
  server.on("upgrade", (req, socket, head) => {
    const deny = (code, text) => {
      try { socket.write(`HTTP/1.1 ${code} ${text}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`); } catch {}
      try { socket.destroy(); } catch {}
    };
    socket.on("error", () => {});
    if (!originAllowed(req)) return deny(403, "Forbidden");
    const key = ipKey(clientIp(req, cfg.TRUST_PROXY, cfg.TRUST_PROXY_HOPS));
    if (!connLimiter.take(key)) return deny(429, "Too Many Requests");
    if (cfg.MAX_CONN > 0 && wss.clients.size >= cfg.MAX_CONN) return deny(503, "Service Unavailable");
    if (cfg.MAX_CONN_IP > 0) {
      const n = ipConns.get(key) || 0;
      if (n >= cfg.MAX_CONN_IP) return deny(429, "Too Many Requests");
      ipConns.set(key, n + 1);
      socket.once("close", () => {                    // 无论握手成败，原始 socket 关闭即回收计数
        const m = (ipConns.get(key) || 1) - 1;
        if (m <= 0) ipConns.delete(key); else ipConns.set(key, m);
      });
    }
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit("connection", ws, req));
  });

  const sweepMs = cfg.HEARTBEAT_MS > 0 ? cfg.HEARTBEAT_MS : 30000;
  const iv = setInterval(() => {
    if (cfg.HEARTBEAT_MS > 0) heartbeatSweep(wss.clients, { stallMs: cfg.BP_STALL_MS });
    connLimiter.sweep();
  }, sweepMs);
  wss.on("close", () => clearInterval(iv));

  const shutdown = () => {
    for (const c of wss.clients) { try { c.close(1001, "server shutdown"); } catch {} }
    wss.close(); server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 3000).unref();
  };
  process.once("SIGTERM", shutdown); process.once("SIGINT", shutdown);

  server.listen(cfg.PORT, cfg.HOST, () => {
    const scheme = nativeTls ? "https" : "http";
    const originDesc = cfg.ALLOWED_ORIGINS.includes("*") ? "任意（已显式放开）"
      : cfg.ALLOWED_ORIGINS.length ? `同源 + ${cfg.ALLOWED_ORIGINS.join("|")}` : "仅同源（默认；跨站页面连接请设 ALLOWED_ORIGINS）";
    console.log(
      `pqsession 中继 v3 已启动 → ${scheme}://${cfg.HOST}:${cfg.PORT}\n` +
      `  单帧上限 ${(cfg.MAX_PAYLOAD / 1048576).toFixed(0)} MiB · 消息限流 ${cfg.MSG_RATE}/s · 字节整形 ${cfg.BYTES_RATE ? (cfg.BYTES_RATE / 1048576).toFixed(0) + " MiB/s" : "关闭"}\n` +
      `  背压 高/低水位 ${(cfg.BP_HIGH / 1048576).toFixed(0)}/${(cfg.BP_LOW / 1048576).toFixed(0)} MiB · 僵死判定 ${cfg.BP_STALL_MS} ms · 心跳 ${cfg.HEARTBEAT_MS} ms\n` +
      `  每 IP 连接上限 ${cfg.MAX_CONN_IP || "不限"} · 新建连接 ${cfg.CONN_RATE ? cfg.CONN_RATE + "/s（突发 " + cfg.CONN_BURST + "）" : "不限"} · 全局上限 ${cfg.MAX_CONN || "不限"} · 未入房清理 ${cfg.JOIN_TIMEOUT_MS} ms\n` +
      `  Origin 策略 ${originDesc} · TRUST_PROXY ${cfg.TRUST_PROXY ? "开（可信代理 " + cfg.TRUST_PROXY_HOPS + " 层）" : "关"} · 算法库 本地 vendor/（已核对 SHA-256）` +
      (nativeTls ? `\n  TLS ≥ ${cfg.TLS_MIN.replace("TLSv", "")} · 密钥交换 ${groups.pq ? "X25519MLKEM768 混合优先（抗量子）" : "经典（X25519/P-256）"}` : "") + "\n" +
      `  中继不记录任何每连接日志（元数据最小化）。`);
  });
}

const isMain = import.meta.url === url.pathToFileURL(process.argv[1] || "").href;
if (isMain) {
  if (process.argv.includes("--check")) process.exit(runCheck().ok ? 0 : 1);
  await startServer();
}
