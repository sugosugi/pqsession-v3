// 中继纯逻辑测试：不需要安装 ws，也不需要联网。  运行：npm test
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import {
  makeHub, makeRateLimiter, makeByteShaper, makeKeyedLimiter, heartbeatSweep, makeOriginPolicy, makeConnectionHandler,
  inlineScriptHashes, inlineStyleHashes, metaCspOf, inlineAttrViolations, buildCsp, prepareAssets, makeStaticHandler,
  readConfig, clientIp, ipKey, connectSources, normalizeWsOrigin, tlsGroups, TLS_GROUPS_CLASSIC,
  ROOT, HTML_FILE, VENDOR_FILES, WORKLET_FILE,
} from "./server.js";

let passed = 0;
function test(name, fn) { fn(); passed++; console.log("  ✓ " + name); }
const R1 = "0123456789abcdef0123456789abcdef", R2 = "fedcba9876543210fedcba9876543210";

// 假客户端：模仿 ws 8 的 WebSocket 对象（send/pause/resume/bufferedAmount/ping/terminate）
class FakeWs extends EventEmitter {
  constructor(name) {
    super(); this.name = name; this.out = []; this.paused = false; this.bufferedAmount = 0;
    this.pending = []; this.closed = null; this.terminated = false; this.pinged = 0; this.room = null;
  }
  send(s, cb) { this.out.push(JSON.parse(s)); if (cb) this.pending.push(cb); }
  flushOne() { const cb = this.pending.shift(); if (cb) cb(); }
  pause() { this.paused = true; }
  resume() { this.paused = false; }
  ping() { this.pinged++; }
  terminate() { this.terminated = true; this.emit("close"); }
  close(code, reason) { this.closed = { code, reason }; this.emit("close"); }
  sigs() { return this.out.filter((m) => m.t === "sig").map((m) => m.d); }
}

console.log("makeHub / 背压");
test("join + relay：只转发给另一端，d 原样不动；房间号必须是 32 位小写十六进制", () => {
  const hub = makeHub();
  const a = new FakeWs("a"), b = new FakeWs("b");
  assert.equal(hub.join(a, R1).n, 1);
  assert.equal(hub.join(b, R1).n, 2);
  assert.deepEqual(a.out[0], { t: "peer", event: "join", n: 2 });
  const d = { v: 3, n: "AAAA", c: "BBBB", nested: { x: [1, 2, { y: null }] } };
  assert.equal(hub.relay(a, d), 1);
  assert.deepEqual(b.sigs(), [d]);
  assert.equal(a.sigs().length, 0);
  const c = new FakeWs("c");
  assert.deepEqual(hub.join(c, R1), { ok: false, reason: "full" });
  for (const bad of [42, "r", "0123", R1.toUpperCase(), R1 + "0", "../" + R1.slice(3)]) assert.deepEqual(hub.join(c, bad), { ok: false, reason: "bad-room" });
  hub.leave(a);
  assert.deepEqual(b.out.at(-1), { t: "peer", event: "leave", n: 1 });
  assert.equal(hub.relay(a, d), 0, "离开房间后不再转发");
});
test("背压：对端缓冲过高 → 暂停来源；排空回调后 → 恢复；暂停期间心跳不误杀", () => {
  let t = 1000;
  const hub = makeHub({ bpHigh: 100, bpLow: 10, now: () => t });
  const a = new FakeWs("a"), b = new FakeWs("b");
  hub.join(a, R1); hub.join(b, R1);
  b.bufferedAmount = 500; hub.relay(a, "x"); hub.relay(a, "x2");
  assert.equal(a.paused, true); assert.equal(a.bpWaitOn, b); assert.equal(a.bpSince, 1000);
  b.bufferedAmount = 50; b.flushOne(); assert.equal(a.paused, true);
  b.bufferedAmount = 0; b.flushOne(); assert.equal(a.paused, false); assert.equal(a.bpWaitOn, null);
  b.bufferedAmount = 1000; hub.relay(a, "x3"); a.isAlive = false;
  assert.deepEqual(heartbeatSweep([a], { now: 2000, stallMs: 0 }), { pinged: 0, killed: 0 });
  assert.equal(a.terminated, false);
});
test("背压：对端离开时来源自动恢复；多原因 hold 全部解除才恢复", () => {
  const hub = makeHub({ bpHigh: 100, bpLow: 10 });
  const a = new FakeWs("a"), b = new FakeWs("b");
  hub.join(a, R1); hub.join(b, R1);
  b.bufferedAmount = 1000; hub.relay(a, "x"); hub.hold(a, "shape"); hub.leave(b);
  assert.equal(a.paused, true); hub.release(a, "shape"); assert.equal(a.paused, false);
});
test("心跳：未回 pong 的终止；被背压拖住超时的对端被判僵死终止", () => {
  const hub = makeHub({ bpHigh: 100, bpLow: 10, now: () => 0 });
  const a = new FakeWs("a"), b = new FakeWs("b"), c = new FakeWs("c");
  hub.join(a, R1); hub.join(b, R1); hub.join(c, R2);
  b.bufferedAmount = 1000; hub.relay(a, "x");
  a.isAlive = true; b.isAlive = true; c.isAlive = false;
  assert.deepEqual(heartbeatSweep([a, b, c], { now: 30000, stallMs: 60000 }), { pinged: 1, killed: 1, stalled: 0 });
  a.isAlive = true; b.isAlive = true;
  assert.equal(heartbeatSweep([a, b], { now: 61000, stallMs: 60000 }).stalled, 1);
  assert.equal(b.terminated, true); assert.equal(a.terminated, false);
  hub.leave(b); assert.equal(a.paused, false);
});

console.log("限流 / 整形");
test("消息令牌桶；字节整形不丢帧、返回需暂停的毫秒数", () => {
  const rl = makeRateLimiter({ ratePerSec: 10, burst: 3 });
  assert.deepEqual([rl.take(1000), rl.take(1000), rl.take(1000), rl.take(1000)], [true, true, true, false]);
  assert.equal(rl.take(1100), true); assert.equal(rl.take(1100), false);
  const sh = makeByteShaper({ bytesPerSec: 1000, burst: 2000 });
  assert.equal(sh.consume(1500, 5000), 0); assert.equal(sh.consume(1500, 5000), 1000); assert.equal(sh.consume(0, 6000), 0);
  assert.equal(makeByteShaper({ bytesPerSec: 0, burst: 0 }).consume(1e9), 0);
});
test("按来源的新建连接限速：突发后拒绝、随时间恢复；桶数有上限；sweep 回收已回满的桶；速率 0 = 不限", () => {
  const kl = makeKeyedLimiter({ ratePerSec: 1, burst: 2, maxKeys: 3 });
  assert.deepEqual([kl.take("a", 0), kl.take("a", 0), kl.take("a", 0)], [true, true, false]);
  assert.equal(kl.take("b", 0), true); assert.equal(kl.take("a", 1000), true);
  kl.take("c", 1000); kl.take("d", 1000); assert.ok(kl.size <= 3);
  kl.sweep(100000); assert.equal(kl.size, 0);
  const off = makeKeyedLimiter({ ratePerSec: 0 }); for (let i = 0; i < 100; i++) assert.equal(off.take("x", 0), true);
});

console.log("客户端 IP（v2 的 X-Forwarded-For 伪造回归）/ IPv6 前缀");
test("TRUST_PROXY：只信任 XFF 从右数第 hops 个值；客户端自己填的最左值被忽略", () => {
  const req = (xff, sock = "10.0.0.2") => ({ headers: xff === undefined ? {} : { "x-forwarded-for": xff }, socket: { remoteAddress: sock } });
  assert.equal(clientIp(req("6.6.6.6, 1.2.3.4"), true), "1.2.3.4", "v2 会取到攻击者随手填的 6.6.6.6");
  const keys = new Set(); for (let i = 0; i < 50; i++) keys.add(ipKey(clientIp(req(`${i}.${i}.${i}.${i}, 1.2.3.4`), true)));
  assert.equal(keys.size, 1, "攻击者每次换一个伪造值也只算同一个来源");
  assert.equal(clientIp(req("6.6.6.6, 1.2.3.4, 10.9.9.9"), true, 2), "1.2.3.4");
  assert.equal(clientIp(req("1.2.3.4"), true, 2), "10.0.0.2", "条目比可信层数少：退回 socket 地址（宁严勿松）");
  assert.equal(clientIp(req(undefined, "::ffff:10.0.0.7"), false), "10.0.0.7");
  assert.equal(clientIp(req("6.6.6.6"), false), "10.0.0.2", "未开 TRUST_PROXY 时完全不看 XFF");
  assert.equal(clientIp(req("1.2.3.4:5678"), true), "1.2.3.4");
  assert.equal(clientIp(req("[2001:db8::1]:443"), true), "2001:db8::1");
});
test("IPv6 按 /64 合并计数；IPv4 与 IPv4 映射地址按完整地址", () => {
  assert.equal(ipKey("2001:db8:1:2:aaaa::1"), ipKey("2001:db8:1:2:ffff:ffff:ffff:ffff"));
  assert.notEqual(ipKey("2001:db8:1:2::1"), ipKey("2001:db8:1:3::1"));
  assert.equal(ipKey("2001:db8::1"), "2001:db8:0:0::/64");
  assert.equal(ipKey("::ffff:192.0.2.1"), "192.0.2.1"); assert.equal(ipKey("192.0.2.1"), "192.0.2.1");
});

console.log("Origin 策略");
test("默认仅同源；列表；* 放行；缺 Origin / null / 非 http 拒绝", () => {
  const same = makeOriginPolicy([]);
  assert.equal(same({ headers: { origin: "https://chat.example.com", host: "chat.example.com" } }), true);
  assert.equal(same({ headers: { origin: "https://evil.example", host: "chat.example.com" } }), false);
  assert.equal(same({ headers: { host: "chat.example.com" } }), false);
  assert.equal(same({ headers: { origin: "null", host: "chat.example.com" } }), false);
  assert.equal(same({ headers: { origin: "file:///x", host: "chat.example.com" } }), false);
  const listed = makeOriginPolicy(["https://Front.example/"]);
  assert.equal(listed({ headers: { origin: "https://front.example", host: "relay.example" } }), true);
  assert.equal(listed({ headers: { origin: "https://other.example", host: "relay.example" } }), false);
  assert.equal(makeOriginPolicy(["*"])({ headers: {} }), true);
  assert.equal(makeOriginPolicy([], { trustProxy: true })({ headers: { origin: "https://pub.example", host: "10.0.0.5:8080", "x-forwarded-host": "pub.example" } }), true);
});

console.log("连接处理");
function wire(cfgOverride = {}) {
  const timers = [];
  const cfg = { ...readConfig({}), ...cfgOverride };
  const hub = makeHub({ bpHigh: cfg.BP_HIGH, bpLow: cfg.BP_LOW });
  const onConn = makeConnectionHandler({
    hub, cfg, now: () => 1e6,
    setTimer: (fn, ms) => { const h = { fn, ms, cleared: false }; timers.push(h); return h; },
    clearTimer: (h) => { h.cleared = true; },
  });
  return { hub, onConn, timers };
}
const J = (room) => Buffer.from(JSON.stringify({ t: "join", room }));
test("畸形输入（null / 数组 / 标量 / 垃圾 / 二进制 / 非法房间号）全部静默丢弃，不抛异常", () => {
  const { onConn } = wire();
  const ws = new FakeWs("x"); onConn(ws);
  for (const raw of ["null", "true", "1", "\"s\"", "[1,2]", "{", "", "{\"t\":\"sig\"}", "{\"t\":\"join\"}", "{\"t\":\"join\",\"room\":5}", "{\"t\":\"join\",\"room\":\"lobby\"}"]) ws.emit("message", Buffer.from(raw), false);
  ws.emit("message", Buffer.from([1, 2, 3]), true);
  assert.equal(ws.out.length, 0);
});
test("正常流程；未入房间的 sig 不转发；每条连接只能入房一次", () => {
  const { hub, onConn } = wire();
  const a = new FakeWs("a"), b = new FakeWs("b"); onConn(a); onConn(b);
  a.emit("message", J(R1), false);
  assert.deepEqual(a.out[0], { t: "joined", n: 1 });
  b.emit("message", Buffer.from(JSON.stringify({ t: "sig", d: "early" })), false);
  assert.equal(a.sigs().length, 0);
  b.emit("message", J(R1), false);
  b.emit("message", Buffer.from(JSON.stringify({ t: "sig", d: { v: 3 } })), false);
  assert.deepEqual(a.sigs(), [{ v: 3 }]);
  const n = a.out.length;
  a.emit("message", J(R2), false);
  assert.equal(a.out.length, n, "第二次 join 被忽略"); assert.equal(a.room, R1); assert.equal(hub.rooms.has(R2), false);
  const c = new FakeWs("c"); onConn(c); c.emit("message", J(R1), false);
  assert.deepEqual(c.out[0], { t: "full" });
  b.emit("close");
  assert.deepEqual(a.out.at(-1), { t: "peer", event: "leave", n: 1 });
});
test("入房超时；字节整形超额时暂停读取而不是丢帧", () => {
  const w1 = wire({ JOIN_TIMEOUT_MS: 5000 });
  const a = new FakeWs("a"), b = new FakeWs("b"); w1.onConn(a); w1.onConn(b);
  b.emit("message", J(R1), false);
  for (const h of w1.timers) if (!h.cleared) h.fn();
  assert.deepEqual(a.closed, { code: 1008, reason: "join timeout" }); assert.equal(b.closed, null);
  const w2 = wire({ BYTES_RATE: 1000, BYTES_BURST: 1000 });
  const x = new FakeWs("x"), y = new FakeWs("y"); w2.onConn(x); w2.onConn(y);
  x.emit("message", J(R1), false); y.emit("message", J(R1), false);
  x.emit("message", Buffer.from(JSON.stringify({ t: "sig", d: "x".repeat(3000) })), false);
  assert.equal(y.sigs().length, 1); assert.equal(x.paused, true);
  const shape = w2.timers.find((h) => h.ms > 0 && h.ms < 5000 && !h.cleared); shape.fn();
  assert.equal(x.paused, false);
});

console.log("CSP / 静态资源 / 算法库固定");
const html = fs.readFileSync(path.join(ROOT, HTML_FILE), "utf8");
function vendorDir({ manifest = true, tamper = false } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pq-vendor-"));
  const files = {};
  for (const f of VENDOR_FILES) {
    const body = `export const ok = ${JSON.stringify(f)};\n` + "// pad\n".repeat(300);
    fs.writeFileSync(path.join(dir, f), body);
    files[f] = { sha256: crypto.createHash("sha256").update(body).digest("hex") };
  }
  if (manifest) fs.writeFileSync(path.join(dir, "manifest.json"), JSON.stringify({ files }));
  if (tamper) fs.appendFileSync(path.join(dir, VENDOR_FILES[0]), "\n// 固定之后被改动\n");
  return dir;
}
test("页面：1 段内联脚本 + 1 段 <style>，哈希都在 <meta> 里；<meta> 不含 unsafe-inline / blob: / esm.sh；标记里没有内联属性", () => {
  const sh = inlineScriptHashes(html), st = inlineStyleHashes(html), meta = metaCspOf(html);
  assert.equal(sh.length, 1); assert.equal(st.length, 1);
  assert.ok(meta.includes(sh[0]) && meta.includes(st[0]));
  assert.ok(!/unsafe-inline|blob:|esm\.sh/.test(meta), meta);
  assert.match(meta, /require-trusted-types-for 'script'/);
  assert.deepEqual(inlineAttrViolations(html), []);
  assert.ok(!/fonts\.googleapis|fonts\.gstatic/.test(html));
});
test("失败即关闭：没有 vendor/ → 拒绝启动；齐全但缺 manifest → 仅警告；manifest 一致 → 通过；文件被改动或像 HTML 错误页 → 拒绝", () => {
  const none = prepareAssets({ vendorDir: path.join(os.tmpdir(), "pq-none-" + Date.now()) });
  assert.equal(none.errors.length, 1); assert.match(none.errors[0], /npm run vendor/);
  const noMan = prepareAssets({ vendorDir: vendorDir({ manifest: false }) });
  assert.deepEqual(noMan.errors, []); assert.ok(noMan.warnings.some((w) => /manifest/.test(w)));
  const ok = prepareAssets({ vendorDir: vendorDir() });
  assert.deepEqual(ok.errors, []); assert.deepEqual(ok.warnings, []);
  for (const f of VENDOR_FILES) assert.ok(ok.assets.has("/vendor/" + f));
  assert.ok(ok.assets.has("/" + WORKLET_FILE) && ok.assets.has("/") && ok.assets.has("/" + HTML_FILE));
  assert.ok(!/esm\.sh|blob:|unsafe-inline/.test(ok.csp)); assert.match(ok.csp, /frame-ancestors 'none'/);
  const tampered = prepareAssets({ vendorDir: vendorDir({ tamper: true }) });
  assert.ok(tampered.errors.some((e) => /manifest\.json 的记录不一致/.test(e)));
  const dir = vendorDir({ manifest: false }); fs.writeFileSync(path.join(dir, VENDOR_FILES[0]), "<html>Not Found</html>" + " ".repeat(2000));
  assert.ok(prepareAssets({ vendorDir: dir }).errors.some((e) => /不是 JS 模块/.test(e)));
});
test("页面被改动而 <meta> 未更新（脚本 / 样式）、出现内联属性、style-src 含 unsafe-inline → 拒绝启动", () => {
  const vd = vendorDir();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pq-html-"));
  fs.copyFileSync(path.join(ROOT, WORKLET_FILE), path.join(root, WORKLET_FILE));
  const tryHtml = (h) => { fs.writeFileSync(path.join(root, HTML_FILE), h); return prepareAssets({ root, vendorDir: vd }).errors; };
  assert.deepEqual(tryHtml(html), []);
  assert.match(tryHtml(html.replace("</script>", "\n// tampered\n</script>")).join(), /未包含内联脚本的当前哈希/);
  assert.match(tryHtml(html.replace("</style>", "\n.x{}\n</style>")).join(), /未包含 <style> 的当前哈希/);
  assert.match(tryHtml(html.replace('<div class="wrap">', '<div class="wrap" style="color:red">')).join(), /内联属性/);
  const meta = metaCspOf(html);
  assert.match(tryHtml(html.replace(meta, meta.replace("style-src ", "style-src 'unsafe-inline' "))).join(), /style-src 含 'unsafe-inline'/);
  assert.match(tryHtml(html.replace(meta, meta.replace("script-src ", "script-src 'unsafe-inline' "))).join(), /script-src 含 'unsafe-inline'/);
  fs.unlinkSync(path.join(root, WORKLET_FILE));
  assert.match(tryHtml(html).join(), /读不到语音模块/);
});
test("buildCsp 形状；connect-src 只含本站（按 Host 显式列出）与合法的 RELAY_ORIGINS", () => {
  const c = buildCsp({ scriptHashes: ["sha256-abc"], styleHashes: ["sha256-def"], connect: ["wss://x.example"] });
  assert.ok(c.startsWith("default-src 'none'; script-src 'self' 'wasm-unsafe-eval' 'sha256-abc'; style-src 'sha256-def'; img-src data:; connect-src 'self' wss://x.example; "));
  assert.match(c, /worker-src 'none'/); assert.match(c, /trusted-types 'none'/);
  const req = (host, extra = {}) => ({ headers: { host, ...extra } });
  assert.deepEqual(connectSources(req("chat.example.com"), { overTls: true }), ["wss://chat.example.com"]);
  assert.deepEqual(connectSources(req("127.0.0.1:8080")), ["wss://127.0.0.1:8080", "ws://127.0.0.1:8080"]);
  assert.deepEqual(connectSources(req("evil.example/x y")), []);
  assert.deepEqual(connectSources(req("a.example"), { overTls: true, relayOrigins: ["wss://Relay.Example:8443/path", "https://no.example", "junk"] }), ["wss://a.example", "wss://relay.example:8443"]);
  assert.deepEqual(connectSources(req("10.0.0.5:8080", { "x-forwarded-host": "pub.example" }), { trustProxy: true, overTls: true }), ["wss://pub.example"]);
  assert.equal(normalizeWsOrigin("https://x.example"), "");
});
test("静态处理：GET/HEAD 正常、其他方法 405、未知路径 404、带全部安全头；语音模块同源提供", () => {
  const prep = prepareAssets({ vendorDir: vendorDir() });
  const h = makeStaticHandler({ assets: prep.assets, cspParts: prep.cspParts, relayOrigins: [], trustProxy: true });
  function run(method, u, headers = {}) {
    let head = null, body = "";
    const res = { writeHead: (s, hs) => { head = { s, hs }; }, end: (b) => { body = b ? b.toString() : ""; } };
    h({ method, url: u, headers: { host: "chat.example.com", ...headers } }, res); return { ...head, body };
  }
  const r = run("GET", "/?x=1");
  assert.equal(r.s, 200); assert.ok(r.body.startsWith("<!doctype html>"));
  for (const k of ["content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "cross-origin-opener-policy", "cross-origin-resource-policy", "origin-agent-cluster", "permissions-policy", "cache-control"]) assert.ok(r.hs[k], "缺响应头 " + k);
  assert.match(r.hs["content-security-policy"], /connect-src 'self' wss:\/\/chat\.example\.com ws:\/\/chat\.example\.com;/);
  assert.match(r.hs["permissions-policy"], /microphone=\(self\)/); assert.match(r.hs["permissions-policy"], /autoplay=\(self\)/); assert.match(r.hs["permissions-policy"], /camera=\(\)/);
  assert.equal(r.hs["strict-transport-security"], undefined);
  const tlsR = run("GET", "/", { "x-forwarded-proto": "https" });
  assert.ok(tlsR.hs["strict-transport-security"]);
  assert.match(tlsR.hs["content-security-policy"], /connect-src 'self' wss:\/\/chat\.example\.com;/, "TLS 下不放行明文 ws://");
  const wl = run("GET", "/" + WORKLET_FILE); assert.equal(wl.s, 200); assert.match(wl.hs["content-type"], /text\/javascript/);
  const hd = run("HEAD", "/" + HTML_FILE); assert.equal(hd.s, 200); assert.equal(hd.body, "");
  assert.equal(run("POST", "/").s, 405);
  assert.equal(run("GET", "/../etc/passwd").s, 404);
  assert.equal(run("GET", "/vendor/manifest.json").s, 404);
});
test("TLS：优先 X25519MLKEM768 混合组（本机 OpenSSL 不支持时自动退回经典组）；TLS_PQ=0 时只用经典组", () => {
  const g = tlsGroups(true);
  assert.equal(typeof g.pq, "boolean");
  if (g.pq) assert.match(g.groups, /^X25519MLKEM768:/); else assert.equal(g.groups, TLS_GROUPS_CLASSIC);
  assert.deepEqual(tlsGroups(false), { groups: TLS_GROUPS_CLASSIC, pq: false });
  assert.equal(readConfig({}).TLS_PQ, true); assert.equal(readConfig({ TLS_PQ: "0" }).TLS_PQ, false);
  assert.equal(readConfig({ TLS_MIN: "1.3" }).TLS_MIN, "TLSv1.3");
});

console.log(`\n全部通过：${passed} 项。`);
