#!/usr/bin/env node
// 真实浏览器端到端测试（可选）：用 Playwright 驱动两个独立的 Chromium 上下文，经真实的 server.js 中继跑完整流程：
//   生成身份 → 加入同一房间 → 核对指纹 → 三消息握手 → 双向聊天 → 双方各发起一次混合重新密钥 →
//   文件传输（收方必须点「保存」才落盘，且不会自动下载）→ 端到端加密语音通话（Chromium 假麦克风）→
//   断开重连后按信任列表自动通过核对。全程记录 CSP / Trusted Types 违规与页面异常，出现即失败。
// 用法：  npm i -D playwright && npx playwright install chromium && npm run vendor && npm run test:browser
//         VENDOR_DIR=/path/to/vendor node test-browser.mjs   （默认 ./vendor；需要 npm run vendor 的真实算法库）
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
let chromium;
try { ({ chromium } = await import("playwright")); }
catch { console.log("跳过：未安装 playwright（npm i -D playwright && npx playwright install chromium）。"); process.exit(0); }
const VENDOR_DIR = process.env.VENDOR_DIR || path.join(ROOT, "vendor");
if (!fs.existsSync(path.join(VENDOR_DIR, "ml-kem.mjs"))) { console.log(`跳过：${VENDOR_DIR} 下没有算法库（先 npm run vendor）。`); process.exit(0); }

const PORT = 20000 + crypto.randomInt(20000);
const srv = spawn(process.execPath, [path.join(ROOT, "server.js")], {
  cwd: ROOT, env: { ...process.env, PORT: String(PORT), HOST: "127.0.0.1", VENDOR_DIR }, stdio: ["ignore", "pipe", "pipe"],
});
let srvOut = ""; srv.stdout.on("data", (d) => (srvOut += d)); srv.stderr.on("data", (d) => (srvOut += d));
for (let i = 0; i < 50 && !/已启动/.test(srvOut); i++) await new Promise((r) => setTimeout(r, 100));
if (!/已启动/.test(srvOut)) { console.error(srvOut); srv.kill(); process.exit(1); }

const browser = await chromium.launch({ args: ["--use-fake-ui-for-media-stream", "--use-fake-device-for-media-stream", "--autoplay-policy=no-user-gesture-required"] });
const url = `http://127.0.0.1:${PORT}/`;
const problems = [];
let passed = 0;
async function step(name, fn) { await fn(); passed++; console.log("  ✓ " + name); }

async function open(name) {
  const ctx = await browser.newContext({ acceptDownloads: true });
  const page = await ctx.newPage();
  await page.addInitScript(() => {
    window.__cspv = [];
    document.addEventListener("securitypolicyviolation", (e) => window.__cspv.push(`${e.violatedDirective} ${e.blockedURI}`));
  });
  page.on("pageerror", (e) => problems.push(`[${name} pageerror] ${e.message}`));
  page.on("console", (m) => { if (/Refused|Content Security Policy|TrustedHTML|TrustedScript/.test(m.text())) problems.push(`[${name} console] ${m.text()}`); });
  page.__downloads = 0; page.on("download", () => { page.__downloads++; });
  await page.goto(url);
  return page;
}
const txt = (p, sel) => p.textContent(sel);
const visible = (p, id) => p.waitForFunction((i) => !document.getElementById(i).classList.contains("hide"), id, { timeout: 30000 });

try {
  console.log("浏览器端到端（真实 Chromium × 2，经真实中继）");
  await step("响应头：CSP 无 unsafe-inline / blob: / 第三方源，connect-src 只含本站；Trusted Types 与 frame-ancestors 生效", async () => {
    const r = await fetch(url);
    const csp = r.headers.get("content-security-policy");
    assert.ok(csp && !/unsafe-inline|blob:|esm\.sh/.test(csp), csp);
    assert.match(csp, new RegExp(`connect-src 'self' wss://127\\.0\\.0\\.1:${PORT} ws://127\\.0\\.0\\.1:${PORT};`));
    assert.match(csp, /require-trusted-types-for 'script'/);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.equal((await fetch(url + "vc-worklet.js")).status, 200);
  });

  const A = await open("A"), B = await open("B");
  const gen = async (p) => { await p.click("#genBtn"); await p.waitForFunction(() => /^([0-9a-f]{4} ){15}[0-9a-f]{4}$/.test(document.getElementById("idFp").textContent)); return txt(p, "#idFp"); };
  const fpA = await gen(A), fpB = await gen(B);
  const code = "T" + crypto.randomBytes(6).toString("hex").toUpperCase();
  const connect = async (p) => { await p.click('nav button[data-tab="connect"]'); await p.fill("#roomCode", code); await p.click("#connectBtn"); };

  await step("两端加入同一房间，各自看到对方的完整指纹", async () => {
    await connect(A); await connect(B);
    await A.waitForFunction((fp) => document.getElementById("peerFp").textContent === fp, fpB, { timeout: 30000 });
    await B.waitForFunction((fp) => document.getElementById("peerFp").textContent === fp, fpA, { timeout: 30000 });
  });

  await step("核对指纹后三消息握手完成：两端会话 ID 一致，纪元 #0", async () => {
    for (const [p, n] of [[A, "小B"], [B, "小A"]]) { await p.fill("#peerNameIn", n); await p.check("#fpCheck"); await p.click("#verifyBtn"); }
    await visible(A, "chatLive"); await visible(B, "chatLive");
    const [sa, sb] = [await txt(A, "#sidShow"), await txt(B, "#sidShow")];
    assert.match(sa, /^[0-9a-f]{32}$/); assert.equal(sa, sb);
    assert.equal(await txt(A, "#epochShow"), "#0");
  });

  const say = async (from, to, msg) => {
    await from.fill("#msgIn", msg); await from.click("#sendBtn");
    await to.waitForFunction((m) => [...document.querySelectorAll("#transcript .bub.in")].some((b) => b.textContent === m), msg, { timeout: 15000 });
  };
  await step("双向文字消息（以 0x01 开头的文本也只当文本显示，不会被解析成控制帧）", async () => {
    await say(A, B, "你好，我是 A");
    await say(B, A, "收到，我是 B");
    await say(A, B, "\u0001F:evil.html\n<script>alert(1)</script>");
    assert.equal(B.__downloads, 0);
  });

  await step("A 手动发起混合重新密钥 → 两端都进入纪元 #1，之后消息照常", async () => {
    await A.click("#rekeyBtn");
    await A.waitForFunction(() => document.getElementById("epochShow").textContent.startsWith("#1"), null, { timeout: 15000 });
    await B.waitForFunction(() => document.getElementById("epochShow").textContent.startsWith("#1"), null, { timeout: 15000 });
    await say(B, A, "纪元 1 里 B 发的");
    await say(A, B, "纪元 1 里 A 发的");
  });

  await step("B 发起下一次重新密钥 → 两端纪元 #2", async () => {
    await B.waitForFunction(() => !document.getElementById("rekeyBtn").disabled, null, { timeout: 15000 });
    await B.click("#rekeyBtn");
    await B.waitForFunction(() => document.getElementById("epochShow").textContent.startsWith("#2"), null, { timeout: 15000 });
    await say(B, A, "纪元 2");
    await A.waitForFunction(() => document.getElementById("epochShow").textContent.startsWith("#2"), null, { timeout: 15000 });
    await say(A, B, "纪元 2 回复");
  });

  await step("文件：收齐后不自动下载；点「保存」才下载，内容逐字节一致", async () => {
    const content = crypto.randomBytes(700 * 1024);             // 跨越 512 KiB 分块
    await A.setInputFiles("#fileMsg", { name: "report.html", mimeType: "text/html", buffer: content });
    await B.waitForSelector(".savebtn", { timeout: 30000 });
    await new Promise((r) => setTimeout(r, 500));
    assert.equal(B.__downloads, 0, "不得自动下载");
    const [dl] = await Promise.all([B.waitForEvent("download"), B.click(".savebtn")]);
    assert.equal(dl.suggestedFilename(), "report.html");
    assert.ok(Buffer.from(fs.readFileSync(await dl.path())).equals(content), "内容一致");
  });

  await step("语音通话：同源 AudioWorklet 在 Trusted Types 下装载成功，双向收到语音包，挂断后两端结束", async () => {
    await A.click("#callBtn");
    await B.waitForSelector("#callAccept:not(.hide)", { timeout: 15000 });
    await B.click("#callAccept");
    const heard = (p) => p.waitForFunction(() => { const m = document.getElementById("callState").textContent.match(/已收 (\d+) 包/); return m && Number(m[1]) >= 15; }, null, { timeout: 20000 });
    await heard(A); await heard(B);
    await A.click("#callEnd");
    await B.waitForFunction(() => !/通话中/.test(document.getElementById("callState").textContent), null, { timeout: 15000 });
  });

  await step("B 断开：A 端会话被重置（密钥销毁）", async () => {
    await B.click('nav button[data-tab="connect"]');
    await B.click("#disconnectBtn");
    await A.waitForFunction(() => document.getElementById("chatLive").classList.contains("hide"), null, { timeout: 15000 });
  });

  await step("B 重新连接：双方按加密信任列表自动通过核对并建立新会话（新会话 ID）", async () => {
    const oldSid = await txt(A, "#sidShow");
    await B.click('nav button[data-tab="connect"]');
    await B.click("#connectBtn");
    await visible(A, "chatLive"); await visible(B, "chatLive");
    assert.match(await txt(A, "#trustState"), /自动通过/);
    const [sa, sb] = [await txt(A, "#sidShow"), await txt(B, "#sidShow")];
    assert.equal(sa, sb); assert.notEqual(sa, oldSid);
    await say(A, B, "重连后的新会话");
  });

  await step("全程没有 CSP / Trusted Types 违规、没有页面异常", async () => {
    for (const p of [A, B]) problems.push(...(await p.evaluate(() => window.__cspv)).map((v) => "[csp] " + v));
    assert.deepEqual(problems, []);
  });
  console.log(`\n全部通过：${passed} 项。`);
} catch (e) {
  console.error("\n失败：", e && e.message || e);
  if (problems.length) console.error(problems.join("\n"));
  process.exitCode = 1;
} finally {
  await browser.close(); srv.kill();
}
