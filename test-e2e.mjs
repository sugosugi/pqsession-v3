// 端到端测试（Node，无浏览器、无网络）：两个客户端（页面里真实的协议层 + 房间信封代码）经真实的中继逻辑
// （server.js 的 makeHub + makeConnectionHandler）跑完 v3 全流程，并扮演“恶意中继”发动攻击：
// 跨连接重放、无密钥注入、篡改、反射、丢帧；以及离线猜口令的代价。运行：node test-e2e.mjs
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import crypto from "node:crypto";
import { makeHub, makeConnectionHandler, readConfig } from "./server.js";
import { loadPage, fakeKem, makeFakeArgon, makeClock, sha } from "./test-extract.mjs";

const mod = await loadPage();
const clock = makeClock();
const pq = mod.createPQSession({ subtle: globalThis.crypto.subtle, randomBytes: (n) => new Uint8Array(crypto.randomBytes(n)), mlkem: fakeKem, argon2id: makeFakeArgon(), now: clock.now });
mod.bindPq(pq);
const enc = new TextEncoder(), dec = new TextDecoder();
const cat = (...a) => pq.concatBytes(...a);
const FR_TEXT = 0x00, FR_CTRL = 0x01, RK_OFFER = 0x58, RK_ANSWER = 0x59, RK_CONFIRM = 0x5a;
let passed = 0;
async function test(name, fn) { await fn(); passed++; console.log("  ✓ " + name); }

const hub = makeHub({ maxRoom: 2 });
const onConn = makeConnectionHandler({ hub, cfg: { ...readConfig({}), JOIN_TIMEOUT_MS: 0 }, setTimer: () => null, clearTimer: () => {} });
const tap = [];                                   // 恶意中继：录下它转发的每一帧
let deliveries = 0;

class Wire extends EventEmitter {                 // 中继一侧看到的“ws 连接”
  constructor(c) { super(); this.c = c; this.room = null; this.bufferedAmount = 0; this.closed = false; }
  send(s, cb) {
    const m = JSON.parse(s); tap.push({ to: this.c.name, conn: this.c.conn, m });
    if (m.t === "sig" && this.c.dropNext) this.c.dropNext = false; else this.c.deliver(m);
    if (cb) cb();
  }
  pause() {} resume() {} ping() {} terminate() { this.close(); }
  close() { if (!this.closed) { this.closed = true; this.emit("close"); } }
}

class Client {                                    // 与页面相同的帧规则（精简版），协议与信封用的是页面里的真实代码
  constructor(name, id) { Object.assign(this, { name, id, texts: [], dropped: [], errors: [], byes: 0, conn: 0 }); }
  connect(keys) {
    Object.assign(this, { room: mod.makeRoomCtx(keys), inbox: Promise.resolve(), tx: Promise.resolve(), peer: null, role: null,
      session: null, pending: null, replied: "", helloSent: false, established: false, full: false, kinds: [] });
    this.conn++;
    this.wire = new Wire(this); onConn(this.wire);
    this.up({ t: "join", room: this.room.id });
  }
  disconnect() { this.wire.close(); if (this.session) pq.sessionWipe(this.session); this.session = null; this.established = false; }
  up(obj) { this.wire.emit("message", Buffer.from(JSON.stringify(obj)), false); }
  deliver(m) { deliveries++; this.inbox = this.inbox.then(() => this.onMsg(m)).catch((e) => this.errors.push(e.message)); }
  idle() { return this.inbox.then(() => this.tx); }
  async sendKind(kind, payload) { mod.setRoom(this.room); const d = await mod.sealKind(kind, payload); this.up({ t: "sig", d }); return d; }
  sendMsg(bytes) {
    const s = this.session;
    this.tx = this.tx.then(async () => this.sendKind(mod.KIND_MSG, await pq.ratchetEncrypt(s, bytes))).catch((e) => { this.errors.push("tx: " + e.message); });
    return this.tx;
  }
  text(t) { return this.sendMsg(cat(new Uint8Array([FR_TEXT]), enc.encode(t))); }
  helloBytes() { return enc.encode(JSON.stringify({ v: 3, pub: this.id.pub })); }
  async hello() { if (this.helloSent) return; this.helloSent = true; await this.sendKind(mod.KIND_HELLO, this.helloBytes()); }
  ctx() {
    const [ti, tr] = this.role === "init" ? [this.room.tag, this.room.peerTag] : [this.room.peerTag, this.room.tag];
    return cat(enc.encode("pqsession/3|hs-ctx"), this.room.idBytes, ti, tr);
  }
  async onMsg(m) {
    if (m.t === "joined") { if (m.n >= 2) await this.hello(); return; }
    if (m.t === "peer") { if (m.event === "join") await this.hello(); return; }
    if (m.t === "full") { this.full = true; return; }
    if (m.t !== "sig") return;
    mod.setRoom(this.room);
    let f; try { f = await mod.unsealKind(m.d); } catch (e) { this.dropped.push("unseal: " + e.message); return; }
    if (!f) { this.dropped.push("reflected"); return; }
    this.kinds.push(f.kind);
    if (f.kind === mod.KIND_HELLO) return this.onHello(f);
    if (!this.room.peerTagHex || f.tagHex !== this.room.peerTagHex || !f.toMe) { this.dropped.push("stale"); return; }
    const p = f.payload.slice();
    if (f.kind === mod.KIND_INVITE && this.role === "resp" && !this.established) {
      const r = await pq.sessionAccept(this.id, this.peer, p, this.ctx()); this.session = r.session; await this.sendKind(mod.KIND_ACCEPT, r.accept);
    } else if (f.kind === mod.KIND_ACCEPT && this.role === "init" && this.pending) {
      const pend = this.pending; this.pending = null;
      const r = await pq.sessionComplete(pend, p); this.session = r.session; await this.sendKind(mod.KIND_FINISH, r.finish); this.established = true;
    } else if (f.kind === mod.KIND_FINISH && this.role === "resp" && this.session && !this.session.confirmed) {
      pq.sessionConfirm(this.session, p); this.established = true;
    } else if (f.kind === mod.KIND_MSG && this.session) {
      const pt = await pq.ratchetDecrypt(this.session, p);
      if (pt[0] === FR_TEXT) this.texts.push(dec.decode(pt.subarray(1)));
      else if (pt[0] === FR_CTRL && pt[1] === RK_OFFER) { const a = await pq.rekeyOnOffer(this.session, pt.subarray(2)); if (a) await this.sendMsg(cat(new Uint8Array([FR_CTRL, RK_ANSWER]), a)); }
      else if (pt[0] === FR_CTRL && pt[1] === RK_ANSWER) { const c = await pq.rekeyOnAnswer(this.session, pt.subarray(2)); if (c) await this.sendMsg(cat(new Uint8Array([FR_CTRL, RK_CONFIRM]), c)); }
    } else if (f.kind === mod.KIND_BYE) {
      if (this.session) pq.sessionWipe(this.session); this.session = null; this.established = false; this.byes++;
    }
  }
  async onHello(f) {
    const o = JSON.parse(dec.decode(f.payload)); pq.validatePub(o.pub);
    if (!this.peer) {
      this.peer = o.pub; this.room.peerTag = f.tag; this.room.peerTagHex = f.tagHex;
      this.role = Buffer.compare(Buffer.from(pq.b64decode(this.id.pub.x25519_pub)), Buffer.from(pq.b64decode(o.pub.x25519_pub))) < 0 ? "init" : "resp";
    }
    if (!this.helloSent) { this.replied = f.tagHex; await this.hello(); }
    else if (!f.toMe && this.replied !== f.tagHex) { this.replied = f.tagHex; await this.sendKind(mod.KIND_HELLO, this.helloBytes()); }
    if (this.role === "init" && !this.pending && !this.session) { const r = await pq.sessionInvite(this.id, this.peer, this.ctx()); this.pending = r.pending; await this.sendKind(mod.KIND_INVITE, r.invite); }
  }
}
async function settle(...cs) {
  for (let i = 0; i < 500; i++) {
    const d0 = deliveries;
    await Promise.all(cs.map((c) => c.idle())); await new Promise((r) => setTimeout(r, 0));
    if (deliveries === d0) return;
  }
  throw new Error("未能静止");
}
const hexOf = (b) => Buffer.from(b).toString("hex");

const CODE = "K7M2QPRS4XAB";
const keys = await mod.deriveRoomKeys(CODE, makeFakeArgon());
const A = new Client("A", await pq.generateKeypair()), B = new Client("B", await pq.generateKeypair());

console.log("经真实中继的完整流程");
await test("加入同一房间 → 身份声明（带连接标签）→ INVITE / ACCEPT / FINISH → 两端会话一致；双向消息", async () => {
  A.connect(keys); B.connect(keys); await settle(A, B);
  assert.ok(A.established && B.established, JSON.stringify({ A: A.errors, B: B.errors }));
  assert.equal(hexOf(A.session.sid), hexOf(B.session.sid));
  await A.text("你好 B"); await B.text("你好 A"); await settle(A, B);
  assert.deepEqual(B.texts, ["你好 B"]); assert.deepEqual(A.texts, ["你好 A"]);
});
await test("经中继的混合重新密钥：两端进入纪元 1，之后双向消息照常", async () => {
  const init = A;
  await init.sendMsg(cat(new Uint8Array([FR_CTRL, RK_OFFER]), await pq.rekeyStart(init.session))); await settle(A, B);
  await B.text("纪元 1"); await A.text("收到"); await settle(A, B);
  assert.equal(A.session.epoch, 1); assert.equal(B.session.epoch, 1);
  assert.deepEqual(A.texts.at(-1), "纪元 1"); assert.deepEqual(B.texts.at(-1), "收到");
});
await test("第三个客户端用同一口令加入：房间已满（1 对 1）", async () => {
  const C = new Client("C", await pq.generateKeypair()); C.connect(keys); await settle(C);
  assert.equal(C.full, true); C.disconnect();
});

console.log("恶意中继");
await test("篡改在途密文：信封认证失败被丢弃，会话不受影响（先验证后提交）", async () => {
  const origSend = Wire.prototype.send;
  Wire.prototype.send = function (s, cb) {
    const m = JSON.parse(s);
    if (m.t === "sig" && this.c === B && !this.done) { this.done = true; const c = Buffer.from(m.d.c, "base64"); c[c.length - 1] ^= 1; m.d.c = c.toString("base64"); return origSend.call(this, JSON.stringify(m), cb); }
    return origSend.call(this, s, cb);
  };
  await A.text("被篡改的这条会丢失"); await settle(A, B);
  Wire.prototype.send = origSend;
  assert.ok(B.dropped.some((x) => /信令帧认证失败/.test(x)));
  await A.text("下一条照常"); await settle(A, B);
  assert.equal(B.texts.at(-1), "下一条照常");
});
await test("不知道口令就注入 / 反射：伪造帧认证失败，反射回来的自己的帧被忽略", async () => {
  B.deliver({ t: "sig", d: { v: 3, n: crypto.randomBytes(12).toString("base64"), c: crypto.randomBytes(300).toString("base64") } });
  const mine = tap.filter((e) => e.to === B.name && e.m.t === "sig").at(-1).m.d;   // A 发出的一帧
  A.deliver({ t: "sig", d: mine });
  await settle(A, B);
  assert.ok(B.dropped.at(-1).startsWith("unseal: 信令帧认证失败")); assert.equal(A.dropped.at(-1), "reflected");
});
await test("跨连接重放（中继无需口令）：旧连接的 INVITE / ACCEPT / FINISH / 消息 / BYE 在新连接里全部被丢弃，新会话毫发无损", async () => {
  await A.sendKind(mod.KIND_BYE, new Uint8Array(0)); await settle(A, B);          // 旧连接里真实发生过的 BYE
  assert.equal(B.byes, 1);
  const recorded = tap.filter((e) => e.to === B.name && e.conn === 1 && e.m.t === "sig").map((e) => e.m.d);
  const oldKinds = B.kinds.slice();
  A.disconnect(); B.disconnect();
  A.connect(keys); B.connect(keys); await settle(A, B);                           // 双方重连：新标签、新会话
  assert.ok(A.established && B.established);
  const sid = hexOf(B.session.sid), texts = B.texts.length, byes = B.byes, stale0 = B.dropped.filter((x) => x === "stale").length;
  for (const d of recorded) B.deliver({ t: "sig", d });
  await settle(A, B);
  const nonHello = oldKinds.filter((k) => k !== mod.KIND_HELLO).length;
  assert.ok(nonHello >= 6, "旧连接录到了握手、消息与 BYE");
  assert.equal(B.dropped.filter((x) => x === "stale").length - stale0, nonHello, "每一条非身份声明的旧帧都被判为“不属于本次连接”");
  assert.equal(B.byes, byes, "旧 BYE 没有拆掉新会话（v2 会）");
  assert.equal(hexOf(B.session.sid), sid); assert.equal(B.texts.length, texts);
  await A.text("重放之后照常"); await settle(A, B);
  assert.equal(B.texts.at(-1), "重放之后照常"); assert.deepEqual(B.errors, []);
});
await test("丢帧：重新密钥的 ANSWER 被中继丢掉 → 发起方超时放弃、重来 → 双方一致进入新纪元", async () => {
  const e0 = A.session.epoch;
  A.dropNext = true;                                                            // 下一条发给 A 的帧（B 的 ANSWER）被丢弃
  await A.sendMsg(cat(new Uint8Array([FR_CTRL, RK_OFFER]), await pq.rekeyStart(A.session))); await settle(A, B);
  assert.equal(A.session.epoch, e0); assert.equal(B.session.rekey && B.session.rekey.role, "answer");
  clock.t += 31000; assert.equal(pq.rekeyExpire(A.session, 30000), true);
  await A.sendMsg(cat(new Uint8Array([FR_CTRL, RK_OFFER]), await pq.rekeyStart(A.session))); await settle(A, B);
  await B.text("新纪元"); await settle(A, B);
  assert.equal(A.session.epoch, e0 + 1); assert.equal(B.session.epoch, e0 + 1); assert.equal(A.texts.at(-1), "新纪元");
});

console.log("离线猜口令的代价");
await test("中继只知道房间标识：验证一个猜测必须跑一次 Argon2id（v2 只要一次 SHA-256）", async () => {
  const kdf = makeFakeArgon();
  const guesses = ["AAAAAAAAAAAA", "K7M2QPRS4XAA", "ZZZZZZZZZZZZ", CODE];
  let hit = null;
  for (const g of guesses) { const k = await mod.deriveRoomKeys(g, kdf); if (hexOf(k.idBytes) === A.room.id) hit = g; }
  assert.equal(hit, CODE); assert.equal(kdf.calls, guesses.length, "每个猜测一次 KDF");
  const v2 = (code) => hexOf(sha(enc.encode("pqsession-room-id-v2"), enc.encode(code))).slice(0, 32);
  assert.notEqual(v2(CODE), A.room.id, "v3 房间标识与 v2 的快速哈希无关");
});

A.disconnect(); B.disconnect();
console.log(`\n全部通过：${passed} 项。`);
