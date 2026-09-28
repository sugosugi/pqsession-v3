// 前端密码学层测试（Node 内跑，不需要浏览器，不需要联网）：测试的是 pqsession-net.html 里真正运行的代码
// （由 test-extract.mjs 原样提取）。注入尺寸忠实的假 KEM，验证 v3 的握手、双向确认、上下文绑定、
// 分纪元混合重新密钥（含丢包 / 并发 / 事后泄露自愈）、长度填充、房间信封、信任存储与语音时序。运行：node test-frontend.mjs
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { loadPage, src, fakeKem, makeFakeArgon, makeClock, sha } from "./test-extract.mjs";

const mod = await loadPage();
const clock = makeClock();
const pq = mod.createPQSession({ subtle: globalThis.crypto.subtle, randomBytes: (n) => new Uint8Array(crypto.randomBytes(n)), mlkem: fakeKem, argon2id: makeFakeArgon(), now: clock.now });
mod.bindPq(pq);
const enc = new TextEncoder(), dec = new TextDecoder();
const hexOf = (b) => Buffer.from(b).toString("hex");
let passed = 0;
async function test(name, fn) { await fn(); passed++; console.log("  ✓ " + name); }

console.log("身份 / 公钥校验");
await test("指纹 256 位、16 组；与 v2 指纹算法相同（升级后已核对的联系人不必重新核对）", async () => {
  const a = await pq.generateKeypair();
  assert.match(a.fingerprint, /^([0-9a-f]{4} ){15}[0-9a-f]{4}$/);
  const x = pq.b64decode(a.pub.x25519_pub), m = pq.b64decode(a.pub.mlkem_pub);
  assert.equal(a.fingerprint, hexOf(sha(enc.encode("pqsession-fingerprint-v2"), x, m)).match(/.{4}/g).join(" "));
});
await test("FIPS 203 模数检查：系数 3328 合法、3329 拒绝；validatePub 拒绝不合规 / 错长度 / 错算法", async () => {
  const pk = new Uint8Array(1568);
  pk[0] = 0x00; pk[1] = 0x0d; assert.equal(pq.mlkemPkValid(pk), true, "3328");
  pk[0] = 0x01; pk[1] = 0x0d; assert.equal(pq.mlkemPkValid(pk), false, "3329");
  pk[0] = 0; pk[1] = 0; pk[1535] = 0xff; pk[1534] = 0xf0; assert.equal(pq.mlkemPkValid(pk), false, "高半字节系数 4095");
  const a = await pq.generateKeypair();
  assert.deepEqual(Object.keys(pq.validatePub(a.pub)), ["x", "m"]);
  const bad = pq.b64decode(a.pub.mlkem_pub); bad[0] = 0xff; bad[1] = 0x0f;
  assert.throws(() => pq.validatePub({ ...a.pub, mlkem_pub: pq.b64encode(bad) }), /模数检查/);
  assert.throws(() => pq.validatePub({ ...a.pub, alg: "X25519" }), /算法/);
  assert.throws(() => pq.validatePub({ ...a.pub, x25519_pub: a.pub.x25519_pub.slice(4) }), /长度/);
  assert.throws(() => pq.validatePub(null), /无效/);
});
await test("身份文件：导出 / 载入往返；私钥与公钥不匹配（X25519 或 ML-KEM）一律拒绝；identityWipe 清零", async () => {
  const a = await pq.generateKeypair(), b = await pq.generateKeypair();
  const j = pq.identityToJSON(a);
  const back = await pq.identityFromJSON(JSON.parse(JSON.stringify(j)));
  assert.equal(back.fingerprint, a.fingerprint); assert.equal(hexOf(back.mSk), hexOf(a.mSk));
  await assert.rejects(pq.identityFromJSON({ ...j, x25519_pub: b.pub.x25519_pub }), /X25519 私钥与文件中的公钥不匹配/);
  await assert.rejects(pq.identityFromJSON({ ...j, mlkem_pub: b.pub.mlkem_pub }), /ML-KEM 私钥与文件中的公钥不匹配/);
  await assert.rejects(pq.identityFromJSON({ ...j, x25519_priv: pq.b64encode(new Uint8Array(31)) }), /长度/);
  await assert.rejects(pq.identityFromJSON({ ...j, mlkem_secret: undefined }), /缺少 mlkem_secret/);
  const xs = back.xPriv, ms = back.mSk; pq.identityWipe(back);
  assert.ok(xs.every((v) => v === 0) && ms.every((v) => v === 0) && back.xPriv === null);
});

console.log("握手（三消息 + 双向显式确认 + 上下文绑定）");
const CTX = enc.encode("ctx-1");
async function handshake(ctx = CTX) {
  const A = await pq.generateKeypair(), B = await pq.generateKeypair();
  const { invite, pending } = await pq.sessionInvite(A, B.pub, ctx);
  assert.equal(invite.length, pq.INVITE_LEN);
  const { accept, session: sb } = await pq.sessionAccept(B, A.pub, invite, ctx);
  assert.equal(accept.length, pq.ACCEPT_LEN);
  const { session: sa, finish } = await pq.sessionComplete(pending, accept);
  assert.equal(finish.length, pq.FINISH_LEN);
  assert.equal(pending.eaPriv, null, "握手完成后一次性私钥已清零/释放");
  assert.equal(sb.confirmed, false);
  await assert.rejects(pq.ratchetEncrypt(sb, enc.encode("too early")), /双向密钥确认/);
  pq.sessionConfirm(sb, finish);
  assert.equal(sb.confirmed, true);
  return { A, B, sa, sb, invite, finish };
}
const xfer = async (from, to, body) => pq.ratchetDecrypt(to, await pq.ratchetEncrypt(from, body));
await test("完整握手：长度精确；B 在收到 FINISH 前不能收发；会话 ID 一致；双向消息；重放与反射被拒", async () => {
  const { sa, sb } = await handshake();
  assert.equal(hexOf(sa.sid), hexOf(sb.sid)); assert.equal(sa.sid.length, 16);
  const c1 = await pq.ratchetEncrypt(sa, enc.encode("hi B"));
  assert.equal(dec.decode(await pq.ratchetDecrypt(sb, c1)), "hi B");
  assert.equal(dec.decode(await xfer(sb, sa, enc.encode("hi A"))), "hi A");
  await assert.rejects(pq.ratchetDecrypt(sb, c1), /重放/);
  await assert.rejects(pq.ratchetDecrypt(sa, c1), /方向/);
});
await test("篡改 ACCEPT → A 密钥确认失败且一次性私钥作废；篡改 FINISH → B 拒绝且会话作废；FINISH 只能用一次", async () => {
  const A = await pq.generateKeypair(), B = await pq.generateKeypair();
  const { invite, pending } = await pq.sessionInvite(A, B.pub, CTX);
  const { accept } = await pq.sessionAccept(B, A.pub, invite, CTX);
  const bad = accept.slice(); bad[bad.length - 1] ^= 1;
  await assert.rejects(pq.sessionComplete(pending, bad), /密钥确认失败/);
  await assert.rejects(pq.sessionComplete(pending, accept), /没有待完成的握手/, "失败后不能拿同一 INVITE 重试");
  const A2 = await pq.generateKeypair(), B2 = await pq.generateKeypair();
  const r = await pq.sessionInvite(A2, B2.pub, CTX); const acc = await pq.sessionAccept(B2, A2.pub, r.invite, CTX);
  const fin = (await pq.sessionComplete(r.pending, acc.accept)).finish.slice(); fin[40] ^= 1;
  assert.throws(() => pq.sessionConfirm(acc.session, fin), /FINISH）无效/);
  assert.equal(acc.session.dead, true);
  const h = await handshake();
  assert.throws(() => pq.sessionConfirm(h.sb, h.finish), /没有等待确认的会话/);
});
await test("中间人换掉 B 的身份：A 的密钥确认失败", async () => {
  const A = await pq.generateKeypair(), B = await pq.generateKeypair(), M = await pq.generateKeypair();
  const { invite, pending } = await pq.sessionInvite(A, B.pub, CTX);
  const { accept } = await pq.sessionAccept(M, A.pub, invite, CTX);
  await assert.rejects(pq.sessionComplete(pending, accept), /密钥确认失败/);
});
await test("上下文绑定：旧 INVITE 被重放进新连接，B 永远等不到有效的 FINISH（v2 会直接显示“会话已建立”）", async () => {
  const A = await pq.generateKeypair(), B = await pq.generateKeypair();
  const old = await pq.sessionInvite(A, B.pub, enc.encode("conn-1"));
  const acc1 = await pq.sessionAccept(B, A.pub, old.invite, enc.encode("conn-1"));
  const { finish } = await pq.sessionComplete(old.pending, acc1.accept);          // 旧连接里真实完成的握手
  const replay = await pq.sessionAccept(B, A.pub, old.invite, enc.encode("conn-2"));   // 中继把旧 INVITE 重放进新连接
  assert.equal(replay.session.confirmed, false);
  assert.throws(() => pq.sessionConfirm(replay.session, finish), /FINISH）无效/, "旧连接的 FINISH 在新上下文里无效");
  const m = await pq.sessionInvite(A, B.pub, enc.encode("ctx-A"));
  const accM = await pq.sessionAccept(B, A.pub, m.invite, enc.encode("ctx-B"));
  await assert.rejects(pq.sessionComplete(m.pending, accM.accept), /密钥确认失败/, "双方上下文不一致 → 握手失败");
});
await test("INVITE 长度 / 魔数不符、一次性 ML-KEM 公钥不合规、缺上下文 → 拒绝", async () => {
  const A = await pq.generateKeypair(), B = await pq.generateKeypair();
  const { invite } = await pq.sessionInvite(A, B.pub, CTX);
  await assert.rejects(pq.sessionAccept(B, A.pub, invite.subarray(0, invite.length - 1), CTX), /长度或魔数/);
  const bad = invite.slice(); bad[9 + 32] = 0xff; bad[9 + 33] = 0x0f;
  await assert.rejects(pq.sessionAccept(B, A.pub, bad, CTX), /模数检查/);
  await assert.rejects(pq.sessionInvite(A, B.pub, new Uint8Array(0)), /上下文/);
});

console.log("棘轮 / 填充");
await test("乱序：跳号消息被缓存，迟到消息仍可解；解密成功后缓存项删除；重复即拒", async () => {
  const { sa, sb } = await handshake();
  const cs = []; for (let i = 0; i < 5; i++) cs.push(await pq.ratchetEncrypt(sa, enc.encode("m" + i)));
  assert.equal(dec.decode(await pq.ratchetDecrypt(sb, cs[4])), "m4");
  assert.equal(sb.skipped.size, 4);
  assert.equal(dec.decode(await pq.ratchetDecrypt(sb, cs[1])), "m1");
  assert.equal(sb.skipped.size, 3);
  await assert.rejects(pq.ratchetDecrypt(sb, cs[1]), /重放/);
});
await test("先验证后提交：伪造的高序号帧认证失败时，接收链与缓存完全不变", async () => {
  const { sa, sb } = await handshake();
  const real = await pq.ratchetEncrypt(sa, enc.encode("real"));
  const forged = real.slice(); forged.set([0, 0, 0, 200], 30);          // n 字段在偏移 30
  const ch = sb.recv.get(0), before = { n: ch.n, ck: hexOf(ch.ck), size: sb.skipped.size };
  await assert.rejects(pq.ratchetDecrypt(sb, forged), /认证失败/);
  assert.equal(ch.n, before.n); assert.equal(hexOf(ch.ck), before.ck); assert.equal(sb.skipped.size, before.size);
  assert.equal(dec.decode(await pq.ratchetDecrypt(sb, real)), "real");
});
await test("跳跃超过 MAX_SKIP 直接拒绝；缓存项对应的真消息认证失败时密钥不被误删；缓存总量封顶", async () => {
  const { sa, sb } = await handshake();
  const c = await pq.ratchetEncrypt(sa, enc.encode("x"));
  const far = c.slice(); far.set([0, 0, 0x10, 0], 30);
  await assert.rejects(pq.ratchetDecrypt(sb, far), /跳跃过大/);
  await pq.ratchetDecrypt(sb, await pq.ratchetEncrypt(sa, enc.encode("m1")));    // c 被缓存
  const t = c.slice(); t[t.length - 1] ^= 1;
  await assert.rejects(pq.ratchetDecrypt(sb, t), /认证失败/);
  assert.equal(dec.decode(await pq.ratchetDecrypt(sb, c)), "x");
  const cs = []; for (let i = 0; i < 1300; i++) cs.push(await pq.ratchetEncrypt(sa, enc.encode("n" + i)));
  await pq.ratchetDecrypt(sb, cs[500]); await pq.ratchetDecrypt(sb, cs[1000]); await pq.ratchetDecrypt(sb, cs[1299]);
  assert.equal(sb.skipped.size, pq.MAX_SKIP_TOTAL);
  await assert.rejects(pq.ratchetDecrypt(sb, cs[0]), /重放/, "最旧的已被淘汰");
});
await test("长度隐藏：短消息落在同一个桶；语音包（497 字节）与邻近大小同桶；非规范填充被拒", async () => {
  const { sa } = await handshake();
  const len = async (n) => (await pq.ratchetEncrypt(sa, new Uint8Array(n))).length;
  assert.equal(await len(1), await len(200)); assert.equal(await len(0), await len(252));
  assert.notEqual(await len(252), await len(253));
  assert.equal(await len(497), await len(493)); assert.equal(await len(497), await len(508));
  assert.equal(pq.padLen(501), 512); assert.equal(pq.padLen(524330), 540672);
  const p = mod.padPlain(enc.encode("abc")); assert.equal(p.length, 256);
  assert.equal(dec.decode(mod.unpadPlain(p)), "abc");
  assert.throws(() => mod.unpadPlain(p.subarray(0, 255)), /填充/);
  const q = p.slice(); q.set([0, 0, 1, 0], 0); assert.throws(() => mod.unpadPlain(q), /填充/);
});
await test("内部锁：并发调用 50 次加密 / 解密，链状态不交错，全部按序可解", async () => {
  const { sa, sb } = await handshake();
  const cs = await Promise.all(Array.from({ length: 50 }, (_, i) => pq.ratchetEncrypt(sa, enc.encode("c" + i))));
  const pts = await Promise.all(cs.map((c) => pq.ratchetDecrypt(sb, c)));
  assert.deepEqual(pts.map((p) => dec.decode(p)), Array.from({ length: 50 }, (_, i) => "c" + i));
});

console.log("分纪元混合重新密钥（事后泄露自愈）");
async function rekey(I, R) {                    // I 发起、R 应答；全部经真实棘轮消息传输
  const offer = await pq.rekeyStart(I); assert.ok(offer);
  const ans = await pq.rekeyOnOffer(R, await xfer(I, R, offer)); assert.ok(ans);
  const conf = await pq.rekeyOnAnswer(I, await xfer(R, I, ans)); assert.ok(conf);
  await xfer(I, R, conf);                       // CONFIRM = 新纪元的第一条消息 → R 提交
}
await test("A 发起：OFFER → ANSWER → CONFIRM；两端进入纪元 1，旧根密钥被清零，新旧密钥不同", async () => {
  const { sa, sb } = await handshake();
  const oldRk = sa.rk, oldHex = hexOf(sa.rk);
  await rekey(sa, sb);
  assert.equal(sa.epoch, 1); assert.equal(sb.epoch, 1);
  assert.ok(oldRk.every((v) => v === 0), "旧根密钥已清零");
  assert.notEqual(hexOf(sa.rk), oldHex); assert.equal(hexOf(sa.rk), hexOf(sb.rk));
  assert.equal(dec.decode(await xfer(sb, sa, enc.encode("e1 B→A"))), "e1 B→A");
  assert.equal(dec.decode(await xfer(sa, sb, enc.encode("e1 A→B"))), "e1 A→B");
});
await test("切换期间在途的旧纪元消息仍可解；两次更新后纪元 0 的密钥全部销毁", async () => {
  const { sa, sb } = await handshake();
  const ans = await pq.rekeyOnOffer(sb, await xfer(sa, sb, await pq.rekeyStart(sa)));
  const ansMsg = await pq.ratchetEncrypt(sb, ans);
  const inflight = await pq.ratchetEncrypt(sb, enc.encode("B 在收到 CONFIRM 之前发的"));
  const conf = await pq.rekeyOnAnswer(sa, await pq.ratchetDecrypt(sa, ansMsg));
  assert.equal(sa.epoch, 1);
  assert.equal(dec.decode(await pq.ratchetDecrypt(sa, inflight)), "B 在收到 CONFIRM 之前发的");
  await xfer(sa, sb, conf);
  await xfer(sb, sa, enc.encode("B 已在纪元 1"));
  await rekey(sb, sa);
  assert.equal(sa.epoch, 2); assert.deepEqual([...sa.recv.keys()].sort(), [1, 2]);
  assert.ok([...sa.skipped.keys()].every((k) => !k.startsWith("0:")));
  await assert.rejects(pq.ratchetDecrypt(sa, inflight.slice()), /纪元|重放/);
});
await test("双方同时发起：A 的 OFFER 胜出，B 放弃自己的并应答", async () => {
  const { sa, sb } = await handshake();
  const oa = await pq.rekeyStart(sa), ob = await pq.rekeyStart(sb);
  const oaAtB = await xfer(sa, sb, oa), obAtA = await xfer(sb, sa, ob);
  assert.equal(await pq.rekeyOnOffer(sa, obAtA), null, "A 忽略 B 的 OFFER");
  const ans = await pq.rekeyOnOffer(sb, oaAtB); assert.ok(ans, "B 应答 A 的 OFFER");
  await xfer(sa, sb, await pq.rekeyOnAnswer(sa, await xfer(sb, sa, ans)));
  assert.equal(sa.epoch, 1); assert.equal(sb.epoch, 1);
  assert.equal(dec.decode(await xfer(sb, sa, enc.encode("ok"))), "ok");
});
await test("ANSWER 丢失：发起方超时放弃并重来；迟到的旧 ANSWER 被忽略；最终一致", async () => {
  const { sa, sb } = await handshake();
  const a1 = await pq.rekeyOnOffer(sb, await xfer(sa, sb, await pq.rekeyStart(sa)));
  const a1Msg = await pq.ratchetEncrypt(sb, a1);                  // 这条 ANSWER 在路上“丢了”
  clock.t += 31000;
  assert.equal(pq.rekeyExpire(sa, 30000), true);
  const a2 = await pq.rekeyOnOffer(sb, await xfer(sa, sb, await pq.rekeyStart(sa)));
  const conf = await pq.rekeyOnAnswer(sa, await xfer(sb, sa, a2));
  assert.equal(await pq.rekeyOnAnswer(sa, await pq.ratchetDecrypt(sa, a1Msg)), null, "迟到的旧 ANSWER 被忽略");
  await xfer(sa, sb, conf);
  assert.equal(sa.epoch, 1); assert.equal(sb.epoch, 1);
  assert.equal(dec.decode(await xfer(sb, sa, enc.encode("after retry"))), "after retry");
});
await test("CONFIRM 丢失：B 暂存不提交、仍用旧纪元发送；A 不会再发起；A 的下一条新纪元消息让 B 提交", async () => {
  const { sa, sb } = await handshake();
  const a = await pq.rekeyOnOffer(sb, await xfer(sa, sb, await pq.rekeyStart(sa)));
  await pq.rekeyOnAnswer(sa, await xfer(sb, sa, a));              // CONFIRM 丢失
  assert.equal(sb.epoch, 0); assert.equal(sb.rekey.role, "answer");
  assert.equal(dec.decode(await xfer(sb, sa, enc.encode("B 仍在纪元 0"))), "B 仍在纪元 0");
  assert.equal(await pq.rekeyStart(sa), null, "对方尚未切到当前纪元：不发起下一次");
  assert.ok(pq.rekeyNudge(sa), "可以催对方提交");
  await xfer(sa, sb, enc.encode("A 的纪元 1 消息"));
  assert.equal(sb.epoch, 1);
  await xfer(sb, sa, enc.encode("B 已提交"));
  assert.equal(pq.rekeyNudge(sa), null);
});
await test("非法 OFFER（纪元不符 / 公钥不合规 / 长度不符）一律拒绝，状态不变", async () => {
  const { sa, sb } = await handshake();
  const o = await pq.rekeyStart(sa);
  const wrongE = o.slice(); wrongE.set([0, 0, 0, 5], 8);
  await assert.rejects(pq.rekeyOnOffer(sb, wrongE), /纪元不符/);
  const badPk = o.slice(); badPk[44] = 0xff; badPk[45] = 0x0f;
  await assert.rejects(pq.rekeyOnOffer(sb, badPk), /模数检查/);
  await assert.rejects(pq.rekeyOnOffer(sb, o.subarray(1)), /长度不符/);
  assert.equal(sb.rekey, null); assert.equal(sb.epoch, 0);
});
await test("事后泄露自愈：窃取了 B 全部会话状态的被动攻击者能读旧纪元，但读不了重新密钥之后的消息", async () => {
  const { sa, sb } = await handshake();
  const cp = (u) => u.slice();
  const stolen = { ...sb, rk: cp(sb.rk), sid: cp(sb.sid), send: { ...sb.send, ck: cp(sb.send.ck) },
    recv: new Map([...sb.recv].map(([e, c]) => [e, { ...c, ck: cp(c.ck) }])), skipped: new Map(), rekey: null, txQ: Promise.resolve(), rxQ: Promise.resolve() };
  const m0 = await pq.ratchetEncrypt(sa, enc.encode("纪元 0 的秘密"));
  assert.equal(dec.decode(await pq.ratchetDecrypt(stolen, m0)), "纪元 0 的秘密", "攻击者确实拿到了完整状态");
  await pq.ratchetDecrypt(sb, m0);
  const offerMsg = await pq.ratchetEncrypt(sa, await pq.rekeyStart(sa));
  await pq.rekeyOnOffer(stolen, await pq.ratchetDecrypt(stolen, offerMsg));   // 攻击者读到 OFFER，并尽其所能模仿 B 的计算
  const ans = await pq.rekeyOnOffer(sb, await pq.ratchetDecrypt(sb, offerMsg));
  const conf = await pq.rekeyOnAnswer(sa, await xfer(sb, sa, ans));
  await pq.ratchetDecrypt(sb, await pq.ratchetEncrypt(sa, conf));
  const m1 = await pq.ratchetEncrypt(sa, enc.encode("纪元 1 的秘密"));
  assert.equal(dec.decode(await pq.ratchetDecrypt(sb, m1)), "纪元 1 的秘密");
  await assert.rejects(pq.ratchetDecrypt(stolen, m1), /认证失败|纪元/, "攻击者跟不上新纪元");
});
await test("sessionWipe 清零根密钥、全部链密钥与缓存；之后拒绝收发", async () => {
  const { sa } = await handshake();
  const rk = sa.rk, ck = sa.send.ck, rc = sa.recv.get(0).ck;
  pq.sessionWipe(sa);
  assert.ok([rk, ck, rc].every((a) => a.every((b) => b === 0)));
  assert.equal(sa.recv.size, 0); assert.equal(sa.dead, true);
  await assert.rejects(pq.ratchetEncrypt(sa, enc.encode("x")), /会话已结束/);
});

console.log("房间层（v3）");
await test("房间标识与信封密钥都来自一次 Argon2id：不再是口令的快速哈希；每验证一个猜测都要调用一次 KDF", async () => {
  const kdf = makeFakeArgon();
  const r1 = await mod.deriveRoomKeys("K7M2QPRS4XAB", kdf), r2 = await mod.deriveRoomKeys("K7M2QPRS4XAB", kdf), r3 = await mod.deriveRoomKeys("K7M2QPRS4XAC", kdf);
  assert.equal(kdf.calls, 3);
  assert.equal(hexOf(r1.idBytes), hexOf(r2.idBytes)); assert.notEqual(hexOf(r1.idBytes), hexOf(r3.idBytes));
  assert.equal(r1.idBytes.length, 16);
  assert.notEqual(hexOf(r1.idBytes), hexOf(sha(enc.encode("pqsession-room-id-v2"), enc.encode("K7M2QPRS4XAB"))).slice(0, 32));
});
await test("口令规范化与随机口令（12 位、无歧义字符、均匀、4 位一组显示）", () => {
  assert.equal(mod.normalizeRoomCode(" k7m2-qprs 4xab "), "K7M2QPRS4XAB");
  assert.equal(mod.normalizeRoomCode("ｋ７ｍ２"), "K7M2");
  const counts = {};
  for (let i = 0; i < 3000; i++) { const r = mod.randomRoom(); assert.match(r, /^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{12}$/); for (const ch of r) counts[ch] = (counts[ch] || 0) + 1; }
  const mean = 36000 / 31; assert.ok(Object.values(counts).every((v) => Math.abs(v - mean) < mean * 0.2));
  assert.equal(mod.groupRoom("K7M2QPRS4XAB"), "K7M2-QPRS-4XAB");
});
async function roomPair(code = "SAME") {
  const k = await mod.deriveRoomKeys(code, makeFakeArgon());
  const A = mod.makeRoomCtx(k), B = mod.makeRoomCtx(k);
  A.peerTag = B.tag; A.peerTagHex = B.tagHex; B.peerTag = A.tag; B.peerTagHex = A.tagHex;
  return { A, B };
}
await test("信封：写明收件连接（toMe）；反射被忽略；重放被拒；窗口内乱序照常；错口令 / v2 帧 / 篡改被拒", async () => {
  const { A, B } = await roomPair(), X = (await roomPair("OTHER")).A;
  mod.setRoom(A);
  const e1 = await mod.sealKind(mod.KIND_INVITE, enc.encode("inv"));
  assert.deepEqual(Object.keys(e1), ["v", "n", "c"]); assert.equal(e1.v, 3);
  assert.equal(await mod.unsealKind(e1), null, "自己的帧被反射回来");
  mod.setRoom(B);
  const f1 = await mod.unsealKind(e1);
  assert.equal(f1.kind, mod.KIND_INVITE); assert.equal(dec.decode(f1.payload), "inv");
  assert.equal(f1.toMe, true); assert.equal(f1.tagHex, A.tagHex);
  await assert.rejects(mod.unsealKind(e1), /重放/);
  mod.setRoom(A); const e3 = await mod.sealKind(4, new Uint8Array([3])), e4 = await mod.sealKind(4, new Uint8Array([4]));
  mod.setRoom(B); assert.deepEqual(Array.from((await mod.unsealKind(e4)).payload), [4]); assert.deepEqual(Array.from((await mod.unsealKind(e3)).payload), [3]);
  mod.setRoom(X); await assert.rejects(mod.unsealKind(e1), /认证失败/);
  mod.setRoom(B); await assert.rejects(mod.unsealKind({ v: 2, n: e1.n, c: e1.c }), /v3 与 v2 不互通/);
  const t = { ...e3, c: e3.c.slice(0, -4) + (e3.c.endsWith("AAAA") ? "BBBB" : "AAAA") };
  await assert.rejects(mod.unsealKind(t), /认证失败/);
});
await test("跨连接重放：旧连接录下的帧在新连接里不再“发给我”，发件连接也不是当前对端（页面据此丢弃）", async () => {
  const k = await mod.deriveRoomKeys("SAME", makeFakeArgon());
  const A1 = mod.makeRoomCtx(k), B1 = mod.makeRoomCtx(k);
  A1.peerTag = B1.tag; A1.peerTagHex = B1.tagHex;
  mod.setRoom(A1); const oldBye = await mod.sealKind(mod.KIND_BYE, new Uint8Array(0));
  const A2 = mod.makeRoomCtx(k), B2 = mod.makeRoomCtx(k);          // 双方重连：新标签
  B2.peerTag = A2.tag; B2.peerTagHex = A2.tagHex;
  mod.setRoom(B2);
  const f = await mod.unsealKind(oldBye);                           // 口令没变，信封本身仍能解开……
  assert.equal(f.toMe, false, "……但它写的收件人是旧连接");
  assert.notEqual(f.tagHex, B2.peerTagHex, "……发件连接也不是当前对端");
});
await test("抗重放窗口：同一计数器只接受一次；比窗口还旧的拒绝；窗口内乱序接受", () => {
  const w = { max: -1, bits: 0n };
  assert.equal(mod.replayWindowAccept(w, 5), true); assert.equal(mod.replayWindowAccept(w, 5), false);
  assert.equal(mod.replayWindowAccept(w, 3), true); assert.equal(mod.replayWindowAccept(w, 200), true);
  assert.equal(mod.replayWindowAccept(w, 100), false); assert.equal(mod.replayWindowAccept(w, 199), true);
});

console.log("信任存储（v3）");
const fpA = (await pq.generateKeypair()).fingerprint, fpB = (await pq.generateKeypair()).fingerprint, fpC = (await pq.generateKeypair()).fingerprint;
const ROOM1 = "0123456789abcdef0123456789abcdef", ROOM2 = "ffffffffffffffffffffffffffffffff";
function fakeBackend(initial) {
  const st = { text: initial === undefined ? null : initial, writes: 0 };
  return { st, read: async () => st.text, write: async (t) => { st.text = t; st.writes++; }, remove: () => { st.text = null; } };
}
const memStorage = (m = new Map()) => ({ m, getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, v), removeItem: (k) => m.delete(k) });
await test("持久化：remember 后新建实例仍能 find；touch 累计；名字规范化；房间记录随存", async () => {
  let t = 1000; const be = fakeBackend();
  const a = mod.makeTrustStore(be, () => t);
  assert.equal(await a.load(), "empty"); assert.equal(a.persistent, true); assert.equal(a.readOnly, false);
  a.remember(fpA, "  小王 "); t = 2000; a.touch(fpA); a.setRoomPeer(ROOM1, fpA); await a.save();
  const b = mod.makeTrustStore(be, () => t);
  assert.equal(await b.load(), "ok");
  const e = b.find(fpA);
  assert.equal(e.name, "小王"); assert.equal(e.count, 2); assert.equal(e.first, 1000); assert.equal(e.last, 2000);
  assert.deepEqual(b.roomPeer(ROOM1), { fp: fpA, at: 2000 }); assert.equal(b.roomPeer(ROOM2), null);
  assert.equal(b.remember("not a fingerprint", "x"), null); assert.equal(b.setRoomPeer("not-a-room", fpA), false);
});
await test("只读保护：解不开 / 坏 JSON → corrupted + 只读，绝不覆盖旧数据；clear() 才解除并删除", async () => {
  const be = fakeBackend("{not json");
  const t = mod.makeTrustStore(be);
  assert.equal(await t.load(), "corrupted"); assert.equal(t.readOnly, true);
  t.remember(fpA, "a"); t.setRoomPeer(ROOM1, fpA); await t.save();
  assert.equal(be.st.writes, 0); assert.equal(be.st.text, "{not json", "旧数据原样保留");
  assert.ok(t.find(fpA), "本页内仍可用（仅内存）");
  await t.clear();
  assert.equal(t.readOnly, false); assert.equal(be.st.text, null);
  t.remember(fpB, "b"); await t.save(); assert.ok(be.st.text.includes(fpB));
  const unreadable = mod.makeTrustStore({ read: async () => false, write: async () => { throw new Error("不应写入"); } });
  assert.equal(await unreadable.load(), "corrupted"); assert.equal(unreadable.readOnly, true);
  const mem = mod.makeTrustStore(null); assert.equal(await mem.load(), "memory"); assert.equal(mem.persistent, false);
  const denied = mod.makeTrustStore({ read: async () => { throw new Error("denied"); }, write: async () => {} });
  assert.equal(await denied.load(), "denied"); assert.equal(denied.persistent, false);
});
await test("sanitize、重名换钥（replaceKey）、删除连带房间记录、导出 / 导入合并", async () => {
  const junk = [{ fp: fpA, name: 5 }, { fp: "zzz" }, null, { fp: fpA, name: "dup" }, { fp: fpB, name: "b", prev: ["nope", fpC] }];
  const t = mod.makeTrustStore(fakeBackend(JSON.stringify({ v: 1, entries: junk, rooms: { [ROOM1]: { fp: fpA, at: 9 }, bad: { fp: fpA } } })), () => 5);
  assert.equal(await t.load(), "ok"); assert.equal(t.size, 2); assert.deepEqual(t.find(fpB).prev, [fpC]);
  let now = 10; const s = mod.makeTrustStore(fakeBackend(), () => now); await s.load();
  s.remember(fpA, "小王"); s.remember(fpB, ""); s.setRoomPeer(ROOM1, fpB);
  now = 20; const e = s.replaceKey("小王", fpB);
  assert.equal(e.fp, fpB); assert.deepEqual(e.prev, [fpA]); assert.equal(s.size, 1);
  assert.equal(s.remove(fpB), true); assert.equal(s.roomPeer(ROOM1), null);
  const x = mod.makeTrustStore(fakeBackend(), () => 1); await x.load(); x.remember(fpA, "a");
  const y = mod.makeTrustStore(fakeBackend(), () => 2); await y.load(); y.remember(fpA, "");
  assert.deepEqual(y.importText(JSON.stringify(x.exportObj())), { added: 0, merged: 1 });
  assert.equal(y.find(fpA).name, "a");
  assert.throws(() => y.importText(JSON.stringify({ app: "other", v: 1 })), /不是 pqsession/);
});
await test("v3 存储密钥由 X25519 与 ML-KEM 两把私钥共同派生：只有 X25519 私钥解不开；存储里只有密文", async () => {
  const id = await pq.generateKeypair(); const storage = memStorage();
  const keys = await mod.trustKeysFor(id);
  const t = mod.makeTrustStore(mod.makeEncryptedBackend(keys.ns, keys.key, storage)); await t.load();
  t.remember(fpA, "小王"); await t.save();
  const stored = storage.getItem(mod.TRUST_KEY + "." + keys.ns);
  assert.ok(stored && !stored.includes("小王") && !stored.includes(fpA.slice(0, 9)));
  const other = { ...id, mSk: id.mSk.slice() }; other.mSk[0] ^= 1;                 // 只改 ML-KEM 私钥
  const k2 = await mod.trustKeysFor(other);
  assert.equal(k2.ns, keys.ns);
  assert.equal(await mod.makeEncryptedBackend(k2.ns, k2.key, storage).read(), false, "只有 X25519 私钥不够");
  const t2 = mod.makeTrustStore(mod.makeEncryptedBackend(keys.ns, keys.key, storage)); assert.equal(await t2.load(), "ok");
  assert.equal(t2.find(fpA).name, "小王");
  assert.equal(id.xPriv.some((v) => v !== 0) && id.mSk.some((v) => v !== 0), true, "派生过程不得清零身份私钥本身");
});
await test("v2 → v3 迁移：旧列表以新密钥重写（丢弃旧房间记录）并删除旧数据；解不开的旧数据原样保留", async () => {
  const id = await pq.generateKeypair(); const storage = memStorage();
  const keys = await mod.trustKeysFor(id);
  const v1 = mod.makeEncryptedBackend(keys.ns, keys.keyV1, storage, { prefix: mod.TRUST_KEY_V1, aad: mod.TRUST_AAD_V1 });
  await v1.write(JSON.stringify({ v: 1, entries: [{ fp: fpA, name: "旧联系人", first: 1, last: 2, count: 3, prev: [] }], rooms: { [ROOM1]: { fp: fpA, at: 5 } } }));
  assert.deepEqual(await mod.migrateTrustV1(keys, storage), { state: "migrated", migrated: 1 });
  assert.equal(storage.getItem(mod.TRUST_KEY_V1 + "." + keys.ns), null, "旧数据已删除");
  const t = mod.makeTrustStore(mod.makeEncryptedBackend(keys.ns, keys.key, storage)); assert.equal(await t.load(), "ok");
  assert.equal(t.find(fpA).name, "旧联系人"); assert.equal(t.roomPeer(ROOM1), null, "旧房间记录不迁移");
  assert.equal((await mod.migrateTrustV1(keys, storage)).state, "has-v2");
  const st2 = memStorage(new Map([[mod.TRUST_KEY_V1 + "." + keys.ns, "garbage"]]));
  assert.equal((await mod.migrateTrustV1(keys, st2)).state, "v1-unreadable");
  assert.equal(st2.getItem(mod.TRUST_KEY_V1 + "." + keys.ns), "garbage");
});

console.log("语音：麦克风权限弹窗（行为 + 静态检查）");
function stubAudioEnv({ resumeSettles }) {
  const prevWindow = globalThis.window, prevNav = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  const env = { gumCalls: 0, ctxCreated: 0, stopped: 0, resolveGum: null };
  env.stream = { getTracks: () => [{ stop() { env.stopped++; } }] };
  globalThis.window = { AudioContext: function () { env.ctxCreated++; this.state = "running"; this.resume = () => (resumeSettles ? Promise.resolve() : new Promise(() => {})); } };
  Object.defineProperty(globalThis, "navigator", { value: { mediaDevices: { getUserMedia: () => { env.gumCalls++; return new Promise((r) => { env.resolveGum = r; }); } } }, configurable: true, writable: true });
  env.restore = () => { globalThis.window = prevWindow; if (prevNav) Object.defineProperty(globalThis, "navigator", prevNav); else delete globalThis.navigator; };
  return env;
}
function bodyOf(name) {
  const i = src.indexOf(`function ${name}(`); assert.ok(i >= 0, "找不到函数 " + name);
  const start = src.indexOf("{", i); let depth = 0, j = start;
  for (; j < src.length; j++) { if (src[j] === "{") depth++; else if (src[j] === "}") { depth--; if (depth === 0) break; } }
  return src.slice(start + 1, j);
}
const stripComments = (t) => t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/[^\n]*/g, "$1");
const codeOf = (name) => stripComments(bodyOf(name));
await test("vcOpenMic 内不含 await，同时发起 AudioContext 与 getUserMedia；取消后授权必停轨道", () => {
  const b = codeOf("vcOpenMic");
  assert.ok(/getUserMedia/.test(b) && /new \(window\.AudioContext/.test(b) && !/\bawait\b/.test(b) && /c\.dead[\s\S]*stop\(\)/.test(b));
});
await test("vcStart / vcAccept 在第一个 await 之前调用 vcOpenMic；resume() 配超时；worklet 从同源文件装载（不再经 blob:）", () => {
  for (const fn of ["vcStart", "vcAccept"]) { const b = codeOf(fn); assert.ok(b.indexOf("vcOpenMic(") >= 0 && b.indexOf("vcOpenMic(") < b.search(/\bawait\b/), fn); }
  assert.ok(/Promise\.race/.test(codeOf("vcResume")));
  const up = codeOf("vcAudioUp");
  assert.ok(/await c\.micP/.test(up) && !/await\s+ctx\.resume\s*\(/.test(up) && up.indexOf("await c.micP") < up.indexOf("audioWorklet"));
  assert.ok(/addModule\(new URL\(VC_WORKLET_URL/.test(up) && !/createObjectURL|Blob\(/.test(up));
});
await test("行为：getUserMedia 在同步块内发起；resume() 永不 settle 也不卡住；取消后才授权的流被停掉", async () => {
  let env = stubAudioEnv({ resumeSettles: true });
  const c = {}; mod.setCall(c); mod.vcOpenMic(c);
  assert.equal(env.gumCalls, 1); env.resolveGum(env.stream); assert.equal(await c.micP, env.stream); await c.resumeP; assert.equal(env.stopped, 0);
  env.restore();
  env = stubAudioEnv({ resumeSettles: false });
  const t0 = Date.now(); await mod.vcResume(new globalThis.window.AudioContext(), 30); assert.ok(Date.now() - t0 < 2000);
  env.restore();
  env = stubAudioEnv({ resumeSettles: true });
  const d = {}; mod.setCall(d); mod.vcOpenMic(d); d.dead = true; env.resolveGum(env.stream);
  await d.micP; await new Promise((r) => setTimeout(r, 0)); assert.equal(env.stopped, 1);
  env.restore();
});

console.log("页面静态检查（v3 不变量）");
await test("没有 innerHTML 类注入接口 / 第三方 CDN 加载 / 旧式自动下载；收到的文件以 octet-stream 保存、只在点击时落盘", () => {
  const code = stripComments(src);
  assert.ok(!/\.innerHTML\b|outerHTML|insertAdjacentHTML|document\.write/.test(code));
  assert.ok(!/https:\/\/esm\.sh/.test(code) && !/downloadBlobParts/.test(code));
  const ff = codeOf("onFileFrame");
  assert.ok(/type: "application\/octet-stream"/.test(ff) && !/saveBlob\(/.test(ff) && /offerSave\(/.test(ff));
  assert.ok(/saveBlob\(name, blob\)/.test(codeOf("offerSave")));
  assert.ok(/FR_TEXT/.test(codeOf("sendText")), "文本带类型前缀");
  const rm = codeOf("recvMsgNow");
  assert.ok(/pt\[0\]===FR_TEXT/.test(rm) && /pt\[0\]!==FR_CTRL/.test(rm));
});
await test("非 HELLO 信令必须来自当前对端连接且写明发给本次连接；握手上下文绑定了房间与双方连接标签", () => {
  const b = codeOf("onSigNow");
  assert.ok(/f\.tagHex!==roomCtx\.peerTagHex/.test(b) && /!f\.toMe/.test(b));
  assert.ok(b.indexOf("KIND_HELLO") < b.indexOf("peerTagHex"), "HELLO 之外的帧才做标签检查");
  assert.ok(/roomCtx\.idBytes, ti, tr/.test(codeOf("hsCtx")));
});

console.log(`\n全部通过：${passed} 项。`);
