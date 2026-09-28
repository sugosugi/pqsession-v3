// 测试辅助：从 pqsession-net.html 提取“页面里真正运行的代码”供 Node 测试导入（不复制、不改写实现）：
//   • 第 1、2 段整段（加密核心 + 会话协议层）；
//   • 第 3 段中 /* @testable:begin */ … /* @testable:end */ 之间的纯逻辑（房间信封、信任存储等）；
//   • 语音的几个函数（vcSleep / vcResume / vcOpenMic），用于麦克风时序的行为测试。
// 并提供尺寸忠实的假 KEM（ML-KEM-1024 的 pk/sk/ct/ss 长度、FIPS 203 合规的 ek、dk 内嵌 ek）与假 Argon2id。
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";

export const ROOT = path.dirname(fileURLToPath(import.meta.url));
export const html = fs.readFileSync(path.join(ROOT, "pqsession-net.html"), "utf8");
export const src = html.match(/<script type="module">([\s\S]*?)<\/script>/)[1];

const seg3 = src.indexOf("* 第 3 段 / 3");
assert.ok(seg3 > 0, "找不到第 3 段标记");
const core = src.slice(0, src.lastIndexOf("/* ====", seg3));
const tb = src.indexOf("/* @testable:begin"), te = src.indexOf("/* @testable:end */");
assert.ok(tb > seg3 && te > tb, "找不到 @testable 标记");
const testable = src.slice(tb, te);

function grab(re, name) { const m = src.match(re); assert.ok(m, "提取失败 " + name); return m[1]; }
const grabFn = (name) => grab(new RegExp(`\\n(function ${name}\\([^)]*\\)\\{[\\s\\S]*?\\n\\})\\n`), name);
const grabLine = (name) => grab(new RegExp(`\\n(function ${name}\\([^)]*\\)\\{.*\\})\\n`), name);

const glue = `
const subtle = globalThis.crypto.subtle;
function randomBytes(n){ const o=new Uint8Array(n); globalThis.crypto.getRandomValues(o); return o; }
const dec = new TextDecoder();
const hexId = (b)=>Array.from(b).map(x=>x.toString(16).padStart(2,"0")).join("");
let pq, toB64, fromB64;
export function bindPq(p){ pq=p; toB64=(b)=>p.b64encode(b); fromB64=(s)=>p.b64decode(s); }
${testable}
let call = null;
${grabLine("vcSleep")}
${grabFn("vcResume")}
${grabFn("vcOpenMic")}
function setCall(c){ call = c; }
function setRoom(r){ roomCtx = r; } function getRoom(){ return roomCtx; }
export { createPQCrypto, createPQSession, padPlain, unpadPlain, padLen, mlkemPkValid, bytesEqual,
  normalizeRoomCode, randomRoom, groupRoom, deriveRoomKeys, makeRoomCtx, sealKind, unsealKind, replayWindowAccept, setRoom, getRoom,
  KIND_HELLO, KIND_INVITE, KIND_ACCEPT, KIND_MSG, KIND_BYE, KIND_FINISH, TAG_LEN,
  makeTrustStore, trustSealText, trustOpenText, makeEncryptedBackend, trustKeysFor, migrateTrustV1, hkdfAesKey,
  TRUST_KEY, TRUST_KEY_V1, TRUST_AAD, TRUST_AAD_V1, vcResume, vcOpenMic, setCall };
`;

export async function loadPage() {
  const tmp = path.join(ROOT, `.test-extract-${process.pid}-${Date.now()}.mjs`);
  fs.writeFileSync(tmp, core + "\n" + glue);
  try { return await import(pathToFileURL(tmp).href); } finally { fs.unlinkSync(tmp); }
}

// ---- 尺寸忠实的假 KEM（只用于测试协议逻辑；不是密码学安全的 KEM） ----
export const sha = (...bs) => new Uint8Array(crypto.createHash("sha256").update(Buffer.concat(bs.map((b) => Buffer.from(b)))).digest());
export const fakeKem = {
  keygen() {
    const seed = crypto.randomBytes(32);
    const pk = new Uint8Array(1568); pk.set(sha(seed), 1536);                    // t̂ 全零（通过 FIPS 203 模数检查）‖ ρ
    const sk = new Uint8Array(3168); sk.set(seed, 0); sk.set(pk, 1536); sk.set(sha(pk), 3104); sk.set(crypto.randomBytes(32), 3136);
    return { publicKey: pk, secretKey: sk };                                     // dk = dk_PKE ‖ ek ‖ H(ek) ‖ z
  },
  encapsulate(pk) { assert.equal(pk.length, 1568); const r = crypto.randomBytes(32); const ct = new Uint8Array(1568); ct.set(r, 0); return { cipherText: ct, sharedSecret: sha(pk.subarray(1536), r) }; },
  decapsulate(ct, sk) { assert.equal(ct.length, 1568); assert.equal(sk.length, 3168); return sha(sha(sk.subarray(0, 32)), ct.subarray(0, 32)); },
};
// 测试用：PBKDF2 代替 Argon2id（只验证派生结构），并统计调用次数
export function makeFakeArgon() {
  const f = async ({ password, salt, hashLen }) => {
    f.calls++;
    const k = await globalThis.crypto.subtle.importKey("raw", password, "PBKDF2", false, ["deriveBits"]);
    return new Uint8Array(await globalThis.crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 1000 }, k, hashLen * 8));
  };
  f.calls = 0;
  return f;
}
export function makeClock(t0 = 1_000_000) { const c = { t: t0, now: () => c.t }; return c; }
