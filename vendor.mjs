#!/usr/bin/env node
// 把运行时依赖的两个算法库固定到本地 ./vendor（之后由 server.js 同源提供；v3 页面没有任何第三方 CDN 退路）：
//   vendor/ml-kem.mjs     ← @noble/post-quantum@0.5.4 的 ml-kem 子模块（单文件 bundle）
//   vendor/hash-wasm.mjs  ← hash-wasm@4.12.0（Argon2id；wasm 以 base64 内嵌，故 CSP 需要 'wasm-unsafe-eval'）
//
// 用法：  npm run vendor                   联网执行一次：下载 → 形状检查 → 功能自检 → 写入 vendor/ 与 manifest.json
//         npm run vendor -- --check        只核对 vendor/ 与 manifest.json（以及 vendor.lock.json，若存在）
//         npm run vendor -- --write-lock   把当前 manifest 的哈希写入 vendor.lock.json（请先在两台不同网络的机器上
//                                          各跑一次 npm run vendor，比对打印出的 SHA-256 一致后再写锁并提交到版本库）
//
// v3 新增的防线（下载来的是密码学实现本身，必须当作不可信输入对待）：
//   • 功能自检：在写入任何文件之前，先在 Node 里真正执行下载到的代码 ——
//       ML-KEM-1024：长度符合 FIPS 203；封装 / 解封一致；篡改密文走隐式拒绝（不同共享秘密、不抛错）；
//                    私钥内嵌公钥（dk = dk_PKE ‖ ek ‖ H(ek) ‖ z，页面载入身份文件时依赖这一布局核验）；
//       Argon2id：   对照 Argon2 参考实现的已知答案（t=2, m=64 MiB, p=1, "password"/"somesalt"）。
//     任何一项不符都拒绝写入（被替换成“能跑但算错”的实现，正是固定依赖要防的东西）。
//   • vendor.lock.json：若存在，下载结果的 SHA-256 必须与之一致，否则拒绝写入。
// 如果你更信任自己的构建链，也可以用 esbuild 从 npm 包（受 package-lock 完整性校验）自行打包，放到 vendor/ 后运行 --check：
//   npm i -D esbuild && npm i @noble/post-quantum@0.5.4 hash-wasm@4.12.0
//   npx esbuild node_modules/@noble/post-quantum/ml-kem.js --bundle --format=esm --target=es2022 --outfile=vendor/ml-kem.mjs
//   npx esbuild node_modules/hash-wasm/dist/index.esm.js   --bundle --format=esm --target=es2022 --outfile=vendor/hash-wasm.mjs
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import os from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const VENDOR = path.join(ROOT, "vendor");
const MANIFEST = path.join(VENDOR, "manifest.json");
const LOCK = path.join(ROOT, "vendor.lock.json");
const ORIGIN = "https://esm.sh";
const FILES = [
  { name: "ml-kem.mjs",    url: `${ORIGIN}/@noble/post-quantum@0.5.4/ml-kem?bundle&target=es2022`, mustExport: /ml_kem1024/, selftest: selftestMlkem },
  { name: "hash-wasm.mjs", url: `${ORIGIN}/hash-wasm@4.12.0?bundle&target=es2022`,                 mustExport: /argon2id/,   selftest: selftestArgon },
];
const sha256 = (b) => crypto.createHash("sha256").update(b).digest("hex");
const eq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));

async function fetchText(u) {
  const r = await fetch(u, { redirect: "follow", headers: { "user-agent": "pqsession-vendor/3.0" } });
  if (!r.ok) throw new Error(`HTTP ${r.status} ${u}`);
  return { text: await r.text(), finalUrl: r.url || u };
}
// 跟随 esm.sh 的转发壳：`export * from "/pkg@ver/es2022/x.mjs"` / `export { default } from ...`
async function resolveBundle(url) {
  let cur = url, hops = 0;
  while (hops++ < 5) {
    const last = await fetchText(cur);
    const m = last.text.match(/^\s*(?:export\s+\*\s+from|export\s*\{[^}]*\}\s*from|import\s+[^"']*from)\s*["'](\/[^"']+)["']/m);
    if (!(last.text.length < 4096 && m)) return { code: last.text, from: last.finalUrl };
    const next = new URL(m[1], ORIGIN);
    if (next.origin !== ORIGIN) throw new Error("转发到了 esm.sh 以外的源：" + next.href);
    cur = next.href;
  }
  throw new Error("转发层级过深：" + url);
}
function sanityCheck(name, code, mustExport) {
  if (code.length < 1000) throw new Error(`${name}: 内容太短，不像模块`);
  if (/^\s*</.test(code)) throw new Error(`${name}: 返回的是 HTML（错误页？）`);
  if (!mustExport.test(code)) throw new Error(`${name}: 未见预期的导出 ${mustExport}`);
  const ext = code.match(/(?:from|import)\s*\(?\s*["'](https?:\/\/[^"']+|\/[^"']+)["']/g);
  if (ext) throw new Error(`${name}: bundle 仍引用外部模块，不是自包含的：${ext.slice(0, 3).join(" ")}`);
}
async function importFromText(code) {
  const tmp = path.join(os.tmpdir(), `pq-vendor-selftest-${process.pid}-${crypto.randomBytes(4).toString("hex")}.mjs`);
  fs.writeFileSync(tmp, code);
  try { return await import(pathToFileURL(tmp).href); } finally { fs.unlinkSync(tmp); }
}
async function selftestMlkem(m) {
  const k = m.ml_kem1024;
  if (!k || typeof k.keygen !== "function") throw new Error("缺少 ml_kem1024.keygen");
  const { publicKey: pk, secretKey: sk } = k.keygen();
  if (pk.length !== 1568 || sk.length !== 3168) throw new Error(`密钥长度不符 FIPS 203（pk ${pk.length} / sk ${sk.length}）`);
  if (!eq(sk.subarray(1536, 3104), pk)) throw new Error("私钥未按 FIPS 203 布局内嵌公钥（页面的身份一致性核验依赖此布局）");
  const { cipherText: ct, sharedSecret: ss } = k.encapsulate(pk);
  if (ct.length !== 1568 || ss.length !== 32) throw new Error("密文 / 共享秘密长度不符");
  if (!eq(k.decapsulate(ct, sk), ss)) throw new Error("封装与解封得到的共享秘密不一致");
  const bad = ct.slice(); bad[0] ^= 1;
  if (eq(k.decapsulate(bad, sk), ss)) throw new Error("篡改密文后仍得到同一共享秘密（隐式拒绝失效）");
  const other = k.keygen();
  if (eq(k.decapsulate(ct, other.secretKey), ss)) throw new Error("错误的私钥解出了同一共享秘密");
  const nonCanon = pk.slice(); nonCanon[0] = 0xff; nonCanon[1] |= 0x0f;       // 第一个系数 ≥ q：FIPS 203 §7.2 要求拒绝
  let rejected = false; try { k.encapsulate(nonCanon); } catch { rejected = true; }
  return rejected ? "长度 / 往返 / 隐式拒绝 / 私钥布局 / 模数检查 全部通过"
                  : "长度 / 往返 / 隐式拒绝 / 私钥布局通过（提示：该版本 encapsulate 未做 FIPS 203 模数检查，页面自身会先检查）";
}
async function selftestArgon(m) {
  const out = await m.argon2id({ password: "password", salt: "somesalt", iterations: 2, parallelism: 1, memorySize: 65536, hashLength: 32, outputType: "hex" });
  const want = "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7";   // Argon2 参考实现 test.c 的已知答案
  if (out !== want) throw new Error(`Argon2id 已知答案不符：得到 ${out}`);
  return "Argon2id 已知答案（RFC 9106 参考实现向量）一致";
}
function readJson(p) { try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return null; } }

async function main() {
  const args = new Set(process.argv.slice(2));
  const lock = readJson(LOCK);
  if (args.has("--write-lock")) {
    const man = readJson(MANIFEST); if (!man) { console.error("没有 vendor/manifest.json，请先 npm run vendor"); process.exit(1); }
    fs.writeFileSync(LOCK, JSON.stringify({ note: "由 npm run vendor -- --write-lock 生成；请在两台不同网络的机器上核对后再提交", files: Object.fromEntries(Object.entries(man.files).map(([k, v]) => [k, { sha256: v.sha256 }])) }, null, 2) + "\n");
    console.log("已写入 vendor.lock.json。请把它与 vendor/ 一起提交到版本库。"); return;
  }
  if (args.has("--check")) {
    const man = readJson(MANIFEST); if (!man) { console.error("没有 vendor/manifest.json，请先 npm run vendor"); process.exit(1); }
    let bad = 0;
    for (const f of FILES) {
      const p = path.join(VENDOR, f.name);
      const h = fs.existsSync(p) ? sha256(fs.readFileSync(p)) : "(缺失)";
      const okMan = man.files && man.files[f.name] && man.files[f.name].sha256 === h;
      const okLock = !lock || (lock.files && lock.files[f.name] && lock.files[f.name].sha256 === h);
      console.log(`${okMan && okLock ? "OK " : "BAD"} ${f.name}  ${h}${okLock ? "" : "  ← 与 vendor.lock.json 不符"}`);
      if (!(okMan && okLock)) bad++;
    }
    process.exit(bad ? 1 : 0);
  }
  const results = [];
  for (const f of FILES) {                                  // 先全部下载并自检，全部通过后才写盘
    process.stdout.write(`下载 ${f.name} ← ${f.url}\n`);
    const { code, from } = await resolveBundle(f.url);
    sanityCheck(f.name, code, f.mustExport);
    const h = sha256(code);
    if (lock && !(lock.files && lock.files[f.name] && lock.files[f.name].sha256 === h))
      throw new Error(`${f.name} 的 SHA-256（${h}）与 vendor.lock.json 不一致：上游内容变了，或下载途中被篡改。拒绝写入。`);
    if (!args.has("--skip-selftest")) console.log("  自检：" + await f.selftest(await importFromText(code)));
    results.push({ f, code, from, h });
  }
  fs.mkdirSync(VENDOR, { recursive: true });
  const manifest = { generatedAt: new Date().toISOString(), files: {} };
  for (const { f, code, from, h } of results) {
    fs.writeFileSync(path.join(VENDOR, f.name), code);
    manifest.files[f.name] = { sha256: h, bytes: Buffer.byteLength(code), resolvedFrom: from };
    console.log(`  → vendor/${f.name}  ${Buffer.byteLength(code)} 字节  sha256=${h}`);
  }
  fs.writeFileSync(MANIFEST, JSON.stringify(manifest, null, 2) + "\n");
  console.log("\n已写入 vendor/manifest.json（server.js 启动时会核对它）。" + (lock ? "已与 vendor.lock.json 核对一致。" :
    "建议在另一台机器 / 另一条网络上再跑一次并比对上面的 SHA-256，一致后执行 npm run vendor -- --write-lock 并把 vendor/ 与 vendor.lock.json 一起提交。"));
}
main().catch((e) => { console.error("失败：" + (e && e.message || e)); process.exit(1); });
