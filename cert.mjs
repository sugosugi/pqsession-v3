#!/usr/bin/env node
// 生成自签名 TLS 证书（局域网 / 测试用）：npm run cert [-- 额外的主机名或 IP ...] [--force]
// 需要本机有 openssl（1.1.1+）。生成 cert.pem / key.pem（私钥权限 600，ECDSA P-256），并打印证书的 SHA-256 指纹：
// 浏览器会对自签名证书报警 —— 请先在证书详情里核对这个指纹，一致再选“继续”，否则你无法确认连上的确实是这台中继。
// 然后：TLS_CERT=cert.pem TLS_KEY=key.pem npm start   （输出目录可用 CERT_DIR 指定）
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const dir = process.env.CERT_DIR || path.dirname(fileURLToPath(import.meta.url));
const cert = path.join(dir, "cert.pem"), key = path.join(dir, "key.pem");
const args = process.argv.slice(2);
if ((fs.existsSync(cert) || fs.existsSync(key)) && !args.includes("--force")) {
  console.error(`${cert} 或 ${key} 已存在；确需覆盖请加 --force。`); process.exit(1);
}
const names = new Set(["localhost"]), ips = new Set(["127.0.0.1", "::1"]);
for (const list of Object.values(os.networkInterfaces())) for (const a of list || []) if (!a.internal && (a.family === "IPv4" || a.family === 4)) ips.add(a.address);
for (const x of args) if (!x.startsWith("--")) (/^[\d.]+$/.test(x) || x.includes(":") ? ips : names).add(x);
const san = [...[...names].map((n) => "DNS:" + n), ...[...ips].map((i) => "IP:" + i)].join(",");
const r = spawnSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
  "-keyout", key, "-out", cert, "-days", "397", "-subj", "/CN=pqsession-relay",
  "-addext", "subjectAltName=" + san, "-addext", "extendedKeyUsage=serverAuth"], { stdio: ["ignore", "pipe", "pipe"] });
if (r.error || r.status !== 0) {
  console.error("调用 openssl 失败：" + (r.error ? r.error.message : r.stderr.toString()));
  console.error("请安装 openssl 1.1.1+，或改用带正式证书的反向代理（并设置 TRUST_PROXY=1）。"); process.exit(1);
}
fs.chmodSync(key, 0o600);
const x = new crypto.X509Certificate(fs.readFileSync(cert));
console.log(`已生成 ${cert} / ${key}（私钥权限 600）\n  主体备用名：${x.subjectAltName}\n  有效期至：${x.validTo}\n  SHA-256 指纹：${x.fingerprint256}\n` +
  "在浏览器证书警告页核对上面的指纹后再继续。启动：TLS_CERT=cert.pem TLS_KEY=key.pem npm start");
