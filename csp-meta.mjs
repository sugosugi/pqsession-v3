#!/usr/bin/env node
// 维护工具：按页面当前的内联 <script> / <style> 重新计算 SHA-256，并写回 pqsession-net.html 的 <meta> CSP。
// 改动了页面里的脚本或样式之后运行：npm run csp      （只检查不写入：npm run csp -- --check）
// 服务器启动时会做同样的计算并与 <meta> 比对，不一致直接拒绝启动 —— 请用本工具更新，不要改成 'unsafe-inline'。
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { inlineScriptHashes, inlineStyleHashes, metaCspOf, HTML_FILE } from "./server.js";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const file = path.join(ROOT, HTML_FILE);
const html = fs.readFileSync(file, "utf8");
const scripts = inlineScriptHashes(html).map((h) => `'${h}'`).join(" ");
const styles = inlineStyleHashes(html).map((h) => `'${h}'`).join(" ");
// <meta> 版策略：比响应头宽松的只有 connect-src（静态托管时页面可能要连别处的中继）；frame-ancestors 在 <meta> 里无效，只能由响应头给出。
const policy = [
  "default-src 'none'",
  `script-src 'self' 'wasm-unsafe-eval' ${scripts}`,
  `style-src ${styles || "'none'"}`,
  "img-src data:",
  "connect-src 'self' ws: wss:",
  "media-src 'none'", "object-src 'none'", "worker-src 'none'", "frame-src 'none'",
  "base-uri 'none'", "form-action 'none'",
  "require-trusted-types-for 'script'", "trusted-types 'none'",
].join("; ");
const cur = metaCspOf(html);
if (cur === null) { console.error("找不到 <meta http-equiv=\"Content-Security-Policy\">"); process.exit(1); }
if (cur === policy) { console.log("<meta> CSP 已是最新：\n  " + policy); process.exit(0); }
if (process.argv.includes("--check")) { console.error("<meta> CSP 与当前内联脚本 / 样式不一致，请运行 npm run csp"); process.exit(1); }
const out = html.replace(/(<meta\s+http-equiv=(["'])Content-Security-Policy\2\s+content=)(["'])[\s\S]*?\3/i, `$1"${policy}"`);
fs.writeFileSync(file, out);
console.log("已更新 <meta> CSP：\n  " + policy);
