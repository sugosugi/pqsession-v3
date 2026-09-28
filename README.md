# pqsession 中继 v3：安全升级版部署说明

v3 是一次**以安全为目标的全面升级**，修复了 v2 的一个严重问题（中继可离线破解房间口令）和多处较高风险问题，并补上了 v2 自述的最大缺口“没有事后泄露自愈”。完整的审计发现、修复方式与协议规格见 **[SECURITY.md](SECURITY.md)**。

| 文件 | 作用 |
| --- | --- |
| `server.js` | 中继服务器 v3（哑管道；失败即关闭的算法库固定；严格 CSP + Trusted Types；XFF 伪造修复；每来源连接限速；抗量子混合 TLS） |
| `pqsession-net.html` | 前端 v3（三消息握手 + 双向密钥确认；分纪元混合重新密钥；房间标识由 Argon2id 派生；信令与连接绑定；长度填充；文件点击保存） |
| `vc-worklet.js` | 语音 AudioWorklet（同源提供，CSP 因此不再需要 `blob:`） |
| `vendor.mjs` | 把 ML-KEM / hash-wasm 固定到 `./vendor`：下载 → 功能自检（含 Argon2id 已知答案）→ 记录 SHA-256 |
| `cert.mjs` | 生成自签名 TLS 证书（`npm run cert`），打印证书指纹供核对 |
| `csp-meta.mjs` | 维护工具：改动页面脚本 / 样式后重算 `<meta>` CSP 哈希（`npm run csp`） |
| `test-relay.mjs`、`test-frontend.mjs`、`test-e2e.mjs` | 不装依赖、不联网即可运行的测试（`npm test`，共 62 项），测的是页面里真正运行的代码 |
| `test-browser.mjs` | 可选：真实 Chromium × 2 经真实中继跑完整流程（含语音），并断言零 CSP / Trusted Types 违规（`npm run test:browser`） |

## 一、最小部署步骤

```bash
npm install                 # 只有 ws 一个依赖
npm run vendor              # 联网一次：下载算法库并做功能自检（任何一项不符都不会写入）
npm run vendor -- --write-lock   # 建议：在另一台机器 / 另一条网络上也跑一次 vendor，比对 SHA-256 一致后写锁
npm run check               # 自检：CSP 哈希、vendor 与 manifest 一致性、配置
npm test                    # 62 项测试
TLS_CERT=fullchain.pem TLS_KEY=privkey.pem npm start     # 原生 TLS；或放在反向代理后：TRUST_PROXY=1 npm start
```

**v3 失败即关闭：** 没有执行 `npm run vendor`、或 vendor 文件与 `vendor/manifest.json`（及 `vendor.lock.json`）记录的哈希不符时，服务器拒绝启动；页面也不再有 esm.sh 退路。请把 `vendor/` 与 `vendor.lock.json` 提交到版本库。

浏览器只在安全上下文（https:// 或 localhost）里提供 Web Crypto 与麦克风；纯 http 暴露到公网时页面无法工作，`--check` 与启动日志都会警告。

## 二、环境变量（全部可选）

| 变量 | 默认 | 含义 |
| --- | --- | --- |
| `PORT` / `HOST` | 8080 / 0.0.0.0 | 监听地址 |
| `TLS_CERT` / `TLS_KEY` | 空 | 同时给出即启用原生 TLS，并自动加 HSTS |
| `TLS_PQ` | 1 | 优先协商 X25519MLKEM768 混合密钥交换（需 Node 自带 OpenSSL ≥ 3.5；不支持时自动退回经典组） |
| `TLS_MIN` | 1.2 | 设为 `1.3` 则只接受 TLS 1.3（TLS 1.2 只保留 ECDHE + AEAD 套件） |
| `TRUST_PROXY` | 关 | 置于反向代理之后才打开：信任 `X-Forwarded-*` |
| `TRUST_PROXY_HOPS` | 1 | 中继前面的**可信代理层数**：客户端 IP 取 XFF 从右数第 N 个值（v2 取最左值，可被伪造） |
| `ALLOWED_ORIGINS` | 空（仅同源） | 逗号分隔的 origin 列表；`*` 表示任意 |
| `RELAY_ORIGINS` | 空 | 本站托管的页面还允许连接的其他中继（如 `wss://relay2.example`），写入 CSP `connect-src` |
| `MAX_CONN_PER_IP` | 64 | 每来源并发连接上限（IPv6 按 /64 计）；0 关闭 |
| `CONN_RATE_PER_IP` / `CONN_BURST_PER_IP` | 5 / 30 | 每来源**新建连接**速率（令牌/秒 / 突发）；0 关闭 |
| `MAX_CONN` | 4096 | 全局并发连接上限；0 关闭 |
| `JOIN_TIMEOUT_MS` | 30000 | 连接后迟迟不 join 的连接被关闭；0 关闭 |
| `MAX_PAYLOAD` | 4 MiB | 单帧上限 |
| `MSG_RATE` / `MSG_BURST` | 2000 / 4000 | 每连接消息条数限流（超额丢弃） |
| `BYTES_RATE` / `BYTES_BURST` | 32 MiB/s / 96 MiB | 每连接字节整形（超额暂停读取，不丢帧）；`BYTES_RATE=0` 关闭 |
| `BP_HIGH` / `BP_LOW` | 8 MiB / 1 MiB | 背压高低水位 |
| `BP_STALL_MS` | 60000 | 对端持续不读超过此时长即判僵死踢出 |
| `HEARTBEAT_MS` | 30000 | 心跳间隔；0 关闭 |
| `VENDOR_DIR` | `./vendor` | 本地算法库目录 |

反向代理后部署时，请确认代理**追加**而不是透传 `X-Forwarded-For`（nginx：`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`），并按实际层数设置 `TRUST_PROXY_HOPS`。

## 三、已核对联系人（信任存储）

- 只保存指纹、你起的名字和「房间标识 → 上次对方指纹」，不含任何密钥。
- **v3：** 加密密钥由你的 **X25519 与 ML-KEM 两把身份私钥**共同派生（v2 只用 X25519 私钥，量子攻击者可由公钥反推）。首次载入身份时自动迁移 v2 列表（v2 的房间记录不迁移）。
- **v3：** 列表无法解密（损坏 / 被篡改 / 不是当前身份加密的）时进入**只读**：不覆盖旧数据、不记住新指纹，所有指纹都需手动核对，直到你确认后点「清空全部」。v2 会悄悄覆盖。
- 同一指纹再次出现自动通过核对；新指纹而你已核对过别人时警告；重名视为“密钥变更”需二次确认；同一房间口令下指纹变化红色告警；连接中途被替换出现的指纹不自动通过。
- 可导出 / 导入 JSON（导出为明文需确认，导入等于信任其中的指纹也需确认）。

## 四、语音通话排错

1. 必须是安全上下文（`https://` 或 `localhost`）。局域网可用 `npm run cert` 生成自签名证书，核对打印出的指纹后在证书警告页选择“继续”。
2. 麦克风权限被设为“拒绝”后浏览器不再弹窗：在地址栏左侧的权限图标里改回“允许”或“询问”后刷新。
3. `Permissions-Policy` 必须保留 `microphone=(self)` 与 `autoplay=(self)`（测试守着这两项）。
4. **v3：** AudioWorklet 从同源 `/vc-worklet.js` 装载。若日志显示“语音处理模块装载失败”，请确认该文件可访问，且反向代理 / CDN 没有改写本站的 `Content-Security-Policy` 响应头。

通话状态栏实时显示“已发 N 包 · 已收 M 包”：发包为 0 是采集侧问题，收包为 0 是链路问题，两者都正常但无声是播放侧问题。

## 五、v3 的行为变化（升级必读）

1. **v3 与 v2 页面不能互通**（握手、信封格式都变了）。双方都要用 v3 页面。
2. **身份指纹不变**：已带外核对过的联系人不必重新核对；身份文件（.key / .pqkey）继续可用，载入时会核验私钥与公钥确实是一对。
3. 房间口令「随机生成」改为 12 位（约 59 bit），4 位一组显示；中继收到的房间标识由口令经 Argon2id 派生。
4. 握手改为三条消息：应答方收到发起方的密钥确认（FINISH）后才显示“会话已建立”。
5. 会话密钥每 2 分钟或每 2000 条消息自动做一次混合（X25519 + ML-KEM-1024）重新密钥，也可以点「立即更新密钥」；会话栏显示当前“密钥纪元”。
6. 收到的文件**不再自动下载**：收齐后在消息里点「保存」才落盘。
7. 私钥导出口令至少 12 位。页面拒绝在别的网页的 iframe 里运行。
8. 服务器没有 `vendor/` 就拒绝启动（见第一节）。

## 六、仍然存在的局限（诚实告知）

- 协议与实现均未经独立审计；`@noble/post-quantum` 官方声明未经审计且不防侧信道。
- JS 无法保证擦除内存：v3 把身份私钥改为可清零的字节数组并在离开页面时清零，但无法控制引擎内部的副本。
- 中继仍看得到 IP、时间、房间标识、按桶取整后的消息大小与节奏（语音恒定码率缓解了节奏泄露）。
- 事后泄露自愈只对**被动**攻击者有效，且以“纪元”为粒度（默认最长约 2 分钟）；持续控制你设备的攻击者不受影响。
- 房间口令只保护元数据（身份公钥、信令）；口令被猜中不影响聊天内容。
- 信任存储遵循 TOFU：第一次若没有认真带外核对，之后的“已知联系人”提示也就没有意义。
