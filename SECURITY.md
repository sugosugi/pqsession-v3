# pqsession v3 安全升级说明

本文件记录对 v2（2.1.2）的安全审计发现、v3 的修复方式、守住每项修复的回归测试，以及 v3 协议规格。

## 一、审计发现与修复

严重度按“攻击者需要什么 × 造成什么”评估。“中继”指运营或控制中继服务器的一方，这正是本项目威胁模型里要防的对象。

| 编号 | 严重度 | v2 的问题 | v3 的修复 | 回归测试 |
| --- | --- | --- | --- | --- |
| F1 | **严重** | 发给中继的房间号 = `SHA-256("pqsession-room-id-v2" ‖ 口令)`，是一个**快速离线校验器**。实测：人起的口令（如 `WANGXIAOMING2024`）636 次猜测即被还原；随机 10 位口令（31¹⁰ ≈ 8.2×10¹⁴）单张 GPU（按 2×10¹⁰ 次/秒估算）约 11 小时穷举完。口令一旦被破，再算一次 Argon2id 就得到信封密钥：中继重新获得读取双方身份公钥、伪造任意信令的能力，Argon2id 的保护被整个绕开。 | 只做一次 Argon2id（64 MiB，t=3），房间标识与信封密钥都由其输出经 HKDF 派生，每验证一个猜测都要付出一次 Argon2id；随机口令加长到 12 位（约 59 bit）。 | `test-frontend`：房间层第 1 项；`test-e2e`：离线猜口令的代价 |
| F2 | 高 | `TRUST_PROXY=1` 时客户端 IP 取 `X-Forwarded-For` **最左值**，而最左值由客户端随意填写：每次换一个伪造值即可绕过“每 IP 并发上限”。IPv6 逐地址计数，一个用户手握 2⁶⁴ 个地址。 | 只取从右数第 `TRUST_PROXY_HOPS` 个值（条目不足时退回 socket 地址）；IPv6 按 /64 合并；新增每来源**新建连接**速率限制。 | `test-relay`：客户端 IP 两项、限速一项 |
| F3 | 高 | 信封的防重放窗口按“发送方的随机连接标签”维护，而信封密钥只取决于口令。中继**无需知道口令**，就能把上一次连接录下的 BYE / INVITE 原样重放进新连接：拆掉会话，或让握手失败并弹出“疑似中间人”告警（久而久之用户对告警麻木）。 | 每次连接生成 16 字节标签；除身份声明外，每一帧都必须**来自当前对端连接且写明发给本次连接**，否则丢弃；握手转录绑定房间标识与双方标签。 | `test-frontend`：跨连接重放；`test-e2e`：跨连接重放（INVITE / ACCEPT / FINISH / 消息 / BYE 全部被丢弃） |
| F4 | 中 | 两消息握手里应答方 B 收到 INVITE 就宣布“会话已建立”，没有发起方的显式密钥确认：被重放的旧 INVITE 也能让 B 显示“与已核对联系人的会话”，而对面其实没有人。 | 三消息握手：A 验证 B 的确认值后发出 FINISH（HMAC 确认值），B 验证通过前会话既不能加密也不能解密。 | `test-frontend`：握手 1–5 项 |
| F5 | 中 | 没有事后泄露自愈：会话状态一旦泄露，此后整个会话都可被读。 | 分纪元混合重新密钥（新的一次性 X25519 + ML-KEM-1024，与旧根密钥经 HKDF 混合），默认每 2 分钟或 2000 条消息自动执行，可手动触发；旧根密钥与更早纪元的密钥随即销毁。 | `test-frontend`：重新密钥 8 项（含“窃取全部状态的攻击者跟不上新纪元”）；`test-e2e`、`test-browser` |
| F6 | 中 | 纯文本消息没有类型前缀：以 `0x01` 开头的文本会被当作控制帧解析，旧式 `0x01 'F' ':'` 路径可直接触发文件下载；收到的文件一律**自动下载**，Blob 的 MIME 由对端决定。 | 每条明文首字节为类型（`0x00` 文本 / `0x01` 控制），其余丢弃；删除旧路径；文件收齐后由用户点「保存」才落盘，Blob 一律 `application/octet-stream`。 | `test-browser`：以 `0x01F:` 开头的文本只显示不下载；文件不自动下载、点保存后逐字节一致；`test-frontend` 静态检查 |
| F7 | 中 | 信任列表的加密密钥只由 X25519 身份私钥派生，量子计算机可由公钥（对端知道）反推；列表无法解密时从空列表开始并在下次保存时**静默覆盖**，等于允许“破坏本机列表”悄悄抹掉全部已核对记录。 | 由 X25519 与 ML-KEM 两把私钥共同派生，自动迁移旧列表；无法解密时进入只读，不覆盖、不写入，直到用户确认清空。 | `test-frontend`：信任存储 5 项 |
| F8 | 中 | 本地 vendor 缺失时页面从 esm.sh 加载密码学实现，服务器默认放行：CDN 或路径上任何人都能替换整套实现。vendor 文件固定之后被改动也无从察觉。 | 失败即关闭：页面只从同源 vendor 加载；服务器启动时核对 `vendor/manifest.json`（及可选的 `vendor.lock.json`），不符拒绝启动；`npm run vendor` 写盘前先执行下载到的代码做功能自检，包括 Argon2id 已知答案。 | `test-relay`：算法库固定两项 |
| F9 | 低 | CSP：`script-src` 含 `blob:`（语音 worklet 需要）、`style-src 'unsafe-inline'`、`connect-src` 允许任意 `ws:`/`wss:`（一旦出现注入即可外传）。 | worklet 改为同源文件；样式改用哈希（全部内联 `style` 属性改为类）；启用 Trusted Types；`connect-src` 只放行本站与 `RELAY_ORIGINS`；补齐 `worker-src` / `frame-src` / `font-src` / `manifest-src 'none'`。服务器发现 `unsafe-inline` 或内联属性即拒绝启动。 | `test-relay`：CSP 四项；`test-browser`：全程零 CSP / Trusted Types 违规 |
| F10 | 低 | `.pqkey` 文件头里的 Argon2 参数无上下界：伪造文件可让浏览器申请巨量内存。 | t 1–16、m 8 MiB–1 GiB、p 1–16。 | — |
| F11 | 低 | 载入身份文件不核验私钥与公钥是否一对：指纹可能与实际使用的私钥不对应，对方核对的指纹因而失去意义。 | 由 X25519 私钥推出公钥比对；检查 ML-KEM 私钥内嵌的公钥（FIPS 203 布局）。 | `test-frontend`：身份文件 |
| F12 | 低 | ML-KEM 公钥只查长度，不做 FIPS 203 §7.2 模数检查。 | 身份公钥、握手一次性公钥、重新密钥公钥在进入 KEM 前全部检查。 | `test-frontend`：模数检查、INVITE、非法 OFFER |
| F13 | 低 | 消息长度原样暴露给中继。 | Padmé 填充（最小 256 字节，开销 ≤ 12%）；语音包全部落在同一个桶。 | `test-frontend`：长度隐藏 |
| F14 | 低 | 部署在不发 `frame-ancestors` 响应头的静态托管上时可被 iframe 嵌套（诱导误点“指纹一致”）。 | 页面检测到被嵌套即拒绝运行。 | — |
| F15 | 低 | 接收队列无上限；异常帧逐条写日志。 | 积压上限 4096 帧；同类日志限频。 | — |
| F16 | 低 | 身份私钥以 base64 字符串驻留内存（无法清零）。 | 以 `Uint8Array` 保存，换身份 / 离开页面时清零。 | `test-frontend`：identityWipe |
| F17 | 低 | 中继接受任意字符串作房间名（截断到 64 字符），每条连接可反复换房间。 | 只接受 32 位小写十六进制；每条连接只能入房一次。 | `test-relay`：hub 与连接处理 |
| F18 | 信息 | 原生 TLS 只用经典密钥交换：记录流量的攻击者将来可解出房间标识与信令时序。 | 优先 X25519MLKEM768 混合组（不支持的客户端自动退回经典组）；TLS 1.2 只保留 ECDHE + AEAD。 | `test-relay`：TLS；已实测握手结果 |
| F19 | 信息 | `package.json` 引用的 `test-e2e.mjs` 与 `cert.mjs` 不在包里，`npm test` 与 `npm run cert` 直接失败。 | 两者重新编写。 | — |

v2 做得好的地方已保留：全程 `textContent`（未发现 XSS 注入点）、“先验证后提交”的棘轮、严格的握手长度校验、中继的崩溃修复与背压、指纹 256 位。

## 二、v3 协议规格

**房间层。** `master = Argon2id(口令, salt = SHA-256("pqsession-room-salt-v3" ‖ 口令)[0:16], t=3, m=64 MiB, p=1)`；房间标识 = `HKDF-SHA-256(master, "pqsession-room-id-v3")` 的前 16 字节；信封密钥 = `HKDF-SHA-256(master, "pqsession-room-env-v3")`。信封为 AES-256-GCM（随机 96 位 nonce，AAD `"PQSESS-room-v3"`），明文为 `发送方标签(16) ‖ 计数器(u32) ‖ 类型(u8) ‖ 接收方标签(16) ‖ 载荷`，接收方用 64 位滑动窗口防重放。

**握手（三消息）。**
```
A → B  INVITE : EKa_x(32) ‖ EKa_m(1568) ‖ ct1 = Encaps(IKb_m)
B → A  ACCEPT : EKb_x(32) ‖ ct2 = Encaps(EKa_m) ‖ ct3 = Encaps(IKa_m) ‖ confB(32)
A → B  FINISH : confA(32)
ikm  = k1 ‖ k2 ‖ k3 ‖ DH(IKa,IKb) ‖ DH(EKa,IKb) ‖ DH(EKa,EKb)
ctx  = "pqsession/3|hs-ctx" ‖ 房间标识 ‖ 发起方连接标签 ‖ 应答方连接标签
th   = SHA-512("PQSESSv3-transcript" ‖ len(ctx) ‖ ctx ‖ idA ‖ idB ‖ EKa_x ‖ EKa_m ‖ ct1 ‖ EKb_x ‖ ct2 ‖ ct3)
root = HKDF-SHA-512(ikm, info = "PQSESSv3-root" ‖ th) → confirmKey / sid(16) / rk₀
confB = HMAC-SHA-256(confirmKey, "PQSESSv3-confirm-B" ‖ th)；confA 同理（标签 -A）
```
经典侧前向保密来自 `DH(EKa,EKb)`，后量子侧来自 `k2`（封装到发起方的一次性 ML-KEM 公钥）；双向认证分别由 `k1`/`k3`（后量子）与静态 DH（经典）提供。

**消息。** 纪元 e 的链密钥 `ck_A2B = HKDF(rk_e, "PQSESSv3-ck-A2B" ‖ e)`（B2A 同理）；逐消息 `(mk, ck') = HKDF(ck, "PQSESSv3-step")`。消息头 `"PQSESSv3" ‖ 4 ‖ sid(16) ‖ 方向 ‖ 纪元(u32) ‖ 序号(u32)` 作为 AEAD 的 AAD；明文先按 Padmé 填充。接收端“先验证后提交”，单次跳号 ≤ 512，缓存密钥总量 ≤ 1024。

**重新密钥。** 在当前纪元的棘轮内传输：`OFFER(rid, e+1, X_i, M_i)` → `ANSWER(rid, e+1, X_r, ct = Encaps(M_i))` → `CONFIRM`（纪元 e+1 的第一条消息）。
```
thR     = SHA-512("PQSESSv3-rekey" ‖ sid ‖ e+1 ‖ rid ‖ X_i ‖ M_i ‖ X_r ‖ ct)
rk_{e+1} = HKDF-SHA-512(ikm = ss_kem ‖ X25519(x_i, X_r), salt = rk_e, info = "PQSESSv3-rekey-rk" ‖ thR)
```
发起方收到 ANSWER 即提交；应答方收到第一条纪元 e+1 的消息才提交（ANSWER 丢失时双方都还在旧纪元，发起方 30 秒后重来）。同时发起时 A 的 OFFER 胜出。只有在“对方已切到当前纪元”之后才会发起下一次，因此双方最多相差一个纪元，接收端只保留上一纪元与当前纪元的密钥。

**应用帧。** 明文首字节：`0x00` 文本；`0x01` 控制帧，第二字节 `S/C/A` 文件、`R/K/D/V` 语音、`X/Y/Z` 重新密钥、`Q` 经会话密钥认证的结束会话。

## 三、威胁模型与仍然存在的局限

v3 防护的对象：完全恶意的中继（读、改、丢、重放、注入任意帧，离线猜口令）、网络上的被动与主动攻击者、“先存后解”的量子攻击者，以及短暂窃取过会话状态的被动攻击者（下一次重新密钥后自愈）。

v3 不能防护：没有带外核对指纹就点了“一致”（TOFU 的根本前提）；持续控制你设备或浏览器的攻击者；中继可见的元数据（IP、时间、房间标识、按桶取整的大小与节奏）；中继随时可以拒绝服务。协议与实现都未经独立审计，底层 ML-KEM 实现不防侧信道，JS 无法保证擦除内存。生死攸关的场景请使用经过审计的工具（如 Signal）。

## 四、如何验证

`npm test` 运行 62 项 Node 测试（中继 18、前端 36、经真实中继逻辑的端到端与攻击 8），测试对象是页面里**真正运行的代码**（由 `test-extract.mjs` 原样提取，而不是副本）。`npm run test:browser` 用两个真实 Chromium 经真实中继跑完整流程（握手、双方各一次重新密钥、文件、语音、断线重连），并断言全程零 CSP / Trusted Types 违规。

注意：本次升级在无网络的环境中完成，测试中的 ML-KEM 与 Argon2id 是**只用于测试、尺寸忠实的替身**，并非真实算法。部署前请在联网机器上执行 `npm run vendor`（会对真实库做功能自检与 Argon2id 已知答案校验），再运行 `npm test` 与 `npm run test:browser`。
