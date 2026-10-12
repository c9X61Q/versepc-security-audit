# VersePC2 客户端安全审查报告

**审查对象**：`VersePC2-1.1.2-linux-x86_64` / `VersePC2.exe`
**审查方式**：静态逆向（strings / 字符串上下文还原 / 模块与命令表重建 / 网络端点提取）
**报告日期**：2025
**风险等级汇总**：**高**（存在远程代码执行面 + 未签名自动更新 + 插件任意执行 + 凭据明文存储）
**条目数**：高危 7 项（H-1 ~ H-7）、中危 8 项（M-1 ~ M-8）、低危提示 1 项（L-1）
**修订记录**：原 H-3「第三方联机内核（hongshi）下载运行」经背景核查为公开第三方项目（Redstone Online2），**已撤销**并降级为 L-1 提示；后续条目编号前移。

---

## 0. 样本概况

| 项目 | Linux | Windows |
|---|---|---|
| 文件名 | `VersePC2-1.1.2-linux-x86_64` | `VersePC2.exe` |
| 格式 | ELF 64-bit PIE, stripped | PE32+ GUI x86-64 |
| 大小 | 69,623,264 B | 73,991,680 B |
| SHA-256 | `88d3e60984f52547f7daff5b358485bea4b0143d05104e811135934831359d19` | `f9dfcf266aec1be42decea086117cf1dcf264917fcc968c251fe8d49a384e6df` |
| 框架 | **Tauri v2.11.5**（Rust 后端 + WebKit2GTK/WebView2 前端） | **Tauri v2.11.5**（Rust 后端 + WebView2 前端） |
| 版本号 | 1.1.2 | 1.5.4.0 |
| 公司/产品 | versepc / VersePC2 | versepc / VersePC2 |
| 构建环境 | `/home/runner/.cargo`（GitHub Actions） | `D:\VerseTools\.cargo`（rsproxy.cn 镜像） |
| 前端 | 静态资源 Brotli 压缩内嵌于二进制 | 同左 |

**功能定位**：Minecraft 启动器 + 联机工具。核心能力包括：版本安装/启动、模组加载器（Fabric/Forge/NeoForge/OptiFine/FabricAPI）安装、CurseForge/Modrinth 整合包与模组下载、微软 Xbox Live 正版登录、外置登录（authlib-injector）、联机隧道（FRP）、服务端托管、插件系统、TTS 语音、崩溃日志分析、AI 对话、壁纸引擎集成。

**自有源码模块 89 个**（清单见 `VersePC2.exe.own_modules.txt` / `VersePC2-linux.own_modules.txt`）。

---

## 1. 高危发现（Critical / High）

### H-1 【严重】自动更新无签名校验，更新源可被劫持 → 远程代码执行

**证据**（二进制内字符串）：
```
https://raw.githubusercontent.com/doujie081231/VersePc2/main/update.json
https://ghfast.top/https://raw.githubusercontent.com/doujie081231/VersePc2/main/update.json
https://ghproxy.net/https://raw.githubusercontent.com/doujie081231/VersePc2/main/update.json
https://gh-proxy.com/https://raw.githubusercontent.com/doujie081231/VersePc2/main/update.json
无法写入更新脚本: / 无法启动更新脚本: / 未找到适用于当前平台的安装包
updates win-x64 VersePC2- ...
```

**问题**：
1. 更新清单与安装包均来自 **个人仓库（`doujie081231/VersePc2`）+ 第三方 GitHub 加速代理**（`ghfast.top` / `ghproxy.net` / `gh-proxy.com`）。
2. 更新流程中**未发现任何签名/公钥校验逻辑**（全二进制 `ring::signature` 仅用于自带 rustls TLS，未用于更新包验签；对比之下 `plugin_download_install` 有 `sha256` 参数，更新器没有）。
3. **加速代理是中间人可控的**：`ghfast.top`、`ghproxy.net` 等第三方代理可返回任意内容。任意一个代理被投毒（或域名被抢注/劫持），即可向全部客户端下发恶意 `VersePC2-x.x.x-win-x64` 安装包并自动执行。
4. 仓库为个人仓库，无组织级保护，账号被盗 = 全量客户端沦陷。

**影响**：全平台客户端远程代码执行（供应链攻击）。攻击者只需控制 1 个代理域名或该 GitHub 账号。

**修复建议**：
- 更新包必须 Ed25519/RSA 签名，公钥硬编码于客户端，验签失败拒绝安装；
- 移除第三方加速代理，或仅将其作为下载通道但**必须**在本地完成签名校验；
- update.json 亦须签名（防版本降级与 URL 劫持）。

---

### H-2 【严重】插件系统具备本机任意程序执行能力，权限校验在客户端且可绕过

**证据**：
```
命令表: plugin_process_exec | pluginId | exe | args | cwd | ini | configName
        plugin_download_install | sha256 | expectedId | plugin_market_index | indexUrl
        plugin_process_status | plugin_process_stop
src\plugin_exec.rs        (Windows 独有模块)
src\filesystem.rs
"插件 %s 未声明 native:exec 权限"
"该插件已有进程在运行.."
"非法的配置文件名"
"插件缺少合法的 plugin.json"
"插件包校验哈希值失败"
插件市场索引: https://gitee.com/doujie081231/verseplugin/raw/master/index.json
```

**问题**：
1. 插件可调用 `plugin_process_exec(pluginId, exe, args, cwd, ini, configName)` **在本机执行任意可执行文件**（`exe` 由插件包/参数指定）。
2. 权限模型是 `plugin.json` 中的 `native:exec` 声明 + 客户端自校验。**权限判断发生在客户端本地**——攻击者只需构造/篡改 `plugin.json` 声明 `native:exec`，或直接调用 IPC，即可获得执行能力。声明式权限对本地攻击者等于无防护。
3. 插件市场索引托管在 **Gitee 个人仓库**（`doujie081231/verseplugin`），无签名；索引可被篡改以向所有客户端推送恶意插件。
4. 插件下载仅做 `sha256` 校验，但 **sha256 值来自同一索引**（`expectedId`/`sha256` 均可由索引控制），哈希校验无法防投毒——攻击者改包同时改哈希即可。
5. `src\plugin_exec.rs` 仅在 Windows 存在，Linux 无——Windows 用户风险更高。

**影响**：本地代码执行 / 插件市场供应链投毒 → 全量客户端 RCE。

**修复建议**：
- 插件包必须签名，公钥内置；`native:exec` 需用户显式二次确认并展示完整命令行；
- 插件执行应限制在沙箱（受限 token / 作业对象 / 目录白名单）；
- 索引须签名，插件 sha256 须为签名保护的固定值而非索引内可变量。

---

> **已撤销条目说明（原 H-3）**：本节原将"第三方联机内核（hongshi / redstone）下载运行"列为严重项。经核查，**hongshi 为公开的第三方联机中继项目（Redstone Online2，官网 `hongshi.site`，开源仓库 `github.com/hongshionline/hongshi2`，Rust 编写，公开 API 文档）**，VersePC2 系按官方公开 API 正常集成，属正常业务依赖，非恶意通道。**该条已撤销**，仅保留为文末低危提示（见 L-1）。

---

### H-3 【高】内网穿透（FRP）隧道：节点与房间信息来自明文第三方接口

**证据**：
```
https://lytapi.asia/frplist58.txt          ← 节点列表（明文文本）
https://lytapi.asia/api.php                 ← 通用 API
https://lytapi.asia/rooma.php               ← 房间列表
https://gitee.com/lyt590/enderlinkupdate/releases/download/frp/frp.zip  ← frpc 客户端下载
"tar -xf -C 解压 frp 客户端失败"  "未在压缩包中找到 frpc.exe"
frpc.ini  src\server_host.rs
字段: node / decryptedToken / localPort / isPublic / remotePort / remote_port
      node_id / room_name / roomName / player_count / game_version
      host_player / hostPlayer / Steve / is_public / server_addr
"frpc 已启动 (PID ...)"  "隧道: %s -> 本机 %s"
OpenUPnP: gamePort playerName roomCode internalPort externalPort useUPnP
```

**问题**：
1. 节点列表来自 `https://lytapi.asia/frplist58.txt`（**明文、无签名、无校验**），可被中间人替换以把用户隧道指向恶意节点。
2. `frpc` 客户端从 **Gitee 个人仓库**下载并解压执行，无签名校验 → 可下发恶意 frpc。
3. 使用 UPnP 自动在路由器上**开放端口**（`useUPnP` / `internalPort` / `externalPort`），可能把内网服务暴露到公网。
4. 字段 `decryptedToken` 表明 token 在此处被**解密后明文传入 frpc 配置**（`frpc.ini`），token 以文件形式落盘。

**影响**：MITM 控制隧道节点、恶意 frpc 执行、内网暴露。

**修复建议**：节点/房间列表走 HTTPS + 签名；frpc 二进制签名校验；默认关闭 UPnP，改为用户显式授权；token 不明文落盘。

---

### H-4 【高】凭据落盘存储，token 保护薄弱

**证据**：
```
accounts.json      ← 账号文件
store.json / app-store.json / versepc_* 
"Token 解密失败" "请重新登录" "refreshToken" "accessToken" "clientToken"
"缺少 accountId" "tokenExpiresAt" "lastRefreshed"
路径: %AppData%\Roaming\VersePC  (.minecraft / runtime / logs)
src/storage.rs  src/auth/token.rs
```
**问题**：
1. 微软 `refreshToken`、`accessToken`、`clientToken`、账号列表全部以 `accounts.json` 落盘。
2. 虽出现 "Token 解密失败" 提示存在某种加解密，但**未发现使用系统凭据库（Windows DPAPI / Credential Manager、Linux keyring / Secret Service）**——检索 `keyring` / `Credential` / `DPAPI` 无对应实现，只有 HTTP 头 `Access-Control-Allow-Credentials`。
3. 自定义加解密若密钥硬编码或与机器绑定方式简单，任何本地进程/恶意软件读取该文件即可离线复现，进而盗取 Minecraft 正版账号（refreshToken 可长期换 accessToken）。

**修复建议**：使用 OS 级凭据库保存 refreshToken；磁盘加密密钥绑定 OS 凭据；支持一键登出清除。

---

### H-5 【高】本地 HTTP API（`127.0.0.1:34254`）鉴权不明

**证据**：
```
本地监听: 127.0.0.1:34254   localIP = "127.0.0.1"   http://127.0.0.1:
路由:
  GET  /api/favorites、/export、/check ; POST /api/favorites/create|rename|delete|add|remove|note|import
  POST /api/crash/analyze ; GET /api/crash/logs ; GET /api/crash/log-content ; POST /api/crash/export
  GET  /api/launch/session-status ; POST /api/launch ; /api/launch/cancel ; /api/launch/check ; /api/launch/args-preview
  GET  /api/msauth/... ; POST /api/msauth/device-code|poll|refresh
  GET  /api/authlib-injector/info|download
  GET  /api/version/select-folder ; /api/install ; /api/check-version-name ; /api/install-cancel
  GET  /api/system/memory ; /api/system/memory-info ; /api/status
  POST /api/jvm/preheat ; /api/jvm/generate-cds ; /api/jvm/optimize-args ; /api/cleanup
  GET  /api/debug/versions        ← 调试接口默认存在
```

**问题**：
1. 存在本地 HTTP 服务（`127.0.0.1:34254`），暴露**安装/启动/清理/内存优化/账号刷新/崩溃日志导出**等敏感操作。
2. **未见任何鉴权头 / token 校验字符串**（如 Authorization 校验、随机端口+token 机制）。若仅有 CORS/Origin 限制，任何本机程序（含浏览器恶意页面经 DNS rebinding 或本机其他恶意软件）都可调用 `POST /api/launch`（拉起游戏进程）、`/api/cleanup`（删缓存）、`/api/crash/export`（导出日志含环境与路径信息）。
3. `/api/debug/versions` 调试接口在生产构建中仍然存在。

**修复建议**：本次随机端口 + 启动时生成的随机 Bearer token，所有请求强制校验；生产构建禁用 `/api/debug/*`；对 `Host`/`Origin` 强校验。

---

### H-6 【高】AI 模块支持自定义 endpoint → SSRF + API Key 外发

**证据**：
```
命令: ai_chat ; 字段: provider / apiKey / endpoint / apiFormat / messages / maxTokens / timeout / custom
"供应商缺少接口地址" "未配置 API Key" "未选择模型" "AI 返回非 JSON"
内置: https://api.anthropic.com/v1/messages (anthropic-version 2023-06-01)
      https://generativelanguage.googleapis.com/v1beta/models/:generateContent?key=
      /chat/completions  (openai 兼容)
"Bearer "  /  "key="        src/ai.rs
```
**问题**：
1. `apiFormat: custom` 允许**用户/前端指定任意 endpoint**，客户端会携带 `apiKey` 直接请求该地址。
2. 若前端页面被 XSS 或 IPC 被诱导调用，可把用户已有的 API Key 发往攻击者服务器（key 泄露），或利用客户端发起 **SSRF**（内网探测、访问云元数据 `169.254.169.254`——字符串中未见针对内网地址/元数据地址的拦截）。
3. 请求日志 `[api_proxy]` 表明存在代理转发层，进一步扩大外发面。

**修复建议**：自定义 endpoint 需白名单+内网地址黑名单（RFC1918、127.0.0.0/8、169.254.0.0/16、::1）；API Key 仅保存于系统凭据库，回填时不回显。

---

### H-7 【高】下载镜像可被任意替换，且缺失完整性校验

**证据**：
```
下载源集合: bmclapi2.bangbang93.com / maven.fabricmc.net / maven.minecraftforge.net /
           maven.neoforged.net / piston-meta.mojang.com / resources.download.minecraft.net /
           api.curseforge.com / api.modrinth.com / mod.mcimirror.top / optifine.net
镜像切换: "切换镜像" "源速度过慢" "所有下载源均失败" "低速检测" "回退单流"
断点续传: content-range / Range bytes=0-0 / 服务器不支持 Range / NO_RANGE_SOURCE
校验: assets 有 sha1；"分块合并后大小不匹配" "文件过小" "文件损坏"
```
**问题**：
1. 存在**镜像自动切换**逻辑，源列表以 HTTP 字符串硬编码，部分镜像域名非官方（`mod.mcimirror.top`、`bmclapi2` 为第三方）。
2. 资源校验以 **sha1**（`resources.download.minecraft.net` 官方即 sha1）与**大小**为主；`[fallback] 文件不完整 size= != expect` 说明部分场景仅比对大小。
3. `mod.mcimirror.top`（第三方 Modrinth 镜像）等未签名源被自动选用时，下载的 jar/mod 可被替换 —— 结合"自动切换镜像"可能被诱导切换到攻击者源。

**修复建议**：优先官方源；第三方镜像必须校验官方 sha1/sha256；禁止自动切换到未校验的镜像；对 Mod 下载强制校验官方哈希。

---

## 2. 中危发现（Medium）

### M-1 硬化不足的 JVM 启动参数（削弱了部分 Java 安全缓解）
```
-XX:-UseAdaptiveSizePolicy -XX:-OmitStackTraceInFastThrow
-Djdk.lang.Process.allowAmbiguousCommands=true      ← 允许含糊命令执行（削弱 ProcessBuilder 校验）
-Dfml.ignoreInvalidMinecraftCertificates=True       ← 忽略无效证书
-Dfml.ignorePatchDiscrepancies=True                 ← 忽略补丁差异
-Dlog4j2.formatMsgNoLookups=true                    ← Log4Shell 缓解（正面）
```
`allowAmbiguousCommands=true` 与 `ignoreInvalidMinecraftCertificates=True` 会降低 Java 侧安全性，可能被恶意 Mod 利用。CDS 生成使用 `-Xshare:dump`。

### M-2 HTTP 客户端 UA 硬编码与代理注入
```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
--proxy-server=http:// / --proxy-server=socks5://   ← WebView2 启动参数注入代理
```
WebView 可被注入 `--proxy-server` 参数（`proxyUrl`），若代理可被前端/配置控制且无校验，可导致全部 WebView 流量被劫持。

### M-3 外置登录（authlib-injector）与赞助模块
```
"第三方登录服务器必须使用 HTTPS 协议"   ← 正面：强制 HTTPS
"仅支持 HTTPS 协议的认证服务器"        ← 正面
orderId / password / "出于安全考虑"     src/api/sponsor.rs
```
authlib 已强制 HTTPS（好），但 `sponsor.rs` 处理 `orderId`/`password` 字段，需确认密码不经不安全通道或日志泄露（当前字符串无法确认，建议人工复核）。

### M-4 端口扫描能力
```
Tauri 命令: redstone_scan_port ; 命令前有 redstone_servers
```
客户端内置端口扫描能力，可被滥用于内网探测（若配合 H-6 本地 API 无鉴权，风险叠加）。

### M-5 崩溃日志导出包含敏感环境信息
```
导出内容包含: 数据目录 / JAVA_DIR / Java路径 / JAVA_HOME / 环境变量 /
             版本 ID / 退出码 / 最近 N 行游戏日志 / crash-report
文件名: VersePC_Log_... ; crash.log ; launch-fail-*.json
```
日志导出可能包含路径、用户名、JVM 参数等，若用户转发给他人或上传，存在信息泄露。

### M-6 硬编码第三方 API Key
```
CurseForge API Key: $2a$10$bL4bIL5pUWqfcO7KQtnMReakwtfHbNKh6v1uTpKlzhwoueEJQnPnm
API 域: https://api.curseforge.com/v1  头: x-api-key
```
CurseForge API Key（bcrypt 形式）**硬编码于二进制**，任何人可提取并冒用配额（可导致该 key 被官方封禁，进而使所有用户 CurseForge 功能失效）。

### M-7 CurseForge/Modrinth/整合包处理
```
modpack 导入: 识别格式 -> 解压 -> "路径越界" 检查(正面) -> 写文件
支持: curseforge / mrpack_native / theseus_adapter
"无法打开 ZIP" "读取 zip 项失败" "写出失败"
```
已见 `路径越界` 检查（ZipSlip 防护，正面），但整合包（用户可从任意来源导入）解压仍需确认对所有条目做规范化路径校验。

### M-8 TTS / WebSocket
```
tts_speak / voice ; zh-CN-XiaoxiaoNeural ; wss ; Path: turn.end
"WebSocket 接收错误" "WebSocket 连接失败" "构建握手请求失败"
```
TTS 使用 WebSocket；需确认 wss 证书校验与消息来源。

---

## 3. 值得肯定的安全设计（Positive）

| 项 | 证据 |
|---|---|
| 使用 rustls + ring，启用证书校验 | `rustls-0.23.42`、`webpki`、`verify_cert.rs` |
| authlib 外置登录强制 HTTPS | "第三方登录服务器必须使用 HTTPS 协议" |
| 整合包解压做路径越界检查 | "路径越界" |
| 下载做 sha1/sha256 + 大小校验 | `sha256`/`sha1` 字段、`文件损坏`/`大小不匹配` 提示 |
| 插件包做 sha256 校验 | `plugin_download_install ... sha256` |
| 二进制开启现代缓解 | PIE(ELF)、`DYNAMIC_BASE`+`NX_COMPAT`+`HIGH_ENTROPY_VA`(PE)、`BIND_NOW`(ELF) |
| 皮肤上传限制 | "限制每分钟只能更换一次皮肤" |
| 日志分析含"出于安全考虑"提示 | `src/api/sponsor.rs` 相关串 |

---

## 4. 风险总表

| ID | 风险 | 等级 | 影响面 | 可被远程触发 |
|---|---|---|---|---|
| H-1 | 未签名自动更新 + 可劫持代理源 | 严重 | 全平台客户端 | 是 |
| H-2 | 插件 `plugin_process_exec` 任意执行 + 市场无签名 | 严重 | Windows 尤甚 | 是 |
| H-3 | FRP 节点/房间明文接口 + frpc 无签名 + UPnP | 高 | 联机用户 | 是 |
| H-4 | refreshToken/账号明文落盘，无 OS 凭据库 | 高 | 登录用户 | 本地 |
| H-5 | 本地 HTTP API(34254) 鉴权不明 + debug 接口残留 | 高 | 所有用户 | 本地/浏览器 |
| H-6 | AI 自定义 endpoint → SSRF + Key 外发 | 高 | 使用 AI 用户 | 是(经前端) |
| H-7 | 下载镜像可切换且校验不足 | 高 | 所有用户 | 是 |
| M-1 | JVM 参数削弱安全 | 中 | 游戏进程 | 间接 |
| M-2 | WebView 代理注入 | 中 | 所有用户 | 配置可控 |
| M-4 | 内置端口扫描 | 中 | 内网 | 本地 |
| M-5 | 崩溃日志含敏感信息 | 中 | 转发用户 | 否 |
| M-6 | CurseForge Key 硬编码 | 中 | 功能可用性 | 否 |
| M-7 | 整合包解压 | 中 | 导入用户 | 是 |
| M-8 | TTS WebSocket | 中 | TTS 用户 | 是 |

---

## 5. 关键 IOC / 外部依赖清单

**自有后端 / 接口域**
```
www.verselauncher.cn/api/servers.json
lytapi.asia  (api.php, rooma.php, frplist58.txt)
hongshi.site (api/download/windowshongshi.exe, newserver.json)
enderlink 相关 (打洞/联机)
```

**更新 / 插件 / 内核分发（重点）**
```
raw.githubusercontent.com/doujie081231/VersePc2/main/update.json
ghfast.top / ghproxy.net / gh-proxy.com / mirror.ghproxy.com  (GitHub 代理)
gitee.com/doujie081231/verseplugin/raw/master/index.json      (插件市场)
gitee.com/lyt590/enderlinkupdate/releases/download/frp/frp.zip (frpc)
github.com/burningtnt/Terracotta  (陶瓦联机内核)
gitee.com/burningtnt/Terracotta ; cnb.cool/HMCL-Terracotta ; cdn.jsdelivr.net/gh/burningtnt/Terracotta
terracotta.glavo.site/nodes ; etnode.zkitefly.eu.org/node1|node2
```

**官方来源（相对可信）**
```
piston-meta.mojang.com / launchermeta.mojang.com / launcher.mojang.com
resources.download.minecraft.net / libraries.minecraft.net
api.minecraftservices.com / user.auth.xboxlive.com / xsts.auth.xboxlive.com
api.curseforge.com / api.modrinth.com / api.minecraftservices.com
meta.fabricmc.net / maven.fabricmc.net / maven.minecraftforge.net / maven.neoforged.net
authlib-injector.yushi.moe
```

**镜像（第三方，需谨慎）**
```
bmclapi2.bangbang93.com / mod.mcimirror.top / mirrors.ustc.edu.cn/adoptium
api.anthropic.com / generativelanguage.googleapis.com   (AI)
```

**CDN / 头像**
```
mc-heads.net / crafatar.com / minotar.net / visage.surgeplay.com
favicon.yandex.net / icons.duckduckgo.com / www.google.com/s2/favicons / t0.gstatic.com
```

**硬编码密钥**
```
CurseForge API Key: $2a$10$bL4bIL5pUWqfcO7KQtnMReakwtfHbNKh6v1uTpKlzhwoueEJQnPnm
```

---

## 6. 结论与优先级修复建议

**总体结论**：VersePC2 是一个功能完整的 Tauri Minecraft 启动器，具备**明确的高风险面**——核心问题集中在"**远程代码/二进制下发链路缺少签名校验**"（更新器、插件、frpc）与"**凭据与本地接口保护不足**"。攻击者若控制任意一个分发节点（个人仓库、GitHub 代理域、Gitee 插件仓库、lytapi 节点接口），即可对全量用户实施供应链攻击。**当前不适于在无隔离的环境中用于敏感账号登录或长期运行。**

> 说明：联机内核 hongshi 已核实为公开第三方项目，非风险项（见 L-1），本结论未将其计入。

**修复优先级（P0 → P2）**：
1. **P0**：更新包签名校验（H-1）；插件包签名 + `native:exec` 强确认 + 沙箱（H-2）。
2. **P0**：本地 HTTP API 引入随机端口 + 随机 Bearer token 强制鉴权，移除 `/api/debug/*`（H-5）。
3. **P1**：refreshToken 迁移至 OS 凭据库（H-4）；AI 自定义 endpoint 加内网黑名单（H-6）；FRP 节点接口 HTTPS+签名、frpc 签名、默认关 UPnP（H-3）。
4. **P1**：下载镜像白名单 + 官方哈希强校验，禁止自动切换到未校验镜像（H-7）；轮换并移除硬编码 CurseForge Key（M-6）。
5. **P2**：复核 JVM 参数与 WebView 代理注入（M-1、M-2）；端口扫描能力加使用告知；崩溃日志导出脱敏（M-5）。

---

## 7. 低危提示 / 依赖信任（Low / Informational）

### L-1 hongshi 联机内核为公开第三方项目（原 H-3，已撤销）

**核查结论**：`hongshi` 即 **Redstone Online2（红石联机2）**，是一个公开的通用"本地游戏端口中转"项目：

| 项 | 内容 |
|---|---|
| 官网 | `https://hongshi.site`（含下载页、服务端页、**公开 API 文档**） |
| 开源仓库 | `https://github.com/hongshionline/hongshi2`（真实存在，Rust，topics: minecraft / nat-traversal / relay-server / tcp-tunnel / tokio） |
| 组件 | `hongshic`（客户端内核）/ `hongshis`（中继服务端）/ `hongshi`（GUI 外壳） |
| 公开节点 | `nj.hongshi.site` / `cd.hongshi.site` / `gz.hongshi.site`（南京/成都/广州） |
| 公开接口 | `GET /api/download/{kind}?platform=&arch=`、`GET /api/server/list` |
| 集成方式 | VersePC2 按官方公开 API 正常集成（`hongshi.site/api/download/windowshongshi.exe` 等） |

**判定**：属**正常第三方业务依赖**，非恶意通道，**不作为风险项**。

**仅保留为提示（非漏洞）**：
- hongshi 官方文档自述 **"licence is not settled yet（许可证未定），仓库暂视为 all rights reserved"**；
- 官方**未提供二进制签名/哈希**，客户端也无本地校验 → 属"**可信但不可验证**"的依赖信任问题；
- 官方明示内核输出 `endpoint=` 为唯一稳定契约、节点全在国内。建议集成方在 UI 标注内核来源，或在有能力时对下载产物做本地哈希记录。

**性质**：Informational（依赖信任），非安全漏洞。

---

## 附录：提取产物

| 文件 | 说明 |
|---|---|
| `VersePC2.exe.urls.txt` | Windows 端全部 URL（153 条） |
| `VersePC2-linux.urls.txt` | Linux 端全部 URL（137 条） |
| `VersePC2.exe.modules.txt` | Windows 端全部模块路径（644 条，含依赖） |
| `VersePC2-linux.modules.txt` | Linux 端全部模块路径（712 条，含依赖） |
| `VersePC2.exe.own_modules.txt` | Windows 端**项目自有**模块（89 条） |
| `VersePC2-linux.own_modules.txt` | Linux 端**项目自有**模块（85 条） |
| `VersePC2-安全审查报告.md` | 本报告 |

> 说明：本报告基于静态逆向（字符串、模块路径、命令表、网络端点）。变量名与精确控制流因二进制 stripped 无法完全还原；标注"需人工复核"的条目建议结合动态调试（Frida / 过程监控 / 抓包）确认。
