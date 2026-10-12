# VersePC2 远程端安全审查报告

**审查对象**：VersePC2 远程端（更新分发、插件市场、联机节点、自有服务端 API、第三方镜像）
**审查方式**：**源码白盒审计**（公开仓库 `doujie081231/VersePc2` 全量克隆）+ 只读接口实测 + 构建产物与发布链路核查
**报告日期**：2026-10-11
**前置产物**：客户端审查已定格（H-1~H-7 / M-1~M-8 / L-1），本报告承接其"移交远程端"的 P0/P1 项，并给出白盒级结论与修正
**总体风险等级**：**严重** —— 存在**多条可闭合的远程代码执行链**，其中更新链路的信任根已被证明在现实中被非预期主体持有

---

## 0. 执行摘要

本次审查取得的**最关键突破**是拿到了 VersePC2 的**完整公开源码**（914 个文件），使所有远程端结论都从"黑盒推断"升级为"源码级确证"。同时通过实测发现了客户端报告未能覆盖的多个攻击面。

### 0.1 五条首要结论

| # | 结论 | 等级 | 性质 |
|---|---|---|---|
| **R-0** | **全局关闭 TLS 证书校验**（5 处，覆盖下载器/插件索引/AI 三大模块）→ HTTPS 完全不提供完整性保证 | **严重** | 白盒确证 + 二进制佐证 |
| **R-1** | **更新链路供应链 RCE**：4 源竞速取第一个响应 + sha256 可选（缺失即放行）+ 关窗自动替换执行 | **严重** | 白盒确证 |
| **R-2** | **代理域名现实劫持**：`gh-proxy.com`/`ghproxy.link` 返回自签 localhost 证书，签发于审查前一日；正常客户端拒绝，VersePC2 因 R-0 接受 | **严重** | 独立实测（主会话复核） |
| **R-3** | **Windows 包全部人工上传、无构建 provenance**：用户量最大的平台无法证明 exe 与 tag 源码一致 | **严重** | API 实测 |
| **R-4** | **插件市场 sha256 与包同源**：改包同时改哈希即可，且 `index_url` 运行时可指定任意地址 → 插件 RCE | **严重** | 白盒 + 实测 |

### 0.2 与客户端报告的差异（修正项）

| 客户端报告条目 | 本报告修正 |
|---|---|
| H-1「自动更新无签名校验，源经第三方代理」 | **升级**：不仅无签名，且 sha256 校验**可被清单自行关闭**；4 源**竞速抢答**；**关闭程序即自动执行**；且硬编码 4 源中 **3 个当前已失效/被劫持** |
| H-3「FRP 节点明文接口 + UPnP」 | **拆分修正**：UPnP **不由联机流程自动触发**（子智能体核实），而是暴露在 `/api/lan/upnp-*` 本地路由（需 IPC 能力）；FRP 部分**结论成立且加重**——`decryptedToken` 不是加密而是**可公开复刻的字符置换** |
| H-5「本地 HTTP API(34254) 无鉴权」 | **实质性修正**：`api/` 目录**不是 HTTP 服务**而是 Tauri IPC；真正的本地 HTTP 服务是 `server_host_daemon.rs`，绑定 **`127.0.0.1:27310`**，含 `POST /api/host/command` 等 11 个**无鉴权**路由 |
| H-7「下载镜像可切换、校验不足」 | **维持**，并补充：`danger_accept_invalid_certs` 使镜像切换的**信任假设完全崩塌** |

### 0.3 新增发现（客户端报告未覆盖）

1. **剪贴板命令注入**（`private_server.rs`）—— 唯一**不依赖供应链投毒、可直接命令执行**的本地漏洞，已无害实证
2. **EasyTier/陶瓦内核**：6 源下载 `terracotta.exe`，唯一校验是"文件 >10KB"
3. **本地开服守护进程 27310** 无鉴权 HTTP API（含任意控制台命令注入）
4. **5 处** `danger_accept_invalid_certs`（此前仅知 1 处）
5. `redstone_online.rs`（对接 hongshi.site）—— 与 enderlink 平行的**第二条远程链**，同样无鉴权无校验

---

## 1. 审查方法与边界

### 1.1 数据来源

| 类别 | 具体方式 |
|---|---|
| **白盒源码** | `git clone --depth 1 https://github.com/doujie081231/VersePc2.git`（914 文件）；GitHub Contents API（base64）用于定点取文件 |
| 接口实测 | 只读 `GET`/`HEAD`，单线程、间隔 ≥1s；**未对任何目标做写操作/爆破/上传/DoS** |
| 构建产物 | Gitee/GitHub release 下载 + `sha256sum` 比对；GitHub Release API `digest`/`uploader` 字段 |
| 证书/DNS | `openssl s_client` + `socket.gethostbyname_ex`；RDAP（部分端点不可达，已标注） |
| 代理域名 | 直接 TLS 握手 + HTTP 行为实测（主会话独立复核） |

### 1.2 工具集与限速说明

`curl` / `python3` / `git` / `openssl` / `nuclei` / `nmap` / `subfinder` / `httpx` / `dnsx` / `ffuf`。
`whois`、`dig`、`jq` **未安装**；`rdap.org` 端点证书 SNI 不匹配、`rdap.cnnic.cn` 不可解析 → 部分域名注册信息**未取得**。

### 1.3 明确的不可测项（不做事后推断）

| 项 | 原因 | 影响 |
|---|---|---|
| 4 个 GitHub 代理镜像的**下载哈希** | 本机出口网络不可达（`ghfast.top`/`ghproxy.net` 连接失败，`gh-proxy.com`/`ghproxy.link` 返回 403） | **"镜像投毒是否已发生"未能证明也未能证伪** |
| Forge 官方 vs 镜像 `maven-metadata.xml` 比对 | 两端均不可达 | 未验证 |
| GitHub/Gitee **2FA 状态**、**collaborators**、**分支保护** | API 401（需认证）；`security_and_analysis` 匿名不返回 | 无法判定 |
| `lytapi.asia` 等**域名注册主体/时长** | RDAP 端点全部失败 | MITM 现实难度无法量化 |

---

## 2. 严重发现（Critical）

### 【R-0】全局关闭 TLS 证书校验 — 全仓库 5 处，覆盖 3 大模块

**白盒证据**：全仓库检索 `danger_accept_invalid_certs`，命中 5 处：

| 文件 | 行 | 影响范围 |
|---|---|---|
| `src-tauri/src/modloaders/shared.rs` | 22 | **插件市场索引**（`plugins.rs`）、服务端托管（`server_host.rs`） |
| `src-tauri/src/download/single.rs` | 30, 58, 115 | **整个资源 / Mod / 整合包 / JDK 下载器** |
| `src-tauri/src/ai.rs` | 273 | **AI 接口**（承载用户自带 API Key 外发） |

```rust
// modloaders/shared.rs:15-26 —— 共享 HTTP 客户端
pub fn shared_client() -> &'static reqwest::Client {
    HTTP_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .user_agent("VersePC/1.0")
            .danger_accept_invalid_certs(true) // 跳过证书验证：部分镜像证书链不完整
            .build()
            .expect("failed to build reqwest client")
    })
}
```

**发行二进制佐证**：Linux 样本 `strings` 命中 rustls 的风险验证器符号
`NoVerifier` / `IgnoreHostname` / `Enforce|Ignore`（`dangerous_configuration` API 编译产物特征）
→ **证明该配置已编译进发行版**，非源码死代码。

**安全后果**：HTTPS 在本项目中**不提供任何完整性或身份保证**。攻击者无需投毒代理、无需抢注域名、无需劫持 DNS —— 任何链路中间人（公共 WiFi、运营商、透明代理、企业网关）均可伪造任意 HTTPS 响应，包括更新清单、插件索引、AI 请求。

**实测对比证明（主会话独立复核）** — 同一请求、两种客户端行为：

```
# 正常客户端（开启证书校验）
$ curl -sS -o /dev/null -w "http=%{http_code} verify=%{ssl_verify_result}" \
    "https://gh-proxy.com/https://raw.githubusercontent.com/doujie081231/VersePc2/main/update.json"
http=000 verify=1          ← TLS 握手失败，证书校验错误，正常软件会拒绝

# VersePC2 的配置（danger_accept_invalid_certs=true）
$ curl -sS -k -o /dev/null -w "http=%{http_code}" \
    "https://gh-proxy.com/https://raw.githubusercontent.com/doujie081231/VersePc2/main/update.json"
http=403                   ← TLS 握手成功，拿到了 HTTP 响应
```

→ **R-0 让 VersePC2 接受了正常客户端会拒绝的劫持证书。**

---

### 【R-1】更新分发链路 = 完整供应链 RCE

**文件**：`src-tauri/src/updater.rs`

#### (a) 4 源并发，"谁先应答谁说了算"（官方源还排最后）

```rust
// updater.rs:29-34
const UPDATE_JSON_SOURCES: &[&str] = &[
    "https://ghfast.top/https://raw.githubusercontent.com/doujie081231/VersePc2/main/update.json",
    "https://ghproxy.net/https://raw.githubusercontent.com/doujie081231/VersePc2/main/update.json",
    "https://gh-proxy.com/https://raw.githubusercontent.com/doujie081231/VersePc2/main/update.json",
    "https://raw.githubusercontent.com/doujie081231/VersePc2/main/update.json",  // ← 官方源在第 4 位
];
```

```rust
// updater.rs:312-331  join_all 后按声明顺序遍历，取第一个 Ok(Some)
let results = futures_util::future::join_all(tasks).await;
for r in results {
    if let Ok(Some(release)) = r { return Ok(release); }   // 无共识、无交叉校验
}
```

> **精确细节**：遍历是**按声明顺序**而非完成顺序，所以严格说是"3 个镜像先被检查 + 组合上谁先成功"。由于前 3 个全为镜像，**任一镜像被控即优先于官方源被采纳**。

#### (b) sha256 为可选 —— 校验可被清单自行关闭

```rust
// updater.rs:284-288  清单解析：sha256 是 Option
sha256: f.get("sha256").and_then(|x| x.as_str()).map(String::from),
```

```rust
// updater.rs:173-201
fn verify_file(path: &Path, expected_size: u64, expected_sha: Option<&str>) -> bool {
    if !path.exists() { return false; }
    if let Ok(md) = fs::metadata(path) {
        if expected_size > 0 && md.len() != expected_size { return false; }
    }
    if let Some(sha) = expected_sha {          // ← 只有给了 sha256 才校验
        let mut hasher = Sha256::new();
        ...
        if !hex_lower(&hasher.finalize()).eq_ignore_ascii_case(sha) { return false; }
    }
    true                                       // ← expected_sha = None 时直落此处放行
}
```

**攻击者只需在下发的 `update.json` 中删除 `sha256` 字段**（并把 `size` 置 0 或设为实际值），校验即被完全旁路。

#### (c) 哈希与包同源，不构成信任锚

`sha256` 与 `url` **同源于同一份明文、无签名、可被投毒的 `update.json`**。改包同时改哈希即可通过校验。源码中**无公钥硬编码、无 Ed25519/RSA 验签逻辑**。

#### (d) 关闭程序即自动执行替换（无需二次确认）

```rust
// updater.rs:auto_install_on_close
pub fn auto_install_on_close(app: &tauri::AppHandle) -> bool {
    let Some(p) = pending_downloaded_path() else { return false; };
    if !p.exists() { return false; }
    if let Some(s) = UPDATE_STATE.lock().unwrap().as_ref() {
        write_pending_notice(&s.release.tag_ver, &s.release.body);
    }
    let _ = install_and_restart(app, &p);   // ← 用户正常退出即触发替换+重启
    true
}
```

#### (e) 安装落地（三平台）

- **Windows**：写 `_versepc_update.bat` → `cmd /c start /min` → 轮询/`taskkill /f` 强杀 → `move /y` 覆盖 exe → `start` 拉起
- **Linux**：写 `_versepc_update.sh` → `cp "$n" "$c" && chmod +x` → `nohup` 拉起
- **macOS**：写 `_versepc_update.sh` → `unzip` → `rm -rf` 旧 `.app` → `mv` 新 `.app` → `open`

#### (f) 实测 `update.json`：三平台版本漂移 4 个版本

```json
{ "version": "1.5.5",
  "files": {
    "win-x64":       { "url": ".../v1.5.5/VersePC2.exe",  "size": 73959936,
                       "sha256": "1b4e104f3516d5e6dd62d0c68700b818ab9ea631dc188b0b6e9fed940e04d58c" },
    "linux-x86_64":  { "url": ".../v1.5.1/VersePC2-linux-x86_64", ... },        // ← 仍指 v1.5.1
    "macos-x86_64":  { "url": ".../v1.5.1/VersePC2-macos-x86_64.zip", ... },    // ← 仍指 v1.5.1
    "macos-aarch64": { "url": ".../v1.5.1/VersePC2-macos-aarch64.zip", ... }    // ← 仍指 v1.5.1
  } }
```

**交叉验证（GitHub Release API `digest` 基准）**：

| 平台 | update.json 声明 sha256 | v1.5.5 真实 digest | v1.5.1 真实 digest | 判定 |
|---|---|---|---|---|
| win-x64 | `1b4e104f…04d58c` | `1b4e104f…04d58c` | `f48a246c…b39b6cf` | ✅ 与 v1.5.5 一致 |
| linux-x86_64 | `aaadd31c…328503` | `2772fd17…f62c2d` | `aaadd31c…328503` | ❌ **等于 v1.5.1 的值** |
| macos-x86_64 | `50d684e9…4c8580` | `29f9cf70…d06600c` | `50d684e9…4c8580` | ❌ **等于 v1.5.1 的值** |
| macos-aarch64 | `8914a2ec…8fd5a9` | `3bd45b5a…3e1b00` | `8914a2ec…8fd5a9` | ❌ **等于 v1.5.1 的值** |

→ **三平台 manifest 滞后 4 个版本**。非 Windows 用户被提示"已是最新"或升级后仍为旧版，**安全修复无法抵达**。这与 `releaseNotes` 自述的"版本号与发布版本不同步，导致升级器误判并反复提示更新"完全吻合。

---

### 【R-2】硬编码代理域名的现实劫持（独立实测）

**主会话亲自复核结果**（非子智能体转述）：

```
$ openssl s_client -connect gh-proxy.com:443 -servername gh-proxy.com | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
subject=O=redirect-cnzz
issuer=O=redirect-cnzz                                   ← 自签，无合法 CA
notBefore=Oct 10 11:09:51 2026 GMT                       ← 签发于审查前一日
notAfter= Oct  7 11:10:51 2036 GMT                       ← 有效期 10 年
X509v3 Subject Alternative Name:
    DNS:localhost, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1   ← 只覆盖 localhost

$ openssl s_client -connect ghproxy.link:443 -servername ghproxy.link | openssl x509 -noout -subject -issuer -dates
subject=O=redirect-cnzz   issuer=O=redirect-cnzz   notBefore=Oct 10 10:54:27 2026 GMT
```

**判定**：正常 CDN 会用合法 CA 为**自身域名**签发证书。这两个域名的特征（自签 + SAN 仅 localhost + 名字自述 "redirect" + 审查前一日签发 + 10 年有效期）是**典型中间人/域名接管特征**。

**当前状态**：`gh-proxy.com` → `45.67.223.32`（非 CDN 段），对 GitHub raw 请求返回 **403**；`ghproxy.link` → `141.193.154.50`，同样 403。

**全部 4 个更新源当前实测状态**：

| 源 | 状态 | 说明 |
|---|---|---|
| `ghfast.top` | ❌ 443 拒绝连接 | 不可用 |
| `ghproxy.net` | ❌ TLS 无响应 | 不可用 |
| `gh-proxy.com` | ⚠️ 403 + **自签 localhost 证书** | 被非预期主体持有 |
| `raw.githubusercontent.com` | ❌ 直连被重置 | 部分网络下不可用 |

→ **客户端硬编码 4 个源中，3 个当前无法正常提供更新清单**。这意味着攻击者只需让任一代理"恢复服务"（或在链路上占据该位置），即可独占响应，**无需与官方源竞争**。

---

### 【R-3】Windows 包全部人工上传 —— 无构建 provenance

**实测证据（GitHub Release API `uploader` 字段，主会话独立复核）**：

| 版本 | Linux / macOS 上传者 | **Windows `.exe` 上传者** | exe 下载量 |
|---|---|---|---|
| v1.5.5 | `github-actions[bot]` | **`doujie081231`（人工）** | 46 |
| v1.5.4 | `github-actions[bot]` | **`doujie081231`（人工）** | 639 |
| v1.5.1 | `github-actions[bot]` | **`doujie081231`（人工）** | 196 |

**含义**：用户量最大的 Windows 平台的每个 exe 都由**开发者本机手工上传**，完全绕过 CI。因此：

1. **无法用任何技术手段证明该 exe 与对应 tag 的源码一致**（无 SLSA provenance、无 attestation、无构建日志）；
2. 攻击者若控制开发者本机，**无需触碰 GitHub、Gitee 或任何镜像**即可投毒，且产物与正常发布**不可区分**；
3. 对比之下，CI 产出的 Linux/macOS 包**理论上可复现**——这一反差恰好说明 Windows 是人工程序中的薄弱环节。

**旁证**：`.github/workflows/windows-build.yml` 存在但**只产出 Actions artifact、从不进入 release**（注释亦自述"产物不进 release"）。且 CI 中 `sponsor-orders.json` 缺失时写入 base64 占位符 `eyJvcmRlcnMioltdfQ==`，与本地构建的编译期嵌入内容不同 → **先天缺少可复现的哈希基线**。

---

### 【R-4】插件市场：哈希与包同源 + 索引地址运行时可指定

**文件**：`src-tauri/src/plugins.rs`

```rust
// plugins.rs:13-14  默认索引（单个 Gitee 个人仓库）
const DEFAULT_INDEX_URL: &str =
    "https://gitee.com/doujie081231/verseplugin/raw/master/index.json";

// plugins.rs:276-281  index_url 是运行时参数 → 可指向任意地址
pub async fn market_index(index_url: &str) -> Value {
    let url = if index_url.trim().is_empty() { DEFAULT_INDEX_URL.to_string() }
              else { index_url.to_string() };
    ...
    match crate::modloaders::shared::fetch_json(&url).await {   // ← 走 R-0 的不校验证书 client
```

```rust
// plugins.rs:321-345
/// 注意：market 提供的是 sha256，而 download_with_mirror 的哈希参数是 sha1，
/// 因此下载阶段不传哈希（只做 size 校验），下载完成后用 sha256 独立校验。
pub async fn download_and_install(url: String, sha256: String, size: u64, expected_id: String) -> Value {
    let sha = if sha256.is_empty() { None } else { Some(sha256.as_str()) };
    let result = match crate::download::download_with_mirror(&url, &tmp, None, size_opt, "auto", 300, None).await {
        //                                                         ↑ sha1 传 None：下载阶段零哈希校验
        Ok(()) => {
            if let Some(expected_sha) = sha {
                match crate::utils::calculate_sha256(&tmp) {
                    Some(actual) if actual.eq_ignore_ascii_case(expected_sha) => {
                        install_from_zip(...).await
                    }
                    _ => json!({ "ok": false, "error": "插件包校验哈希值失败" }),
                }
            } else {
                install_from_zip(...).await          // ← sha256 为空：直接安装，零校验
            }
        }
    };
}
```

**实测证据（3/3 哈希与索引同源）**：

| 插件 | index.json 声明 sha256 | 实际下载计算 sha256 | 一致 |
|---|---|---|---|
| verse-server-host | `a4e5a5ca…109272` | `a4e5a5ca…109272` | ✅ |
| verse-frp-manager | `4DC945E5…10B35`（大写） | `4dc945e5…10b35` | ✅ |
| mc-map-preview | `F748F078…A1211C`（大写） | `f748f078…a1211c` | ✅ |

→ 哈希与 `downloadUrl` **同处一个文档、同一台服务器、同一次匿名 GET**，其中两个包与索引还在**同一仓库同一分支**。**改包同时改哈希即可绕过 —— "哈希校验"自证清白，不构成信任锚。**

**三重缺陷**：
1. `index_url` 前端可控 → 索引可被重定向；
2. `sha256` 由调用方传入，为空则**跳过校验直接安装**；
3. 下载阶段（`download_with_mirror` 的 `sha1` 参数）传 `None` → **零哈希校验**。

**注意 schema 风险**：index.json 中 2/3 的 sha256 为**大写**、1/3 小写；`update.json` 全小写。客户端若未做大小写归一化，校验行为将不可预期（`plugins.rs` 用了 `eq_ignore_ascii_case`，此处实现正确——但索引格式不统一本身是流程缺陷）。

---

### 【R-5】`plugin_process_exec`：本机任意程序执行

**文件**：`src-tauri/src/plugin_exec.rs`

```rust
#[tauri::command]
pub async fn plugin_process_exec(
    app: tauri::AppHandle, plugin_id: String, exe: String,
    args: Option<Vec<String>>, cwd: Option<String>,
    ini: Option<String>, config_name: Option<String>,
) -> Value {
    if !has_native_exec(&plugin_id) {
        return err(403, &format!("插件 {} 未声明 native:exec 权限", plugin_id));
    }
    ...
    let mut cmd = tokio::process::Command::new(&exe);   // ← exe 完全来自调用方
    cmd.args(&launch_args);                              // ← args / cwd 同样来自调用方
    if let Some(dir) = cwd { cmd.current_dir(dir); }
```

唯一门槛 `has_native_exec()` 读取的是**磁盘上插件目录内的 `plugin.json`**：

```rust
fn has_native_exec(id: &str) -> bool {
    let dir = plugins::plugin_dir(id);
    let Ok(content) = std::fs::read_to_string(dir.join("plugin.json")) else { return false; };
    ... m.get("permissions").and_then(|p| p.get("native"))
           .and_then(|a| a.as_array())
           .map(|arr| arr.iter().any(|v| v.as_str() == Some("exec")))
}
```

→ **授权判定依据是攻击者可随插件包一起投递的文件**。装上一个含 `{"permissions":{"native":["exec"]}}` 的插件，即获得任意 `exe` + 任意 `args` + 任意 `cwd` 的执行能力。

**正向细节**：`config_name` 做了目录穿越防护（拒绝 `/`、`\`、`..`），这部分实现正确。

---

## 3. 高危发现

### 【H-A】前端配置先天不安全：CSP 关闭 + 全局 Tauri + DevTools 开启

**文件**：`src-tauri/tauri.conf.json`

```json
"app": {
    "withGlobalTauri": true,             // window.__TAURI__ 全局暴露
    "windows": [{ "devtools": true, ... }],
    "security": { "csp": null }          // CSP 完全禁用
}
```

三者叠加：**WebView 内任何脚本都能无阻碍调用全部 81 个 IPC 命令**。经提取 `generate_handler!` 宏，注册命令共 **81 个**，其中敏感类 **21 个**：

```
updater_install_update / updater_download_update      ← 替换并重启自身
plugin_process_exec / plugin_process_stop            ← 任意程序执行
plugin_download_install                              ← 安装插件（→ 执行）
server_host_command / server_host_delete
private_server_update / private_server_delete
scene_renderer_download / saves::version_save_update ...
```

`updater_install_update` 可直接被前端调用 —— **不需要等用户关窗**，前端拿到包即可替换执行。

### 【H-B】本地开服守护进程：`127.0.0.1:27310` 零鉴权 HTTP API

**文件**：`src-tauri/src/server_host_daemon.rs`、`src-tauri/src/bin/verse-server-host.rs`

```rust
// bin/verse-server-host.rs:10  固定默认端口
let mut port: u16 = 27310;

// server_host_daemon.rs:163-175  11 个路由，绑定 loopback，无任何鉴权
let app = Router::new()
    .route("/api/host/list",    get(api_list))
    .route("/api/host/status",  post(api_status))
    .route("/api/host/create",  post(api_create))
    .route("/api/host/start",   post(api_start))
    .route("/api/host/stop",    post(api_stop))
    .route("/api/host/command", post(api_command))     // ← 任意控制台命令
    .route("/api/host/delete",  post(api_delete))      // ← 删除服务器实例
    .route("/api/host/sync",    post(api_sync))
    .route("/api/host/resolve", post(api_resolve))
    .route("/api/host/detect",  post(api_detect))
    .route("/api/host/stream",  get(api_stream))       // ← SSE 日志流
    .with_state(state);

let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
axum::serve(listener, app).await?;

// server_host_daemon.rs:115-117  cmd 原样透传
async fn api_command(State(st): State<AppState>, Json(body): Json<Value>) -> Json<Value> {
    Json(server_host::host_command(&st.sink, get_str(&body, "serverId"), get_str(&body, "cmd")).await)
}
```

**判定**：绑定 `127.0.0.1:27310` 意味着**任何本机进程 / 本机浏览器页面**都能直接调用，且**无 token、无 Origin 校验、无鉴权**。`POST /api/host/command` 把 `cmd` 原样交给 MC 服务端控制台 → 等价于对该服务进程的任意指令注入（`/op`、`/execute`、`/stop` 等）。

**暴露条件**：该守护进程是独立二进制 `verse-server-host`，由"本地开服"插件（`plugin_market_index` 中 `id = verse-server-host`）机制拉起。**安装开服插件后端口即常驻**。

### 【H-C】剪贴板命令注入 —— 不依赖供应链的直接命令执行（已无害实证）

**文件**：`src-tauri/src/private_server.rs:530-570`（`private_server_copy_address`）

```rust
#[cfg(target_os = "windows")]
{
    let safe = address.replace('\\', "\\\\").replace('"', "\\\"");
    let out = std::process::Command::new("powershell")
        .arg("-NoProfile").arg("-Command")
        .arg(format!("Set-Clipboard -Value \"{}\"", safe))     // 仅转义 \ 与 "
        .output();
}
#[cfg(any(target_os = "linux", target_os = "android"))]
{
    let safe = address.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!(
        "printf '%s' \"{}\" | (command -v wl-copy >/dev/null && wl-copy || ...)", safe);
    std::process::Command::new("sh").arg("-c").arg(&script).status()
}
```

**缺陷**：转义只处理 `\` 与 `"`（防引号闭合），**未处理命令替换 `$(...)` 与反引号** —— 而命令替换**不需要破坏引号闭合**即可执行。

**无害实证（主会话复刻其转义逻辑并执行，使用标记字符串）**：

```
输入:     $(echo INJECTED_MARKER)
转义后:   $(echo INJECTED_MARKER)              ← $ 与 ( ) 原样保留
生成 shell: printf '%s' "$(echo INJECTED_MARKER)" | cat
实际输出: INJECTED_MARKER                      ← 命令替换真实执行

输入:     `echo BACKTICK_MARKER`
实际输出: BACKTICK_MARKER                      ← 反引号同样执行
```

**可达性**：`address` 来自前端（私人服务器地址字段）。前端被注入 / 用户被诱导添加恶意地址即触发。**这是本次审查中唯一不依赖供应链投毒、可直接达成命令执行的漏洞。** Windows 分支同理（PowerShell 的 `$(...)`、`;` 未过滤）。

### 【H-D】联机链路：明文节点列表 + 可复刻的"加密" + 泄露他人房间

**文件**：`src-tauri/src/enderlink_online.rs`

```rust
const HALL_URL:   &str = "https://lytapi.asia/rooma.php";
const CREATE_URL: &str = "https://lytapi.asia/api.php";
const NODES_URL:  &str = "https://lytapi.asia/frplist58.txt";
```

**(a) `decryptedToken` 不是加密，是可公开复刻的字符置换**

```rust
// enderlink_online.rs:87-97
fn decrypt_token(enc: &str) -> String {
    let mut out = String::new();
    for ch in enc.chars() {
        let c = ch.to_ascii_lowercase();
        if c.is_ascii_lowercase() {
            let idx = c as u8 - b'a';
            out.push_str(&(21 + idx as u32).to_string());   // a→21, b→22, ... z→46
        }
    }
    out
}
```

→ **无密钥、无密码学强度**。任何人复刻这 25 行即可推导任意节点的真实 token（实测样例：`k6uGKdMeQy` → `314127312433253745`）。攻击者用正确明文 token 自建 frps，客户端会**正常握手成功**。token 最终**明文写入 `frpc-<pid>.toml`**。

**(b) 节点列表零完整性校验 + HTTP 明文同内容**

```rust
// parse_nodes: 只做 '#'/'['/']'/空白 文本切分，无 hash/签名/证书固定
```

**实测（子智能体，主会话采信）**：
```
$ curl -i http://lytapi.asia/frplist58.txt
HTTP/1.1 200 OK
Content-Length: 114
5#[美国洛杉矶-VMISS 216.40.87.51:15442 k6uGKdMeQy]
3#[日本东京-腾讯云 43.165.169.111:15442 k6uGKdMeQy]
```
→ **80 端口以明文返回与 HTTPS 逐字一致的节点列表**。MITM 无需任何 TLS 手段即可替换节点。

**(c) `api.php` 无鉴权 + 泄露他人房间信息 + CORS `*`**

```
$ curl -i "https://lytapi.asia/api.php"
HTTP/2 200
access-control-allow-origin: *
access-control-allow-methods: GET, POST, DELETE, OPTIONS
{"success":true,"data":{"rooms":[
  {"id":12466569,"remote_port":38134,"node_id":21,"room_name":"玩家的房间",
   "description":"SUNSETawa - 新的世界§r","server_addr":"139.155.96.224",
   "host_player":"玩家","full_room_code":"38134_21"} ...]}}

$ curl -H "Authorization: Bearer bogus-token-12345" "https://lytapi.asia/api.php"
http=200   ← 伪造凭据照样 200：根本没有校验
```

→ 泄露**节点公网 IP、可直连端口、房间连接码 `full_room_code`、玩家世界名、主机玩家名**；无分页/限流，**可未授权批量枚举**；CORS `*` 允许任意站点跨域读取。

**(d) frpc 下载：无签名 + 一次投毒长期有效**

```rust
// enderlink_online.rs:145-147
if exe.exists() { return Ok(()); }      // ← 存在即永不重下
// L169-183: tar -xf 解压后直接拉起，无哈希/签名/版本固定
```

第三方源：`https://gitee.com/lyt590/enderlinkupdate/releases/download/frp/frp.zip`（实测 HTTP 200，30,449,853 字节，内含 `frpc.exe` **与 `frps.exe`**）。

### 【H-E】EasyTier / 陶瓦内核：6 源下载，唯一校验是"文件 >10KB"

**文件**：`src-tauri/src/easytier/process.rs:194-260`

```rust
let exe_path = tc_dir.join("terracotta.exe");
if exe_path.exists() { return Ok(()); }          // ← 存在即永不重下

let urls = [
    "https://gitee.com/burningtnt/Terracotta/releases/download/v...",      // 第三方
    "https://cnb.cool/HMCL-Terracotta/Terracotta/-/releases/download/v...",// 第三方
    "https://cdn.jsdelivr.net/gh/burningtnt/Terracotta@v...",              // 第三方 CDN
    "https://ghfast.top/https://github.com/...",                           // 第三方代理
    "https://mirror.ghproxy.com/https://github.com/...",                   // 第三方代理
    "https://github.com/burningtnt/Terracotta/releases/download/v...",
];
...
Ok(b) if b.len() >= 10000 => { bytes = Some(b.to_vec()); break; }   // ← 唯一"校验"：>10KB
...
let mut cmd = tokio::process::Command::new(&bin_path);              // 下载后直接执行
```

→ 6 个源中 5 个为第三方，**无哈希、无签名**，门槛仅"文件大于 10KB"。**客户端报告完全未覆盖此模块。**

### 【H-F】第二条远程链：`redstone_online.rs`（对接 hongshi.site）

与 enderlink 平行、同样无鉴权无校验：

- `hongshi.site/api/download/client?platform=&arch=` → HEAD 200，`content-length: 851728`，**无 `Content-MD5`/`Digest`/`Signature` 头**
- 下载后唯一校验是 `bytes.len() < 10000` → **≥10KB 任意二进制即落盘执行**
- 全文件检索 `verify|sign|hash|sha|md5|hmac` **零命中**
- `hongshi.site/api/server/list` 返回节点映射，无签名可替换

---

## 4. 中危与说明项

### 【M-A】UPnP 控制面暴露（修正客户端报告 H-3）

**澄清两个子智能体的表述分歧**：`private_server.rs` / `server_host.rs` / `enderlink_online.rs` 中确无 UPnP 引用；但 UPnP **确实存在**于 `network/upnp.rs` + `api/lan.rs`：

```
POST /api/lan/upnp-map       添加 UPnP 端口映射（SSDP + SOAP AddPortMapping）
POST /api/lan/upnp-unmap     删除映射
GET  /api/lan/upnp-status    当前映射列表
GET  /api/lan/upnp-diagnose  诊断
POST /api/lan/remote-create  创建远程房间（含 UPnP + 公网 IP）
```

`internalPort` 缺省 25565、`NewLeaseDuration=0`（**永久映射**）、无二次确认、无端口白名单。

**修正结论**：UPnP **不由联机流程自动触发**（原 H-3 指控过重）；**但控制面经 Tauri IPC 暴露**，一旦获得 webview JS 执行能力（见 H-A：CSP 关闭 + 全局 Tauri）即可静默改写路由器映射。

### 【M-B】镜像改写与竞速取源

```rust
// download/mirror.rs:124-147  官方前缀 → 第三方镜像的字符串改写
pub fn to_mirror_url(original: &str) -> Option<String> {
    ... original.starts_with("https://maven.minecraftforge.net/") =>
        original.replace("https://maven.minecraftforge.net/", "https://bmclapi2.bangbang93.com/maven/") ...
}

// shared.rs  双源竞速："并发请求所有候选 URL，谁先成功返回就用谁"
while let Some(result) = join_set.join_next().await {
    if let Ok(Ok(v)) = result { return Ok(v); }
}
```

「最快的应答者获胜」+ R-0（关闭证书校验）→ 攻击者抢先应答即可稳定赢得竞速；镜像改写后完整性完全取决于第三方镜像。

**镜像实测可信性（截至审查日）**：

| 镜像 | 结论 | 硬证据 |
|---|---|---|
| **BMCLAPI** | ✅ 当前可信 | `guava-21.0.jar` sha1 `3a3d111be1be1b745edfa7d91678a12d7ed38709`，与 Maven Central 官方 `.sha1` sidecar **精确一致** |
| **Modrinth 镜像** | ✅ 当前可信（API 层） | `/modrinth/v2/project/sodium` 返回真实上游数据（`id=AANobbMI, org=CaffeineMC`） |
| **Forge Maven 镜像** | ❌ **不可用** | `raw.gitmirror.com` **NXDOMAIN**（域名已无法解析，客户端内配置失效） |

**架构观察**：BMCLAPI **非自建存储** —— 实测 302 链为 `bmclapi2 → mirrors.cernet.edu.cn → cmcc.mirrors.ustc.edu.cn`，**信任链实际延伸至 CERNET 与 USTC**，信任面被放大。

### 【M-C】AI 模块：TLS 无校验 + 自定义 endpoint

`ai.rs:273` 亦使用 `danger_accept_invalid_certs(true)`。结合客户端报告 H-6（`apiFormat: custom` 允许任意 endpoint、无内网地址黑名单），用户自带的 **API Key 在链路上可被中间人取得**（既因 endpoint 可控，也因证书不校验）。

### 【M-D】发布流程与仓库治理（实测，多为正向）

| 项 | 实测结果 | 评价 |
|---|---|---|
| 26 个 release 发布者 | **全部同一作者 `doujie081231`（id 252411941）** | 无异常账号 ✅ |
| 贡献者 | `contributors` API **全仓库仅 1 位**（566 次提交） | 无第三方提交 ✅ |
| `update.json` 提交历史 | **18 条全部作者 doujie081231**，无伪造邮箱 | 无第三方改动 ✅ |
| commit 签名 | **全部 `verification.verified=false`（unsigned）** | ⚠️ 无 GPG 签名 |
| Workflow 供应链 | **无** `pull_request_target`/`workflow_run`/第三方 action；权限最小化（`windows-build.yml` 仅 `contents: read`） | ✅ 良好实践 |
| 2FA / collaborators / 分支保护 | **API 401，无法判定** | ⚠️ 不可测 |

**历史风险点**：commit `0de11e25f54e`（2026-10-07 03:10）曾将**自建服务器 `verselauncher.cn` 设为 update.json 与安装包的首选源**；同日 05:20 的 `dee03ac399c2` **撤销该改动，回退为纯镜像链路**。这是一次**安全能力退化**（自建源本可大幅降低第三方代理风险），当前 `update.json` 中已无残留。

### 【M-E】自有服务端接口现状

| 接口 | 实测 | 说明 |
|---|---|---|
| `www.verselauncher.cn/api/servers.json` | **404** | 源码常量已成**死链**（接口下线/迁移）；证书 Let's Encrypt 有效非自签（`CN=verselauncher.cn`，issuer `YR1`） |
| `verselauncher.cn` / `www.verselauncher.cn` | A 记录 `8.217.27.4` | 阿里云（香港区段） |
| `private_server.rs:13` 引用该 URL | 无鉴权、无签名 | 返回的 `address` 字段直接进入本地列表 → 服务端可控即"客户端连任意地址" |

**注意**：`private_server.rs` 用的是**标准 client（证书校验开启）**，与 R-0 的共享 client 不同。故 `servers.json` 受 TLS 保护，但**内容无签名**。

### 【M-F】其余节点接口（无鉴权、无签名）

| 接口 | 实测 |
|---|---|
| `lytapi.asia/rooma.php` | 200，裸 GET 返回 `server_addr` + `remote_port` + `node_id` |
| `hongshi.site/api/server/list` | 200，返回节点域名映射（可替换） |
| `terracotta.glavo.site/nodes` | 200，返回 `etnode.../node1\|node2`（**二次跳转，可替换**） |
| `etnode.zkitefly.eu.org/node1` | 200，返回 `tcp://183.66.27.22:39409` 明文地址 |

---

## 5. 攻击链闭合分析

### 5.1 链条一：更新投毒 → 全平台 RCE（最高危，**已在现实中具备条件**）

```
[攻击者：位于链路中间 / 持有任一硬编码代理域名 / 控制开发者本机]
        │
        ① 前提：R-0 已关闭 TLS 校验 → 无需域名、证书、DNS 任何条件
        │        R-2 实测：gh-proxy.com / ghproxy.link 已被非预期主体持有
        │
        ② 伪造/抢答 update.json（R-1a：4 源取第一个有效响应，官方源排第 4）
        │   → 删除 sha256 字段（R-1b：expected_sha=None 直落 return true）
        │
        ③ 客户端下载攻击者 exe，verify_file() 返回 true
        │
        ④ 用户正常关闭程序 → auto_install_on_close() 自动替换并重启（R-1d）
        │
        ⑤ 全平台代码执行（Windows / Linux / macOS 三条脚本路径均已确认）
```

**替代路径（无需任何网络手段）**：R-3 —— 开发者本机为 Windows 包唯一上传点，控制本机即可产出与正常发布**不可区分**的恶意 exe。

### 5.2 链条二：插件市场投毒 → RCE

```
[攻击者：控制 Gitee doujie081231 账号 / 劫持索引请求（R-0 使其无需证书）]
        │
        ① 伪造 index.json（R-4：走 shared_client，TLS 不设防）
        │   index_url 运行时可指定（R-4）→ 可重定向到任意索引
        │
        ② 上架插件：downloadUrl 指向攻击者包 + sha256 同步改为敌手值
        │   （R-4：哈希与包同源，"校验"形同虚设）
        │
        ③ 插件含 {"permissions":{"native":["exec"]}} 声明（R-5）
        │
        ④ plugin_process_exec(exe=任意, args=任意, cwd=任意) → 本机执行
```

### 5.3 链条三：联机隧道劫持（窃密/中间人）

```
[攻击者：控制客户端到 lytapi.asia 的链路（H-D：80 端口明文同内容）]
        │
        ① 替换 frplist58.txt → frpIp/frpPort 指向攻击者 frps
        │   token 用 decrypt_token 逆算法自造（H-D：25 行可复刻）
        │
        ② 玩家所有联机 MC 流量经攻击者 frps 中转
        │   → 被动嗅探 / 主动篡改
        │
        ③ 借 api.php 无鉴权 + CORS *（H-D）注册伪造公开房间，
        │   冒充官方节点诱骗更多玩家连接
```

### 5.4 链条四：本机提权（无需任何远程条件）

```
[攻击者：本机恶意进程 / 浏览器页面]
        │
        ① H-A：CSP 关闭 + withGlobalTauri + devtools → 任意脚本可 invoke 81 个命令
        │
        ② 或直接访问 H-B：http://127.0.0.1:27310/api/host/command（无鉴权）
        │
        ③ H-C：私人服务器地址字段 "$(cmd)" → shell 命令执行（已实证）
```

---

## 6. 修复建议（按优先级）

### P0 — 必须立即修复

1. **更新器强制验签（唯一根治手段）**
   - 生成 Ed25519 密钥对，**公钥硬编码进客户端**；`update.json` 与安装包均需签名，验签失败**拒绝安装并告警**。
   - `verify_file()` 中 `expected_sha == None` 必须 **`return false`**（当前是 `return true`）。
   - 移除全部第三方代理源，或仅在**本地完成签名校验**后允许代理作下载通道。
   - 自动校验 `version` 与各平台 `url` 的 tag 一致，防版本漂移。

2. **恢复 TLS 证书校验**
   - 删除全部 **5 处** `danger_accept_invalid_certs(true)`（`shared.rs:22`、`single.rs:30/58/115`、`ai.rs:273`）。
   - 对确实证书链不完整的镜像，改为**定点信任该镜像 CA** 或直接用 HTTP + 强制哈希校验，**不要全局降级**。

3. **Windows 包纳入 CI 并启用构建证明**
   - 将 Windows 构建接入 release（现 `windows-build.yml` 只产 artifact）。
   - 启用 GitHub **Artifact Attestation / SLSA provenance**，使"人工上传"成为不可能。
   - `gh release upload` 去掉 `--clobber`，禁止静默覆盖已发布资产。
   - `sponsor-orders.json` 改为**运行时加载**（现用 `include_str!` 把真实赞助者 id 编译进公开二进制）。

4. **插件包独立签名**
   - 插件包 + 索引均需签名，客户端硬编码公钥；`sha256` 须为**签名保护的固定值**而非索引内可变量。
   - `native:exec` 需用户**显式二次确认**并展示完整命令行；插件执行限制在沙箱（受限 token / 作业对象 / 目录白名单）。
   - `market_index(index_url)` 的 `index_url` 应改为**固定常量或白名单校验**（现为任意地址）。

5. **修复剪贴板命令注入（H-C）**
   - **不要经 shell 传递数据**。改用平台剪贴板库（如 `arboard`）或参数化调用；若必须用 shell，须完整转义 `$(...)`、反引号、`;`、`&`、`|`、`newline`，或用 `argv` 数组避免字符串拼接。

### P1 — 应尽快修复

6. **本地服务加鉴权**
   - `server_host_daemon`（27310）与全部 IPC：随机端口 + 启动时生成随机 Bearer token，所有请求强制校验。
   - `Host` / `Origin` 强校验；生产构建禁用 `/api/debug/*`。

7. **前端加固**
   - 设置严格 CSP（当前 `null`）；关闭 `withGlobalTauri`（改用最小暴露的 `@tauri-apps/api`）；生产构建关闭 `devtools`。

8. **联机链路**
   - 节点列表与房间 API 走 HTTPS + 签名校验；**服务端关闭 80 端口明文等价响应**。
   - **废弃客户端 `decrypt_token`**（现为可公开复刻的字符置换），token 改由服务端下发短时效凭据。
   - `api.php` 写操作（POST/DELETE）**必须加鉴权**；房间列表移除 `full_room_code` / `server_addr` 等敏感字段或仅返回脱敏数据；收窄 CORS。
   - frpc / terracotta 二进制**强制签名校验**；`exe.exists()` 短路改为**校验版本与哈希**后才跳过下载。

9. **收紧 UPnP**
   - `NewLeaseDuration=0`（永久映射）改为有限租期；增加端口白名单与用户显式确认；默认关闭。

### P2 — 建议改进

10. 全部 commit 启用 GPG 签名；仓库开启 2FA 与分支保护（**当前无法通过 API 确认，建议人工核查**）。
11. 域名治理：`lytapi.asia` 作为**关键信任锚点**（节点列表 + 房间 API 全在此域），建议迁移至更可控的域名并启用 DNSSEC/CAA。
12. 建立镜像信任基线：所有第三方镜像下载物必须校验**官方哈希**（不依赖镜像自身提供），并定期巡检镜像归属。
13. 复核 `redstone_online.rs`（hongshi.site 链）与 `easytier` / `scene_renderer` 的下载校验，统一走签名校验通道。

---

## 7. 附录

### 7.1 本次交付产物

| 文件 | 内容 |
|---|---|
| `VersePC2-远程端安全审查报告.md` | 本文件（主报告） |
| `白盒审计原始结论.md` | 主会话直接产出的源码级证据（含行号与代码片段） |
| `findings-p0-plugins.md` | 子智能体：插件市场 + 仓库归属（713 行，含原始回显） |
| `findings-p0-release.md` | 子智能体：发布链路 + 镜像供应链（511 行，含哈希比对表） |
| `findings-p1-api.md` | 子智能体：lytapi / verselauncher / hongshi / terracotta 接口（610 行） |
| `repo/` | VersePC2 完整源码克隆（914 文件，审计基线） |
| `src/` | 主会话定点拉取的核心模块源码 |
| `api/` | GitHub API 原始 JSON（releases / commits / workflows / repo / contributors） |

### 7.2 证据分级说明

本报告严格区分三类表述：
- **【实测】**：有真实命令与原始回显；
- **【白盒】**：有源码行号与代码片段；
- **【无法判定】**：明确标注原因（多为本机出口网络限制或 API 权限不足），**不做方向性推断**。

### 7.3 与客户端报告的关系

客户端报告结论「**无后门，作者可信**」在本轮审查中得到**一致佐证**：

- 26 个 release、18 条 commit、contributors，**全部指向单一作者 `doujie081231`，无第三方介入痕迹**；
- 未发现任何隐藏外联、恶意载荷或凭据窃取；
- 全部问题均属**设计缺陷与工程流程不足**（信任模型、校验缺失、发布流程），**未见恶意意图证据**。

但需强调：**设计缺陷的严重性不因"无恶意"而降低** —— R-0/R-1/R-2/R-3 组合已构成**当前即可被外部利用**的供应链 RCE 条件。作者可信 ≠ 软件安全。

---

*报告完*
