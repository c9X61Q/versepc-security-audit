# VersePC2 后门专项排查报告

**排查目标**：确认作者是否在客户端中植入后门（隐蔽外联、未授权执行、静默数据回传、持久化、凭据窃取等）
**排查对象**：`VersePC2.exe`（Windows）/ `VersePC2-1.1.2-linux-x86_64`（Linux）
**排查方式**：静态逆向（行为关键词扫描 + 全上下文还原 + 外联主机白名单比对 + 内嵌载荷检测 + 启动序列追踪）
**结论**：**未发现后门。** 未发现任何隐蔽外联、静默执行、数据回传、持久化或凭据窃取行为。所有可疑点均可解释为正常业务功能。
**风险定性**：**无后门**；但存在**设计缺陷类风险**（更新/插件链路缺签名、本地 API 无鉴权），见配套《安全审查报告》。

---

## 1. 排查方法

| 维度 | 手段 |
|---|---|
| 行为关键词 | 扫描 7 大类后门特征词（执行/落地/持久化/外联/凭据/注入/可疑中文），逐一还原上下文 |
| 外联审计 | 提取全部 URL 主机（124 个），与官方来源白名单比对，识别非白名单主机 |
| 载荷检测 | 全库扫描 ≥120 字符 base64 串（97+93 个），解码检测 PE/ELF/脚本魔数 |
| 直连检测 | 扫描硬编码公网 IP（排除私网/回环/保留） |
| 启动序列 | 还原完整 `[boot]` 初始化链，确认启动时无隐藏网络行为 |
| 执行面 | 定位所有 `Command`/`powershell`/`explorer`/`Start-Process` 调用点并还原用途 |

---

## 2. 逐项排查结果

### 2.1 进程执行 / 拉起（无后门）

| 可疑点 | 上下文还原 | 判定 |
|---|---|---|
| `powershell.exe -NoProfile -NonInteractive -Command` | 配合 `Start-Process -FilePath $env:OPEN_RS_TARGET` / `explorer.exe`，用于 **`open_external` 命令打开链接或文件夹**（Tauri opener 插件标准实现） | ✅ 正常 |
| `powershell -ExecutionPolicyBypass -EncodedCommand` | 完整脚本已还原：**用 `WScript.Shell` 在桌面创建 `.lnk` 快捷方式**（`CreateShortcut` / `TargetPath` / `WorkingDirectory` / `Description`），由用户主动触发的 `create-shortcut` 命令调用 | ✅ 正常（`-EncodedCommand` 是避免引号转义的标准写法，非混淆） |
| `cmd.exe /c` | 仅用于 **`run.bat` 启动脚本**（支持用户自定义启动脚本）与 rustc 内部实现 | ✅ 正常 |
| `explorer.exe /select,<path>` | **打开版本目录并选中文件夹**（open-folder 功能） | ✅ 正常 |
| `winebrowser` | Linux 下打开 URL 的桌面集成方式 | ✅ 正常 |
| `java.exe` / `javaw.exe` | 启动 Minecraft 游戏本体 | ✅ 正常 |
| `frpc.exe` / `hongshic` | 联机隧道进程（联机功能） | ✅ 正常 |

**结论**：所有进程执行点均对应明确的 UI 功能，无隐藏执行、无参数拼接注入、无远程触发路径。

### 2.2 下载即执行 / 落地（无后门）

| 下载物 | 来源 | 判定 |
|---|---|---|
| `frp.zip` → `frpc.exe` | `gitee.com/lyt590/enderlinkupdate` | ✅ 联机功能（⚠️ 无签名，见 H-3） |
| `windowshongshi.exe` | `hongshi.site`（公开第三方项目） | ✅ 联机功能（已核实为公开项目，见 L-1） |
| `scene-renderer-windows-x64.zip` | 自身 GitHub release | ✅ 壁纸引擎功能 |
| 游戏资源 / 库 / 资产 | Mojang 官方 + BMCLAPI 镜像 | ✅ 正常 |
| Java 运行时 | Adoptium / Azul / Microsoft | ✅ 正常 |
| 更新包 `VersePC2-x.x.x.exe` | 个人 GitHub + 代理 | ⚠️ 无签名（见 H-1），**但为正常更新功能，非后门** |

**结论**：所有下载物均服务于明示功能且来源可解释，**无静默下载执行**。

### 2.3 外联主机审计（无后门）

**全部 124 个主机均已归类**，无非白名单可疑主机。关键新增主机均为官方：

| 主机 | 用途 |
|---|---|
| `login.microsoftonline.com` / `developer.microsoft.com` / `go.microsoft.com` | 微软正版登录 |
| `cdn-alt.modrinth.com` | Modrinth CDN |
| `mirrors.cernet.edu.cn` / `raw.gitmirror.com` | 国内镜像加速 |
| `hongshi.site` / `nj.hongshi.site` | 公开联机项目（已核实） |
| `lytapi.asia` | 联机节点/房间接口（自有服务） |
| `www.verselauncher.cn` | 自有服务器列表接口 |

**未发现**：C2 域名、Webhook、Telegram/Discord 回传（`discord` 命中全部为 mod 的 `discord_url` 字段）、pastebin、ngrok 隧道（`ngrok` 命中为 mod 名 `ngrok-api`）、自建上报端点。

### 2.4 内嵌载荷检测（无后门）

- Windows：97 个长 base64 串，**解码后无 PE/ELF/PowerShell/PHP/Shebang 载荷**
- Linux：93 个长 base64 串，**同样无可执行载荷**
- 硬编码公网 IP：全部为**版本号拼接假阳性**（如 `1.21.41.20` = MC 版本串），**无真实 C2 IP**

### 2.5 持久化 / 自启（无后门）

- **无** `CurrentVersion\Run`、`RunOnce`、`schtasks`、`crontab`、`LaunchAgent`、`systemd` 写入
- **无** `autostart` / `auto_start` / 开机自启逻辑
- 唯一 `Startup` 命中为 MSI/安装器模板字符串
- 唯一 `.lnk` 创建**需用户主动触发**（`create-shortcut` 命令）

### 2.6 凭据 / 敏感读取（无后门）

| 可疑点 | 还原 | 判定 |
|---|---|---|
| `password` / `wallet` | mod 名称翻译表（如 `wallet` 等）中的词 | ✅ 噪音 |
| `clipboard`（剪贴板） | `Set-Clipboard`（作者**写入**剪贴板，非读取）；其余为 mod 名 | ✅ 正常 |
| `screenshot` | **自身截图管理 API**（`/api/screenshots`），管理游戏截图 | ✅ 正常 |
| `GetAsyncKeyState` | 仅 1 处，位于 winit/窗口库键盘状态查询 | ✅ 库代码 |
| `上传` | 全部为 `上传皮肤`（Minecraft 正版皮肤上传，官方 API）或 mod 名 | ✅ 正常 |
| `采集` / `监控` | 全部为 **mod 名称翻译**（如「连锁采集」「实用物流监控2」） | ✅ 噪音 |
| `accounts.json` | 登录账号存储（⚠️ 无 OS 凭据库，见 H-4），**但未外发** | ⚠️ 设计缺陷，非后门 |

**未发现**：键盘记录、屏幕截取外发、浏览器凭据读取（Login Data/Cookies）、SSH 密钥、钱包文件窃取。

### 2.7 注入 / 隐蔽（无后门）

- `VirtualAlloc` / `WriteProcessMemory` / `CreateRemoteThread` / `SetWindowsHookEx`：**全部为 0**（无进程注入）
- `LoadLibrary` / `GetProcAddress`：来自 `windows-sys` 等系统 FFI 库的正常绑定
- `obfuscat` 命中：全部为 **mod 名称**（`obfuscate-lib-compatible-fix` 等）；无代码混淆器特征

### 2.8 启动序列（无后门）

完整启动链已还原，**行为完全可解释**：

```
[boot] page_load
[boot] setup start
[boot] after data_dir          ← 创建数据目录
[boot] after Store::new        ← 初始化本地存储
[store] 已完成旧版 Electron 数据迁移
[boot] after migrate
[boot] before ensure / after ensure   ← 文件完整性
[boot] after manage
[boot] setup done
[boot] 后台预热 Java 列表完成    ← 后台扫描本地 Java
```

**启动时无任何隐藏网络回调、无下载执行、无外联上报。**

---

## 3. 更新器行为专项（虽非后门，但最接近"可被滥用"）

**更新脚本 `_versepc_update.bat` 完整还原**（自替换机制，属正常做法）：

```bat
@echo off & chcp 65001 >nul
:wait                       ' 等待主程序退出(最多8次)
  tasklist /fi "imagename eq <exe>" | find /i "<exe>"
  if errorlevel 1 goto replace
  set /a tries+=1
  if %tries% geq 8 goto kill
  timeout /t 1 /nobreak >nul & goto wait
:kill                       ' 超时后强制结束进程
  taskkill /f /im "<exe>"
:replace                    ' 替换 exe 并重启
  move /y "%NEW%" "%CUR%"
  ...
  start "" "%CUR%"
:done
del /q "%~f0"               ' 自删除
```

**判定**：这是**标准的更新自替换脚本**（等进程退出→替换→重启→自删），逻辑透明，**不是后门**。
**但**：脚本由下载内容生成，且下载包**无签名校验**（见 H-1）—— 这不构成"作者植入后门"，但构成"可被第三方投毒"的风险面。二者须区分。

---

## 4. 最终结论

| 排查项 | 结果 |
|---|---|
| 隐藏外联 / C2 | ✅ 未发现 |
| 静默下载执行 | ✅ 未发现 |
| 内嵌恶意载荷 | ✅ 未发现 |
| 持久化 / 开机自启 | ✅ 未发现 |
| 键盘记录 / 屏幕外发 | ✅ 未发现 |
| 浏览器 / SSH / 钱包凭据窃取 | ✅ 未发现 |
| 进程注入 / Hook | ✅ 未发现 |
| 数据静默回传 | ✅ 未发现 |
| 启动时隐藏行为 | ✅ 未发现 |

### 作者是否塞了后门？

**没有。** 两个客户端中**未发现任何后门特征**。所有"可疑"字符串均可溯源到：
1. Minecraft mod 中文名称翻译表（占绝大多数噪音：`采集`、`监控`、`wallet`、`上传` 等）
2. 标准 Tauri / Rust 库代码（`LoadLibrary`、`GetAsyncKeyState`、`clipboard` 等）
3. 明确对应 UI 功能的业务代码（打开文件夹、创建快捷方式、联机、更新）

### 但需要区分两类问题

| | 后门（恶意） | 设计缺陷（可被滥用） |
|---|---|---|
| 是否存在 | ❌ **不存在** | ✅ **存在** |
| 表现 | 隐蔽控制、窃密、回传 | 更新/插件无签名、本地 API 无鉴权、token 落盘 |
| 责任 | 作者主动植入 | 安全工程不足 |
| 风险 | — | 第三方可投毒利用（见 H-1/H-2） |

**一句话**：作者**没有留后门**；但软件的**供应链与本地接口防护做得不严**，攻击者若能控制分发节点（个人 GitHub/Gitee 仓库、代理域名），可借"合法更新/插件"机制实施攻击——这是**设计风险**，不是**作者恶意**。

---

## 附：排查证据文件

| 文件 | 内容 |
|---|---|
| `VersePC2.exe.urls.txt` | 全部外联 URL（153 条） |
| `VersePC2-linux.urls.txt` | Linux 端全部 URL（137 条） |
| `VersePC2.exe.own_modules.txt` | 自有模块 89 个 |
| `VersePC2-linux.own_modules.txt` | 自有模块 85 个 |
| `VersePC2-安全审查报告.md` | 配套安全审查报告（H-1~H-7 高危、M-1~M-8 中危、L-1 低危） |
