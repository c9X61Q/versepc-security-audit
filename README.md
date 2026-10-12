# VersePC2 安全审查结果

对 VersePC2 客户端及其远程端的静态安全审查结果。

## 在线阅读

https://c9x61q.github.io/versepc-security-audit/

## 报告清单

| 报告 | 内容 |
|------|------|
| [客户端安全审查报告](reports/VersePC2-安全审查报告.md) | 客户端二进制的 7 项高危 + 8 项中危问题 |
| [远程端安全审查报告](reports/VersePC2-远程端安全审查报告.md) | 服务端接口、分发链路、联机节点审查 |
| [后端安全审查报告](reports/VersePC2-后端安全审查报告.md) | verselauncher.cn 后端接口审查 |
| [后门专项排查报告](reports/VersePC2-后门专项排查报告.md) | 8 维度后门排查（结论：未发现后门） |

## 目录

```
.
├── index.html          在线阅读页（白底黑字，markdown 渲染）
├── reports/            审查报告（Markdown）
└── evidence/           审查证据（模块清单 / URL 清单）
```

## 审查对象

- `VersePC2.exe`（Windows，v1.5.4）
- `VersePC2-1.1.2-linux-x86_64`（Linux，v1.1.2）
- 架构：Tauri v2.11.5（Rust 后端 + WebView 前端）
- 方式：静态逆向（字符串 / 模块结构 / 命令表 / 网络端点）

## 说明

本仓库仅包含**审查结果（文本）**，不包含被审查的源码或二进制。
