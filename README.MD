<p align="center">
  <img src="https://img.shields.io/badge/version-v0.5.18-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-0078D6?style=flat-square&logo=windows" alt="Platform">
  <img src="https://img.shields.io/badge/language-Rust%20nightly-dea584?style=flat-square&logo=rust" alt="Language">
  <img src="https://img.shields.io/badge/status-active-success?style=flat-square" alt="Status">
</p>

<p align="center">
  <h1 align="center">LouisMod</h1>
  <p align="center">
    <strong>External CS2 Gameplay Enhancer / 外部 CS2 游戏增强器</strong><br>
    <sub>Fork of Valthrun · Dual Backend · Web Control Panel · Silent Aim</sub>
  </p>
</p>

---

## Overview / 概述

LouisMod is an **external, read-only** Counter-Strike 2 gameplay enhancer. It never injects code into the game process — leaving minimal detectable footprint.

LouisMod 是一个**外部、只读**的 CS2 游戏增强器。不向游戏进程注入代码，检测痕迹极小。

### Why LouisMod? / 为什么选择 LouisMod？

| | Traditional Cheats / 传统外挂 | **LouisMod** |
|---|---|---|
| Detection vector / 检测方式 | DLL injection + hooking | External process, indirect syscalls / 外部进程+间接syscall |
| Memory footprint / 内存占用 | Injected code in CS2 space | Own process, no cross-process interference / 独立进程 |
| Syscall origin / 调用来源 | ntdll hooks (detected) | ntdll gadget call → looks native / 伪装成ntdll调用 |
| Backend / 后端 | Kernel OR Win32 API | Auto-fallback: kernel → user-mode syscall camouflage |
| No driver? / 无驱动? | Useless / 无法使用 | Works for VAC via user-mode / 用户态即可官匹 |

### Dual Backend Architecture / 双后端架构

```
┌────────────────────────────────────────────┐
│                 controller.exe              │
│                                             │
│  ┌─────────────────────────────────────┐    │
│  │         DriverInterface trait        │    │
│  └──────────┬──────────────┬───────────┘    │
│             │              │                 │
│     ┌───────▼──────┐ ┌────▼──────────────┐  │
│     │ LouisModDriver│ │ UserModeDriver    │  │
│     │ (kernel)      │ │ (user-mode)       │  │
│     ├───────────────┤ ├───────────────────┤  │
│     │ DeviceIoControl│ │ Indirect syscalls │  │
│     │ ObCallbacks   │ │ Gadget camouflage │  │
│     │ CR3 mitigation│ │ PEB walk          │  │
│     │ Kernel handles│ │ NtOpenProcess     │  │
│     └───────────────┘ └───────────────────┘  │
│             │              │                 │
│     requires driver     zero setup           │
│     admin required      no admin needed      │
│     需要驱动+管理员      无需配置无需管理员    │
└────────────────────────────────────────────┘
```

`create_driver()` probes the kernel driver first. On failure — the default for most users — it falls back to user-mode. **No config, no driver, no reboot.**

`create_driver()` 先尝试内核驱动，失败后自动回退用户态。**零配置，无驱动，无需重启。**

---

## Features / 功能特性

### ESP / 视觉辅助

| Feature / 功能 | Description / 描述 |
|---------|-------------|
| Skeleton ESP / 骨骼 | Full bone rendering / 完整骨骼渲染 |
| Box ESP / 盒子 | 2D / 3D bounding boxes / 动态包围盒 |
| Health bar / 血量条 | Gradient health indication / 渐变色血量 |
| Head dot / 头点 | Precise head marker / 精确头部标记 |
| Info panel / 信息显示 | Name, HP, armor, weapon / 名称血量护甲武器 |
| Offscreen arrows / 超车箭头 | Directional indicators / 屏幕外目标指示 |
| Multi-profile / 多配置 | Enemy/Team/Visibility simultaneous / 同时启用多套配置 |

### Combat / 战斗

| Feature / 功能 | Description / 描述 |
|---------|-------------|
| **Silent Aim / 静默自瞄** | Writes angles to server — no mouse movement / 直接写入服务器角度 |
| **Trigger Bot / 自动扳机** | Auto-fire on crosshair with delay / 准星指向敌人自动开枪 |
| **Recoil Control / 压枪** | Automatic recoil compensation / 自动后坐力补偿 |

### Utility / 工具

| Feature / 功能 | Description / 描述 |
|---------|-------------|
| **Grenade Helper / 投掷物助手** | Trajectory preview / 轨迹预览 |
| **Bomb Timer / 炸弹计时** | C4 countdown, defuse info / 倒计时拆弹信息 |
| **Spectator List / 观战列表** | Shows who's watching / 显示观战者 |
| **Sniper Crosshair / 狙击准星** | Persistent crosshair when scoped / 开镜持久准星 |
| **Stream Proof / 防截屏** | Hidden from streaming software / 直播软件不可见 |

### Radar / 雷达

External radar at [radar.valth.run](https://radar.valth.run) / 外部雷达页面

---

## Web Control Panel / Web 控制面板

```bash
http://localhost:16384
```

| Page / 页面 | Description / 描述 |
|-----|------|
| Dashboard / 仪表板 | One-click toggle all / 一键开关 |
| ESP Config / ESP配置 | Visual config editor / 可视化编辑器 |
| Trigger Bot | Delay, mode, hotkey / 延迟模式热键 |
| Silent Aim / 静默自瞄 | FOV, hotkey, auto-shoot / 视野热键自动开枪 |
| Profiles / 配置文件 | Save/load/export/import / JSON导入导出 |

- **Real-time sync** via WebSocket / WebSocket实时同步
- **Command palette** `Ctrl+K` / 命令面板

---

## Quick Start / 快速开始

### Prerequisites / 环境要求

- **Windows 10/11 x64**
- **Rust nightly** — `rustup default nightly`
- That's it. / 就这些。

### Build / 构建

```bash
git clone --recursive https://github.com/KongBai1145/LouisMod
cd LouisMod
cargo build --release -p controller
```

### Run / 运行

```bash
.\target\release\controller.exe
# Web panel: http://localhost:16384
```

> No driver needed for VAC-protected official matchmaking. / 官匹无需驱动。

---

## Download & Run (No Build) / 下载即用（无需构建）

### 1. Download / 下载

Go to [GitHub Releases](https://github.com/KongBai1145/LouisMod/releases) and download the latest `controller.exe`.

前往 [GitHub Releases](https://github.com/KongBai1145/LouisMod/releases) 下载最新 `controller.exe`。

### 2. Run / 运行

Double-click `controller.exe`. The program will:
- Auto-detect whether the kernel driver is loaded
- Fall back to user-mode indirect syscalls if no driver (sufficient for VAC)
- Start the web control panel on port `16384`

双击 `controller.exe` 即可运行。程序会：
- 自动检测内核驱动是否已加载
- 无驱动时自动回退用户态间接 syscall（对 VAC 足够安全）
- 在端口 `16384` 启动 Web 控制面板

### 3. Open Control Panel / 打开控制面板

```
http://localhost:16384
```

- Toggle features on the Dashboard / 在仪表盘开关功能
- Configure ESP, Trigger Bot, Silent Aim / 配置 ESP、扳机、静默自瞄
- Save/load profiles via localStorage / 通过 localStorage 保存/加载配置
- Press `Ctrl+K` for command palette / 按 `Ctrl+K` 打开命令面板

### 4. Stop / 停止

Close the console window or press `Ctrl+C` in the terminal.

关闭控制台窗口或在终端按 `Ctrl+C`。

---

### Optional: Kernel Driver / 可选：安装内核驱动

For Faceit/ESEA or maximum stealth / 针对第三方反作弊或最强隐匿：

```bash
cd louismod-kdriver\driver
build.bat
cd ..\..\tools
setup_all.cmd          # Run as Administrator / 管理员运行
```

---

## Architecture / 项目结构

```
LouisMod/
├── controller/                    # 主程序 / Main application
│   ├── src/
│   │   ├── main.rs                    # 入口主循环 / Entry point
│   │   ├── enhancements/              # 功能模块 / Features
│   │   │   ├── silent_aim.rs          # Silent Aim / 静默自瞄
│   │   │   ├── trigger.rs             # Trigger Bot / 自动扳机
│   │   │   ├── aim.rs                 # Recoil Control / 压枪
│   │   │   ├── grenade_helper.rs      # Grenade Helper / 投掷物
│   │   │   ├── bomb.rs                # Bomb Timer / 炸弹计时
│   │   │   └── player/                # Player ESP / 玩家ESP
│   │   ├── settings/                  # 配置系统 / Config
│   │   ├── web/                       # Axum HTTP + WebSocket
│   │   └── view/                      # ImGui overlay
│   └── resources/web/                 # Web frontend / 前端
├── cs2/                              # 游戏交互层 / Game layer
├── louismod-kdriver/                 # 驱动+用户态双后端 / Dual backend
│   └── src/
│       ├── lib.rs                     # Factory / 工厂函数
│       ├── trait_interface.rs         # DriverInterface trait
│       └── usermode/
│           ├── mod.rs                 # UserModeDriver
│           └── syscall.rs             # Syscall table, gadget camouflage
├── cs2-schema/                       # Schema 系统
├── overlay/                          # ImGui overlay
├── radar/                            # Radar / 雷达
├── tools/                            # Driver scripts / 驱动脚本
└── utils/state                       # StateRegistry
```

---

## Security Model / 安全模型

### 1. Indirect Syscalls / 间接系统调用

Syscall numbers extracted from clean on-disk `ntdll.dll` — not the in-memory copy that anti-cheats may hook. Each `Nt*` call uses raw inline assembly bypassing user-mode hooks.

从磁盘干净 `ntdll.dll` 提取 syscall 号——不使用可能被 hook 的内存中的 ntdll。每个 `Nt*` 调用使用裸内联汇编，绕过用户态 hook。

### 2. Return Address Camouflage / 返回地址伪装

Instead of executing `syscall` in our module (kernel records it), we `call` into a `syscall; ret` gadget inside ntdll.dll. The kernel sees ntdll.dll as the syscall origin.

不在自己模块执行 `syscall`，而是 `call` 到 ntdll.dll 内部的 `syscall;ret` gadget。内核记录的调用地址在 ntdll.dll 内。

```
Direct / 直接 (可检测):             Camouflaged / 伪装 (安全):
controller.exe                  controller.exe
  └─ syscall ← recorded here      └─ call ntdll!syscall;ret
                                                   └─ syscall ← recorded here
```

### 3. Bypassed APIs / 绕过的 API

- **OpenProcess** → `NtOpenProcess` via indirect syscall
- **Process enum** → `NtQuerySystemInformation(SystemProcessInformation)`
- **Module enum** → PEB walk via indirect syscalls

---

## Keybinds / 键位

| Action / 功能 | Key / 默认键 |
|--------|-----|
| Settings overlay / 设置 | `Pause` |
| Trigger Bot | `MouseMiddle` (hold / 按住) |

All rebindable / 全部可自定义

---

## FAQ / 常见问题

<details>
<summary><b>Without kernel driver? / 无驱动可用吗？</b></summary>
Yes. User-mode backend works for VAC-protected official matchmaking. Build and run.
可以。用户态后端对 VAC 官匹完全可用。构建即用。
</details>

<details>
<summary><b>Detectable? / 会被检测吗？</b></summary>
VAC is user-mode. Indirect syscalls + gadget camouflage bypass its detection vectors. No cheat is 100% undetectable — use at your own risk.
VAC 是用户态反作弊。间接 syscall + gadget 伪装可绕过检测。没有任何外挂 100% 不被检测——风险自负。
</details>

<details>
<summary><b>Faceit/ESEA? / 能用第三方平台吗？</b></summary>
Faceit and ESEA use kernel-level anti-cheats. The kernel driver backend is designed for this. User-mode will not suffice.
Faceit/ESEA 使用内核级反作弊。需使用内核驱动后端。用户态不够。
</details>

---

## Disclaimer / 免责声明

This project is for **educational and research purposes only**. Using this software may violate Valve's terms of service. Use at your own risk.

本项目**仅供学习和研究**。使用本软件可能违反 Valve 服务条款。风险自负。

---

## Credits / 致谢

- **Original / 原版** [Valthrun](https://github.com/valthrun/valthrun-cs2) by WolverinDEV
- **Fork & Enhancements / 本版增强** by [LouisAlice](https://github.com/KongBai1145)
- **Discord** — [Join / 加入](https://discord.gg/ecKbpAPW5T)

---

<p align="center">
  <sub>Built with Rust · Powered by indirect syscalls · No injection, no hooks</sub><br>
  <sub>Rust 构建 · 间接 syscall 驱动 · 无注入 无 Hook</sub>
</p>
