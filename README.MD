<p align="center">
  <img src="https://img.shields.io/badge/version-v0.5.18-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11%20x64-0078D6?style=flat-square&logo=windows" alt="Platform">
  <img src="https://img.shields.io/badge/language-Rust%20nightly-dea584?style=flat-square&logo=rust" alt="Language">
  <img src="https://img.shields.io/badge/status-active-success?style=flat-square" alt="Status">
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License">
</p>

<p align="center">
  <h1 align="center">LouisMod</h1>
  <p align="center"><strong>External CS2 Gameplay Enhancer</strong><br>
  <sub>Fork of Valthrun with dual backend, enhanced features, and web control panel</sub></p>
</p>

---

## Overview

LouisMod is an **external, read-only** Counter-Strike 2 gameplay enhancer. It never injects code into the game process and never reads from game memory without explicit purpose — leaving minimal detectable footprint.

### Why LouisMod?

| | Traditional Cheats | LouisMod |
|---|---|---|
| **Detection vector** | DLL injection + hooking | External process, indirect syscalls |
| **Memory footprint** | Injected code in CS2 address space | Own process, no cross-process interference |
| **Syscall origin** | ntdll hooks (detected) | ntdll gadget call → looks native |
| **Backend** | Kernel driver or Win32 API | Auto-fallback: kernel → user-mode syscall camouflage |
| **No driver?** | Useless | Works perfectly for VAC via user-mode backend |

### Dual Backend Architecture

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
└────────────────────────────────────────────┘
```

The factory function `create_driver()` probes the kernel driver first. On failure — which is the default for most users — it seamlessly falls back to the user-mode backend. No configuration, no driver compilation, no reboot.

---

## Features

### Visual (ESP)

| Feature | Description |
|---------|-------------|
| Skeleton ESP | Full bone rendering with configurable colors |
| Box ESP | 2D / 3D bounding boxes with dynamic sizing |
| Health bar | Gradient health indication |
| Head dot | Precise head position marker |
| Info panel | Name, HP, armor, weapon — per-player overlay |
| Weapon ESP | Rendered weapon names and icons |
| Chicken ESP | Because why not |
| Offscreen arrows | Directional indicators for off-screen targets |
| Multi-profile | Enemy / Team / Visibility-based configs simultaneously |

### Combat

| Feature | Description |
|---------|-------------|
| **Silent Aim** | Writes view angles directly to server — no local mouse movement |
| **Trigger Bot** | Auto-fire on crosshair target with configurable delay |
| **Recoil Control** | Automatic recoil compensation with bullet-count threshold |

### Utility

| Feature | Description |
|---------|-------------|
| **Grenade Helper** | Trajectory preview for smoke, molotov, flashbang, HE |
| **Bomb Timer** | C4 countdown, defuse timer, position indicator |
| **Spectator List** | Shows who's watching you |
| **Sniper Crosshair** | Persistent crosshair when scoped |
| **Stream Proof** | Anti-screenshot — overlay hidden from streaming software |

### Radar

External radar at [radar.valth.run](https://radar.valth.run) — full map with player positions, grenade trajectories, and bomb status.

---

## Web Control Panel

All configuration is done through a browser-based dashboard at **`http://localhost:16384`**.

```
┌─────────────────────────────────────────────────┐
│  Dashboard  │  ESP  │  Trigger  │  Silent Aim   │
│─────────────────────────────────────────────────│
│                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │ ESP      │  │ Trigger  │  │ Silent   │      │
│  │ Config   │  │ Bot      │  │ Aim      │      │
│  │          │  │ Settings │  │ Settings │      │
│  └──────────┘  └──────────┘  └──────────┘      │
│                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │ Grenade  │  │ Config   │  │ Settings │      │
│  │ Helper   │  │ Profiles │  │          │      │
│  └──────────┘  └──────────┘  └──────────┘      │
│                                                 │
│  Ctrl+K: Command Palette  │  WebSocket live sync│
└─────────────────────────────────────────────────┘
```

- **Real-time sync** — Changes reflect in-game instantly via WebSocket
- **Profile system** — Save / load / export / import config profiles as JSON
- **Command palette** — `Ctrl+K` for keyboard-driven navigation

---

## Default Keybinds

| Action | Key |
|--------|-----|
| Open settings overlay | `Pause` |
| Trigger Bot | `MouseMiddle` (hold) |
| Silent Aim | None (AlwaysOn) |
| ESP toggle | None (AlwaysOn) |

All rebindable via web panel or in-game overlay.

---

## Quick Start

### Prerequisites

- **Windows 10 or 11, x64**
- **Rust nightly** — `rustup default nightly`
- That's it. No WDK, no Visual Studio, no driver signing certificate.

### Build

```bash
git clone --recursive https://github.com/KongBai1145/LouisMod
cd LouisMod
cargo build --release -p controller
```

### Run

```bash
.\target\release\controller.exe
```

Open `http://localhost:16384` in your browser. Configure. Play.

> The user-mode backend handles everything for VAC-protected servers. No driver setup needed.

### Optional: Install Kernel Driver

For Faceit, ESEA, or maximum stealth:

```bash
# 1. Build the driver (MSVC + WDK required)
cd louismod-kdriver\driver
build.bat

# 2. Install (run as Administrator)
cd ..\..\tools
setup_all.cmd

# 3. Launch — auto-detects and uses kernel backend
..\target\release\controller.exe
```

See `tools/README.md` for detailed instructions.

---

## Architecture

```
LouisMod/
├── controller/                    # Main application
│   ├── src/
│   │   ├── main.rs                    # Entry point, main loop
│   │   ├── enhancements/              # Feature modules
│   │   │   ├── player/                # Player ESP system
│   │   │   ├── trigger.rs             # Trigger Bot
│   │   │   ├── silent_aim.rs          # Silent Aim
│   │   │   ├── aim.rs                 # Recoil Control
│   │   │   ├── grenade_helper.rs      # Grenade Helper
│   │   │   ├── bomb.rs                # Bomb Timer
│   │   │   ├── spectators_list.rs     # Spectator List
│   │   │   └── sniper_crosshair.rs    # Sniper Crosshair
│   │   ├── settings/                  # Configuration system
│   │   ├── web/                       # Axum HTTP + WebSocket server
│   │   ├── view/                      # ImGui overlay rendering
│   │   └── utils/                     # Helpers, ImGui extensions
│   └── resources/web/                 # Web frontend (SPA)
├── cs2/                              # Game interaction layer
│   └── src/
│       ├── handle.rs                  # CS2Handle: memory I/O
│       ├── schema_runtime/            # Runtime schema resolver
│       └── state/                     # Game state types
├── louismod-kdriver/                 # Kernel driver + user-mode backend
│   └── src/
│       ├── lib.rs                     # Factory, LouisModDriver
│       ├── trait_interface.rs         # DriverInterface trait
│       ├── command.rs                 # IOCTL protocol
│       ├── device.rs                  # DeviceHandle
│       ├── types.rs                   # Shared types
│       └── usermode/
│           ├── mod.rs                 # UserModeDriver
│           └── syscall.rs             # Syscall table, gadget camouflage
├── cs2-schema/                       # Schema system
│   ├── generated/                     # Auto-generated structs
│   ├── provider/                      # runtime_offset! macro
│   ├── dumper/                        # Schema dump tool
│   └── cutl/                          # CUtl containers
├── overlay/                          # ImGui overlay layer
├── radar/                            # Radar service
├── tools/                            # Driver installation scripts
└── utils/state                       # StateRegistry framework
```

---

## Security Model

### User-Mode Backend Deep Dive

The user-mode driver achieves stealth without a kernel driver through three techniques:

**1. Indirect Syscalls**

Syscall numbers are extracted from a clean on-disk `ntdll.dll` — not from the in-memory copy which anti-cheats may hook. Each `Nt*` call uses raw inline assembly with the extracted numbers, bypassing any user-mode hooks on ntdll.

**2. Return Address Camouflage**

Instead of executing `syscall` in our own module (which the kernel would record), we `call` into a `syscall; ret` gadget located inside the already-loaded `ntdll.dll`. The kernel's syscall origin tracking sees `ntdll.dll`, not `controller.exe`.

```
Direct (detectable):            Camouflaged (safe):
controller.exe                  controller.exe
  └─ syscall ← recorded here      └─ call ntdll!syscall;ret
                                                   └─ syscall ← recorded here
```

**3. Bypassed Win32 APIs**

- **OpenProcess** → `NtOpenProcess` via indirect syscall (bypasses kernel32 + ntdll hooks)
- **Process enumeration** → `NtQuerySystemInformation(SystemProcessInformation)` via indirect syscall
- **Module enumeration** → PEB walk via `NtQueryInformationProcess` + `NtReadVirtualMemory`

### Detection Surface

| Component | User-Mode | Kernel Driver |
|-----------|-----------|---------------|
| Process handle | In user handle table | In kernel handle table |
| Syscall origin | ntdll gadget (appears native) | Kernel IOCTL |
| Process visibility | Normal (PID visible) | Can be hidden |
| Input simulation | SendInput | Kernel-level input |
| Anti-anti-cheat | VAC only | VAC + Faceit/ESEA |

---

## Configuration

`config.yaml` is auto-generated on first run alongside the executable. All settings are editable through the Web Panel or directly in the YAML file.

```yaml
key_settings: Pause
trigger_bot_mode: Trigger
key_trigger_bot: MouseMiddle
aim_silent: false
aim_silent_fov: 5.0
aim_silent_team_check: true
# ... all features toggleable per-profile
```

---

## FAQ

<details>
<summary><b>Does this work without a kernel driver?</b></summary>
Yes. The user-mode backend provides full functionality for official matchmaking (VAC). Simply build and run. No driver, no admin, no reboot.
</details>

<details>
<summary><b>Is this detectable?</b></summary>
VAC is a user-mode anti-cheat. LouisMod's indirect syscalls + gadget camouflage bypass its detection vectors. That said, no cheat is 100% undetectable — use at your own risk.
</details>

<details>
<summary><b>Can I use this on Faceit / ESEA?</b></summary>
Faceit and ESEA use kernel-level anti-cheats. The kernel driver backend is designed for this, but full compatibility depends on the specific anti-cheat version. The user-mode backend will not suffice.
</details>

<details>
<summary><b>Why Rust?</b></summary>
Zero-cost abstractions, memory safety, and a rich type system make Rust ideal for systems programming. Schema structs are generated at compile time with correct alignment, and the macro system enables runtime offset resolution with static caching.
</details>

---

## Credits

- **Original Valthrun** by [WolverinDEV](https://github.com/valthrun) — The foundation of this project
- **Fork & Enhancements** by [LouisAlice](https://github.com/KongBai1145)
- **Discord** — [Join the community](https://discord.gg/ecKbpAPW5T)
- **Wiki** — [wiki.valth.run](https://wiki.valth.run)

---

## Disclaimer

This project is for **educational and research purposes only**. Using this software may violate Valve's Terms of Service. The author assumes no liability for any consequences of its use.

---

<p align="center">
  <sub>Built with Rust · Powered by indirect syscalls · No injection, no hooks</sub>
</p>
