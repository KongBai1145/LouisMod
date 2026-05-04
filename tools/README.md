# LouisMod — tools/

## Scripts

| File | Description | Admin Required |
|------|-------------|----------------|
| `setup_all.cmd` | One-click setup: enable testsigning + install kernel driver | Yes |
| `uninstall_driver.bat` | Remove `LouisModDriver` service | Yes |
| `check_testsigning.ps1` | Check if test signing mode is enabled | Yes (auto-elevates) |
| `elevate.ps1` | Launch bcdedit as admin to enable testsigning | Yes |

## When to Use

**You don't need the driver for VAC-protected official matchmaking.** The user-mode backend (indirect syscalls with return-address camouflage) provides sufficient stealth for VAC.

Install the kernel driver only if:
- You play on Faceit, ESEA, or other third-party anti-cheats
- You want maximum stealth regardless

## Setup Flow

```
setup_all.cmd  ──>  Phase 1: Enable testsigning (one-time, requires reboot)
                 ──>  Phase 2: Install and start louismod.sys
```

### Step-by-step

1. **Build the driver** (see `louismod-kdriver/driver/`)
2. **Run `setup_all.cmd` as Administrator**
3. If testsigning is not enabled → reboot → run again
4. Driver service `LouisModDriver` will be created and started
5. Run `controller.exe` — it auto-detects the driver

### Uninstall

Run `uninstall_driver.bat` as Administrator. Optionally disable test signing:
```bash
bcdedit /set testsigning off
```

## How It Works

`controller.exe` calls `create_driver()` which tries:
1. **Kernel driver** via `LouisModDriver::create_from_env()` — opens `louismod.sys` via DeviceIoControl
2. **User-mode fallback** via `UserModeDriver::create()` — indirect syscalls with NtOpenProcess + PEB walk

If the driver isn't loaded, the user-mode backend takes over seamlessly. No configuration needed.
