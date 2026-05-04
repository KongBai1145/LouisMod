mod syscall;

use std::{
    ffi::OsString,
    os::windows::ffi::OsStringExt,
    sync::atomic::{
        AtomicUsize,
        Ordering,
    },
};

use windows::Win32::{
    System::Threading::{
        PROCESS_QUERY_INFORMATION,
        PROCESS_VM_READ,
    },
    UI::Input::KeyboardAndMouse::{
        SendInput,
        INPUT,
        INPUT_KEYBOARD,
        INPUT_MOUSE,
        KEYBDINPUT,
        KEYEVENTF_KEYUP,
        KEYEVENTF_SCANCODE,
        MOUSEEVENTF_HWHEEL,
        MOUSEEVENTF_LEFTDOWN,
        MOUSEEVENTF_LEFTUP,
        MOUSEEVENTF_MIDDLEDOWN,
        MOUSEEVENTF_MIDDLEUP,
        MOUSEEVENTF_MOVE,
        MOUSEEVENTF_RIGHTDOWN,
        MOUSEEVENTF_RIGHTUP,
        MOUSEEVENTF_WHEEL,
        MOUSEINPUT,
        MOUSE_EVENT_FLAGS,
        VIRTUAL_KEY,
    },
};

use crate::{
    error::{
        IResult,
        InterfaceError,
    },
    trait_interface::DriverInterface,
    types::*,
};

// ---------------------------------------------------------------
// UserModeDriver
// ---------------------------------------------------------------
#[allow(dead_code)]
pub struct UserModeDriver {
    process_handle: u64,
    process_id: ProcessId,
    syscalls: syscall::SyscallTable,
    gadget: u64,
    modules: Vec<ProcessModuleInfo>,
    read_calls: AtomicUsize,
    features: DriverFeature,
    version: VersionInfo,
}

impl UserModeDriver {
    pub fn create() -> IResult<Self> {
        let (syscalls, gadget) = syscall::load_syscall_data()?;

        if gadget != 0 {
            log::debug!("Using syscall;ret gadget at ntdll+{:#X}", gadget);
        }

        // Find cs2.exe via indirect NtQuerySystemInformation
        let pid = find_cs2_process(gadget, syscalls.nt_query_system_information)?;

        // Open a handle via indirect NtOpenProcess — bypasses kernel32/ntdll hooks
        let desired_access = PROCESS_VM_READ.0 | PROCESS_QUERY_INFORMATION.0;
        log::info!("Opening CS2 PID={} with desired_access=0x{:X} (VM_READ|QUERY_INFO)", pid, desired_access);
        let handle_val = syscall::nt_open_process_via_gadget(
            gadget,
            syscalls.nt_open_process,
            pid,
            desired_access,
        )?;

        // Enumerate modules via PEB walk using indirect syscalls
        let modules = enumerate_modules_via_peb(&syscalls, gadget, handle_val)?;

        let features = DriverFeature::PROCESS_LIST
            | DriverFeature::PROCESS_MODULES
            | DriverFeature::MEMORY_READ
            | DriverFeature::MEMORY_WRITE
            | DriverFeature::INPUT_KEYBOARD
            | DriverFeature::INPUT_MOUSE
            | DriverFeature::METRICS;

        let mut version = VersionInfo::default();
        version.set_application_name("louismod-usermode");
        version.version_major = 0;
        version.version_minor = 5;
        version.version_patch = 18;

        log::debug!(
            "UserModeDriver initialized (PID {}) with {} modules",
            pid,
            modules.len()
        );

        // Test: compare indirect syscall vs real kernel32!ReadProcessMemory
        if let Some(engine2) = modules.iter().find(|m| m.get_base_dll_name() == Some("engine2.dll")) {
            use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
            use windows::Win32::Foundation::HANDLE;
            // Test via real ReadProcessMemory
            let mut rpm_buf = [0u8; 64];
            let mut rpm_read: usize = 0;
            let h = HANDLE(handle_val as isize);
            unsafe {
                let ok = ReadProcessMemory(h, engine2.base_address as *const _, rpm_buf.as_mut_ptr() as *mut _, 64, Some(&mut rpm_read));
                if ok.is_ok() {
                    log::info!("  RPM(engine2+0, 64B) OK: {:02X?}", &rpm_buf[..16]);
                } else {
                    log::error!("  RPM(engine2+0, 64B) FAILED: {}", std::io::Error::last_os_error());
                }
                // Try 64KB via RPM
                let mut rpm_large = vec![0u8; 65536];
                let mut rpm_large_read: usize = 0;
                let ok2 = ReadProcessMemory(h, engine2.base_address as *const _, rpm_large.as_mut_ptr() as *mut _, 65536, Some(&mut rpm_large_read));
                if ok2.is_ok() {
                    log::info!("  RPM(engine2+0, 64KB) OK: {:02X?}", &rpm_large[..16]);
                } else {
                    log::error!("  RPM(engine2+0, 64KB) FAILED: {}", std::io::Error::last_os_error());
                }
                // Try 64KB at engine2+0x10000
                let ok3 = ReadProcessMemory(h, (engine2.base_address + 0x10000) as *const _, rpm_large.as_mut_ptr() as *mut _, 65536, Some(&mut rpm_large_read));
                if ok3.is_ok() {
                    log::info!("  RPM(engine2+0x10000, 64KB) OK: {:02X?}", &rpm_large[..16]);
                } else {
                    log::error!("  RPM(engine2+0x10000, 64KB) FAILED: {}", std::io::Error::last_os_error());
                }
            }
        }

        for m in &modules {
            log::trace!(
                "  {:X} {} (size {})",
                m.base_address,
                m.get_base_dll_name().unwrap_or("?"),
                m.module_size
            );
        }

        Ok(Self {
            process_handle: handle_val,
            process_id: pid,
            syscalls,
            gadget,
            modules,
            read_calls: AtomicUsize::new(0),
            features,
            version,
        })
    }
}

// ---------------------------------------------------------------
// DriverInterface impl
// ---------------------------------------------------------------
impl DriverInterface for UserModeDriver {
    fn driver_features(&self) -> DriverFeature {
        self.features
    }

    fn driver_version(&self) -> VersionInfo {
        self.version
    }

    fn total_read_calls(&self) -> usize {
        self.read_calls.load(Ordering::Relaxed)
    }

    fn list_processes(&self) -> IResult<Vec<ProcessInfo>> {
        list_processes_internal(self.gadget, self.syscalls.nt_query_system_information)
    }

    fn list_modules(
        &self,
        _pid: ProcessId,
        _dt: DirectoryTableType,
    ) -> IResult<Vec<ProcessModuleInfo>> {
        Ok(self.modules.clone())
    }

    fn read_bytes(
        &self,
        _pid: ProcessId,
        _dt: DirectoryTableType,
        addr: u64,
        buf: &mut [u8],
    ) -> IResult<()> {
        self.read_calls.fetch_add(1, Ordering::Relaxed);
        // Try indirect syscall first
        if read_mem(&self.syscalls, self.gadget, self.process_handle, addr, buf).is_ok() {
            return Ok(());
        }
        // On Windows 11 26200+ code pages may be unreadable via direct syscall
        // from outside ntdll. Fall back to kernel32!ReadProcessMemory which
        // internally calls NtReadVirtualMemory with the correct return address.
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
        use windows::Win32::Foundation::HANDLE;
        let mut bytes_read: usize = 0;
        unsafe {
            ReadProcessMemory(
                HANDLE(self.process_handle as isize),
                addr as *const _,
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                Some(&mut bytes_read),
            )
        }
        .map_err(|_| InterfaceError::MemoryAccessFailed)
    }

    fn write_bytes(
        &self,
        _pid: ProcessId,
        _dt: DirectoryTableType,
        addr: u64,
        buf: &[u8],
    ) -> IResult<()> {
        let mut bytes_written: u64 = 0;
        let status = unsafe {
            syscall::syscall_5_via_gadget(
                self.gadget,
                self.syscalls.nt_write_virtual_memory,
                self.process_handle,
                addr,
                buf.as_ptr() as u64,
                buf.len() as u64,
                &mut bytes_written as *mut u64 as u64,
            )
        };
        if status < 0 {
            return Err(InterfaceError::MemoryAccessFailed);
        }
        Ok(())
    }

    fn send_keyboard_state(&self, states: &[KeyboardState]) -> IResult<()> {
        for state in states {
            let mut input: INPUT = unsafe { std::mem::zeroed() };
            input.r#type = INPUT_KEYBOARD;
            unsafe {
                input.Anonymous.ki = KEYBDINPUT {
                    wVk: VIRTUAL_KEY(0),
                    wScan: state.scane_code,
                    dwFlags: if state.down {
                        KEYEVENTF_SCANCODE
                    } else {
                        KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP
                    },
                    time: 0,
                    dwExtraInfo: 0,
                };
                SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
            }
        }
        Ok(())
    }

    fn send_mouse_state(&self, states: &[MouseState]) -> IResult<()> {
        for state in states {
            let mut flags: u32 = MOUSEEVENTF_MOVE.0;

            for (i, btn) in state.buttons.iter().enumerate() {
                match (i, btn) {
                    (0, Some(true)) => flags |= MOUSEEVENTF_LEFTDOWN.0,
                    (0, Some(false)) => flags |= MOUSEEVENTF_LEFTUP.0,
                    (1, Some(true)) => flags |= MOUSEEVENTF_RIGHTDOWN.0,
                    (1, Some(false)) => flags |= MOUSEEVENTF_RIGHTUP.0,
                    (2, Some(true)) => flags |= MOUSEEVENTF_MIDDLEDOWN.0,
                    (2, Some(false)) => flags |= MOUSEEVENTF_MIDDLEUP.0,
                    _ => {}
                }
            }

            if state.hwheel {
                flags |= MOUSEEVENTF_HWHEEL.0;
            }
            if state.wheel {
                flags |= MOUSEEVENTF_WHEEL.0;
            }

            let mut input: INPUT = unsafe { std::mem::zeroed() };
            input.r#type = INPUT_MOUSE;
            unsafe {
                input.Anonymous.mi = MOUSEINPUT {
                    dx: state.last_x,
                    dy: state.last_y,
                    mouseData: 0,
                    dwFlags: MOUSE_EVENT_FLAGS(flags),
                    time: 0,
                    dwExtraInfo: 0,
                };
                SendInput(&[input], std::mem::size_of::<INPUT>() as i32);
            }
        }
        Ok(())
    }

    fn toggle_process_protection(&self, _mode: ProcessProtectionMode) -> IResult<()> {
        // no-op — cannot do ObRegisterCallbacks from user-mode
        Ok(())
    }

    fn add_metrics_record(&self, _rt: &str, _rp: &str) -> IResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------
// Process enumeration via indirect NtQuerySystemInformation
// ---------------------------------------------------------------

// SYSTEM_PROCESS_INFORMATION offsets for Windows 10/11 x64:
//   NextEntryOffset: +0x00 (ULONG)
//   ImageName:       +0x38 (UNICODE_STRING)
//   UniqueProcessId: +0x50 (HANDLE/PVOID)

/// Call NtQuerySystemInformation(SystemProcessInformation, 5) via indirect syscall.
fn query_system_process_info(gadget: u64, syscall_num: u32) -> IResult<Vec<u8>> {
    let mut size: u32 = 0x40000; // 256 KB
    loop {
        let mut buf = vec![0u8; size as usize];
        let mut ret_len: u32 = 0;
        let status = unsafe {
            syscall::syscall_4_via_gadget(
                gadget,
                syscall_num,
                5, /* SystemProcessInformation */
                buf.as_mut_ptr() as u64,
                size as u64,
                &mut ret_len as *mut u32 as u64,
            )
        };
        if status >= 0 {
            unsafe { buf.set_len(ret_len as usize) };
            return Ok(buf);
        }
        if status == 0xC000_0004_u32 as i32 {
            // STATUS_INFO_LENGTH_MISMATCH
            size = size.checked_mul(2).unwrap_or(u32::MAX);
            if size > 0x100_0000 {
                return Err(InterfaceError::BufferAllocationFailed);
            }
            continue;
        }
        return Err(InterfaceError::CommandGenericError {
            message: format!("NtQuerySystemInformation failed: 0x{:X}", status as u32),
        });
    }
}

/// Walk SYSTEM_PROCESS_INFORMATION linked list, extract (PID, name) pairs.
fn parse_process_info(data: &[u8]) -> Vec<(u32, String)> {
    let data_base = data.as_ptr() as usize;
    let data_end = data_base + data.len();
    let mut results = Vec::new();
    let mut offset = 0usize;

    while offset + 0x58 <= data.len() {
        let next_entry = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;

        let pid = u64::from_le_bytes([
            data[offset + 0x50],
            data[offset + 0x51],
            data[offset + 0x52],
            data[offset + 0x53],
            data[offset + 0x54],
            data[offset + 0x55],
            data[offset + 0x56],
            data[offset + 0x57],
        ]) as u32;

        let name_len = u16::from_le_bytes([data[offset + 0x38], data[offset + 0x39]]);
        let name_buf = u64::from_le_bytes([
            data[offset + 0x40],
            data[offset + 0x41],
            data[offset + 0x42],
            data[offset + 0x43],
            data[offset + 0x44],
            data[offset + 0x45],
            data[offset + 0x46],
            data[offset + 0x47],
        ]);

        let name = if name_len > 0 && name_buf != 0 {
            let name_ptr = name_buf as usize;
            if name_ptr >= data_base && name_ptr + name_len as usize <= data_end {
                let name_slice =
                    unsafe { std::slice::from_raw_parts(name_buf as *const u8, name_len as usize) };
                let wide: Vec<u16> = name_slice
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                OsString::from_wide(&wide).to_string_lossy().to_string()
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        results.push((pid, name));

        if next_entry == 0 {
            break;
        }
        offset += next_entry;
    }
    results
}

fn find_cs2_process(gadget: u64, syscall_num: u32) -> IResult<ProcessId> {
    let data = query_system_process_info(gadget, syscall_num)?;
    for (pid, name) in parse_process_info(&data) {
        if name.to_lowercase() == "cs2.exe" {
            return Ok(pid);
        }
    }
    Err(InterfaceError::ProcessUnknown)
}

fn list_processes_internal(gadget: u64, syscall_num: u32) -> IResult<Vec<ProcessInfo>> {
    let data = query_system_process_info(gadget, syscall_num)?;
    let mut processes = Vec::new();
    for (pid, name) in parse_process_info(&data) {
        let mut info = ProcessInfo::default();
        info.process_id = pid;
        info.set_image_base_name(&name);
        processes.push(info);
    }
    Ok(processes)
}

// ---------------------------------------------------------------
// PEB-based module enumeration via indirect syscalls
// ---------------------------------------------------------------

/// PROCESS_BASIC_INFORMATION for NtQueryInformationProcess
#[repr(C)]
struct ProcessBasicInformation {
    exit_status: i32,
    peb_base_address: u64,
    affinity_mask: u64,
    base_priority: i32,
    unique_process_id: u64,
    inherited_from_unique_process_id: u64,
}

/// Minimal PEB layout (x64) — we only need Ldr at offset 0x18
#[repr(C)]
struct PebPartial {
    _pad0: [u8; 0x18],
    ldr: u64, // PPEB_LDR_DATA
}

/// Minimal PEB_LDR_DATA layout (x64) — we only need InLoadOrderModuleList at 0x10
#[repr(C)]
struct PebLdrPartial {
    _pad0: [u8; 0x10],
    in_load_order_module_list: ListEntry,
}

#[repr(C)]
struct ListEntry {
    flink: u64,
    blink: u64,
}

/// LDR_DATA_TABLE_ENTRY partial (x64) — enough to read DllBase, SizeOfImage, BaseDllName
#[repr(C)]
struct LdrEntryPartial {
    in_load_order_links: ListEntry,   // 0x00
    in_memory_order_links: ListEntry, // 0x10
    in_init_order_links: ListEntry,   // 0x20
    dll_base: u64,                    // 0x30
    entry_point: u64,                 // 0x38
    size_of_image: u32,               // 0x40
    _pad1: [u8; 4],                   // 0x44
    full_dll_name: UnicodeString,     // 0x48
    base_dll_name: UnicodeString,     // 0x58
}

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: u64, // PWSTR
}

fn read_mem(
    syscalls: &syscall::SyscallTable,
    gadget: u64,
    handle: u64,
    addr: u64,
    buf: &mut [u8],
) -> IResult<()> {
    let mut bytes_read: u64 = 0;
    let status = unsafe {
        syscall::syscall_5_via_gadget(
            gadget,
            syscalls.nt_read_virtual_memory,
            handle,
            addr,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            &mut bytes_read as *mut u64 as u64,
        )
    };
    if status < 0 {
        return Err(InterfaceError::MemoryAccessFailed);
    }
    Ok(())
}

fn enumerate_modules_via_peb(
    syscalls: &syscall::SyscallTable,
    gadget: u64,
    handle: u64,
) -> IResult<Vec<ProcessModuleInfo>> {
    // 1. Get PEB address via NtQueryInformationProcess
    let mut pbi = ProcessBasicInformation {
        exit_status: 0,
        peb_base_address: 0,
        affinity_mask: 0,
        base_priority: 0,
        unique_process_id: 0,
        inherited_from_unique_process_id: 0,
    };
    let mut ret_len: u64 = 0;

    let status = unsafe {
        syscall::syscall_5_via_gadget(
            gadget,
            syscalls.nt_query_information_process,
            handle,
            0, // ProcessBasicInformation
            &mut pbi as *mut _ as u64,
            std::mem::size_of::<ProcessBasicInformation>() as u64,
            &mut ret_len as *mut u64 as u64,
        )
    };
    if status < 0 {
        return Err(InterfaceError::CommandGenericError {
            message: format!("NtQueryInformationProcess failed: 0x{:X}", status as u32),
        });
    }
    if pbi.peb_base_address == 0 {
        return Err(InterfaceError::CommandGenericError {
            message: "PEB address is null".into(),
        });
    }

    // 2. Read PEB → Ldr pointer
    let mut peb = PebPartial {
        _pad0: [0u8; 0x18],
        ldr: 0,
    };
    read_mem(syscalls, gadget, handle, pbi.peb_base_address, unsafe {
        std::slice::from_raw_parts_mut(
            &mut peb as *mut _ as *mut u8,
            std::mem::size_of::<PebPartial>(),
        )
    })?;

    if peb.ldr == 0 {
        return Err(InterfaceError::InvalidResponse);
    }

    // 3. Read PEB_LDR_DATA → InLoadOrderModuleList
    let mut ldr_data = PebLdrPartial {
        _pad0: [0u8; 0x10],
        in_load_order_module_list: ListEntry { flink: 0, blink: 0 },
    };
    read_mem(syscalls, gadget, handle, peb.ldr, unsafe {
        std::slice::from_raw_parts_mut(
            &mut ldr_data as *mut _ as *mut u8,
            std::mem::size_of::<PebLdrPartial>(),
        )
    })?;

    // InLoadOrderModuleList.Flink is the first real entry
    let mut current = ldr_data.in_load_order_module_list.flink;
    let list_head = peb.ldr + 0x10; // address of the list head sentinel

    // 4. Walk the linked list
    let mut modules: Vec<ProcessModuleInfo> = Vec::new();
    // Safety valve — max 256 modules
    for _ in 0..256 {
        if current == list_head || current == 0 {
            break;
        }

        let mut entry: LdrEntryPartial = unsafe { std::mem::zeroed() };
        read_mem(syscalls, gadget, handle, current, unsafe {
            std::slice::from_raw_parts_mut(
                &mut entry as *mut _ as *mut u8,
                std::mem::size_of::<LdrEntryPartial>(),
            )
        })?;

        if entry.dll_base == 0 {
            current = entry.in_load_order_links.flink;
            continue;
        }

        // Read BaseDllName from target process
        let mut dll_name_buf = vec![0u8; entry.base_dll_name.length as usize];
        if !dll_name_buf.is_empty() {
            let _ = read_mem(
                syscalls,
                gadget,
                handle,
                entry.base_dll_name.buffer,
                &mut dll_name_buf,
            );
        }

        let dll_name_ucs2: Vec<u16> = dll_name_buf
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let dll_name_str = OsString::from_wide(&dll_name_ucs2)
            .to_string_lossy()
            .to_string();

        let mut mod_info = ProcessModuleInfo::default();
        mod_info.base_address = entry.dll_base;
        mod_info.module_size = entry.size_of_image as u64;
        mod_info.set_base_dll_name(
            std::path::Path::new(&dll_name_str)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&dll_name_str),
        );

        modules.push(mod_info);

        current = entry.in_load_order_links.flink;
    }

    Ok(modules)
}
