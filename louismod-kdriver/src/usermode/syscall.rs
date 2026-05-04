use std::fs;

use windows::Win32::System::LibraryLoader::GetModuleHandleA;

use crate::error::{
    IResult,
    InterfaceError,
};

// ---------------------------------------------------------------
// Syscall numbers extracted from a clean ntdll.dll
// ---------------------------------------------------------------
#[allow(dead_code)]
pub struct SyscallTable {
    pub nt_read_virtual_memory: u32,
    pub nt_write_virtual_memory: u32,
    pub nt_query_system_information: u32,
    pub nt_open_process: u32,
    pub nt_query_information_process: u32,
}

/// Read ntdll.dll from disk and extract the syscall numbers we need.
pub fn load_syscall_table() -> IResult<SyscallTable> {
    let sys_dir = system_directory()?;
    let ntdll_path = format!("{}\\ntdll.dll", sys_dir);

    let data = fs::read(&ntdll_path).map_err(|e| InterfaceError::CommandGenericError {
        message: format!("Failed to read {}: {}", ntdll_path, e),
    })?;

    if data.len() < 0x1000 {
        return Err(InterfaceError::InvalidResponse);
    }

    // DOS header
    let e_magic = u16::from_le_bytes([data[0], data[1]]);
    if e_magic != 0x5A4D {
        return Err(InterfaceError::CommandGenericError {
            message: "Invalid DOS header in ntdll.dll".into(),
        });
    }
    let e_lfanew = i32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;

    // NT headers
    if e_lfanew + 0x18 + 8 > data.len() {
        return Err(InterfaceError::InvalidResponse);
    }
    let pe_sig = u32::from_le_bytes([
        data[e_lfanew],
        data[e_lfanew + 1],
        data[e_lfanew + 2],
        data[e_lfanew + 3],
    ]);
    if pe_sig != 0x0000_4550 {
        return Err(InterfaceError::CommandGenericError {
            message: "Invalid PE signature in ntdll.dll".into(),
        });
    }

    // IMAGE_FILE_HEADER is 20 bytes starting at e_lfanew + 4
    let file_header_offset = e_lfanew + 4;
    let size_of_optional_header =
        u16::from_le_bytes([data[file_header_offset + 16], data[file_header_offset + 17]]) as usize;

    // Optional header starts after file header
    let optional_header_offset = file_header_offset + 20;

    // Check PE32+ magic
    let pe_magic = u16::from_le_bytes([
        data[optional_header_offset],
        data[optional_header_offset + 1],
    ]);
    if pe_magic != 0x020B {
        // PE32+
        return Err(InterfaceError::CommandGenericError {
            message: "ntdll.dll is not PE32+".into(),
        });
    }

    // Data directory[0] (export directory) is at a fixed offset in optional header
    // For PE32+, export dir RVA is at optional_header_offset + 112 (0x70)
    let data_dir_offset = optional_header_offset + 112;
    if data_dir_offset + 8 > data.len() {
        return Err(InterfaceError::InvalidResponse);
    }
    let export_rva = u32::from_le_bytes([
        data[data_dir_offset],
        data[data_dir_offset + 1],
        data[data_dir_offset + 2],
        data[data_dir_offset + 3],
    ]);
    let export_size = u32::from_le_bytes([
        data[data_dir_offset + 4],
        data[data_dir_offset + 5],
        data[data_dir_offset + 6],
        data[data_dir_offset + 7],
    ]);

    if export_rva == 0 || export_size == 0 {
        return Err(InterfaceError::CommandGenericError {
            message: "No export directory in ntdll.dll".into(),
        });
    }

    // Resolve RVA to file offset (walk sections)
    let sections_offset = optional_header_offset + size_of_optional_header;
    let export_offset = rva_to_offset(&data, sections_offset, export_rva)?;

    // Read IMAGE_EXPORT_DIRECTORY
    // struct: Characteristics(4) + TimeDateStamp(4) + MajorVersion(2) + MinorVersion(2)
    //   + Name(4) + Base(4) + NumberOfFunctions(4) + NumberOfNames(4)
    //   + AddressOfFunctions(4) + AddressOfNames(4) + AddressOfNameOrdinals(4) = 40 bytes
    //
    // Offsets (decimal):
    //   0: Characteristics    4: TimeDateStamp     8: MajorVersion
    //  10: MinorVersion       12: Name             16: Base
    //  20: NumberOfFunctions  24: NumberOfNames    28: AddressOfFunctions
    //  32: AddressOfNames     36: AddressOfNameOrdinals
    let exp = export_offset;
    let number_of_functions = u32::from_le_bytes([
        data[exp + 20],
        data[exp + 21],
        data[exp + 22],
        data[exp + 23],
    ]);
    let number_of_names = u32::from_le_bytes([
        data[exp + 24],
        data[exp + 25],
        data[exp + 26],
        data[exp + 27],
    ]);
    let address_of_functions = u32::from_le_bytes([
        data[exp + 28],
        data[exp + 29],
        data[exp + 30],
        data[exp + 31],
    ]);
    let address_of_names = u32::from_le_bytes([
        data[exp + 32],
        data[exp + 33],
        data[exp + 34],
        data[exp + 35],
    ]);
    let address_of_name_ordinals = u32::from_le_bytes([
        data[exp + 36],
        data[exp + 37],
        data[exp + 38],
        data[exp + 39],
    ]);
    let func_rva = rva_to_offset(&data, sections_offset, address_of_functions)?;
    let name_rva = rva_to_offset(&data, sections_offset, address_of_names)?;
    let ord_rva = rva_to_offset(&data, sections_offset, address_of_name_ordinals)?;

    // Names we're looking for
    let targets: [(&str, u32); 5] = [
        ("NtReadVirtualMemory", 0),
        ("NtWriteVirtualMemory", 0),
        ("NtQuerySystemInformation", 0),
        ("NtOpenProcess", 0),
        ("NtQueryInformationProcess", 0),
    ];
    let mut found = [0u32; 5];
    let mut found_mask = 0u32;

    // Scan the name pointer table
    for i in 0..number_of_names {
        let idx = i as usize;
        let name_ptr_offset = name_rva + idx * 4;
        if name_ptr_offset + 4 > data.len() {
            break;
        }
        let name_rva_val = u32::from_le_bytes([
            data[name_ptr_offset],
            data[name_ptr_offset + 1],
            data[name_ptr_offset + 2],
            data[name_ptr_offset + 3],
        ]);
        let name_offset = match rva_to_offset(&data, sections_offset, name_rva_val) {
            Ok(off) => off,
            Err(_) => continue,
        };

        // Read the function name as C string
        let name_end = data[name_offset..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(0);
        if name_end == 0 {
            continue;
        }
        let name = &data[name_offset..name_offset + name_end];
        let name_str = std::str::from_utf8(name).unwrap_or("");

        // Check if it's one of our targets
        for (ti, target_name) in targets.iter().enumerate() {
            if (found_mask >> ti) & 1 != 0 {
                continue; // already found
            }
            if name_str == target_name.0 {
                // Get ordinal
                if idx * 2 + 2 > data.len().saturating_sub(ord_rva) {
                    break;
                }
                let ordinal =
                    u16::from_le_bytes([data[ord_rva + idx * 2], data[ord_rva + idx * 2 + 1]]);
                if (ordinal as usize) < number_of_functions as usize {
                    let func_offset = func_rva + (ordinal as usize) * 4;
                    if func_offset + 4 <= data.len() {
                        let func_rva_val = u32::from_le_bytes([
                            data[func_offset],
                            data[func_offset + 1],
                            data[func_offset + 2],
                            data[func_offset + 3],
                        ]);
                        // Resolve function RVA to file offset and read syscall number
                        if let Ok(stub_offset) = rva_to_offset(&data, sections_offset, func_rva_val)
                        {
                            // Search for `mov eax, imm32` (0xB8) within first 32 bytes of stub.
                            // On older Windows, it's at offset 0; on newer builds (Win11 26200+),
                            // there's a `mov r10, rcx` (0x4C 0x8B 0xD1) before it.
                            let stub_max = (stub_offset + 32).min(data.len());
                            for si in stub_offset..stub_max.saturating_sub(5) {
                                if data[si] == 0xB8 {
                                    let sysnum = u32::from_le_bytes([
                                        data[si + 1], data[si + 2], data[si + 3], data[si + 4],
                                    ]);
                                    log::debug!("  found syscall {} = 0x{:X} (at stub offset +{})", target_name.0, sysnum, si - stub_offset);
                                    found[ti] = sysnum;
                                    found_mask |= 1 << ti;
                                    break;
                                }
                            }
                        }
                    }
                }
                break;
            }
        }
    }

    // Verify we found all 5
    if found_mask != 0b11111 {
        let missing: Vec<&str> = targets
            .iter()
            .enumerate()
            .filter(|(i, _)| (found_mask >> i) & 1 == 0)
            .map(|(_, t)| t.0)
            .collect();
        return Err(InterfaceError::CommandGenericError {
            message: format!("Failed to find syscall numbers for: {:?}", missing),
        });
    }

    Ok(SyscallTable {
        nt_read_virtual_memory: found[0],
        nt_write_virtual_memory: found[1],
        nt_query_system_information: found[2],
        nt_open_process: found[3],
        nt_query_information_process: found[4],
    })
}

// ---------------------------------------------------------------
// NtOpenProcess types (indirect syscall — bypass kernel32/ntdll hooks)
// ---------------------------------------------------------------

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: u64,
    object_name: u64,
    attributes: u32,
    security_descriptor: u64,
    security_quality_of_service: u64,
}

#[repr(C)]
struct ClientId {
    unique_process: u64,
    unique_thread: u64,
}

/// Open a process handle via indirect NtOpenProcess syscall (with gadget if available).
pub fn nt_open_process_via_gadget(
    gadget: u64,
    syscall_num: u32,
    pid: u32,
    desired_access: u32,
) -> IResult<u64> {
    let mut handle: u64 = 0;
    let mut oa = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: 0,
        object_name: 0,
        attributes: 0,
        security_descriptor: 0,
        security_quality_of_service: 0,
    };
    let mut cid = ClientId {
        unique_process: pid as u64,
        unique_thread: 0,
    };

    let status = unsafe {
        syscall_4_via_gadget(
            gadget,
            syscall_num,
            &mut handle as *mut u64 as u64,
            desired_access as u64,
            &mut oa as *mut ObjectAttributes as u64,
            &mut cid as *mut ClientId as u64,
        )
    };
    if status < 0 {
        return Err(InterfaceError::CommandGenericError {
            message: format!("NtOpenProcess failed on PID {}: 0x{:X}", pid, status as u32),
        });
    }
    Ok(handle)
}

// ---------------------------------------------------------------
// Syscall-return-address camouflage: jump to ntdll's syscall;ret
// ---------------------------------------------------------------

/// Find a `syscall; ret` (0x0F 0x05 0xC3) gadget in already-loaded ntdll.dll.
///
/// We jump to this gadget instead of executing `syscall` inline, so the kernel
/// records the syscall instruction address as belonging to ntdll.dll — not our
/// own module.
pub fn find_syscall_ret_gadget() -> IResult<u64> {
    unsafe {
        let ntdll = GetModuleHandleA(windows::core::s!("ntdll.dll")).map_err(|e| {
            InterfaceError::CommandGenericError {
                message: format!("GetModuleHandleA(ntdll) failed: {}", e),
            }
        })?;

        let base = ntdll.0 as *const u8;
        let data = std::slice::from_raw_parts(base, 0x200000); // ntdll is < 2 MB

        // DOS header
        if data.len() < 0x40 {
            return Err(InterfaceError::InvalidResponse);
        }
        let e_lfanew =
            i32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;

        // NT headers → optional header → section count
        let file_header_offset = e_lfanew + 4;
        let num_sections =
            u16::from_le_bytes([data[file_header_offset + 2], data[file_header_offset + 3]])
                as usize;
        let size_of_optional_header =
            u16::from_le_bytes([data[file_header_offset + 16], data[file_header_offset + 17]])
                as usize;

        let sections_offset = file_header_offset + 20 + size_of_optional_header;

        // Walk section headers to find .text
        const SECTION_HEADER_SIZE: usize = 40;
        for i in 0..num_sections {
            let shdr = sections_offset + i * SECTION_HEADER_SIZE;
            if shdr + SECTION_HEADER_SIZE > data.len() {
                break;
            }
            let name = std::str::from_utf8(&data[shdr..shdr + 8]).unwrap_or("");
            if name.starts_with(".text") {
                let virtual_address = u32::from_le_bytes([
                    data[shdr + 12],
                    data[shdr + 13],
                    data[shdr + 14],
                    data[shdr + 15],
                ]);
                let virtual_size = u32::from_le_bytes([
                    data[shdr + 8],
                    data[shdr + 9],
                    data[shdr + 10],
                    data[shdr + 11],
                ]);

                let text_start = base.add(virtual_address as usize);
                let text_size = virtual_size as usize;
                let text_bytes = std::slice::from_raw_parts(text_start, text_size.min(0x100000));

                // Scan for 0x0F 0x05 0xC3 (syscall; ret)
                let needle: [u8; 3] = [0x0F, 0x05, 0xC3];
                for j in 0..text_bytes.len().saturating_sub(2) {
                    if text_bytes[j] == needle[0]
                        && text_bytes[j + 1] == needle[1]
                        && text_bytes[j + 2] == needle[2]
                    {
                        return Ok(text_start.add(j) as u64);
                    }
                }
                break;
            }
        }

        Err(InterfaceError::CommandGenericError {
            message: "syscall;ret gadget not found in ntdll .text".into(),
        })
    }
}

/// Combined initialization: load syscall numbers + find camouflage gadget.
///
/// Returns (SyscallTable, gadget_addr). gadget_addr is 0 if gadget lookup failed,
/// signalling the caller to fall back to direct inline syscalls.
pub fn load_syscall_data() -> IResult<(SyscallTable, u64)> {
    let table = load_syscall_table()?;
    let gadget = find_syscall_ret_gadget().unwrap_or_else(|e| {
        log::warn!("syscall;ret gadget not found ({}), using direct syscall", e);
        0
    });
    Ok((table, gadget))
}

/// Perform a 4-argument indirect syscall via the ntdll gadget.
///
/// If `gadget` is 0, falls back to direct inline syscall.
///
/// # Safety
/// Arguments and syscall number must be valid for the target syscall.
#[inline(never)]
pub unsafe fn syscall_4_via_gadget(
    gadget: u64,
    number: u32,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
) -> i32 {
    if gadget == 0 {
        return syscall_4(number, arg1, arg2, arg3, arg4);
    }
    let status: i32;
    core::arch::asm!(
        "mov r10, rcx",
        "call {gadget}",
        gadget = in(reg) gadget,
        in("eax") number,
        in("rcx") arg1,
        in("rdx") arg2,
        in("r8")  arg3,
        in("r9")  arg4,
        lateout("eax") status,
        options(nostack),
    );
    status
}

/// Perform a 5-argument indirect syscall via the ntdll gadget.
///
/// Copies arg5 from [rsp+0x28] to [rsp+0x20] before the call so that after
/// `call` (which decrements rsp by 8) it lands at [rsp+0x28] from the
/// gadget's perspective, exactly where the kernel expects it.
///
/// If `gadget` is 0, falls back to direct inline syscall.
///
/// # Safety
/// Arguments and syscall number must be valid for the target syscall.
#[inline(never)]
pub unsafe fn syscall_5_via_gadget(
    gadget: u64,
    number: u32,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    _arg5: u64,
) -> i32 {
    if gadget == 0 {
        return syscall_5(number, arg1, arg2, arg3, arg4, _arg5);
    }
    let status: i32;
    core::arch::asm!(
        "mov rax, [rsp + 0x28]",
        "mov [rsp + 0x20], rax",
        "mov r10, rcx",
        "call {gadget}",
        gadget = in(reg) gadget,
        in("eax") number,
        in("rcx") arg1,
        in("rdx") arg2,
        in("r8")  arg3,
        in("r9")  arg4,
        lateout("eax") status,
        options(nostack),
    );
    status
}

/// Walk section headers to convert a relative virtual address to a file offset.
///
/// Handles the PE header area specially: if the RVA falls before the first
/// section's VirtualAddress, it's in the header area where file offset == RVA.
fn rva_to_offset(data: &[u8], sections_offset: usize, rva: u32) -> IResult<usize> {
    const SECTION_HEADER_SIZE: usize = 40;

    for i in 0..96 {
        let shdr = sections_offset + i * SECTION_HEADER_SIZE;
        if shdr + SECTION_HEADER_SIZE > data.len() {
            break;
        }
        let virtual_size = u32::from_le_bytes([
            data[shdr + 8],
            data[shdr + 9],
            data[shdr + 10],
            data[shdr + 11],
        ]);
        let virtual_address = u32::from_le_bytes([
            data[shdr + 12],
            data[shdr + 13],
            data[shdr + 14],
            data[shdr + 15],
        ]);
        let size_of_raw_data = u32::from_le_bytes([
            data[shdr + 16],
            data[shdr + 17],
            data[shdr + 18],
            data[shdr + 19],
        ]);
        let pointer_to_raw_data = u32::from_le_bytes([
            data[shdr + 20],
            data[shdr + 21],
            data[shdr + 22],
            data[shdr + 23],
        ]);

        // On first section, check if RVA falls in header area (before first section)
        if i == 0 && rva < virtual_address {
            // Header area: PE headers are mapped at RVA 0 with the same layout as file
            let offset = rva as usize;
            if offset < data.len() {
                return Ok(offset);
            }
        }

        let section_limit = virtual_size.max(size_of_raw_data);
        if section_limit == 0 {
            continue;
        }
        if rva >= virtual_address && rva < virtual_address + section_limit {
            let offset = (rva - virtual_address) as usize + pointer_to_raw_data as usize;
            if offset < data.len() {
                return Ok(offset);
            }
        }
    }

    Err(InterfaceError::CommandGenericError {
        message: format!("RVA 0x{:X} not found in any section", rva),
    })
}

// ---------------------------------------------------------------
// Indirect syscall wrappers (inline asm, x64)
// ---------------------------------------------------------------

/// Perform a 4-argument indirect syscall.
///
/// # Safety
/// Arguments and syscall number must be valid for the target syscall.
#[inline(never)]
#[allow(dead_code)]
pub unsafe fn syscall_4(number: u32, arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> i32 {
    let status: i32;
    core::arch::asm!(
        "mov r10, rcx",
        "syscall",
        in("eax") number,
        in("rcx") arg1,
        in("rdx") arg2,
        in("r8")  arg3,
        in("r9")  arg4,
        lateout("eax") status,
        out("r11") _,
        options(nostack),
    );
    status
}

/// Perform a 5-argument indirect syscall.
///
/// The 5th argument must already be on the stack per the x64 calling convention.
///
/// # Safety
/// Arguments and syscall number must be valid for the target syscall.
#[inline(never)]
pub unsafe fn syscall_5(
    number: u32,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    _arg5: u64,
) -> i32 {
    let status: i32;
    core::arch::asm!(
        "mov r10, rcx",
        "syscall",
        in("eax") number,
        in("rcx") arg1,
        in("rdx") arg2,
        in("r8")  arg3,
        in("r9")  arg4,
        // arg5 is on the stack at [rsp+0x28] — already placed there by caller
        lateout("eax") status,
        out("r11") _,
        options(nostack),
    );
    status
}

/// Convenience wrapper: NtReadVirtualMemory via indirect syscall.
///
/// # Safety
/// Handle must be a valid process handle with VM_READ access.
#[allow(dead_code)]
pub unsafe fn nt_read_virtual_memory(
    syscall_number: u32,
    process_handle: u64,
    base_address: u64,
    buffer: *mut u8,
    size: u64,
    bytes_read: *mut u64,
) -> i32 {
    syscall_5(
        syscall_number,
        process_handle,
        base_address,
        buffer as u64,
        size,
        bytes_read as u64,
    )
}

/// Convenience wrapper: NtWriteVirtualMemory via indirect syscall.
///
/// # Safety
/// Handle must be a valid process handle with VM_WRITE access.
#[allow(dead_code)]
pub unsafe fn nt_write_virtual_memory(
    syscall_number: u32,
    process_handle: u64,
    base_address: u64,
    buffer: *const u8,
    size: u64,
    bytes_written: *mut u64,
) -> i32 {
    syscall_5(
        syscall_number,
        process_handle,
        base_address,
        buffer as u64,
        size,
        bytes_written as u64,
    )
}

/// Get the system directory path (e.g. "C:\\Windows\\System32").
fn system_directory() -> IResult<String> {
    // Use the standard environment variable
    std::env::var("SystemRoot")
        .or_else(|_| std::env::var("WINDIR"))
        .map(|root| format!("{}\\System32", root))
        .map_err(|_| InterfaceError::CommandGenericError {
            message: "Failed to determine system directory".into(),
        })
}
