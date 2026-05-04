use crate::{
    error::{
        IResult,
        InterfaceError,
    },
    types::*,
};

// ------------------------------------------------------------
// Wire protocol constants (must match driver/driver.h)
// ------------------------------------------------------------
pub const WIRE_HEADER_SIZE: usize = 8;
pub const LOUISMOD_PROTOCOL_VERSION: u32 = 0x01;

// Command IDs
pub const CMD_INIT: u32 = 0x00;
pub const CMD_PROCESS_LIST: u32 = 0x01;
pub const CMD_MODULE_LIST: u32 = 0x02;
pub const CMD_READ_MEMORY: u32 = 0x03;
pub const CMD_WRITE_MEMORY: u32 = 0x04;
pub const CMD_MOUSE_INPUT: u32 = 0x05;
pub const CMD_KEYBOARD_INPUT: u32 = 0x06;
pub const CMD_PROTECT_PROCESS: u32 = 0x07;
pub const CMD_CR3_ENABLE: u32 = 0x08;
pub const CMD_CR3_DISABLE: u32 = 0x09;
pub const CMD_BATCH_READ: u32 = 0x0A;

// Batch read limits
pub const BATCH_MAX_ENTRIES: usize = 64;
pub const BATCH_MAX_ENTRY_SIZE: u32 = 4096;

// Feature flags (must match driver.h)
pub const FEATURE_PROCESS_LIST: u64 = 0x0000_0001;
pub const FEATURE_PROCESS_MODULES: u64 = 0x0000_0002;
pub const FEATURE_MEMORY_READ: u64 = 0x0000_0100;
pub const FEATURE_MEMORY_WRITE: u64 = 0x0000_0200;
pub const FEATURE_INPUT_KEYBOARD: u64 = 0x0001_0000;
pub const FEATURE_INPUT_MOUSE: u64 = 0x0002_0000;
pub const FEATURE_CR3: u64 = 0x0100_0000;

// Max entries
pub const PROCESS_NAME_MAX: usize = 32;
pub const MODULE_NAME_MAX: usize = 64;
pub const MOUSE_BUTTON_MAX: usize = 5;
pub const KEYBOARD_MAX_KEYS: usize = 256;

// ------------------------------------------------------------
// XOR payload encryption (must match driver.h)
// ------------------------------------------------------------
fn xor_payload(data: &mut [u8], key: u32) {
    for i in 0..data.len() {
        data[i] ^= ((key + i as u32) & 0xFF) as u8;
    }
}

// ------------------------------------------------------------
// Request/Response builder
// ------------------------------------------------------------
pub fn build_request(command_id: u32, payload: &[u8]) -> Vec<u8> {
    let xor_key = rand_key();
    let mut packet = Vec::with_capacity(WIRE_HEADER_SIZE + payload.len());

    // Header: command_id + xor_key
    packet.extend_from_slice(&command_id.to_le_bytes());
    packet.extend_from_slice(&xor_key.to_le_bytes());

    // Payload
    if !payload.is_empty() {
        let mut enc_payload = payload.to_vec();
        xor_payload(&mut enc_payload, xor_key);
        packet.extend_from_slice(&enc_payload);
    }

    packet
}

pub fn parse_response<T>(
    response: &[u8],
    xor_key: u32,
    parser: fn(&[u8]) -> IResult<T>,
) -> IResult<T> {
    if response.len() < WIRE_HEADER_SIZE {
        return Err(InterfaceError::InvalidResponse);
    }

    let status = i32::from_le_bytes([response[0], response[1], response[2], response[3]]);
    let resp_key = u32::from_le_bytes([response[4], response[5], response[6], response[7]]);

    // Verify XOR key (should match what we sent)
    if resp_key != xor_key {
        log::warn!("XOR key mismatch in response");
    }

    if status < 0 {
        // NTSTATUS error
        return Err(ntstatus_to_error(status));
    }

    let payload = &response[WIRE_HEADER_SIZE..];
    if payload.is_empty() {
        return parser(&[]);
    }

    let mut dec_payload = payload.to_vec();
    xor_payload(&mut dec_payload, resp_key);
    parser(&dec_payload)
}

// ------------------------------------------------------------
// Random XOR key generator (thread-safe via AtomicU64)
// ------------------------------------------------------------
use std::sync::atomic::AtomicU64;

static SEED: AtomicU64 = AtomicU64::new(0);

fn rand_key() -> u32 {
    let current = SEED.load(std::sync::atomic::Ordering::Relaxed);
    if current == 0 {
        // Initialize from QPC
        let mut freq: i64 = 0;
        let mut count: i64 = 0;
        unsafe {
            let _ = windows::Win32::System::Performance::QueryPerformanceFrequency(&mut freq);
            let _ = windows::Win32::System::Performance::QueryPerformanceCounter(&mut count);
        }
        let seed = (count as u64) ^ (freq as u64);
        SEED.store(seed, std::sync::atomic::Ordering::Relaxed);
    }
    // LCG: advance the seed
    let old = SEED.load(std::sync::atomic::Ordering::Relaxed);
    let new = old
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    SEED.store(new, std::sync::atomic::Ordering::Relaxed);
    (new >> 32) as u32
}

// ------------------------------------------------------------
// NTSTATUS to InterfaceError conversion
// ------------------------------------------------------------
pub(crate) fn ntstatus_to_error(status: i32) -> InterfaceError {
    match status {
        -0x3FFFFFFF => InterfaceError::MemoryAccessFailed, // STATUS_UNSUCCESSFUL
        -0x40000005 => InterfaceError::BufferAllocationFailed, // STATUS_INSUFFICIENT_RESOURCES
        -0x3FFFFFB4 => InterfaceError::MemoryAccessFailed, // STATUS_PARTIAL_COPY
        -0x3FFFFFDE => InterfaceError::FeatureUnsupported, // STATUS_NOT_IMPLEMENTED
        _ => {
            if status < 0 {
                InterfaceError::CommandGenericError {
                    message: format!("NTSTATUS error: 0x{:08X}", status as u32),
                }
            } else {
                InterfaceError::CommandGenericError {
                    message: format!("Unknown error: {}", status),
                }
            }
        }
    }
}

// ------------------------------------------------------------
// Command-specific serialization
// ------------------------------------------------------------

// Init reply
pub fn parse_init_reply(data: &[u8]) -> IResult<(u32, u16, u16, u64)> {
    if data.len() < 16 {
        return Err(InterfaceError::InvalidResponse);
    }
    let protocol_version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let driver_major = u16::from_le_bytes([data[4], data[5]]);
    let driver_minor = u16::from_le_bytes([data[6], data[7]]);
    let features = u64::from_le_bytes([
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
    ]);

    Ok((protocol_version, driver_major, driver_minor, features))
}

// Process list
pub fn parse_process_list(data: &[u8]) -> IResult<Vec<ProcessInfo>> {
    if data.len() < 4 {
        return Ok(Vec::new());
    }

    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let entry_size = 4 + PROCESS_NAME_MAX * 2; // pid(u32) + WCHAR name
    let mut processes = Vec::with_capacity(count);

    for i in 0..count {
        let offset = 4 + i * entry_size;
        if offset + entry_size > data.len() {
            break;
        }

        let pid = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);

        // Read WCHAR name and convert to UTF-8 buffer
        let mut name_bytes = [0u8; PROCESS_NAME_MAX];
        for j in 0..PROCESS_NAME_MAX {
            let char_offset = offset + 4 + j * 2;
            if char_offset + 2 <= data.len() {
                let wc = u16::from_le_bytes([data[char_offset], data[char_offset + 1]]);
                name_bytes[j] = if wc < 128 { wc as u8 } else { b'?' };
            }
        }

        let mut info = ProcessInfo::default();
        info.process_id = pid;
        info.set_image_base_name(
            std::str::from_utf8(&name_bytes)
                .unwrap_or("unknown")
                .trim_end_matches('\0'),
        );

        processes.push(info);
    }

    Ok(processes)
}

// Module list request
pub fn build_module_list_req(process_id: ProcessId) -> Vec<u8> {
    process_id.to_le_bytes().to_vec()
}

pub fn parse_module_list(data: &[u8]) -> IResult<Vec<ProcessModuleInfo>> {
    if data.len() < 4 {
        return Ok(Vec::new());
    }

    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let entry_size = 8 + 8 + MODULE_NAME_MAX * 2; // base(u64) + size(u64) + WCHAR name
    let mut modules = Vec::with_capacity(count);

    for i in 0..count {
        let offset = 4 + i * entry_size;
        if offset + entry_size > data.len() {
            break;
        }

        let base = u64::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);

        let size = u64::from_le_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
            data[offset + 12],
            data[offset + 13],
            data[offset + 14],
            data[offset + 15],
        ]);

        // Extract DLL name from full path
        let mut name_bytes = [0u8; MODULE_NAME_MAX];
        for j in 0..MODULE_NAME_MAX {
            let char_offset = offset + 16 + j * 2;
            if char_offset + 2 <= data.len() {
                let wc = u16::from_le_bytes([data[char_offset], data[char_offset + 1]]);
                name_bytes[j] = if wc < 128 { wc as u8 } else { b'?' };
            }
        }

        let name_str = std::str::from_utf8(&name_bytes)
            .unwrap_or("")
            .trim_end_matches('\0');

        // Extract just the DLL filename from full path
        let dll_name = name_str
            .split('\\')
            .last()
            .unwrap_or(name_str)
            .split('/')
            .last()
            .unwrap_or(name_str);

        let mut info = ProcessModuleInfo::default();
        info.base_address = base;
        info.module_size = size;
        info.set_base_dll_name(dll_name);

        modules.push(info);
    }

    Ok(modules)
}

// Memory read request
pub fn build_read_req(process_id: ProcessId, address: u64, size: u32) -> Vec<u8> {
    let mut req = Vec::with_capacity(4 + 8 + 4);
    req.extend_from_slice(&process_id.to_le_bytes());
    req.extend_from_slice(&address.to_le_bytes());
    req.extend_from_slice(&size.to_le_bytes());
    req
}

// Memory write request
pub fn build_write_req(process_id: ProcessId, address: u64, data: &[u8]) -> Vec<u8> {
    let size = data.len() as u32;
    let mut req = Vec::with_capacity(4 + 8 + 4 + data.len());
    req.extend_from_slice(&process_id.to_le_bytes());
    req.extend_from_slice(&address.to_le_bytes());
    req.extend_from_slice(&size.to_le_bytes());
    req.extend_from_slice(data);
    req
}

// Mouse input
pub fn build_mouse_input(states: &[MouseState]) -> Vec<u8> {
    let count = states.len().min(1); // kernel expects at most 1 state packet
    if count == 0 {
        return Vec::new();
    }

    let s = &states[0];
    // Encode buttons: 0=none, 1=press, 2=release
    let mut packet = Vec::with_capacity(2 * MOUSE_BUTTON_MAX + 2 + 2 + 2);
    for i in 0..MOUSE_BUTTON_MAX {
        let val = match s.buttons.get(i) {
            Some(Some(true)) => 1u16,
            Some(Some(false)) => 2u16,
            _ => 0u16,
        };
        packet.extend_from_slice(&val.to_le_bytes());
    }
    packet.extend_from_slice(&(s.last_x as i16).to_le_bytes());
    packet.extend_from_slice(&(s.last_y as i16).to_le_bytes());
    packet.extend_from_slice(&0i16.to_le_bytes()); // wheel
    packet
}

// Keyboard input
pub fn build_keyboard_input(states: &[KeyboardState]) -> Vec<u8> {
    let mut packet = vec![0u8; KEYBOARD_MAX_KEYS * 2];
    for (i, s) in states.iter().enumerate() {
        if i >= KEYBOARD_MAX_KEYS {
            break;
        }
        let val = if s.down { s.scane_code } else { 0u16 };
        let offset = i * 2;
        packet[offset..offset + 2].copy_from_slice(&val.to_le_bytes());
    }
    packet
}

// Process protection
pub fn build_protect_process_req(process_id: ProcessId, enable: bool) -> Vec<u8> {
    let mut req = Vec::with_capacity(8);
    req.extend_from_slice(&process_id.to_le_bytes());
    req.extend_from_slice(&(if enable { 1u32 } else { 0u32 }).to_le_bytes());
    req
}

// ------------------------------------------------------------
// Batch read
// ------------------------------------------------------------

/// Per-entry result from a batch read.
pub struct BatchReadEntry {
    pub status: i32,
    pub data: Vec<u8>,
}

/// Build a batch read request from (pid, address, size) tuples.
pub fn build_batch_read_req(entries: &[(u32, u64, u32)]) -> Vec<u8> {
    let count = entries.len().min(BATCH_MAX_ENTRIES);
    let mut req = Vec::with_capacity(4 + count * (4 + 8 + 4));
    req.extend_from_slice(&(count as u32).to_le_bytes());
    for &(pid, addr, size) in entries.iter().take(count) {
        let clamped = size.min(BATCH_MAX_ENTRY_SIZE);
        req.extend_from_slice(&pid.to_le_bytes());
        req.extend_from_slice(&addr.to_le_bytes());
        req.extend_from_slice(&clamped.to_le_bytes());
    }
    req
}

/// Parse a batch read reply into per-entry results.
pub fn parse_batch_read_reply(data: &[u8]) -> IResult<Vec<BatchReadEntry>> {
    if data.len() < 4 {
        return Err(InterfaceError::InvalidResponse);
    }
    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let mut offset = 4;
    let mut results = Vec::with_capacity(count);

    for _ in 0..count {
        if offset + 8 > data.len() {
            break;
        }
        let status = i32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let data_size = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]) as usize;
        offset += 8;

        let entry_data = if data_size > 0 && offset + data_size <= data.len() {
            data[offset..offset + data_size].to_vec()
        } else {
            Vec::new()
        };
        offset += data_size;

        results.push(BatchReadEntry {
            status,
            data: entry_data,
        });
    }

    Ok(results)
}
