use bitflags::bitflags;
use std::fmt;

pub type ProcessId = u32;

// ------------------------------------------------------------
// DirectoryTableType
// ------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryTableType {
    Default,
    Explicit { directory_table_base: u64 },
    Cr3Shenanigans,
}

// ------------------------------------------------------------
// DriverFeature flags
// ------------------------------------------------------------
bitflags! {
    pub struct DriverFeature : u64 {
        const PROCESS_LIST             = 0x00_00_00_01;
        const PROCESS_MODULES          = 0x00_00_00_02;
        const PROCESS_PROTECTION_KERNEL = 0x00_00_00_04;
        const PROCESS_PROTECTION_ZENITH = 0x00_00_00_08;

        const MEMORY_READ              = 0x00_00_01_00;
        const MEMORY_WRITE             = 0x00_00_02_00;

        const INPUT_KEYBOARD           = 0x00_01_00_00;
        const INPUT_MOUSE              = 0x00_02_00_00;

        const METRICS                 = 0x01_00_00_00;
        const DTT_EXPLICIT             = 0x02_00_10_00;
        const CR3_SHENANIGANS         = 0x04_00_00_00;
    }
}

// ------------------------------------------------------------
// Fixed-buffer string helpers
// ------------------------------------------------------------
fn fixed_buffer_to_str(buf: &[u8]) -> Option<&str> {
    let len = buf.iter().position(|&v| v == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..len]).ok()
}

fn str_to_fixed_buffer(buf: &mut [u8], value: &str) {
    let bytes = value.as_bytes();
    let copy_len = buf.len().min(bytes.len());
    buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
    if copy_len < buf.len() {
        buf[copy_len] = 0;
    }
}

// ------------------------------------------------------------
// ProcessInfo
// ------------------------------------------------------------
#[derive(Debug, Clone, Copy)]
pub struct ProcessInfo {
    pub process_id: ProcessId,
    pub image_base_name: [u8; 0x0F],
    pub directory_table_base: u64,
}

impl Default for ProcessInfo {
    fn default() -> Self {
        Self {
            process_id: 0,
            image_base_name: [0; 0x0F],
            directory_table_base: 0,
        }
    }
}

impl ProcessInfo {
    pub fn get_image_base_name(&self) -> Option<&str> {
        fixed_buffer_to_str(&self.image_base_name)
    }

    pub fn set_image_base_name(&mut self, value: &str) -> bool {
        str_to_fixed_buffer(&mut self.image_base_name, value);
        value.len() <= self.image_base_name.len()
    }
}

// ------------------------------------------------------------
// ProcessModuleInfo
// ------------------------------------------------------------
#[derive(Debug, Clone, Copy)]
pub struct ProcessModuleInfo {
    pub base_dll_name: [u8; 0x100],
    pub base_address: u64,
    pub module_size: u64,
}

impl Default for ProcessModuleInfo {
    fn default() -> Self {
        Self {
            base_dll_name: [0; 0x100],
            base_address: 0,
            module_size: 0,
        }
    }
}

impl ProcessModuleInfo {
    pub fn get_base_dll_name(&self) -> Option<&str> {
        fixed_buffer_to_str(&self.base_dll_name)
    }

    pub fn set_base_dll_name(&mut self, value: &str) -> bool {
        str_to_fixed_buffer(&mut self.base_dll_name, value);
        value.len() <= self.base_dll_name.len()
    }
}

// ------------------------------------------------------------
// VersionInfo
// ------------------------------------------------------------
#[derive(Debug, Clone, Copy, Default)]
pub struct VersionInfo {
    pub application_name: [u8; 0x20],
    pub version_major: u32,
    pub version_minor: u32,
    pub version_patch: u32,
}

impl VersionInfo {
    pub fn get_application_name(&self) -> Option<&str> {
        fixed_buffer_to_str(&self.application_name)
    }

    pub fn set_application_name(&mut self, value: &str) -> bool {
        str_to_fixed_buffer(&mut self.application_name, value);
        value.len() <= self.application_name.len()
    }
}

// ------------------------------------------------------------
// Keyboard / Mouse state
// ------------------------------------------------------------
#[derive(Debug, Default, Clone, Copy)]
pub struct KeyboardState {
    pub scane_code: u16,
    pub down: bool,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct MouseState {
    pub buttons: [Option<bool>; 5],
    pub hwheel: bool,
    pub wheel: bool,
    pub last_x: i32,
    pub last_y: i32,
}

// ------------------------------------------------------------
// ProcessProtectionMode
// ------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessProtectionMode {
    None,
    Kernel,
    Zenith,
}

impl Default for ProcessProtectionMode {
    fn default() -> Self {
        Self::None
    }
}

// ------------------------------------------------------------
// Console logging helper
// ------------------------------------------------------------
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Debug => write!(f, "DEBUG"),
            Self::Info => write!(f, "INFO"),
            Self::Warn => write!(f, "WARN"),
            Self::Error => write!(f, "ERROR"),
        }
    }
}
