use std::{
    ffi::OsStr,
    os::windows::ffi::OsStrExt,
    ptr,
};

use windows::Win32::{
    Foundation::{
        CloseHandle,
        HANDLE,
        INVALID_HANDLE_VALUE,
    },
    Storage::FileSystem::{
        CreateFileW,
        FILE_FLAGS_AND_ATTRIBUTES,
        FILE_SHARE_READ,
        FILE_SHARE_WRITE,
        OPEN_EXISTING,
    },
    System::IO::DeviceIoControl,
};

use crate::{
    command,
    error::{
        IResult,
        InterfaceError,
    },
};

/// Fallback device path (used when registry lookup fails)
const FIXED_DEVICE_PATH: &str = "\\\\.\\Global\\LouisModCore";

/// Registry path where the driver stores its random device name
const REGISTRY_KEY: &str = "SOFTWARE\\LouisMod";
const REGISTRY_VALUE: &str = "DeviceName";

/// CTL_CODE(0x8000, 0x0824, METHOD_BUFFERED, FILE_ANY_ACCESS)
/// FILE_ANY_ACCESS = 0, METHOD_BUFFERED = 0
const IOCTL_LOUISMOD_COMMAND: u32 = (0x8000u32 << 16) | (0x0824u32 << 2);

/// Raw handle to the kernel driver device.
/// Opens via CreateFileW, sends commands via DeviceIoControl.
pub struct DeviceHandle {
    handle: HANDLE,
}

unsafe impl Send for DeviceHandle {}

impl DeviceHandle {
    /// Discover the device name from registry.
    /// The kernel driver stores its random device name under HKLM\SOFTWARE\LouisMod.
    fn discover_device_path() -> String {
        use windows::Win32::System::Registry::{
            RegOpenKeyExW,
            RegQueryValueExW,
            HKEY_LOCAL_MACHINE,
            KEY_READ,
            REG_VALUE_TYPE,
        };

        let key_path: Vec<u16> = OsStr::new(REGISTRY_KEY)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let value_name: Vec<u16> = OsStr::new(REGISTRY_VALUE)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut key_handle = HKEY_LOCAL_MACHINE;
        let open_result = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                windows::core::PCWSTR::from_raw(key_path.as_ptr()),
                0u32,
                KEY_READ,
                &mut key_handle,
            )
        };

        if open_result.is_err() {
            log::debug!("Registry key not found, using fixed device path");
            return format!("\\\\.\\Global\\LouisModCore");
        }

        let mut buf = [0u16; 128];
        let mut buf_size = (buf.len() * 2) as u32;
        let mut data_type = REG_VALUE_TYPE(0);

        let query_result = unsafe {
            RegQueryValueExW(
                key_handle,
                windows::core::PCWSTR::from_raw(value_name.as_ptr()),
                Some(ptr::null_mut()),
                Some(&mut data_type),
                Some(buf.as_mut_ptr() as *mut u8),
                Some(&mut buf_size),
            )
        };

        unsafe {
            let _ = windows::Win32::System::Registry::RegCloseKey(key_handle);
        }

        if query_result.is_err() {
            log::debug!("Registry value not found, using fixed device path");
            return format!("\\\\.\\Global\\LouisModCore");
        }

        // Convert null-terminated UTF-16 to String
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        let device_name = String::from_utf16_lossy(&buf[..len]);

        // Build the full device path: \\.\Global\<device_name>
        // The kernel stores just the device name (e.g., "lm_abc123..."), not the full path
        if device_name.starts_with("\\Device\\") {
            // Kernel stores full NT path like \Device\lm_xxx
            // Convert to Win32 device path: \\.\Global\lm_xxx
            let short_name = &device_name[8..]; // skip "\Device\"
            format!("\\\\.\\Global\\{}", short_name)
        } else {
            format!("\\\\.\\Global\\{}", device_name)
        }
    }

    /// Open the LouisMod kernel device.
    /// First tries registry-discovered random device name, falls back to fixed path.
    pub fn open() -> IResult<Self> {
        let device_path = Self::discover_device_path();
        log::debug!("Attempting to open device at: {}", device_path);

        let path: Vec<u16> = OsStr::new(&device_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe {
            CreateFileW(
                windows::core::PCWSTR::from_raw(path.as_ptr()),
                0xC0000000u32, // GENERIC_READ | GENERIC_WRITE
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                Some(ptr::null()),
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                HANDLE(0),
            )
        };

        match handle {
            Ok(h) if h != INVALID_HANDLE_VALUE => Ok(Self { handle: h }),
            _ => {
                // Try fallback fixed path
                if device_path != FIXED_DEVICE_PATH {
                    log::debug!("Random device not found, trying fixed path");
                    let fallback_path: Vec<u16> = OsStr::new(FIXED_DEVICE_PATH)
                        .encode_wide()
                        .chain(std::iter::once(0))
                        .collect();

                    let fallback_handle = unsafe {
                        CreateFileW(
                            windows::core::PCWSTR::from_raw(fallback_path.as_ptr()),
                            0xC0000000u32,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            Some(ptr::null()),
                            OPEN_EXISTING,
                            FILE_FLAGS_AND_ATTRIBUTES(0),
                            HANDLE(0),
                        )
                    }
                    .map_err(|e| {
                        InterfaceError::DeviceOpenFailed(format!(
                            "Failed to open device at {}: {}",
                            FIXED_DEVICE_PATH, e
                        ))
                    })?;

                    if fallback_handle == INVALID_HANDLE_VALUE {
                        return Err(InterfaceError::DeviceOpenFailed(format!(
                            "Failed to open device at {} (INVALID_HANDLE_VALUE)",
                            FIXED_DEVICE_PATH
                        )));
                    }

                    Ok(Self {
                        handle: fallback_handle,
                    })
                } else {
                    Err(InterfaceError::DeviceOpenFailed(format!(
                        "Failed to open device at {}",
                        device_path
                    )))
                }
            }
        }
    }

    /// Send a command to the driver and return the decrypted response payload.
    ///
    /// Handles XOR encryption/decryption, IOCTL dispatch, and NTSTATUS checking.
    pub fn send_command(&self, command_id: u32, payload: &[u8]) -> IResult<Vec<u8>> {
        let packet = command::build_request(command_id, payload);
        let xor_key = u32::from_le_bytes([packet[4], packet[5], packet[6], packet[7]]);

        let mut output = vec![0u8; 0x10000]; // 64KB output buffer
        let mut bytes_returned = 0u32;

        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_LOUISMOD_COMMAND,
                Some(packet.as_ptr() as *const std::ffi::c_void),
                packet.len() as u32,
                Some(output.as_mut_ptr() as *mut std::ffi::c_void),
                output.len() as u32,
                Some(&mut bytes_returned),
                None,
            )
        }
        .map_err(|_| InterfaceError::CommunicationFailed("DeviceIoControl failed".to_string()))?;

        output.truncate(bytes_returned as usize);

        // Parse response: check NTSTATUS, decrypt payload, return raw payload bytes
        command::parse_response(&output, xor_key, |data| Ok(data.to_vec()))
    }
}

impl Drop for DeviceHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}
