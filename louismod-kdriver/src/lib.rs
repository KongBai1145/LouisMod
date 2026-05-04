pub mod command;
pub mod device;
pub mod error;
pub mod trait_interface;
pub mod types;
pub mod usermode;

use std::sync::{
    atomic::{
        AtomicUsize,
        Ordering,
    },
    Arc,
};

/// LouisMod custom kernel driver interface.
/// Communicates directly with louismod.sys via DeviceIoControl.
pub struct LouisModDriver {
    device: DeviceHandle,
    features: DriverFeature,
    version: VersionInfo,
    read_calls: AtomicUsize,
}

impl LouisModDriver {
    /// Open the driver device and negotiate protocol version.
    pub fn create_from_env() -> IResult<Self> {
        let device = DeviceHandle::open()?;

        // CMD_INIT to get version + features
        let reply = device.send_command(command::CMD_INIT, &[])?;
        let (protocol_version, driver_major, driver_minor, features_bits) =
            command::parse_init_reply(&reply)?;

        if protocol_version != command::LOUISMOD_PROTOCOL_VERSION {
            return Err(InterfaceError::ProtocolMismatch {
                expected: command::LOUISMOD_PROTOCOL_VERSION,
                actual: protocol_version,
            });
        }

        let mut version = VersionInfo::default();
        version.set_application_name("louismod-driver");
        version.version_major = driver_major as u32;
        version.version_minor = driver_minor as u32;

        Ok(Self {
            device,
            features: DriverFeature::from_bits_truncate(features_bits),
            version,
            read_calls: AtomicUsize::new(0),
        })
    }

    // ------------------------------------------------------------
    // Feature / version queries
    // ------------------------------------------------------------

    pub fn driver_features(&self) -> DriverFeature {
        self.features
    }

    pub fn driver_version(&self) -> &VersionInfo {
        &self.version
    }

    pub fn total_read_calls(&self) -> usize {
        self.read_calls.load(Ordering::Relaxed)
    }

    // ------------------------------------------------------------
    // Process / module enumeration
    // ------------------------------------------------------------

    pub fn list_processes(&self) -> IResult<Vec<ProcessInfo>> {
        let reply = self.device.send_command(command::CMD_PROCESS_LIST, &[])?;
        command::parse_process_list(&reply)
    }

    pub fn list_modules(
        &self,
        process_id: ProcessId,
        _dt: DirectoryTableType,
    ) -> IResult<Vec<ProcessModuleInfo>> {
        let req = command::build_module_list_req(process_id);
        let reply = self.device.send_command(command::CMD_MODULE_LIST, &req)?;
        command::parse_module_list(&reply)
    }

    // ------------------------------------------------------------
    // Memory read / write
    // ------------------------------------------------------------

    pub fn read<T: Copy>(
        &self,
        process_id: ProcessId,
        _dt: DirectoryTableType,
        address: u64,
    ) -> IResult<T> {
        let size = std::mem::size_of::<T>() as u32;
        let req = command::build_read_req(process_id, address, size);
        let reply = self.device.send_command(command::CMD_READ_MEMORY, &req)?;

        self.read_calls.fetch_add(1, Ordering::Relaxed);

        if reply.len() < size as usize {
            return Err(InterfaceError::MemoryAccessFailed);
        }

        Ok(unsafe { (reply.as_ptr() as *const T).read_unaligned() })
    }

    pub fn read_slice<T: Copy>(
        &self,
        process_id: ProcessId,
        _dt: DirectoryTableType,
        address: u64,
        buffer: &mut [T],
    ) -> IResult<()> {
        let byte_len = buffer
            .len()
            .checked_mul(std::mem::size_of::<T>())
            .ok_or_else(|| InterfaceError::CommandGenericError {
                message: "read_slice size overflow".into(),
            })?;
        let req = command::build_read_req(process_id, address, byte_len as u32);
        let reply = self.device.send_command(command::CMD_READ_MEMORY, &req)?;

        self.read_calls.fetch_add(1, Ordering::Relaxed);

        if reply.len() < byte_len {
            return Err(InterfaceError::MemoryAccessFailed);
        }

        unsafe {
            std::ptr::copy_nonoverlapping(
                reply.as_ptr() as *const T,
                buffer.as_mut_ptr(),
                buffer.len(),
            );
        }
        Ok(())
    }

    pub fn write<T: Copy>(
        &self,
        process_id: ProcessId,
        _dt: DirectoryTableType,
        address: u64,
        value: &T,
    ) -> IResult<()> {
        let size = std::mem::size_of::<T>() as u32;
        let data =
            unsafe { std::slice::from_raw_parts((value as *const T) as *const u8, size as usize) };
        let req = command::build_write_req(process_id, address, data);
        self.device.send_command(command::CMD_WRITE_MEMORY, &req)?;
        Ok(())
    }

    // ------------------------------------------------------------
    // Input simulation
    // ------------------------------------------------------------

    pub fn send_keyboard_state(&self, states: &[KeyboardState]) -> IResult<()> {
        let payload = command::build_keyboard_input(states);
        self.device
            .send_command(command::CMD_KEYBOARD_INPUT, &payload)?;
        Ok(())
    }

    pub fn send_mouse_state(&self, states: &[MouseState]) -> IResult<()> {
        let payload = command::build_mouse_input(states);
        self.device
            .send_command(command::CMD_MOUSE_INPUT, &payload)?;
        Ok(())
    }

    // ------------------------------------------------------------
    // Process protection (ObRegisterCallbacks)
    // ------------------------------------------------------------

    pub fn toggle_process_protection(&self, mode: ProcessProtectionMode) -> IResult<()> {
        match mode {
            ProcessProtectionMode::None => {
                self.device.send_command(
                    command::CMD_PROTECT_PROCESS,
                    &command::build_protect_process_req(0, false),
                )?;
            }
            ProcessProtectionMode::Kernel | ProcessProtectionMode::Zenith => {
                self.device.send_command(
                    command::CMD_PROTECT_PROCESS,
                    &command::build_protect_process_req(0, true),
                )?;
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------
    // CR3 shenanigan mitigations
    // ------------------------------------------------------------

    pub fn enable_cr3_shenanigan_mitigation(&self) -> IResult<()> {
        self.device.send_command(command::CMD_CR3_ENABLE, &[])?;
        Ok(())
    }

    pub fn disable_cr3_shenanigan_mitigation(&self) -> IResult<()> {
        self.device.send_command(command::CMD_CR3_DISABLE, &[])?;
        Ok(())
    }

    // ------------------------------------------------------------
    // Batch read — multiple addresses in a single IOCTL
    // ------------------------------------------------------------

    /// Read multiple memory regions in one driver call.
    ///
    /// `entries` is a slice of `(address, size)` pairs — all reads target
    /// `process_id`. Returns per-entry results; check `entry.status >= 0`
    /// to determine success for each.
    pub fn batch_read(
        &self,
        process_id: ProcessId,
        entries: &[(u64, u32)],
    ) -> IResult<Vec<command::BatchReadEntry>> {
        let req_entries: Vec<(u32, u64, u32)> = entries
            .iter()
            .map(|&(addr, size)| (process_id, addr, size))
            .collect();

        let req = command::build_batch_read_req(&req_entries);
        let reply = self.device.send_command(command::CMD_BATCH_READ, &req)?;
        let results = command::parse_batch_read_reply(&reply)?;

        self.read_calls.fetch_add(results.len(), Ordering::Relaxed);
        Ok(results)
    }

    // ------------------------------------------------------------
    // Metrics (no-op in our driver)
    // ------------------------------------------------------------

    pub fn add_metrics_record(&self, _record_type: &str, _record_payload: &str) -> IResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------
// DriverInterface impl for LouisModDriver (kernel)
// ---------------------------------------------------------------
impl DriverInterface for LouisModDriver {
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
        // inherent method shadows trait method — no recursion
        self.list_processes()
    }

    fn list_modules(
        &self,
        pid: ProcessId,
        dt: DirectoryTableType,
    ) -> IResult<Vec<ProcessModuleInfo>> {
        self.list_modules(pid, dt)
    }

    fn read_bytes(
        &self,
        pid: ProcessId,
        dt: DirectoryTableType,
        addr: u64,
        buf: &mut [u8],
    ) -> IResult<()> {
        self.read_slice(pid, dt, addr, buf)
    }

    fn write_bytes(
        &self,
        pid: ProcessId,
        _dt: DirectoryTableType,
        addr: u64,
        buf: &[u8],
    ) -> IResult<()> {
        let req = command::build_write_req(pid, addr, buf);
        self.device.send_command(command::CMD_WRITE_MEMORY, &req)?;
        Ok(())
    }

    fn send_keyboard_state(&self, states: &[KeyboardState]) -> IResult<()> {
        self.send_keyboard_state(states)
    }

    fn send_mouse_state(&self, states: &[MouseState]) -> IResult<()> {
        self.send_mouse_state(states)
    }

    fn toggle_process_protection(&self, mode: ProcessProtectionMode) -> IResult<()> {
        self.toggle_process_protection(mode)
    }

    fn add_metrics_record(&self, rt: &str, rp: &str) -> IResult<()> {
        self.add_metrics_record(rt, rp)
    }
}

// ---------------------------------------------------------------
// Factory: try kernel driver first, fall back to user-mode
// ---------------------------------------------------------------

/// Try to create a kernel driver; fall back to user-mode indirect syscalls.
pub fn create_driver() -> IResult<Arc<dyn DriverInterface>> {
    match LouisModDriver::create_from_env() {
        Ok(d) => {
            log::info!("Using kernel driver");
            Ok(Arc::new(d))
        }
        Err(e) => {
            log::warn!(
                "Kernel driver unavailable ({}), falling back to user-mode",
                e
            );
            UserModeDriver::create().map(|d| Arc::new(d) as Arc<dyn DriverInterface>)
        }
    }
}

// ------------------------------------------------------------
// Re-exports
// ------------------------------------------------------------
pub use crate::{
    command::{
        build_batch_read_req,
        build_keyboard_input,
        build_module_list_req,
        build_mouse_input,
        build_protect_process_req,
        build_read_req,
        build_request,
        build_write_req,
        parse_batch_read_reply,
        parse_init_reply,
        parse_module_list,
        parse_process_list,
        parse_response,
        BatchReadEntry,
    },
    device::DeviceHandle,
    error::{
        IResult,
        InterfaceError,
    },
    trait_interface::DriverInterface,
    types::*,
    usermode::UserModeDriver,
};
