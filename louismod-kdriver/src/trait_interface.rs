use crate::error::IResult;
use crate::types::{
    DirectoryTableType, DriverFeature, KeyboardState, MouseState, ProcessId, ProcessInfo,
    ProcessModuleInfo, ProcessProtectionMode, VersionInfo,
};

/// Abstract interface over kernel driver and user-mode backends.
///
/// Uses byte-slice based read/write (rather than generics) so that the trait
/// remains object-safe and can be stored as `Arc<dyn DriverInterface>`.
pub trait DriverInterface: Send + Sync {
    fn driver_features(&self) -> DriverFeature;
    fn driver_version(&self) -> VersionInfo;
    fn total_read_calls(&self) -> usize;

    // Process / module enumeration
    fn list_processes(&self) -> IResult<Vec<ProcessInfo>>;
    fn list_modules(&self, pid: ProcessId, dt: DirectoryTableType) -> IResult<Vec<ProcessModuleInfo>>;

    // Memory — byte-slice based
    fn read_bytes(&self, pid: ProcessId, dt: DirectoryTableType, addr: u64, buf: &mut [u8]) -> IResult<()>;
    fn write_bytes(&self, pid: ProcessId, dt: DirectoryTableType, addr: u64, buf: &[u8]) -> IResult<()>;

    // Input simulation
    fn send_keyboard_state(&self, states: &[KeyboardState]) -> IResult<()>;
    fn send_mouse_state(&self, states: &[MouseState]) -> IResult<()>;

    // Process protection (no-op in user-mode)
    fn toggle_process_protection(&self, mode: ProcessProtectionMode) -> IResult<()>;

    // Metrics (no-op in user-mode)
    fn add_metrics_record(&self, rt: &str, rp: &str) -> IResult<()>;
}
