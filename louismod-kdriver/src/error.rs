use thiserror::Error;

#[derive(Error, Debug)]
pub enum InterfaceError {
    #[error("failed to find any memory driver")]
    NoDriverFound,

    #[error("failed to open device: {0}")]
    DeviceOpenFailed(String),

    #[error("IOCTL communication failed: {0}")]
    CommunicationFailed(String),

    #[error("protocol mismatch (expected {expected}, got {actual})")]
    ProtocolMismatch { expected: u32, actual: u32 },

    #[error("command failed: {message}")]
    CommandGenericError { message: String },

    #[error("feature is not supported")]
    FeatureUnsupported,

    #[error("the driver is unavailable")]
    InitializeDriverUnavailable,

    #[error("process unknown")]
    ProcessUnknown,

    #[error("process is ubiquitous")]
    ProcessUbiquitous,

    #[error("failed to access memory")]
    MemoryAccessFailed,

    #[error("memory has been paged out")]
    MemoryAccessPagedOut,

    #[error("failed to allocate a properly sized buffer")]
    BufferAllocationFailed,

    #[error("invalid response from driver")]
    InvalidResponse,
}

pub type IResult<T> = Result<T, InterfaceError>;

impl InterfaceError {
    pub fn detailed_message(&self) -> Option<String> {
        match self {
            Self::NoDriverFound => Some(
                "Could not find the LouisMod kernel driver.\n\
                 Please ensure louismod.sys is installed and running:\n\
                 - Run install_driver.bat as Administrator\n\
                 - Verify with: sc query LouisMod\n"
                    .to_string(),
            ),
            Self::DeviceOpenFailed(e) => Some(format!(
                "Failed to open driver device.\n\
                 Error: {}\n\n\
                 Possible causes:\n\
                 1. Driver not installed (run install_driver.bat as Admin)\n\
                 2. Driver not started (sc start LouisMod)\n\
                 3. Test signing mode not enabled (bcdedit /set testsigning on)\n\
                 4. Need to reboot after enabling test signing",
                e
            )),
            Self::CommunicationFailed(e) => Some(format!(
                "Driver communication failed: {}\n\
                 The driver may have crashed or been blocked by security software.",
                e
            )),
            Self::InitializeDriverUnavailable => Some(
                "The kernel driver is loaded but not responding.\n\
                 Try restarting the LouisMod service: sc stop LouisMod ^&^& sc start LouisMod"
                    .to_string(),
            ),
            _ => None,
        }
    }
}
