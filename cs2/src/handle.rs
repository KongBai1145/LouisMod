#![allow(dead_code)]

use std::{
    error::Error,
    ffi::CStr,
    fmt::Debug,
    ops::{
        Deref,
        DerefMut,
    },
    sync::{
        Arc,
        Weak,
    },
};

use anyhow::Context;
use obfstr::obfstr;
use raw_struct::{
    FromMemoryView,
    MemoryView,
};
use utils_state::{
    State,
    StateCacheType,
    StateRegistry,
};
use louismod_kdriver::{
    create_driver,
    DirectoryTableType,
    DriverFeature,
    DriverInterface,
    InterfaceError,
    KeyboardState,
    MouseState,
    ProcessId,
    ProcessModuleInfo,
    ProcessProtectionMode,
};

use crate::{
    SearchPattern,
    Signature,
    SignatureType,
};

struct CS2MemoryView {
    handle: Weak<CS2Handle>,
}

impl MemoryView for CS2MemoryView {
    fn read_memory(
        &self,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let Some(handle) = self.handle.upgrade() else {
            return Err(anyhow::anyhow!("CS2 handle gone").into());
        };

        Ok(handle.read_slice(offset, buffer)?)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Module {
    Client,
    Engine,
    Schemasystem,
    Tier0,
}

impl Module {
    fn get_module_name(&self) -> &'static str {
        match self {
            Module::Client => "client.dll",
            Module::Engine => "engine2.dll",
            Module::Schemasystem => "schemasystem.dll",
            Module::Tier0 => "tier0.dll",
        }
    }
}

/// Handle to the CS2 process
pub struct CS2Handle {
    weak_self: Weak<Self>,
    metrics: bool,

    modules: Vec<ProcessModuleInfo>,
    process_id: ProcessId,

    pub ke_interface: Arc<dyn DriverInterface>,
}

impl CS2Handle {
    pub fn create(metrics: bool) -> anyhow::Result<Arc<Self>> {
        let interface = create_driver()?;
        if metrics {
            let _ = interface.add_metrics_record("application-type", env!("CARGO_CRATE_NAME"));
        }

        if interface
            .driver_features()
            .contains(DriverFeature::PROCESS_PROTECTION_KERNEL)
        {
            /*
             * Please no not analyze me:
             * https://www.unknowncheats.me/wiki/Valve_Anti-Cheat:VAC_external_tool_detection_(and_more)
             *
             * Even tough we don't have open handles to CS2 we don't want anybody to read our process.
             */
            if let Err(err) = interface.toggle_process_protection(ProcessProtectionMode::Kernel) {
                log::warn!("Failed to enable process protection: {}", err)
            };
        }

        let process = interface
            .list_processes()?
            .into_iter()
            .filter(|process| {
                process.get_image_base_name().unwrap_or_default() == obfstr!("cs2.exe")
            })
            .collect::<Vec<_>>();
        let process = if process.is_empty() {
            return Err(InterfaceError::ProcessUnknown.into());
        } else if process.len() > 1 {
            return Err(InterfaceError::ProcessUbiquitous.into());
        } else {
            process.first().unwrap()
        };

        let modules = interface.list_modules(process.process_id, DirectoryTableType::Default)?;
        log::debug!(
            "{}. Process id {}",
            obfstr!("Successfully initialized CS2 handle"),
            process.process_id
        );

        log::trace!("{} ({})", obfstr!("CS2 modules"), modules.len());
        for module in modules.iter() {
            log::trace!(
                "  - {} ({:X} - {:X})",
                module.get_base_dll_name().unwrap_or("unknown"),
                module.base_address,
                module.base_address + module.module_size
            );
        }

        Ok(Arc::new_cyclic(|weak_self| Self {
            weak_self: weak_self.clone(),
            metrics,
            modules,
            process_id: process.process_id,

            ke_interface: interface,
        }))
    }

    fn get_module_info(&self, target: Module) -> Option<&ProcessModuleInfo> {
        self.modules
            .iter()
            .find(|module| module.get_base_dll_name() == Some(target.get_module_name()))
    }

    pub fn process_id(&self) -> ProcessId {
        self.process_id
    }

    pub fn send_keyboard_state(&self, states: &[KeyboardState]) -> anyhow::Result<()> {
        self.ke_interface.send_keyboard_state(states)?;
        Ok(())
    }

    pub fn send_mouse_state(&self, states: &[MouseState]) -> anyhow::Result<()> {
        self.ke_interface.send_mouse_state(states)?;
        Ok(())
    }

    pub fn add_metrics_record(&self, record_type: &str, record_payload: &str) {
        if !self.metrics {
            /* user opted out */
            return;
        }

        let _ = self
            .ke_interface
            .add_metrics_record(record_type, record_payload);
    }

    pub fn module_address(&self, module: Module, address: u64) -> Option<u64> {
        let module = self.get_module_info(module)?;
        if address < module.base_address || address >= (module.base_address + module.module_size) {
            None
        } else {
            Some(address - module.base_address)
        }
    }

    pub fn memory_address(&self, module: Module, offset: u64) -> anyhow::Result<u64> {
        Ok(self
            .get_module_info(module)
            .with_context(|| format!("{} {}", obfstr!("missing module"), module.get_module_name()))?
            .base_address as u64
            + offset)
    }

    pub fn read_sized<T: Copy>(&self, address: u64) -> anyhow::Result<T> {
        let size = std::mem::size_of::<T>();
        if size <= 64 {
            let mut buf = [0u8; 64];
            self.ke_interface
                .read_bytes(self.process_id, DirectoryTableType::Default, address, &mut buf[..size])?;
            Ok(unsafe { (buf.as_ptr() as *const T).read_unaligned() })
        } else {
            let mut buf = vec![0u8; size];
            self.ke_interface
                .read_bytes(self.process_id, DirectoryTableType::Default, address, &mut buf)?;
            Ok(unsafe { (buf.as_ptr() as *const T).read_unaligned() })
        }
    }

    pub fn read_slice<T: Copy>(&self, address: u64, buffer: &mut [T]) -> anyhow::Result<()> {
        let byte_len = buffer.len().checked_mul(std::mem::size_of::<T>()).ok_or_else(|| {
            anyhow::anyhow!("read_slice size overflow")
        })?;

        // Stack-allocate small reads to avoid per-read heap allocation
        const STACK_BUF: usize = 256;
        if byte_len <= STACK_BUF {
            let mut bytes = [0u8; STACK_BUF];
            self.ke_interface
                .read_bytes(self.process_id, DirectoryTableType::Default, address, &mut bytes[..byte_len])?;
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const T, buffer.as_mut_ptr(), buffer.len());
            }
        } else {
            let mut bytes = vec![0u8; byte_len];
            self.ke_interface
                .read_bytes(self.process_id, DirectoryTableType::Default, address, &mut bytes)?;
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const T, buffer.as_mut_ptr(), buffer.len());
            }
        }
        Ok(())
    }

    pub fn write_sized<T: Copy>(&self, address: u64, value: &T) -> anyhow::Result<()> {
        let data = unsafe {
            std::slice::from_raw_parts(
                (value as *const T) as *const u8,
                std::mem::size_of::<T>(),
            )
        };
        self.ke_interface
            .write_bytes(self.process_id, DirectoryTableType::Default, address, data)?;
        Ok(())
    }

    pub fn read_string(
        &self,
        address: u64,
        expected_length: Option<usize>,
    ) -> anyhow::Result<String> {
        let initial = expected_length.unwrap_or(64);
        let mut buffer = vec![0u8; initial];
        self.read_slice(address, buffer.as_mut_slice())
            .context("read_string")?;

        if let Ok(str) = CStr::from_bytes_until_nul(&buffer) {
            return Ok(str.to_str().context("invalid string contents")?.to_string());
        }

        // Rare: string longer than initial guess, double each retry
        let mut len = initial * 2;
        loop {
            buffer.resize(len, 0u8);
            self.read_slice(address, buffer.as_mut_slice())
                .context("read_string")?;

            if let Ok(str) = CStr::from_bytes_until_nul(&buffer) {
                return Ok(str.to_str().context("invalid string contents")?.to_string());
            }

            len *= 2;
        }
    }

    pub fn create_memory_view(&self) -> Arc<dyn MemoryView + Send + Sync> {
        Arc::new(CS2MemoryView {
            handle: self.weak_self.clone(),
        })
    }

    #[must_use]
    pub fn find_pattern(
        &self,
        address: u64,
        length: usize,
        pattern: &dyn SearchPattern,
    ) -> anyhow::Result<Option<u64>> {
        if pattern.length() > length {
            return Ok(None);
        }

        let mut buffer = Vec::<u8>::with_capacity(length);
        buffer.resize(length, 0);
        self.ke_interface.read_bytes(
            self.process_id,
            DirectoryTableType::Default,
            address,
            &mut buffer,
        )?;

        for (index, window) in buffer.windows(pattern.length()).enumerate() {
            if !pattern.is_matching(window) {
                continue;
            }

            return Ok(Some(address + index as u64));
        }

        Ok(None)
    }

    pub fn resolve_signature(&self, module: Module, signature: &Signature) -> anyhow::Result<u64> {
        log::trace!("Resolving '{}' in {:?}", signature.debug_name, module);
        let module_info = self.get_module_info(module).with_context(|| {
            format!("{} {}", obfstr!("missing module"), module.get_module_name())
        })?;

        let inst_offset = self
            .find_pattern(
                module_info.base_address,
                module_info.module_size as usize,
                &*signature.pattern,
            )?
            .with_context(|| {
                format!(
                    "{} {}",
                    obfstr!("failed to find pattern"),
                    signature.debug_name
                )
            })?;

        let value = u32::read_object(&*self.create_memory_view(), inst_offset + signature.offset)
            .map_err(|err| anyhow::anyhow!("{}", err))? as u64;
        let value = match &signature.value_type {
            SignatureType::Offset => value,
            SignatureType::RelativeAddress { inst_length } => inst_offset + value + inst_length,
        };

        match &signature.value_type {
            SignatureType::Offset => log::trace!(
                " => {:X} (inst at {:X})",
                value,
                self.module_address(module, inst_offset).unwrap_or(u64::MAX)
            ),
            SignatureType::RelativeAddress { .. } => log::trace!(
                "  => {:X} ({:X})",
                value,
                self.module_address(module, value).unwrap_or(u64::MAX)
            ),
        }

        Ok(value)
    }
}

pub struct StateVariable<T: 'static + Send + Sync>(T);

impl<T: 'static + Send + Sync> StateVariable<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    pub fn value(&self) -> &T {
        &self.0
    }

    pub fn value_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: 'static + Send + Sync> State for StateVariable<T> {
    type Parameter = ();

    fn create(_states: &StateRegistry, _param: Self::Parameter) -> anyhow::Result<Self> {
        anyhow::bail!("StateVariable must be manually set")
    }

    fn cache_type() -> StateCacheType {
        StateCacheType::Persistent
    }
}

impl<T: 'static + Send + Sync> Deref for StateVariable<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.value()
    }
}

impl<T: 'static + Send + Sync> DerefMut for StateVariable<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.value_mut()
    }
}

pub type StateCS2Handle = StateVariable<Arc<CS2Handle>>;
pub type StateCS2Memory = StateVariable<Arc<dyn MemoryView + Send + Sync>>;

impl StateCS2Memory {
    pub fn view_arc(&self) -> Arc<dyn MemoryView> {
        self.value().clone()
    }

    pub fn view(&self) -> &dyn MemoryView {
        &**self.value()
    }
}
