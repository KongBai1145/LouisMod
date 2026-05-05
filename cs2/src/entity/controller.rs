use anyhow::{
    anyhow,
    Context,
};
use cs2_schema_generated::cs2::client::{
    CCSPlayerController,
    CEntityInstance,
};
use raw_struct::{
    builtins::Ptr64,
    FromMemoryView,
};
use utils_state::{
    State,
    StateCacheType,
    StateRegistry,
};

use super::{
    StateEntityList,
};
use crate::{
    CS2Offset,
    StateCS2Memory,
    StateResolvedOffset,
    StateSafeMemoryReader,
};

pub struct StateLocalPlayerController {
    pub instance: Ptr64<dyn CCSPlayerController>,
}

impl State for StateLocalPlayerController {
    type Parameter = ();

    fn create(states: &StateRegistry, _param: Self::Parameter) -> anyhow::Result<Self> {
        let memory = states.resolve::<StateCS2Memory>(())?;
        let offset = states.resolve::<StateResolvedOffset>(CS2Offset::LocalController)?;
        Ok(Self {
            instance: Ptr64::read_object(memory.view(), offset.address).map_err(|e| anyhow!(e))?,
        })
    }

    fn cache_type() -> StateCacheType {
        StateCacheType::Volatile
    }
}

struct StatePlayerControllerClass {
    address: u64,
}

impl State for StatePlayerControllerClass {
    type Parameter = ();

    fn create(states: &StateRegistry, _param: Self::Parameter) -> anyhow::Result<Self> {
        let smr = states.resolve::<StateSafeMemoryReader>(())?;
        let local_controller = states.resolve::<StateLocalPlayerController>(())?;

        // Read controller address from Ptr64 (it's stored at the resolved offset)
        let offset = states.resolve::<StateResolvedOffset>(CS2Offset::LocalController)?;
        let controller_addr = smr.read_ptr(offset.address)?;
        if controller_addr == 0 { anyhow::bail!("null controller"); }

        // CEntityInstance::m_pEntity is at offset 0x00 -> entity identity ptr
        let identity_addr = smr.read_ptr(controller_addr)?;
        if identity_addr == 0 { anyhow::bail!("null entity identity"); }

        // CEntityIdentity::m_pEntityClassInfo is at offset 0x08
        let class_info_addr = smr.read_ptr(identity_addr + 0x08)?;

        Ok(Self { address: class_info_addr })
    }

    fn cache_type() -> StateCacheType {
        StateCacheType::Persistent
    }
}

pub struct StatePlayerControllers {
    pub instances: Vec<Ptr64<dyn CCSPlayerController>>,
}

impl State for StatePlayerControllers {
    type Parameter = ();

    fn create(states: &StateRegistry, _param: Self::Parameter) -> anyhow::Result<Self> {
        let controller_class_address = states.resolve::<StatePlayerControllerClass>(())?;
        let entities = states.resolve::<StateEntityList>(())?;

        Ok(Self {
            instances: entities
                .entities()
                .iter()
                .filter(|entity| {
                    if let Ok(ptr) = entity.entity_class_info() {
                        ptr.address == controller_class_address.address
                    } else {
                        false
                    }
                })
                .map(|entity| entity.entity_ptr())
                .collect::<anyhow::Result<Vec<_>>>()?,
        })
    }
}
