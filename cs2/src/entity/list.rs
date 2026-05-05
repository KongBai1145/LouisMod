use std::collections::BTreeMap;

use anyhow::anyhow;
use cs2_schema_cutl::EntityHandle;
use utils_state::{
    State,
    StateCacheType,
    StateRegistry,
};

use crate::{
    safe_memory::{
        self,
        SafeEntityIdentity,
        SafeMemoryReader,
        ofs,
    },
    CS2Offset,
    StateSafeMemoryReader,
    StateResolvedOffset,
};

#[derive(Clone)]
pub struct StateEntityList {
    entities: Vec<SafeEntityIdentity>,
    handle_lookup: BTreeMap<u32, usize>,
}

impl State for StateEntityList {
    type Parameter = ();

    fn create(_states: &StateRegistry, _param: Self::Parameter) -> anyhow::Result<Self> {
        Ok(Self { entities: Vec::new(), handle_lookup: Default::default() })
    }

    fn cache_type() -> StateCacheType {
        StateCacheType::Persistent
    }

    fn update(&mut self, states: &StateRegistry) -> anyhow::Result<()> {
        let smr = states.resolve::<StateSafeMemoryReader>(())?;
        let offset = states.resolve::<StateResolvedOffset>(CS2Offset::GlobalEntityList)?;

        self.entities.clear();
        self.handle_lookup.clear();

        let scanned = safe_memory::scan_entities(&smr, offset.address)
            .map_err(|e| anyhow!("entity scan: {}", e))?;

        for ent in scanned {
            self.handle_lookup.insert(ent.entity_index(), self.entities.len());
            self.entities.push(ent);
        }

        Ok(())
    }
}

impl StateEntityList {
    pub fn entities(&self) -> &[SafeEntityIdentity] {
        &self.entities
    }

    pub fn identity_from_index(&self, entity_index: u32) -> Option<&SafeEntityIdentity> {
        self.handle_lookup.get(&entity_index).and_then(|i| self.entities.get(*i))
    }

    pub fn entity_from_handle<T: ?Sized>(
        &self,
        handle: &EntityHandle<T>,
    ) -> Option<u64> {
        let idx = handle.get_entity_index();
        self.identity_from_index(idx).map(|e| e.entity_ptr)
    }

    pub fn entities_of_class(
        &self,
        class_name: &str,
        smr: &SafeMemoryReader,
    ) -> Vec<&SafeEntityIdentity> {
        self.entities.iter()
            .filter(|e| {
                safe_memory::read_class_name(smr, e.class_info_ptr)
                    .ok()
                    .map(|n| n == class_name)
                    .unwrap_or(false)
            })
            .collect()
    }
}
