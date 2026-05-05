/// Legacy adapter: provides old method names on SafeEntityIdentity
/// without doing any raw_struct operations.
use cs2_schema_cutl::EntityHandle;
use raw_struct::builtins::Ptr64;
use crate::safe_memory::SafeEntityIdentity;

impl SafeEntityIdentity {
    /// Returns Ptr64<T> from entity address. No dereference.
    pub fn entity_ptr<T: ?Sized>(&self) -> anyhow::Result<Ptr64<T>> {
        if self.entity_ptr == 0 { anyhow::bail!("null entity ptr"); }
        Ok(unsafe { std::mem::transmute::<u64, Ptr64<T>>(self.entity_ptr) })
    }

    /// Returns Ptr64 wrapping class info address. No dereference.
    pub fn entity_class_info(&self) -> anyhow::Result<Ptr64<()>> {
        if self.class_info_ptr == 0 { anyhow::bail!("null class info"); }
        Ok(unsafe { std::mem::transmute::<u64, Ptr64<()>>(self.class_info_ptr) })
    }

    /// Returns EntityHandle from the raw packed handle value.
    pub fn handle<T: ?Sized>(&self) -> anyhow::Result<EntityHandle<T>> {
        // EntityHandle is a u32 packed value. Transmute the handle_raw (u64) low 32 bits.
        let packed = (self.handle_raw & 0xFFFF_FFFF) as u32;
        Ok(unsafe { std::mem::transmute::<u32, EntityHandle<T>>(packed) })
    }
}

pub fn handle_index(raw: u64) -> u32 { (raw & 0x7FFF) as u32 }
pub fn handle_serial(raw: u64) -> u32 { ((raw >> 15) & 0x1FFFF) as u32 }
