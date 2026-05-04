mod handle;
pub use handle::*;

mod signature;
pub use signature::*;

pub mod schema;

mod offsets;
pub use offsets::*;

pub mod state;
pub use state::*;

mod entity;
pub use entity::*;

mod schema_gen;
pub use schema_gen::*;

mod model;
pub use model::*;

mod convar;
pub use convar::*;

mod weapon;
pub use weapon::*;

mod class_name_cache;
pub use class_name_cache::*;

mod pattern;
pub use pattern::*;
pub use louismod_kdriver::{
    KeyboardState,
    MouseState,
    InterfaceError,
};

pub mod schema_runtime;

/// Dump the CS2 schema (offsets) from the running game.
/// If `modules` is provided, only include offsets for those modules.
pub fn create_dump(
    registry: &utils_state::StateRegistry,
    modules: Option<&[&str]>,
) -> anyhow::Result<schema_runtime::RuntimeSchemaState> {
    let mut schema = schema_runtime::RuntimeSchemaState::from_game(registry)?;

    if let Some(filter) = modules {
        schema.offsets.retain(|offset| {
            filter.iter().any(|f| offset.module.contains(f))
        });
    }

    Ok(schema)
}
