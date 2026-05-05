use louismod_kdriver::{
    DriverInterface,
    ProcessId,
    DirectoryTableType,
};

pub use nalgebra::{Vector2, Vector3, Vector4, Matrix4, Quaternion};

// ---- Schema offsets (Rev 10627055, Apr 30 2026) ----
pub mod ofs {
    // CEntityIdentity
    pub const ENTITY_PTR: u64 = 0x00;
    pub const CLASS_INFO_PTR: u64 = 0x08;
    pub const ENTITY_HANDLE: u64 = 0x10;

    // CEntityClassInfo
    pub const CLASS_BINDING: u64 = 0x08;
    // CSchemaClassBinding
    pub const CLASS_NAME_STR: u64 = 0x08;

    // CBaseEntity
    pub const M_P_GAME_SCENE_NODE: u64 = 0x330;
    pub const M_I_HEALTH: u64 = 0x34C;
    pub const M_I_TEAM_NUM: u64 = 0x3EB;
    pub const M_I_MAX_HEALTH: u64 = 0x348;

    // CBasePlayerPawn
    pub const M_P_WEAPON_SERVICES: u64 = 0x13F0;
    pub const M_P_ITEM_SERVICES: u64 = 0x13F8;

    // CGameSceneNode
    pub const M_VEC_ABS_ORIGIN: u64 = 0xD0;
    pub const M_B_DORMANT: u64 = 0x10B;

    // CSkeletonInstance
    pub const M_MODEL_STATE: u64 = 0x190;

    // CModelState
    pub const M_H_MODEL: u64 = 0xA0;
    pub const M_BONE_ARRAY: u64 = 0x80;
    pub const M_BONE_COUNT: u64 = 0x10C;

    // BoneStateData (size 0x20)
    pub const BONE_POS: u64 = 0x00;
    pub const BONE_ROT: u64 = 0x0C;

    // CModel
    pub const MODEL_HULL_MIN: u64 = 0x18;
    pub const MODEL_HULL_MAX: u64 = 0x24;
    pub const MODEL_VIEW_MIN: u64 = 0x30;
    pub const MODEL_VIEW_MAX: u64 = 0x3C;
    pub const MODEL_BONE_COUNT: u64 = 0x160;
    pub const MODEL_BONE_NAMES: u64 = 0x168;
    pub const MODEL_BONE_PARENTS: u64 = 0x180;
    pub const MODEL_BONE_FLAGS: u64 = 0x1B0;

    // CPlayer_WeaponServices
    pub const M_H_ACTIVE_WEAPON: u64 = 0x58;

    // CCSPlayer_ItemServices
    pub const M_B_HAS_DEFUSER: u64 = 0x40;
    pub const M_B_HAS_HELMET: u64 = 0x41;

    // CCSPlayerController
    pub const M_H_PLAYER_PAWN: u64 = 0x8FC;
    pub const M_SANITIZED_NAME: u64 = 0x850;

    // CBasePlayerController
    pub const M_H_PAWN: u64 = 0x6B4;
    pub const M_ISZ_PLAYER_NAME: u64 = 0x708;

    // C_CSPlayerPawnBase
    pub const M_FL_FLASH_BANG_TIME: u64 = 0x15FC;

    // C_CSPlayerPawn
    pub const M_AIM_PUNCH_ANGLE: u64 = 0x16E4;
    pub const M_B_IS_SCOPED: u64 = 0x2718;
    pub const M_B_IS_DEFUSING: u64 = 0x271A;
    pub const M_I_SHOTS_FIRED: u64 = 0x272C;
    pub const M_ANG_EYE_ANGLES: u64 = 0x3DF0;

    // C_BaseModelEntity
    pub const M_VEC_VIEW_OFFSET: u64 = 0xD80;

    // C_EconItemView
    pub const M_I_ITEM_DEFINITION_INDEX: u64 = 0x1BA;

    // C_BasePlayerWeapon
    pub const M_I_CLIP1: u64 = 0x18F0;

    // Globals
    pub const GLOBALS_CURTIME: u64 = 0x00;
    pub const GLOBALS_FRAMECOUNT: u64 = 0x04;
    pub const GLOBALS_MAXPLAYERS: u64 = 0x10;
    pub const GLOBALS_INTERVAL: u64 = 0x2C;
    pub const GLOBALS_TIME2: u64 = 0x30;

    // CNetworkGameClient
    pub const MAP_NAME_PTR: u64 = 0x218;

    // Entity list structure
    pub const OUTER_LIST_SIZE: u64 = 64;
    pub const INNER_LIST_SIZE: u64 = 512;
    pub const IDENTITY_SIZE: u64 = 0x28;
}

// ---- Data structures ----
#[derive(Clone, Debug)]
pub struct SafeEntityIdentity {
    pub identity_addr: u64,
    pub entity_ptr: u64,
    pub class_info_ptr: u64,
    pub handle_raw: u64,
}

impl SafeEntityIdentity {
    pub fn entity_index(&self) -> u32 {
        (self.handle_raw & 0x7FFF) as u32
    }
    pub fn serial(&self) -> u32 {
        ((self.handle_raw >> 15) & 0x1FFFF) as u32
    }
    pub fn is_valid(&self) -> bool {
        self.entity_ptr != 0 && self.class_info_ptr != 0
    }
    /// Get entity address for raw memory reads (compat)
    pub fn entity_ptr_raw(&self) -> u64 { self.entity_ptr }
    /// Get class info address (compat)
    pub fn class_info_ptr_raw(&self) -> u64 { self.class_info_ptr }
    /// Get entity handle raw value (compat)
    pub fn handle_raw_value(&self) -> u64 { self.handle_raw }
}

#[derive(Clone, Debug)]
pub struct SafePawnInfo {
    pub health: i32,
    pub max_health: i32,
    pub team_id: u8,
    pub name: String,
    pub position: Vector3<f32>,
    pub eye_angles: Vector2<f32>,
    pub weapon_id: u32,
    pub weapon_name: String,
    pub ammo_clip: i32,
    pub is_alive: bool,
    pub is_scoped: bool,
    pub is_flashed: bool,
    pub has_defuser: bool,
    pub has_helmet: bool,
    pub is_defusing: bool,
}

#[derive(Clone, Debug)]
pub struct SafeBoneState {
    pub position: Vector3<f32>,
    pub rotation: Quaternion<f32>,
}

#[derive(Clone, Debug)]
pub struct SafeGlobals {
    pub cur_time: f32,
    pub frame_count: u32,
    pub max_players: u32,
    pub interval: f32,
    pub time2: f32,
}

#[derive(Clone, Debug)]
pub struct SafeModelInfo {
    pub hull_min: Vector3<f32>,
    pub hull_max: Vector3<f32>,
    pub view_min: Vector3<f32>,
    pub view_max: Vector3<f32>,
    pub bone_count: usize,
    pub bones: Vec<SafeBoneDef>,
}

#[derive(Clone, Debug)]
pub struct SafeBoneDef {
    pub name: String,
    pub parent: Option<usize>,
    pub flags: u32,
}

// ---- SafeMemoryReader ----
pub struct SafeMemoryReader {
    ke: std::sync::Arc<dyn DriverInterface>,
    pid: ProcessId,
}

impl SafeMemoryReader {
    pub fn new(ke: std::sync::Arc<dyn DriverInterface>, pid: ProcessId) -> Self {
        Self { ke, pid }
    }

    pub fn read<T: Copy>(&self, addr: u64) -> anyhow::Result<T> {
        let size = std::mem::size_of::<T>();
        if size <= 64 {
            let mut buf = [0u8; 64];
            self.ke.read_bytes(self.pid, DirectoryTableType::Default, addr, &mut buf[..size])?;
            Ok(unsafe { (buf.as_ptr() as *const T).read_unaligned() })
        } else {
            let mut buf = vec![0u8; size];
            self.ke.read_bytes(self.pid, DirectoryTableType::Default, addr, &mut buf)?;
            Ok(unsafe { (buf.as_ptr() as *const T).read_unaligned() })
        }
    }

    pub fn read_at<T: Copy>(&self, base: u64, offset: u64) -> anyhow::Result<T> {
        self.read::<T>(base + offset)
    }

    pub fn read_ptr(&self, addr: u64) -> anyhow::Result<u64> {
        self.read::<u64>(addr)
    }

    pub fn read_f32(&self, addr: u64) -> anyhow::Result<f32> { self.read(addr) }
    pub fn read_i32(&self, addr: u64) -> anyhow::Result<i32> { self.read(addr) }
    pub fn read_u32(&self, addr: u64) -> anyhow::Result<u32> { self.read(addr) }
    pub fn read_bool(&self, addr: u64) -> anyhow::Result<bool> { self.read(addr) }

    pub fn read_string(&self, ptr: u64, max: usize) -> anyhow::Result<String> {
        if ptr == 0 { return Ok(String::new()); }
        let mut buf = vec![0u8; max.min(1024)];
        self.ke.read_bytes(self.pid, DirectoryTableType::Default, ptr, &mut buf)?;
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        Ok(String::from_utf8_lossy(&buf[..end]).to_string())
    }

    pub fn read_wide_string(&self, ptr: u64, max: usize) -> anyhow::Result<String> {
        if ptr == 0 { return Ok(String::new()); }
        let mut buf = vec![0u8; max * 2];
        self.ke.read_bytes(self.pid, DirectoryTableType::Default, ptr, &mut buf)?;
        let mut chars = Vec::new();
        for c in buf.chunks_exact(2) {
            let c = u16::from_le_bytes([c[0], c[1]]);
            if c == 0 { break; }
            chars.push(c);
        }
        Ok(String::from_utf16_lossy(&chars))
    }

    pub fn read_slice<T: Copy>(&self, addr: u64, count: usize) -> anyhow::Result<Vec<T>> {
        let size = std::mem::size_of::<T>() * count;
        let mut buf = vec![0u8; size];
        self.ke.read_bytes(self.pid, DirectoryTableType::Default, addr, &mut buf)?;
        Ok(unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const T, count).to_vec() })
    }

    /// Follow pointer chain: base -> *(base+offsets[0]) -> *(...+offsets[1]) -> ...
    pub fn read_chain(&self, mut addr: u64, offsets: &[u64]) -> anyhow::Result<u64> {
        for &off in offsets {
            addr = self.read_ptr(addr + off)?;
            if addr == 0 { anyhow::bail!("null at offset 0x{:X}", off); }
        }
        Ok(addr)
    }
}

// ---- Entity scanning ----
pub fn scan_entities(smr: &SafeMemoryReader, entity_list_addr: u64) -> anyhow::Result<Vec<SafeEntityIdentity>> {
    let outer_ptr = smr.read_ptr(entity_list_addr)?;
    if outer_ptr == 0 { return Ok(Vec::new()); }
    let mut entities = Vec::with_capacity(1024);
    for bi in 0..ofs::OUTER_LIST_SIZE {
        let inner_ptr = smr.read_ptr(outer_ptr + bi * 8)?;
        if inner_ptr == 0 { continue; }
        for ei in 0..ofs::INNER_LIST_SIZE {
            let addr = inner_ptr + ei * ofs::IDENTITY_SIZE;
            match smr.read_ptr(addr + ofs::ENTITY_PTR) {
                Ok(ep) if ep != 0 => {},
                _ => continue,
            }
            let ep = smr.read_ptr(addr + ofs::ENTITY_PTR)?;
            let ci = smr.read_ptr(addr + ofs::CLASS_INFO_PTR).unwrap_or(0);
            let hr = smr.read_at::<u64>(addr, ofs::ENTITY_HANDLE).unwrap_or(0xFFFFFFFF);
            let expected = ((bi << 9) | ei) as u32;
            if (hr & 0x7FFF) as u32 != expected { continue; }
            entities.push(SafeEntityIdentity { identity_addr: addr, entity_ptr: ep, class_info_ptr: ci, handle_raw: hr });
        }
    }
    Ok(entities)
}

pub fn find_entity(entities: &[SafeEntityIdentity], index: u32) -> Option<&SafeEntityIdentity> {
    entities.iter().find(|e| e.entity_index() == index)
}

// ---- Class name reading ----
pub fn read_class_name(smr: &SafeMemoryReader, class_info_ptr: u64) -> anyhow::Result<String> {
    if class_info_ptr == 0 { anyhow::bail!("null class info"); }
    let binding = smr.read_ptr(class_info_ptr + ofs::CLASS_BINDING)?;
    if binding == 0 { anyhow::bail!("null class binding"); }
    let name_ptr = smr.read_ptr(binding + ofs::CLASS_NAME_STR)?;
    smr.read_string(name_ptr, 128)
}

// ---- Player pawn info ----
pub fn read_pawn_info(smr: &SafeMemoryReader, pawn_addr: u64) -> anyhow::Result<SafePawnInfo> {
    let health = smr.read_at::<i32>(pawn_addr, ofs::M_I_HEALTH)?;
    let max_health = smr.read_at::<i32>(pawn_addr, ofs::M_I_MAX_HEALTH).unwrap_or(100);
    let team_id = smr.read_at::<u8>(pawn_addr, ofs::M_I_TEAM_NUM)?;
    let is_scoped = smr.read_at::<bool>(pawn_addr, ofs::M_B_IS_SCOPED).unwrap_or(false);
    let is_defusing = smr.read_at::<bool>(pawn_addr, ofs::M_B_IS_DEFUSING).unwrap_or(false);
    let is_alive = health > 0 && health <= max_health;

    // Name from controller (read via pawn's controller handle)
    let name = String::new();
    let weapon_id = 0u32;
    let weapon_name = String::new();
    let ammo_clip = 0i32;

    // Position and angles
    let scene_node = smr.read_ptr(pawn_addr + ofs::M_P_GAME_SCENE_NODE).unwrap_or(0);
    let position = if scene_node != 0 {
        smr.read_at::<Vector3<f32>>(scene_node, ofs::M_VEC_ABS_ORIGIN).unwrap_or(Vector3::new(0.0, 0.0, 0.0))
    } else { Vector3::new(0.0, 0.0, 0.0) };
    let eye_angles = smr.read_at::<Vector2<f32>>(pawn_addr, ofs::M_ANG_EYE_ANGLES).unwrap_or(Vector2::new(0.0, 0.0));

    // Item services
    let items_ptr = smr.read_ptr(pawn_addr + ofs::M_P_ITEM_SERVICES).unwrap_or(0);
    let (has_defuser, has_helmet) = if items_ptr != 0 {
        (smr.read_at::<bool>(items_ptr, ofs::M_B_HAS_DEFUSER).unwrap_or(false),
         smr.read_at::<bool>(items_ptr, ofs::M_B_HAS_HELMET).unwrap_or(false))
    } else { (false, false) };

    // Flash
    let flash = smr.read_at::<f32>(pawn_addr, ofs::M_FL_FLASH_BANG_TIME).unwrap_or(0.0);
    let is_flashed = flash > 0.0;

    Ok(SafePawnInfo {
        health, max_health, team_id, name, position, eye_angles,
        weapon_id, weapon_name, ammo_clip, is_alive, is_scoped, is_flashed,
        has_defuser, has_helmet, is_defusing,
    })
}

// ---- Bones ----
pub fn read_bone_data(smr: &SafeMemoryReader, pawn_addr: u64) -> anyhow::Result<Vec<SafeBoneState>> {
    use ofs::*;
    let scene_node = smr.read_ptr(pawn_addr + M_P_GAME_SCENE_NODE)?;
    if scene_node == 0 { anyhow::bail!("no scene node"); }
    // CSkeletonInstance inherits CGameSceneNode, so m_modelState is at the same offset
    let model_state = smr.read_ptr(scene_node + M_MODEL_STATE)?;
    if model_state == 0 { anyhow::bail!("no model state"); }
    let bone_array = smr.read_ptr(model_state + M_BONE_ARRAY)?;
    let bone_count = smr.read_at::<u32>(model_state, M_BONE_COUNT).unwrap_or(0);
    if bone_array == 0 || bone_count == 0 || bone_count > 200 { anyhow::bail!("invalid bone data"); }
    let mut bones = Vec::with_capacity(bone_count as usize);
    for i in 0..bone_count as usize {
        let ba = bone_array + (i as u64) * 0x20;
        let pos = smr.read_at::<Vector3<f32>>(ba, BONE_POS)?;
        let rot = smr.read_at::<Quaternion<f32>>(ba, BONE_ROT)?;
        bones.push(SafeBoneState { position: pos, rotation: rot });
    }
    Ok(bones)
}

// ---- Model info ----
pub fn read_model_info(smr: &SafeMemoryReader, model_addr: u64) -> anyhow::Result<SafeModelInfo> {
    use ofs::*;
    let hull_min = smr.read_at::<Vector3<f32>>(model_addr, MODEL_HULL_MIN)?;
    let hull_max = smr.read_at::<Vector3<f32>>(model_addr, MODEL_HULL_MAX)?;
    let view_min = smr.read_at::<Vector3<f32>>(model_addr, MODEL_VIEW_MIN)?;
    let view_max = smr.read_at::<Vector3<f32>>(model_addr, MODEL_VIEW_MAX)?;
    let bc = smr.read_at::<u32>(model_addr, MODEL_BONE_COUNT)? as usize;
    let bone_count = bc.min(6000);
    let names_ptr = smr.read_ptr(model_addr + MODEL_BONE_NAMES)?;
    let parents_ptr = smr.read_ptr(model_addr + MODEL_BONE_PARENTS)?;
    let flags_ptr = smr.read_ptr(model_addr + MODEL_BONE_FLAGS)?;
    let mut bones = Vec::with_capacity(bone_count);
    for i in 0..bone_count {
        let name = if names_ptr != 0 {
            let np = smr.read_ptr(names_ptr + (i as u64) * 8).unwrap_or(0);
            smr.read_string(np, 64).unwrap_or_default()
        } else { format!("bone{}", i) };
        let parent = if parents_ptr != 0 {
            let p = smr.read_at::<u16>(parents_ptr, (i as u64) * 2).unwrap_or(u16::MAX);
            if (p as usize) < bone_count { Some(p as usize) } else { None }
        } else { None };
        let flags = if flags_ptr != 0 {
            smr.read_at::<u32>(flags_ptr, (i as u64) * 4).unwrap_or(0)
        } else { 0 };
        bones.push(SafeBoneDef { name, parent, flags });
    }
    Ok(SafeModelInfo { hull_min, hull_max, view_min, view_max, bone_count, bones })
}

// ---- Globals ----
pub fn read_globals(smr: &SafeMemoryReader, addr: u64) -> anyhow::Result<SafeGlobals> {
    use ofs::*;
    Ok(SafeGlobals {
        cur_time: smr.read_at::<f32>(addr, GLOBALS_CURTIME)?,
        frame_count: smr.read_at::<u32>(addr, GLOBALS_FRAMECOUNT)?,
        max_players: smr.read_at::<u32>(addr, GLOBALS_MAXPLAYERS)?,
        interval: smr.read_at::<f32>(addr, GLOBALS_INTERVAL)?,
        time2: smr.read_at::<f32>(addr, GLOBALS_TIME2)?,
    })
}
