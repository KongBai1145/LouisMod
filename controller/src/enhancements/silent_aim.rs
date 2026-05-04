use anyhow::Context;
use cs2::{
    CEntityIdentityEx,
    ClassNameCache,
    MouseState,
    StateCS2Memory,
    StateEntityList,
    StateLocalPlayerController,
};
use cs2_schema_generated::cs2::client::{
    C_BaseEntity,
    C_BaseModelEntity,
    C_CSPlayerPawn,
    CGameSceneNode,
    CSkeletonInstance,
};
use nalgebra::Vector3;
use overlay::UnicodeTextRenderer;
use raw_struct::builtins::Ptr64;

use cs2_schema_provider::runtime_offset;

use super::Enhancement;
use crate::{
    settings::{
        AppSettings,
        KeyToggleMode,
    },
    view::KeyToggle,
    UpdateContext,
};

pub struct SilentAim {
    toggle: KeyToggle,
}

impl SilentAim {
    pub fn new() -> Self {
        Self {
            toggle: KeyToggle::new(),
        }
    }

    fn calc_angle(src: Vector3<f32>, dst: Vector3<f32>) -> (f32, f32) {
        let delta = dst - src;
        let hyp = (delta.x * delta.x + delta.y * delta.y).sqrt();
        let pitch = -delta.z.atan2(hyp).to_degrees();
        let yaw = delta.y.atan2(delta.x).to_degrees();
        (pitch.clamp(-89.0, 89.0), yaw)
    }

    fn calc_fov(current: (f32, f32), target: (f32, f32)) -> f32 {
        let dp = current.0 - target.0;
        let dy = current.1 - target.1;
        (dp * dp + dy * dy).sqrt()
    }
}

impl Enhancement for SilentAim {
    fn update(&mut self, ctx: &UpdateContext) -> anyhow::Result<()> {
        let settings = ctx.states.resolve::<AppSettings>(())?;
        if !settings.aim_silent {
            return Ok(());
        }

        let mode = if settings.aim_silent_hotkey.is_some() {
            KeyToggleMode::Trigger
        } else {
            KeyToggleMode::AlwaysOn
        };

        self.toggle.update(&mode, ctx.input, &settings.aim_silent_hotkey);
        if !self.toggle.enabled {
            return Ok(());
        }

        let memory = ctx.states.resolve::<StateCS2Memory>(())?;
        let entities = ctx.states.resolve::<StateEntityList>(())?;
        let class_name_cache = ctx.states.resolve::<ClassNameCache>(())?;

        // Get local player controller and pawn
        let local_controller = ctx.states.resolve::<StateLocalPlayerController>(())?;
        let Some(local_controller_ref) = local_controller
            .instance
            .value_reference(memory.view_arc())
        else {
            return Ok(());
        };
        let local_team = local_controller_ref.m_iTeamNum()?;
        let local_pawn_handle = local_controller_ref.m_hPlayerPawn()?;
        let local_pawn_ptr = match entities.entity_from_handle(&local_pawn_handle) {
            Some(ptr) => ptr,
            None => return Ok(()),
        };

        // Read local pawn data
        let local_pawn = match local_pawn_ptr.value_reference(memory.view_arc()) {
            Some(pawn) => pawn,
            None => return Ok(()),
        };

        // Save original eye angles for restore
        let original_angles = local_pawn.m_angEyeAngles()?;

        // Get local player eye position
        let local_scene_node = local_pawn
            .m_pGameSceneNode()?
            .value_reference(memory.view_arc())
            .context("local game scene node nullptr")?
            .cast::<dyn CSkeletonInstance>();
        let local_origin = Vector3::from_column_slice(&local_scene_node.m_vecAbsOrigin()?);
        let view_offset = local_pawn.m_vecViewOffset()?;
        let local_eye_pos =
            local_origin + Vector3::new(view_offset.m_vecX()?, view_offset.m_vecY()?, view_offset.m_vecZ()?);

        let current_angles = (original_angles[0], original_angles[1]);

        // Find best target within FOV
        let mut best_fov = settings.aim_silent_fov;
        let mut best_angle: Option<(f32, f32)> = None;

        for entity_identity in entities.entities() {
            let class_name = match class_name_cache
                .lookup(&entity_identity.entity_class_info()?)
            {
                Ok(Some(name)) => name,
                _ => continue,
            };
            if *class_name != "C_CSPlayerPawn" {
                continue;
            }

            let pawn_ptr: Ptr64<dyn C_CSPlayerPawn> = entity_identity.entity_ptr()?;
            let pawn = match pawn_ptr.value_reference(memory.view_arc()) {
                Some(p) => p,
                None => continue,
            };

            // Skip local player
            if pawn_ptr.address == local_pawn_ptr.address {
                continue;
            }

            // Health check
            if pawn.m_iHealth()? <= 0 {
                continue;
            }

            // Team check
            if settings.aim_silent_team_check && pawn.m_iTeamNum()? == local_team {
                continue;
            }

            // Dormant check
            let scene_node = match pawn
                .m_pGameSceneNode()?
                .value_reference(memory.view_arc())
            {
                Some(node) => node.cast::<dyn CSkeletonInstance>(),
                None => continue,
            };
            if scene_node.m_bDormant()? {
                continue;
            }

            let target_pos = Vector3::from_column_slice(&scene_node.m_vecAbsOrigin()?);
            let target_eye = target_pos + Vector3::new(0.0, 0.0, 36.0);

            let aim_angle = Self::calc_angle(local_eye_pos, target_eye);
            let fov = Self::calc_fov(current_angles, aim_angle);

            if fov < best_fov {
                best_fov = fov;
                best_angle = Some(aim_angle);
            }
        }

        // Apply silent aim
        if let Some((pitch, yaw)) = best_angle {
            let eye_angles_offset = runtime_offset!(15824, "client.dll", "C_CSPlayerPawn", "m_angEyeAngles");
            let write_addr = local_pawn_ptr.address + eye_angles_offset;
            let aim_angles = [pitch, yaw, original_angles[2], original_angles[3]];

            // Write aim angles
            ctx.cs2.write_sized::<[f32; 4]>(write_addr, &aim_angles)?;

            // Auto shoot if enabled
            if settings.aim_silent_auto_shoot {
                ctx.cs2.send_mouse_state(&[MouseState {
                    buttons: [Some(true); 5],
                    ..Default::default()
                }])?;

                ctx.cs2.send_mouse_state(&[MouseState {
                    buttons: [Some(false); 5],
                    ..Default::default()
                }])?;
            }

            // Restore original angles immediately
            ctx.cs2.write_sized::<[f32; 4]>(write_addr, &original_angles)?;
        }

        Ok(())
    }

    fn render(
        &self,
        _states: &utils_state::StateRegistry,
        _ui: &imgui::Ui,
        _unicode_text: &UnicodeTextRenderer,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}
