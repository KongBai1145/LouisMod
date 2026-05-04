use axum::{
    extract::{
        Path,
        State,
    },
    Json,
};
use serde_json::Value;

use super::server::WebAppState;
use crate::settings::{
    AppSettings,
    EspSelector,
};

pub async fn get_settings(State(state): State<WebAppState>) -> Json<Value> {
    let settings = state.settings.read().unwrap();
    match serde_json::to_value(&*settings) {
        Ok(value) => Json(value),
        Err(e) => Json(serde_json::json!({"error": e.to_string()})),
    }
}

pub async fn update_settings(
    State(state): State<WebAppState>,
    Json(updates): Json<Value>,
) -> Json<Value> {
    let mut settings = state.settings.write().unwrap();

    // Try direct deserialization first (full replacement)
    if let Ok(new_settings) = serde_json::from_value::<AppSettings>(updates.clone()) {
        *settings = new_settings;
    } else {
        // Fallback: deep merge the update into current settings
        let current = serde_json::to_value(&*settings).unwrap_or_default();
        let merged = deep_merge(current, updates);
        match serde_json::from_value::<AppSettings>(merged) {
            Ok(new_settings) => *settings = new_settings,
            Err(e) => {
                return Json(
                    serde_json::json!({"error": format!("failed to apply settings: {}", e)}),
                )
            }
        }
    }

    state
        .settings_changed
        .store(true, std::sync::atomic::Ordering::Release);
    Json(serde_json::json!({"status": "ok"}))
}

pub async fn save_settings(State(state): State<WebAppState>) -> Json<Value> {
    let settings = state.settings.read().unwrap();
    match crate::settings::save_app_settings(&*settings) {
        Ok(()) => Json(serde_json::json!({"status": "ok"})),
        Err(e) => Json(serde_json::json!({"error": e.to_string()})),
    }
}

pub async fn get_esp_configs(State(state): State<WebAppState>) -> Json<Value> {
    let settings = state.settings.read().unwrap();
    let mut configs = serde_json::Map::new();

    for (key, config) in &settings.esp_settings {
        if let Ok(value) = serde_json::to_value(config) {
            let enabled = settings
                .esp_settings_enabled
                .get(key)
                .copied()
                .unwrap_or(false);
            if let Some(obj) = value.as_object() {
                let mut entry = obj.clone();
                entry.insert("enabled".to_string(), serde_json::json!(enabled));
                entry.insert("key".to_string(), serde_json::json!(key));
                configs.insert(key.clone(), serde_json::Value::Object(entry));
            }
        }
    }

    Json(serde_json::json!({
        "configs": configs,
        "tree": build_esp_tree(&settings)
    }))
}

pub async fn get_esp_config(
    State(state): State<WebAppState>,
    Path(key): Path<String>,
) -> Json<Value> {
    let settings = state.settings.read().unwrap();
    match settings.esp_settings.get(&key) {
        Some(config) => {
            let mut value = serde_json::to_value(config).unwrap_or_default();
            let enabled = settings
                .esp_settings_enabled
                .get(&key)
                .copied()
                .unwrap_or(false);
            if let Some(obj) = value.as_object_mut() {
                obj.insert("enabled".to_string(), serde_json::json!(enabled));
                obj.insert("key".to_string(), serde_json::json!(key));
            }
            Json(value)
        }
        None => Json(serde_json::json!({"error": "config not found"})),
    }
}

pub async fn update_esp_config(
    State(state): State<WebAppState>,
    Path(key): Path<String>,
    Json(updates): Json<Value>,
) -> Json<Value> {
    let mut settings = state.settings.write().unwrap();

    if let Some(config) = settings.esp_settings.get_mut(&key) {
        if let Ok(updated) = serde_json::from_value(updates.clone()) {
            *config = updated;
        }

        if let Some(enabled) = updates.get("enabled").and_then(|v| v.as_bool()) {
            settings.esp_settings_enabled.insert(key.clone(), enabled);
        }

        state
            .settings_changed
            .store(true, std::sync::atomic::Ordering::Release);
        Json(serde_json::json!({"status": "ok"}))
    } else {
        Json(serde_json::json!({"error": "config not found"}))
    }
}

pub async fn toggle_feature(
    State(state): State<WebAppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Json<Value> {
    let feature = match params.get("feature") {
        Some(f) => f.as_str(),
        None => return Json(serde_json::json!({"error": "missing feature parameter"})),
    };

    let mut settings = state.settings.write().unwrap();
    match feature {
        "bomb_timer" => settings.bomb_timer = !settings.bomb_timer,
        "bomb_label" => settings.bomb_label = !settings.bomb_label,
        "spectators_list" => settings.spectators_list = !settings.spectators_list,
        "watermark" => settings.valthrun_watermark = !settings.valthrun_watermark,
        "sniper_crosshair" => settings.sniper_crosshair = !settings.sniper_crosshair,
        "hide_overlay" => {
            settings.hide_overlay_from_screen_capture = !settings.hide_overlay_from_screen_capture
        }
        "debug_window" => settings.render_debug_window = !settings.render_debug_window,
        "aim_assist_recoil" => settings.aim_assist_recoil = !settings.aim_assist_recoil,
        "aim_silent" => settings.aim_silent = !settings.aim_silent,
        other => return Json(serde_json::json!({"error": format!("unknown feature: {}", other)})),
    }

    state
        .settings_changed
        .store(true, std::sync::atomic::Ordering::Release);
    Json(serde_json::json!({"status": "ok", "feature": feature}))
}

fn deep_merge(base: Value, overlay: Value) -> Value {
    match (base, overlay) {
        (Value::Object(mut base_map), Value::Object(overlay_map)) => {
            for (k, v) in overlay_map {
                if base_map.contains_key(&k) && v.is_object() {
                    let base_val = base_map.remove(&k).unwrap();
                    base_map.insert(k, deep_merge(base_val, v));
                } else {
                    base_map.insert(k, v);
                }
            }
            Value::Object(base_map)
        }
        (_, overlay) => overlay,
    }
}

fn build_esp_tree(settings: &AppSettings) -> Value {
    fn walk_selector(selector: &EspSelector, settings: &AppSettings) -> Value {
        let key = selector.config_key();
        let display = selector.config_display();
        let enabled = settings
            .esp_settings_enabled
            .get(&key)
            .copied()
            .unwrap_or(false);
        let has_config = settings.esp_settings.contains_key(&key);

        let children: Vec<Value> = selector
            .children()
            .iter()
            .map(|child| walk_selector(child, settings))
            .collect();

        serde_json::json!({
            "key": key,
            "display": display,
            "enabled": enabled,
            "hasConfig": has_config,
            "children": children,
        })
    }

    let player = walk_selector(&EspSelector::Player, settings);
    let chicken = walk_selector(&EspSelector::Chicken, settings);
    let weapon = walk_selector(&EspSelector::Weapon, settings);

    serde_json::json!([player, chicken, weapon])
}
