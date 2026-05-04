use std::sync::{
    atomic::AtomicBool,
    Arc,
};

use axum::{
    extract::{
        ws::{
            WebSocket,
            WebSocketUpgrade,
        },
        State,
    },
    response::{
        Html,
        Response,
    },
    routing::get,
    Router,
};
use tokio::sync::broadcast;
use tower_http::cors::CorsLayer;

use super::api;
use crate::settings::AppSettings;

pub struct WebServer {
    pub settings: Arc<std::sync::RwLock<AppSettings>>,
    pub settings_changed: Arc<AtomicBool>,
    pub ws_tx: broadcast::Sender<String>,
}

impl WebServer {
    pub fn new(settings: AppSettings) -> Self {
        let (ws_tx, _) = broadcast::channel(32);
        Self {
            settings: Arc::new(std::sync::RwLock::new(settings)),
            settings_changed: Arc::new(AtomicBool::new(false)),
            ws_tx,
        }
    }

    pub fn new_with_state(
        settings: Arc<std::sync::RwLock<AppSettings>>,
        settings_changed: Arc<AtomicBool>,
    ) -> Self {
        let (ws_tx, _) = broadcast::channel(32);
        Self {
            settings,
            settings_changed,
            ws_tx,
        }
    }

    fn create_shared_state(&self) -> WebAppState {
        WebAppState {
            settings: self.settings.clone(),
            settings_changed: self.settings_changed.clone(),
            ws_tx: self.ws_tx.clone(),
        }
    }

    pub async fn start(self, port: u16) -> anyhow::Result<()> {
        let state = self.create_shared_state();

        let app = Router::new()
            .route(
                "/api/settings",
                get(api::get_settings).put(api::update_settings),
            )
            .route("/api/settings/save", get(api::save_settings))
            .route("/api/esp-configs", get(api::get_esp_configs))
            .route(
                "/api/esp-config/{key}",
                get(api::get_esp_config).put(api::update_esp_config),
            )
            .route("/api/action/toggle-feature", get(api::toggle_feature))
            .route("/ws", get(ws_handler))
            .route("/", get(index_handler))
            .layer(CorsLayer::permissive())
            .with_state(state);

        let addr = format!("0.0.0.0:{}", port);
        log::info!("Web control panel starting on http://{}", addr);

        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<WebAppState>) -> Response {
    ws.on_upgrade(move |socket| handle_web_socket(socket, state))
}

async fn handle_web_socket(socket: WebSocket, state: WebAppState) {
    super::ws::handle_web_socket(socket, state).await;
}

async fn index_handler() -> Html<&'static str> {
    Html(include_str!("../../resources/web/index.html"))
}

#[derive(Clone)]
pub struct WebAppState {
    pub settings: Arc<std::sync::RwLock<AppSettings>>,
    pub settings_changed: Arc<AtomicBool>,
    pub ws_tx: broadcast::Sender<String>,
}
