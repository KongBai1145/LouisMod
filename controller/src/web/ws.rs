use axum::extract::ws::{
    Message,
    WebSocket,
};
use futures_util::{
    SinkExt,
    StreamExt,
};
use tokio::sync::broadcast;

use super::server::WebAppState;

pub async fn handle_web_socket(mut socket: WebSocket, state: WebAppState) {
    let mut rx = state.ws_tx.subscribe();

    // Send initial settings on connect
    let initial_msg = {
        let settings = state.settings.read().unwrap();
        serde_json::to_string(&*settings)
            .ok()
            .map(|json| format!("{{\"type\":\"settings\",\"payload\":{}}}", json))
    };

    if let Some(msg) = initial_msg {
        if socket.send(Message::Text(msg)).await.is_err() {
            return;
        }
    }

    // Split socket into send/recv halves
    let (mut sender, mut receiver) = socket.split();

    // Channel to bridge broadcast messages into the select! loop
    let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<String>();

    // Forward broadcast messages to the channel
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(msg) => {
                    if out_tx.send(msg).is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Closed) => break,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
            }
        }
    });

    // Main loop: handle incoming messages and outgoing broadcasts
    loop {
        tokio::select! {
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Close(_))) => break,
                    Some(Ok(Message::Text(text))) => {
                        if text.trim() == r#"{"type":"ping"}"# {
                            // pong is implicit or ignore
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) => break,
                    None => break,
                }
            }
            Some(msg) = out_rx.recv() => {
                if sender.send(Message::Text(msg)).await.is_err() {
                    break;
                }
            }
        }
    }
}
