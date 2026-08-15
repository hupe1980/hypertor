//! WebSocket over Tor.
//!
//! ```console
//! $ cargo run --example websocket --features ws
//! ```

use hypertor::{TorClient, TorWebSocket};

#[tokio::main]
async fn main() -> hypertor::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("hypertor=info")
        .init();

    let client = TorClient::new().await?;

    // A public echo service, reached through Tor.
    let mut ws = TorWebSocket::connect(&client, "wss://echo.websocket.org/").await?;

    ws.send_text("hello from hypertor").await?;

    if let Some(message) = ws.recv().await? {
        println!("echoed back: {message:?}");
    }

    ws.close().await
}
