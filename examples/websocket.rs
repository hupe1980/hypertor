//! WebSocket over Tor.
//!
//! ```console
//! $ cargo run --example websocket --features ws
//! ```

use hypertor::{TorClient, TorWebSocket, WsMessage};

#[tokio::main]
async fn main() -> hypertor::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("hypertor=info")
        .init();

    let client = TorClient::new().await?;

    // Override with your own endpoint:
    //   HYPERTOR_WS_URL=ws://your.onion/socket cargo run --example websocket --features ws
    let url = std::env::var("HYPERTOR_WS_URL")
        .unwrap_or_else(|_| "wss://echo.websocket.events/".to_string());

    println!("connecting to {url} over Tor...");

    // The connection honours the client's IsolationLevel, exactly as an HTTP
    // request would. `TorWebSocket::builder` pins a circuit, adds handshake
    // headers, or changes the message size limits.
    let ws = TorWebSocket::connect(&client, &url).await?;

    // Sending and receiving both need `&mut`, so an interactive protocol has to
    // split the connection to do both at once.
    let (mut tx, mut rx) = ws.split();

    let reader = tokio::spawn(async move {
        while let Ok(Some(message)) = rx.recv().await {
            match message {
                WsMessage::Text(text) => println!("echoed back: {text}"),
                WsMessage::Close(reason) => {
                    println!("peer closed: {reason:?}");
                    break;
                }
                other => println!("received: {other:?}"),
            }
        }
    });

    tx.send_text("hello from hypertor").await?;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    tx.close().await?;
    reader.await.ok();
    Ok(())
}
