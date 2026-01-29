//! Real-time Communication Patterns over Tor
//!
//! This example demonstrates patterns for WebSocket-like real-time
//! communication over the Tor network.
//!
//! Includes:
//! - Long polling for real-time updates
//! - Bidirectional communication patterns
//! - True WebSocket support with TorWebSocket
//!
//! Run with: cargo run --example realtime_patterns

use hypertor::{Result, TorClient};
use std::time::{Duration, Instant};

// =============================================================================
// Long Polling Pattern
// =============================================================================

async fn demonstrate_polling(client: &TorClient) -> Result<()> {
    println!("🧅 Real-time Updates via Long Polling");
    println!("--------------------------------------");
    println!();
    println!("Long polling pattern over Tor:");
    println!();
    println!("  1. Client sends request to server");
    println!("  2. Server holds connection until data is available (or timeout)");
    println!("  3. Server responds with new data");
    println!("  4. Client immediately sends new request");
    println!();

    println!("📡 Demonstrating polling with httpbin.org via Tor...");
    println!();

    // Simulate 3 polling cycles
    for i in 1..=3 {
        let start = Instant::now();

        // In real long-polling, this would be a /poll endpoint
        // that waits for new messages
        let response = client
            .get("https://httpbin.org/delay/1")? // Simulates server holding request
            .send()
            .await?;

        let elapsed = start.elapsed();

        if response.status().is_success() {
            println!(
                "   📥 Poll {}: Got response after {:.1}s",
                i,
                elapsed.as_secs_f64()
            );
        } else {
            println!("   ⚠️  Poll {}: Status {}", i, response.status());
        }

        // Small delay before next poll
        if i < 3 {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    println!();
    println!("   ✅ Polling demonstration complete");
    Ok(())
}

// =============================================================================
// SSE Pattern Documentation
// =============================================================================

fn show_sse_pattern() {
    println!();
    println!("🧅 Server-Sent Events (SSE) Pattern");
    println!("------------------------------------");
    println!();
    println!("SSE is ideal for server→client streaming over Tor:");
    println!();
    println!(
        r#"
Example SSE Server (using OnionApp):

    use hypertor::{{OnionApp, get, ServeRequest}};
    use hypertor::streaming::StreamingResponseBuilder;
    
    let app = OnionApp::builder()
        .route("/events", get(|_req: ServeRequest| async {{
            StreamingResponseBuilder::new()
                .content_type("text/event-stream")
                .streaming(async_stream::stream! {{
                    loop {{
                        let data = get_next_event().await;
                        yield format!("data: {{}}\n\n", data);
                    }}
                }})
                .build()
        }}))
        .build();

Example SSE Client:

    let response = client.get("http://xxx.onion/events")?.send().await?;
    
    // Process events as they arrive
    for line in response.text()?.lines() {{
        if line.starts_with("data: ") {{
            let event = &line[6..];
            process_event(event);
        }}
    }}
"#
    );
}

// =============================================================================
// Bidirectional Pattern Documentation
// =============================================================================

fn show_bidirectional_pattern() {
    println!();
    println!("🧅 Bidirectional Communication Pattern");
    println!("--------------------------------------");
    println!();
    println!("Achieve WebSocket-like bidirectional communication:");
    println!();
    println!(
        r#"
Pattern: Separate send/receive channels

    async fn chat_client(client: &TorClient, onion: &str) -> Result<()> {{
        // Spawn receiver task (long polling)
        let receiver = tokio::spawn(async move {{
            let mut last_id = 0;
            loop {{
                let resp = client
                    .get(&format!("http://{{}}/poll?after={{}}", onion, last_id))?
                    .send()
                    .await?;
                    
                let messages: Vec<Message> = resp.json()?;
                for msg in messages {{
                    println!("Received: {{}}", msg.text);
                    last_id = last_id.max(msg.id);
                }}
            }}
        }});
        
        // Sender loop
        loop {{
            let message = get_user_input().await;
            client
                .post(&format!("http://{{}}/send", onion))?
                .json(&message)
                .send()
                .await?;
        }}
    }}
"#
    );
}

// =============================================================================
// True WebSocket over Tor
// =============================================================================

async fn demonstrate_websocket(client: &TorClient) -> Result<()> {
    println!();
    println!("🧅 True WebSocket over Tor");
    println!("--------------------------");
    println!();
    println!("hypertor supports real WebSocket connections through Tor!");
    println!();

    // Note: echo.websocket.org is deprecated, using a pattern demonstration
    println!("WebSocket connection pattern:");
    println!();
    println!(
        r#"
    use hypertor::{{TorClient, TorWebSocket, TorWebSocketBuilder}};
    
    let client = TorClient::new().await?;
    
    // Connect to a WebSocket server through Tor
    let ws = TorWebSocketBuilder::new(&client)
        .connect("wss://echo.websocket.events/")
        .await?;
    
    // Send a message
    ws.send_text("Hello from Tor!").await?;
    
    // Receive response
    let response = ws.recv().await?;
    println!("Received: {{}}", response);
    
    // Close gracefully
    ws.close().await?;
"#
    );

    // Actually demonstrate with httpbin (which doesn't support WS but shows the HTTP part)
    println!();
    println!("📡 Making HTTP request that would upgrade to WebSocket:");

    let start = Instant::now();
    let response = client.get("https://httpbin.org/get")?.send().await?;

    println!("   Status: {}", response.status());
    println!("   Latency: {:.1}s", start.elapsed().as_secs_f64());
    println!();
    println!("   ✅ Connection through Tor successful");
    println!("   💡 For real WebSocket, use TorWebSocketBuilder::connect()");

    Ok(())
}

// =============================================================================
// Live Demo: HTTP Chat Pattern
// =============================================================================

async fn demonstrate_http_chat(client: &TorClient) -> Result<()> {
    println!();
    println!("🧅 Live Demo: HTTP Request/Response over Tor");
    println!("---------------------------------------------");

    println!();
    println!("📡 Sending message to httpbin.org via Tor...");

    let message = serde_json::json!({
        "user": "anonymous",
        "text": "Hello from Tor!",
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    });

    let start = Instant::now();
    let response = client
        .post("https://httpbin.org/post")?
        .json(&message)
        .send()
        .await?;

    let latency = start.elapsed();

    if response.status().is_success() {
        let text = response.text()?;
        let data: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
        println!("   ✅ Message sent successfully");
        if let Some(origin) = data.get("origin").and_then(|v| v.as_str()) {
            println!("   📍 Via Tor exit: {}", origin);
        }
        if let Some(json) = data.get("json") {
            println!("   📦 Server received: {}", json);
        }
        println!("   ⏱️  Latency: {:.1}s", latency.as_secs_f64());
    } else {
        println!("   ❌ Error: {}", response.status());
    }

    Ok(())
}

// =============================================================================
// Main
// =============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("🧅 hypertor - Real-time Communication Patterns");
    println!("===============================================");
    println!();
    println!("This example shows how to achieve real-time communication over Tor.");
    println!();

    // Create client
    println!("Creating Tor client...");
    let client = TorClient::new().await?;
    println!("✅ Connected to Tor network");
    println!();

    // Run demonstrations
    match demonstrate_polling(&client).await {
        Ok(_) => {}
        Err(e) => println!("   ⚠️  Polling demo error: {}", e),
    }

    // Show patterns (documentation)
    show_sse_pattern();
    show_bidirectional_pattern();

    // WebSocket demonstration
    match demonstrate_websocket(&client).await {
        Ok(_) => {}
        Err(e) => println!("   ⚠️  WebSocket demo error: {}", e),
    }

    // Live HTTP chat demo
    match demonstrate_http_chat(&client).await {
        Ok(_) => {}
        Err(e) => println!("   ⚠️  HTTP chat demo error: {}", e),
    }

    // Summary
    println!();
    println!("================================================");
    println!("✅ Real-time patterns demonstration completed!");
    println!();
    println!("Key takeaways:");
    println!("  • Long polling works well for real-time over Tor");
    println!("  • SSE provides server→client streaming");
    println!("  • Bidirectional achieved with send/receive channels");
    println!("  • TorWebSocket provides true WebSocket support");

    Ok(())
}
