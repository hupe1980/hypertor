//! Basic usage example for hypertor
//!
//! Run with: RUST_LOG=hypertor=info cargo run --example basic_usage
//!
//! Note: First run may take 30-60 seconds to bootstrap the Tor network.
//! Subsequent runs use the cached Tor directory and are much faster.

use hypertor::{ConfigBuilder, HeaderMiddleware, MiddlewareStack, Result, RetryConfig, TorClient};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging (recommended to see bootstrap progress)
    tracing_subscriber::fmt::init();

    // ===========================================================================
    // Example 1: Simple client with Tor-appropriate timeout
    // ===========================================================================
    println!("=== Example 1: Basic Client ===");
    println!("Creating Tor client (first run may take 30-60s to bootstrap)...");

    // Use a longer timeout since Tor circuits add latency
    let config = ConfigBuilder::new()
        .timeout(Duration::from_secs(120)) // Tor needs more time
        .build()?;

    let client = TorClient::with_config(config).await?;
    println!("Tor client ready!");

    // Make a request to the official Tor check service
    // This confirms we're actually using Tor, not just showing an IP
    println!("\nFetching check.torproject.org to verify Tor connection...");

    // Use aggressive retry for reliability over Tor
    let retry_config = RetryConfig::aggressive();

    let response = hypertor::retry::with_retry(&retry_config, || async {
        client
            .get("https://check.torproject.org/api/ip")?
            .timeout(Duration::from_secs(60))
            .send()
            .await
    })
    .await?;

    println!("Status: {}", response.status());

    // Parse the JSON response to show Tor status
    let body = response.text()?;
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
        let is_tor = json.get("IsTor").and_then(|v| v.as_bool()).unwrap_or(false);
        let ip = json.get("IP").and_then(|v| v.as_str()).unwrap_or("unknown");

        if is_tor {
            println!("✓ Congratulations! You are using Tor.");
            println!("  Exit IP: {}", ip);
        } else {
            println!("✗ WARNING: Not using Tor! IP: {}", ip);
        }
    } else {
        println!("Response: {}", body);
    }

    // ===========================================================================
    // Example 2: Stream isolation for privacy
    // ===========================================================================
    println!("\n=== Example 2: Stream Isolation ===");

    // Create an isolated session (uses unique token for circuit isolation)
    // Each isolated session gets its own Tor circuit
    let isolated = client.isolated();
    println!(
        "Isolated session created with token: {:?}",
        isolated.token()
    );

    // ===========================================================================
    // Example 3: Different isolation levels
    // ===========================================================================
    println!("\n=== Example 3: Isolation Levels ===");
    println!("Available isolation levels:");
    println!("  - IsolationLevel::None: Share circuits (fastest, less private)");
    println!("  - IsolationLevel::ByHost: New circuit per host");
    println!("  - IsolationLevel::PerRequest: New circuit per request (most private)");

    // ===========================================================================
    // Example 4: Middleware stack
    // ===========================================================================
    println!("\n=== Example 4: Middleware ===");

    // Create middleware stack with Tor Browser headers
    let _middleware =
        MiddlewareStack::new().with_request(HeaderMiddleware::new().with_tor_browser_headers());

    println!("Middleware stack created with Tor Browser headers");

    // ===========================================================================
    // Connection pool stats
    // ===========================================================================
    println!("\n=== Connection Pool Stats ===");
    println!("Pool size: {}", client.pool_size());

    println!("\n✓ All examples completed successfully!");
    Ok(())
}
