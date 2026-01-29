//! Multiple Identities Example - Circuit Isolation
//!
//! This example demonstrates how to use circuit isolation to
//! maintain multiple anonymous identities simultaneously.
//!
//! Useful for:
//! - Accessing multiple accounts without correlation
//! - Testing from different Tor exit nodes
//! - Privacy-sensitive operations requiring separation
//!
//! Run with: cargo run --example multiple_identities

use hypertor::{ConfigBuilder, IsolationLevel, Result, TorClient};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("🧅 hypertor - Multiple Identities Example");
    println!("==========================================");
    println!();
    println!("Each identity uses a separate Tor circuit,");
    println!("appearing to come from a different IP address.");
    println!();

    // Create a base client
    let config = ConfigBuilder::new()
        .timeout(Duration::from_secs(60))
        .isolation(IsolationLevel::PerRequest)
        .build()?;

    let client = TorClient::with_config(config).await?;
    println!("✅ Connected to Tor network");
    println!();

    // Create isolated sessions for different identities
    println!("🔄 Creating 3 isolated identities...");
    println!();

    let identities = vec![client.isolated(), client.isolated(), client.isolated()];

    // Check each identity's IP
    println!("📡 Checking IP addresses for each identity:");
    println!("--------------------------------------------");

    let mut ips: Vec<Option<String>> = Vec::new();

    for (i, identity) in identities.iter().enumerate() {
        match client
            .get("https://check.torproject.org/api/ip")?
            .isolation(identity.token())
            .send()
            .await
        {
            Ok(response) => {
                let text = response.text()?;
                if let Ok(data) = serde_json::from_str::<serde_json::Value>(&text) {
                    let ip = data.get("IP").and_then(|v| v.as_str()).unwrap_or("unknown");
                    println!("   Identity {}: {}", i + 1, ip);
                    ips.push(Some(ip.to_string()));
                } else {
                    println!("   Identity {}: Failed to parse response", i + 1);
                    ips.push(None);
                }
            }
            Err(e) => {
                println!("   Identity {}: Error - {}", i + 1, e);
                ips.push(None);
            }
        }
    }

    // Verify isolation
    println!();
    let unique_ips: std::collections::HashSet<&String> = ips
        .iter()
        .filter_map(|ip: &Option<String>| ip.as_ref())
        .collect();
    let valid_count = ips
        .iter()
        .filter(|ip: &&Option<String>| ip.is_some())
        .count();

    if unique_ips.len() == valid_count && valid_count > 0 {
        println!("✅ All identities have different IPs!");
        println!("   Circuit isolation is working correctly.");
    } else if unique_ips.len() > 1 {
        println!("⚠️  Some identities share IPs (normal for same exit node)");
    } else if valid_count > 0 {
        println!("⚠️  All identities have the same IP");
        println!("   This can happen if Tor reuses the same exit node.");
    }

    // Demonstrate identity persistence
    println!();
    println!("📡 Testing identity persistence:");
    println!("--------------------------------");
    println!("   Making 3 requests with same identity token...");

    let persistent_identity = client.isolated();

    for i in 1..=3 {
        match client
            .get("https://check.torproject.org/api/ip")?
            .isolation(persistent_identity.token())
            .send()
            .await
        {
            Ok(response) => {
                let text = response.text()?;
                if let Ok(data) = serde_json::from_str::<serde_json::Value>(&text) {
                    let ip = data.get("IP").and_then(|v| v.as_str()).unwrap_or("?");
                    println!("   Request {}: IP = {}", i, ip);
                }
            }
            Err(e) => println!("   Request {}: Error - {}", i, e),
        }
    }

    println!();
    println!("   💡 Same identity token = same circuit = same IP");

    // Cleanup
    println!();
    println!("✅ Multiple identities demo completed!");
    println!();
    println!("Key takeaways:");
    println!("  • isolated() creates a unique circuit token");
    println!("  • Different tokens → different circuits → different IPs");
    println!("  • Same token → same circuit → same IP (until rotation)");
    println!("  • Useful for accessing multiple accounts anonymously");

    Ok(())
}
