//! Keeping activities on separate Tor circuits.
//!
//! ```console
//! $ cargo run --example isolation
//! ```

use hypertor::{IsolationToken, TorClient};

#[tokio::main]
async fn main() -> hypertor::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("hypertor=info")
        .init();

    let client = TorClient::new().await?;

    // Two personas that must never be linkable to each other. Requests carrying
    // the same token share a circuit; different tokens never do.
    let alice = IsolationToken::new();
    let bob = IsolationToken::new();

    for (name, token) in [("alice", alice), ("bob", bob)] {
        let ip: serde_json::Value = client
            .get("https://check.torproject.org/api/ip")?
            .isolation(token)
            .send()
            .await?
            .json()?;

        println!("{name} exits from {}", ip["IP"]);
    }

    // The same token again reuses alice's circuit, so the exit IP matches.
    let ip: serde_json::Value = client
        .get("https://check.torproject.org/api/ip")?
        .isolation(alice)
        .send()
        .await?
        .json()?;

    println!("alice again exits from {} (same as before)", ip["IP"]);

    Ok(())
}
