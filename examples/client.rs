//! Making HTTP requests over Tor.
//!
//! ```console
//! $ cargo run --example client
//! ```

use hypertor::TorClient;

#[tokio::main]
async fn main() -> hypertor::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "hypertor=info".into()),
        )
        .init();

    // Bootstrapping downloads a Tor directory. The first run takes a while;
    // later runs reuse the cache.
    println!("bootstrapping Tor...");
    let client = TorClient::new().await?;
    println!("connected\n");

    // Confirm we are actually going through Tor.
    let response = client
        .get("https://check.torproject.org/api/ip")?
        .send()
        .await?
        .error_for_status()?;

    println!("exit relay says: {}", response.text()?);

    // Onion services need no exit relay at all.
    let response = client
        .get("http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/")?
        .send()
        .await?;

    println!(
        "DuckDuckGo onion: {} ({} bytes)",
        response.status(),
        response.len()
    );

    // A second request to the same host reuses the pooled connection and its
    // circuit, so it returns far faster than the first.
    let start = std::time::Instant::now();
    client
        .get("https://check.torproject.org/api/ip")?
        .send()
        .await?;
    println!("second request to a warm connection: {:?}", start.elapsed());

    Ok(())
}
