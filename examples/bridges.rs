//! Reaching Tor from a network that blocks it.
//!
//! Bridges are unlisted relays; a pluggable transport disguises the traffic so
//! deep packet inspection cannot recognise it as Tor. Get real bridge lines
//! from <https://bridges.torproject.org>.
//!
//! ```console
//! $ cargo run --example bridges
//! ```

use hypertor::{TorClient, VanguardMode};

#[tokio::main]
async fn main() -> hypertor::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("hypertor=info")
        .init();

    // Replace these with bridge lines issued to you. Shared, published bridges
    // are the first ones a censor blocks.
    let bridges = [
        "obfs4 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=... iat-mode=0",
        "obfs4 192.0.2.2:443 89ABCDEF0123456789ABCDEF0123456789ABCDEF cert=... iat-mode=0",
    ];

    let result = TorClient::builder()
        .bridges(bridges)
        // obfs4 ships as the `lyrebird` binary in current Tor packages.
        .transport("obfs4", "/usr/bin/lyrebird")
        // Vanguards cost little and blunt guard-discovery attacks.
        .vanguards(VanguardMode::Full)
        .build()
        .await;

    match result {
        Ok(client) => {
            let response = client
                .get("https://check.torproject.org/api/ip")?
                .send()
                .await?;
            println!("reached Tor through a bridge: {}", response.text()?);
        }
        Err(e) => {
            eprintln!("could not connect through the configured bridges: {e}");
            eprintln!("the placeholder bridge lines above are not real relays.");
        }
    }

    Ok(())
}
