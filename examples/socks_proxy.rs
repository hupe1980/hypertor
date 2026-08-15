//! A local SOCKS5 proxy that routes any program through Tor.
//!
//! ```console
//! $ cargo run --example socks_proxy
//! $ curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
//! ```
//!
//! Use `socks5h` (curl's `--socks5-hostname`), not `socks5`: the latter makes
//! the client resolve DNS locally, which leaks every hostname you visit.

use hypertor::{SocksConfig, SocksProxy, TorClient};

#[tokio::main]
async fn main() -> hypertor::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("hypertor=info")
        .init();

    println!("bootstrapping Tor...");
    let client = TorClient::new().await?;

    let config = SocksConfig::default();
    println!("SOCKS5 proxy on {}\n", config.bind_addr);
    println!(
        "  curl --socks5-hostname {} https://check.torproject.org/api/ip",
        config.bind_addr
    );
    println!("\nDifferent SOCKS credentials get different circuits:");
    println!(
        "  curl -x socks5h://alice:x@{} https://check.torproject.org/api/ip",
        config.bind_addr
    );
    println!(
        "  curl -x socks5h://bob:x@{}   https://check.torproject.org/api/ip",
        config.bind_addr
    );

    SocksProxy::from_client(&client, config).run().await
}
