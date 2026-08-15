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

    // Binding first means the address is known before anything is served,
    // which matters when the configured port is 0.
    let proxy = SocksProxy::from_client(&client, SocksConfig::default()).await?;
    let addr = proxy.local_addr()?;

    println!("SOCKS5 proxy on {addr}\n");
    println!("  curl --socks5-hostname {addr} https://check.torproject.org/api/ip");
    println!("\nDifferent SOCKS credentials get different circuits:");
    println!("  curl -x socks5h://alice:x@{addr} https://check.torproject.org/api/ip");
    println!("  curl -x socks5h://bob:x@{addr}   https://check.torproject.org/api/ip");

    proxy.serve().await
}
