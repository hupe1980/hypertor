//! SOCKS5 Proxy Example - Local Tor Proxy for Any Application
//!
//! This example demonstrates how to run a local SOCKS5 proxy that
//! routes traffic through Tor. This allows ANY application that
//! supports SOCKS5 to use Tor transparently.
//!
//! Use cases:
//! - Route curl/wget through Tor: `curl --socks5 127.0.0.1:9050 http://example.com`
//! - Configure browsers to use Tor
//! - Route Python requests through Tor
//! - Use with any SOCKS5-compatible application
//!
//! Run with: cargo run --example socks_proxy

use hypertor::{Config, ProxyConfig, Result, Socks5Proxy};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("🧅 hypertor - SOCKS5 Proxy Example");
    println!("===================================");
    println!();

    // ===========================================================================
    // Example 1: Default Proxy (localhost:9050)
    // ===========================================================================
    println!("Starting SOCKS5 proxy on 127.0.0.1:9050...");
    println!();
    println!("Usage examples:");
    println!("  curl --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip");
    println!(
        "  curl --socks5-hostname 127.0.0.1:9050 http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
    );
    println!();
    println!("Python requests:");
    println!("  import requests");
    println!(
        "  proxies = {{'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}}"
    );
    println!("  requests.get('https://check.torproject.org/api/ip', proxies=proxies)");
    println!();
    println!("Press Ctrl+C to stop the proxy.");
    println!();

    // Create proxy with default config (127.0.0.1:9050)
    let proxy = Socks5Proxy::with_defaults();

    // Run the proxy (blocks until shutdown)
    proxy.run().await?;

    println!("✅ Proxy stopped.");
    Ok(())
}

/// Example with custom configuration
#[allow(dead_code)]
async fn custom_proxy_example() -> Result<()> {
    // Custom bind address (different port)
    let bind_addr = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        19050, // Custom port
    );

    // Configure the proxy
    let proxy_config = ProxyConfig::new(bind_addr)
        .with_max_connections(100) // Limit concurrent connections
        .with_isolation(12345); // Use specific isolation token

    // Use custom Tor config if needed
    let tor_config = Config::default();

    let proxy = Socks5Proxy::new(proxy_config, tor_config);

    println!("Custom proxy on 127.0.0.1:19050");
    proxy.run().await
}

/// Example with multiple isolated proxies
#[allow(dead_code)]
async fn multi_identity_proxy() -> Result<()> {
    // Each proxy gets a different isolation token
    // Traffic through different proxies will use different Tor circuits

    let configs = vec![
        (9050u16, 1u64, "identity-1"),
        (9051u16, 2u64, "identity-2"),
        (9052u16, 3u64, "identity-3"),
    ];

    println!("Starting multiple isolated SOCKS5 proxies:");

    let mut handles = vec![];

    for (port, token, name) in configs {
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);

        let config = ProxyConfig::new(bind_addr).with_isolation(token);

        let proxy = Socks5Proxy::new(config, Config::default());

        println!("  {} on port {} (isolation token: {})", name, port, token);

        handles.push(tokio::spawn(async move {
            if let Err(e) = proxy.run().await {
                eprintln!("Proxy error: {}", e);
            }
        }));
    }

    println!();
    println!("Each proxy will route through different Tor circuits!");
    println!("Use different ports to maintain separate identities.");

    // Wait for all proxies
    for handle in handles {
        handle.await.ok();
    }

    Ok(())
}

/*
================================================================================
SOCKS5 PROXY USE CASES
================================================================================

1. COMMAND LINE TOOLS

   # Check Tor IP
   curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip

   # Access .onion sites
   curl --socks5-hostname 127.0.0.1:9050 http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion

   # wget with Tor
   wget -e use_proxy=yes -e http_proxy=socks5://127.0.0.1:9050 https://example.com

2. PYTHON APPLICATIONS

   import requests

   proxies = {
       'http': 'socks5h://127.0.0.1:9050',
       'https': 'socks5h://127.0.0.1:9050'
   }

   # Regular sites
   r = requests.get('https://check.torproject.org/api/ip', proxies=proxies)
   print(r.json())

   # .onion sites (use socks5h for DNS resolution through Tor)
   r = requests.get('http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion', proxies=proxies)

3. BROWSER CONFIGURATION

   Firefox:
   - Settings > Network Settings > Manual proxy configuration
   - SOCKS Host: 127.0.0.1, Port: 9050
   - SOCKS v5
   - Check "Proxy DNS when using SOCKS v5"

4. SSH OVER TOR

   ssh -o ProxyCommand="nc -X 5 -x 127.0.0.1:9050 %h %p" user@host

5. GIT OVER TOR

   git config --global http.proxy 'socks5://127.0.0.1:9050'

================================================================================
IMPORTANT: socks5 vs socks5h
================================================================================

- socks5://  - DNS resolution happens locally (leaks DNS!)
- socks5h:// - DNS resolution happens through Tor (recommended)

Always use socks5h:// (or --socks5-hostname in curl) for full anonymity.

================================================================================
*/
