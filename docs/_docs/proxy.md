---
title: "SOCKS5 Proxy"
permalink: /docs/proxy/
excerpt: "Run a local SOCKS5 proxy to route any application through Tor"
---

Run a local SOCKS5 proxy server that routes any SOCKS5-compatible application through the Tor network.

## Overview

The `Socks5Proxy` component provides a standard SOCKS5 proxy interface, allowing you to:

- **Universal Tor Access** — Route any SOCKS5-compatible application through Tor
- **Zero Configuration** — Default binds to `127.0.0.1:9050` (Tor standard)
- **Circuit Isolation** — Separate Tor circuits per connection or user
- **Multi-Identity** — Run multiple proxies with different isolation tokens

## Basic Usage

### Rust

```rust
use hypertor::{Socks5Proxy, Result};

#[tokio::main]
async fn main() -> Result<()> {
    // Start SOCKS5 proxy on default address (127.0.0.1:9050)
    let proxy = Socks5Proxy::with_defaults();
    
    println!("SOCKS5 proxy running on 127.0.0.1:9050");
    println!("Press Ctrl+C to stop");
    
    proxy.run().await?;
    Ok(())
}
```

### Custom Configuration

```rust
use hypertor::{Socks5Proxy, ProxyConfig};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

let config = ProxyConfig {
    bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1080),
    isolation_by_auth: true,  // Different Tor identity per SOCKS auth
    timeout_secs: 120,
};

let proxy = Socks5Proxy::with_config(config);
proxy.run().await?;
```

## Using the Proxy

Once the SOCKS5 proxy is running, you can route any SOCKS5-compatible application through Tor:

### curl

```bash
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
```

> **Note**: Use `--socks5-hostname` (not `--socks5`) to resolve DNS through Tor. This prevents DNS leaks.

### wget

```bash
wget -e use_proxy=yes -e http_proxy=socks5://127.0.0.1:9050 https://example.com
```

### Python (requests)

```python
import requests

proxies = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

resp = requests.get('https://check.torproject.org/api/ip', proxies=proxies)
print(f"Tor IP: {resp.json()['IP']}")
```

> **Note**: Use `socks5h://` (with 'h') to resolve DNS through the proxy (Tor). Plain `socks5://` leaks DNS.

### Python (aiohttp)

```python
import aiohttp
import aiohttp_socks

async def fetch_via_tor():
    connector = aiohttp_socks.ProxyConnector.from_url('socks5://127.0.0.1:9050')
    async with aiohttp.ClientSession(connector=connector) as session:
        async with session.get('https://check.torproject.org/api/ip') as resp:
            data = await resp.json()
            print(f"Tor IP: {data['IP']}")
```

### Git

```bash
git config --global http.proxy socks5h://127.0.0.1:9050
git clone https://github.com/example/repo.git
```

### SSH

```bash
ssh -o ProxyCommand='nc -x 127.0.0.1:9050 %h %p' user@host
```

### Firefox/Browsers

1. Settings → Network Settings
2. Manual proxy configuration
3. SOCKS Host: `127.0.0.1`, Port: `9050`
4. SOCKS v5
5. ✅ "Proxy DNS when using SOCKS v5"

## Circuit Isolation

Control how Tor circuits are assigned to connections:

### Per-Connection Isolation

```rust
use hypertor::{Socks5Proxy, ProxyConfig};

// Each connection gets its own Tor circuit (different exit IP)
let proxy = Socks5Proxy::builder()
    .isolation_per_connection(true)
    .build();
```

### Authentication-Based Isolation

```rust
// Different SOCKS auth credentials = different Tor identity
let proxy = Socks5Proxy::builder()
    .isolation_by_auth(true)
    .build();

// Client A: socks5://user1:pass1@127.0.0.1:9050 → Circuit A
// Client B: socks5://user2:pass2@127.0.0.1:9050 → Circuit B
```

### Custom Isolation Tokens

```rust
use hypertor::{Socks5Proxy, IsolationToken};

// Create proxy with custom isolation token
let token = IsolationToken::new();
let proxy = Socks5Proxy::builder()
    .isolation_token(token.clone())
    .build();

// All connections through this proxy share the same Tor circuit
```

## Multi-Identity Proxies

Run multiple SOCKS5 proxies with different identities:

```rust
use hypertor::{Socks5Proxy, IsolationToken};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

// Proxy 1: Identity for browsing
let proxy1 = Socks5Proxy::builder()
    .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9051))
    .isolation_token(IsolationToken::new())
    .build();

// Proxy 2: Identity for API access  
let proxy2 = Socks5Proxy::builder()
    .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9052))
    .isolation_token(IsolationToken::new())
    .build();

// Run both
tokio::join!(proxy1.run(), proxy2.run());
```

## Security Considerations

### DNS Leaks

Always use `socks5h://` (with 'h') in clients that support it, or `--socks5-hostname` for curl. This ensures DNS resolution happens through Tor, not locally.

### Local Binding

By default, the proxy binds to `127.0.0.1` (localhost only). If you need to expose it on a network:

```rust
// ⚠️ Exposes Tor proxy to network - use with caution!
let proxy = Socks5Proxy::builder()
    .bind("0.0.0.0:9050".parse()?)
    .build();
```

### Authentication

For network-exposed proxies, enable authentication:

```rust
let proxy = Socks5Proxy::builder()
    .auth("username", "password")
    .build();
```

## Example: Full Application

```rust
use hypertor::{Socks5Proxy, ProxyConfig, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[tokio::main]
async fn main() -> Result<()> {
    // Configure proxy
    let proxy = Socks5Proxy::builder()
        .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9050))
        .isolation_by_auth(true)
        .build();
    
    println!("╔════════════════════════════════════════╗");
    println!("║  hypertor SOCKS5 Proxy                ║");
    println!("╠════════════════════════════════════════╣");
    println!("║  Address: 127.0.0.1:9050              ║");
    println!("║  Isolation: Per-authentication        ║");
    println!("╚════════════════════════════════════════╝");
    println!();
    println!("Test with:");
    println!("  curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip");
    
    proxy.run().await?;
    Ok(())
}
```

## Next Steps

- [TorClient Documentation](/docs/client/) — Direct HTTP client API
- [OnionApp Documentation](/docs/server/) — Host your own .onion service
- [Security Features](/docs/security/) — PoW, Vanguards, Leak Detection
