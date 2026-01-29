# 🧅 hypertor

**The Tor network library for Rust and Python** — consume AND host onion services with the simplicity of `reqwest` and `axum`.

[![CI](https://github.com/hupe1980/hypertor/actions/workflows/ci.yml/badge.svg)](https://github.com/hupe1980/hypertor/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/hypertor.svg)](https://crates.io/crates/hypertor)
[![Documentation](https://docs.rs/hypertor/badge.svg)](https://docs.rs/hypertor)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.86-blue.svg)](https://www.rust-lang.org)

---

## Why hypertor?

Most Tor libraries only do one thing: make requests. hypertor does both:

| Component | Purpose | Similar To |
|-----------|---------|------------|
| **TorClient** | Make HTTP requests over Tor | `reqwest`, `httpx` |
| **OnionService** | Host .onion services | `axum`, `FastAPI` |

**Production-Ready Security** — All features wired to real arti APIs:

| Feature | Purpose | arti API |
|---------|---------|----------|
| 🛡️ **Vanguards** | Guard discovery protection | `VanguardConfigBuilder::mode()` |
| ⚡ **Proof-of-Work** | DoS protection (Equi-X) | `OnionServiceConfigBuilder::enable_pow()` |
| 🚦 **Rate Limiting** | Intro point flooding protection | `rate_limit_at_intro()` |
| 🔐 **Client Auth** | Restricted service discovery | `RestrictedDiscoveryConfigBuilder` |
| 🌉 **Bridges** | Censorship circumvention | `TorClientConfigBuilder::bridges()` |
| 🔌 **Pluggable Transports** | Traffic obfuscation | `TransportConfigBuilder` |

---

## Quick Start

### Rust — Client

```rust
use hypertor::{TorClient, Result};

#[tokio::main]
async fn main() -> Result<()> {
    // Create client (connects to Tor network)
    let client = TorClient::new().await?;
    
    // Make requests just like reqwest
    let resp = client
        .get("http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion")?
        .send()
        .await?;
    
    println!("Tor Check: {}", resp.text()?);
    Ok(())
}
```

### Rust — Server

```rust
use hypertor::{OnionApp, ServeResponse};

#[tokio::main]
async fn main() -> hypertor::Result<()> {
    let app = OnionApp::new()
        .get("/", || async { ServeResponse::text("Hello from .onion!") })
        .get("/health", || async { 
            ServeResponse::text(r#"{"status":"ok"}"#)
                .with_header("Content-Type", "application/json")
        });
    
    // Start the hidden service
    let addr = app.run().await?;
    println!("🧅 Live at: {}", addr);
    Ok(())
}
```

### Python — Client

```python
import asyncio
from hypertor import AsyncClient

async def main():
    async with AsyncClient(timeout=60) as client:
        # Check our Tor IP
        resp = await client.get("https://check.torproject.org/api/ip")
        print(f"Tor IP: {resp.json().get('IP')}")
        
        # Access an onion service
        resp = await client.get(
            "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
        )
        print(f"Status: {resp.status_code}")

asyncio.run(main())
```

### Python — Server (FastAPI-style)

```python
from hypertor import OnionApp

app = OnionApp()

@app.get("/")
async def home():
    return "Welcome to my .onion service!"

@app.post("/api/echo")
async def echo(request):
    data = await request.json()
    return {"received": data}

@app.get("/users/{user_id}")
async def get_user(user_id: int):
    return {"id": user_id, "name": "Alice"}

if __name__ == "__main__":
    app.run()  # 🧅 Service live at: xyz...xyz.onion
```

---

## Installation

### Rust

```toml
[dependencies]
hypertor = "0.4"
tokio = { version = "1", features = ["full"] }
```

### Python

```bash
pip install hypertor
```

### TLS Backends

hypertor defaults to **rustls** for security reasons:

| Backend | Default | Security | Notes |
|---------|---------|----------|-------|
| `rustls` | ✅ | **Best** | Consistent TLS fingerprint, pure Rust, memory-safe |
| `native-tls` | | Good | Uses OS TLS stack, platform-specific fingerprints |

#### Why rustls is the default

For anonymity-focused applications, **TLS fingerprinting** is a real threat. Different TLS libraries produce different fingerprints based on cipher suite ordering, extensions, and timing. Using `native-tls` means:

- **Linux**: OpenSSL fingerprint
- **macOS**: SecureTransport fingerprint (also has Tor stream compatibility issues)
- **Windows**: SChannel fingerprint

This leaks your operating system to any observer. With `rustls`, you get the **same fingerprint on all platforms**, making it harder to distinguish users.

Additionally, `rustls` is:
- **Memory-safe**: Pure Rust, no C library vulnerabilities
- **Auditable**: Easier to verify for security
- **Isolated**: Not affected by compromised system CA stores

If you need `native-tls` for specific compatibility:

```toml
[dependencies]
hypertor = { version = "0.4", default-features = false, features = ["client", "native-tls"] }
```

---

## Features

### 🔌 TorClient — HTTP Client

```rust
use hypertor::{TorClient, IsolationLevel};
use std::time::Duration;

// Builder pattern for full control
let client = TorClient::builder()
    .timeout(Duration::from_secs(60))
    .max_connections(20)
    .isolation(IsolationLevel::PerRequest)  // Fresh circuit per request
    .follow_redirects(true)
    .build()
    .await?;

// POST with typed JSON
let resp = client.post("http://api.onion/users")?
    .json(&User { name: "Alice".into() })
    .send().await?;

// Query parameters
let resp = client.get("http://api.onion/search")?
    .query(&[("q", "rust"), ("page", "1")])
    .send().await?;
```

### 🧅 OnionApp — Hidden Service Framework

```rust
use hypertor::{OnionApp, OnionAppConfig, ServeRequest, ServeResponse, get};
use std::time::Duration;

let config = OnionAppConfig::new()
    .with_port(80)
    .with_timeout(Duration::from_secs(30))
    .with_key_path("/var/lib/myapp/keys");  // Persist .onion address

let app = OnionApp::with_config(config)
    .get("/", || async { ServeResponse::text("Home") })
    .post("/api/data", |req: ServeRequest| async move {
        let body = req.text().unwrap_or_default();
        ServeResponse::text(&format!(r#"{{"echo":{}}}"#, body))
    })
    .route("/health", get(|| async {
        ServeResponse::text(r#"{"status":"healthy"}"#)
            .with_header("Content-Type", "application/json")
    }));

let addr = app.run().await?;  // Returns "abc...xyz.onion"
```

### 🔐 Security Configuration

hypertor provides security presets that configure real arti hardening features:

```rust
use hypertor::security::{SecurityLevel, ServiceSecurityConfig};
use hypertor::onion_service::OnionServiceConfig;

// Security presets for onion services
let standard = ServiceSecurityConfig::standard();   // Basic protection
let enhanced = ServiceSecurityConfig::enhanced();   // PoW + rate limiting
let maximum = ServiceSecurityConfig::maximum();     // Full hardening

// Or configure manually with fluent API
let config = OnionServiceConfig::new("my-service")
    .with_pow()                        // Proof-of-Work (Equi-X)
    .pow_queue_depth(16000)            // Queue depth
    .rate_limit_at_intro(10.0, 20)     // Rate: 10/s, burst: 20
    .max_streams_per_circuit(100)      // Stream limit
    .vanguards_full()                  // Full vanguards
    .num_intro_points(5);              // High availability
```

### 🌉 Censorship Circumvention (China, Iran, Russia)

```rust
use hypertor::{TorClientBuilder, VanguardMode};

let client = TorClientBuilder::new()
    // Multiple bridges for redundancy
    .bridge("obfs4 192.0.2.1:443 FINGERPRINT cert=... iat-mode=0")
    .bridge("obfs4 192.0.2.2:443 FINGERPRINT cert=... iat-mode=0")
    // Pluggable transport binary
    .transport("obfs4", "/usr/bin/obfs4proxy")
    // Full vanguards for hostile networks
    .vanguards(VanguardMode::Full)
    .build()
    .await?;
```

### 🔄 Stream Isolation

Keep different activities on separate Tor circuits:

```rust
use hypertor::{TorClient, IsolationToken};

let client = TorClient::new().await?;

// Create isolated sessions
let banking = IsolationToken::new();
let browsing = IsolationToken::new();

// These use the same circuit (banking identity)
client.get("http://bank.onion")?.isolation(banking.clone()).send().await?;
client.get("http://bank.onion/transfer")?.isolation(banking.clone()).send().await?;

// This uses a different circuit (browsing identity)
client.get("http://news.onion")?.isolation(browsing.clone()).send().await?;
```

### ⚡ Resilience Features

```rust
use hypertor::{
    CircuitBreaker, BreakerConfig,
    AdaptiveRetry, AdaptiveRetryConfig,
    TokenBucket,
};

// Circuit breaker - fail fast when service is down
let breaker = CircuitBreaker::new(BreakerConfig {
    failure_threshold: 5,
    reset_timeout: Duration::from_secs(30),
    ..Default::default()
});

// Adaptive retry - learns optimal behavior
let retry = AdaptiveRetry::new(AdaptiveRetryConfig {
    max_attempts: 3,
    min_delay: Duration::from_millis(100),
    max_delay: Duration::from_secs(10),
    ..Default::default()
});

// Rate limiting
let limiter = TokenBucket::new(100, 100.0);  // 100 req/sec
```

### 📊 Observability

```rust
use hypertor::{TorMetrics, export_metrics};

let metrics = TorMetrics::new();

// Record operations
metrics.record_request("GET", 200, 1.5, 100, 5000);
metrics.record_circuit_build(true, 2.0);

// Export Prometheus format
let prometheus_text = metrics.export();
// # HELP hypertor_http_requests_total Total HTTP requests
// # TYPE hypertor_http_requests_total counter
// hypertor_http_requests_total{method="GET",status="200"} 1
```

### 🌉 Bridge Support (Censorship Circumvention)

```rust
use hypertor::{TorClientBuilder, VanguardMode};

// Configure bridges and transports via builder
let client = TorClientBuilder::new()
    .bridge("obfs4 192.0.2.1:443 FINGERPRINT cert=CERT iat-mode=0")
    .transport("obfs4", "/usr/bin/obfs4proxy")
    .vanguards(VanguardMode::Full)
    .build()
    .await?;
```

### � SOCKS5 Proxy

Run a local SOCKS5 proxy to route ANY application through Tor:

```rust
use hypertor::{Socks5Proxy, ProxyConfig};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

// Start SOCKS5 proxy on localhost:9050
let proxy = Socks5Proxy::with_defaults();
proxy.run().await?;  // Runs on 127.0.0.1:9050
```

Then use with any SOCKS5-compatible tool:

```bash
# curl
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip

# Python requests
proxies = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
requests.get('https://example.com', proxies=proxies)

# wget, git, ssh, browsers...
```

### �🔌 WebSocket over Tor

```rust
use hypertor::websocket::TorWebSocket;

// Connect to WebSocket over Tor
let mut ws = TorWebSocket::connect("ws://chat.onion/ws").await?;

// Send and receive messages
ws.send_text("Hello, Tor!").await?;
let msg = ws.recv().await?;
```

### 📡 HTTP/2 Support

```rust
use hypertor::http2::{Http2Connection, Http2Config};

// HTTP/2 multiplexing over Tor
let mut conn = Http2Connection::client(Http2Config::default());
let stream_id = conn.create_stream()?;
conn.send_headers(stream_id, headers, false)?;
conn.send_data(stream_id, body, true)?;
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        YOUR APPLICATION                          │
├─────────────────────────────────────────────────────────────────┤
│  TorClient          │  OnionService       │  OnionApp (serve)   │
│  (HTTP over Tor)    │  (host .onion)      │  (axum-like API)    │
├─────────────────────────────────────────────────────────────────┤
│                         hypertor core                            │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │
│  │ Circuits │ │ Security │ │Resilience│ │ Observability    │   │
│  │ Pooling  │ │ Vanguards│ │ Retry    │ │ Metrics/Tracing  │   │
│  │ Isolation│ │ PoW/Auth │ │ Breaker  │ │ Health Checks    │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│                     arti-client 0.38 (Tor)                       │
└─────────────────────────────────────────────────────────────────┘
```

### Module Overview

| Category | Modules |
|----------|---------|
| **Core** | `client`, `serve`, `onion_service`, `config`, `error`, `body` |
| **Security** | `security` (presets, vanguards, PoW, rate limiting) |
| **Networking** | `pool`, `isolation`, `circuit`, `proxy` (SOCKS5), `dns`, `doh`, `tls` |
| **Resilience** | `retry`, `breaker`, `rotation`, `adaptive`, `backpressure` |
| **Performance** | `cache`, `dedup`, `ratelimit`, `queue`, `prewarm`, `batch` |
| **Protocols** | `http2`, `websocket` |
| **Observability** | `observability`, `prometheus`, `tracing`, `health`, `metrics` |

---

## Examples

### Basic Client Usage

```bash
cargo run --example basic_usage
```

### Security Features Demo

```bash
cargo run --example security_features
```

### SOCKS5 Proxy

```bash
cargo run --example socks_proxy
# Then: curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
```

---

## Metrics

| Metric | Value |
|--------|-------|
| Source Files | 51 |
| Lines of Code | ~26,900 |
| Unit Tests | 207 |
| Integration Tests | 26 |
| Security Tests | 58 |
| Doc Tests | 1 |
| **Total Tests** | **292** |
| arti Version | 0.38 |
| Rust Edition | 2024 |
| MSRV | 1.85 |

Run all tests:
```bash
cargo test                     # All 292 tests
cargo test --test security     # Security tests (58)
```

---

## Security Considerations

### What hypertor Protects Against

| Threat | Protection | Implementation |
|--------|------------|----------------|
| Guard discovery | Vanguards (Lite/Full) | `VanguardConfigBuilder::mode()` |
| DoS attacks | Proof-of-Work (Equi-X) | `OnionServiceConfigBuilder::enable_pow()` |
| Intro flooding | Rate limiting | `rate_limit_at_intro()` |
| Stream flooding | Stream limits | `max_concurrent_streams_per_circuit()` |
| IP exposure | Bridges + transports | `TorClientConfigBuilder::bridges()` |
| Unauthorized access | Client authorization | `RestrictedDiscoveryConfigBuilder` |
| Secret leaks | Zeroize on drop | `SecretKey` with `ZeroizeOnDrop` |

### What hypertor Does NOT Protect Against

- ❌ Application-level data leaks (your code)
- ❌ Timing attacks from your application logic
- ❌ Malware on your system
- ❌ Compromised exit nodes (for clearnet access)

---

## Development

```bash
# Run tests
cargo test --lib

# Run clippy
cargo clippy --lib -- -D warnings

# Build Python wheel
maturin develop --features python

# Run example
cargo run --example basic_usage

# Serve docs locally
just docs
```

---

## Documentation

- [Quick Start Guide](https://hupe1980.github.io/hypertor/docs/quickstart/)
- [TorClient API](https://hupe1980.github.io/hypertor/docs/client/)
- [OnionApp API](https://hupe1980.github.io/hypertor/docs/server/)
- [Security Features](https://hupe1980.github.io/hypertor/docs/security/)
- [Python Bindings](https://hupe1980.github.io/hypertor/docs/python/)

---

## ⚠️ Disclaimer

**This software is provided for educational and research purposes only.**

- **No Anonymity Guarantee**: While hypertor leverages the Tor network via arti, no software can guarantee complete anonymity. Your operational security practices, threat model, and usage patterns significantly impact your privacy.
- **No Warranty**: This software is provided "as is" without warranty of any kind. The authors are not responsible for any damages or legal consequences arising from its use.
- **Legal Compliance**: Users are solely responsible for ensuring their use of this software complies with all applicable laws and regulations in their jurisdiction.
- **Not Endorsed by Tor Project**: This is an independent project and is not affiliated with, endorsed by, or sponsored by The Tor Project.
- **Security Considerations**: Always review the [Security Guide](https://hupe1980.github.io/hypertor/docs/security/) before deploying in production.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please open issues and pull requests on GitHub.
