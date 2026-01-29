# HyperTor Rust Examples

Examples demonstrating how to use HyperTor for building anonymous applications
over the Tor network in Rust.

## Running Examples

```bash
# Client examples (no server feature needed)
cargo run --example basic_usage
cargo run --example secure_api_client
cargo run --example multiple_identities
cargo run --example realtime_patterns
cargo run --example security_features
cargo run --example socks_proxy

# Server example (requires server feature)
cargo run --example onion_service --features server
```

> **Note**: First run may take 30-60 seconds to bootstrap the Tor network.
> Subsequent runs use the cached directory and are much faster.

## Examples Overview

### 1. Basic Usage (`basic_usage.rs`)

Introduction to TorClient with core features:

```bash
cargo run --example basic_usage
```

**Features demonstrated:**
- Creating a `TorClient` with defaults
- Making requests through Tor network
- Configuration with `ConfigBuilder`
- Retry patterns for reliability
- Stream isolation with `IsolationToken`
- Middleware stack setup

### 2. Secure API Client (`secure_api_client.rs`)

Production-grade Tor client with full resilience stack:

```bash
cargo run --example secure_api_client
```

**Features demonstrated:**
- `CircuitBreaker` for fail-fast behavior
- `RateLimiter` for request throttling
- `RetryConfig` with exponential backoff
- In-memory caching with TTL
- Comprehensive error handling
- Request statistics tracking

### 3. Multiple Identities (`multiple_identities.rs`)

Circuit isolation for maintaining separate anonymous identities:

```bash
cargo run --example multiple_identities
```

**Features demonstrated:**
- `IsolationToken` for circuit separation
- `isolated()` sessions
- IP verification for isolation testing
- Identity persistence patterns

### 4. Onion Service (`onion_service.rs`)

Host an anonymous .onion web service:

```bash
cargo run --example onion_service --features server
```

**Features demonstrated:**
- `OnionApp` with route registration
- GET and POST handlers
- JSON request/response handling
- Shared state with `Arc<Mutex<T>>`
- Health check endpoints

### 5. Real-time Patterns (`realtime_patterns.rs`)

WebSocket-like communication over Tor:

```bash
cargo run --example realtime_patterns
```

**Features demonstrated:**
- Long polling pattern
- Server-Sent Events (SSE) concepts
- Bidirectional communication patterns
- Live polling with `httpbin.org`

### 6. Security Features (`security_features.rs`)

All security hardening features:

```bash
cargo run --example security_features
```

**Features demonstrated:**
- Censored network client (bridges, transports)
- Maximum security onion service (PoW, vanguards)
- Client authorization
- Security presets (`ServiceSecurityConfig`, `ClientSecurityConfig`)

### 7. SOCKS5 Proxy (`socks_proxy.rs`)

Run a local SOCKS5 proxy for any application:

```bash
cargo run --example socks_proxy
```

**Features demonstrated:**
- `Socks5Proxy` for transparent Tor routing
- `ProxyConfig` with custom bind address
- Circuit isolation per proxy
- Integration with curl, wget, browsers, Python

## API Quick Reference

### TorClient

```rust
use hypertor::{TorClient, ConfigBuilder, IsolationLevel};

// Simple client
let client = TorClient::new().await?;

// Configured client
let config = ConfigBuilder::new()
    .timeout(Duration::from_secs(60))
    .max_connections(20)
    .isolation(IsolationLevel::PerRequest)
    .build()?;
let client = TorClient::with_config(config).await?;

// Make requests
let resp = client.get("https://check.torproject.org/api/ip")?.send().await?;
let resp = client.post("https://api.example.com")?.json(&data).send().await?;
```

### OnionApp (Server)

```rust
use hypertor::{OnionApp, ServeRequest, ServeResponse};

let app = OnionApp::new()
    .get("/", |_req: ServeRequest| async {
        ServeResponse::json(&json!({"status": "ok"})).unwrap()
    })
    .post("/api/echo", |req: ServeRequest| async move {
        let body = req.json::<serde_json::Value>()?;
        ServeResponse::json(&body)
    });

let address = app.run().await?;  // Returns "abc...xyz.onion"
```

### Resilience Patterns

```rust
use hypertor::{CircuitBreaker, BreakerConfig, RateLimiter, RateLimitConfig, RetryConfig};

// Circuit breaker
let breaker = CircuitBreaker::new(BreakerConfig {
    failure_threshold: 5,
    reset_timeout: Duration::from_secs(30),
    ..Default::default()
});

// Rate limiter
let limiter = RateLimiter::new(RateLimitConfig {
    default_rate: 10.0,
    default_burst: 20,
    ..Default::default()
});

// Retry with backoff
let retry = RetryConfig {
    max_retries: 3,
    initial_delay: Duration::from_secs(1),
    backoff_multiplier: 2.0,
    ..Default::default()
};
```

## Notes

1. **First run takes time** - Tor needs to bootstrap (~30-60 seconds)
2. **Requests are slower** - Tor adds latency (expect 5-30 seconds per request)
3. **Some examples need network** - `basic_usage`, `secure_api_client`, etc. connect to real Tor
4. **Server example runs indefinitely** - Press Ctrl+C to stop
