---
title: "TorClient"
permalink: /docs/client/
excerpt: "HTTP client for the Tor network"
---

HTTP client for the Tor network. As simple as `reqwest`, but routes everything through Tor.

## Overview

`TorClient` is a high-level HTTP client that connects to the Tor network and routes all requests through onion circuits. It provides:

- **Simple API** — Familiar request/response pattern
- **Connection pooling** — Reuse circuits for performance
- **Circuit isolation** — Separate identities per request or session
- **Resilience** — Retry, circuit breaker, backpressure
- **Observability** — Prometheus metrics, tracing

## Basic Usage

### Rust

```rust
use hypertor::{TorClient, Result};

#[tokio::main]
async fn main() -> Result<()> {
    // Create client (connects to Tor network)
    let client = TorClient::new().await?;
    
    // GET request
    let resp = client.get("http://example.onion")?
        .send().await?;
    println!("Status: {}", resp.status());
    
    // POST with JSON
    let resp = client.post("http://api.onion/data")?
        .json(&serde_json::json!({"key": "value"}))
        .send().await?;
    
    // Read response
    let body: serde_json::Value = resp.json()?;
    println!("{:?}", body);
    
    Ok(())
}
```

### Python

```python
import asyncio
from hypertor import AsyncClient, TimeoutError, HypertorError

async def main():
    async with AsyncClient(timeout=60) as client:
        # GET request
        resp = await client.get("https://check.torproject.org/api/ip")
        print(f"Status: {resp.status_code}")
        print(f"Tor IP: {resp.json().get('IP')}")
        
        # POST with JSON
        resp = await client.post(
            "https://httpbin.org/post",
            json='{"key": "value"}'
        )
        
        # Read response
        body = resp.json()
        print(body)

asyncio.run(main())
```

## Configuration

Use the builder pattern for advanced configuration:

```rust
use hypertor::{TorClient, IsolationLevel};
use std::time::Duration;

let client = TorClient::builder()
    // Timeouts
    .timeout(Duration::from_secs(30))
    
    // Circuit isolation (separate identity per request)
    .isolation(IsolationLevel::PerRequest)
    
    // Connection pooling
    .max_connections(20)
    
    // Follow redirects
    .follow_redirects(true)
    .max_redirects(5)
    
    // Build
    .build()
    .await?;
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `timeout` | 30s | Request timeout |
| `isolation` | `None` | Circuit isolation level |
| `max_connections` | 10 | Max pooled connections |
| `follow_redirects` | false | Follow HTTP redirects |
| `max_redirects` | 5 | Max redirects to follow |
| `verify_tls` | true | Verify TLS certificates |

## Circuit Isolation

Circuit isolation determines how Tor circuits are shared between requests. This is crucial for both **performance** (circuit reuse) and **privacy** (traffic separation).

| Level | Behavior | Use Case |
|-------|----------|----------|
| `None` | All requests share circuits | Maximum performance, same identity |
| `PerSession` | Circuits per session/client | Default, good balance |
| `PerRequest` | Fresh circuit per request | Maximum privacy, slower |
| `PerHost` | Circuits per destination | Multi-service access |

```rust
use hypertor::{TorClient, IsolationLevel, IsolationToken};

// Per-request isolation (different IP each time)
let client = TorClient::builder()
    .isolation(IsolationLevel::PerRequest)
    .build().await?;

// Custom isolation token (group related requests)
let token = IsolationToken::new();
let resp = client.get("http://example.onion")?
    .isolation(token.clone())
    .send().await?;
```

## HTTP Methods

```rust
// GET
let resp = client.get("http://example.onion")?.send().await?;

// POST with JSON
let resp = client.post("http://example.onion/api")?
    .json(&data)
    .send().await?;

// POST with form data
let resp = client.post("http://example.onion/form")?
    .form(&[("key", "value")])?
    .send().await?;

// PUT
let resp = client.put("http://example.onion/resource")?
    .body("data")
    .send().await?;

// DELETE
let resp = client.delete("http://example.onion/resource")?
    .send().await?;

// HEAD
let resp = client.head("http://example.onion")?.send().await?;

// PATCH
let resp = client.patch("http://example.onion/resource")?
    .json(&partial_update)
    .send().await?;
```

## Query Parameters

```rust
// Add query parameters
let resp = client.get("http://example.onion/search")?
    .query(&[("q", "rust"), ("page", "1")])  // ?q=rust&page=1
    .send().await?;

// Multiple values for same key
let resp = client.get("http://example.onion/filter")?
    .query(&[("tag", "security"), ("tag", "tor"), ("tag", "rust")])
    .send().await?;

// With structs (requires serde)
#[derive(Serialize)]
struct SearchParams {
    q: String,
    page: u32,
    limit: u32,
}

let params = SearchParams { q: "tor".into(), page: 1, limit: 50 };
let resp = client.get("http://example.onion/search")?
    .query(&params)
    .send().await?;
```

## Request Headers

```rust
// Set individual headers
let resp = client.get("http://example.onion")?
    .header("X-Custom-Header", "value")
    .header("Accept", "application/json")
    .send().await?;

// Set multiple headers
use hypertor::HeaderMap;

let mut headers = HeaderMap::new();
headers.insert("X-API-Key", "secret-key".parse()?);
headers.insert("X-Request-ID", uuid::Uuid::new_v4().to_string().parse()?);

let resp = client.get("http://example.onion")?
    .headers(headers)
    .send().await?;
```

## Working with Responses

```rust
let resp = client.get("http://example.onion")?.send().await?;

// Status
let status = resp.status();  // u16
let is_ok = resp.status().is_success();  // 2xx

// Headers
let content_type = resp.headers().get("content-type");

// Body as text
let text = resp.text()?;

// Body as JSON
let data: MyStruct = resp.json()?;

// Body as bytes
let bytes = resp.bytes()?;

// Streaming large responses
let mut stream = resp.bytes_stream();
while let Some(chunk) = stream.next().await {
    let chunk = chunk?;
    process_chunk(&chunk)?;
}
```

## Authentication

```rust
// Basic auth
let resp = client.get("http://example.onion")?
    .basic_auth("username", "password")
    .send().await?;

// Bearer token
let resp = client.get("http://example.onion")?
    .bearer_auth("my-token")
    .send().await?;

// Custom authentication header
let resp = client.get("http://example.onion")?
    .header("X-API-Key", "your-api-key")
    .send().await?;
```

## Resilience & Retries

HyperTor includes built-in resilience features:

```rust
use hypertor::{TorClient, RetryConfig, CircuitBreakerConfig};
use std::time::Duration;

let client = TorClient::builder()
    // Retry failed requests
    .retry(RetryConfig {
        max_retries: 3,
        initial_delay: Duration::from_millis(100),
        max_delay: Duration::from_secs(5),
        exponential_backoff: true,
        retry_on: vec![500, 502, 503, 504],
    })
    // Circuit breaker (prevent cascade failures)
    .circuit_breaker(CircuitBreakerConfig {
        failure_threshold: 5,
        success_threshold: 2,
        timeout: Duration::from_secs(30),
    })
    .build().await?;
```

## Backpressure & Rate Limiting

Protect onion services from being overwhelmed:

```rust
use hypertor::{TorClient, RateLimitConfig};
use std::time::Duration;

let client = TorClient::builder()
    // Client-side rate limiting
    .rate_limit(RateLimitConfig {
        requests_per_second: 10,
        burst_size: 20,
    })
    // Concurrent request limit
    .max_concurrent_requests(5)
    // Backpressure (wait when overwhelmed)
    .backpressure_strategy(BackpressureStrategy::Wait)
    .build().await?;
```

## Circuit Management

Control Tor circuits directly for advanced use cases:

```rust
use hypertor::TorClient;

let client = TorClient::new().await?;

// Get current circuit information
let circuit = client.circuit_info().await?;
println!("Circuit ID: {}", circuit.id);
println!("Path: {:?}", circuit.path);
println!("Guard: {}", circuit.guard);
println!("Exit: {}", circuit.exit);

// Force new circuit (new IP address)
client.new_circuit().await?;

// Get multiple circuits for load balancing
let circuits = client.circuits(5).await?;
```

## Observability

### Prometheus Metrics

```rust
use hypertor::{TorClient, MetricsConfig};

let client = TorClient::builder()
    .metrics(MetricsConfig {
        enabled: true,
        prefix: "hypertor",
        histogram_buckets: vec![0.01, 0.05, 0.1, 0.5, 1.0, 5.0],
    })
    .build().await?;

// Metrics are automatically exported
// hypertor_requests_total{method="GET", status="200"}
// hypertor_request_duration_seconds{method="GET", quantile="0.99"}
// hypertor_circuit_build_time_seconds
// hypertor_active_connections
```

### OpenTelemetry Tracing

```rust
use hypertor::{TorClient, TracingConfig};

let client = TorClient::builder()
    .tracing(TracingConfig {
        enabled: true,
        trace_circuits: true,
        trace_requests: true,
    })
    .build().await?;

// Traces include:
// - Circuit establishment
// - Request/response lifecycle
// - Retry attempts
// - Error details
```

## Error Handling

```rust
use hypertor::{TorClient, Error};

match client.get("http://example.onion")?.send().await {
    Ok(resp) => println!("Success: {}", resp.status()),
    Err(Error::Timeout { operation, duration }) => {
        println!("{} timed out after {:?}", operation, duration);
    }
    Err(Error::Connection { host, port, .. }) => {
        println!("Failed to connect to {}:{}", host, port);
    }
    Err(Error::CircuitFailed { reason }) => {
        println!("Circuit failed: {}", reason);
    }
    Err(Error::TorNetwork { code, message }) => {
        println!("Tor network error {}: {}", code, message);
    }
    Err(e) => println!("Error: {}", e),
}
```

## Typed API Helpers

For cleaner API interactions with typed serialization/deserialization:

```rust
use hypertor::TorClient;
use serde::{Serialize, Deserialize};

#[derive(Serialize)]
struct CreateUser {
    username: String,
    email: String,
}

#[derive(Deserialize)]
struct User {
    id: u64,
    username: String,
    email: String,
}

// Typed POST returning deserialized response
let user: User = client.post("http://api.onion/users")?
    .json(&CreateUser {
        username: "alice".into(),
        email: "alice@example.com".into(),
    })
    .send().await?
    .json()?;

// Typed GET with automatic deserialization
let users: Vec<User> = client.get("http://api.onion/users")?
    .send().await?
    .json()?;
```

## Proxy Chain Support

Chain through additional proxies before Tor:

```rust
use hypertor::{TorClient, ProxyConfig};

let client = TorClient::builder()
    // Chain through SOCKS5 proxy before Tor
    .proxy(ProxyConfig::Socks5 {
        host: "127.0.0.1".into(),
        port: 1080,
        auth: None,
    })
    .build().await?;
```

## Next Steps

- [OnionApp Documentation](/docs/server/) — Host your own .onion service
- [Security Features](/docs/security/) — PoW, Vanguards, Leak Detection
- [Python Bindings](/docs/python/) — Full Python API reference
