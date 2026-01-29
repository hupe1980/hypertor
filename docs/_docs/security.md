---
title: "Security Features"
permalink: /docs/security/
excerpt: "Built-in protections for anonymity and DoS resistance"
---

HyperTor includes several security features to protect both clients and services. These are enabled by default where appropriate.

## Overview

| Feature | Purpose | Default |
|---------|---------|---------|
| **Vanguards-lite** | Protects guard relays from discovery | Enabled |
| **Proof of Work** | Prevents DDoS attacks on services | Off |
| **Traffic Padding** | Prevents traffic analysis | Configurable |
| **Circuit Isolation** | Separates different activities | Session-based |
| **Rate Limiting** | Controls request rates | Per-connection |

## Vanguards-lite

**What it protects against:** Guard enumeration attacks that could deanonymize hidden services.

Tor uses "guard" relays as the first hop for all circuits. If an attacker can identify your guards, they can narrow down your location. Vanguards adds additional layers of protection.

### How It Works

1. **Layer 2 Guards** — A small set of relays used after the guard
2. **Rotation Policy** — Guards rotate slowly, making enumeration expensive
3. **Persistent Selection** — Guards persist across restarts

### Configuration

```rust
// Enabled by default for OnionApp
let app = OnionApp::builder()
    .vanguards_enabled(true)  // Default
    .vanguards_full(false)    // Use lite mode
    .build();
```

In Python:

```python
app = OnionApp(
    vanguards_enabled=True,   # Default
    vanguards_full=False      # Use lite mode
)
```

### Vanguards Modes

| Mode | Protection | Overhead |
|------|------------|----------|
| **Lite** (default) | Good protection, low overhead | ~10% more circuit build time |
| **Full** | Maximum protection | ~30% more circuit build time |
| **Off** | No additional protection | Baseline performance |

## Proof of Work (PoW)

**What it protects against:** DDoS attacks and resource exhaustion.

When enabled, clients must solve a computational puzzle before connecting to your service. This makes attacks expensive while legitimate users pay only a small one-time cost.

### How It Works

1. Client requests connection
2. Server sends PoW challenge
3. Client solves puzzle (requires CPU work)
4. Server verifies solution
5. Connection proceeds

The difficulty adjusts automatically based on server load.

### Configuration

```rust
let app = OnionApp::builder()
    .pow_enabled(true)
    .pow_target_bits(20)      // Base difficulty
    .pow_adaptive(true)       // Auto-adjust to load
    .pow_queue_size(100)      // Max pending challenges
    .build();
```

In Python:

```python
app = OnionApp(
    pow_enabled=True,
    pow_target_bits=20,       # Base difficulty
    pow_adaptive=True,        # Auto-adjust to load
    pow_queue_size=100        # Max pending challenges
)
```

### Difficulty Levels

| Target Bits | Time to Solve | Use Case |
|-------------|---------------|----------|
| 16 | ~50ms | Light protection |
| 20 | ~500ms | Default, balanced |
| 24 | ~5s | High-value services |
| 28 | ~1min | Extreme protection |

### Client Support

The `TorClient` automatically handles PoW challenges:

```rust
// Client automatically solves PoW if required
let resp = client.get("http://protected-service.onion")?
    .send().await?;
```

```python
# Client automatically solves PoW if required
resp = await client.get("http://protected-service.onion")
```

## Traffic Padding

**What it protects against:** Traffic analysis attacks that correlate traffic patterns.

Traffic padding adds dummy data to mask the real traffic patterns, making it harder for observers to correlate your activity.

### Configuration

```rust
let client = TorClient::builder()
    .padding_enabled(true)
    .padding_mode(PaddingMode::Normal)  // or Reduced, Maximum
    .build().await?;
```

In Python:

```python
client = TorClient(
    padding_enabled=True,
    padding_mode="normal"  # or "reduced", "maximum"
)
```

### Padding Modes

| Mode | Description | Overhead |
|------|-------------|----------|
| `Reduced` | Minimal padding | ~5% bandwidth |
| `Normal` | Balanced protection | ~15% bandwidth |
| `Maximum` | Full protection | ~30% bandwidth |

## Circuit Isolation

**What it protects against:** Activity correlation across different operations.

Circuit isolation ensures different activities use different Tor circuits, preventing observers from linking them together.

### Isolation Levels

```rust
use hypertor::{TorClient, IsolationLevel};

let client = TorClient::builder()
    .isolation(IsolationLevel::PerSession)  // Default
    .build().await?;
```

| Level | Description | Use Case |
|-------|-------------|----------|
| `None` | All requests share circuits | Maximum performance |
| `PerSession` | Circuits per client instance | Default, balanced |
| `PerRequest` | Fresh circuit per request | Maximum privacy |
| `PerHost` | Circuits per destination | Multi-service |

### Custom Isolation

Group related requests together while isolating from others:

```rust
use hypertor::IsolationToken;

// Create isolation groups
let session_a = IsolationToken::new();
let session_b = IsolationToken::new();

// These share a circuit
client.get("http://a.onion")?.isolation(session_a.clone()).send().await?;
client.get("http://a.onion/page")?.isolation(session_a.clone()).send().await?;

// This uses a different circuit
client.get("http://a.onion")?.isolation(session_b.clone()).send().await?;
```

## Rate Limiting

Built-in rate limiting for services:

```rust
use hypertor::middleware::RateLimit;
use std::time::Duration;

let app = OnionApp::new();

// Global rate limit: 100 requests per minute per connection
app.middleware(RateLimit::new(100, Duration::from_secs(60)));

// Per-route rate limit
app.get("/api/expensive", expensive_handler)
    .rate_limit(10, Duration::from_secs(60));
```

In Python:

```python
from hypertor import OnionApp, RateLimit
from datetime import timedelta

app = OnionApp()

# Global rate limit
app.use(RateLimit(requests=100, window=timedelta(minutes=1)))

# Per-route rate limit
@app.get("/api/expensive", rate_limit=RateLimit(10, timedelta(minutes=1)))
async def expensive(request):
    ...
```

## Security Best Practices

### For Hidden Services

1. **Enable Proof of Work** for public services
2. **Use Vanguards** (enabled by default)
3. **Set rate limits** appropriate for your use case
4. **Persist keys** to maintain identity
5. **Monitor connections** for anomalies

```rust
let app = OnionApp::builder()
    .pow_enabled(true)
    .pow_target_bits(20)
    .vanguards_enabled(true)
    .connection_limit(100)
    .key_path("/secure/path/to/keys")
    .build();
```

### For Clients

1. **Use circuit isolation** for sensitive operations
2. **Enable padding** if traffic analysis is a concern
3. **Don't reuse client instances** for unrelated activities
4. **Handle timeouts gracefully** — Tor can be slow

```rust
let client = TorClient::builder()
    .isolation(IsolationLevel::PerRequest)
    .padding_enabled(true)
    .timeout(Duration::from_secs(60))
    .build().await?;
```

## Security Considerations

### What HyperTor Protects

- ✅ IP address of client and server
- ✅ Network observer seeing connection endpoints
- ✅ Traffic content (encrypted)
- ✅ Guard enumeration (with Vanguards)
- ✅ DDoS attacks (with PoW)
- ✅ DNS leaks (all DNS via Tor exit automatically)
- ✅ Circuit path vulnerabilities (analysis via `circuits` module)

### What HyperTor Does NOT Protect

- ❌ Application-level data leaks (if you put your name in POST body)
- ❌ Malware on your system
- ❌ Human error in operational security
- ❌ Compromised exit nodes (for clearnet access - use TLS)
- ❌ Side-channel attacks on your hardware

### Design Philosophy

HyperTor is an HTTP client library, not a browser. Browser-level concerns like:

- Canvas/WebGL fingerprinting
- WebRTC leaks
- Font enumeration
- Plugin detection

...do not apply to an HTTP client. DNS resolution is handled automatically via Tor exit nodes by the underlying arti library — there is no way for DNS to leak if you use `TorClient`.

### Additional Recommendations

1. **Keep dependencies updated** — Security vulnerabilities get patched
2. **Use memory-safe code** — HyperTor is written in Rust with `#![forbid(unsafe_code)]`
3. **Minimize logging** — Logs can deanonymize users
4. **Sanitize user input** — Same as any web application
5. **Use HTTPS in addition to Tor** — Defense in depth
6. **Don't add identifying headers** — Avoid `X-Forwarded-For`, custom `User-Agent`

## Next Steps

- [TorClient Documentation](/docs/client/) — HTTP client for Tor
- [OnionApp Documentation](/docs/server/) — Host hidden services
- [Python Bindings](/docs/python/) — Full Python API reference
