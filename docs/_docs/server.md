---
title: "OnionApp"
permalink: /docs/server/
excerpt: "Host .onion services with FastAPI-like simplicity"
---

Host anonymous services on the Tor network. As simple as Flask or FastAPI, but accessible via .onion addresses.

## Overview

`OnionApp` lets you create HTTP servers accessible only through the Tor network. When you start the app, it:

1. Generates or loads cryptographic keys
2. Registers with the Tor network
3. Serves requests at a `.onion` address

## Basic Usage

### Rust

```rust
use hypertor::{OnionApp, Request, Response, Result};

#[tokio::main]
async fn main() -> Result<()> {
    // Create app
    let app = OnionApp::new();
    
    // Define routes
    app.get("/", |_req| async {
        Response::text("Hello from the dark web!")
    });
    
    app.get("/api/data", |_req| async {
        Response::json(&serde_json::json!({
            "message": "Secret data",
            "timestamp": chrono::Utc::now()
        }))
    });
    
    // Start server (prints .onion address)
    let addr = app.run().await?;
    println!("Service running at: {}", addr);
    
    // Keep running
    tokio::signal::ctrl_c().await?;
    Ok(())
}
```

### Python

```python
import asyncio
from hypertor import OnionApp

app = OnionApp()

@app.get("/")
async def index(request):
    return {"message": "Hello from the dark web!"}

@app.post("/api/echo")
async def echo(request):
    data = await request.json()
    return {"received": data}

async def main():
    async with app.run() as addr:
        print(f"Service running at: {addr}")
        # Keep running until interrupted
        await asyncio.Event().wait()

asyncio.run(main())
```

## Configuration

```rust
use hypertor::{OnionApp, SecurityLevel};
use std::time::Duration;

let app = OnionApp::builder()
    // Security
    .pow_enabled(true)
    .pow_target_bits(16)
    .vanguards_enabled(true)
    
    // Performance
    .connection_limit(100)
    .request_timeout(Duration::from_secs(30))
    
    // Identity
    .key_path("/path/to/keys")  // Persist .onion address
    
    // Build
    .build();
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `pow_enabled` | false | Require proof-of-work from clients |
| `pow_target_bits` | 20 | PoW difficulty (higher = harder) |
| `vanguards_enabled` | true | Use Vanguards-lite for guard protection |
| `connection_limit` | 50 | Max concurrent connections |
| `request_timeout` | 60s | Timeout per request |
| `key_path` | None | Path to persist keypair |

## Routing

```rust
// Basic routes
app.get("/", handler);
app.post("/api/create", handler);
app.put("/api/update", handler);
app.delete("/api/delete", handler);
app.patch("/api/patch", handler);

// Path parameters
app.get("/users/:id", |req| async move {
    let id = req.param("id")?;
    Response::json(&get_user(id).await)
});

// Multiple parameters
app.get("/posts/:post_id/comments/:comment_id", |req| async move {
    let post_id = req.param("post_id")?;
    let comment_id = req.param("comment_id")?;
    // ...
});
```

## Working with Requests

```rust
use hypertor::{Request, Response};

app.post("/api/data", |req: Request| async move {
    // Headers
    let content_type = req.header("content-type");
    let auth = req.header("authorization");
    
    // Query parameters (?key=value)
    let page = req.query("page").unwrap_or("1");
    let limit = req.query("limit").unwrap_or("10");
    
    // JSON body
    let data: MyStruct = req.json()?;
    
    // Form data
    let form = req.form()?;
    let name = form.get("name");
    
    // Raw body
    let bytes = req.body();
    
    Response::ok()
});
```

## Response Building

```rust
use hypertor::{Response, StatusCode};

// Text
Response::text("Hello, World!")

// JSON
Response::json(&data)

// With status code
Response::with_status(StatusCode::CREATED)
    .json(&created_resource)

// With headers
Response::json(&data)
    .header("X-Custom", "value")
    .header("Cache-Control", "no-store")

// Redirect
Response::redirect("/new-location")

// Errors
Response::not_found()
Response::bad_request("Invalid input")
Response::internal_error("Something went wrong")
```

## Middleware

```rust
use hypertor::{OnionApp, Request, Response, Middleware};

// Custom middleware
struct LoggingMiddleware;

impl Middleware for LoggingMiddleware {
    async fn call(&self, req: Request, next: Next) -> Response {
        let start = std::time::Instant::now();
        let path = req.path().to_string();
        
        let resp = next.call(req).await;
        
        println!("{} {} - {:?}", 
            resp.status(), path, start.elapsed());
        resp
    }
}

let app = OnionApp::new();
app.middleware(LoggingMiddleware);
```

### Built-in Middleware

```rust
use hypertor::middleware::*;

// CORS
app.middleware(Cors::permissive());

// Rate limiting
app.middleware(RateLimit::new(100, Duration::from_secs(60)));

// Compression
app.middleware(Compression::default());

// Timeout
app.middleware(Timeout::new(Duration::from_secs(30)));
```

## Persistent Identity

By default, each restart generates a new .onion address. To keep the same address:

```rust
// Save/load keys to persist identity
let app = OnionApp::builder()
    .key_path("/var/lib/myapp/tor_keys")
    .build();
```

The key directory will contain:
- `hs_ed25519_secret_key` — Private key (KEEP SECRET!)
- `hs_ed25519_public_key` — Public key
- `hostname` — Your .onion address

## Client Authorization

Restrict access to specific clients:

```rust
let app = OnionApp::builder()
    // Enable client auth
    .client_auth_enabled(true)
    // Add authorized clients
    .authorized_client("descriptor:x25519:CLIENT_KEY_HERE")
    .build();
```

Only clients with the corresponding private key can connect.

### Managing Authorized Clients

```rust
use hypertor::{OnionApp, ClientAuth};

// Generate a new client key pair
let (client_public, client_private) = ClientAuth::generate_keypair()?;
println!("Give to client: {}", client_private.to_string());

// Add to server
let app = OnionApp::builder()
    .client_auth_enabled(true)
    .authorized_client(&client_public)
    .build();

// Dynamic client management
let app = OnionApp::new();
app.add_authorized_client(&client_public).await?;
app.remove_authorized_client(&client_public).await?;
app.list_authorized_clients().await?;
```

## Proof of Work (Anti-DDoS)

Require clients to solve a computational puzzle before connecting:

```rust
let app = OnionApp::builder()
    .pow_enabled(true)
    .pow_target_bits(20)  // Difficulty level
    .build();
```

This makes DDoS attacks expensive while legitimate clients only pay a small one-time cost.

### Dynamic PoW Adjustment

```rust
use hypertor::{OnionApp, PowConfig};

let app = OnionApp::builder()
    .pow(PowConfig {
        enabled: true,
        base_difficulty: 16,
        max_difficulty: 24,
        // Auto-adjust based on load
        auto_adjust: true,
        target_latency: Duration::from_millis(500),
    })
    .build();
```

## Traffic Padding

Add dummy traffic to prevent traffic analysis:

```rust
use hypertor::{OnionApp, PaddingConfig};

let app = OnionApp::builder()
    .traffic_padding(PaddingConfig {
        enabled: true,
        // Pad responses to multiples of this size
        block_size: 512,
        // Add random delay to responses
        timing_jitter: Duration::from_millis(50),
        // Send periodic dummy packets
        dummy_traffic: true,
        dummy_interval: Duration::from_secs(30),
    })
    .build();
```

## WebSocket Support

```rust
use hypertor::{OnionApp, WebSocket, Message};

app.websocket("/ws", |ws: WebSocket| async move {
    while let Some(msg) = ws.recv().await? {
        match msg {
            Message::Text(text) => {
                ws.send(Message::Text(format!("Echo: {}", text))).await?;
            }
            Message::Binary(data) => {
                ws.send(Message::Binary(data)).await?;
            }
            Message::Ping(data) => {
                ws.send(Message::Pong(data)).await?;
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
    Ok(())
});
```

## Static File Serving

```rust
use hypertor::{OnionApp, StaticFiles};

// Serve directory
app.static_files("/assets", StaticFiles::new("/path/to/assets")
    .index_file("index.html")
    .cache_control("max-age=3600")
);

// Single file
app.get("/favicon.ico", StaticFiles::file("/path/to/favicon.ico"));
```

## Request Validation

```rust
use hypertor::{OnionApp, Request, Response};
use validator::Validate;

#[derive(Deserialize, Validate)]
struct CreateUser {
    #[validate(length(min = 3, max = 32))]
    username: String,
    #[validate(email)]
    email: String,
    #[validate(length(min = 8))]
    password: String,
}

app.post("/users", |req: Request| async move {
    let user: CreateUser = req.json()?;
    
    if let Err(errors) = user.validate() {
        return Response::bad_request(errors.to_string());
    }
    
    // Proceed with validated data
    Response::json(&create_user(user).await?)
});
```

## Error Handling

```rust
use hypertor::{OnionApp, Error};

// Global error handler
app.on_error(|err: Error| async move {
    eprintln!("Error: {}", err);
    Response::internal_error("Something went wrong")
});

// Per-route error handling
app.get("/risky", |req| async move {
    match do_risky_thing().await {
        Ok(data) => Response::json(&data),
        Err(e) => Response::bad_request(e.to_string()),
    }
});

// Custom error types
#[derive(Debug)]
enum ApiError {
    NotFound(String),
    Validation(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::NotFound(msg) => Response::not_found().json(&json!({"error": msg})),
            ApiError::Validation(msg) => Response::bad_request().json(&json!({"error": msg})),
            ApiError::Internal(msg) => Response::internal_error().json(&json!({"error": msg})),
        }
    }
}
```

## State Management

```rust
use std::sync::Arc;
use tokio::sync::RwLock;

struct AppState {
    counter: RwLock<u64>,
    db: Database,
}

let state = Arc::new(AppState {
    counter: RwLock::new(0),
    db: Database::connect().await?,
});

let app = OnionApp::with_state(state.clone());

app.get("/count", move |req| {
    let state = state.clone();
    async move {
        let mut counter = state.counter.write().await;
        *counter += 1;
        Response::json(&serde_json::json!({
            "count": *counter
        }))
    }
});
```

## Graceful Shutdown

```rust
use hypertor::OnionApp;
use tokio::signal;

let app = OnionApp::new();
// ... define routes ...

let server = app.run().await?;
println!("Service running at: {}", server.onion_address());

// Wait for shutdown signal
signal::ctrl_c().await?;

// Graceful shutdown with timeout
server.shutdown(Duration::from_secs(30)).await?;
println!("Server shut down gracefully");
```

## Health Checks

```rust
use hypertor::{OnionApp, HealthCheck};

let app = OnionApp::builder()
    .health_check(HealthCheck {
        enabled: true,
        path: "/health",
        include_details: false,  // Don't leak internal info
    })
    .build();

// Custom health check
app.get("/health", |_| async {
    let db_ok = check_database().await.is_ok();
    let cache_ok = check_cache().await.is_ok();
    
    if db_ok && cache_ok {
        Response::ok().json(&json!({
            "status": "healthy",
            "checks": {
                "database": "ok",
                "cache": "ok"
            }
        }))
    } else {
        Response::with_status(503).json(&json!({
            "status": "unhealthy"
        }))
    }
});
```

## Observability

### Prometheus Metrics

```rust
use hypertor::{OnionApp, MetricsConfig};

let app = OnionApp::builder()
    .metrics(MetricsConfig {
        enabled: true,
        path: "/metrics",
        prefix: "myservice",
    })
    .build();

// Metrics exposed:
// myservice_requests_total{method="GET", path="/api", status="200"}
// myservice_request_duration_seconds{quantile="0.99"}
// myservice_active_connections
// myservice_pow_attempts_total
```

### Structured Logging

```rust
use hypertor::{OnionApp, LogConfig};

let app = OnionApp::builder()
    .logging(LogConfig {
        format: LogFormat::Json,
        level: "info",
        // Redact sensitive data
        redact_headers: vec!["authorization", "cookie"],
        redact_body_fields: vec!["password", "token"],
    })
    .build();
```

## Multi-Service Architecture

Run multiple .onion services from one application:

```rust
use hypertor::{OnionApp, ServiceConfig};

// Public API service
let public_app = OnionApp::builder()
    .key_path("/keys/public")
    .build();
public_app.get("/api", public_handler);

// Admin service (separate .onion address)
let admin_app = OnionApp::builder()
    .key_path("/keys/admin")
    .client_auth_enabled(true)
    .build();
admin_app.get("/admin", admin_handler);

// Run both
tokio::try_join!(
    public_app.run(),
    admin_app.run(),
)?;
```

## Next Steps

- [TorClient Documentation](/docs/client/) — Make requests to .onion services
- [Security Features](/docs/security/) — PoW, Vanguards, Leak Detection
- [Python Bindings](/docs/python/) — Full Python API reference
