---
title: "Quick Start"
permalink: /docs/quickstart/
excerpt: "Get up and running with hypertor in under 5 minutes"
---

Get up and running with hypertor in under 5 minutes.

## Installation

### Rust

Add hypertor to your `Cargo.toml`:

```toml
[dependencies]
hypertor = "0.4"
tokio = { version = "1", features = ["full"] }
```

### Python

Install from PyPI:

```bash
pip install hypertor
```

## Making Your First Request

hypertor's `TorClient` works just like `reqwest` or Python's `requests` — but routes everything through Tor.

### Rust

```rust
use hypertor::{TorClient, Result};

#[tokio::main]
async fn main() -> Result<()> {
    // Create a Tor client (bootstraps automatically)
    let client = TorClient::new().await?;
    
    // Make a GET request to an onion service
    let response = client
        .get("http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion")?
        .send()
        .await?;
    
    println!("Status: {}", response.status());
    println!("Body: {}", response.text()?);
    
    Ok(())
}
```

### Python

```python
import asyncio
from hypertor import AsyncClient

async def main():
    async with AsyncClient(timeout=60) as client:
        response = await client.get(
            "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
        )
        
        print(f"Status: {response.status_code}")
        print(f"Body: {response.text()}")

asyncio.run(main())
```

## POST with JSON

### Rust

```rust
use hypertor::TorClient;
use serde::Serialize;

#[derive(Serialize)]
struct User {
    name: String,
    email: String,
}

#[tokio::main]
async fn main() -> hypertor::Result<()> {
    let client = TorClient::new().await?;
    
    let response = client
        .post("http://api.example.onion/users")?
        .json(&User {
            name: "Alice".into(),
            email: "alice@example.onion".into(),
        })
        .send()
        .await?;
    
    println!("Created: {}", response.text()?);
    Ok(())
}
```

### Python

```python
async with AsyncClient(timeout=60) as client:
    response = await client.post(
        "https://httpbin.org/post",
        json='{"name": "Alice", "email": "alice@example.onion"}'
    )
    print(response.json())
```

## Builder Pattern (Advanced Configuration)

### Rust

```rust
use hypertor::{TorClient, IsolationLevel};
use std::time::Duration;

let client = TorClient::builder()
    .timeout(Duration::from_secs(60))
    .max_connections(20)
    .isolation(IsolationLevel::PerRequest)
    .follow_redirects(true)
    .build()
    .await?;
```

### Python

```python
from hypertor import AsyncClient

# Python API is simpler - just timeout configuration
async with AsyncClient(timeout=60) as client:
    # Requests are automatically routed through Tor
    response = await client.get("https://check.torproject.org/api/ip")
    print(response.json())
```

## Creating an Onion Service

`OnionApp` lets you host your own .onion service with a FastAPI-like API.

### Rust

```rust
use hypertor::{OnionApp, get, Json, Result};
use serde::Serialize;

#[derive(Serialize)]
struct Message {
    message: String,
}

async fn home() -> &'static str {
    "Welcome to my onion service! 🧅"
}

async fn api_hello() -> Json<Message> {
    Json(Message {
        message: "Hello from Tor!".into(),
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let app = OnionApp::new()
        .route("/", get(home))
        .route("/api/hello", get(api_hello));
    
    // Start the service - prints your .onion address
    app.run().await?;
    
    Ok(())
}
```

### Python

```python
from hypertor import OnionApp

app = OnionApp()

@app.get("/")
async def home():
    return "Welcome to my onion service! 🧅"

@app.get("/api/hello")
async def api_hello():
    return {"message": "Hello from Tor!"}

if __name__ == "__main__":
    app.run()  # Prints: 🧅 Service live at: xyz...xyz.onion
```

## Security Analysis

Run a security scan on your client to detect potential anonymity leaks:

### Rust

```rust
use hypertor::{TorClient, Result};
use hypertor::security::{SecurityScanner, ScanConfig};

#[tokio::main]
async fn main() -> Result<()> {
    let client = TorClient::new().await?;
    
    // Create security scanner
    let scanner = SecurityScanner::new(ScanConfig {
        leak_detection: true,
        fingerprint_analysis: true,
        timing_analysis: true,
        circuit_analysis: true,
        ..Default::default()
    });
    
    // Run comprehensive security scan
    let report = scanner.scan(&client).await?;
    
    println!("🔒 Security Score: {}/100", report.score);
    
    for finding in report.findings() {
        println!("  [{:?}] {}", finding.severity, finding.description);
    }
    
    Ok(())
}
```

### Python

```python
from hypertor import AsyncClient

# Note: SecurityScanner is available in Rust only
# In Python, manually check for security issues
async def check_tor_status():
    async with AsyncClient(timeout=60) as client:
        resp = await client.get("https://check.torproject.org/api/ip")
        data = resp.json()
        
        print(f"🔒 Tor Status Check")
        print(f"   Using Tor: {data.get('IsTor', False)}")
        print(f"   Exit IP: {data.get('IP', 'unknown')}")

import asyncio
asyncio.run(check_tor_status())
```

## Verify Your IP is Hidden

Confirm you're connecting through Tor:

### Rust

```rust
use hypertor::{TorClient, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let client = TorClient::new().await?;
    
    // Check if we're using Tor
    let resp = client
        .get("https://check.torproject.org/api/ip")?
        .send()
        .await?;
    
    let data: serde_json::Value = resp.json()?;
    
    if data["IsTor"].as_bool() == Some(true) {
        println!("✅ Connected through Tor!");
        println!("   IP: {}", data["IP"]);
    } else {
        println!("❌ NOT connected through Tor!");
    }
    
    Ok(())
}
```

### Python

```python
from hypertor import AsyncClient
import asyncio

async def main():
    async with AsyncClient(timeout=60) as client:
        resp = await client.get("https://check.torproject.org/api/ip")
        data = resp.json()
    
    if data.get("IsTor"):
        print(f"✅ Connected through Tor!")
        print(f"   IP: {data['IP']}")
    else:
        print("❌ NOT connected through Tor!")
```

## Next Steps

- [TorClient Documentation](/docs/client/) — HTTP client details
- [OnionApp Documentation](/docs/server/) — Server framework details
- [Security Features](/docs/security/) — PoW, Vanguards, Leak Detection
- [Python Bindings](/docs/python/) — Full Python API reference
