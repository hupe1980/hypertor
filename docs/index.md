---
layout: single
title: "hypertor"
excerpt: "The Tor network library for Rust and Python"
header:
  overlay_color: "#16213e"
  overlay_filter: "0.7"
classes: wide
sidebar: false
author_profile: false
---

<style>
.feature-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1.5rem;
  margin: 2rem 0;
}
.feature-card {
  background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
  border: 1px solid #0f3460;
  border-radius: 12px;
  padding: 1.5rem;
  transition: transform 0.2s, box-shadow 0.2s;
}
.feature-card:hover {
  transform: translateY(-4px);
  box-shadow: 0 8px 25px rgba(0, 255, 136, 0.15);
}
.feature-card h3 {
  color: #00ff88;
  margin-top: 0;
  font-size: 1.1rem;
}
.feature-card p {
  color: #a0a0a0;
  margin-bottom: 0;
  font-size: 0.95rem;
}
.hero-section {
  text-align: center;
  padding: 2rem 0 3rem;
}
.hero-section h1 {
  font-size: 3rem;
  margin-bottom: 0.5rem;
}
.hero-section .tagline {
  font-size: 1.3rem;
  color: #888;
  margin-bottom: 2rem;
}
.cta-buttons {
  display: flex;
  gap: 1rem;
  justify-content: center;
  flex-wrap: wrap;
  margin-bottom: 2rem;
}
.cta-buttons a {
  display: inline-block;
  padding: 0.8rem 1.8rem;
  border-radius: 8px;
  font-weight: 600;
  text-decoration: none;
  transition: all 0.2s;
}
.cta-primary {
  background: #00ff88;
  color: #1a1a2e !important;
}
.cta-primary:hover {
  background: #00cc6a;
  transform: translateY(-2px);
}
.cta-secondary {
  background: transparent;
  border: 2px solid #00ff88;
  color: #00ff88 !important;
}
.cta-secondary:hover {
  background: rgba(0, 255, 136, 0.1);
}
.code-section {
  background: #0d1117;
  border-radius: 12px;
  padding: 1.5rem;
  margin: 2rem 0;
  border: 1px solid #30363d;
}
.code-section h4 {
  color: #00ff88;
  margin-top: 0;
  font-size: 0.9rem;
  text-transform: uppercase;
  letter-spacing: 1px;
}
.comparison-table {
  width: 100%;
  border-collapse: collapse;
  margin: 2rem 0;
}
.comparison-table th, .comparison-table td {
  padding: 1rem;
  text-align: left;
  border-bottom: 1px solid #30363d;
}
.comparison-table th {
  background: #16213e;
  color: #00ff88;
}
.comparison-table tr:hover {
  background: rgba(0, 255, 136, 0.05);
}
.stats-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 1rem;
  margin: 2rem 0;
  text-align: center;
}
.stat-item {
  background: #16213e;
  padding: 1.5rem;
  border-radius: 8px;
  border: 1px solid #0f3460;
}
.stat-item .number {
  font-size: 2rem;
  font-weight: 700;
  color: #00ff88;
}
.stat-item .label {
  color: #888;
  font-size: 0.9rem;
}
.use-case-section {
  background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
  border-radius: 12px;
  padding: 2rem;
  margin: 2rem 0;
  border: 1px solid #30363d;
}
.use-case-section h3 {
  color: #00ff88;
  margin-top: 0;
}
.use-case-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
  margin-top: 1rem;
}
.use-case-item {
  padding: 0.75rem 1rem;
  background: rgba(0, 255, 136, 0.05);
  border-radius: 8px;
  border-left: 3px solid #00ff88;
}
.arch-diagram {
  background: #0d1117;
  border-radius: 12px;
  padding: 1rem;
  margin: 2rem 0;
  border: 1px solid #30363d;
  overflow-x: auto;
}
.arch-diagram pre {
  margin: 0;
  color: #c9d1d9;
  font-size: 0.85rem;
}
@media (max-width: 768px) {
  .stats-grid {
    grid-template-columns: repeat(2, 1fr);
  }
  .hero-section h1 {
    font-size: 2rem;
  }
}
</style>

<div class="hero-section">
  <h1>🧅 hypertor</h1>
  <p class="tagline">The Tor network library for Rust and Python</p>
  <p style="color: #666; max-width: 650px; margin: 0 auto 2rem;">
    Consume AND host onion services with the simplicity of <code>reqwest</code> and <code>axum</code>. 
    State-of-the-art security features including PoW DoS protection, Vanguards, and traffic analysis defense.
  </p>
  <div class="cta-buttons">
    <a href="{{ '/docs/quickstart/' | relative_url }}" class="cta-primary">Get Started</a>
    <a href="https://github.com/hupe1980/hypertor" class="cta-secondary">GitHub</a>
  </div>
</div>

<div class="stats-grid">
  <div class="stat-item">
    <div class="number">27K+</div>
    <div class="label">Lines of Code</div>
  </div>
  <div class="stat-item">
    <div class="number">51</div>
    <div class="label">Modules</div>
  </div>
  <div class="stat-item">
    <div class="number">292</div>
    <div class="label">Tests</div>
  </div>
  <div class="stat-item">
    <div class="number">71</div>
    <div class="label">Benchmarks</div>
  </div>
</div>

---

## Why hypertor?

Traditional Tor libraries force you to choose: either a complex low-level API for security researchers, or a simplified wrapper that sacrifices control. **hypertor** provides both: a batteries-included experience for common tasks, with full access to advanced security features when you need them.

<div class="use-case-section">
  <h3>🎯 Built For</h3>
  <div class="use-case-grid">
    <div class="use-case-item">Security Researchers</div>
    <div class="use-case-item">Penetration Testers</div>
    <div class="use-case-item">Privacy Applications</div>
    <div class="use-case-item">Anonymous APIs</div>
    <div class="use-case-item">Whistleblower Platforms</div>
    <div class="use-case-item">Censorship Circumvention</div>
    <div class="use-case-item">Secure Communication</div>
    <div class="use-case-item">Onion Service Hosting</div>
  </div>
</div>

---

## Two Libraries in One

<table class="comparison-table">
  <tr>
    <th>Component</th>
    <th>Purpose</th>
    <th>Similar To</th>
  </tr>
  <tr>
    <td><strong>TorClient</strong></td>
    <td>Make HTTP requests over Tor anonymously</td>
    <td><code>reqwest</code>, <code>httpx</code></td>
  </tr>
  <tr>
    <td><strong>OnionApp</strong></td>
    <td>Host .onion services with routing</td>
    <td><code>axum</code>, <code>FastAPI</code></td>
  </tr>
</table>

---

## Quick Examples

<div class="code-section" markdown="1">
<h4>Rust — Anonymous Client</h4>

```rust
use hypertor::{TorClient, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let client = TorClient::new().await?;
    
    let resp = client
        .get("http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion")?
        .send()
        .await?;
    
    println!("Status: {}", resp.status());
    Ok(())
}
```
</div>

<div class="code-section" markdown="1">
<h4>Rust — Onion Service</h4>

```rust
use hypertor::{OnionApp, ServeResponse};

#[tokio::main]
async fn main() -> hypertor::Result<()> {
    let app = OnionApp::new()
        .get("/", || async { ServeResponse::text("Hello from .onion!") })
        .get("/api/status", || async {
            ServeResponse::json(&serde_json::json!({"status": "operational"}))
        });
    
    let addr = app.run().await?;
    println!("🧅 Live at: {}", addr);
    Ok(())
}
```
</div>

<div class="code-section" markdown="1">
<h4>Python — httpx-style Client</h4>

```python
import asyncio
from hypertor import AsyncClient

async def main():
    async with AsyncClient(timeout=60) as client:
        resp = await client.get("https://check.torproject.org/api/ip")
        print(f"Tor IP: {resp.json().get('IP')}")

asyncio.run(main())
```
</div>

<div class="code-section" markdown="1">
<h4>Python — FastAPI-style Server</h4>

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

if __name__ == "__main__":
    app.run()  # 🧅 Live at: xyz...xyz.onion
```
</div>

---

## Security Features

<div class="feature-grid">
  <div class="feature-card">
    <h3>🛡️ PoW DoS Protection</h3>
    <p>Tor 0.4.8+ Proof-of-Work defense with adaptive difficulty automatically protects your service from DDoS attacks without affecting legitimate users.</p>
  </div>
  <div class="feature-card">
    <h3>🔐 Client Authorization</h3>
    <p>Basic & Stealth authorization modes with x25519 key derivation. Restrict access to authorized clients while hiding service existence from others.</p>
  </div>
  <div class="feature-card">
    <h3>📊 Vanguards Protection</h3>
    <p>Vanguards-lite guard relay protection prevents circuit enumeration attacks that could reveal your service's location.</p>
  </div>
  <div class="feature-card">
    <h3>🎭 Traffic Analysis Defense</h3>
    <p>WTF-PAD, Tamaraw padding, and circuit padding machines resist website fingerprinting and correlation attacks.</p>
  </div>
  <div class="feature-card">
    <h3>🔍 Leak Detection</h3>
    <p>Comprehensive security scanner detects DNS leaks, header fingerprinting, timing patterns, and content leaks before they compromise anonymity.</p>
  </div>
  <div class="feature-card">
    <h3>⏱️ Timing Attack Protection</h3>
    <p>Built-in timing correlation defense with jitter injection and pattern detection to prevent traffic analysis attacks.</p>
  </div>
  <div class="feature-card">
    <h3>⚡ Congestion Control</h3>
    <p>Vegas RTT-based congestion control (Tor Proposal 324) provides optimal throughput without overwhelming the network.</p>
  </div>
  <div class="feature-card">
    <h3>🔌 WebSocket & gRPC</h3>
    <p>Real-time bidirectional WebSocket communication and gRPC services over Tor for modern application architectures.</p>
  </div>
  <div class="feature-card">
    <h3>🌉 Bridge Support</h3>
    <p>Full support for obfs4, snowflake, meek, and webtunnel pluggable transports for censorship circumvention.</p>
  </div>
  <div class="feature-card">
    <h3>📈 Prometheus Metrics</h3>
    <p>Production-ready observability with counters, gauges, histograms, and automatic /metrics endpoint for monitoring.</p>
  </div>
</div>

---

## Security Presets

Choose your security level based on your threat model:

```rust
use hypertor::SecurityConfig;

// Basic Tor protection (fastest)
SecurityConfig::standard()

// PoW + Vanguards (recommended for most)
SecurityConfig::enhanced()

// Full Vanguards + Client Authorization
SecurityConfig::maximum()

// Stealth Auth + Max PoW + Tamaraw padding
SecurityConfig::paranoid()
```

| Preset | PoW | Vanguards | Client Auth | Traffic Padding | Use Case |
|--------|-----|-----------|-------------|-----------------|----------|
| `standard` | ❌ | ❌ | ❌ | ❌ | Development, low-risk |
| `enhanced` | ✅ | lite | ❌ | ❌ | Most production services |
| `maximum` | ✅ | full | basic | ❌ | High-value targets |
| `paranoid` | ✅ max | full | stealth | Tamaraw | State-level adversaries |

---

## Architecture

<div class="arch-diagram">
<pre>
┌─────────────────────────────────────────────────────────────────────┐
│                         YOUR APPLICATION                             │
├─────────────────────────────────────────────────────────────────────┤
│   TorClient            │   OnionApp             │   SOCKS5 Proxy    │
│   (consume .onion)     │   (host .onion)        │   (bridge tools)  │
├─────────────────────────────────────────────────────────────────────┤
│                           hypertor core                              │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌──────────────┐  │
│  │ Connection │  │  Privacy   │  │  Security  │  │ Observability│  │
│  │  Pooling   │  │  Padding   │  │  PoW/Auth  │  │   Metrics    │  │
│  │   Retry    │  │ Vanguards  │  │  Analysis  │  │   Tracing    │  │
│  └────────────┘  └────────────┘  └────────────┘  └──────────────┘  │
├─────────────────────────────────────────────────────────────────────┤
│                       arti-client (Tor Protocol)                     │
├─────────────────────────────────────────────────────────────────────┤
│                       Tor Network (6000+ relays)                     │
└─────────────────────────────────────────────────────────────────────┘
</pre>
</div>

---

## Performance

| Operation | Time | Notes |
|-----------|------|-------|
| Circuit establishment | ~2-4s | Initial connection |
| HTTP request (warm) | ~200-500ms | With pooled circuit |
| OnionApp startup | ~3-5s | Service registration |
| Request throughput | ~50-100 req/s | Depends on circuit |

All benchmarks run with `cargo bench` — 71 benchmarks covering all major operations.

---

## Installation

### Rust

```toml
[dependencies]
hypertor = "0.3"
tokio = { version = "1", features = ["full"] }
```

### Python

```bash
pip install hypertor
```

---

## Documentation

<div class="feature-grid">
  <div class="feature-card">
    <h3><a href="{{ '/docs/quickstart/' | relative_url }}">📚 Quick Start</a></h3>
    <p>Get up and running in 5 minutes with basic examples for both client and server usage.</p>
  </div>
  <div class="feature-card">
    <h3><a href="{{ '/docs/client/' | relative_url }}">🌐 TorClient Guide</a></h3>
    <p>Deep dive into the HTTP client: requests, authentication, streaming, and advanced options.</p>
  </div>
  <div class="feature-card">
    <h3><a href="{{ '/docs/server/' | relative_url }}">🧅 OnionApp Guide</a></h3>
    <p>Build and deploy onion services with routing, middleware, and security configuration.</p>
  </div>
  <div class="feature-card">
    <h3><a href="{{ '/docs/security/' | relative_url }}">🔒 Security Guide</a></h3>
    <p>Configure PoW, Vanguards, client authorization, and traffic analysis defenses.</p>
  </div>
</div>

---

<div style="text-align: center; margin: 3rem 0;">
  <a href="{{ '/docs/quickstart/' | relative_url }}" class="cta-primary" style="font-size: 1.1rem; padding: 1rem 2rem;">
    🚀 Get Started Now
  </a>
</div>

---

## ⚠️ Disclaimer

<div style="background: linear-gradient(135deg, #2d1b1b 0%, #1a1a2e 100%); border: 1px solid #5c3a3a; border-radius: 12px; padding: 1.5rem; margin: 2rem 0;">

**This software is provided for educational and research purposes only.**

- **No Anonymity Guarantee**: While hypertor leverages the Tor network via arti, no software can guarantee complete anonymity. Your operational security practices, threat model, and usage patterns significantly impact your privacy.
- **No Warranty**: This software is provided "as is" without warranty of any kind. The authors are not responsible for any damages or legal consequences arising from its use.
- **Legal Compliance**: Users are solely responsible for ensuring their use of this software complies with all applicable laws and regulations in their jurisdiction.
- **Not Endorsed by Tor Project**: This is an independent project and is not affiliated with, endorsed by, or sponsored by The Tor Project.
- **Security Considerations**: Always review the <a href="{{ '/docs/security/' | relative_url }}">Security Guide</a> before deploying in production.

</div>
