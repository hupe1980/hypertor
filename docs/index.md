---
layout: single
title: "hypertor"
excerpt: "Tor for Rust and Python"
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
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 1.25rem;
  margin: 2rem 0;
}
.feature-card {
  background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
  border: 1px solid #0f3460;
  border-radius: 12px;
  padding: 1.4rem;
}
.feature-card h3 {
  color: #00ff88;
  margin-top: 0;
  font-size: 1.05rem;
}
.feature-card p {
  color: #a8a8b3;
  margin-bottom: 0;
  font-size: 0.94rem;
  line-height: 1.55;
}
.hero { text-align: center; padding: 1rem 0 2rem; }
.hero .tagline { font-size: 1.2rem; color: #9a9aa5; margin-bottom: 1.5rem; }
.cta { display: flex; gap: .75rem; justify-content: center; flex-wrap: wrap; margin-bottom: 1rem; }
</style>

<div class="hero">
  <p class="tagline">Make HTTP requests over the Tor network, and host onion services.</p>
  <div class="cta">
    <a class="btn btn--primary btn--large" href="{{ site.baseurl }}/docs/quickstart/">Get started</a>
    <a class="btn btn--inverse btn--large" href="https://github.com/hupe1980/hypertor">GitHub</a>
    <a class="btn btn--inverse btn--large" href="https://docs.rs/hypertor">API docs</a>
  </div>
</div>

hypertor is a thin layer over two mature pieces of software:
[**arti**](https://gitlab.torproject.org/tpo/core/arti), the Tor Project's Rust implementation of
Tor, and [**hyper**](https://hyper.rs), the HTTP stack `reqwest` is built on. It supplies the seam
between them and the ergonomics on top.

It implements no Tor protocol and no HTTP protocol of its own — cryptography and protocol handling
belong in the projects that specialise in them.

**No Tor daemon required.**

---

## Rust

```rust
use hypertor::TorClient;

#[tokio::main]
async fn main() -> hypertor::Result<()> {
    let client = TorClient::new().await?;

    let body = client
        .get("https://check.torproject.org/api/ip")?
        .send()
        .await?
        .error_for_status()?
        .text()?;

    println!("{body}");
    Ok(())
}
```

## Python

```python
import hypertor

with hypertor.Client() as client:
    print(client.get("https://check.torproject.org/api/ip").json())
```

## Hosting a service

```rust
use hypertor::{OnionApp, ServeResponse};

let app = OnionApp::new()
    .get("/", |_req| async { ServeResponse::text("hello from .onion") });

let service = app.serve("my-service").await?;
println!("live at {}", service.onion_address());
service.wait().await
```

---

<div class="feature-grid">

  <div class="feature-card">
    <h3>Pooling that actually pools</h3>
    <p>The Tor connector plugs into hyper's pooling client, so a warm circuit is reused across
    requests. Over Tor that is the difference between seconds and milliseconds.</p>
  </div>

  <div class="feature-card">
    <h3>Circuit isolation, first class</h3>
    <p>Decide explicitly which of your activities may be linked to one another. Different isolation
    tokens are guaranteed never to share a circuit — or a connection pool.</p>
  </div>

  <div class="feature-card">
    <h3>Redirects that don't betray you</h3>
    <p>Credentials are stripped across origins, and a redirect from a <code>.onion</code> out to
    clearnet is refused unless you ask for it.</p>
  </div>

  <div class="feature-card">
    <h3>No local DNS, ever</h3>
    <p>Hostnames are resolved by the exit relay. The SOCKS proxy refuses IP literals by default, so a
    misconfigured client fails loudly instead of leaking quietly.</p>
  </div>

  <div class="feature-card">
    <h3>Errors that don't leak</h3>
    <p>Hostnames are scrubbed from error messages, because error messages end up in logs and bug
    reports.</p>
  </div>

  <div class="feature-card">
    <h3>Real onion service hardening</h3>
    <p>Vanguards, Equi-X proof of work, intro-point rate limiting and restricted discovery — every
    one wired straight to arti.</p>
  </div>

</div>

---

## Install

```toml
[dependencies]
hypertor = "0.3"
tokio = { version = "1", features = ["full"] }
```

```bash
pip install hypertor
```

---

## Documentation

| | |
|---|---|
| [Quick start]({{ site.baseurl }}/docs/quickstart/) | Install and make your first request |
| [Installation]({{ site.baseurl }}/docs/installation/) | Feature flags, platforms, TLS backends |
| [Client]({{ site.baseurl }}/docs/client/) | Requests, isolation, redirects, retries |
| [Onion services]({{ site.baseurl }}/docs/server/) | Hosting, persistence, hardening |
| [SOCKS5 proxy]({{ site.baseurl }}/docs/proxy/) | Routing other programs through Tor |
| [Security]({{ site.baseurl }}/docs/security/) | The threat model, and its limits |
| [Python]({{ site.baseurl }}/docs/python/) | The Python API |

---

## A word of caution

hypertor is not an anonymity system in its own right, and no library can be. Tor protects the
network path; it cannot protect you from an application that logs in with your real identity, from
timing patterns in your own traffic, or from a compromised machine.

Read the [Tor Project's guidance](https://support.torproject.org/) before relying on this for
anything that matters. This project is not affiliated with, endorsed by, or sponsored by the Tor
Project.
