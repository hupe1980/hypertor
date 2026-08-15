---
title: "Quick Start"
permalink: /docs/quickstart/
toc: true
---

hypertor makes HTTP requests over the Tor network and hosts onion services. It is a thin layer over
[arti](https://gitlab.torproject.org/tpo/core/arti) — the Tor Project's Rust implementation of Tor —
and [hyper](https://hyper.rs), the HTTP stack `reqwest` is built on.

**No Tor daemon required.** arti speaks the Tor protocol directly, so there is nothing to install
alongside your program.

## Install

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

## Your first request

```rust
use hypertor::TorClient;

#[tokio::main]
async fn main() -> hypertor::Result<()> {
    // Bootstrapping downloads a Tor directory consensus. The first run takes
    // tens of seconds; later runs reuse the cache and are much faster.
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

```python
import hypertor

with hypertor.Client() as client:
    print(client.get("https://check.torproject.org/api/ip").json())
```

## Reaching an onion service

`.onion` addresses work exactly like any other URL, and never touch an exit relay — the connection
is end-to-end encrypted and authenticated by Tor itself, because the address *is* the service's
public key.

```rust
let response = client
    .get("http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/")?
    .send()
    .await?;
```

## Hosting an onion service

```rust
use hypertor::{OnionApp, ServeResponse};

#[tokio::main]
async fn main() -> hypertor::Result<()> {
    let app = OnionApp::new()
        .get("/", |_req| async { ServeResponse::text("hello from .onion") });

    let service = app.serve("my-service").await?;
    println!("live at {}", service.onion_address());
    service.wait().await
}
```

Requires the `server` feature:

```toml
hypertor = { version = "0.3", features = ["server"] }
```

## What to expect

Tor is slower than the clearnet, and that is inherent to how it works rather than a defect you can
tune away.

| Operation | Typical cost |
|---|---|
| Bootstrapping (cold cache) | 10–60 s |
| Bootstrapping (warm cache) | 1–5 s |
| Building a circuit | 1–5 s |
| A request on an established circuit | 0.2–2 s |
| Publishing an onion service descriptor | 10–60 s |

hypertor pools connections through hyper, so the circuit cost is paid once per destination rather
than once per request. Reuse a single `TorClient` for the lifetime of your program.

## Next

- [Client]({{ site.baseurl }}/docs/client/) — requests, isolation, redirects, retries
- [Onion services]({{ site.baseurl }}/docs/server/) — hosting, persistence, hardening
- [SOCKS5 proxy]({{ site.baseurl }}/docs/proxy/) — routing other programs through Tor
- [Security]({{ site.baseurl }}/docs/security/) — the threat model, and its limits
- [Python]({{ site.baseurl }}/docs/python/) — the Python API
