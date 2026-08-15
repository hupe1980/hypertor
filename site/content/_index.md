+++
title = "hypertor"
description = "Tor for Rust and Python. Make HTTP requests over the Tor network and host onion services, with no Tor daemon required."
template = "index.html"
sort_by = "weight"

[extra]
headline = "Tor, without the daemon."
tagline = """
Make HTTP requests over the Tor network and host onion services, from Rust or Python. hypertor is a
thin layer over <a href="https://gitlab.torproject.org/tpo/core/arti" rel="noopener">arti</a>, the
Tor Project's own Rust implementation of Tor, and <a href="https://hyper.rs" rel="noopener">hyper</a>,
the HTTP stack <code>reqwest</code> is built on.
"""
note = """
No <code>tor</code> daemon, no Tor Browser, no <code>torsocks</code> — hypertor speaks the Tor
protocol itself. It implements no Tor protocol and no HTTP protocol of its own: cryptography and
protocol handling belong in the projects that specialise in them.
"""
+++

<section class="band"><div class="band-inner two-up">

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

```python
import hypertor

URL = "https://check.torproject.org/api/ip"

with hypertor.Client() as client:
    response = client.get(URL)
    response.raise_for_status()
    print(response.json())
```

</div></section>

<section class="band band--alt"><div class="band-inner">

## What it adds over wiring arti and hyper together yourself

<div class="grid">
<article class="feature">

### Pooling that actually pools

The Tor connector plugs into hyper's pooling client, so a warm circuit is reused across requests.
Building a circuit costs seconds; a request on an established one costs a few hundred milliseconds.

</article>
<article class="feature">

### Circuit isolation, all the way down

Decide explicitly which activities may be linked. Each isolation group gets its own connection pool
*and its own TLS session store*, so a resumed session cannot hand a server the link the circuits
were keeping apart.

</article>
<article class="feature">

### Redirects that don't betray you

Credentials are stripped whenever a redirect crosses an origin, dot segments are resolved before the
request is sent, and a redirect from a `.onion` out to clearnet is refused unless you ask for it.

</article>
<article class="feature">

### No local DNS, ever

Hostnames are resolved by the exit relay. The SOCKS proxy refuses IP literals by default and speaks
Tor's `RESOLVE` extension, so a misconfigured client fails loudly instead of leaking a plaintext
query from your real address.

</article>
<article class="feature">

### Post-quantum key exchange

Clearnet TLS leads with the `X25519MLKEM768` hybrid, so a session key is safe unless both halves
break. "Harvest now, decrypt later" describes an adversary with exactly the patience to care about
Tor traffic.

</article>
<article class="feature">

### Services that don't stand out

A hosted onion service answers only `BEGIN` streams on the ports it publishes, and emits no `Date`,
`Server` or reproducible `ETag` — the headers used to match a hidden service to the host behind it.

</article>
<article class="feature">

### Streams, not buffers

Upload from a file and download to one without holding either in memory. Decompression is
incremental, so the size limit bounds a decompression bomb instead of discovering one.

</article>
<article class="feature">

### Errors that don't leak

Hostnames are scrubbed from error messages, because error messages end up in logs, bug reports and
issue trackers.

</article>
</div>

</div></section>

<section class="band"><div class="band-inner two-up">

<div>

## Host an onion service

A small routed HTTP framework on top of a real onion service. The HTTP is hyper's, so parsing,
chunked bodies and keep-alive behave exactly as they do anywhere else — and both HTTP/1.1 and
HTTP/2 are served on the same virtual port.

[Hosting guide →](@/docs/server.md)

</div>

```rust
use hypertor::{OnionApp, ServeResponse};

let app = OnionApp::new()
    .get("/", |_req| async {
        ServeResponse::html("<h1>hello</h1>")
    })
    .get("/users/{id}", |req| async move {
        let id = req.param("id").unwrap_or_default();
        ServeResponse::json(&serde_json::json!({ "id": id }))
    });

let service = app.serve("my-service").await?;
println!("live at {}", service.onion_address());
service.wait().await
```

</div></section>

<section class="band band--alt"><div class="band-inner narrow">

## Install

```bash
cargo add hypertor
cargo add tokio --features full
```

```bash
pip install hypertor
```

Rust 1.91 or later; Python 3.10 or later. Wheels ship for Linux and macOS on x86-64 and arm64, and
for Windows on x86-64, so the Python package needs no Rust toolchain.

</div></section>
