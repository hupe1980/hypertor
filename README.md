# 🧅 hypertor

**Tor for Rust and Python.** Make HTTP requests over the Tor network, and host onion services.

[![CI](https://github.com/hupe1980/hypertor/actions/workflows/ci.yml/badge.svg)](https://github.com/hupe1980/hypertor/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/hypertor.svg)](https://crates.io/crates/hypertor)
[![Documentation](https://docs.rs/hypertor/badge.svg)](https://docs.rs/hypertor)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.86-blue.svg)](https://www.rust-lang.org)

---

hypertor is a thin layer over two mature pieces of software:
[**arti**](https://gitlab.torproject.org/tpo/core/arti), the Tor Project's Rust implementation of
Tor, and [**hyper**](https://hyper.rs), the HTTP stack `reqwest` is built on. It supplies the seam
between them and the ergonomics on top.

It implements no Tor protocol and no HTTP protocol of its own. That is the point: cryptography and
protocol handling belong in the projects that specialise in them.

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

with hypertor.Client() as client:
    print(client.get("https://check.torproject.org/api/ip").json())
```

---

## Install

**Rust**

```toml
[dependencies]
hypertor = "0.3"
tokio = { version = "1", features = ["full"] }
```

**Python**

```bash
pip install hypertor
```

No system Tor daemon is required. arti speaks the Tor protocol directly.

---

## What it does

| | |
|---|---|
| **`TorClient`** | HTTP/1.1 and HTTP/2 over Tor, with real connection pooling |
| **`OnionService`** | Host a `.onion` service; hand you the raw inbound streams |
| **`OnionApp`** | A small routed HTTP framework on top of `OnionService` |
| **`SocksProxy`** | A local SOCKS5 front-end, so any program can use Tor |
| **`TorWebSocket`** | WebSocket over Tor |

---

## Client

```rust
use std::time::Duration;
use hypertor::{IsolationLevel, TorClient};

let client = TorClient::builder()
    .timeout(Duration::from_secs(60))
    .isolation(IsolationLevel::PerHost)
    .max_retries(2)
    .build()
    .await?;

// JSON in, typed JSON out.
let created: User = client
    .post("http://api.onion/users")?
    .json(&NewUser { name: "Alice".into() })
    .send()
    .await?
    .error_for_status()?
    .json()?;

// Query parameters, encoded for you.
let results = client
    .get("http://search.onion/")?
    .query([("q", "rust & tor"), ("page", "1")])
    .send()
    .await?;
```

### Connection pooling is real

The Tor connector plugs into hyper's pooling client, so a warm circuit is reused across requests.
This matters more over Tor than anywhere else: building a circuit costs seconds, while a request on
an established one costs a few hundred milliseconds.

```rust
client.get(url)?.send().await?;  // builds a circuit — slow
client.get(url)?.send().await?;  // reuses it — fast
```

---

## Circuit isolation

Two requests on the same circuit exit the Tor network from the same relay at the same time, and can
be linked by anyone watching it. Isolation is how you decide which of your activities are allowed to
be linked to each other.

```rust
use hypertor::IsolationToken;

let alice = IsolationToken::new();
let bob = IsolationToken::new();

// Same token → same circuit. Different tokens → never the same circuit.
client.get("http://forum.onion/inbox")?.isolation(alice).send().await?;
client.get("http://forum.onion/profile")?.isolation(alice).send().await?;
client.get("http://shop.onion/cart")?.isolation(bob).send().await?;
```

| `IsolationLevel` | Behaviour | Cost |
|---|---|---|
| `None` | hypertor adds no isolation | Cheapest |
| `PerHost` *(default)* | One circuit family per destination host | Reuses warm circuits |
| `PerRequest` | A fresh circuit for every request | Seconds per request |
| `Fixed(token)` | One explicit token for everything | — |

---

## Hosting an onion service

```rust
use hypertor::{OnionApp, OnionService, ServeResponse};

let app = OnionApp::new()
    .get("/", |_req| async { ServeResponse::html("<h1>hello</h1>") })
    .get("/health", |_req| async {
        ServeResponse::json(&serde_json::json!({"status": "ok"}))
    })
    .get("/users/{id}", |req| async move {
        let id = req.param("id").unwrap_or_default().to_string();
        ServeResponse::json(&serde_json::json!({ "id": id }))
    });

let service = OnionService::builder()
    .nickname("my-service")?
    .state_dir("/var/lib/my-service")   // keeps the .onion address stable
    .launch()
    .await?;

let serving = app.serve_on(service).await?;
println!("live at {}", serving.onion_address());
serving.wait().await
```

> **`state_dir` is what makes your address permanent.** A `.onion` address is derived from a keypair
> arti stores there. A service launched without one gets a brand-new address on every restart. Treat
> the directory as secret: anyone who copies it can impersonate your service.

The HTTP is hyper's, so chunked bodies, keep-alive, pipelining and HTTP/2 all behave exactly as they
do in any other hyper server.

### Hardening

Every option maps to an arti feature; hypertor implements none of this itself.

```rust
OnionService::builder()
    .nickname("high-value")?
    .state_dir("/var/lib/svc")
    .vanguards(hypertor::VanguardMode::Full)   // guard-discovery defence
    .proof_of_work(true)                        // Equi-X PoW — needs the `pow` feature
    .rate_limit_at_intro(10, 20)                // token bucket at intro points
    .num_intro_points(5)                        // availability
    .authorize_client("alice", alice_key)       // restricted discovery
    .launch()
    .await?;
```

Proof of work needs the `pow` feature. It is not part of `full` because the Equi-X implementation
(`equix`, `hashx`) is LGPL-3.0-only while hypertor is MIT — a default build stays entirely
permissively licensed, and enabling PoW without the feature is an error at launch rather than a
silently unprotected service.

**Restricted discovery** is the strongest defence available: with any client authorised, the service
descriptor is encrypted so only holders of the listed keys can even find the introduction points.
Clients generate their own keys (`arti hsc get-key`) — hypertor will not generate them for you,
because the secret half must never exist on the server.

---

## SOCKS5 proxy

Route any SOCKS5-capable program through Tor.

```rust
use hypertor::{SocksConfig, SocksProxy, TorClient};

let client = TorClient::new().await?;
SocksProxy::from_client(&client, SocksConfig::default()).run().await
```

```bash
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
```

**Use `socks5h`, never `socks5`.** `socks5://` makes the client resolve DNS locally first, leaking a
plaintext query from your real IP for every host you visit. hypertor's proxy rejects requests
carrying a locally-resolved IP literal by default, so a misconfigured client fails loudly rather
than leaking quietly.

Different SOCKS credentials get different circuits, following Tor's `IsolateSOCKSAuth` convention:

```bash
curl -x socks5h://alice:x@127.0.0.1:9050 https://example.com   # circuit A
curl -x socks5h://bob:x@127.0.0.1:9050   https://example.com   # circuit B
```

---

## Python

```python
import hypertor

# Sync
with hypertor.Client(timeout=60, isolation="per_host") as client:
    response = client.get("http://api.onion/data")
    response.raise_for_status()
    print(response.json())

    client.post("http://api.onion/users", json={"name": "Alice"})
```

```python
import asyncio

async def main():
    async with hypertor.AsyncClient() as client:
        # Concurrent, over separate circuits.
        responses = await asyncio.gather(
            client.get("http://a.onion/"),
            client.get("http://b.onion/"),
        )

asyncio.run(main())
```

```python
# Hosting a service
app = hypertor.OnionApp("my-service", state_dir="./onion-state")

@app.get("/")
def home(request):
    return "hello from .onion"

@app.get("/users/{user_id}")
def get_user(request):
    return {"id": request.params["user_id"]}

app.run()   # prints the .onion address, then serves
```

The bindings release the GIL for the duration of every network call, so a Tor request does not
freeze the rest of your program.

---

## Feature flags

| Feature | Default | Adds |
|---|---|---|
| `client` | ✅ | `TorClient` and the HTTP client stack |
| `rustls` | ✅ | TLS via rustls — identical fingerprint on every platform |
| `native-tls` | | TLS via the OS stack (see below) |
| `server` | | `OnionService`, `OnionApp` |
| `pow` | | Equi-X proof of work — **pulls in LGPL-3.0 crates** |
| `socks` | | `SocksProxy` |
| `ws` | | `TorWebSocket` |
| `python` | | the PyO3 bindings |

```toml
hypertor = { version = "0.3", features = ["server", "socks"] }
```

### Why rustls is the default

TLS handshakes are fingerprintable: the set and ordering of cipher suites, extensions and supported
groups differ per implementation. `native-tls` binds to whatever the host provides — OpenSSL on
Linux, SecureTransport on macOS, SChannel on Windows — so your handshake announces your operating
system to the exit relay. With `rustls`, every hypertor user emits the same ClientHello.

`native-tls` also cannot enforce a TLS 1.3 floor or negotiate ALPN, so `min_tls_version(Tls13)` is
an error there rather than a silent downgrade, and HTTP/2 over TLS is unavailable.

---

## Security notes

**What the design protects against**

| | |
|---|---|
| DNS leaking your destinations | Hostnames are always resolved by the exit relay, never locally |
| Credentials replayed to another host | Stripped on any cross-origin redirect |
| A `.onion` redirecting you to clearnet | Refused unless explicitly allowed |
| Hostnames leaking into your logs | Scrubbed in `Error` output by default (via `safelog`) |
| Decompression bombs | The size limit applies to the *decompressed* body |
| Path traversal in static files | Paths are canonicalised and confined to the root |
| Response splitting | Header values containing CR/LF are refused |
| Guard discovery | `VanguardMode`, wired to arti |
| Introduction floods | Proof-of-work and intro rate limiting, wired to arti |

**What no library can protect against**

hypertor is not an anonymity system in its own right. Tor protects the network path. It cannot
protect you from an application that logs in with your real identity, from timing patterns in your
own traffic, from a browser fingerprint, or from a compromised machine. Read the
[Tor Project's guidance](https://support.torproject.org/) before relying on this for anything that
matters.

---

## Development

```bash
cargo test --all-features          # unit and integration tests
cargo test -- --ignored            # tests that need a live Tor connection
cargo clippy --all-targets --all-features -- -D warnings
cargo bench

maturin develop --features python  # build the Python extension
pytest                             # offline Python tests
pytest -m network                  # includes live tests
```

---

## Documentation

- [Quick start](https://hupe1980.github.io/hypertor/docs/quickstart/)
- [Client](https://hupe1980.github.io/hypertor/docs/client/)
- [Onion services](https://hupe1980.github.io/hypertor/docs/server/)
- [SOCKS5 proxy](https://hupe1980.github.io/hypertor/docs/proxy/)
- [Security](https://hupe1980.github.io/hypertor/docs/security/)
- [Python](https://hupe1980.github.io/hypertor/docs/python/)
- [API reference on docs.rs](https://docs.rs/hypertor)

---

## Disclaimer

Provided for research and educational use. No anonymity guarantee: your operational security,
threat model and usage patterns matter more than any library. Not affiliated with, endorsed by, or
sponsored by the Tor Project. You are responsible for complying with the law where you are.

## License

MIT. See [LICENSE](LICENSE).
