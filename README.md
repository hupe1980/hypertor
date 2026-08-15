# 🧅 hypertor

**Tor for Rust and Python.** Make HTTP requests over the Tor network, and host onion services.

[![CI](https://github.com/hupe1980/hypertor/actions/workflows/ci.yml/badge.svg)](https://github.com/hupe1980/hypertor/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/hypertor.svg)](https://crates.io/crates/hypertor)
[![PyPI](https://img.shields.io/pypi/v/hypertor.svg)](https://pypi.org/project/hypertor/)
[![Documentation](https://docs.rs/hypertor/badge.svg)](https://docs.rs/hypertor)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.91-blue.svg)](https://www.rust-lang.org)

hypertor is a thin layer over two mature pieces of software:
[**arti**](https://gitlab.torproject.org/tpo/core/arti), the Tor Project's Rust implementation of
Tor, and [**hyper**](https://hyper.rs), the HTTP stack `reqwest` is built on. It supplies the seam
between them and the ergonomics on top.

It implements no Tor protocol and no HTTP protocol of its own. That is the point: cryptography and
protocol handling belong in the projects that specialise in them.

**No Tor daemon required** — no `tor`, no Tor Browser, no `torsocks`.

📖 **[Documentation](https://hupe1980.github.io/hypertor)** · [API reference](https://docs.rs/hypertor) · [Changelog](CHANGELOG.md)

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

## Install

```bash
cargo add hypertor
cargo add tokio --features full
```

```bash
pip install hypertor
```

Rust 1.91 or later; Python 3.10 or later. Wheels ship for Linux, macOS and Windows on x86-64 and
arm64, so the Python package needs no Rust toolchain.

## What it does

| | |
|---|---|
| **`TorClient`** | HTTP/1.1 and HTTP/2 over Tor, with real connection pooling |
| **`OnionService`** | Host a `.onion` service; hands you the raw inbound streams |
| **`OnionApp`** | A small routed HTTP framework on top of `OnionService` |
| **`SocksProxy`** | A local SOCKS5 front-end, so any program can use Tor |
| **`TorWebSocket`** | WebSocket over Tor, splittable for concurrent read and write |

| Feature | Default | Adds |
|---|---|---|
| `client` | ✅ | `TorClient` and the HTTP client stack |
| `rustls` | ✅ | TLS via rustls — one fingerprint on every platform |
| `native-tls` | | TLS via the OS stack (leaks your platform; see the docs) |
| `server` | | `OnionService`, `OnionApp` |
| `socks` | | `SocksProxy` |
| `ws` | | `TorWebSocket` |
| `pow` | | Equi-X proof of work — **pulls in LGPL-3.0 crates** |
| `static-sqlite` | | Link SQLite statically (useful on Windows) |

```bash
cargo add hypertor --features server,socks
```

`full` is everything except `pow`, so a default build stays permissively licensed. There is no
`python` feature: the bindings are a separate, unpublished crate, so a Rust dependency on hypertor
never pulls in pyo3.

Exactly one TLS backend is **required** — Tor's own link protocol is TLS, so even a `server`-only
build needs one. If you set `default-features = false`, put `rustls` (or `native-tls`) back.

0.4 is a hard cut from 0.2.2 with no migration shim; the [changelog](CHANGELOG.md) is the migration
guide.

## Why not just wire arti and hyper together yourself

**Connection pooling that actually pools.** The Tor connector plugs into hyper's pooling client, so
a warm circuit is reused across requests. Building a circuit costs seconds; a request on an
established one costs a few hundred milliseconds.

**Circuit isolation as a first-class concept.** Decide explicitly which of your activities may be
linked. Each isolation group gets its own connection pool *and its own TLS session store* — sharing
the latter would let a server link exactly the requests the circuits kept apart.

**Bodies that stream in both directions.** Upload from a file and download to one without holding
either in memory. Decompression is incremental, so the size limit bounds a decompression bomb rather
than discovering one.

**Onion services that do not stand out.** A hosted service answers only `BEGIN` streams on the
virtual ports it publishes — behaving differently is itself a fingerprint.

## Security at a glance

The [Security](https://hupe1980.github.io/hypertor/docs/security/) page explains the threat model and
its limits. In brief, the design protects against:

| | |
|---|---|
| DNS leaking your destinations | Hostnames are always resolved by the exit relay, never locally |
| A client falling back to system DNS | The SOCKS proxy speaks Tor's `RESOLVE` / `RESOLVE_PTR` |
| Credentials replayed to another host | Stripped on any cross-origin redirect |
| A `.onion` redirecting you to clearnet | Refused unless explicitly allowed |
| TLS tickets relinking isolated circuits | One session store per isolation group |
| Recorded traffic decrypted later | `X25519MLKEM768` post-quantum key exchange |
| Hostnames leaking into your logs | Scrubbed from `Error` output by default |
| Decompression bombs | Decoded incrementally and abandoned at the limit |
| Clock-skew correlation of a service | No `Date`, `Server` or `X-Powered-By` header |
| Matching a service to its clearnet host | `ETag` is keyed per process; no `Last-Modified` |
| Path traversal in static files | Paths are canonicalised and confined to the root |
| Slowloris against your service | Header read deadline and a connection cap |
| Guard discovery | `VanguardMode`, wired to arti |

**What no library can protect against.** hypertor is not an anonymity system in its own right. Tor
protects the network path. It cannot protect you from an application that logs in with your real
identity, from timing patterns in your own traffic, or from a compromised machine. Read the
[Tor Project's guidance](https://support.torproject.org/) before relying on this for anything that
matters.

## Development

```bash
just check              # fmt, clippy, tests
just check-all          # everything CI runs

cargo test --features full                # offline
cargo test --features full -- --ignored   # needs a live Tor connection
cargo bench

cd bindings/python
uv sync --all-extras
maturin develop
uv run pytest
```

The HTTP framework is tested end to end over an in-memory pipe — a real hyper client against a real
`OnionApp` — so routing, framing, keep-alive, HTTP/2 and the body limits are covered on every commit
rather than only when someone runs the live tests.

### Repository layout

```
Cargo.toml        the published crate, and the workspace root
src/              the library
examples/  tests/  benches/
bindings/python/  the Python bindings — Rust crate, Python package, tests,
                  examples and pyproject.toml, all in one place
site/             the documentation site (Zola)
```

The bindings are a **separate, unpublished crate** that uses hypertor through its public API. That
keeps pyo3 out of every Rust user's dependency graph, and means anything the bindings cannot reach is
a gap in the Rust API rather than something to paper over.

## Disclaimer

Provided for research and educational use. No anonymity guarantee: your operational security, threat
model and usage patterns matter more than any library. Not affiliated with, endorsed by, or
sponsored by the Tor Project. You are responsible for complying with the law where you are.

## License

MIT. See [LICENSE](LICENSE).
