---
title: "Installation"
permalink: /docs/installation/
toc: true
---

## Rust

```toml
[dependencies]
hypertor = "0.3"
tokio = { version = "1", features = ["full"] }
```

Minimum supported Rust version: **1.86** (Rust 2024 edition).

### Feature flags

| Feature | Default | Adds |
|---|---|---|
| `client` | ✅ | `TorClient` and the HTTP client stack |
| `rustls` | ✅ | TLS via rustls — identical fingerprint on every platform |
| `native-tls` | | TLS via the operating system's stack |
| `server` | | `OnionService` and `OnionApp` |
| `pow` | | Equi-X proof of work (see the licensing note below) |
| `socks` | | `SocksProxy`, a local SOCKS5 front-end |
| `ws` | | `TorWebSocket` |
| `python` | | the PyO3 bindings |
| `static-sqlite` | | link SQLite statically (useful on Windows) |

```toml
# Client and onion service hosting
hypertor = { version = "0.3", features = ["server"] }

# Everything
hypertor = { version = "0.3", features = ["full"] }
```

### Choosing a TLS backend

`rustls` is the default and the right choice for almost everyone. See
[Security]({{ site.baseurl }}/docs/security/#tls-fingerprinting) for why.

If you must use the operating system's TLS stack:

```toml
hypertor = { version = "0.3", default-features = false, features = ["client", "native-tls"] }
```

Note that `native-tls` cannot enforce a TLS 1.3 floor and cannot negotiate ALPN, so
`min_tls_version(Tls13)` returns an error there rather than silently downgrading, and HTTP/2 over
TLS is unavailable.

### Proof of work and licensing

`pow` enables the Equi-X proof-of-work defence for onion services. It is **not** included in `full`,
because the implementation (`equix`, `hashx`) is **LGPL-3.0-only** while hypertor itself is MIT.
A default build — client or server — contains no copyleft code.

```toml
hypertor = { version = "0.3", features = ["server", "pow"] }
```

Calling `.proof_of_work(true)` without the feature is an error at launch, rather than a service that
silently runs unprotected.

## Python

```bash
pip install hypertor
```

Requires Python **3.10 or later**. Wheels ship for Linux, macOS and Windows on x86-64 and arm64; no
Rust toolchain is needed to install one.

### Building from source

```bash
git clone https://github.com/hupe1980/hypertor
cd hypertor

uv sync --all-extras          # or: pip install maturin pytest
maturin develop --features python
```

## No Tor daemon needed

hypertor uses arti, a pure-Rust Tor implementation, so it speaks the Tor protocol itself. You do not
need the C `tor` daemon, Tor Browser, or `torsocks` installed.

## Platform notes

**Windows.** arti needs SQLite for its state store. If your system provides none, enable
`static-sqlite`:

```toml
hypertor = { version = "0.3", features = ["static-sqlite"] }
```

**Pluggable transports.** Bridges using `obfs4`, `snowflake` or `webtunnel` need the corresponding
transport binary installed separately — hypertor launches it, it does not bundle it. On Debian and
Ubuntu, `apt install obfs4proxy` provides `lyrebird`.

## Verifying it works

```bash
cargo run --example client
```

Should print a JSON object with `"IsTor": true`.
