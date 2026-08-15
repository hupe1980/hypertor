+++
title = "Installation"
description = "Install hypertor for Rust or Python: feature flags, TLS backends, platform notes and building from source."
weight = 1
+++

## Rust

```bash
cargo add hypertor
cargo add tokio --features full
```

Minimum supported Rust version: **1.91**, which is what arti 0.45 requires. hypertor cannot build on anything older, so it declares that floor rather than a friendlier-looking one that would fail deep inside a dependency.

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
| `static-sqlite` | | link SQLite statically (useful on Windows) |

There is no `python` feature; see [Building from source](#building-from-source) below.

```bash
# Client and onion service hosting
cargo add hypertor --features server

# Everything
cargo add hypertor --features full
```

### Choosing a TLS backend

`rustls` is the default and the right choice for almost everyone. See
[Security](@/docs/security.md#tls-fingerprinting) for why.

**Exactly one TLS backend is required**, and not because of `https://` — Tor's own link protocol is
TLS, so even a `server`-only build that never makes an outbound request needs one. If you turn
default features off, remember to put one back:

```bash
# Wrong: fails to compile.
cargo add hypertor --no-default-features --features server

# Right.
cargo add hypertor --no-default-features --features server,rustls
```

hypertor says so directly at compile time. It used to fail a crate away with `unresolved import
tor_rtcompat::PreferredRuntime`, which names neither the cause nor the fix.

The crypto provider is **aws-lc-rs**, which is rustls's own default, the provider arti uses for Tor
link TLS, and the only one of the two that offers post-quantum key exchange — its defaults lead with
the `X25519MLKEM768` hybrid. hypertor installs it explicitly at startup: rustls can only infer a
provider when exactly one is compiled in and panics otherwise, and an application that pulls
rustls's `ring` feature in from elsewhere would otherwise take that panic in its own build.

If you must use the operating system's TLS stack:

```bash
cargo add hypertor --no-default-features --features client,native-tls
```

Note that `native-tls` cannot enforce a TLS 1.3 floor and cannot negotiate ALPN, so
`min_tls_version(Tls13)` returns an error there rather than silently downgrading, and HTTP/2 over
TLS is unavailable.

### Proof of work and licensing

`pow` enables the Equi-X proof-of-work defence for onion services. It is **not** included in `full`,
because the implementation (`equix`, `hashx`) is **LGPL-3.0-only** while hypertor itself is MIT.
A default build — client or server — contains no copyleft code.

```bash
cargo add hypertor --features server,pow
```

Calling `.proof_of_work(true)` without the feature is an error at launch, rather than a service that
silently runs unprotected.

## Python

```bash
pip install hypertor
```

Requires Python **3.10 or later**. Wheels ship for Linux and macOS on x86-64 and arm64, and for
Windows on x86-64; no Rust toolchain is needed to install one.

They are built against CPython's stable ABI (`abi3`), so a single wheel per platform serves every
interpreter from 3.10 up — the same file installs on 3.10 and on 3.13. SQLite is linked statically
into it, so arti's state store does not depend on whatever `libsqlite3` the target system has, or
lacks.

On a platform with no wheel, `pip` falls back to the source distribution and compiles arti, which
needs a Rust toolchain and takes a while.

### Building from source

```bash
git clone https://github.com/hupe1980/hypertor
cd hypertor/bindings/python

uv sync --all-extras          # or: pip install maturin pytest
maturin develop
```

Everything for the bindings lives in `bindings/python`: the Rust crate, the Python package, its
tests, its examples and its `pyproject.toml`.

That crate is **not published to crates.io**. It depends on `hypertor` through the same public API
any other consumer uses, so a Rust dependency on `hypertor` never pulls in pyo3, and there is no
`python` feature to enable. `maturin` turns on `pyo3/extension-module`, which leaves CPython's
symbols for the loading interpreter to supply; the crate does not enable it itself, so a plain
`cargo build` in the workspace links against libpython and works — which is what makes the bindings
unit-testable at all.

## No Tor daemon needed

hypertor uses arti, a pure-Rust Tor implementation, so it speaks the Tor protocol itself. You do not
need the C `tor` daemon, Tor Browser, or `torsocks` installed.

## Platform notes

**Windows.** arti needs SQLite for its state store. If your system provides none, enable
`static-sqlite`:

```bash
cargo add hypertor --features static-sqlite
```

**Pluggable transports.** Bridges using `obfs4`, `snowflake` or `webtunnel` need the corresponding
transport binary installed separately — hypertor launches it, it does not bundle it. On Debian and
Ubuntu, `apt install obfs4proxy` provides `lyrebird`.

## Verifying it works

```bash
cargo run --example client
```

Should print a JSON object with `"IsTor": true`.
