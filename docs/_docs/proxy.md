---
title: "SOCKS5 Proxy"
permalink: /docs/proxy/
toc: true
---

A local SOCKS5 proxy that routes any SOCKS-capable program through Tor. Requires the `socks`
feature:

```toml
hypertor = { version = "0.3", features = ["socks"] }
```

## Running one

```rust
use hypertor::{SocksConfig, SocksProxy, TorClient};

#[tokio::main]
async fn main() -> hypertor::Result<()> {
    let client = TorClient::new().await?;
    SocksProxy::from_client(&client, SocksConfig::default()).run().await
}
```

Listens on `127.0.0.1:9050` by default — the same port the C Tor daemon uses, so existing
configurations work unchanged.

```bash
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
git -c http.proxy=socks5h://127.0.0.1:9050 clone https://example.com/repo.git
```

## Use `socks5h`, not `socks5`

This is the single most important thing on this page.

`socks5://` makes the **client** resolve the hostname before connecting, using your system resolver.
That sends a plaintext DNS query from your real IP address for every site you visit. Your traffic is
tunnelled, but your browsing history is not — which defeats the point entirely.

`socks5h://` (curl's `--socks5-hostname`) sends the *hostname* to the proxy and lets Tor resolve it
at the exit relay.

| Tool | Correct | Wrong |
|---|---|---|
| curl | `--socks5-hostname` or `-x socks5h://` | `--socks5`, `-x socks5://` |
| git | `socks5h://` | `socks5://` |
| Python `requests` | `socks5h://` | `socks5://` |
| Firefox | tick "Proxy DNS when using SOCKS v5" | leaving it unticked |

hypertor's proxy **rejects requests carrying a bare IP address** by default, precisely so a
misconfigured client fails loudly instead of leaking quietly. If you genuinely mean to connect to a
literal address:

```rust
SocksConfig {
    allow_ip_literals: true,
    ..Default::default()
}
```

## Circuit isolation by credentials

Following Tor's `IsolateSOCKSAuth` convention, connections presenting different SOCKS
username/password pairs are placed on different circuits:

```bash
curl -x socks5h://alice:x@127.0.0.1:9050 https://example.com   # circuit A
curl -x socks5h://alice:x@127.0.0.1:9050 https://example.com   # circuit A again
curl -x socks5h://bob:x@127.0.0.1:9050   https://example.com   # circuit B
```

The credentials are an isolation label, not a secret — any value is accepted, and none is verified.
The proxy is loopback-only, so there is nothing to guard against.

Disable it if you want every connection to share circuits freely:

```rust
SocksConfig {
    isolate_socks_auth: false,
    ..Default::default()
}
```

## Configuration

```rust
use std::net::SocketAddr;
use hypertor::SocksConfig;

SocksConfig {
    bind_addr: "127.0.0.1:9150".parse::<SocketAddr>().unwrap(),
    max_connections: 512,
    isolate_socks_auth: true,
    allow_ip_literals: false,
    allow_non_loopback_bind: false,
    ..Default::default()
};
```

### Do not expose it to the network

Binding anywhere other than loopback creates an **open proxy**: anyone who can reach the port can
route traffic through your Tor connection, and it will be attributed to you. hypertor refuses such a
bind unless you explicitly set `allow_non_loopback_bind`.

If you need to serve other machines, put it behind an SSH tunnel or a VPN rather than exposing it.

## Limitations

Only the `CONNECT` command is supported. `BIND` and `UDP ASSOCIATE` are not implemented, because
neither has a meaningful interpretation over Tor: Tor carries TCP streams, and cannot accept inbound
connections to a client or forward UDP datagrams.
