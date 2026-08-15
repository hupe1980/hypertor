+++
title = "SOCKS5 proxy"
description = "Run a local SOCKS5 front-end so any program can reach the Tor network, without leaking DNS."
weight = 5
+++

A local SOCKS5 proxy that routes any SOCKS-capable program through Tor. Requires the `socks`
feature:

```bash
cargo add hypertor --features socks
```

## Running one

```rust
use hypertor::{SocksConfig, SocksProxy, TorClient};

#[tokio::main]
async fn main() -> hypertor::Result<()> {
    let client = TorClient::new().await?;

    // Binding is separate from serving, so the address is known before any
    // traffic is handled.
    let proxy = SocksProxy::from_client(&client, SocksConfig::default()).await?;
    println!("listening on {}", proxy.local_addr()?);

    proxy.serve().await
}
```

Set `bind_addr` to port 0 and read `local_addr()` back when you want the OS to choose — useful in
tests, and when you do not want to fight over 9050.

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

## Name lookups through the proxy

The proxy implements Tor's SOCKS extensions `RESOLVE` (`0xF0`) and `RESOLVE_PTR` (`0xF1`), so a
client that wants a name resolved can ask the proxy to do it at an exit relay instead of resolving
locally. `torsocks` and anything else that intercepts `getaddrinfo` relies on this; without it such
a client either fails outright or falls back to the system resolver, which is exactly the leak the
proxy exists to prevent.

The answer comes back in the reply's bound-address field, as Tor's `socks-extensions.txt` specifies
— there is no separate message type.

`CONNECT`, `RESOLVE` and `RESOLVE_PTR` are the whole supported set. `BIND` and `UDP ASSOCIATE` have
no meaning over Tor and are refused.

The DNS-leak guard applies to `CONNECT` alone: a `RESOLVE` carries a hostname by definition, and a
`RESOLVE_PTR` carries an address by definition. Both are the client doing the right thing.

## Credentials are not retained

SOCKS credentials select a circuit and authenticate nobody, so any pair is accepted. They are kept
as a keyed hash rather than stored: people reuse passwords, and a long-lived map of plaintext
credentials is a thing worth not having in a process image or a core dump.

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

Tor's non-standard `RESOLVE` and `RESOLVE_PTR` SOCKS extensions are not implemented either. Use
`TorClient::resolve`, which performs the lookup at an exit relay through the same client.
