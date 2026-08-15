# Examples

```bash
cargo run --example client                        # HTTP requests over Tor
cargo run --example streaming                     # large downloads and uploads
cargo run --example isolation                     # separate circuits per persona
cargo run --example bridges                       # reaching Tor from a censored network
cargo run --example onion_service --features server
cargo run --example socks_proxy   --features socks
cargo run --example websocket     --features ws
```

Every example bootstraps Tor, which takes tens of seconds on a cold cache. Set
`RUST_LOG=hypertor=debug` to watch what it is doing.

| Example | Shows |
|---|---|
| [`client.rs`](client.rs) | Requests, JSON, connection reuse |
| [`streaming.rs`](streaming.rs) | Downloading and uploading without buffering |
| [`isolation.rs`](isolation.rs) | Keeping activities on separate circuits |
| [`bridges.rs`](bridges.rs) | Bridges and pluggable transports |
| [`onion_service.rs`](onion_service.rs) | Hosting a routed HTTP service, hardened |
| [`socks_proxy.rs`](socks_proxy.rs) | A local SOCKS5 front-end for other programs |
| [`websocket.rs`](websocket.rs) | WebSocket over Tor, split for concurrent send and receive |
