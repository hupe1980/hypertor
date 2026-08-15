# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) — with the
usual 0.x caveat that a minor bump may break.

## [Unreleased]

## [0.4.0]

A deliberate hard cut from 0.2.2. 0.4 rebuilds the client on hyper's pooling
stack, moves to arti 0.45, and deletes roughly thirty modules that reimplemented
— usually less well — things hyper and arti already do. **There is no migration
shim**; the changes below are the migration guide.

The version skips 0.3 because the surface has almost nothing in common with
0.2.2, and a neighbouring number would have implied otherwise.

### Security

- **Stacked `Content-Encoding` spread over several header lines is no longer
  half-decoded.** RFC 9110 §5.2 makes repeated field lines equivalent to one
  comma-joined line, and `HeaderMap` keeps them apart rather than joining them,
  so `Content-Encoding: gzip` followed by `Content-Encoding: br` was read as
  plain `gzip`: the body was gunzipped and returned still Brotli-compressed.
  `Encoding::from_headers` now reads every line of the field, which is the case
  its stacked-encoding refusal was always meant to cover. `If-None-Match` in the
  static file handler is read the same way.
- **TLS session resumption is partitioned by isolation group.** Sharing one
  rustls session store across groups let a server link two requests that were
  deliberately placed on different circuits, by handing the second a ticket the
  first was issued. Each group now gets its own store, and
  `IsolationLevel::PerRequest` disables resumption outright.
- **The crypto provider is `aws-lc-rs`, not `ring`.** hypertor forced `ring`
  while arti pulled in `aws-lc-rs` for Tor link TLS, so a default build carried
  both — which is what made rustls unable to infer a provider, and what the
  explicit install existed to paper over. `ring` also implements no
  post-quantum group; the default now leads with the `X25519MLKEM768` hybrid,
  which matters for an audience a "harvest now, decrypt later" adversary is
  interested in by definition.
- **Onion services answer only `BEGIN`, and only on published virtual ports.**
  Anything else is refused with `END DONE`. arti's own documentation warns that
  an implementation behaving otherwise "will be distinguishable".
- **Static file `ETag`s are keyed per process.** The usual `mtime-size`
  validator is reproducible by anyone holding a copy of the file and embeds a
  timestamp — OnionScan found `ETag` among the headers most useful for matching
  a hidden service to the clearnet host serving the same files. No
  `Last-Modified`, `Server` or `X-Powered-By` is sent at all.
- **No `Date` header by default** (`OnionApp::date_header(true)` restores it).
  A timestamp on every response is the oracle Murdoch's clock-skew attack
  (CCS 2006) reads.
- **Redirect targets are `remove_dot_segments`-normalised** per RFC 3986 §5.2.4
  before use, so hypertor and the server cannot disagree about which resource
  was requested.
- **The SOCKS proxy refuses IP literals by default** (a client that resolved the
  name itself already leaked a DNS query), refuses non-loopback binds by
  default, and implements Tor's `RESOLVE` / `RESOLVE_PTR` extensions so a client
  need not fall back to the system resolver.
- Hostnames in `Error` are wrapped in `safelog::Sensitive` and render as
  `[scrubbed]`. `Error::host()` returns the real value when you need it.

### Added

- `Body::from_file`, `Body::from_stream`, `Body::sized_stream` — request bodies
  that stream instead of buffering. `Body::is_replayable()` reports whether a
  body can survive a retry or a `307`.
- `RequestBuilder::send_streaming` and `Streaming`, for downloads that never
  have to fit in memory. The size limit applies to the decoded body in both
  APIs, so this is not a way around it.
- `OnionApp`: path parameters (`/users/{id}`), `405` with a correct `Allow`
  header, streamed static files with traversal confinement, `max_connections`,
  `header_timeout`, `max_body_size`, and graceful shutdown.
- `OnionApp::serve_connection`, which serves one already-accepted stream — an
  `OnionApp` is now testable over an in-memory pipe, and usable over any
  transport.
- `TorWebSocket::split`, giving an independent `Sender` and `Receiver` for
  protocols that must read and write at once.
- `TorClientBuilder::lazy_bootstrap` and `TorClient::bootstrap`, to decide when
  the bootstrap cost is paid and where its failure is handled.
- `TorClient::from_arti`, to share one bootstrapped arti instance — one
  directory cache, one guard set — between a client and an onion service.
- Bridges and pluggable transports: `TorClientBuilder::bridge` / `transport`. A
  bridge line naming a transport with no binary registered is now rejected at
  build time instead of hanging until timeout.
- `TorClientBuilder::tls_session_resumption`, which was reachable only through
  `Config` despite being documented on the builder path.

### Changed

- **Breaking: the client is built on `hyper_util`'s pooling client.** A warm
  circuit is reused across requests rather than rebuilt per request, and HTTP/2
  is negotiated by ALPN and multiplexed onto one connection.
- **Breaking: `IsolationLevel::PerHost` is the default.** Requests to different
  hosts no longer share a circuit unless you ask for that with
  `IsolationLevel::None`.
- **Breaking: `Error` is a `#[non_exhaustive]` typed enum** with `is_retryable`,
  `is_tor`, `is_timeout`, `status` and `host` accessors.
- **Breaking: the Python bindings are a separate, unpublished crate** in
  `bindings/python`. There is no longer a `python` Cargo feature, so a Rust
  dependency on hypertor never pulls in pyo3, and no `cdylib` artifact is built
  for consumers who cannot use one.
- **Breaking: minimum Rust is 1.91** (was 1.86), which is what arti 0.45
  requires.
- **A missing TLS backend is now a `compile_error!` naming the cause and the
  fix.** `--no-default-features --features server` previously failed a crate
  away with `unresolved import tor_rtcompat::PreferredRuntime`. One of `rustls`
  or `native-tls` is mandatory for `client` and `server` alike, because Tor's
  link protocol is itself TLS.
- Default timeout is 60 s, above the 30 s connect timeout nested inside it. The
  previous 30 s request timeout always fired first, which made the connect
  timeout dead code that reported the wrong operation.
- `HEAD` responses are no longer judged by the size they describe. RFC 9110
  §9.3.2 headers describe the body a `GET` would return, so reading them as real
  bytes made `client.head(url)` fail on any resource above the size limit while
  transferring nothing.
- Retry documentation no longer claims a retry means a fresh circuit. It means a
  new connection; only `IsolationLevel::PerRequest` guarantees a different path.
- `native-tls` returns an error for `min_tls_version(Tls13)` rather than
  silently giving you TLS 1.2.
- Documentation moved to a Zola site under `site/`.

### Removed

- **Breaking: the cookie jar (`cookies`), deliberately and permanently.** A jar
  shared across requests would relink the activities circuit isolation exists to
  separate — the network layer would hold while the application layer gave the
  correlation away for free. Set `Cookie` yourself and its scope is yours to
  choose; hypertor strips it on any cross-origin redirect.
- **Breaking: the hand-rolled HTTP machinery**, replaced by hyper and
  `hyper-util`: `pool`, `keepalive`, `http2`, `compression`, `streaming`,
  `timeout` and `retry`. These were competent reimplementations of what the
  stack `reqwest` is built on already does, and a second implementation of
  connection reuse, HPACK and flow control is a liability in a library whose
  users cannot afford a framing bug.
- **Breaking: `dns` and `doh`.** `doh` resolved names through DNS-over-HTTPS
  providers (Cloudflare, Google, Quad9) when the exit relay is what should be
  doing the lookup. Names are now always handed to arti and resolved by the
  exit; there is no local resolution path left to misconfigure.
- **Breaking: the ambient-infrastructure modules**, which belonged in the
  application rather than in a Tor library: `adaptive`, `backpressure`, `batch`,
  `breaker`, `cache`, `dedup`, `health`, `hooks`, `metrics`, `middleware`,
  `observability`, `prewarm`, `prometheus`, `queue`, `ratelimit`, `rotation`,
  `session` and `tracing`. A `prometheus` exporter in a privacy library is a
  side channel with a scrape endpoint.
- **Breaking: the `intercept` feature and module.** A TLS-intercepting proxy is
  not something a Tor client should make easy.
- **Breaking: the `padding` and `http2` features**, which gated nothing that
  worked; HTTP/2 is now always available and negotiated by ALPN.
- **Breaking: the `python` feature** (see above).
- **Breaking: `security.rs` and `circuit.rs`**, whose contents are now either
  arti's job or folded into `isolation`, `redirect` and `tls` where they are
  actually reachable and tested.

[Unreleased]: https://github.com/hupe1980/hypertor/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/hupe1980/hypertor/compare/v0.2.2...v0.4.0
