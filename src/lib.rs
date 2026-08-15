//! Tor for Rust: make HTTP requests over the Tor network, and host onion
//! services.
//!
//! hypertor is a thin, honest layer over two mature pieces of software:
//! [arti](https://gitlab.torproject.org/tpo/core/arti), the Tor Project's Rust
//! implementation of Tor, and [hyper](https://hyper.rs), the HTTP stack
//! `reqwest` is built on. It supplies the seam between them and the ergonomics
//! on top; it implements no Tor protocol and no HTTP protocol of its own.
//!
//! # Making requests
//!
//! ```rust,no_run
//! use hypertor::TorClient;
//!
//! #[tokio::main]
//! async fn main() -> hypertor::Result<()> {
//!     let client = TorClient::new().await?;
//!
//!     let body = client
//!         .get("https://check.torproject.org/api/ip")?
//!         .send()
//!         .await?
//!         .error_for_status()?
//!         .text()?;
//!
//!     println!("{body}");
//!     Ok(())
//! }
//! ```
//!
//! `.onion` addresses work the same way, and never touch an exit relay:
//!
//! ```rust,no_run
//! # async fn demo(client: &hypertor::TorClient) -> hypertor::Result<()> {
//! let response = client.get("http://example.onion/api")?.send().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Hosting an onion service
//!
//! ```rust,no_run
//! # #[cfg(feature = "server")]
//! # mod demo {
//! use hypertor::{OnionApp, ServeResponse};
//!
//! pub async fn run() -> hypertor::Result<()> {
//!     let app = OnionApp::new()
//!         .get("/", |_req| async { ServeResponse::text("hello") });
//!
//!     let service = app.serve("my-service").await?;
//!     println!("{}", service.onion_address());
//!     service.wait().await
//! }
//! # }
//! ```
//!
//! # What hypertor adds over wiring arti and hyper together yourself
//!
//! - **Connection pooling that actually pools.** The Tor connector plugs into
//!   hyper's pooling client, so a warm circuit is reused across requests rather
//!   than paying seconds of circuit setup every time.
//! - **Circuit isolation as a first-class concept.** [`IsolationLevel`] and
//!   [`IsolationToken`] let you decide explicitly which of your activities may
//!   be linked to one another.
//! - **Redirects that do not betray you.** Credentials are stripped across
//!   origins, and a redirect from a `.onion` out to clearnet is refused unless
//!   you opt in. See [`RedirectPolicy`].
//! - **No local DNS, ever.** Hostnames are resolved by the exit relay. A Tor
//!   integration that resolves names locally leaks every site you visit.
//! - **Bodies that stream in both directions.** [`Body::from_file`] uploads
//!   without buffering; [`send_streaming`](RequestBuilder::send_streaming)
//!   downloads without buffering. Decompression happens incrementally, so the
//!   size limit bounds a decompression bomb instead of discovering one.
//! - **Errors that do not leak.** Hostnames in [`Error`] are scrubbed when
//!   displayed, because error messages end up in logs.
//! - **Onion services that are not distinguishable.** A hosted service accepts
//!   only `BEGIN` streams for the virtual ports it publishes, which is what
//!   every other implementation does — behaving differently is itself a
//!   fingerprint.
//!
//! # What hypertor does not do
//!
//! It is not an anonymity system in its own right, and no library can be. Tor
//! protects the network path; it cannot protect you from an application that
//! logs in with your real identity, from timing patterns in your own traffic,
//! or from anything running on a compromised machine. Read the
//! [Tor Project's guidance](https://support.torproject.org/) before relying on
//! this for anything that matters.
//!
//! It also keeps **no cookie jar**, deliberately. A jar shared across requests
//! would relink activities that [`IsolationLevel`] exists to keep apart — the
//! separation would still hold at the network layer while the application layer
//! gave the correlation away for free. Set `Cookie` yourself, and its scope is
//! yours to choose.
//!
//! # Feature flags
//!
//! | Feature | Default | What it adds |
//! |---|---|---|
//! | `client` | yes | [`TorClient`] and the HTTP client stack |
//! | `rustls` | yes | TLS via rustls — one fingerprint on every platform |
//! | `native-tls` | no | TLS via the OS stack; leaks your platform, see [`tls`] |
//! | `server` | no | [`OnionService`] and [`OnionApp`] |
//! | `pow` | no | Equi-X proof-of-work; **pulls in LGPL-3.0 crates** |
//! | `socks` | no | [`SocksProxy`], a local SOCKS5 front-end |
//! | `ws` | no | [`TorWebSocket`] |
//! | `static-sqlite` | no | link SQLite statically; needed on Windows |
//!
//! `full` is `client + server + socks + ws + rustls`. It deliberately excludes
//! `pow`, so a default build stays entirely permissively licensed.
//!
//! There is no `python` feature. The bindings are a separate, unpublished crate
//! (`bindings/python` in the repository) that consumes this one through its
//! public API, so a Rust dependency on `hypertor` never pulls in pyo3.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

// A TLS backend is not optional for anything that opens or accepts a Tor
// connection, and not because of `https://` — Tor's *own* link protocol is TLS,
// so `tor_rtcompat::PreferredRuntime` only exists when `tor-rtcompat` has a
// backend. Without this guard the build fails a crate away with `unresolved
// import tor_rtcompat::PreferredRuntime`, which names neither the cause nor the
// fix, and does so identically for `client`, `server`, `socks` and `ws`.
#[cfg(all(
    any(feature = "client", feature = "server"),
    not(any(feature = "rustls", feature = "native-tls"))
))]
compile_error!(
    "hypertor needs a TLS backend. Enable `rustls` (recommended: one ClientHello \
     on every platform, and post-quantum key exchange) or `native-tls`. This is \
     required even for a server-only build that never makes an outbound HTTPS \
     request, because Tor's link protocol is itself TLS."
);

pub mod config;
pub mod error;
pub mod isolation;
pub mod prelude;
pub mod redirect;
pub mod stream;
pub mod tls;

#[cfg(feature = "client")]
pub mod body;
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "client")]
mod connector;
#[cfg(feature = "client")]
pub mod request;
#[cfg(feature = "client")]
pub mod response;

#[cfg(feature = "server")]
pub mod onion_service;
#[cfg(feature = "server")]
pub mod serve;

#[cfg(feature = "socks")]
pub mod socks;
#[cfg(feature = "ws")]
pub mod websocket;

// ---------------------------------------------------------------------------
// Re-exports
// ---------------------------------------------------------------------------

pub use config::{Config, ConfigBuilder, DEFAULT_USER_AGENT, TlsConfig, TlsVersion};
pub use error::{Error, Result};
pub use isolation::{IsolatedSession, IsolationLevel, IsolationToken};
pub use redirect::{RedirectAction, RedirectPolicy};
pub use stream::TorStream;

/// Vanguard mode, re-exported from arti.
///
/// Vanguards restrict which relays may occupy the middle positions of your
/// circuits, raising the cost of the guard-discovery attacks that long-lived
/// connections — onion services above all — are exposed to.
pub use tor_guardmgr::VanguardMode;

#[cfg(feature = "client")]
pub use body::{Body, Encoding};
#[cfg(feature = "client")]
pub use client::{TorClient, TorClientBuilder};
#[cfg(feature = "client")]
pub use request::RequestBuilder;
#[cfg(feature = "client")]
pub use response::{Response, Streaming};

#[cfg(feature = "server")]
pub use onion_service::{OnionService, OnionServiceBuilder, OnionServiceConfig, OnionStream};
#[cfg(feature = "server")]
pub use serve::{OnionApp, Request as ServeRequest, Response as ServeResponse, ServingApp};

#[cfg(feature = "socks")]
pub use socks::{SocksConfig, SocksProxy};
#[cfg(feature = "ws")]
pub use websocket::{
    Close as WsClose, Message as WsMessage, Receiver as WsReceiver, Sender as WsSender,
    TorWebSocket, TorWebSocketBuilder,
};

/// The version of this crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
