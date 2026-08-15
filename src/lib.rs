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
//! - **Errors that do not leak.** Hostnames in [`Error`] are scrubbed when
//!   displayed, because error messages end up in logs.
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
//! | `python` | no | the PyO3 bindings |

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod body;
pub mod config;
pub mod error;
pub mod isolation;
pub mod prelude;
pub mod redirect;
pub mod stream;
pub mod tls;

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

#[cfg(feature = "python")]
mod python;

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
pub use client::{TorClient, TorClientBuilder};
#[cfg(feature = "client")]
pub use request::RequestBuilder;
#[cfg(feature = "client")]
pub use response::Response;

#[cfg(feature = "server")]
pub use onion_service::{OnionService, OnionServiceBuilder, OnionServiceConfig, OnionStream};
#[cfg(feature = "server")]
pub use serve::{OnionApp, Request as ServeRequest, Response as ServeResponse, ServingApp};

#[cfg(feature = "socks")]
pub use socks::{SocksConfig, SocksProxy};
#[cfg(feature = "ws")]
pub use websocket::{Message as WsMessage, TorWebSocket};

/// The version of this crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
