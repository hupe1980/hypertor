//! The common imports, in one line.
//!
//! ```rust,no_run
//! use hypertor::prelude::*;
//!
//! # async fn demo() -> Result<()> {
//! let client = TorClient::new().await?;
//! let body = client.get("http://example.onion")?.send().await?.text()?;
//! # Ok(())
//! # }
//! ```

pub use crate::VanguardMode;
pub use crate::config::{Config, TlsVersion};
pub use crate::error::{Error, Result};
pub use crate::isolation::{IsolatedSession, IsolationLevel, IsolationToken};
pub use crate::redirect::RedirectPolicy;

#[cfg(feature = "client")]
pub use crate::client::{TorClient, TorClientBuilder};
#[cfg(feature = "client")]
pub use crate::request::RequestBuilder;
#[cfg(feature = "client")]
pub use crate::response::Response;

#[cfg(feature = "server")]
pub use crate::onion_service::{OnionService, OnionServiceBuilder};
#[cfg(feature = "server")]
pub use crate::serve::{OnionApp, Request as ServeRequest, Response as ServeResponse};

#[cfg(feature = "socks")]
pub use crate::socks::{SocksConfig, SocksProxy};
#[cfg(feature = "ws")]
pub use crate::websocket::{Message as WsMessage, TorWebSocket};
