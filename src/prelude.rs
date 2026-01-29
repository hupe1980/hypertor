//! Convenient re-exports for common hypertor usage.
//!
//! This module provides a prelude that re-exports the most commonly used
//! types and traits for both client and server usage.
//!
//! # Example
//!
//! ```rust,ignore
//! use hypertor::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Client usage
//!     let client = TorClient::new().await?;
//!     let resp = client.get("http://example.onion")?.send().await?;
//!     println!("{}", resp.text()?);
//!
//!     // Server usage
//!     let app = OnionApp::new()
//!         .security(SecurityConfig::enhanced())
//!         .route("/", get(|| async { "Hello!" }));
//!
//!     Ok(())
//! }
//! ```

// Core types
pub use crate::body::Body;
pub use crate::client::{TorClient, TorClientBuilder};
pub use crate::config::{Config, ConfigBuilder};
pub use crate::error::{Error, Result};
pub use crate::request::RequestBuilder;
pub use crate::response::Response;

// Server framework
pub use crate::serve::{
    AppStats, Handler, Json, MethodHandler, OnionApp, OnionAppConfig, Request as ServeRequest,
    Response as ServeResponse, delete, get, head, options, patch, post, put,
};

// Security (presets that wire to real arti APIs)
pub use crate::security::{ClientSecurityConfig, SecurityLevel, ServiceSecurityConfig};

// Session & Cookies
pub use crate::cookies::{Cookie, CookieJar};
pub use crate::session::Session;

// Resilience
pub use crate::retry::RetryConfig;
pub use crate::timeout::Timeouts;

// Isolation
pub use crate::isolation::{IsolationLevel, IsolationToken};

// Compression
pub use crate::compression::Compression;

// Middleware
pub use crate::middleware::MiddlewareStack;

// Metrics
pub use crate::health::{HealthCheck, HealthStatus};
pub use crate::metrics::HttpMetrics;

// SOCKS5 Proxy
pub use crate::proxy::{ProxyConfig, Socks5Proxy};

// WebSocket
pub use crate::websocket::{
    CloseCode,
    Frame,
    Message as WsMessage,
    // REAL WebSocket over Tor
    TorWebSocket,
    TorWebSocketBuilder,
    WebSocketClient,
    WebSocketConfig,
    WebSocketState,
};

// Prometheus Metrics (Production Observability)
pub use crate::prometheus::{
    MetricsRegistry, PrometheusCounter, PrometheusGauge, PrometheusHistogram, TorMetrics,
    export_metrics, global_metrics,
};

// DNS-over-HTTPS (Privacy DNS)
pub use crate::doh::{DohConfig, DohProvider, DohResolver, RecordType};

// HTTP/2 Protocol
pub use crate::http2::{Hpack, Http2Config, Http2Connection};

// Onion Service Hosting (Real Tor Integration)
pub use crate::onion_service::{
    ClientAuthKey as HsClientKey,
    ClientAuthMode,
    OnionService as HiddenService,
    OnionServiceConfig as HsConfig,
    SecretKey, // Secure key wrapper with zeroize
    ServiceState as HsState,
    ServiceStats as HsStats,
};

// Tracing
pub use crate::tracing::{Span, SpanId, TraceContext, TraceId, Tracer};

// Duration for timeouts
pub use std::time::Duration;
