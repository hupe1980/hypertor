//! # hypertor — Best-in-Class Tor Network Library
//!
//! The Tor network library for Rust — consume AND host onion services
//! with the simplicity of `reqwest` and `axum`.
//!
//! ## Quick Start
//!
//! ### Client (like reqwest)
//!
//! ```rust,no_run
//! use hypertor::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     let client = TorClient::new().await?;
//!     let resp = client.get("http://example.onion")?.send().await?;
//!     println!("{}", resp.text()?);
//!     Ok(())
//! }
//! ```
//!
//! ### Server (like axum)
//!
//! ```rust,ignore
//! use hypertor::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     let app = OnionApp::builder()
//!         .route("/", get(|_req| async { "Hello from .onion!" }))
//!         .build();
//!     app.run().await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Features
//!
//! - **TorClient**: HTTP client over Tor with connection pooling, retries, compression
//! - **OnionApp**: FastAPI/axum-style onion service framework
//! - **Security**: PoW DoS protection, client auth, website fingerprinting defense
//! - **Performance**: HTTP/2 multiplexing, circuit prewarming, request batching
//! - **Privacy**: Stream isolation, vanguards, traffic padding
//! - **Python**: Full sync and async bindings via PyO3

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![warn(missing_docs, rust_2018_idioms)]

// Require at least one TLS backend - Tor cannot function without TLS
#[cfg(not(any(feature = "native-tls", feature = "rustls")))]
compile_error!(
    "hypertor requires a TLS backend. Enable either 'rustls' (recommended) or 'native-tls' feature."
);

// ============================================================================
// Core Modules
// ============================================================================

pub mod body;
pub mod client;
pub mod config;
pub mod error;
pub mod prelude;
pub mod request;
pub mod response;
pub mod serve;
pub mod stream;

// ============================================================================
// Networking
// ============================================================================

pub mod circuit;
pub mod dns;
pub mod doh;
pub mod isolation;
pub mod pool;
pub mod proxy;
pub mod tls;

// ============================================================================
// Resilience
// ============================================================================

pub mod adaptive;
pub mod backpressure;
pub mod breaker;
pub mod retry;
pub mod rotation;

// ============================================================================
// Performance
// ============================================================================

pub mod batch;
pub mod cache;
pub mod dedup;
pub mod keepalive;
pub mod prewarm;
pub mod queue;
pub mod ratelimit;

// ============================================================================
// Privacy & Security
// ============================================================================

pub mod onion_service;
pub mod security;

// ============================================================================
// Protocol Support
// ============================================================================

pub mod http2;
pub mod websocket;

// ============================================================================
// Observability
// ============================================================================

pub mod health;
pub mod hooks;
pub mod metrics;
pub mod observability;
pub mod prometheus;
pub mod tracing;

// ============================================================================
// HTTP Features
// ============================================================================

pub mod compression;
pub mod cookies;
pub mod middleware;
pub mod redirect;
pub mod session;
pub mod streaming;
pub mod timeout;

// ============================================================================
// Integration
// ============================================================================

pub mod intercept;

// ============================================================================
// Python Bindings
// ============================================================================

#[cfg(feature = "python")]
pub mod python;

// ============================================================================
// Re-exports — Core
// ============================================================================

pub use body::Body;
pub use client::{TorClient, TorClientBuilder};
pub use config::{Config, ConfigBuilder};
pub use error::{Error, Result};
pub use request::RequestBuilder;
pub use response::Response;
pub use serve::{
    AppStats, Handler, Json, MethodHandler, OnionApp, OnionAppConfig, Request as ServeRequest,
    Response as ServeResponse, delete, get, head, options, patch, post, put,
};

// ============================================================================
// Re-exports — Networking
// ============================================================================

pub use circuit::{CircuitConfig, CircuitManager, CircuitStats};
pub use dns::{DnsCache, DnsResult, TorDnsResolver};
pub use doh::{
    DnsRecord, DnsResponse, DohConfig, DohError, DohFormat, DohProvider, DohResolver, DohStats,
    MultiDohResolver, RecordData, RecordType,
};
pub use isolation::{IsolatedSession, IsolationLevel, IsolationToken};
pub use pool::{ConnectionPool, PoolConfig};
pub use proxy::{ProxyConfig, ShutdownHandle, Socks5Proxy};

// ============================================================================
// Re-exports — Resilience
// ============================================================================

pub use adaptive::{
    AdaptiveRetry, AdaptiveRetryConfig, AdaptiveRetryManager, AdaptiveRetryStats, AttemptOutcome,
    RetryDecision,
};
pub use backpressure::{
    BackpressureConfig, BackpressureController, BackpressureError, BackpressurePermit,
    BackpressureStats, LoadShedder,
};
pub use breaker::{BreakerConfig, BreakerManager, BreakerResult, BreakerState, CircuitBreaker};
pub use retry::RetryConfig;
pub use rotation::{CircuitHealth, CircuitRotator, RotationConfig, RotationStats};

// ============================================================================
// Re-exports — Performance
// ============================================================================

pub use batch::{Batch, BatchConfig, BatchItem, BatchProcessor, Batcher, BatcherStats};
pub use cache::{CacheConfig, CacheControl, CachedResponse, HttpCache};
pub use dedup::{DedupConfig, Deduplicator, RequestKey, SharedResult};
pub use keepalive::{ConnectionState, KeepAliveConfig, KeepAliveHints};
pub use prewarm::{CircuitPrewarmer, PrewarmConfig};
pub use queue::{Priority, PriorityQueue, QueueConfig, QueueStatistics};
pub use ratelimit::{RateLimitConfig, RateLimitResult, RateLimiter, TokenBucket};

// ============================================================================
// Re-exports — Privacy & Security
// ============================================================================

pub use security::{
    ClientSecurityConfig,
    // Security Presets (wire to real arti APIs)
    SecurityLevel,
    ServiceSecurityConfig,
};
// Re-export VanguardMode from arti for user convenience
// This is the REAL vanguard API - wired to TorClientConfigBuilder::vanguards().mode()
pub use tor_guardmgr::VanguardMode;
// onion_service provides real arti-based onion service hosting
pub use onion_service::{
    ClientAuthKey as HsClientKey,
    ClientAuthMode,
    // Client authorization key for restricted discovery
    HsClientDescEncKey,
    OnionService as HiddenService,
    OnionServiceConfig as HsConfig,
    OnionServiceWithEvents as HiddenServiceWithEvents,
    OnionStream as HsStream,
    RateLimit,
    ServiceEvent as HsEvent,
    ServiceState as HsState,
    ServiceStats as HsStats,
};

// ============================================================================
// Re-exports — Protocol Support
// ============================================================================

pub use http2::{
    ConnectionState as Http2ConnectionState, ErrorCode as Http2ErrorCode, Frame as Http2Frame,
    FrameFlags, FrameHeader, FrameType, Hpack, Http2Config, Http2Connection, Http2Error,
    Http2Stats, SettingId, Settings as Http2Settings, Stream as Http2Stream, StreamEvent,
    StreamState as Http2StreamState,
};

pub use websocket::{
    CloseCode,
    CloseFrame,
    EchoHandler,
    Frame,
    Message as WsMessage,
    Opcode,
    // REAL WebSocket over Tor
    TorWebSocket,
    TorWebSocketBuilder,
    UpgradeRequest,
    UpgradeResponse,
    WebSocketClient,
    WebSocketConfig,
    WebSocketConnection,
    WebSocketError,
    WebSocketHandler,
    WebSocketServer,
    WebSocketState,
    WebSocketStats,
    generate_accept_key,
    generate_client_key,
};

// ============================================================================
// Re-exports — Observability
// ============================================================================

pub use health::{HealthCheck, HealthCheckConfig, HealthStatus, Metrics};
pub use hooks::{ErrorHook, Hooks, PostResponseHook, PreRequestHook};
pub use metrics::{Counter, Gauge, Histogram, HttpMetrics, MetricsReport};
pub use prometheus::{
    HistogramTimer, MetricsRegistry, PrometheusCounter, PrometheusGauge, PrometheusHistogram,
    PrometheusSummary, TorMetrics, default_latency_buckets, export_metrics, global_metrics, labels,
    size_buckets, tor_latency_buckets,
};
pub use tracing::{Span, SpanId, SpanKind, SpanStatus, TraceContext, TraceId, Tracer};

// ============================================================================
// Re-exports — HTTP Features
// ============================================================================

pub use compression::Compression;
pub use cookies::{Cookie, CookieJar};
pub use middleware::{HeaderMiddleware, LoggingMiddleware, MiddlewareStack, RateLimitMiddleware};
pub use redirect::{RedirectAction, RedirectGuard, RedirectPolicy};
pub use session::Session;
pub use streaming::{StreamingBody, StreamingResponseBuilder};
pub use timeout::Timeouts;

// ============================================================================
// Re-exports — Integration
// ============================================================================

pub use intercept::{
    FnRequestInterceptor, FnResponseInterceptor, HttpExchange, HttpHistory, InterceptConfig,
    InterceptId, InterceptProxy, InterceptedRequest, InterceptedResponse, ModifiedRequest,
    ModifiedResponse, RequestAction, RequestInterceptor, ResponseAction, ResponseInterceptor,
};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
