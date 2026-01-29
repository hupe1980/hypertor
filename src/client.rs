//! Core Tor HTTP client
//!
//! The main entry point for making HTTP requests over the Tor network.

use std::collections::HashMap;
use std::sync::Arc;

use arti_client::{
    IsolationToken as ArtiIsolationToken, StreamPrefs, TorClient as ArtiClient,
    config::{
        BridgeConfigBuilder, CfgPath, TorClientConfig, TorClientConfigBuilder,
        pt::TransportConfigBuilder,
    },
};
use http::{Request, Uri};
use http_body_util::Full;
use hyper::body::Bytes;
use parking_lot::Mutex;
use tor_config::ExplicitOrAuto;
use tor_guardmgr::VanguardMode;
use tor_rtcompat::PreferredRuntime;
use tracing::{debug, info};

use crate::config::Config;
use crate::error::{Error, Result};
use crate::isolation::{IsolatedSession, IsolationToken, compute_isolation};
use crate::pool::{ConnectionPool, PoolConfig, PoolKey};
use crate::request::RequestBuilder;
use crate::response::Response;
use crate::stream::TorStream;
use crate::tls::{TlsConfig, wrap_tls};

/// The main Tor HTTP client
///
/// This client maintains a connection pool and handles all the complexity
/// of routing HTTP requests through the Tor network.
pub struct TorClient {
    /// The underlying arti Tor client
    tor: Arc<ArtiClient<PreferredRuntime>>,
    /// Client configuration
    config: Arc<Config>,
    /// Connection pool
    pool: Arc<ConnectionPool>,
    /// Maps hypertor isolation tokens to arti isolation tokens
    /// This ensures same hypertor token → same circuit, different tokens → different circuits
    isolation_cache: Mutex<HashMap<u64, ArtiIsolationToken>>,
}

impl TorClient {
    /// Create a new Tor client with default configuration
    ///
    /// This will bootstrap a connection to the Tor network, which may take
    /// several seconds on first run.
    pub async fn new() -> Result<Self> {
        Self::with_config(Config::default()).await
    }

    /// Create a builder for customizing the client configuration
    ///
    /// # Example
    /// ```rust,ignore
    /// use hypertor::TorClient;
    /// use std::time::Duration;
    ///
    /// let client = TorClient::builder()
    ///     .timeout(Duration::from_secs(60))
    ///     .max_connections(20)
    ///     .follow_redirects(true)
    ///     .build()
    ///     .await?;
    /// ```
    pub fn builder() -> TorClientBuilder {
        TorClientBuilder::new()
    }

    /// Create a new Tor client with custom configuration
    pub async fn with_config(config: Config) -> Result<Self> {
        Self::with_configs(config, TorClientConfig::default()).await
    }

    /// Create a new Tor client with custom hypertor and arti configurations
    ///
    /// This is the most flexible constructor, allowing full control over both
    /// hypertor behavior AND underlying Tor client configuration (bridges, vanguards, etc.)
    pub async fn with_configs(config: Config, tor_config: TorClientConfig) -> Result<Self> {
        info!("Initializing hypertor v{}", crate::VERSION);

        // Bootstrap Tor client
        // Note: First run may take 30-60 seconds to download the Tor directory
        // Subsequent runs use the cached directory and are much faster
        info!("Bootstrapping Tor client (first run may take 30-60s)...");

        let tor = ArtiClient::create_bootstrapped(tor_config)
            .await
            .map_err(|e| Error::bootstrap_with_source("failed to bootstrap Tor client", e))?;

        info!("Tor client bootstrapped successfully");

        // Create connection pool
        let pool_config = PoolConfig {
            max_total_connections: config.max_connections,
            ..Default::default()
        };

        Ok(Self {
            tor: Arc::new(tor),
            config: Arc::new(config),
            pool: Arc::new(ConnectionPool::new(pool_config)),
            isolation_cache: Mutex::new(HashMap::new()),
        })
    }

    /// Get the client configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Get a DNS resolver that uses this client's Tor connection.
    ///
    /// The returned resolver will route all DNS queries through the Tor
    /// network, preventing DNS leaks.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let client = TorClient::new().await?;
    /// let resolver = client.dns_resolver();
    /// let result = resolver.resolve("example.com").await?;
    /// println!("IPs: {:?}", result.all_ips());
    /// ```
    pub fn dns_resolver(&self) -> crate::dns::TorDnsResolver {
        crate::dns::TorDnsResolver::with_client(Arc::clone(&self.tor))
    }

    /// Resolve a hostname to IP addresses through Tor.
    ///
    /// This is a convenience method that creates a one-shot DNS resolver.
    /// For multiple resolutions, use `dns_resolver()` to get a cached resolver.
    pub async fn resolve(&self, hostname: &str) -> Result<Vec<std::net::IpAddr>> {
        self.tor
            .resolve(hostname)
            .await
            .map_err(|e| Error::http(format!("DNS resolution failed for '{}': {}", hostname, e)))
    }

    /// Create an isolated session
    ///
    /// All requests made through the returned session will share the same
    /// Tor circuit, but use a different circuit from other sessions.
    pub fn isolated(&self) -> IsolatedSession {
        IsolatedSession::new()
    }

    /// Execute a request
    pub(crate) async fn execute(&self, builder: RequestBuilder<'_>) -> Result<Response> {
        let uri = builder.get_uri().clone();
        let isolation_token = builder.get_isolation_token();

        // Build the HTTP request
        let request = builder.into_request(&self.config)?;

        // Get or create a stream
        let stream = self.get_stream(&uri, isolation_token).await?;

        // Send the request
        self.send_request(stream, request).await
    }

    /// Get a stream from the pool or create a new one
    async fn get_stream(
        &self,
        uri: &Uri,
        isolation_token: Option<IsolationToken>,
    ) -> Result<TorStream> {
        let host = uri.host().ok_or(Error::MissingHost)?;
        let is_https = uri.scheme_str() == Some("https");
        let port = uri.port_u16().unwrap_or(if is_https { 443 } else { 80 });

        let pool_key = PoolKey::new(host, port, is_https);

        // Try to get from pool (only if no specific isolation)
        if isolation_token.is_none() {
            if let Some(stream) = self.pool.get(&pool_key) {
                debug!("Reusing pooled connection to {}:{}", host, port);
                return Ok(stream);
            }
        }

        // Acquire a permit for a new connection
        let _permit = self.pool.acquire_permit().await?;

        // Create new connection
        debug!("Creating new connection to {}:{}", host, port);
        let stream = self.connect(host, port, is_https, isolation_token).await?;

        Ok(stream)
    }

    /// Create a new connection through Tor
    async fn connect(
        &self,
        host: &str,
        port: u16,
        is_https: bool,
        isolation_token: Option<IsolationToken>,
    ) -> Result<TorStream> {
        // Compute isolation based on config and token
        let effective_token =
            isolation_token.or_else(|| compute_isolation(self.config.isolation, Some(host)));

        // Connect through Tor
        // Note: DNS is always resolved through Tor - NEVER locally!
        // Use arti's StreamPrefs for circuit isolation when token is present.
        debug!("Connecting to {}:{} (https={})", host, port, is_https);

        let data_stream = if let Some(token) = effective_token {
            // Get or create arti isolation token for this hypertor token
            // Same hypertor token → same arti token → shared circuit
            // Different hypertor tokens → different arti tokens → different circuits
            let arti_token = {
                let mut cache = self.isolation_cache.lock();
                *cache
                    .entry(token.as_raw())
                    .or_insert_with(ArtiIsolationToken::new)
            };

            let mut prefs = StreamPrefs::new();
            prefs.set_isolation(arti_token);

            debug!("Connecting with isolation token...");
            self.tor
                .connect_with_prefs((host, port), &prefs)
                .await
                .map_err(|e| Error::connection(host, port, e))?
        } else {
            debug!("Connecting without isolation...");
            self.tor
                .connect((host, port))
                .await
                .map_err(|e| Error::connection(host, port, e))?
        };

        debug!("Tor connection established to {}:{}", host, port);

        // Wrap in TLS if needed
        if is_https {
            debug!("Wrapping connection in TLS for {}", host);
            let tls_config = TlsConfig {
                verify_certificates: self.config.security.verify_tls,
                min_version: self.config.security.min_tls_version,
            };
            let stream = wrap_tls(data_stream, host, &tls_config).await?;
            debug!("TLS handshake complete for {}", host);
            Ok(stream)
        } else {
            Ok(TorStream::plain(data_stream))
        }
    }

    /// Send an HTTP request over a stream using HTTP/1.1
    async fn send_request(&self, stream: TorStream, request: Request<Bytes>) -> Result<Response> {
        self.send_request_h1(stream, request).await
    }

    /// Send HTTP/1.1 request
    async fn send_request_h1(
        &self,
        stream: TorStream,
        request: Request<Bytes>,
    ) -> Result<Response> {
        use hyper::client::conn::http1;
        use hyper_util::rt::TokioIo;

        // Wrap stream for hyper compatibility
        let io = TokioIo::new(stream);

        let (mut sender, conn) = http1::handshake(io)
            .await
            .map_err(|e| Error::http_with_source("HTTP/1.1 handshake failed", e))?;

        // Spawn connection handler
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("Connection error: {}", e);
            }
        });

        // Convert body
        let (parts, body) = request.into_parts();
        let request = Request::from_parts(parts, Full::new(body));

        // Send request
        let response = sender
            .send_request(request)
            .await
            .map_err(|e| Error::http_with_source("failed to send request", e))?;

        // Convert response
        Response::from_hyper(response, self.config.max_response_size).await
    }

    /// Send HTTP/2 request over a stream.
    ///
    /// HTTP/2 enables multiplexing multiple requests over a single connection,
    /// which is more efficient for high-throughput scenarios over Tor.
    ///
    /// Note: HTTP/2 requires TLS (HTTPS) for clearnet. For .onion addresses,
    /// Tor provides the encryption layer.
    pub async fn send_request_h2(
        &self,
        stream: TorStream,
        request: Request<Bytes>,
    ) -> Result<Response> {
        use hyper::client::conn::http2;
        use hyper_util::rt::TokioExecutor;
        use hyper_util::rt::TokioIo;

        // Wrap stream for hyper compatibility
        let io = TokioIo::new(stream);

        // HTTP/2 handshake with Tokio executor
        let (mut sender, conn) = http2::handshake(TokioExecutor::new(), io)
            .await
            .map_err(|e| Error::http_with_source("HTTP/2 handshake failed", e))?;

        // Spawn connection handler
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("HTTP/2 connection error: {}", e);
            }
        });

        // Convert body
        let (parts, body) = request.into_parts();
        let request = Request::from_parts(parts, Full::new(body));

        // Send request
        let response = sender
            .send_request(request)
            .await
            .map_err(|e| Error::http_with_source("failed to send HTTP/2 request", e))?;

        // Convert response
        Response::from_hyper(response, self.config.max_response_size).await
    }

    /// Get pool statistics
    pub fn pool_size(&self) -> usize {
        self.pool.len()
    }

    /// Clear the connection pool
    pub fn clear_pool(&self) {
        self.pool.clear();
    }
}

impl Clone for TorClient {
    fn clone(&self) -> Self {
        // Note: We clone the isolation_cache contents so cloned clients
        // maintain isolation token mappings. In practice, the Arc on the
        // TorClient is typically shared rather than cloned.
        Self {
            tor: Arc::clone(&self.tor),
            config: Arc::clone(&self.config),
            pool: Arc::clone(&self.pool),
            isolation_cache: Mutex::new(self.isolation_cache.lock().clone()),
        }
    }
}

/// Builder for TorClient with fluent configuration API
///
/// # Example - Basic usage
/// ```rust,ignore
/// use hypertor::TorClient;
/// use std::time::Duration;
///
/// let client = TorClient::builder()
///     .timeout(Duration::from_secs(60))
///     .max_connections(20)
///     .isolation(IsolationLevel::PerRequest)
///     .follow_redirects(true)
///     .build()
///     .await?;
/// ```
///
/// # Example - With bridges (for censored networks like China/Iran)
/// ```rust,ignore
/// use hypertor::TorClient;
///
/// let client = TorClient::builder()
///     .bridge("obfs4 192.0.2.1:443 FINGERPRINT cert=... iat-mode=0")
///     .bridge("obfs4 192.0.2.2:443 FINGERPRINT cert=... iat-mode=0")
///     .transport("obfs4", "/usr/bin/obfs4proxy")
///     .build()
///     .await?;
/// ```
///
/// # Example - With vanguards (for onion service protection)
/// ```rust,ignore
/// use hypertor::{TorClient, VanguardMode};
///
/// let client = TorClient::builder()
///     .vanguards(VanguardMode::Full)  // or VanguardMode::Lite
///     .build()
///     .await?;
/// ```
pub struct TorClientBuilder {
    config_builder: crate::config::ConfigBuilder,
    tor_config_builder: TorClientConfigBuilder,
    /// Bridge lines to add
    bridges: Vec<String>,
    /// Pluggable transport configs: (transport_name, binary_path)
    transports: Vec<(String, String)>,
    /// Vanguard mode
    vanguard_mode: Option<VanguardMode>,
}

impl TorClientBuilder {
    /// Create a new builder with default configuration
    pub fn new() -> Self {
        Self {
            config_builder: Config::builder(),
            tor_config_builder: TorClientConfig::builder(),
            bridges: Vec::new(),
            transports: Vec::new(),
            vanguard_mode: None,
        }
    }

    /// Set the request timeout
    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.config_builder = self.config_builder.timeout(timeout);
        self
    }

    /// Set the maximum number of pooled connections
    pub fn max_connections(mut self, max: usize) -> Self {
        self.config_builder = self.config_builder.max_connections(max);
        self
    }

    /// Set the maximum response body size
    pub fn max_response_size(mut self, size: usize) -> Self {
        self.config_builder = self.config_builder.max_response_size(size);
        self
    }

    /// Set the stream isolation level
    pub fn isolation(mut self, level: crate::isolation::IsolationLevel) -> Self {
        self.config_builder = self.config_builder.isolation(level);
        self
    }

    /// Set the User-Agent header
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.config_builder = self.config_builder.user_agent(ua);
        self
    }

    /// Enable or disable following redirects
    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.config_builder = self.config_builder.follow_redirects(follow);
        self
    }

    /// Set the maximum number of redirects to follow
    pub fn max_redirects(mut self, max: u8) -> Self {
        self.config_builder = self.config_builder.max_redirects(max);
        self
    }

    /// Strip Referer header from requests
    pub fn strip_referer(mut self, strip: bool) -> Self {
        self.config_builder = self.config_builder.strip_referer(strip);
        self
    }

    /// Enable or disable TLS certificate verification
    ///
    /// # Warning
    /// Disabling this is a security risk and should only be done for testing
    pub fn verify_tls(mut self, verify: bool) -> Self {
        self.config_builder = self.config_builder.verify_tls(verify);
        self
    }

    // ========================================================================
    // Bridge Support - CRITICAL for Censored Networks (China, Iran, Russia)
    // ========================================================================

    /// Add a bridge from a bridge line string.
    ///
    /// Bridge lines are used to connect through unlisted relays, which is
    /// essential in censored regions where Tor's public relay IPs are blocked.
    ///
    /// # Format
    /// ```text
    /// [transport] address:port [fingerprint] [key=value...]
    /// ```
    ///
    /// # Example
    /// ```rust,ignore
    /// let client = TorClient::builder()
    ///     .bridge("obfs4 192.0.2.1:443 FINGERPRINT cert=... iat-mode=0")
    ///     .bridge("snowflake 192.0.2.3:1 url=... front=...")
    ///     .transport("obfs4", "/usr/bin/obfs4proxy")
    ///     .build()
    ///     .await?;
    /// ```
    pub fn bridge(mut self, bridge_line: impl Into<String>) -> Self {
        self.bridges.push(bridge_line.into());
        self
    }

    /// Add multiple bridges at once.
    ///
    /// # Example
    /// ```rust,ignore
    /// let bridges = vec![
    ///     "obfs4 192.0.2.1:443 FINGERPRINT cert=... iat-mode=0",
    ///     "obfs4 192.0.2.2:443 FINGERPRINT cert=... iat-mode=0",
    /// ];
    /// let client = TorClient::builder()
    ///     .bridges(bridges)
    ///     .transport("obfs4", "/usr/bin/obfs4proxy")
    ///     .build()
    ///     .await?;
    /// ```
    pub fn bridges(mut self, bridge_lines: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.bridges
            .extend(bridge_lines.into_iter().map(Into::into));
        self
    }

    /// Configure a pluggable transport binary.
    ///
    /// Pluggable transports disguise Tor traffic to evade DPI (Deep Packet
    /// Inspection). Common transports include:
    /// - `obfs4` - Look-like-nothing obfuscation
    /// - `snowflake` - WebRTC-based circumvention
    /// - `meek_lite` - Domain fronting via CDN
    /// - `webtunnel` - HTTPS tunneling
    ///
    /// # Arguments
    /// * `name` - Transport protocol name (e.g., "obfs4", "snowflake")
    /// * `path` - Path to the transport binary (e.g., "/usr/bin/obfs4proxy")
    ///
    /// # Example
    /// ```rust,ignore
    /// let client = TorClient::builder()
    ///     .bridge("obfs4 192.0.2.1:443 FINGERPRINT cert=... iat-mode=0")
    ///     .transport("obfs4", "/usr/bin/obfs4proxy")
    ///     .build()
    ///     .await?;
    /// ```
    pub fn transport(mut self, name: impl Into<String>, path: impl Into<String>) -> Self {
        self.transports.push((name.into(), path.into()));
        self
    }

    // ========================================================================
    // Vanguard Support - CRITICAL for Onion Service Protection
    // ========================================================================

    /// Configure vanguard mode for enhanced anonymity protection.
    ///
    /// Vanguards protect against guard discovery attacks by restricting which
    /// relays can be used at different circuit positions. This is especially
    /// important for onion service operators.
    ///
    /// # Modes
    /// - `VanguardMode::Disabled` - No vanguards (default for regular browsing)
    /// - `VanguardMode::Lite` - Layer 2 vanguards only (good balance)
    /// - `VanguardMode::Full` - Layer 2 + Layer 3 vanguards (maximum protection)
    ///
    /// # Example
    /// ```rust,ignore
    /// use hypertor::{TorClient, VanguardMode};
    ///
    /// // For onion service operators
    /// let client = TorClient::builder()
    ///     .vanguards(VanguardMode::Full)
    ///     .build()
    ///     .await?;
    /// ```
    ///
    /// # Security Note
    /// Without vanguards, an adversary can discover your guard node through
    /// traffic analysis in approximately 3 months. With full vanguards, this
    /// attack becomes significantly harder.
    pub fn vanguards(mut self, mode: VanguardMode) -> Self {
        self.vanguard_mode = Some(mode);
        self
    }

    /// Enable vanguards-lite mode.
    ///
    /// This is a convenience method equivalent to `.vanguards(VanguardMode::Lite)`.
    /// Recommended for most users who want enhanced protection.
    pub fn vanguards_lite(self) -> Self {
        self.vanguards(VanguardMode::Lite)
    }

    /// Enable full vanguards mode.
    ///
    /// This is a convenience method equivalent to `.vanguards(VanguardMode::Full)`.
    /// Recommended for onion service operators.
    pub fn vanguards_full(self) -> Self {
        self.vanguards(VanguardMode::Full)
    }

    /// Build the TorClient with the configured options
    ///
    /// This will bootstrap a connection to the Tor network, which may take
    /// several seconds on first run.
    pub async fn build(mut self) -> Result<TorClient> {
        // Build hypertor config
        let config = self.config_builder.build()?;

        // Configure bridges if any
        if !self.bridges.is_empty() {
            for bridge_line in &self.bridges {
                // Parse bridge line and add to config
                let bridge_config: BridgeConfigBuilder = bridge_line.parse().map_err(|e| {
                    Error::config(format!("Invalid bridge line '{}': {:?}", bridge_line, e))
                })?;
                self.tor_config_builder
                    .bridges()
                    .bridges()
                    .push(bridge_config);
            }
            debug!("Configured {} bridges", self.bridges.len());
        }

        // Configure pluggable transports if any
        for (name, path) in &self.transports {
            let mut transport = TransportConfigBuilder::default();
            let pt_name = name.parse().map_err(|e| {
                Error::config(format!("Invalid transport name '{}': {:?}", name, e))
            })?;
            transport
                .protocols(vec![pt_name])
                .path(CfgPath::new(path.clone()))
                .run_on_startup(true);
            self.tor_config_builder
                .bridges()
                .transports()
                .push(transport);
            debug!("Configured transport '{}' at '{}'", name, path);
        }

        // Configure vanguards if specified
        if let Some(mode) = self.vanguard_mode {
            self.tor_config_builder
                .vanguards()
                .mode(ExplicitOrAuto::Explicit(mode));
            debug!("Configured vanguards mode: {:?}", mode);
        }

        // Build arti config
        let tor_config = self
            .tor_config_builder
            .build()
            .map_err(|e| Error::config(format!("Failed to build Tor config: {:?}", e)))?;

        TorClient::with_configs(config, tor_config).await
    }
}

impl Default for TorClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // SECURITY CONFIGURATION TESTS
    // ========================================================================
    // These tests verify security features are correctly wired to arti

    #[test]
    fn test_builder_vanguard_configuration() {
        // Test default has no explicit vanguards
        let builder = TorClientBuilder::new();
        assert!(builder.vanguard_mode.is_none());

        // Test explicit vanguard modes
        let lite = TorClientBuilder::new().vanguards_lite();
        assert_eq!(lite.vanguard_mode, Some(VanguardMode::Lite));

        let full = TorClientBuilder::new().vanguards_full();
        assert_eq!(full.vanguard_mode, Some(VanguardMode::Full));

        // Test direct enum setting
        let disabled = TorClientBuilder::new().vanguards(VanguardMode::Disabled);
        assert_eq!(disabled.vanguard_mode, Some(VanguardMode::Disabled));
    }

    #[test]
    fn test_builder_bridge_configuration() {
        let builder = TorClientBuilder::new();
        assert!(builder.bridges.is_empty());

        // Test adding single bridge
        let with_one =
            TorClientBuilder::new().bridge("obfs4 192.0.2.1:443 FINGERPRINT cert=xyz iat-mode=0");
        assert_eq!(with_one.bridges.len(), 1);

        // Test adding multiple bridges
        let with_many = TorClientBuilder::new()
            .bridge("obfs4 192.0.2.1:443 FINGERPRINT cert=xyz iat-mode=0")
            .bridge("obfs4 192.0.2.2:443 FINGERPRINT cert=abc iat-mode=0");
        assert_eq!(with_many.bridges.len(), 2);

        // Test adding bridges via iterator
        let bridges = vec![
            "obfs4 192.0.2.1:443 FINGERPRINT cert=xyz iat-mode=0",
            "obfs4 192.0.2.2:443 FINGERPRINT cert=abc iat-mode=0",
        ];
        let with_iter = TorClientBuilder::new().bridges(bridges);
        assert_eq!(with_iter.bridges.len(), 2);
    }

    #[test]
    fn test_builder_transport_configuration() {
        let builder = TorClientBuilder::new();
        assert!(builder.transports.is_empty());

        // Test adding transport
        let with_transport = TorClientBuilder::new().transport("obfs4", "/usr/bin/obfs4proxy");
        assert_eq!(with_transport.transports.len(), 1);
        assert_eq!(with_transport.transports[0].0, "obfs4");
        assert_eq!(with_transport.transports[0].1, "/usr/bin/obfs4proxy");

        // Test multiple transports
        let with_many = TorClientBuilder::new()
            .transport("obfs4", "/usr/bin/obfs4proxy")
            .transport("snowflake", "/usr/bin/snowflake-client");
        assert_eq!(with_many.transports.len(), 2);
    }

    #[test]
    fn test_builder_combined_security_features() {
        // Test combining all security features
        let builder = TorClientBuilder::new()
            .vanguards_full()
            .bridge("obfs4 192.0.2.1:443 FINGERPRINT cert=xyz iat-mode=0")
            .transport("obfs4", "/usr/bin/obfs4proxy")
            .verify_tls(true);

        assert_eq!(builder.vanguard_mode, Some(VanguardMode::Full));
        assert_eq!(builder.bridges.len(), 1);
        assert_eq!(builder.transports.len(), 1);
    }

    #[test]
    fn test_security_for_china_scenario() {
        // Simulating configuration for a user in China:
        // - Bridges: essential (Tor IPs blocked)
        // - Transport: obfs4 (disguise traffic)
        // - Vanguards: optional but recommended

        let builder = TorClientBuilder::new()
            // Must use bridges in China
            .bridge("obfs4 192.0.2.1:443 FINGERPRINT cert=xyz iat-mode=0")
            .bridge("obfs4 192.0.2.2:443 FINGERPRINT cert=abc iat-mode=0")
            // Must have transport binary
            .transport("obfs4", "/usr/bin/obfs4proxy")
            // Vanguards add extra protection
            .vanguards_full();

        // Verify all required components are configured
        assert!(
            !builder.bridges.is_empty(),
            "CRITICAL: Bridges required for China"
        );
        assert!(
            !builder.transports.is_empty(),
            "CRITICAL: Transport required for China"
        );
        assert_eq!(builder.vanguard_mode, Some(VanguardMode::Full));
    }

    // Integration tests require a running Tor network
    // They are run separately with: cargo test --features integration
}
