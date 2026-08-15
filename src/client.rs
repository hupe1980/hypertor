//! The Tor HTTP client.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use arti_client::config::{
    BridgeConfigBuilder, CfgPath, TorClientConfig, TorClientConfigBuilder,
    pt::TransportConfigBuilder,
};
use http::{Method, Uri};
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use parking_lot::Mutex;
use tor_config::ExplicitOrAuto;
use tor_guardmgr::VanguardMode;
use tor_rtcompat::PreferredRuntime;
use tracing::{debug, info};

use crate::config::{Config, ConfigBuilder};
use crate::connector::TorConnector;
use crate::error::{Error, Result};
use crate::isolation::{IsolatedSession, IsolationLevel, IsolationToken};
use crate::request::RequestBuilder;
use crate::tls::TlsConnector;

/// How many distinct isolation groups we keep pools and tokens for.
///
/// These maps have to be bounded: a client walking a large link graph would
/// otherwise accumulate one entry per host forever. When a map fills up it is
/// cleared wholesale, which costs a few fresh connections and never grows
/// without limit.
const ISOLATION_CACHE_CAPACITY: usize = 512;

type PooledClient = HyperClient<TorConnector, crate::body::Body>;

/// An HTTP client that sends every request over the Tor network.
///
/// Cloning is cheap and shares the underlying Tor client, connection pool and
/// circuits, so a `TorClient` can be handed to as many tasks as you like.
///
/// ```rust,no_run
/// use hypertor::TorClient;
///
/// # async fn demo() -> hypertor::Result<()> {
/// let client = TorClient::new().await?;
/// let body = client.get("https://check.torproject.org/api/ip")?.send().await?.text()?;
/// println!("{body}");
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct TorClient {
    inner: Arc<Inner>,
}

struct Inner {
    tor: Arc<arti_client::TorClient<PreferredRuntime>>,
    config: Arc<Config>,
    tls: Option<TlsConnector>,
    /// The default group, used when a request needs no special isolation.
    default_group: IsolatedGroup,
    /// One group per isolation token, so isolated requests never reuse a
    /// connection — or a TLS session — belonging to a different group.
    isolated: Mutex<HashMap<IsolationToken, IsolatedGroup>>,
    /// Stable per-host tokens for [`IsolationLevel::PerHost`].
    host_tokens: Mutex<HashMap<String, IsolationToken>>,
}

impl TorClient {
    /// Bootstrap a client with the default configuration.
    ///
    /// This connects to the Tor network and downloads a directory consensus.
    /// The first run typically takes a few tens of seconds; later runs reuse the
    /// cached directory and are much faster.
    pub async fn new() -> Result<Self> {
        Self::builder().build().await
    }

    /// Start configuring a client.
    pub fn builder() -> TorClientBuilder {
        TorClientBuilder::new()
    }

    /// Build a client from an already-bootstrapped arti client.
    ///
    /// Use this to share one Tor instance — and therefore one directory cache,
    /// one guard set and one set of circuits — between a client and an
    /// [`OnionService`](crate::OnionService), or to reuse an arti client
    /// configured by other means.
    pub fn from_arti(
        tor: Arc<arti_client::TorClient<PreferredRuntime>>,
        config: Config,
    ) -> Result<Self> {
        let tls = if cfg!(any(feature = "rustls", feature = "native-tls")) {
            Some(TlsConnector::new(&config.tls)?)
        } else {
            None
        };

        let config = Arc::new(config);

        let default_group = IsolatedGroup::new(&tor, tls.clone(), &config, None);

        Ok(Self {
            inner: Arc::new(Inner {
                tor,
                config,
                tls,
                default_group,
                isolated: Mutex::new(HashMap::new()),
                host_tokens: Mutex::new(HashMap::new()),
            }),
        })
    }

    /// The configuration in use.
    pub fn config(&self) -> &Config {
        &self.inner.config
    }

    /// The underlying arti client, for operations hypertor does not wrap.
    pub fn arti(&self) -> &arti_client::TorClient<PreferredRuntime> {
        &self.inner.tor
    }

    /// The TLS connector for an isolation group.
    ///
    /// Building one from scratch parses the whole system trust store, so the
    /// certificate configuration is shared; what differs per group is the TLS
    /// session-resumption store. Sharing *that* would let a server link two
    /// requests placed on deliberately different circuits, by handing the
    /// second a ticket the first was issued.
    #[cfg_attr(not(feature = "ws"), allow(dead_code))]
    pub(crate) fn tls_for(&self, isolation: Isolation) -> Option<TlsConnector> {
        self.group_for(isolation).tls
    }

    /// Bootstrap now, rather than on the first request.
    ///
    /// Only meaningful for a client built with
    /// [`lazy_bootstrap`](TorClientBuilder::lazy_bootstrap): an eagerly-built
    /// client is already bootstrapped and this returns immediately. Calling it
    /// lets you decide when to pay the cost — and where to handle the failure —
    /// instead of having a user's first request absorb both.
    pub async fn bootstrap(&self) -> Result<()> {
        self.inner
            .tor
            .bootstrap()
            .await
            .map_err(|e| Error::bootstrap("could not bootstrap the Tor client", e))
    }

    /// Resolve a hostname through Tor.
    ///
    /// The lookup is performed by an exit relay, so it never leaves your machine
    /// as a plaintext DNS query. You rarely need this: the client resolves names
    /// over Tor automatically when connecting.
    pub async fn resolve(&self, hostname: &str) -> Result<Vec<std::net::IpAddr>> {
        self.inner
            .tor
            .resolve(hostname)
            .await
            .map_err(|e| Error::connect(hostname, 0, e))
    }

    /// Reverse-resolve an address through Tor.
    ///
    /// Like [`resolve`](Self::resolve), the lookup is performed by an exit
    /// relay, so it never leaves your machine as a plaintext DNS query.
    pub async fn resolve_ptr(&self, address: std::net::IpAddr) -> Result<Vec<String>> {
        self.inner
            .tor
            .resolve_ptr(address)
            .await
            .map_err(|e| Error::connect(address.to_string(), 0, e))
    }

    /// Start a group of requests that share one circuit, isolated from the rest.
    pub fn isolated_session(&self) -> IsolatedSession {
        IsolatedSession::new()
    }

    /// Begin a `GET` request.
    pub fn get(&self, url: &str) -> Result<RequestBuilder> {
        self.request(Method::GET, url)
    }

    /// Begin a `POST` request.
    pub fn post(&self, url: &str) -> Result<RequestBuilder> {
        self.request(Method::POST, url)
    }

    /// Begin a `PUT` request.
    pub fn put(&self, url: &str) -> Result<RequestBuilder> {
        self.request(Method::PUT, url)
    }

    /// Begin a `PATCH` request.
    pub fn patch(&self, url: &str) -> Result<RequestBuilder> {
        self.request(Method::PATCH, url)
    }

    /// Begin a `DELETE` request.
    pub fn delete(&self, url: &str) -> Result<RequestBuilder> {
        self.request(Method::DELETE, url)
    }

    /// Begin a `HEAD` request.
    pub fn head(&self, url: &str) -> Result<RequestBuilder> {
        self.request(Method::HEAD, url)
    }

    /// Begin an `OPTIONS` request.
    pub fn options(&self, url: &str) -> Result<RequestBuilder> {
        self.request(Method::OPTIONS, url)
    }

    /// Begin a request with an arbitrary method.
    pub fn request(&self, method: Method, url: &str) -> Result<RequestBuilder> {
        let uri: Uri = url
            .parse()
            .map_err(|e| Error::invalid_url(format!("{url:?}: {e}")))?;

        // Validate the target now, so a bad URL fails at the call site rather
        // than deep inside the connector.
        crate::connector::Target::from_uri(&uri)?;

        Ok(RequestBuilder::new(self.clone(), method, uri))
    }

    /// The pool to use for a request.
    pub(crate) fn pool_for(&self, isolation: Isolation) -> PooledClient {
        self.group_for(isolation).pool
    }

    /// The connection pool and TLS configuration for an isolation group.
    fn group_for(&self, isolation: Isolation) -> IsolatedGroup {
        let token = match isolation {
            Isolation::Shared => return self.inner.default_group.clone(),
            // A single-use token will never be looked up again, so caching its
            // group would be pure churn — build a throwaway one and let it drop
            // with the request. Its TLS configuration resumes nothing, since a
            // connection used once can never benefit and a stored ticket is
            // only something for a later connection to be correlated by.
            Isolation::SingleUse(token) => {
                let tls = self
                    .inner
                    .tls
                    .as_ref()
                    .map(TlsConnector::without_session_resumption);
                return IsolatedGroup::new(&self.inner.tor, tls, &self.inner.config, Some(token));
            }
            Isolation::Reusable(token) => token,
        };

        let mut groups = self.inner.isolated.lock();

        if groups.len() >= ISOLATION_CACHE_CAPACITY && !groups.contains_key(&token) {
            debug!("clearing isolated connection pools at capacity");
            groups.clear();
        }

        groups
            .entry(token)
            .or_insert_with(|| {
                // A store of its own, so a resumed session can never span two
                // isolation groups.
                let tls = self
                    .inner
                    .tls
                    .as_ref()
                    .map(TlsConnector::with_separate_session_cache);
                IsolatedGroup::new(&self.inner.tor, tls, &self.inner.config, Some(token))
            })
            .clone()
    }

    /// Resolve the isolation to use for one request.
    pub(crate) fn isolation_for(&self, uri: &Uri, explicit: Option<IsolationToken>) -> Isolation {
        match resolve_isolation(self.inner.config.isolation, explicit) {
            Some(isolation) => isolation,
            // PerHost is the one case needing the client's own cache.
            None => {
                let Some(host) = uri.host() else {
                    return Isolation::Shared;
                };
                let host = host.to_ascii_lowercase();

                let mut cache = self.inner.host_tokens.lock();
                if cache.len() >= ISOLATION_CACHE_CAPACITY && !cache.contains_key(&host) {
                    debug!("clearing per-host isolation cache at capacity");
                    cache.clear();
                }

                Isolation::Reusable(*cache.entry(host).or_default())
            }
        }
    }
}

/// Resolve isolation for everything except [`IsolationLevel::PerHost`], which
/// needs the client's host cache and returns `None` here.
fn resolve_isolation(level: IsolationLevel, explicit: Option<IsolationToken>) -> Option<Isolation> {
    // A token attached to the request always wins over the client-wide level,
    // and the caller may reuse it, so its pool is worth keeping.
    if let Some(token) = explicit {
        return Some(Isolation::Reusable(token));
    }

    match level {
        IsolationLevel::None => Some(Isolation::Shared),
        IsolationLevel::Fixed(token) => Some(Isolation::Reusable(token)),
        IsolationLevel::PerRequest => Some(Isolation::SingleUse(IsolationToken::new())),
        IsolationLevel::PerHost => None,
    }
}

/// The isolation resolved for one request, and whether its pool is worth
/// keeping around.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Isolation {
    /// No isolation of our own; use the shared pool.
    Shared,
    /// A token that will recur, so its pool is cached.
    Reusable(IsolationToken),
    /// A token used exactly once; its pool is built and discarded.
    SingleUse(IsolationToken),
}

impl Isolation {
    /// The arti token to apply, if any.
    ///
    /// Used by connections made outside the HTTP pool — a
    /// [`TorWebSocket`](crate::TorWebSocket) dials arti directly but must still
    /// honour the client-wide [`IsolationLevel`], or it would be a hole in
    /// exactly the guarantee the setting exists to provide.
    #[cfg_attr(not(feature = "ws"), allow(dead_code))]
    pub(crate) fn token(self) -> Option<IsolationToken> {
        match self {
            Isolation::Shared => None,
            Isolation::Reusable(token) | Isolation::SingleUse(token) => Some(token),
        }
    }
}

impl std::fmt::Debug for TorClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TorClient")
            .field("isolation", &self.inner.config.isolation)
            .field("timeout", &self.inner.config.timeout)
            .finish_non_exhaustive()
    }
}

/// Everything scoped to one isolation group.
///
/// The connection pool and the TLS session store have to be partitioned
/// together: separating circuits while sharing session tickets would leave the
/// server able to link exactly the requests the circuits kept apart.
#[derive(Clone)]
struct IsolatedGroup {
    pool: PooledClient,
    tls: Option<TlsConnector>,
}

impl IsolatedGroup {
    fn new(
        tor: &Arc<arti_client::TorClient<PreferredRuntime>>,
        tls: Option<TlsConnector>,
        config: &Arc<Config>,
        isolation: Option<IsolationToken>,
    ) -> Self {
        let connector =
            TorConnector::new(Arc::clone(tor), tls.clone(), Arc::clone(config), isolation);

        let pool = HyperClient::builder(TokioExecutor::new())
            .pool_idle_timeout(config.pool_idle_timeout)
            .pool_max_idle_per_host(config.pool_max_idle_per_host)
            // Circuits are expensive to build and cheap to keep; letting hyper
            // retry a canceled request on a fresh connection avoids surfacing a
            // pooled-connection race as a user-visible error.
            .retry_canceled_requests(true)
            .build(connector);

        Self { pool, tls }
    }
}

/// Builds a [`TorClient`].
///
/// ```rust,no_run
/// use std::time::Duration;
/// use hypertor::{IsolationLevel, TorClient};
///
/// # async fn demo() -> hypertor::Result<()> {
/// let client = TorClient::builder()
///     .timeout(Duration::from_secs(60))
///     .isolation(IsolationLevel::PerRequest)
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct TorClientBuilder {
    config: ConfigBuilder,
    tor_config: TorClientConfigBuilder,
    bridges: Vec<String>,
    transports: Vec<(String, String)>,
    vanguards: Option<VanguardMode>,
    state_dir: Option<PathBuf>,
    cache_dir: Option<PathBuf>,
    lazy_bootstrap: bool,
}

impl TorClientBuilder {
    /// Create a builder with hypertor's defaults.
    pub fn new() -> Self {
        Self {
            config: Config::builder(),
            tor_config: TorClientConfig::builder(),
            bridges: Vec::new(),
            transports: Vec::new(),
            vanguards: None,
            state_dir: None,
            cache_dir: None,
            lazy_bootstrap: false,
        }
    }

    /// Replace the whole HTTP-side configuration.
    ///
    /// The individual setters below are shorthands for fields of [`Config`];
    /// use this when you already have one, and note that it overwrites anything
    /// set before it.
    pub fn config(mut self, config: Config) -> Self {
        self.config = ConfigBuilder::from(config);
        self
    }

    /// Deadline for a whole request, including circuit setup and redirects.
    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.config = self.config.timeout(timeout);
        self
    }

    /// How long an idle pooled connection is kept before being closed.
    ///
    /// A pooled connection is a live Tor circuit. Keeping one costs almost
    /// nothing and rebuilding it costs seconds, so the default is generous.
    pub fn pool_idle_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.config = self.config.pool_idle_timeout(timeout);
        self
    }

    /// Return from [`build`](Self::build) without waiting for Tor to bootstrap.
    ///
    /// Bootstrapping downloads a directory consensus and takes tens of seconds
    /// on a cold cache. With this set, `build` returns at once and the first
    /// request that needs the network waits for bootstrap instead — which is
    /// what you want in a process that must start promptly, or that may never
    /// make a request at all.
    ///
    /// The cost is moved rather than removed: the first request pays it, and
    /// bootstrap failures surface there rather than at construction. Call
    /// [`TorClient::bootstrap`] to pay it at a moment of your choosing.
    pub fn lazy_bootstrap(mut self, lazy: bool) -> Self {
        self.lazy_bootstrap = lazy;
        self
    }

    /// Deadline for opening one Tor stream and completing its TLS handshake.
    pub fn connect_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.config = self.config.connect_timeout(timeout);
        self
    }

    /// Maximum idle connections kept per destination host.
    pub fn pool_max_idle_per_host(mut self, max: usize) -> Self {
        self.config = self.config.pool_max_idle_per_host(max);
        self
    }

    /// Maximum response body size, in bytes.
    pub fn max_response_size(mut self, size: usize) -> Self {
        self.config = self.config.max_response_size(size);
        self
    }

    /// Circuit isolation strategy.
    pub fn isolation(mut self, level: IsolationLevel) -> Self {
        self.config = self.config.isolation(level);
        self
    }

    /// The User-Agent to send.
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.config = self.config.user_agent(ua);
        self
    }

    /// How redirects are handled.
    pub fn redirect(mut self, policy: crate::redirect::RedirectPolicy) -> Self {
        self.config = self.config.redirect(policy);
        self
    }

    /// How many times a retryable failure is retried. See
    /// [`Config::max_retries`](crate::Config::max_retries) for what a retry
    /// does and does not give you.
    pub fn max_retries(mut self, retries: u32) -> Self {
        self.config = self.config.max_retries(retries);
        self
    }

    /// Allow TLS sessions to be resumed. See [`TlsConfig::session_resumption`].
    ///
    /// [`TlsConfig::session_resumption`]: crate::TlsConfig::session_resumption
    pub fn tls_session_resumption(mut self, enabled: bool) -> Self {
        self.config = self.config.tls_session_resumption(enabled);
        self
    }

    /// Accept and transparently decode compressed responses.
    pub fn compression(mut self, enabled: bool) -> Self {
        self.config = self.config.compression(enabled);
        self
    }

    /// Offer HTTP/2 via ALPN on `https://` targets.
    pub fn http2(mut self, enabled: bool) -> Self {
        self.config = self.config.http2(enabled);
        self
    }

    /// Lowest acceptable TLS version.
    pub fn min_tls_version(mut self, version: crate::config::TlsVersion) -> Self {
        self.config = self.config.min_tls_version(version);
        self
    }

    /// Disable TLS certificate verification.
    ///
    /// # Warning
    ///
    /// See [`ConfigBuilder::danger_accept_invalid_certs`].
    pub fn danger_accept_invalid_certs(mut self, accept: bool) -> Self {
        self.config = self.config.danger_accept_invalid_certs(accept);
        self
    }

    /// Where arti keeps persistent state (keys, guards).
    ///
    /// Reusing a state directory preserves your guard relays across restarts,
    /// which is what Tor's guard design depends on: picking fresh guards every
    /// run multiplies your exposure to a hostile first hop.
    pub fn state_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.state_dir = Some(path.into());
        self
    }

    /// Where arti caches the directory consensus.
    ///
    /// Safe to delete: it is rebuilt on the next bootstrap, unlike
    /// [`state_dir`](Self::state_dir), which holds keys.
    pub fn cache_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.cache_dir = Some(path.into());
        self
    }

    /// Add a bridge line.
    ///
    /// Bridges are unlisted relays. They are the entry point when a network
    /// blocks Tor's published relay addresses, as in China, Iran and Russia.
    /// A bridge usually also needs its pluggable transport binary, configured
    /// with [`transport`](Self::transport).
    ///
    /// ```rust,no_run
    /// # use hypertor::TorClient;
    /// # async fn demo() -> hypertor::Result<()> {
    /// let client = TorClient::builder()
    ///     .bridge("obfs4 192.0.2.1:443 FINGERPRINT cert=CERT iat-mode=0")
    ///     .transport("obfs4", "/usr/bin/lyrebird")
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn bridge(mut self, bridge_line: impl Into<String>) -> Self {
        self.bridges.push(bridge_line.into());
        self
    }

    /// Add several bridge lines.
    pub fn bridges(mut self, lines: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.bridges.extend(lines.into_iter().map(Into::into));
        self
    }

    /// Register a pluggable transport binary.
    ///
    /// Pluggable transports disguise Tor traffic against deep packet
    /// inspection. `obfs4` (shipped as the `lyrebird` binary) is the common
    /// choice; `snowflake` and `webtunnel` are also widely deployed.
    pub fn transport(mut self, name: impl Into<String>, binary: impl Into<String>) -> Self {
        self.transports.push((name.into(), binary.into()));
        self
    }

    /// Set the vanguard mode.
    ///
    /// Vanguards constrain which relays may appear at the middle positions of
    /// your circuits, which raises the cost of the guard-discovery attacks that
    /// long-lived onion service connections are vulnerable to.
    ///
    /// Leave this unset to accept arti's default, which already enables
    /// vanguards-lite where it matters.
    pub fn vanguards(mut self, mode: VanguardMode) -> Self {
        self.vanguards = Some(mode);
        self
    }

    /// Bootstrap the client.
    pub async fn build(mut self) -> Result<TorClient> {
        // Must happen before arti is touched: arti builds its own rustls
        // configuration while bootstrapping, and rustls panics rather than
        // guessing when the provider is ambiguous.
        crate::tls::install_crypto_provider();

        let config = self.config.build()?;

        if let Some(dir) = &self.state_dir {
            self.tor_config.storage().state_dir(cfg_path(dir));
        }
        if let Some(dir) = &self.cache_dir {
            self.tor_config.storage().cache_dir(cfg_path(dir));
        }

        for line in &self.bridges {
            let bridge: BridgeConfigBuilder = line
                .parse()
                .map_err(|e| Error::config(format!("invalid bridge line {line:?}: {e:?}")))?;
            self.tor_config.bridges().bridges().push(bridge);
        }
        if !self.bridges.is_empty() {
            debug!(count = self.bridges.len(), "configured bridges");
        }

        for (name, path) in &self.transports {
            let protocol = name
                .parse()
                .map_err(|e| Error::config(format!("invalid transport name {name:?}: {e:?}")))?;

            let mut transport = TransportConfigBuilder::default();
            transport
                .protocols(vec![protocol])
                .path(CfgPath::new(path.clone()))
                .run_on_startup(true);

            self.tor_config.bridges().transports().push(transport);
            debug!(transport = %name, "configured pluggable transport");
        }

        if !self.bridges.is_empty() && self.transports.is_empty() {
            // A bridge line naming a transport is useless without the binary
            // that speaks it, and the resulting failure is otherwise opaque.
            let needs_transport = self.bridges.iter().any(|line| {
                line.split_whitespace().next().is_some_and(|w| {
                    !w.contains(':') && !w.chars().next().is_some_and(|c| c.is_ascii_digit())
                })
            });

            if needs_transport {
                return Err(Error::config(
                    "a bridge line names a pluggable transport, but no transport binary was \
                     registered; add .transport(\"obfs4\", \"/path/to/lyrebird\")",
                ));
            }
        }

        if let Some(mode) = self.vanguards {
            self.tor_config
                .vanguards()
                .mode(ExplicitOrAuto::Explicit(mode));
            debug!(?mode, "configured vanguards");
        }

        let tor_config = self
            .tor_config
            .build()
            .map_err(|e| Error::config(format!("invalid Tor configuration: {e}")))?;

        let runtime = PreferredRuntime::current().map_err(|e| {
            Error::config(format!(
                "hypertor needs to be built inside a tokio runtime: {e}"
            ))
        })?;

        // `OnDemand` in both cases. It is what makes the lazy path work at all,
        // and on the eager path bootstrap has already completed by the time any
        // request is made, so it changes nothing there.
        let arti = arti_client::TorClient::with_runtime(runtime)
            .config(tor_config)
            .bootstrap_behavior(arti_client::BootstrapBehavior::OnDemand);

        let tor = if self.lazy_bootstrap {
            debug!("creating an unbootstrapped Tor client; the first request will bootstrap");
            arti.create_unbootstrapped()
                .map_err(|e| Error::bootstrap("could not create the Tor client", e))?
        } else {
            info!("bootstrapping Tor (the first run downloads a directory and can take a while)");
            let tor = arti
                .create_bootstrapped()
                .await
                .map_err(|e| Error::bootstrap("could not bootstrap the Tor client", e))?;
            info!("Tor bootstrapped");
            tor
        };

        TorClient::from_arti(tor, config)
    }
}

/// arti wants its paths as `CfgPath`, which is built from a string.
///
/// A path that is not valid UTF-8 is passed through lossily rather than
/// rejected: the alternative is refusing to start over a byte in a directory
/// name that arti will very likely handle fine.
fn cfg_path(path: &std::path::Path) -> CfgPath {
    CfgPath::new(path.to_string_lossy().into_owned())
}

impl Default for TorClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Resolve isolation, asserting the level is not the PerHost special case.
    fn resolve(level: IsolationLevel, explicit: Option<IsolationToken>) -> Isolation {
        resolve_isolation(level, explicit).expect("not the PerHost case")
    }

    /// A syntactically valid obfs4 bridge line (the relay does not exist).
    const BRIDGE_LINE: &str =
        "obfs4 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=abc iat-mode=0";

    #[test]
    fn bridge_lines_accumulate() {
        let builder = TorClientBuilder::new()
            .bridge(BRIDGE_LINE)
            .bridges([BRIDGE_LINE]);
        assert_eq!(builder.bridges.len(), 2);
    }

    #[test]
    fn transports_accumulate() {
        let builder = TorClientBuilder::new()
            .transport("obfs4", "/usr/bin/lyrebird")
            .transport("snowflake", "/usr/bin/snowflake-client");
        assert_eq!(builder.transports.len(), 2);
    }

    #[tokio::test]
    async fn bridge_without_its_transport_is_rejected() {
        // Silently bootstrapping without the transport would hang until timeout
        // with no indication of why.
        let err = TorClientBuilder::new()
            .bridge(BRIDGE_LINE)
            .build()
            .await
            .expect_err("must reject");

        assert!(
            err.to_string().contains("transport"),
            "unhelpful error: {err}"
        );
    }

    #[test]
    fn single_use_isolation_is_not_cached() {
        // A PerRequest token is never looked up again, so caching its pool
        // would be churn with no hit rate.
        assert!(matches!(
            resolve(IsolationLevel::PerRequest, None),
            Isolation::SingleUse(_)
        ));
    }

    #[test]
    fn reusable_isolation_is_cached() {
        let token = IsolationToken::new();
        assert_eq!(
            resolve(IsolationLevel::Fixed(token), None),
            Isolation::Reusable(token)
        );
        assert_eq!(
            resolve(IsolationLevel::None, Some(token)),
            Isolation::Reusable(token),
            "an explicit per-request token may be reused by the caller"
        );
    }

    #[test]
    fn no_isolation_uses_the_shared_pool() {
        assert_eq!(resolve(IsolationLevel::None, None), Isolation::Shared);
    }

    #[test]
    fn per_host_defers_to_the_clients_cache() {
        assert!(
            resolve_isolation(IsolationLevel::PerHost, None).is_none(),
            "PerHost must be resolved against the host cache, not here"
        );
    }

    #[test]
    fn per_request_tokens_differ_every_time() {
        let a = resolve(IsolationLevel::PerRequest, None);
        let b = resolve(IsolationLevel::PerRequest, None);
        assert_ne!(a, b);
    }

    #[test]
    fn vanguard_mode_is_recorded() {
        let builder = TorClientBuilder::new().vanguards(VanguardMode::Full);
        assert_eq!(builder.vanguards, Some(VanguardMode::Full));
    }
}
