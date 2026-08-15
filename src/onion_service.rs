//! Hosting onion services.
//!
//! [`OnionService`] wraps arti's onion service provider and hands you a stream
//! of inbound connections. If you want an HTTP server on top of it, use
//! [`OnionApp`](crate::OnionApp), which does exactly that.
//!
//! ```rust,no_run
//! use hypertor::{OnionService, OnionServiceConfig};
//!
//! # async fn demo() -> hypertor::Result<()> {
//! let mut service = OnionService::builder()
//!     .nickname("my-service")?
//!     .state_dir("/var/lib/my-service")
//!     .launch()
//!     .await?;
//!
//! println!("reachable at {}", service.onion_address());
//!
//! while let Some(stream) = service.accept().await {
//!     tokio::spawn(async move { /* speak your protocol over `stream` */ });
//! }
//! # Ok(())
//! # }
//! ```

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use arti_client::config::TorClientConfigBuilder;
use arti_client::config::onion_service::OnionServiceConfigBuilder;
use arti_client::{DataStream, TorClient as ArtiClient};
use futures::StreamExt;
use safelog::DisplayRedacted;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tor_cell::relaycell::msg::Connected;
use tor_config::ExplicitOrAuto;
use tor_guardmgr::VanguardMode;
use tor_hscrypto::pk::HsClientDescEncKey;
use tor_hsservice::RunningOnionService;
use tor_hsservice::config::TokenBucketConfig;
use tor_rtcompat::PreferredRuntime;
use tracing::{debug, info, warn};

use crate::error::{Error, Result};

/// How many accepted streams may queue up before backpressure kicks in.
const ACCEPT_QUEUE_DEPTH: usize = 64;

/// Configuration for an onion service.
///
/// Every option is passed through to arti; hypertor implements no onion service
/// protocol logic of its own.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OnionServiceConfig {
    /// The service nickname, which selects its key material.
    pub nickname: String,
    /// The virtual port clients connect to on the `.onion` address.
    pub port: u16,
    /// Where arti stores keys and other persistent state.
    ///
    /// **This is what makes your `.onion` address stable.** The address is
    /// derived from a keypair that arti keeps here, so a service started
    /// without a persistent state directory gets a brand-new address on every
    /// restart.
    pub state_dir: Option<PathBuf>,
    /// Vanguard mode, which hardens circuit path selection.
    pub vanguards: Option<VanguardMode>,
    /// Require clients to solve a proof-of-work puzzle when the service is busy.
    ///
    /// Requires the `pow` feature.
    pub proof_of_work: bool,
    /// Depth of the proof-of-work rendezvous queue.
    pub pow_queue_depth: Option<usize>,
    /// Cap on concurrent streams within one client circuit.
    pub max_streams_per_circuit: u32,
    /// Token-bucket rate limit at the introduction points, as `(rate, burst)`.
    pub rate_limit_at_intro: Option<(u32, u32)>,
    /// How many introduction points to maintain.
    pub num_intro_points: u8,
    /// Clients authorised under restricted discovery, as `(nickname, key)`.
    pub authorized_clients: Vec<(String, HsClientDescEncKey)>,
}

impl Default for OnionServiceConfig {
    fn default() -> Self {
        Self {
            nickname: "hypertor".into(),
            port: 80,
            state_dir: None,
            vanguards: None,
            proof_of_work: false,
            pow_queue_depth: None,
            max_streams_per_circuit: 65535,
            rate_limit_at_intro: None,
            num_intro_points: 3,
            authorized_clients: Vec::new(),
        }
    }
}

/// Builds and launches an [`OnionService`].
#[derive(Clone, Default)]
pub struct OnionServiceBuilder {
    config: OnionServiceConfig,
    tor: Option<Arc<ArtiClient<PreferredRuntime>>>,
}

impl std::fmt::Debug for OnionServiceBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnionServiceBuilder")
            .field("config", &self.config)
            .field("shares_tor_client", &self.tor.is_some())
            .finish()
    }
}

impl OnionServiceBuilder {
    /// Start from the defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the service nickname.
    ///
    /// The nickname selects which key material arti uses, and therefore which
    /// `.onion` address you get. Two services sharing a nickname and a state
    /// directory share an identity.
    ///
    /// Fails if the nickname is not a valid arti identifier.
    pub fn nickname(mut self, nickname: impl Into<String>) -> Result<Self> {
        let nickname = nickname.into();
        // Validate now rather than at launch, when the failure is far from its
        // cause.
        nickname
            .parse::<tor_hsservice::HsNickname>()
            .map_err(|e| Error::config(format!("invalid service nickname: {e}")))?;
        self.config.nickname = nickname;
        Ok(self)
    }

    /// The virtual port clients connect to.
    pub fn port(mut self, port: u16) -> Self {
        self.config.port = port;
        self
    }

    /// Where arti stores keys and persistent state.
    ///
    /// Set this to keep the same `.onion` address across restarts. Treat the
    /// directory as secret material: anyone who copies it can impersonate your
    /// service.
    pub fn state_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.state_dir = Some(path.into());
        self
    }

    /// Set the vanguard mode.
    ///
    /// Onion services keep long-lived circuits, which is exactly the condition
    /// guard-discovery attacks exploit. `VanguardMode::Full` is the strongest
    /// setting; leaving this unset accepts arti's default.
    pub fn vanguards(mut self, mode: VanguardMode) -> Self {
        self.config.vanguards = Some(mode);
        self
    }

    /// Require proof-of-work from clients when the service is under load.
    ///
    /// Implements the Equi-X scheme from Tor proposal 327, which raises the
    /// cost of introduction floods without penalising ordinary clients when the
    /// service is idle.
    ///
    /// # Requires the `pow` feature
    ///
    /// The Equi-X implementation (`equix`, `hashx`) is LGPL-3.0-only, while
    /// hypertor is MIT, so it is opt-in rather than part of `full`. Enabling
    /// this without the feature is an error at launch rather than a silently
    /// unprotected service.
    pub fn proof_of_work(mut self, enabled: bool) -> Self {
        self.config.proof_of_work = enabled;
        self
    }

    /// Depth of the proof-of-work rendezvous queue.
    ///
    /// A deeper queue absorbs bigger bursts at the cost of memory.
    pub fn pow_queue_depth(mut self, depth: usize) -> Self {
        self.config.pow_queue_depth = Some(depth);
        self
    }

    /// Cap concurrent streams within one client circuit.
    pub fn max_streams_per_circuit(mut self, max: u32) -> Self {
        self.config.max_streams_per_circuit = max;
        self
    }

    /// Rate-limit introductions, in requests per second with a burst allowance.
    pub fn rate_limit_at_intro(mut self, rate: u32, burst: u32) -> Self {
        self.config.rate_limit_at_intro = Some((rate, burst));
        self
    }

    /// How many introduction points to maintain.
    ///
    /// More points means better availability and a larger footprint in the
    /// directory. arti accepts 1 to 20; the default is 3.
    pub fn num_intro_points(mut self, count: u8) -> Self {
        self.config.num_intro_points = count;
        self
    }

    /// Authorise a client under restricted discovery.
    ///
    /// With any client authorised, the service descriptor is encrypted so that
    /// only holders of these keys can find and reach the service. This is the
    /// strongest DoS defence available, because unauthorised clients cannot even
    /// discover the introduction points.
    ///
    /// Keys are x25519 public keys generated by the *client*, using
    /// `arti hsc get-key` or an equivalent. hypertor deliberately does not
    /// generate them for you: the secret half must never exist on the server.
    pub fn authorize_client(
        mut self,
        nickname: impl Into<String>,
        key: HsClientDescEncKey,
    ) -> Self {
        self.config.authorized_clients.push((nickname.into(), key));
        self
    }

    /// Host this service on an existing Tor client.
    ///
    /// Sharing one arti client between a [`TorClient`](crate::TorClient) and a
    /// service reuses a single directory cache and guard set, which is both
    /// faster and better for anonymity than running two independent instances.
    ///
    /// When you supply a client, its configuration governs vanguards; the
    /// [`vanguards`](Self::vanguards) setting here is ignored.
    pub fn on_client(mut self, tor: Arc<ArtiClient<PreferredRuntime>>) -> Self {
        self.tor = Some(tor);
        self
    }

    /// Launch the service and publish its descriptor.
    pub async fn launch(self) -> Result<OnionService> {
        let config = self.config;

        let tor = match self.tor {
            Some(tor) => tor,
            None => {
                let mut builder = TorClientConfigBuilder::default();

                if let Some(dir) = &config.state_dir {
                    let path =
                        arti_client::config::CfgPath::new(dir.to_string_lossy().into_owned());
                    builder.storage().state_dir(path.clone());
                    builder.storage().cache_dir(path);
                }

                if let Some(mode) = config.vanguards {
                    builder.vanguards().mode(ExplicitOrAuto::Explicit(mode));
                }

                let tor_config = builder
                    .build()
                    .map_err(|e| Error::config(format!("invalid Tor configuration: {e}")))?;

                info!("bootstrapping Tor for onion service {}", config.nickname);

                ArtiClient::create_bootstrapped(tor_config)
                    .await
                    .map_err(|e| Error::bootstrap("could not bootstrap the Tor client", e))?
            }
        };

        let svc_config = build_service_config(&config)?;

        let (running, rend_requests) = tor
            .launch_onion_service(svc_config)
            .map_err(|e| Error::onion_source("could not launch the onion service", e))?
            .ok_or_else(|| {
                Error::onion(
                    "this Tor client was built without onion service support; \
                     enable the `onion-service-service` feature of arti-client",
                )
            })?;

        let address = running
            .onion_address()
            .ok_or_else(|| Error::onion("the service has no onion address yet"))?
            .display_unredacted()
            .to_string();

        info!(port = config.port, "onion service published");

        let (tx, rx) = mpsc::channel(ACCEPT_QUEUE_DEPTH);

        let handler = tokio::spawn(async move {
            let streams = tor_hsservice::handle_rend_requests(rend_requests);
            tokio::pin!(streams);

            while let Some(request) = streams.next().await {
                // `accept` completes the handshake and returns the bidirectional
                // stream. It can fail for one client without affecting others.
                match request.accept(Connected::new_empty()).await {
                    Ok(stream) => {
                        if tx.send(stream).await.is_err() {
                            debug!("no receiver left; stopping the accept loop");
                            break;
                        }
                    }
                    Err(e) => warn!(error = %e, "could not accept an inbound stream"),
                }
            }

            debug!("rendezvous stream ended");
        });

        Ok(OnionService {
            address,
            config,
            _running: running,
            _tor: tor,
            incoming: rx,
            handler,
        })
    }
}

fn build_service_config(
    config: &OnionServiceConfig,
) -> Result<arti_client::config::onion_service::OnionServiceConfig> {
    let nickname = config
        .nickname
        .parse()
        .map_err(|e| Error::config(format!("invalid service nickname: {e}")))?;

    let mut builder = OnionServiceConfigBuilder::default();
    builder.nickname(nickname);

    if config.proof_of_work && !cfg!(feature = "pow") {
        // Quietly launching without the requested DoS defence would leave the
        // operator believing they are protected when they are not.
        return Err(Error::config(
            "proof_of_work(true) requires the `pow` feature; rebuild with \
             features = [\"pow\"] (note: it pulls in LGPL-3.0 dependencies)",
        ));
    }

    builder.enable_pow(config.proof_of_work);
    builder.max_concurrent_streams_per_circuit(config.max_streams_per_circuit);
    builder.num_intro_points(config.num_intro_points);

    if config.proof_of_work
        && let Some(depth) = config.pow_queue_depth
    {
        builder.pow_rend_queue_depth(depth);
    }

    if let Some((rate, burst)) = config.rate_limit_at_intro {
        builder.rate_limit_at_intro(Some(TokenBucketConfig::new(rate, burst)));
    }

    if !config.authorized_clients.is_empty() {
        let restricted = builder.restricted_discovery();
        restricted.enabled(true);

        for (nickname, key) in &config.authorized_clients {
            let parsed = nickname
                .parse()
                .map_err(|e| Error::config(format!("invalid client nickname {nickname:?}: {e}")))?;
            restricted
                .static_keys()
                .access()
                .push((parsed, key.clone()));
        }

        info!(
            count = config.authorized_clients.len(),
            "restricted discovery enabled"
        );
    }

    builder
        .build()
        .map_err(|e| Error::config(format!("invalid onion service configuration: {e}")))
}

/// A running onion service.
///
/// Dropping this shuts the service down and unpublishes its descriptor.
pub struct OnionService {
    address: String,
    config: OnionServiceConfig,
    /// Kept alive: dropping it retracts the service.
    _running: Arc<RunningOnionService>,
    /// Kept alive so the service outlives a caller-supplied client going away.
    _tor: Arc<ArtiClient<PreferredRuntime>>,
    incoming: mpsc::Receiver<DataStream>,
    handler: tokio::task::JoinHandle<()>,
}

impl OnionService {
    /// Start building a service.
    pub fn builder() -> OnionServiceBuilder {
        OnionServiceBuilder::new()
    }

    /// The `.onion` address clients use to reach this service.
    pub fn onion_address(&self) -> &str {
        &self.address
    }

    /// The configuration this service was launched with.
    pub fn config(&self) -> &OnionServiceConfig {
        &self.config
    }

    /// Wait for the next inbound stream.
    ///
    /// Returns `None` once the service has shut down.
    pub async fn accept(&mut self) -> Option<DataStream> {
        self.incoming.recv().await
    }
}

impl Drop for OnionService {
    fn drop(&mut self) {
        self.handler.abort();
    }
}

impl std::fmt::Debug for OnionService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnionService")
            .field("nickname", &self.config.nickname)
            .field("port", &self.config.port)
            .finish_non_exhaustive()
    }
}

pin_project_lite::pin_project! {
    /// An inbound connection to an onion service.
    ///
    /// A thin wrapper over arti's [`DataStream`] so callers need not depend on
    /// arti directly.
    pub struct OnionStream {
        #[pin]
        inner: DataStream,
    }
}

impl OnionStream {
    /// Wrap an arti stream.
    pub fn new(inner: DataStream) -> Self {
        Self { inner }
    }

    /// Unwrap back to the arti stream.
    pub fn into_inner(self) -> DataStream {
        self.inner
    }
}

impl AsyncRead for OnionStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl AsyncWrite for OnionStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nicknames_are_validated_eagerly() {
        assert!(OnionServiceBuilder::new().nickname("my-service").is_ok());
        // A bad nickname must fail here, not several seconds into launch().
        assert!(OnionServiceBuilder::new().nickname("").is_err());
        assert!(OnionServiceBuilder::new().nickname("has spaces").is_err());
    }

    #[test]
    fn defaults_are_conservative() {
        let config = OnionServiceConfig::default();
        assert_eq!(config.num_intro_points, 3);
        assert!(!config.proof_of_work);
        // No state directory means an ephemeral address; that must be an
        // explicit choice rather than an accident, and is documented as such.
        assert!(config.state_dir.is_none());
    }

    #[test]
    fn service_config_builds_with_hardening_enabled() {
        let config = OnionServiceConfig {
            nickname: "hardened".into(),
            rate_limit_at_intro: Some((10, 20)),
            num_intro_points: 5,
            max_streams_per_circuit: 100,
            ..Default::default()
        };

        assert!(build_service_config(&config).is_ok());
    }

    #[test]
    fn proof_of_work_requires_its_feature() {
        let config = OnionServiceConfig {
            nickname: "pow".into(),
            proof_of_work: true,
            ..Default::default()
        };

        let result = build_service_config(&config);

        if cfg!(feature = "pow") {
            assert!(result.is_ok(), "the pow feature is on; it must build");
        } else {
            // Launching without the requested defence would be worse than
            // refusing: the operator would believe they were protected.
            let err = result.expect_err("must refuse without the feature");
            assert!(err.to_string().contains("pow"), "unhelpful error: {err}");
        }
    }

    #[test]
    fn intro_point_count_is_validated_by_arti() {
        let config = OnionServiceConfig {
            num_intro_points: 200,
            ..Default::default()
        };
        assert!(build_service_config(&config).is_err());
    }
}
