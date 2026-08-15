//! Hosting onion services.
//!
//! [`OnionService`] wraps arti's onion service provider and hands you a stream
//! of inbound connections. If you want an HTTP server on top of it, use
//! [`OnionApp`](crate::OnionApp), which does exactly that.
//!
//! ```rust,no_run
//! use hypertor::OnionService;
//!
//! # async fn demo() -> hypertor::Result<()> {
//! let mut service = OnionService::builder()
//!     .nickname("my-service")?
//!     .state_dir("/var/lib/my-service")
//!     .port(1234)
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
use tor_cell::relaycell::msg::{Connected, End, EndReason};
use tor_config::ExplicitOrAuto;
use tor_guardmgr::VanguardMode;
use tor_hscrypto::pk::HsClientDescEncKey;
use tor_hsservice::RunningOnionService;
use tor_hsservice::config::TokenBucketConfig;
use tor_proto::stream::IncomingStreamRequest;
use tor_rtcompat::PreferredRuntime;
use tracing::{debug, info, warn};

use crate::error::{Error, Result};

/// How many accepted streams may queue up before backpressure kicks in.
const ACCEPT_QUEUE_DEPTH: usize = 64;

/// Whether an inbound stream request should be served.
///
/// Every other onion service implementation accepts only `BEGIN` messages, and
/// only for the virtual ports it actually publishes. arti's documentation says
/// so in as many words: *"for consistency with other onion service
/// implementations, you should typically only accept BEGIN messages, and only
/// check the port in those messages. If you behave differently, your
/// implementation will be distinguishable."*
///
/// A service that answers on every port is therefore not merely misconfigured —
/// it is fingerprintable, which in a privacy tool is the bug that matters.
fn should_accept(request: &IncomingStreamRequest, ports: &[u16]) -> bool {
    match request {
        IncomingStreamRequest::Begin(begin) => ports.contains(&begin.port()),
        // BEGIN_DIR is for directory requests, which a service does not serve;
        // RESOLVE is an exit-relay function. Neither belongs here.
        _ => false,
    }
}

/// Configuration for an onion service.
///
/// Every option is passed through to arti; hypertor implements no onion service
/// protocol logic of its own.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OnionServiceConfig {
    /// The service nickname, which selects its key material.
    pub nickname: String,
    /// The virtual ports clients may connect to on the `.onion` address.
    ///
    /// A stream requesting any other port is rejected with `END DONE`, which is
    /// what every other onion service implementation does. Answering on all
    /// ports would make the service distinguishable.
    pub ports: Vec<u16>,
    /// Where arti stores keys and other persistent state.
    ///
    /// `None` means arti's own default location for the platform — under
    /// `~/.local/share/arti` on Linux, `~/Library/Application Support/arti` on
    /// macOS — **which is persistent**. Leaving this unset does not give you a
    /// throwaway service: see [`OnionServiceBuilder::state_dir`].
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
            ports: vec![80],
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
    /// **The nickname is the identity.** It selects which key material arti
    /// uses inside the state directory, and therefore which `.onion` address
    /// you get. Two services sharing a nickname and a state directory *are* the
    /// same service as far as the network is concerned — including across
    /// restarts, and including when the state directory is the default one.
    ///
    /// Defaults to `hypertor`, which means two unrelated programs that both
    /// leave it alone will publish the same address on one machine and evict
    /// each other. Pick something specific to your service.
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

    /// The virtual port clients connect to, replacing the default of 80.
    ///
    /// Streams asking for any other port are rejected, as they are by every
    /// other onion service implementation.
    pub fn port(mut self, port: u16) -> Self {
        self.config.ports = vec![port];
        self
    }

    /// Accept several virtual ports.
    ///
    /// Useful when one service answers on, say, both 80 and 443. An empty list
    /// is rejected at launch: a service that accepts nothing can only confuse
    /// whoever deployed it.
    pub fn ports(mut self, ports: impl IntoIterator<Item = u16>) -> Self {
        self.config.ports = ports.into_iter().collect();
        self
    }

    /// Where arti stores keys and persistent state.
    ///
    /// # Your address is already stable without this
    ///
    /// A `.onion` address is derived from a keypair that arti files under the
    /// service [`nickname`](Self::nickname) inside its state directory, and the
    /// default state directory is a persistent per-user one
    /// (`~/.local/share/arti` and equivalents). So a service relaunched with
    /// the same nickname comes back at the **same address** whether or not you
    /// call this.
    ///
    /// What this setting controls is *where* that material lives — which is
    /// what you want for a service that must survive being deployed to a
    /// different machine, or that should not write into the invoking user's
    /// home directory.
    ///
    /// When this builder launches a Tor client of its own, the directory holds
    /// arti's consensus cache as well as its keys, so one path is all a
    /// self-contained deployment has to be told about. Pass an already-built
    /// client to [`on_client`](Self::on_client) to place the two separately;
    /// that client's own storage configuration then governs both, and this
    /// setting is ignored.
    ///
    /// To get a genuinely fresh address, change the nickname or point this at a
    /// directory that does not yet exist. There is no "no state" mode: arti has
    /// to keep the key somewhere for the address to mean anything at all.
    ///
    /// Treat the directory as secret material. Anyone who copies it can
    /// impersonate your service, and there is no revocation.
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
    /// When you supply a client, *that client's* configuration governs
    /// everything to do with the Tor instance itself: storage locations and
    /// vanguards included. [`state_dir`](Self::state_dir) and
    /// [`vanguards`](Self::vanguards) are therefore ignored here, and setting
    /// either alongside this is logged as a warning rather than passed over in
    /// silence — a state directory that is quietly not used is a service at an
    /// address its operator did not expect.
    ///
    /// Everything under [`OnionServiceConfig`] that describes the *service*
    /// rather than the client — the nickname, ports, hardening, authorised
    /// clients — still applies.
    pub fn on_client(mut self, tor: Arc<ArtiClient<PreferredRuntime>>) -> Self {
        self.tor = Some(tor);
        self
    }

    /// Launch the service and publish its descriptor.
    pub async fn launch(self) -> Result<OnionService> {
        // See `TorClientBuilder::build`: arti's own TLS configuration is built
        // during bootstrap, and rustls panics on an ambiguous provider.
        crate::tls::install_crypto_provider();

        let config = self.config;

        let tor = match self.tor {
            Some(tor) => {
                // These configure the Tor client, and the caller supplied one
                // already built. Ignoring them silently is how a service ends
                // up at an address whose key lives somewhere its operator did
                // not intend.
                if config.state_dir.is_some() {
                    warn!(
                        "state_dir is ignored when the onion service runs on a client passed to \
                         on_client; configure storage on that client instead"
                    );
                }
                if config.vanguards.is_some() {
                    warn!(
                        "vanguards is ignored when the onion service runs on a client passed to \
                         on_client; configure vanguards on that client instead"
                    );
                }
                tor
            }
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

        info!(ports = ?config.ports, "onion service published");

        let (tx, rx) = mpsc::channel(ACCEPT_QUEUE_DEPTH);
        let ports = config.ports.clone();

        let handler = tokio::spawn(async move {
            let streams = tor_hsservice::handle_rend_requests(rend_requests);
            tokio::pin!(streams);

            while let Some(request) = streams.next().await {
                if !should_accept(request.request(), &ports) {
                    debug!("rejecting an inbound stream for an unpublished port");
                    // DONE, not MISC: any other reason would set this service
                    // apart from the rest of the network.
                    if let Err(e) = request.reject(End::new_with_reason(EndReason::DONE)).await {
                        debug!(error = %e, "could not reject an inbound stream");
                    }
                    continue;
                }

                // `accept` completes the handshake and returns the bidirectional
                // stream. It can fail for one client without affecting others.
                match request.accept(Connected::new_empty()).await {
                    Ok(stream) => {
                        if tx.send(OnionStream::new(stream)).await.is_err() {
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

    if config.ports.is_empty() {
        return Err(Error::config(
            "an onion service must accept at least one virtual port; \
             every inbound stream would otherwise be rejected",
        ));
    }

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
    incoming: mpsc::Receiver<OnionStream>,
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
    /// Returns `None` once the service has shut down. The stream implements
    /// [`AsyncRead`] and [`AsyncWrite`], so any protocol can be spoken over it.
    pub async fn accept(&mut self) -> Option<OnionStream> {
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
            .field("ports", &self.config.ports)
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
        // `None` defers to arti's own state directory, which is persistent.
        // It does *not* mean the service is ephemeral, and the documentation
        // says so — it claimed the opposite for a long time.
        assert!(config.state_dir.is_none());
    }

    #[test]
    fn the_default_nickname_is_shared_and_that_is_worth_knowing() {
        // Two programs that both leave the nickname alone publish the same
        // address on one machine, because the nickname is what selects the key.
        assert_eq!(OnionServiceConfig::default().nickname, "hypertor");
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

    #[test]
    fn a_service_with_no_ports_is_refused() {
        // It would launch, publish a descriptor, and reject every client.
        let config = OnionServiceConfig {
            ports: Vec::new(),
            ..Default::default()
        };
        assert!(build_service_config(&config).is_err());
    }

    // ---- inbound stream filtering ------------------------------------------

    fn begin(port: u16) -> IncomingStreamRequest {
        IncomingStreamRequest::Begin(
            tor_cell::relaycell::msg::Begin::new("", port, 0).expect("valid begin"),
        )
    }

    #[test]
    fn only_published_ports_are_served() {
        assert!(should_accept(&begin(80), &[80]));
        assert!(should_accept(&begin(443), &[80, 443]));
        assert!(!should_accept(&begin(22), &[80]));
    }

    #[test]
    fn non_begin_requests_are_refused() {
        // A service is not a directory cache and not an exit relay. Answering
        // these would make hypertor's services stand out from every other
        // implementation on the network.
        assert!(!should_accept(
            &IncomingStreamRequest::BeginDir(tor_cell::relaycell::msg::BeginDir::default()),
            &[80]
        ));
    }

    #[test]
    fn the_port_builder_replaces_rather_than_appends() {
        let builder = OnionServiceBuilder::new().port(8080);
        assert_eq!(builder.config.ports, vec![8080]);

        let builder = OnionServiceBuilder::new().ports([80, 443]);
        assert_eq!(builder.config.ports, vec![80, 443]);
    }
}
