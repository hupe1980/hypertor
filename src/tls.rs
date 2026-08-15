//! TLS for clearnet targets reached through a Tor exit relay.
//!
//! # Why rustls is the default
//!
//! TLS handshakes are fingerprintable. The set and ordering of cipher suites,
//! extensions, supported groups and signature algorithms differ per
//! implementation, so the TLS stack you use is visible to the exit relay and to
//! anyone watching it.
//!
//! `native-tls` binds to whatever the host provides — OpenSSL on Linux,
//! SecureTransport on macOS, SChannel on Windows — so the handshake announces
//! your operating system. With `rustls` every hypertor user emits the same
//! ClientHello regardless of platform, which is the whole point.
//!
//! # Post-quantum key exchange
//!
//! The provider is `aws-lc-rs`, whose defaults lead with the `X25519MLKEM768`
//! hybrid key exchange: classical X25519 combined with ML-KEM-768, so the
//! session key is safe unless *both* are broken. That matters more here than in
//! most places. "Harvest now, decrypt later" — record traffic today, decrypt it
//! when a cryptographically relevant quantum computer exists — is an adversary
//! with exactly the resources and the patience to be interested in the people
//! who route their traffic over Tor.
//!
//! `ring`, which hypertor previously forced, implements no post-quantum group
//! at all. Using it silently gave up this property.
//!
//! # Session resumption is partitioned by isolation group
//!
//! rustls enables TLS session resumption by default. Left shared, that quietly
//! undoes [`IsolationLevel`](crate::IsolationLevel): two requests placed on
//! deliberately different circuits would still present the *same* session
//! ticket to the server, which can then link them however carefully the
//! network layer kept them apart.
//!
//! Every isolation group therefore gets its own session store, and a
//! single-use group ([`IsolationLevel::PerRequest`](crate::IsolationLevel))
//! disables resumption outright, since a connection used once can never benefit
//! from it. The isolation group *is* the boundary within which linkage is
//! something you already accepted.
//!
//! # This does not apply to `.onion`
//!
//! Onion connections are already end-to-end encrypted and authenticated by the
//! rendezvous protocol, and the address is itself the service's public key.
//! hypertor therefore does not wrap `.onion` targets in TLS unless the URL says
//! `https://` explicitly.

#[cfg(any(feature = "rustls", feature = "native-tls"))]
use std::sync::Arc;

use arti_client::DataStream;

use crate::config::TlsConfig;
#[cfg(any(feature = "rustls", feature = "native-tls"))]
use crate::config::TlsVersion;
use crate::error::{Error, Result};
use crate::stream::TorStream;

/// How many server names one isolation group remembers sessions for.
///
/// rustls's own default. The store is per isolation group rather than per
/// process, so this bounds each group individually.
#[cfg(feature = "rustls")]
const SESSION_CACHE_SIZE: usize = 256;

/// ALPN protocol identifiers, most preferred first.
#[cfg(feature = "rustls")]
const ALPN_H2_HTTP11: &[&[u8]] = &[b"h2", b"http/1.1"];
#[cfg(feature = "rustls")]
const ALPN_HTTP11: &[&[u8]] = &[b"http/1.1"];

/// Select the process-wide rustls cryptography provider.
///
/// hypertor uses **aws-lc-rs**, which is rustls's own default and the provider
/// arti already uses for Tor link TLS — so one process speaks one cryptographic
/// stack rather than two. It also leads with the `X25519MLKEM768` hybrid key
/// exchange, which `ring` does not implement at all; see the module
/// documentation on post-quantum key exchange.
///
/// rustls can only infer a provider when exactly one is compiled in, and
/// *panics* otherwise — the first time anything builds a TLS configuration,
/// which for hypertor is during `TorClient::new()`. hypertor's own dependencies
/// resolve to aws-lc-rs alone, but it is a library: an application that pulls
/// rustls's `ring` feature in from somewhere else would reintroduce the
/// ambiguity and take that panic in *its* build, at runtime, for a reason with
/// nothing to do with its own code. Installing explicitly costs a `Once` and
/// removes that failure mode.
///
/// Idempotent, and safe to race: a provider installed by the surrounding
/// application wins, and hypertor does not fight it.
pub fn install_crypto_provider() {
    #[cfg(feature = "rustls")]
    {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }
}

/// A prepared TLS client configuration.
///
/// Building this is expensive — it reads and parses the entire system trust
/// store — so it is built once per [`TorClient`](crate::TorClient) and shared by
/// every connection. The previous behaviour, reloading the root store on each
/// request, cost tens of milliseconds and hundreds of allocations per
/// connection.
#[derive(Clone)]
pub struct TlsConnector {
    #[cfg(feature = "rustls")]
    inner: Arc<tokio_rustls::rustls::ClientConfig>,
    /// Whether this connector may resume TLS sessions at all.
    ///
    /// Carried alongside the config because rustls exposes no way to read the
    /// setting back off one.
    #[cfg(feature = "rustls")]
    resumption: bool,
    #[cfg(all(feature = "native-tls", not(feature = "rustls")))]
    inner: Arc<tokio_native_tls::TlsConnector>,
    #[cfg(not(any(feature = "rustls", feature = "native-tls")))]
    inner: std::marker::PhantomData<()>,
}

impl std::fmt::Debug for TlsConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConnector").finish_non_exhaustive()
    }
}

impl TlsConnector {
    /// Build a connector from the given configuration.
    ///
    /// Fails if no TLS backend is compiled in, or if the system trust store
    /// cannot be read while certificate verification is enabled — failing loudly
    /// here is far better than failing on every later handshake with an opaque
    /// "unknown issuer".
    pub fn new(config: &TlsConfig) -> Result<Self> {
        #[cfg(feature = "rustls")]
        {
            Ok(Self {
                inner: Arc::new(build_rustls_config(config)?),
                resumption: config.session_resumption,
            })
        }

        #[cfg(all(feature = "native-tls", not(feature = "rustls")))]
        {
            Ok(Self {
                inner: Arc::new(build_native_tls_config(config)?),
            })
        }

        #[cfg(not(any(feature = "rustls", feature = "native-tls")))]
        {
            let _ = config;
            Err(Error::tls(
                "no TLS backend compiled in; enable the `rustls` or `native-tls` feature",
            ))
        }
    }

    /// A connector with the same certificate configuration but its own TLS
    /// session-resumption store.
    ///
    /// Sharing a store across isolation groups would let a server link two
    /// requests that were deliberately placed on different circuits: the second
    /// connection presents a ticket the first was issued. The expensive part of
    /// a connector is parsing the system trust store, and that is shared here
    /// via `Arc` — only the session cache is new.
    #[cfg_attr(not(feature = "client"), allow(dead_code))]
    pub(crate) fn with_separate_session_cache(&self) -> Self {
        #[cfg(feature = "rustls")]
        {
            if !self.resumption {
                // Already resuming nothing; a second empty store adds nothing.
                return self.clone();
            }

            let mut config = (*self.inner).clone();
            config.resumption =
                tokio_rustls::rustls::client::Resumption::in_memory_sessions(SESSION_CACHE_SIZE);
            Self {
                inner: Arc::new(config),
                resumption: true,
            }
        }

        #[cfg(not(feature = "rustls"))]
        {
            // native-tls exposes no session cache to partition. It also does not
            // resume sessions on its own, so there is nothing to separate.
            self.clone()
        }
    }

    /// A connector that will not resume a TLS session at all.
    ///
    /// Used for a connection that is made once and discarded, where resumption
    /// could never pay off and storing a ticket only creates something for a
    /// later connection to be correlated by.
    #[cfg_attr(not(feature = "client"), allow(dead_code))]
    pub(crate) fn without_session_resumption(&self) -> Self {
        #[cfg(feature = "rustls")]
        {
            let mut config = (*self.inner).clone();
            config.resumption = tokio_rustls::rustls::client::Resumption::disabled();
            Self {
                inner: Arc::new(config),
                resumption: false,
            }
        }

        #[cfg(not(feature = "rustls"))]
        {
            self.clone()
        }
    }

    /// Perform a TLS handshake over an established Tor stream.
    ///
    /// `host` is used for SNI and certificate verification. It must be the name
    /// from the URL, never an IP address resolved locally — resolving locally
    /// would leak the destination outside Tor.
    pub async fn connect(&self, stream: DataStream, host: &str) -> Result<TorStream> {
        #[cfg(feature = "rustls")]
        {
            use tokio_rustls::rustls::pki_types::ServerName;

            let server_name = ServerName::try_from(host.to_owned()).map_err(|_| {
                Error::invalid_url(format!("{host} is not a valid TLS server name"))
            })?;

            let connector = tokio_rustls::TlsConnector::from(Arc::clone(&self.inner));
            let tls = connector
                .connect(server_name, stream)
                .await
                .map_err(|e| Error::tls_handshake(host, e))?;

            Ok(TorStream::rustls(tls))
        }

        #[cfg(all(feature = "native-tls", not(feature = "rustls")))]
        {
            let tls = self
                .inner
                .connect(host, stream)
                .await
                .map_err(|e| Error::tls_handshake(host, e))?;

            Ok(TorStream::native_tls(tls))
        }

        #[cfg(not(any(feature = "rustls", feature = "native-tls")))]
        {
            let _ = (stream, host);
            Err(Error::tls("no TLS backend compiled in"))
        }
    }
}

#[cfg(feature = "rustls")]
fn build_rustls_config(config: &TlsConfig) -> Result<tokio_rustls::rustls::ClientConfig> {
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};

    install_crypto_provider();

    let versions: &[&tokio_rustls::rustls::SupportedProtocolVersion] = match config.min_version {
        TlsVersion::Tls12 => tokio_rustls::rustls::ALL_VERSIONS,
        TlsVersion::Tls13 => &[&tokio_rustls::rustls::version::TLS13],
    };

    let builder = ClientConfig::builder_with_protocol_versions(versions);

    let mut tls = if config.verify_certificates {
        let mut roots = RootCertStore::empty();
        let loaded = rustls_native_certs::load_native_certs();

        for cert in loaded.certs {
            // Individual malformed certificates in a system store are common and
            // not fatal; an empty store afterwards is.
            let _ = roots.add(cert);
        }

        if roots.is_empty() {
            let detail = loaded
                .errors
                .first()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "the store contained no usable certificates".to_string());
            return Err(Error::tls(format!(
                "could not load any trusted root certificates from the system store: {detail}"
            )));
        }

        builder.with_root_certificates(roots).with_no_client_auth()
    } else {
        // Explicitly opted into by `danger_accept_invalid_certs`.
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(danger::NoVerification::new()))
            .with_no_client_auth()
    };

    if !config.session_resumption {
        tls.resumption = tokio_rustls::rustls::client::Resumption::disabled();
    }

    tls.alpn_protocols = if config.alpn_h2 {
        ALPN_H2_HTTP11
    } else {
        ALPN_HTTP11
    }
    .iter()
    .map(|p| p.to_vec())
    .collect();

    Ok(tls)
}

/// Certificate verification bypass, reachable only through
/// [`ConfigBuilder::danger_accept_invalid_certs`](crate::ConfigBuilder::danger_accept_invalid_certs).
#[cfg(feature = "rustls")]
mod danger {
    use tokio_rustls::rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use tokio_rustls::rustls::crypto::{
        CryptoProvider, verify_tls12_signature, verify_tls13_signature,
    };
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use tokio_rustls::rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    pub(super) struct NoVerification(CryptoProvider);

    impl NoVerification {
        pub(super) fn new() -> Self {
            Self(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider())
        }
    }

    impl ServerCertVerifier for NoVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
}

#[cfg(all(feature = "native-tls", not(feature = "rustls")))]
fn build_native_tls_config(config: &TlsConfig) -> Result<tokio_native_tls::TlsConnector> {
    use tokio_native_tls::native_tls::{Protocol, TlsConnector as NativeConnector};

    let mut builder = NativeConnector::builder();

    // native-tls exposes no TLS 1.3 floor. Silently accepting 1.2 when the
    // caller asked for 1.3 would be a downgrade they never agreed to, so refuse.
    match config.min_version {
        TlsVersion::Tls12 => {
            builder.min_protocol_version(Some(Protocol::Tlsv12));
        }
        TlsVersion::Tls13 => {
            return Err(Error::tls(
                "the native-tls backend cannot enforce a TLS 1.3 floor; \
                 build with the `rustls` feature to require TLS 1.3",
            ));
        }
    }

    if !config.verify_certificates {
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);
    }

    // native-tls offers no ALPN control, so HTTP/2 over TLS is unavailable here.
    let connector = builder
        .build()
        .map_err(|e| Error::tls(format!("could not build native-tls connector: {e}")))?;

    Ok(tokio_native_tls::TlsConnector::from(connector))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "rustls")]
    fn connector_builds_from_the_system_trust_store() {
        let connector = TlsConnector::new(&TlsConfig::default());
        assert!(
            connector.is_ok(),
            "default TLS config must build: {:?}",
            connector.err()
        );
    }

    #[test]
    #[cfg(feature = "rustls")]
    fn post_quantum_key_exchange_is_offered_by_default() {
        // "Harvest now, decrypt later" is an adversary with exactly the
        // resources and the patience to be interested in Tor users. `ring`,
        // which hypertor used to force, implements no post-quantum group at
        // all — so this asserts the provider choice, not just the config.
        let config = build_rustls_config(&TlsConfig::default()).expect("builds");

        let names: Vec<String> = config
            .crypto_provider()
            .kx_groups
            .iter()
            .map(|g| format!("{:?}", g.name()))
            .collect();

        assert!(
            names.iter().any(|n| n.contains("MLKEM")),
            "no post-quantum key exchange on offer: {names:?}"
        );
    }

    #[test]
    #[cfg(feature = "rustls")]
    fn each_isolation_group_gets_its_own_session_store() {
        // Sharing a resumption store across isolation groups hands a server the
        // link that circuit isolation was there to prevent: the second
        // connection presents a ticket the first was issued.
        let base = TlsConnector::new(&TlsConfig::default()).expect("builds");
        let a = base.with_separate_session_cache();
        let b = base.with_separate_session_cache();

        // rustls keeps the store inside `Resumption`, which is opaque. What is
        // observable is that each group holds its own `ClientConfig`, and
        // `Resumption::in_memory_sessions` builds a fresh store every time it is
        // called — so distinct configs here mean distinct stores.
        assert!(
            !Arc::ptr_eq(&a.inner, &b.inner),
            "two isolation groups shared one TLS configuration, and therefore \
             one session store"
        );
        assert!(
            !Arc::ptr_eq(&a.inner, &base.inner),
            "a group shared the default group's TLS configuration"
        );
    }

    #[test]
    #[cfg(feature = "rustls")]
    fn separate_groups_still_share_the_expensive_trust_store() {
        // Partitioning must not mean re-parsing the system roots per group.
        let base = TlsConnector::new(&TlsConfig::default()).expect("builds");
        let a = base.with_separate_session_cache();

        assert!(
            Arc::ptr_eq(a.inner.crypto_provider(), base.inner.crypto_provider()),
            "the crypto provider was rebuilt per isolation group"
        );
        assert_eq!(
            a.inner.alpn_protocols, base.inner.alpn_protocols,
            "partitioning must not change what is negotiated"
        );
    }

    #[test]
    #[cfg(feature = "rustls")]
    fn a_single_use_group_resumes_nothing() {
        // A connection made once cannot benefit from a stored ticket, and the
        // ticket would only be something for a later connection to be
        // correlated by.
        let base = TlsConnector::new(&TlsConfig::default()).expect("builds");
        let once = base.without_session_resumption();

        assert!(!once.resumption, "a single-use connector may not resume");
        assert!(
            !Arc::ptr_eq(&once.inner, &base.inner),
            "the single-use connector reused the shared configuration"
        );
    }

    #[test]
    #[cfg(feature = "rustls")]
    fn resumption_can_be_turned_off_entirely() {
        let config = TlsConfig {
            session_resumption: false,
            ..Default::default()
        };
        let connector = TlsConnector::new(&config).expect("builds");

        assert!(!connector.resumption);
        // Partitioning something that stores nothing is a no-op, not a bug: the
        // configuration is reused rather than needlessly cloned.
        let partitioned = connector.with_separate_session_cache();
        assert!(!partitioned.resumption);
        assert!(Arc::ptr_eq(&partitioned.inner, &connector.inner));
    }

    #[test]
    #[cfg(feature = "rustls")]
    fn early_data_is_never_enabled() {
        // TLS 1.3 0-RTT data is replayable by anyone who observes it.
        let config = build_rustls_config(&TlsConfig::default()).expect("builds");
        assert!(!config.enable_early_data);
    }

    #[test]
    #[cfg(feature = "rustls")]
    fn key_material_is_not_logged() {
        // rustls only writes SSLKEYLOGFILE when asked. For a privacy library,
        // never asking is the whole point.
        let config = build_rustls_config(&TlsConfig::default()).expect("builds");
        assert!(
            !format!("{:?}", config.key_log).contains("KeyLogFile"),
            "a key log was installed"
        );
    }

    #[test]
    #[cfg(feature = "rustls")]
    fn alpn_advertises_h2_only_when_enabled() {
        let with_h2 = build_rustls_config(&TlsConfig::default()).expect("builds");
        assert_eq!(
            with_h2.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );

        let config = TlsConfig {
            alpn_h2: false,
            ..Default::default()
        };
        let without = build_rustls_config(&config).expect("builds");
        assert_eq!(without.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    #[cfg(all(feature = "native-tls", not(feature = "rustls")))]
    fn native_tls_refuses_to_pretend_it_can_enforce_tls13() {
        let config = TlsConfig {
            min_version: TlsVersion::Tls13,
            ..Default::default()
        };
        assert!(TlsConnector::new(&config).is_err());
    }
}
