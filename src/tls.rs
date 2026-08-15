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
//! # This does not apply to `.onion`
//!
//! Onion connections are already end-to-end encrypted and authenticated by the
//! rendezvous protocol, and the address is itself the service's public key.
//! hypertor therefore does not wrap `.onion` targets in TLS unless the URL says
//! `https://` explicitly.

use std::sync::Arc;

use arti_client::DataStream;

use crate::config::{TlsConfig, TlsVersion};
use crate::error::{Error, Result};
use crate::stream::TorStream;

/// ALPN protocol identifiers, most preferred first.
#[cfg(feature = "rustls")]
const ALPN_H2_HTTP11: &[&[u8]] = &[b"h2", b"http/1.1"];
#[cfg(feature = "rustls")]
const ALPN_HTTP11: &[&[u8]] = &[b"http/1.1"];

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

    // rustls requires a process-wide crypto provider. Installing is idempotent
    // and racing installs are harmless, so an already-installed provider (from
    // another library in the same process) is not an error.
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

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
            Self(tokio_rustls::rustls::crypto::ring::default_provider())
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
