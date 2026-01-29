//! TLS abstraction layer
//!
//! Provides a unified interface for TLS operations regardless of the
//! underlying TLS implementation (native-tls or rustls).
//!
//! # Security Considerations
//!
//! **rustls is strongly recommended** for anonymity-focused applications:
//!
//! | Threat | native-tls | rustls |
//! |--------|------------|--------|
//! | TLS Fingerprinting | Different per OS | Consistent |
//! | Compromised System CAs | Vulnerable | Controllable |
//! | Memory Safety | C libraries | Pure Rust |
//! | Platform Bugs | Common (esp. macOS) | Rare |
//!
//! The default is `rustls` to minimize fingerprinting and maximize safety.

use arti_client::DataStream;

use crate::config::TlsVersion;
use crate::error::{Error, Result};
use crate::stream::TorStream;

/// TLS connector configuration
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Verify server certificates
    pub verify_certificates: bool,
    /// Minimum TLS version
    pub min_version: TlsVersion,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            verify_certificates: true,
            min_version: TlsVersion::Tls12,
        }
    }
}

/// Perform TLS handshake using native-tls
#[cfg(all(feature = "native-tls", not(feature = "rustls")))]
pub async fn wrap_tls_native(
    stream: DataStream,
    host: &str,
    config: &TlsConfig,
) -> Result<TorStream> {
    use tokio_native_tls::TlsConnector;
    use tokio_native_tls::native_tls::{Protocol, TlsConnector as NativeTlsConnector};

    let mut builder = NativeTlsConnector::builder();

    // Set minimum protocol version
    let min_protocol = match config.min_version {
        TlsVersion::Tls12 => Protocol::Tlsv12,
        TlsVersion::Tls13 => Protocol::Tlsv12, // native-tls auto-negotiates to 1.3
    };
    builder.min_protocol_version(Some(min_protocol));

    // Configure certificate verification
    if !config.verify_certificates {
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);
    }

    let connector = builder.build().map_err(|e| Error::TlsConfig {
        message: e.to_string(),
    })?;

    let connector = TlsConnector::from(connector);

    // Add timeout to TLS handshake - Tor streams can be slow
    let tls_handshake = connector.connect(host, stream);
    let tls_stream = tokio::time::timeout(std::time::Duration::from_secs(30), tls_handshake)
        .await
        .map_err(|_| Error::TlsConfig {
            message: format!("TLS handshake timed out for {}", host),
        })?
        .map_err(|e| Error::tls_handshake(host, e))?;

    Ok(TorStream::native_tls(tls_stream))
}

/// Perform TLS handshake using rustls
#[cfg(feature = "rustls")]
pub async fn wrap_tls_rustls(
    stream: DataStream,
    host: &str,
    _config: &TlsConfig,
) -> Result<TorStream> {
    use std::sync::Arc;
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::ClientConfig;
    use tokio_rustls::rustls::RootCertStore;
    use tokio_rustls::rustls::crypto::ring::default_provider;
    use tokio_rustls::rustls::pki_types::ServerName;

    // Install the ring crypto provider (safe to call multiple times - it's idempotent)
    let _ = default_provider().install_default();

    // Load native root certificates
    let mut root_store = RootCertStore::empty();
    let certs_result = rustls_native_certs::load_native_certs();
    for cert in certs_result.certs {
        let _ = root_store.add(cert);
    }

    // Create rustls config
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| Error::invalid_url(host, "invalid hostname for TLS"))?;

    // Add timeout to TLS handshake
    let tls_handshake = connector.connect(server_name, stream);
    let tls_stream = tokio::time::timeout(std::time::Duration::from_secs(30), tls_handshake)
        .await
        .map_err(|_| Error::TlsConfig {
            message: format!("TLS handshake timed out for {}", host),
        })?
        .map_err(|e| Error::tls_handshake(host, e))?;

    Ok(TorStream::rustls(tls_stream))
}

/// Wrap a stream in TLS using the configured backend
///
/// # Backend Priority
///
/// If both backends are enabled, **rustls takes priority** for security:
/// - Consistent TLS fingerprint across all platforms
/// - Pure Rust implementation (memory-safe)
/// - Not affected by system CA store compromise
pub async fn wrap_tls(stream: DataStream, host: &str, config: &TlsConfig) -> Result<TorStream> {
    // SECURITY: Prefer rustls over native-tls when both are enabled
    // rustls provides consistent fingerprinting and is memory-safe
    #[cfg(feature = "rustls")]
    {
        return wrap_tls_rustls(stream, host, config).await;
    }

    #[cfg(all(feature = "native-tls", not(feature = "rustls")))]
    {
        return wrap_tls_native(stream, host, config).await;
    }

    #[cfg(not(any(feature = "native-tls", feature = "rustls")))]
    {
        let _ = (stream, host, config);
        Err(Error::TlsConfig {
            message: "No TLS backend enabled. Enable 'native-tls' or 'rustls' feature.".to_string(),
        })
    }
}
