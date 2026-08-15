//! Client configuration.
//!
//! Every field here is read by the client at runtime. If an option exists, it
//! does something.

use std::time::Duration;

use crate::error::{Error, Result};
use crate::isolation::IsolationLevel;
use crate::redirect::RedirectPolicy;

/// The User-Agent hypertor sends by default.
///
/// This matches the Tor Browser's User-Agent so that hypertor requests blend
/// into the largest available anonymity set rather than announcing themselves.
///
/// Tor Browser is built on the Firefox Extended Support Release, and its
/// User-Agent changes roughly once a year when a new ESR ships. If you are
/// building something long-lived, pin your own value with
/// [`ConfigBuilder::user_agent`] and update it deliberately — a stale default
/// is more identifying than a current one.
pub const DEFAULT_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0";

/// Client configuration.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Config {
    /// Deadline for a whole request, including circuit setup and redirects.
    pub timeout: Duration,
    /// Deadline for opening one Tor stream and completing its TLS handshake.
    pub connect_timeout: Duration,
    /// Maximum idle connections kept alive per destination host.
    pub pool_max_idle_per_host: usize,
    /// How long an idle pooled connection is kept before being closed.
    pub pool_idle_timeout: Duration,
    /// Maximum response body size accepted, in bytes.
    ///
    /// Enforced *while streaming*, so an oversized body is aborted rather than
    /// buffered. Also applied to the decompressed size, which bounds
    /// decompression bombs.
    pub max_response_size: usize,
    /// Circuit isolation strategy.
    pub isolation: IsolationLevel,
    /// The User-Agent to send. Defaults to [`DEFAULT_USER_AGENT`].
    pub user_agent: String,
    /// How redirects are handled.
    pub redirect: RedirectPolicy,
    /// Number of times a failed request is retried on a fresh circuit.
    ///
    /// Only failures for which [`Error::is_retryable`](crate::Error::is_retryable)
    /// holds are retried, and only for idempotent requests.
    pub max_retries: u32,
    /// Whether to accept and transparently decode compressed responses.
    pub compression: bool,
    /// TLS behaviour.
    pub tls: TlsConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            // Tor adds several hundred ms per hop; 30 s is generous for a
            // request on an established circuit and tolerable for a cold one.
            timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(60),
            pool_max_idle_per_host: 4,
            pool_idle_timeout: Duration::from_secs(90),
            max_response_size: 16 * 1024 * 1024,
            isolation: IsolationLevel::default(),
            user_agent: DEFAULT_USER_AGENT.to_string(),
            redirect: RedirectPolicy::default(),
            max_retries: 2,
            compression: true,
            tls: TlsConfig::default(),
        }
    }
}

impl Config {
    /// Start building a configuration.
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }
}

/// TLS behaviour for clearnet (`https://`) targets.
///
/// This does not apply to `.onion` addresses: connections to an onion service
/// are end-to-end encrypted and authenticated by the Tor rendezvous protocol
/// itself, and the `.onion` name *is* the public key.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TlsConfig {
    /// Verify server certificates against the system trust store.
    ///
    /// Disabling this makes every `https://` connection trivially
    /// interceptable by the exit relay. It exists for testing against local
    /// services with self-signed certificates and nothing else.
    pub verify_certificates: bool,
    /// Lowest acceptable TLS version.
    pub min_version: TlsVersion,
    /// Offer HTTP/2 via ALPN, falling back to HTTP/1.1.
    pub alpn_h2: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            verify_certificates: true,
            // TLS 1.2 is the floor. 1.3 is negotiated whenever the peer
            // supports it; requiring it outright still breaks a meaningful
            // slice of the long tail.
            min_version: TlsVersion::Tls12,
            alpn_h2: true,
        }
    }
}

/// Minimum acceptable TLS version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum TlsVersion {
    /// TLS 1.2.
    #[default]
    Tls12,
    /// TLS 1.3 only.
    Tls13,
}

/// Builder for [`Config`].
#[derive(Debug, Clone, Default)]
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    /// Deadline for a whole request, including circuit setup and redirects.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.config.timeout = timeout;
        self
    }

    /// Deadline for opening one Tor stream and completing its TLS handshake.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.config.connect_timeout = timeout;
        self
    }

    /// Maximum idle connections kept alive per destination host.
    pub fn pool_max_idle_per_host(mut self, max: usize) -> Self {
        self.config.pool_max_idle_per_host = max;
        self
    }

    /// How long an idle pooled connection is kept before being closed.
    pub fn pool_idle_timeout(mut self, timeout: Duration) -> Self {
        self.config.pool_idle_timeout = timeout;
        self
    }

    /// Maximum response body size accepted, in bytes.
    pub fn max_response_size(mut self, size: usize) -> Self {
        self.config.max_response_size = size;
        self
    }

    /// Circuit isolation strategy.
    pub fn isolation(mut self, level: IsolationLevel) -> Self {
        self.config.isolation = level;
        self
    }

    /// The User-Agent to send.
    ///
    /// Changing this away from [`DEFAULT_USER_AGENT`] shrinks your anonymity
    /// set. Do it when you are talking to an API that requires it, not by
    /// default.
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.config.user_agent = ua.into();
        self
    }

    /// How redirects are handled.
    pub fn redirect(mut self, policy: RedirectPolicy) -> Self {
        self.config.redirect = policy;
        self
    }

    /// Number of retries on a fresh circuit for retryable failures.
    pub fn max_retries(mut self, retries: u32) -> Self {
        self.config.max_retries = retries;
        self
    }

    /// Whether to accept and transparently decode compressed responses.
    pub fn compression(mut self, enabled: bool) -> Self {
        self.config.compression = enabled;
        self
    }

    /// Lowest acceptable TLS version for `https://` targets.
    pub fn min_tls_version(mut self, version: TlsVersion) -> Self {
        self.config.tls.min_version = version;
        self
    }

    /// Offer HTTP/2 via ALPN for `https://` targets.
    pub fn http2(mut self, enabled: bool) -> Self {
        self.config.tls.alpn_h2 = enabled;
        self
    }

    /// Disable TLS certificate verification.
    ///
    /// # Warning
    ///
    /// This makes every `https://` connection interceptable by the exit relay,
    /// which is an untrusted party by design. Only use it against local test
    /// servers.
    pub fn danger_accept_invalid_certs(mut self, accept: bool) -> Self {
        self.config.tls.verify_certificates = !accept;
        self
    }

    /// Validate and produce the [`Config`].
    pub fn build(self) -> Result<Config> {
        let c = &self.config;
        if c.timeout.is_zero() {
            return Err(Error::config("timeout must be greater than zero"));
        }
        if c.connect_timeout.is_zero() {
            return Err(Error::config("connect_timeout must be greater than zero"));
        }
        if c.max_response_size == 0 {
            return Err(Error::config(
                "max_response_size must be greater than zero; \
                 use a large value rather than 0 to mean 'unlimited'",
            ));
        }
        if c.user_agent.is_empty() {
            return Err(Error::config("user_agent must not be empty"));
        }
        if http::HeaderValue::from_str(&c.user_agent).is_err() {
            return Err(Error::config(
                "user_agent contains characters that are not valid in an HTTP header",
            ));
        }
        Ok(self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let c = Config::default();
        assert!(c.tls.verify_certificates);
        assert!(c.compression);
        assert_eq!(c.user_agent, DEFAULT_USER_AGENT);
        // Redirects are followed by default, matching every other HTTP client.
        assert!(c.redirect.is_enabled());
    }

    #[test]
    fn zero_values_are_rejected() {
        assert!(Config::builder().timeout(Duration::ZERO).build().is_err());
        assert!(Config::builder().max_response_size(0).build().is_err());
        assert!(Config::builder().user_agent("").build().is_err());
    }

    #[test]
    fn user_agent_with_control_characters_is_rejected() {
        assert!(
            Config::builder()
                .user_agent("evil\r\nX-Injected: 1")
                .build()
                .is_err()
        );
    }

    #[test]
    fn builder_round_trips() {
        let c = Config::builder()
            .timeout(Duration::from_secs(90))
            .max_retries(5)
            .compression(false)
            .build()
            .expect("valid config");
        assert_eq!(c.timeout, Duration::from_secs(90));
        assert_eq!(c.max_retries, 5);
        assert!(!c.compression);
    }
}
