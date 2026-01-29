//! Configuration for hypertor client
//!
//! Provides a builder pattern for creating client configurations with
//! security-hardened defaults.

use std::time::Duration;

use crate::error::{Error, Result};
use crate::isolation::IsolationLevel;

/// Client configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// Request timeout
    pub timeout: Duration,
    /// Maximum number of pooled connections
    pub max_connections: usize,
    /// Maximum response body size (DoS protection)
    pub max_response_size: usize,
    /// Stream isolation level
    pub isolation: IsolationLevel,
    /// Security configuration
    pub security: SecurityConfig,
    /// User-Agent header (uses Tor Browser's by default for anonymity)
    pub user_agent: String,
    /// Whether to follow HTTP redirects
    pub follow_redirects: bool,
    /// Maximum number of redirects to follow
    pub max_redirects: u8,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            // Reasonable timeout for Tor latency
            timeout: Duration::from_secs(30),
            // Connection pool size
            max_connections: 10,
            // 10MB max response (DoS protection)
            max_response_size: 10 * 1024 * 1024,
            // Default isolation
            isolation: IsolationLevel::None,
            // Security defaults
            security: SecurityConfig::default(),
            // Tor Browser User-Agent for anonymity set
            user_agent: "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"
                .to_string(),
            // Redirects off by default (security)
            follow_redirects: false,
            max_redirects: 5,
        }
    }
}

impl Config {
    /// Create a new configuration builder
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::new()
    }
}

/// Security-specific configuration
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Strip Referer header to prevent privacy leaks
    pub strip_referer: bool,
    /// Verify TLS certificates
    pub verify_tls: bool,
    /// Minimum TLS version
    pub min_tls_version: TlsVersion,
    /// Allowed TLS cipher suites (empty = all secure defaults)
    pub cipher_suites: Vec<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            strip_referer: true,
            verify_tls: true,
            min_tls_version: TlsVersion::Tls12,
            cipher_suites: Vec::new(),
        }
    }
}

/// Minimum TLS version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    /// TLS 1.2
    Tls12,
    /// TLS 1.3
    Tls13,
}

/// Builder for client configuration
#[derive(Debug, Clone)]
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    /// Create a new builder with default values
    pub fn new() -> Self {
        Self {
            config: Config::default(),
        }
    }

    /// Set the request timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.config.timeout = timeout;
        self
    }

    /// Set the maximum number of pooled connections
    pub fn max_connections(mut self, max: usize) -> Self {
        self.config.max_connections = max;
        self
    }

    /// Set the maximum response body size
    pub fn max_response_size(mut self, size: usize) -> Self {
        self.config.max_response_size = size;
        self
    }

    /// Set the stream isolation level
    pub fn isolation(mut self, level: IsolationLevel) -> Self {
        self.config.isolation = level;
        self
    }

    /// Set the User-Agent header
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.config.user_agent = ua.into();
        self
    }

    /// Enable or disable following redirects
    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.config.follow_redirects = follow;
        self
    }

    /// Set the maximum number of redirects to follow
    pub fn max_redirects(mut self, max: u8) -> Self {
        self.config.max_redirects = max;
        self
    }

    /// Strip Referer header from requests
    pub fn strip_referer(mut self, strip: bool) -> Self {
        self.config.security.strip_referer = strip;
        self
    }

    /// Enable or disable TLS certificate verification
    ///
    /// # Warning
    /// Disabling this is a security risk and should only be done for testing
    pub fn verify_tls(mut self, verify: bool) -> Self {
        self.config.security.verify_tls = verify;
        self
    }

    /// Set the minimum TLS version
    pub fn min_tls_version(mut self, version: TlsVersion) -> Self {
        self.config.security.min_tls_version = version;
        self
    }

    /// Build the configuration
    pub fn build(self) -> Result<Config> {
        // Validate configuration
        if self.config.timeout.is_zero() {
            return Err(Error::config("timeout cannot be zero"));
        }
        if self.config.max_connections == 0 {
            return Err(Error::config("max_connections must be at least 1"));
        }
        if self.config.max_response_size == 0 {
            return Err(Error::config("max_response_size must be at least 1"));
        }

        Ok(self.config)
    }
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.max_connections, 10);
        assert!(!config.follow_redirects);
        assert!(config.security.verify_tls);
    }

    #[test]
    fn test_builder() {
        let config = Config::builder()
            .timeout(Duration::from_secs(60))
            .max_connections(20)
            .follow_redirects(true)
            .build()
            .expect("config should be valid");

        assert_eq!(config.timeout, Duration::from_secs(60));
        assert_eq!(config.max_connections, 20);
        assert!(config.follow_redirects);
    }

    #[test]
    fn test_builder_validation() {
        let result = Config::builder().max_connections(0).build();
        assert!(result.is_err());
    }
}
