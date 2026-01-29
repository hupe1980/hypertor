//! Typed error handling for hypertor
//!
//! All errors are typed using `thiserror` for:
//! - Compile-time error checking
//! - Pattern matching on error variants  
//! - Python exception mapping
//! - Zero panics guarantee

use std::time::Duration;
use thiserror::Error;

/// Result type alias for hypertor operations
pub type Result<T> = std::result::Result<T, Error>;

/// All errors that can occur in hypertor
#[derive(Error, Debug)]
pub enum Error {
    // =========================================================================
    // Tor Network Errors
    // =========================================================================
    /// Failed to bootstrap the Tor client
    #[error("Tor bootstrap failed: {message}")]
    Bootstrap {
        /// Human-readable error message
        message: String,
        /// Underlying arti error
        #[source]
        source: Option<BoxedError>,
    },

    /// Failed to establish connection through Tor
    #[error("Connection to {host}:{port} failed")]
    Connection {
        /// Target hostname
        host: String,
        /// Target port
        port: u16,
        /// Underlying error
        #[source]
        source: BoxedError,
    },

    /// Circuit creation failed
    #[error("Failed to create Tor circuit: {message}")]
    Circuit {
        /// Error details
        message: String,
        /// Underlying error
        #[source]
        source: Option<BoxedError>,
    },

    // =========================================================================
    // TLS Errors
    // =========================================================================
    /// TLS handshake failed
    #[error("TLS handshake failed for {host}")]
    TlsHandshake {
        /// Target hostname
        host: String,
        /// Underlying TLS error
        #[source]
        source: BoxedError,
    },

    /// TLS configuration error
    #[error("TLS configuration error: {message}")]
    TlsConfig {
        /// Error details
        message: String,
    },

    /// Certificate verification failed
    #[error("Certificate verification failed for {host}: {reason}")]
    CertificateVerification {
        /// Target hostname
        host: String,
        /// Reason for failure
        reason: String,
    },

    // =========================================================================
    // HTTP Errors
    // =========================================================================
    /// HTTP protocol error
    #[error("HTTP error: {message}")]
    Http {
        /// Error details
        message: String,
        /// Underlying hyper error
        #[source]
        source: Option<BoxedError>,
    },

    /// Invalid HTTP request
    #[error("Invalid request: {message}")]
    InvalidRequest {
        /// What's wrong with the request
        message: String,
    },

    /// Response body too large
    #[error("Response too large: {size} bytes exceeds limit of {limit} bytes")]
    ResponseTooLarge {
        /// Actual response size
        size: usize,
        /// Configured limit
        limit: usize,
    },

    /// Invalid URL
    #[error("Invalid URL: {url}")]
    InvalidUrl {
        /// The invalid URL
        url: String,
        /// What's wrong with it
        reason: String,
    },

    /// Missing hostname in URL
    #[error("URL missing hostname")]
    MissingHost,

    /// Too many redirects
    #[error("Too many redirects: {count} (limit: {limit})")]
    TooManyRedirects {
        /// Number of redirects followed
        count: u32,
        /// Maximum allowed
        limit: u32,
    },

    // =========================================================================
    // Timeout Errors
    // =========================================================================
    /// Operation timed out
    #[error("{operation} timed out after {duration:?}")]
    Timeout {
        /// What operation timed out
        operation: String,
        /// How long we waited
        duration: Duration,
    },

    /// Connection pool exhausted
    #[error("Connection pool exhausted, max {max_connections} connections")]
    PoolExhausted {
        /// Maximum configured connections
        max_connections: usize,
    },

    // =========================================================================
    // I/O Errors
    // =========================================================================
    /// Generic I/O error
    #[error("I/O error: {message}")]
    Io {
        /// Error context
        message: String,
        /// Underlying I/O error
        #[source]
        source: std::io::Error,
    },

    // =========================================================================
    // Configuration Errors
    // =========================================================================
    /// Invalid configuration
    #[error("Configuration error: {message}")]
    Config {
        /// What's wrong with the configuration
        message: String,
    },

    /// Protocol error (SOCKS5, etc.)
    #[error("Protocol error: {0}")]
    Protocol(String),
}

/// Boxed error for storing heterogeneous error sources
pub type BoxedError = Box<dyn std::error::Error + Send + Sync + 'static>;

impl Error {
    /// Create a bootstrap error
    pub fn bootstrap(message: impl Into<String>) -> Self {
        Self::Bootstrap {
            message: message.into(),
            source: None,
        }
    }

    /// Create a bootstrap error with source
    pub fn bootstrap_with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Bootstrap {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Create a connection error
    pub fn connection(
        host: impl Into<String>,
        port: u16,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Connection {
            host: host.into(),
            port,
            source: Box::new(source),
        }
    }

    /// Create an HTTP error
    pub fn http(message: impl Into<String>) -> Self {
        Self::Http {
            message: message.into(),
            source: None,
        }
    }

    /// Create an HTTP error with source
    pub fn http_with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Http {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Create a TLS handshake error
    pub fn tls_handshake(
        host: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::TlsHandshake {
            host: host.into(),
            source: Box::new(source),
        }
    }

    /// Create a timeout error
    pub fn timeout(operation: impl Into<String>, duration: Duration) -> Self {
        Self::Timeout {
            operation: operation.into(),
            duration,
        }
    }

    /// Create an invalid URL error
    pub fn invalid_url(url: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidUrl {
            url: url.into(),
            reason: reason.into(),
        }
    }

    /// Create an I/O error
    pub fn io(message: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            message: message.into(),
            source,
        }
    }

    /// Create a config error
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config {
            message: message.into(),
        }
    }

    /// Returns true if this error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Error::Connection { .. }
                | Error::Circuit { .. }
                | Error::Timeout { .. }
                | Error::PoolExhausted { .. }
        )
    }

    /// Returns true if this is a timeout error
    pub fn is_timeout(&self) -> bool {
        matches!(self, Error::Timeout { .. })
    }

    /// Returns true if this is a TLS-related error
    pub fn is_tls(&self) -> bool {
        matches!(
            self,
            Error::TlsHandshake { .. }
                | Error::TlsConfig { .. }
                | Error::CertificateVerification { .. }
        )
    }
}

// Conversions from common error types

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Io {
            message: err.to_string(),
            source: err,
        }
    }
}

impl From<http::uri::InvalidUri> for Error {
    fn from(err: http::uri::InvalidUri) -> Self {
        Self::InvalidUrl {
            url: String::new(),
            reason: err.to_string(),
        }
    }
}

impl From<http::Error> for Error {
    fn from(err: http::Error) -> Self {
        Self::Http {
            message: err.to_string(),
            source: Some(Box::new(err)),
        }
    }
}

impl From<hyper::Error> for Error {
    fn from(err: hyper::Error) -> Self {
        Self::Http {
            message: err.to_string(),
            source: Some(Box::new(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_error_is_retryable() {
        let timeout = Error::timeout("request", Duration::from_secs(30));
        assert!(timeout.is_retryable());

        let config = Error::config("bad config");
        assert!(!config.is_retryable());
    }

    #[test]
    fn test_error_display() {
        let err = Error::timeout("connection", Duration::from_secs(10));
        assert_eq!(err.to_string(), "connection timed out after 10s");
    }
}
