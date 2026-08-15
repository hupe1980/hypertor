//! Typed errors for hypertor.
//!
//! Every fallible operation returns [`enum@Error`], a `thiserror` enum you can match
//! on. There is no `anyhow`-style opaque error and no stringly-typed failure.
//!
//! # Hostnames are scrubbed by default
//!
//! Error messages routinely end up in logs, bug reports and crash handlers. For
//! a library whose whole purpose is anonymity, an error like
//! `connection to secretforum7xyz.onion:80 failed` is a leak.
//!
//! Every host in this module is therefore wrapped in [`safelog::Sensitive`],
//! which renders as `[scrubbed]` unless the application explicitly opts in via
//! [`safelog::disable_safe_logging`]. Use [`Error::host`] when you need the real
//! value programmatically — that accessor never redacts.

use std::time::Duration;

use safelog::Sensitive;
use thiserror::Error;

/// Result alias used throughout hypertor.
pub type Result<T> = std::result::Result<T, Error>;

/// A boxed underlying error, preserved as the [`std::error::Error::source`].
pub type BoxedError = Box<dyn std::error::Error + Send + Sync>;

/// Everything that can go wrong in hypertor.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    // ------------------------------------------------------------------
    // Tor
    // ------------------------------------------------------------------
    /// The Tor client could not bootstrap (fetch a directory and build circuits).
    #[error("Tor bootstrap failed: {message}")]
    Bootstrap {
        /// What went wrong.
        message: String,
        /// The underlying arti error.
        #[source]
        source: Option<BoxedError>,
    },

    /// A stream to the target could not be opened over Tor.
    #[error("connection to {host}:{port} failed")]
    Connect {
        /// Target host (scrubbed when displayed).
        host: Sensitive<String>,
        /// Target port.
        port: u16,
        /// The underlying arti error.
        #[source]
        source: BoxedError,
    },

    // ------------------------------------------------------------------
    // TLS
    // ------------------------------------------------------------------
    /// The TLS handshake with the target failed.
    #[error("TLS handshake with {host} failed")]
    TlsHandshake {
        /// Target host (scrubbed when displayed).
        host: Sensitive<String>,
        /// The underlying TLS error.
        #[source]
        source: BoxedError,
    },

    /// The TLS stack could not be configured.
    #[error("TLS configuration error: {message}")]
    Tls {
        /// What went wrong.
        message: String,
    },

    // ------------------------------------------------------------------
    // HTTP
    // ------------------------------------------------------------------
    /// A protocol-level HTTP failure (handshake, framing, transport).
    #[error("HTTP error: {message}")]
    Http {
        /// What went wrong.
        message: String,
        /// The underlying hyper error.
        #[source]
        source: Option<BoxedError>,
    },

    /// The server answered, but with a status the caller rejected.
    ///
    /// Produced only by `error_for_status`. It carries the [`StatusCode`] so
    /// callers can branch on it — `404` and `503` usually deserve different
    /// handling, and forcing a string match to tell them apart would be poor.
    ///
    /// [`StatusCode`]: http::StatusCode
    #[error("server returned {status} {reason}")]
    Status {
        /// The status code the server sent.
        status: http::StatusCode,
        /// Its canonical reason phrase, if it has one.
        reason: String,
    },

    /// The request could not be built or was rejected before being sent.
    #[error("invalid request: {message}")]
    InvalidRequest {
        /// What is wrong with the request.
        message: String,
    },

    /// The URL could not be parsed, or is not usable over Tor.
    #[error("invalid URL: {reason}")]
    InvalidUrl {
        /// Why the URL was rejected.
        reason: String,
    },

    /// The response body exceeded the configured limit.
    ///
    /// `size` is the number of bytes seen when the limit tripped; the body is
    /// not buffered any further, so this is not a full content length.
    #[error("response body exceeds limit of {limit} bytes")]
    BodyTooLarge {
        /// Bytes observed before aborting.
        size: usize,
        /// The configured limit.
        limit: usize,
    },

    /// The redirect chain exceeded the configured limit.
    #[error("too many redirects (limit: {limit})")]
    TooManyRedirects {
        /// The configured limit.
        limit: usize,
    },

    /// A response body used a Content-Encoding that could not be decoded.
    #[error("could not decode response body: {message}")]
    Decode {
        /// What went wrong.
        message: String,
    },

    /// A request body failed while being streamed.
    #[error("request body error: {message}")]
    Body {
        /// What went wrong.
        message: String,
        /// The underlying failure from the caller's stream.
        #[source]
        source: Option<BoxedError>,
    },

    // ------------------------------------------------------------------
    // Timing
    // ------------------------------------------------------------------
    /// An operation exceeded its deadline.
    #[error("{operation} timed out after {duration:?}")]
    Timeout {
        /// The operation that timed out.
        operation: &'static str,
        /// The deadline that elapsed.
        duration: Duration,
    },

    // ------------------------------------------------------------------
    // Onion services
    // ------------------------------------------------------------------
    /// Hosting or reaching an onion service failed.
    #[error("onion service error: {message}")]
    OnionService {
        /// What went wrong.
        message: String,
        /// The underlying arti error.
        #[source]
        source: Option<BoxedError>,
    },

    // ------------------------------------------------------------------
    // Configuration & I/O
    // ------------------------------------------------------------------
    /// The configuration is invalid or internally inconsistent.
    #[error("configuration error: {message}")]
    Config {
        /// What is wrong with the configuration.
        message: String,
    },

    /// An underlying I/O operation failed.
    ///
    /// The message is inlined rather than left to the `source` chain: most
    /// logging setups print only the top-level `Display`, and a bare
    /// "I/O error" tells nobody anything.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    /// The target host this error refers to, **unredacted**.
    ///
    /// Returns `None` for errors that are not tied to a specific host. Use this
    /// when you need to act on the host programmatically; prefer the `Display`
    /// impl whenever the value may reach a log.
    pub fn host(&self) -> Option<&str> {
        match self {
            Error::Connect { host, .. } | Error::TlsHandshake { host, .. } => {
                Some(host.as_inner().as_str())
            }
            _ => None,
        }
    }

    /// Whether retrying the same request has a realistic chance of succeeding.
    ///
    /// Connection-level failures are transient by nature: the next attempt
    /// opens a new stream, and under
    /// [`IsolationLevel::PerRequest`](crate::IsolationLevel::PerRequest) a new
    /// circuit as well, so a bad relay is routed around rather than hit again.
    /// Configuration and request-shape errors are not retryable, and neither
    /// are timeouts of the *whole* operation, since the caller's deadline has
    /// already passed.
    pub fn is_retryable(&self) -> bool {
        match self {
            // A stream that could not be opened, or whose TLS handshake failed,
            // says nothing about the request itself.
            Error::Connect { .. } | Error::TlsHandshake { .. } => true,
            // Framing and keep-alive failures: usually a pooled connection the
            // peer had already closed.
            Error::Http { .. } => true,
            // Bootstrap failed, the caller's deadline has passed, the body
            // stream is consumed, or the request itself is wrong. None of these
            // get better by trying again.
            _ => false,
        }
    }

    /// Whether this error came from the Tor layer rather than from HTTP.
    pub fn is_tor(&self) -> bool {
        matches!(self, Error::Bootstrap { .. } | Error::Connect { .. })
    }

    /// Whether this error is a timeout.
    pub fn is_timeout(&self) -> bool {
        matches!(self, Error::Timeout { .. })
    }

    /// The HTTP status, for errors produced by `error_for_status`.
    pub fn status(&self) -> Option<http::StatusCode> {
        match self {
            Error::Status { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// Rebuild an owned error of the same kind from a borrowed one.
    ///
    /// hyper boxes our connector errors behind `dyn Error`, so a failed request
    /// only gives us a `&Error` back. `Error` is not `Clone` — the boxed
    /// sources are not — but the *variant* has to survive that round trip, or
    /// [`is_retryable`](Self::is_retryable) and [`is_tor`](Self::is_tor) would
    /// report the wrong thing for exactly the failures that matter most.
    ///
    /// The underlying source is dropped; its message is folded into the text.
    #[cfg_attr(not(feature = "client"), allow(dead_code))]
    pub(crate) fn same_kind(&self) -> Error {
        let detail = || {
            std::error::Error::source(self)
                .map(|s| format!("{self}: {s}"))
                .unwrap_or_else(|| self.to_string())
        };

        match self {
            Error::Connect { host, port, .. } => Error::Connect {
                host: host.clone(),
                port: *port,
                source: Box::new(Detail(detail())),
            },
            Error::TlsHandshake { host, .. } => Error::TlsHandshake {
                host: host.clone(),
                source: Box::new(Detail(detail())),
            },
            Error::Bootstrap { message, .. } => Error::Bootstrap {
                message: message.clone(),
                source: None,
            },
            Error::Timeout {
                operation,
                duration,
            } => Error::Timeout {
                operation,
                duration: *duration,
            },
            Error::Tls { message } => Error::Tls {
                message: message.clone(),
            },
            Error::InvalidUrl { reason } => Error::InvalidUrl {
                reason: reason.clone(),
            },
            Error::InvalidRequest { message } => Error::InvalidRequest {
                message: message.clone(),
            },
            Error::Config { message } => Error::Config {
                message: message.clone(),
            },
            Error::Decode { message } => Error::Decode {
                message: message.clone(),
            },
            Error::Body { message, .. } => Error::Body {
                message: message.clone(),
                source: Some(Box::new(Detail(detail()))),
            },
            Error::BodyTooLarge { size, limit } => Error::BodyTooLarge {
                size: *size,
                limit: *limit,
            },
            Error::TooManyRedirects { limit } => Error::TooManyRedirects { limit: *limit },
            Error::Status { status, reason } => Error::Status {
                status: *status,
                reason: reason.clone(),
            },
            // Anything else keeps its message but becomes a generic HTTP
            // failure, which is a safe classification: not retryable.
            other => Error::Http {
                message: other.to_string(),
                source: None,
            },
        }
    }
}

/// Crate-internal constructors.
///
/// Which of these are reachable depends on the feature set — a `server`-only
/// build never opens an outbound connection, for instance — so they are grouped
/// here rather than carrying a `cfg` apiece.
#[allow(dead_code)]
impl Error {
    pub(crate) fn bootstrap<E>(message: impl Into<String>, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Error::Bootstrap {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    pub(crate) fn connect<E>(host: impl Into<String>, port: u16, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Error::Connect {
            host: Sensitive::new(host.into()),
            port,
            source: Box::new(source),
        }
    }

    pub(crate) fn tls_handshake<E>(host: impl Into<String>, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Error::TlsHandshake {
            host: Sensitive::new(host.into()),
            source: Box::new(source),
        }
    }

    pub(crate) fn tls(message: impl Into<String>) -> Self {
        Error::Tls {
            message: message.into(),
        }
    }

    pub(crate) fn http(message: impl Into<String>) -> Self {
        Error::Http {
            message: message.into(),
            source: None,
        }
    }

    pub(crate) fn http_source<E>(message: impl Into<String>, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Error::Http {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    pub(crate) fn invalid_request(message: impl Into<String>) -> Self {
        Error::InvalidRequest {
            message: message.into(),
        }
    }

    pub(crate) fn invalid_url(reason: impl Into<String>) -> Self {
        Error::InvalidUrl {
            reason: reason.into(),
        }
    }

    pub(crate) fn decode(message: impl Into<String>) -> Self {
        Error::Decode {
            message: message.into(),
        }
    }

    pub(crate) fn timeout(operation: &'static str, duration: Duration) -> Self {
        Error::Timeout {
            operation,
            duration,
        }
    }

    pub(crate) fn config(message: impl Into<String>) -> Self {
        Error::Config {
            message: message.into(),
        }
    }

    #[cfg(feature = "server")]
    pub(crate) fn onion(message: impl Into<String>) -> Self {
        Error::OnionService {
            message: message.into(),
            source: None,
        }
    }

    #[cfg(feature = "server")]
    pub(crate) fn onion_source<E>(message: impl Into<String>, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Error::OnionService {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }
}

/// Carries a rendered message where the original source cannot be cloned.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct Detail(pub(crate) String);

impl std::fmt::Display for Detail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Detail {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_is_scrubbed_in_display_but_reachable_programmatically() {
        let err = Error::Connect {
            host: Sensitive::new("secretforum.onion".to_string()),
            port: 80,
            source: Box::new(std::io::Error::other("nope")),
        };

        let rendered = err.to_string();
        assert!(
            !rendered.contains("secretforum"),
            "hostname leaked into Display: {rendered}"
        );
        assert_eq!(err.host(), Some("secretforum.onion"));
    }

    #[test]
    fn transient_failures_are_retryable() {
        let connect = Error::connect("example.onion", 80, std::io::Error::other("x"));
        assert!(connect.is_retryable());
        assert!(connect.is_tor());

        let config = Error::config("bad");
        assert!(!config.is_retryable());
        assert!(!config.is_tor());
    }

    #[test]
    fn same_kind_preserves_classification_across_the_hyper_boundary() {
        // hyper hands connector failures back as `&dyn Error`, so if the
        // variant were lost here, a transient connect failure would stop being
        // retryable and stop being recognised as a Tor error.
        let original = Error::connect("example.onion", 80, std::io::Error::other("refused"));
        let rebuilt = original.same_kind();

        assert!(rebuilt.is_retryable());
        assert!(rebuilt.is_tor());
        assert_eq!(rebuilt.host(), Some("example.onion"));
        assert!(!rebuilt.to_string().contains("example.onion"));
    }

    #[test]
    fn same_kind_preserves_timeouts() {
        let original = Error::timeout("Tor connect", Duration::from_secs(5));
        let rebuilt = original.same_kind();

        assert!(rebuilt.is_timeout());
        assert!(!rebuilt.is_retryable());
    }

    #[test]
    fn same_kind_keeps_the_underlying_detail_in_the_source() {
        let original = Error::connect("h.onion", 80, std::io::Error::other("no route"));
        let rebuilt = original.same_kind();

        let source = std::error::Error::source(&rebuilt).expect("source preserved");
        assert!(source.to_string().contains("no route"), "{source}");
    }

    #[test]
    fn timeouts_are_not_retryable() {
        let err = Error::timeout("request", Duration::from_secs(1));
        assert!(err.is_timeout());
        assert!(!err.is_retryable());
    }
}
