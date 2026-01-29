//! Timeout configuration for fine-grained control.
//!
//! Provides granular timeout settings for different phases of an HTTP request.

use std::time::Duration;

/// Granular timeout configuration for HTTP requests.
///
/// Each timeout controls a specific phase of the request lifecycle.
/// All timeouts default to sensible values optimized for Tor's latency.
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    /// Total request timeout (default: 30s)
    ///
    /// The maximum time allowed for the entire request, from initiating
    /// the connection to receiving the complete response.
    pub total: Duration,

    /// Connection timeout (default: 10s)
    ///
    /// Maximum time to establish a TCP connection through Tor.
    /// This includes circuit building if needed.
    pub connect: Duration,

    /// TLS handshake timeout (default: 10s)
    ///
    /// Maximum time for the TLS handshake after TCP connection.
    pub tls_handshake: Duration,

    /// Request send timeout (default: 30s)
    ///
    /// Maximum time to send the complete request (headers + body).
    pub request: Duration,

    /// Response header timeout (default: 30s)
    ///
    /// Maximum time to receive the response headers after sending the request.
    pub response_headers: Duration,

    /// Idle timeout for pooled connections (default: 90s)
    ///
    /// Maximum time a connection can remain idle in the pool before being closed.
    pub idle: Duration,

    /// Read timeout per chunk (default: 30s)
    ///
    /// Maximum time to wait for data while reading the response body.
    pub read: Duration,

    /// Write timeout per chunk (default: 30s)
    ///
    /// Maximum time to wait while writing request data.
    pub write: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            // Tor circuits can take 5-10s to establish
            total: Duration::from_secs(30),
            connect: Duration::from_secs(10),
            tls_handshake: Duration::from_secs(10),
            request: Duration::from_secs(30),
            response_headers: Duration::from_secs(30),
            // Keep connections warm but not too long
            idle: Duration::from_secs(90),
            read: Duration::from_secs(30),
            write: Duration::from_secs(30),
        }
    }
}

impl Timeouts {
    /// Create a new timeout configuration with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create timeouts optimized for fast responses (short timeouts).
    #[must_use]
    pub fn fast() -> Self {
        Self {
            total: Duration::from_secs(15),
            connect: Duration::from_secs(5),
            tls_handshake: Duration::from_secs(5),
            request: Duration::from_secs(10),
            response_headers: Duration::from_secs(10),
            idle: Duration::from_secs(30),
            read: Duration::from_secs(10),
            write: Duration::from_secs(10),
        }
    }

    /// Create timeouts for slow/large transfers.
    #[must_use]
    pub fn slow() -> Self {
        Self {
            total: Duration::from_secs(120),
            connect: Duration::from_secs(30),
            tls_handshake: Duration::from_secs(30),
            request: Duration::from_secs(60),
            response_headers: Duration::from_secs(60),
            idle: Duration::from_secs(180),
            read: Duration::from_secs(60),
            write: Duration::from_secs(60),
        }
    }

    /// Create timeouts with no limits (use with caution).
    #[must_use]
    pub fn none() -> Self {
        Self {
            total: Duration::MAX,
            connect: Duration::MAX,
            tls_handshake: Duration::MAX,
            request: Duration::MAX,
            response_headers: Duration::MAX,
            idle: Duration::MAX,
            read: Duration::MAX,
            write: Duration::MAX,
        }
    }

    /// Set the total request timeout.
    #[must_use]
    pub fn with_total(mut self, timeout: Duration) -> Self {
        self.total = timeout;
        self
    }

    /// Set the connection timeout.
    #[must_use]
    pub fn with_connect(mut self, timeout: Duration) -> Self {
        self.connect = timeout;
        self
    }

    /// Set the TLS handshake timeout.
    #[must_use]
    pub fn with_tls_handshake(mut self, timeout: Duration) -> Self {
        self.tls_handshake = timeout;
        self
    }

    /// Set the idle timeout.
    #[must_use]
    pub fn with_idle(mut self, timeout: Duration) -> Self {
        self.idle = timeout;
        self
    }

    /// Set the read timeout.
    #[must_use]
    pub fn with_read(mut self, timeout: Duration) -> Self {
        self.read = timeout;
        self
    }

    /// Set the write timeout.
    #[must_use]
    pub fn with_write(mut self, timeout: Duration) -> Self {
        self.write = timeout;
        self
    }

    /// Check if any timeout is zero (invalid).
    #[must_use]
    pub fn has_zero(&self) -> bool {
        self.total.is_zero()
            || self.connect.is_zero()
            || self.tls_handshake.is_zero()
            || self.request.is_zero()
            || self.response_headers.is_zero()
            || self.read.is_zero()
            || self.write.is_zero()
    }

    /// Get the minimum of total timeout and a specific phase timeout.
    #[must_use]
    pub fn effective_connect(&self) -> Duration {
        self.total.min(self.connect)
    }

    /// Get the effective TLS handshake timeout.
    #[must_use]
    pub fn effective_tls(&self) -> Duration {
        self.total.min(self.tls_handshake)
    }

    /// Get the effective read timeout.
    #[must_use]
    pub fn effective_read(&self) -> Duration {
        self.total.min(self.read)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_default_timeouts() {
        let t = Timeouts::default();
        assert_eq!(t.total, Duration::from_secs(30));
        assert_eq!(t.connect, Duration::from_secs(10));
        assert!(!t.has_zero());
    }

    #[test]
    fn test_fast_timeouts() {
        let t = Timeouts::fast();
        assert_eq!(t.total, Duration::from_secs(15));
        assert_eq!(t.connect, Duration::from_secs(5));
    }

    #[test]
    fn test_builder_pattern() {
        let t = Timeouts::new()
            .with_total(Duration::from_secs(60))
            .with_connect(Duration::from_secs(20));

        assert_eq!(t.total, Duration::from_secs(60));
        assert_eq!(t.connect, Duration::from_secs(20));
    }

    #[test]
    fn test_effective_timeouts() {
        let t = Timeouts::new()
            .with_total(Duration::from_secs(5))
            .with_connect(Duration::from_secs(10));

        // Total should cap connect
        assert_eq!(t.effective_connect(), Duration::from_secs(5));
    }
}
