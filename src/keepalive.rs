//! Connection keep-alive management.
//!
//! Provides HTTP/1.1 connection keep-alive with proper lifecycle management.

use std::time::{Duration, Instant};

use http::{HeaderMap, Version, header};

/// Connection keep-alive configuration.
#[derive(Debug, Clone, Copy)]
pub struct KeepAliveConfig {
    /// Whether keep-alive is enabled
    pub enabled: bool,
    /// Maximum idle time before closing connection
    pub idle_timeout: Duration,
    /// Maximum number of requests per connection
    pub max_requests: Option<u32>,
    /// Interval for TCP keep-alive probes
    pub tcp_keepalive: Option<Duration>,
}

impl Default for KeepAliveConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            idle_timeout: Duration::from_secs(90),
            max_requests: Some(100),
            tcp_keepalive: Some(Duration::from_secs(60)),
        }
    }
}

impl KeepAliveConfig {
    /// Create a new keep-alive configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Disable keep-alive.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    /// Set the idle timeout.
    #[must_use]
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Set the maximum requests per connection.
    #[must_use]
    pub fn with_max_requests(mut self, max: u32) -> Self {
        self.max_requests = Some(max);
        self
    }

    /// Set no limit on requests per connection.
    #[must_use]
    pub fn unlimited_requests(mut self) -> Self {
        self.max_requests = None;
        self
    }

    /// Set TCP keep-alive interval.
    #[must_use]
    pub fn with_tcp_keepalive(mut self, interval: Duration) -> Self {
        self.tcp_keepalive = Some(interval);
        self
    }
}

/// Connection state for keep-alive tracking.
#[derive(Debug)]
pub struct ConnectionState {
    /// When the connection was created
    pub created_at: Instant,
    /// When the connection was last used
    pub last_used: Instant,
    /// Number of requests made on this connection
    pub request_count: u32,
    /// Whether the connection is currently in use
    pub in_use: bool,
    /// Keep-alive configuration
    config: KeepAliveConfig,
}

impl ConnectionState {
    /// Create a new connection state.
    pub fn new(config: KeepAliveConfig) -> Self {
        let now = Instant::now();
        Self {
            created_at: now,
            last_used: now,
            request_count: 0,
            in_use: false,
            config,
        }
    }

    /// Mark connection as used for a new request.
    pub fn use_connection(&mut self) {
        self.last_used = Instant::now();
        self.request_count += 1;
        self.in_use = true;
    }

    /// Mark connection as idle (request completed).
    pub fn release(&mut self) {
        self.last_used = Instant::now();
        self.in_use = false;
    }

    /// Check if the connection should be kept alive.
    pub fn should_keep_alive(&self) -> bool {
        if !self.config.enabled {
            return false;
        }

        // Check request limit
        if let Some(max) = self.config.max_requests {
            if self.request_count >= max {
                return false;
            }
        }

        // Check idle timeout
        if self.last_used.elapsed() > self.config.idle_timeout {
            return false;
        }

        true
    }

    /// Check if the connection has expired (idle too long).
    pub fn is_expired(&self) -> bool {
        self.last_used.elapsed() > self.config.idle_timeout
    }

    /// Get the time until the connection expires.
    pub fn time_to_expiry(&self) -> Duration {
        self.config
            .idle_timeout
            .saturating_sub(self.last_used.elapsed())
    }

    /// Get the connection age.
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get the idle time.
    pub fn idle_time(&self) -> Duration {
        self.last_used.elapsed()
    }
}

/// Analyze response headers for keep-alive hints.
#[derive(Debug, Clone)]
pub struct KeepAliveHints {
    /// Whether the server supports keep-alive
    pub keep_alive: bool,
    /// Server-suggested timeout
    pub timeout: Option<Duration>,
    /// Server-suggested max requests
    pub max: Option<u32>,
}

impl KeepAliveHints {
    /// Parse keep-alive hints from response headers.
    pub fn from_headers(headers: &HeaderMap, version: Version) -> Self {
        // HTTP/1.1 defaults to keep-alive, HTTP/1.0 requires explicit header
        let mut keep_alive = version == Version::HTTP_11;

        // Check Connection header
        if let Some(conn) = headers.get(header::CONNECTION) {
            if let Ok(value) = conn.to_str() {
                let value_lower = value.to_lowercase();
                if value_lower.contains("close") {
                    keep_alive = false;
                } else if value_lower.contains("keep-alive") {
                    keep_alive = true;
                }
            }
        }

        let mut timeout = None;
        let mut max = None;

        // Parse Keep-Alive header for hints
        if let Some(ka) = headers.get("keep-alive") {
            if let Ok(value) = ka.to_str() {
                for param in value.split(',') {
                    let param = param.trim();
                    if let Some(rest) = param.strip_prefix("timeout=") {
                        if let Ok(secs) = rest.trim().parse::<u64>() {
                            timeout = Some(Duration::from_secs(secs));
                        }
                    } else if let Some(rest) = param.strip_prefix("max=") {
                        if let Ok(n) = rest.trim().parse::<u32>() {
                            max = Some(n);
                        }
                    }
                }
            }
        }

        Self {
            keep_alive,
            timeout,
            max,
        }
    }

    /// Check if connection should be closed after this response.
    pub fn should_close(&self) -> bool {
        !self.keep_alive
    }
}

/// Build the Connection header value for a request.
pub fn connection_header_value(keep_alive: bool) -> &'static str {
    if keep_alive { "keep-alive" } else { "close" }
}

/// Build keep-alive header for requests.
pub fn keep_alive_header_value(config: &KeepAliveConfig) -> String {
    let mut parts = vec![format!("timeout={}", config.idle_timeout.as_secs())];

    if let Some(max) = config.max_requests {
        parts.push(format!("max={}", max));
    }

    parts.join(", ")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use http::header::HeaderValue;

    #[test]
    fn test_keep_alive_config() {
        let config = KeepAliveConfig::new();
        assert!(config.enabled);
        assert_eq!(config.idle_timeout, Duration::from_secs(90));
        assert_eq!(config.max_requests, Some(100));
    }

    #[test]
    fn test_connection_state() {
        let config = KeepAliveConfig::new();
        let mut state = ConnectionState::new(config);

        assert!(!state.in_use);
        assert_eq!(state.request_count, 0);
        assert!(state.should_keep_alive());

        state.use_connection();
        assert!(state.in_use);
        assert_eq!(state.request_count, 1);

        state.release();
        assert!(!state.in_use);
    }

    #[test]
    fn test_keep_alive_hints_http11() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=30, max=50"));

        let hints = KeepAliveHints::from_headers(&headers, Version::HTTP_11);
        assert!(hints.keep_alive);
        assert_eq!(hints.timeout, Some(Duration::from_secs(30)));
        assert_eq!(hints.max, Some(50));
    }

    #[test]
    fn test_keep_alive_hints_close() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONNECTION, HeaderValue::from_static("close"));

        let hints = KeepAliveHints::from_headers(&headers, Version::HTTP_11);
        assert!(!hints.keep_alive);
        assert!(hints.should_close());
    }

    #[test]
    fn test_connection_header_value() {
        assert_eq!(connection_header_value(true), "keep-alive");
        assert_eq!(connection_header_value(false), "close");
    }
}
