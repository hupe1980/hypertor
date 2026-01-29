//! Health checks and status monitoring
//!
//! Provides health check functionality to verify Tor connectivity
//! and monitor client status.

use std::time::{Duration, Instant};

use tracing::warn;

use crate::client::TorClient;
use crate::error::{Error, Result};

/// Health status of the client
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthStatus {
    /// Client is healthy and can make requests
    Healthy,
    /// Client is functional but with degraded performance
    Degraded,
    /// Client is not functional
    Unhealthy,
}

/// Detailed health check result
#[derive(Debug, Clone)]
pub struct HealthCheck {
    /// Overall health status
    pub status: HealthStatus,
    /// Whether Tor bootstrap is complete
    pub tor_connected: bool,
    /// Latency to test endpoint (if checked)
    pub latency: Option<Duration>,
    /// Number of pooled connections
    pub pool_size: usize,
    /// Error message if unhealthy
    pub error: Option<String>,
    /// When the check was performed
    pub checked_at: Instant,
}

impl HealthCheck {
    /// Check if the client is healthy
    pub fn is_healthy(&self) -> bool {
        self.status == HealthStatus::Healthy
    }
}

/// Health check configuration
#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    /// Timeout for health check requests
    pub timeout: Duration,
    /// URL to use for connectivity test (should be fast)
    pub test_url: Option<String>,
    /// Whether to perform actual request test
    pub full_check: bool,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            test_url: None,
            full_check: false,
        }
    }
}

impl TorClient {
    /// Perform a health check
    pub async fn health_check(&self) -> HealthCheck {
        self.health_check_with_config(HealthCheckConfig::default())
            .await
    }

    /// Perform a health check with custom configuration
    pub async fn health_check_with_config(&self, config: HealthCheckConfig) -> HealthCheck {
        let start = Instant::now();
        let pool_size = self.pool_size();

        // Basic check - is Tor connected?
        let tor_connected = true; // Tor client is bootstrapped at creation

        if !config.full_check {
            return HealthCheck {
                status: HealthStatus::Healthy,
                tor_connected,
                latency: None,
                pool_size,
                error: None,
                checked_at: start,
            };
        }

        // Full check - try to make a request
        if let Some(test_url) = config.test_url {
            match self.check_connectivity(&test_url, config.timeout).await {
                Ok(latency) => {
                    let status = if latency > Duration::from_secs(5) {
                        HealthStatus::Degraded
                    } else {
                        HealthStatus::Healthy
                    };

                    HealthCheck {
                        status,
                        tor_connected,
                        latency: Some(latency),
                        pool_size,
                        error: None,
                        checked_at: start,
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Health check failed");
                    HealthCheck {
                        status: HealthStatus::Unhealthy,
                        tor_connected,
                        latency: None,
                        pool_size,
                        error: Some(e.to_string()),
                        checked_at: start,
                    }
                }
            }
        } else {
            HealthCheck {
                status: HealthStatus::Healthy,
                tor_connected,
                latency: None,
                pool_size,
                error: None,
                checked_at: start,
            }
        }
    }

    async fn check_connectivity(&self, url: &str, timeout: Duration) -> Result<Duration> {
        let start = Instant::now();

        let response = tokio::time::timeout(timeout, async { self.head(url)?.send().await })
            .await
            .map_err(|_| Error::timeout("health check", timeout))??;

        if response.is_success() || response.status_code() < 500 {
            Ok(start.elapsed())
        } else {
            Err(Error::http(format!(
                "health check returned status {}",
                response.status_code()
            )))
        }
    }
}

/// Simple metrics collection
#[derive(Debug, Default)]
pub struct Metrics {
    /// Total requests made
    pub requests_total: std::sync::atomic::AtomicU64,
    /// Successful requests
    pub requests_success: std::sync::atomic::AtomicU64,
    /// Failed requests
    pub requests_failed: std::sync::atomic::AtomicU64,
    /// Total bytes received
    pub bytes_received: std::sync::atomic::AtomicU64,
}

impl Metrics {
    /// Create new metrics instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful request
    pub fn record_success(&self, bytes: u64) {
        use std::sync::atomic::Ordering::Relaxed;
        self.requests_total.fetch_add(1, Relaxed);
        self.requests_success.fetch_add(1, Relaxed);
        self.bytes_received.fetch_add(bytes, Relaxed);
    }

    /// Record a failed request
    pub fn record_failure(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        self.requests_total.fetch_add(1, Relaxed);
        self.requests_failed.fetch_add(1, Relaxed);
    }

    /// Get current metrics snapshot
    pub fn snapshot(&self) -> MetricsSnapshot {
        use std::sync::atomic::Ordering::Relaxed;
        MetricsSnapshot {
            requests_total: self.requests_total.load(Relaxed),
            requests_success: self.requests_success.load(Relaxed),
            requests_failed: self.requests_failed.load(Relaxed),
            bytes_received: self.bytes_received.load(Relaxed),
        }
    }
}

/// Snapshot of metrics at a point in time
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    /// Total requests made
    pub requests_total: u64,
    /// Successful requests
    pub requests_success: u64,
    /// Failed requests
    pub requests_failed: u64,
    /// Total bytes received
    pub bytes_received: u64,
}

impl MetricsSnapshot {
    /// Get success rate as a percentage
    pub fn success_rate(&self) -> f64 {
        if self.requests_total == 0 {
            100.0
        } else {
            (self.requests_success as f64 / self.requests_total as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_metrics_recording() {
        let metrics = Metrics::new();
        metrics.record_success(1000);
        metrics.record_success(500);
        metrics.record_failure();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.requests_total, 3);
        assert_eq!(snapshot.requests_success, 2);
        assert_eq!(snapshot.requests_failed, 1);
        assert_eq!(snapshot.bytes_received, 1500);
    }

    #[test]
    fn test_success_rate() {
        let snapshot = MetricsSnapshot {
            requests_total: 100,
            requests_success: 90,
            requests_failed: 10,
            bytes_received: 0,
        };
        assert!((snapshot.success_rate() - 90.0).abs() < 0.01);
    }
}
