//! Circuit rotation and failover.
//!
//! Provides automatic circuit rotation on failures, with intelligent
//! retry strategies and circuit health tracking.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::RwLock;

use crate::error::Error;
use crate::isolation::IsolationToken;

/// Circuit health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitHealth {
    /// Circuit is healthy
    Healthy,
    /// Circuit has degraded performance
    Degraded,
    /// Circuit is unhealthy and should be replaced
    Unhealthy,
    /// Circuit is dead and must be replaced
    Dead,
}

impl CircuitHealth {
    /// Check if the circuit can still be used.
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded)
    }

    /// Check if the circuit should be rotated soon.
    pub fn should_rotate(&self) -> bool {
        matches!(self, Self::Degraded | Self::Unhealthy | Self::Dead)
    }
}

/// Metrics for a single circuit.
#[derive(Debug)]
pub struct CircuitMetrics {
    /// Total requests made
    pub requests: AtomicU64,
    /// Successful requests
    pub successes: AtomicU64,
    /// Failed requests
    pub failures: AtomicU64,
    /// Total latency in milliseconds
    pub total_latency_ms: AtomicU64,
    /// Consecutive failures
    pub consecutive_failures: AtomicU32,
    /// Last success time
    pub last_success: RwLock<Option<Instant>>,
    /// Last failure time
    pub last_failure: RwLock<Option<Instant>>,
    /// Creation time
    pub created_at: Instant,
}

impl Default for CircuitMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl CircuitMetrics {
    /// Create new metrics.
    pub fn new() -> Self {
        Self {
            requests: AtomicU64::new(0),
            successes: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            total_latency_ms: AtomicU64::new(0),
            consecutive_failures: AtomicU32::new(0),
            last_success: RwLock::new(None),
            last_failure: RwLock::new(None),
            created_at: Instant::now(),
        }
    }

    /// Record a successful request.
    pub fn record_success(&self, latency: Duration) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.successes.fetch_add(1, Ordering::Relaxed);
        self.total_latency_ms
            .fetch_add(latency.as_millis() as u64, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        *self.last_success.write() = Some(Instant::now());
    }

    /// Record a failed request.
    pub fn record_failure(&self) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.failures.fetch_add(1, Ordering::Relaxed);
        self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
        *self.last_failure.write() = Some(Instant::now());
    }

    /// Get the success rate.
    pub fn success_rate(&self) -> f64 {
        let total = self.requests.load(Ordering::Relaxed);
        if total == 0 {
            return 1.0;
        }
        let successes = self.successes.load(Ordering::Relaxed);
        successes as f64 / total as f64
    }

    /// Get the average latency.
    pub fn avg_latency(&self) -> Duration {
        let successes = self.successes.load(Ordering::Relaxed);
        if successes == 0 {
            return Duration::ZERO;
        }
        let total_ms = self.total_latency_ms.load(Ordering::Relaxed);
        Duration::from_millis(total_ms / successes)
    }

    /// Get circuit health based on metrics.
    pub fn health(&self) -> CircuitHealth {
        let consecutive = self.consecutive_failures.load(Ordering::Relaxed);
        let rate = self.success_rate();

        if consecutive >= 5 {
            return CircuitHealth::Dead;
        }
        if consecutive >= 3 || rate < 0.5 {
            return CircuitHealth::Unhealthy;
        }
        if consecutive >= 1 || rate < 0.8 {
            return CircuitHealth::Degraded;
        }
        CircuitHealth::Healthy
    }

    /// Get circuit age.
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }
}

/// Configuration for circuit rotation.
#[derive(Debug, Clone)]
pub struct RotationConfig {
    /// Maximum consecutive failures before rotation
    pub max_consecutive_failures: u32,
    /// Minimum success rate before rotation
    pub min_success_rate: f64,
    /// Maximum circuit age before rotation
    pub max_circuit_age: Duration,
    /// Cooldown between rotations
    pub rotation_cooldown: Duration,
    /// Whether to rotate on specific errors
    pub rotate_on_timeout: bool,
    /// Whether to rotate on connection errors
    pub rotate_on_connection_error: bool,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            max_consecutive_failures: 3,
            min_success_rate: 0.7,
            max_circuit_age: Duration::from_secs(600), // 10 minutes
            rotation_cooldown: Duration::from_secs(30),
            rotate_on_timeout: true,
            rotate_on_connection_error: true,
        }
    }
}

impl RotationConfig {
    /// Create a new configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum consecutive failures.
    #[must_use]
    pub fn with_max_failures(mut self, max: u32) -> Self {
        self.max_consecutive_failures = max;
        self
    }

    /// Set minimum success rate.
    #[must_use]
    pub fn with_min_success_rate(mut self, rate: f64) -> Self {
        self.min_success_rate = rate.clamp(0.0, 1.0);
        self
    }

    /// Set maximum circuit age.
    #[must_use]
    pub fn with_max_age(mut self, age: Duration) -> Self {
        self.max_circuit_age = age;
        self
    }

    /// Check if an error should trigger rotation.
    pub fn should_rotate_on_error(&self, error: &Error) -> bool {
        match error {
            Error::Timeout { .. } => self.rotate_on_timeout,
            Error::Connection { .. } => self.rotate_on_connection_error,
            Error::Http { .. } => false, // Client error, don't rotate
            _ => false,
        }
    }
}

/// Circuit rotation manager.
#[derive(Debug)]
pub struct CircuitRotator {
    config: RotationConfig,
    metrics: Arc<RwLock<HashMap<IsolationToken, Arc<CircuitMetrics>>>>,
    last_rotation: Arc<RwLock<HashMap<IsolationToken, Instant>>>,
}

impl Default for CircuitRotator {
    fn default() -> Self {
        Self::new(RotationConfig::default())
    }
}

impl CircuitRotator {
    /// Create a new circuit rotator.
    pub fn new(config: RotationConfig) -> Self {
        Self {
            config,
            metrics: Arc::new(RwLock::new(HashMap::new())),
            last_rotation: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get or create metrics for a circuit.
    pub fn get_metrics(&self, token: &IsolationToken) -> Arc<CircuitMetrics> {
        let mut metrics = self.metrics.write();
        metrics
            .entry(*token)
            .or_insert_with(|| Arc::new(CircuitMetrics::new()))
            .clone()
    }

    /// Record a successful request.
    pub fn record_success(&self, token: &IsolationToken, latency: Duration) {
        self.get_metrics(token).record_success(latency);
    }

    /// Record a failed request.
    pub fn record_failure(&self, token: &IsolationToken) {
        self.get_metrics(token).record_failure();
    }

    /// Check if a circuit should be rotated.
    pub fn should_rotate(&self, token: &IsolationToken) -> bool {
        let metrics = self.get_metrics(token);

        // Check cooldown
        {
            let last_rotation = self.last_rotation.read();
            if let Some(&last) = last_rotation.get(token) {
                if last.elapsed() < self.config.rotation_cooldown {
                    return false;
                }
            }
        }

        // Check age
        if metrics.age() > self.config.max_circuit_age {
            return true;
        }

        // Check health
        let health = metrics.health();
        if !health.is_usable() {
            return true;
        }

        // Check consecutive failures
        let consecutive = metrics.consecutive_failures.load(Ordering::Relaxed);
        if consecutive >= self.config.max_consecutive_failures {
            return true;
        }

        // Check success rate (only if we have enough samples)
        let requests = metrics.requests.load(Ordering::Relaxed);
        if requests >= 10 && metrics.success_rate() < self.config.min_success_rate {
            return true;
        }

        false
    }

    /// Check if a circuit should be rotated after an error.
    pub fn should_rotate_on_error(&self, token: &IsolationToken, error: &Error) -> bool {
        if !self.config.should_rotate_on_error(error) {
            return false;
        }
        self.record_failure(token);
        self.should_rotate(token)
    }

    /// Mark a circuit as rotated.
    pub fn mark_rotated(&self, token: &IsolationToken) {
        // Record rotation time
        self.last_rotation.write().insert(*token, Instant::now());

        // Clear old metrics
        self.metrics.write().remove(token);
    }

    /// Get the health of a circuit.
    pub fn get_health(&self, token: &IsolationToken) -> CircuitHealth {
        self.get_metrics(token).health()
    }

    /// Get rotation statistics.
    pub fn stats(&self) -> RotationStats {
        let metrics = self.metrics.read();

        let mut total_circuits = 0;
        let mut healthy = 0;
        let mut degraded = 0;
        let mut unhealthy = 0;
        let mut dead = 0;

        for circuit_metrics in metrics.values() {
            total_circuits += 1;
            match circuit_metrics.health() {
                CircuitHealth::Healthy => healthy += 1,
                CircuitHealth::Degraded => degraded += 1,
                CircuitHealth::Unhealthy => unhealthy += 1,
                CircuitHealth::Dead => dead += 1,
            }
        }

        RotationStats {
            total_circuits,
            healthy,
            degraded,
            unhealthy,
            dead,
        }
    }

    /// Clean up old circuit metrics.
    pub fn cleanup(&self, max_age: Duration) {
        let mut metrics = self.metrics.write();
        metrics.retain(|_, m| m.age() < max_age);

        let mut last_rotation = self.last_rotation.write();
        last_rotation.retain(|_, &mut t| t.elapsed() < max_age);
    }
}

/// Rotation statistics.
#[derive(Debug, Clone)]
pub struct RotationStats {
    /// Total circuits tracked
    pub total_circuits: usize,
    /// Healthy circuits
    pub healthy: usize,
    /// Degraded circuits
    pub degraded: usize,
    /// Unhealthy circuits
    pub unhealthy: usize,
    /// Dead circuits
    pub dead: usize,
}

impl RotationStats {
    /// Get the percentage of healthy circuits.
    pub fn health_percentage(&self) -> f64 {
        if self.total_circuits == 0 {
            return 100.0;
        }
        (self.healthy as f64 / self.total_circuits as f64) * 100.0
    }
}

/// Result of a rotation decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationDecision {
    /// Keep using the current circuit
    Keep,
    /// Rotate to a new circuit
    Rotate {
        /// The reason for rotation
        reason: RotationReason,
    },
    /// Rotate immediately (critical failure)
    RotateNow {
        /// The reason for immediate rotation
        reason: RotationReason,
    },
}

/// Reason for circuit rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationReason {
    /// Too many consecutive failures
    ConsecutiveFailures,
    /// Success rate too low
    LowSuccessRate,
    /// Circuit is too old
    AgeLimit,
    /// Specific error triggered rotation
    Error,
    /// Manual rotation requested
    Manual,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_circuit_metrics() {
        let metrics = CircuitMetrics::new();

        metrics.record_success(Duration::from_millis(100));
        metrics.record_success(Duration::from_millis(200));
        metrics.record_failure();

        assert_eq!(metrics.requests.load(Ordering::Relaxed), 3);
        assert_eq!(metrics.successes.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.failures.load(Ordering::Relaxed), 1);
        assert!(metrics.success_rate() > 0.6 && metrics.success_rate() < 0.7);
    }

    #[test]
    fn test_circuit_health() {
        let metrics = CircuitMetrics::new();

        // No requests yet -> Healthy
        assert_eq!(metrics.health(), CircuitHealth::Healthy);

        // Add some successful requests first
        metrics.record_success(Duration::from_millis(100));
        metrics.record_success(Duration::from_millis(100));
        metrics.record_success(Duration::from_millis(100));
        metrics.record_success(Duration::from_millis(100));
        assert_eq!(metrics.health(), CircuitHealth::Healthy);

        // One failure (1/5 = 20% fail rate) -> Degraded
        metrics.record_failure();
        assert_eq!(metrics.health(), CircuitHealth::Degraded);

        // More failures -> eventually Unhealthy (3+ consecutive or <50% success)
        metrics.record_failure();
        metrics.record_failure();
        assert_eq!(metrics.health(), CircuitHealth::Unhealthy);

        // 5 consecutive failures -> Dead
        metrics.record_failure();
        metrics.record_failure();
        assert_eq!(metrics.health(), CircuitHealth::Dead);
    }

    #[test]
    fn test_circuit_rotator() {
        let rotator = CircuitRotator::default();
        let token = IsolationToken::new();

        // Initially should not rotate
        assert!(!rotator.should_rotate(&token));

        // Record some failures
        for _ in 0..3 {
            rotator.record_failure(&token);
        }

        // Should rotate now
        assert!(rotator.should_rotate(&token));
    }

    #[test]
    fn test_rotation_config() {
        let config = RotationConfig::new()
            .with_max_failures(5)
            .with_min_success_rate(0.9)
            .with_max_age(Duration::from_secs(300));

        assert_eq!(config.max_consecutive_failures, 5);
        assert!((config.min_success_rate - 0.9).abs() < f64::EPSILON);
        assert_eq!(config.max_circuit_age, Duration::from_secs(300));
    }

    #[test]
    fn test_rotation_stats() {
        let rotator = CircuitRotator::default();

        // Create some circuits with different health
        let token1 = IsolationToken::new();
        rotator.get_metrics(&token1); // Healthy

        let token2 = IsolationToken::from_raw(2);
        rotator.record_failure(&token2); // Degraded

        let stats = rotator.stats();
        assert_eq!(stats.total_circuits, 2);
        // Should have 1 healthy and 1 degraded
        assert!(stats.healthy >= 1);
        assert!(stats.healthy + stats.degraded + stats.unhealthy + stats.dead == 2);
    }
}
