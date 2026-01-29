//! Circuit breaker pattern for fault tolerance.
//!
//! Implements the circuit breaker pattern to prevent cascading failures
//! by failing fast when a service is unhealthy.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::RwLock;

/// Circuit breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    /// Circuit is closed - requests flow normally
    Closed,
    /// Circuit is open - requests fail immediately
    Open,
    /// Circuit is half-open - testing if service recovered
    HalfOpen,
}

impl BreakerState {
    /// Check if requests should be allowed.
    pub fn allows_requests(&self) -> bool {
        matches!(self, Self::Closed | Self::HalfOpen)
    }

    /// Check if the circuit is tripped.
    pub fn is_tripped(&self) -> bool {
        matches!(self, Self::Open | Self::HalfOpen)
    }
}

/// Circuit breaker configuration.
#[derive(Debug, Clone)]
pub struct BreakerConfig {
    /// Number of failures before opening the circuit
    pub failure_threshold: u32,
    /// Number of successes to close a half-open circuit
    pub success_threshold: u32,
    /// Time to wait before transitioning from open to half-open
    pub reset_timeout: Duration,
    /// Time window for counting failures
    pub failure_window: Duration,
    /// Maximum concurrent requests in half-open state
    pub half_open_max_requests: u32,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 3,
            reset_timeout: Duration::from_secs(30),
            failure_window: Duration::from_secs(60),
            half_open_max_requests: 3,
        }
    }
}

impl BreakerConfig {
    /// Create a new configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the failure threshold.
    #[must_use]
    pub fn with_failure_threshold(mut self, threshold: u32) -> Self {
        self.failure_threshold = threshold;
        self
    }

    /// Set the success threshold.
    #[must_use]
    pub fn with_success_threshold(mut self, threshold: u32) -> Self {
        self.success_threshold = threshold;
        self
    }

    /// Set the reset timeout.
    #[must_use]
    pub fn with_reset_timeout(mut self, timeout: Duration) -> Self {
        self.reset_timeout = timeout;
        self
    }

    /// Create a sensitive configuration (trips quickly).
    pub fn sensitive() -> Self {
        Self {
            failure_threshold: 3,
            success_threshold: 2,
            reset_timeout: Duration::from_secs(15),
            failure_window: Duration::from_secs(30),
            half_open_max_requests: 1,
        }
    }

    /// Create a tolerant configuration (more forgiving).
    pub fn tolerant() -> Self {
        Self {
            failure_threshold: 10,
            success_threshold: 5,
            reset_timeout: Duration::from_secs(60),
            failure_window: Duration::from_secs(120),
            half_open_max_requests: 5,
        }
    }
}

/// Circuit breaker for a single endpoint.
#[derive(Debug)]
pub struct CircuitBreaker {
    config: BreakerConfig,
    state: RwLock<BreakerState>,
    failure_count: AtomicU32,
    success_count: AtomicU32,
    half_open_requests: AtomicU32,
    last_failure: RwLock<Option<Instant>>,
    opened_at: RwLock<Option<Instant>>,
    total_requests: AtomicU64,
    total_failures: AtomicU64,
    total_rejections: AtomicU64,
}

impl CircuitBreaker {
    /// Create a new circuit breaker.
    pub fn new(config: BreakerConfig) -> Self {
        Self {
            config,
            state: RwLock::new(BreakerState::Closed),
            failure_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
            half_open_requests: AtomicU32::new(0),
            last_failure: RwLock::new(None),
            opened_at: RwLock::new(None),
            total_requests: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
            total_rejections: AtomicU64::new(0),
        }
    }

    /// Get the current state.
    pub fn state(&self) -> BreakerState {
        self.maybe_transition();
        *self.state.read()
    }

    /// Check if a request is allowed.
    pub fn allow_request(&self) -> BreakerResult {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.maybe_transition();

        let state = *self.state.read();
        match state {
            BreakerState::Closed => BreakerResult::Allowed,
            BreakerState::Open => {
                self.total_rejections.fetch_add(1, Ordering::Relaxed);
                BreakerResult::Rejected {
                    retry_after: self.time_until_half_open(),
                }
            }
            BreakerState::HalfOpen => {
                let current = self.half_open_requests.fetch_add(1, Ordering::Relaxed);
                if current < self.config.half_open_max_requests {
                    BreakerResult::AllowedProbe
                } else {
                    self.half_open_requests.fetch_sub(1, Ordering::Relaxed);
                    self.total_rejections.fetch_add(1, Ordering::Relaxed);
                    BreakerResult::Rejected {
                        retry_after: Some(Duration::from_millis(100)),
                    }
                }
            }
        }
    }

    /// Record a successful request.
    pub fn record_success(&self) {
        let state = *self.state.read();

        match state {
            BreakerState::Closed => {
                // Reset failure count on success
                self.failure_count.store(0, Ordering::Relaxed);
            }
            BreakerState::HalfOpen => {
                self.half_open_requests.fetch_sub(1, Ordering::Relaxed);
                let count = self.success_count.fetch_add(1, Ordering::Relaxed) + 1;
                if count >= self.config.success_threshold {
                    self.close();
                }
            }
            BreakerState::Open => {
                // Shouldn't happen, but ignore
            }
        }
    }

    /// Record a failed request.
    pub fn record_failure(&self) {
        self.total_failures.fetch_add(1, Ordering::Relaxed);
        *self.last_failure.write() = Some(Instant::now());

        let state = *self.state.read();

        match state {
            BreakerState::Closed => {
                let count = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
                if count >= self.config.failure_threshold {
                    self.open();
                }
            }
            BreakerState::HalfOpen => {
                self.half_open_requests.fetch_sub(1, Ordering::Relaxed);
                // Single failure in half-open reopens the circuit
                self.open();
            }
            BreakerState::Open => {
                // Already open, ignore
            }
        }
    }

    /// Transition to open state.
    fn open(&self) {
        let mut state = self.state.write();
        *state = BreakerState::Open;
        *self.opened_at.write() = Some(Instant::now());
        self.success_count.store(0, Ordering::Relaxed);
        self.half_open_requests.store(0, Ordering::Relaxed);
    }

    /// Transition to closed state.
    fn close(&self) {
        let mut state = self.state.write();
        *state = BreakerState::Closed;
        self.failure_count.store(0, Ordering::Relaxed);
        self.success_count.store(0, Ordering::Relaxed);
        *self.opened_at.write() = None;
    }

    /// Check and perform state transitions.
    fn maybe_transition(&self) {
        let current_state = *self.state.read();

        match current_state {
            BreakerState::Open => {
                if let Some(opened) = *self.opened_at.read() {
                    if opened.elapsed() >= self.config.reset_timeout {
                        let mut state = self.state.write();
                        if *state == BreakerState::Open {
                            *state = BreakerState::HalfOpen;
                            self.half_open_requests.store(0, Ordering::Relaxed);
                            self.success_count.store(0, Ordering::Relaxed);
                        }
                    }
                }
            }
            BreakerState::Closed => {
                // Check if failures are outside the window
                if let Some(last) = *self.last_failure.read() {
                    if last.elapsed() > self.config.failure_window {
                        self.failure_count.store(0, Ordering::Relaxed);
                    }
                }
            }
            BreakerState::HalfOpen => {
                // No automatic transitions from half-open
            }
        }
    }

    /// Get time until the circuit might transition to half-open.
    fn time_until_half_open(&self) -> Option<Duration> {
        if let Some(opened) = *self.opened_at.read() {
            let elapsed = opened.elapsed();
            if elapsed < self.config.reset_timeout {
                return Some(self.config.reset_timeout - elapsed);
            }
        }
        None
    }

    /// Force the circuit to close (manual override).
    pub fn force_close(&self) {
        self.close();
    }

    /// Force the circuit to open (manual override).
    pub fn force_open(&self) {
        self.open();
    }

    /// Get circuit breaker statistics.
    pub fn stats(&self) -> BreakerStats {
        BreakerStats {
            state: self.state(),
            total_requests: self.total_requests.load(Ordering::Relaxed),
            total_failures: self.total_failures.load(Ordering::Relaxed),
            total_rejections: self.total_rejections.load(Ordering::Relaxed),
            current_failures: self.failure_count.load(Ordering::Relaxed),
            current_successes: self.success_count.load(Ordering::Relaxed),
        }
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(BreakerConfig::default())
    }
}

/// Result of checking if a request is allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakerResult {
    /// Request is allowed (circuit closed)
    Allowed,
    /// Request is allowed as a probe (circuit half-open)
    AllowedProbe,
    /// Request is rejected (circuit open)
    Rejected {
        /// Suggested time to wait before retrying
        retry_after: Option<Duration>,
    },
}

impl BreakerResult {
    /// Check if the request is allowed.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed | Self::AllowedProbe)
    }

    /// Check if this is a probe request.
    pub fn is_probe(&self) -> bool {
        matches!(self, Self::AllowedProbe)
    }
}

/// Circuit breaker statistics.
#[derive(Debug, Clone)]
pub struct BreakerStats {
    /// Current state
    pub state: BreakerState,
    /// Total requests attempted
    pub total_requests: u64,
    /// Total failures recorded
    pub total_failures: u64,
    /// Total rejections due to open circuit
    pub total_rejections: u64,
    /// Current failure count in window
    pub current_failures: u32,
    /// Current success count (half-open only)
    pub current_successes: u32,
}

impl BreakerStats {
    /// Calculate the failure rate.
    pub fn failure_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 0.0;
        }
        self.total_failures as f64 / self.total_requests as f64
    }

    /// Calculate the rejection rate.
    pub fn rejection_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 0.0;
        }
        self.total_rejections as f64 / self.total_requests as f64
    }
}

/// Multi-host circuit breaker manager.
#[derive(Debug)]
pub struct BreakerManager {
    config: BreakerConfig,
    breakers: RwLock<std::collections::HashMap<String, Arc<CircuitBreaker>>>,
}

impl BreakerManager {
    /// Create a new manager.
    pub fn new(config: BreakerConfig) -> Self {
        Self {
            config,
            breakers: RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Get or create a circuit breaker for a host.
    pub fn get(&self, host: &str) -> Arc<CircuitBreaker> {
        // Try read lock first
        {
            let breakers = self.breakers.read();
            if let Some(breaker) = breakers.get(host) {
                return Arc::clone(breaker);
            }
        }

        // Need write lock to create
        let mut breakers = self.breakers.write();
        breakers
            .entry(host.to_string())
            .or_insert_with(|| Arc::new(CircuitBreaker::new(self.config.clone())))
            .clone()
    }

    /// Check if a request to a host is allowed.
    pub fn allow_request(&self, host: &str) -> BreakerResult {
        self.get(host).allow_request()
    }

    /// Record success for a host.
    pub fn record_success(&self, host: &str) {
        self.get(host).record_success();
    }

    /// Record failure for a host.
    pub fn record_failure(&self, host: &str) {
        self.get(host).record_failure();
    }

    /// Get all hosts with open circuits.
    pub fn open_circuits(&self) -> Vec<String> {
        let breakers = self.breakers.read();
        breakers
            .iter()
            .filter(|(_, b)| b.state() == BreakerState::Open)
            .map(|(h, _)| h.clone())
            .collect()
    }

    /// Get statistics for all hosts.
    pub fn all_stats(&self) -> Vec<(String, BreakerStats)> {
        let breakers = self.breakers.read();
        breakers
            .iter()
            .map(|(h, b)| (h.clone(), b.stats()))
            .collect()
    }
}

impl Default for BreakerManager {
    fn default() -> Self {
        Self::new(BreakerConfig::default())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_circuit_breaker_closed() {
        let breaker = CircuitBreaker::default();
        assert_eq!(breaker.state(), BreakerState::Closed);
        assert!(breaker.allow_request().is_allowed());
    }

    #[test]
    fn test_circuit_breaker_opens_on_failures() {
        let config = BreakerConfig::new().with_failure_threshold(3);
        let breaker = CircuitBreaker::new(config);

        // Record failures
        breaker.record_failure();
        breaker.record_failure();
        assert_eq!(breaker.state(), BreakerState::Closed);

        breaker.record_failure();
        assert_eq!(breaker.state(), BreakerState::Open);
        assert!(!breaker.allow_request().is_allowed());
    }

    #[test]
    fn test_circuit_breaker_success_resets_failures() {
        let config = BreakerConfig::new().with_failure_threshold(3);
        let breaker = CircuitBreaker::new(config);

        breaker.record_failure();
        breaker.record_failure();
        breaker.record_success(); // Resets count

        breaker.record_failure();
        assert_eq!(breaker.state(), BreakerState::Closed);
    }

    #[test]
    fn test_circuit_breaker_half_open() {
        let config = BreakerConfig::new()
            .with_failure_threshold(1)
            .with_reset_timeout(Duration::from_millis(10));
        let breaker = CircuitBreaker::new(config);

        breaker.record_failure();
        assert_eq!(breaker.state(), BreakerState::Open);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(15));
        assert_eq!(breaker.state(), BreakerState::HalfOpen);
    }

    #[test]
    fn test_breaker_manager() {
        let manager = BreakerManager::default();

        manager.record_success("host1.onion");
        manager.record_failure("host2.onion");

        let stats1 = manager.get("host1.onion").stats();
        let stats2 = manager.get("host2.onion").stats();

        assert_eq!(stats1.total_failures, 0);
        assert_eq!(stats2.total_failures, 1);
    }

    #[test]
    fn test_breaker_stats() {
        let breaker = CircuitBreaker::default();

        for _ in 0..10 {
            let _ = breaker.allow_request();
            breaker.record_success();
        }
        for _ in 0..2 {
            let _ = breaker.allow_request();
            breaker.record_failure();
        }

        let stats = breaker.stats();
        assert_eq!(stats.total_requests, 12);
        assert!(stats.failure_rate() > 0.16 && stats.failure_rate() < 0.17);
    }
}
