//! Circuit management for Tor connections
//!
//! Provides higher-level circuit lifecycle management including:
//! - Circuit health monitoring
//! - Automatic circuit rotation
//! - Per-destination circuit tracking

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tracing::{debug, info};

use crate::isolation::IsolationToken;

/// Circuit identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CircuitId(u64);

static CIRCUIT_COUNTER: AtomicU64 = AtomicU64::new(0);

impl CircuitId {
    /// Create a new unique circuit ID
    pub fn new() -> Self {
        Self(CIRCUIT_COUNTER.fetch_add(1, Ordering::Relaxed))
    }
}

impl Default for CircuitId {
    fn default() -> Self {
        Self::new()
    }
}

/// Circuit health status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitHealth {
    /// Circuit is healthy and usable
    Healthy,
    /// Circuit has degraded performance
    Degraded,
    /// Circuit should be replaced
    Unhealthy,
}

/// Metadata about a circuit
#[derive(Debug)]
pub struct CircuitInfo {
    /// Unique circuit identifier
    pub id: CircuitId,
    /// When the circuit was created
    pub created_at: Instant,
    /// Last time the circuit was used
    pub last_used: Instant,
    /// Number of requests made on this circuit
    pub request_count: u64,
    /// Number of failures on this circuit
    pub failure_count: u64,
    /// Isolation token if isolated
    pub isolation_token: Option<IsolationToken>,
}

impl CircuitInfo {
    /// Create new circuit info
    pub fn new(isolation_token: Option<IsolationToken>) -> Self {
        let now = Instant::now();
        Self {
            id: CircuitId::new(),
            created_at: now,
            last_used: now,
            request_count: 0,
            failure_count: 0,
            isolation_token,
        }
    }

    /// Get the age of this circuit
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get time since last use
    pub fn idle_time(&self) -> Duration {
        self.last_used.elapsed()
    }

    /// Record a successful request
    pub fn record_success(&mut self) {
        self.last_used = Instant::now();
        self.request_count += 1;
    }

    /// Record a failed request
    pub fn record_failure(&mut self) {
        self.last_used = Instant::now();
        self.failure_count += 1;
    }

    /// Get the health status of this circuit
    pub fn health(&self, config: &CircuitConfig) -> CircuitHealth {
        // Too old
        if self.age() > config.max_circuit_age {
            return CircuitHealth::Unhealthy;
        }

        // Too many failures
        if self.failure_count > config.max_failures {
            return CircuitHealth::Unhealthy;
        }

        // Too many requests (for privacy)
        if self.request_count > config.max_requests_per_circuit {
            return CircuitHealth::Unhealthy;
        }

        // High failure rate
        if self.request_count > 10 {
            let failure_rate = self.failure_count as f64 / self.request_count as f64;
            if failure_rate > 0.3 {
                return CircuitHealth::Degraded;
            }
        }

        CircuitHealth::Healthy
    }
}

/// Configuration for circuit management
#[derive(Debug, Clone)]
pub struct CircuitConfig {
    /// Maximum age of a circuit before rotation
    pub max_circuit_age: Duration,
    /// Maximum requests per circuit (for privacy)
    pub max_requests_per_circuit: u64,
    /// Maximum failures before circuit is marked unhealthy
    pub max_failures: u64,
    /// Idle timeout before circuit cleanup
    pub idle_timeout: Duration,
}

impl Default for CircuitConfig {
    fn default() -> Self {
        Self {
            max_circuit_age: Duration::from_secs(600), // 10 minutes
            max_requests_per_circuit: 100,             // Privacy limit
            max_failures: 5,                           // Failure threshold
            idle_timeout: Duration::from_secs(120),    // 2 minutes
        }
    }
}

/// Manages circuit lifecycle and health
pub struct CircuitManager {
    /// Active circuits by destination
    circuits: RwLock<HashMap<String, CircuitInfo>>,
    /// Configuration
    config: CircuitConfig,
}

impl CircuitManager {
    /// Create a new circuit manager
    pub fn new(config: CircuitConfig) -> Self {
        Self {
            circuits: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Get or create a circuit for a destination
    pub fn get_or_create(&self, destination: &str, isolation: Option<IsolationToken>) -> CircuitId {
        let key = self.make_key(destination, isolation);

        // Check if we have a healthy circuit
        {
            let circuits = self.circuits.read();
            if let Some(info) = circuits.get(&key) {
                if info.health(&self.config) == CircuitHealth::Healthy {
                    return info.id;
                }
            }
        }

        // Create new circuit
        let mut circuits = self.circuits.write();
        let info = CircuitInfo::new(isolation);
        let id = info.id;
        circuits.insert(key, info);

        debug!(circuit_id = id.0, destination, "Created new circuit");
        id
    }

    /// Record a successful request on a circuit
    pub fn record_success(&self, destination: &str, isolation: Option<IsolationToken>) {
        let key = self.make_key(destination, isolation);
        let mut circuits = self.circuits.write();
        if let Some(info) = circuits.get_mut(&key) {
            info.record_success();
        }
    }

    /// Record a failed request on a circuit
    pub fn record_failure(&self, destination: &str, isolation: Option<IsolationToken>) {
        let key = self.make_key(destination, isolation);
        let mut circuits = self.circuits.write();
        if let Some(info) = circuits.get_mut(&key) {
            info.record_failure();
        }
    }

    /// Clean up old/unhealthy circuits
    pub fn cleanup(&self) {
        let mut circuits = self.circuits.write();
        let before = circuits.len();

        circuits.retain(|_, info| {
            info.health(&self.config) != CircuitHealth::Unhealthy
                && info.idle_time() < self.config.idle_timeout
        });

        let removed = before - circuits.len();
        if removed > 0 {
            info!(removed, remaining = circuits.len(), "Cleaned up circuits");
        }
    }

    /// Get statistics about managed circuits
    pub fn stats(&self) -> CircuitStats {
        let circuits = self.circuits.read();

        let mut healthy = 0;
        let mut degraded = 0;
        let mut unhealthy = 0;

        for info in circuits.values() {
            match info.health(&self.config) {
                CircuitHealth::Healthy => healthy += 1,
                CircuitHealth::Degraded => degraded += 1,
                CircuitHealth::Unhealthy => unhealthy += 1,
            }
        }

        CircuitStats {
            total: circuits.len(),
            healthy,
            degraded,
            unhealthy,
        }
    }

    fn make_key(&self, destination: &str, isolation: Option<IsolationToken>) -> String {
        match isolation {
            Some(token) => format!("{}:{}", destination, token.as_raw()),
            None => destination.to_string(),
        }
    }
}

/// Statistics about managed circuits
#[derive(Debug, Clone)]
pub struct CircuitStats {
    /// Total number of circuits
    pub total: usize,
    /// Number of healthy circuits
    pub healthy: usize,
    /// Number of degraded circuits
    pub degraded: usize,
    /// Number of unhealthy circuits
    pub unhealthy: usize,
}

impl Default for CircuitManager {
    fn default() -> Self {
        Self::new(CircuitConfig::default())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_circuit_id_uniqueness() {
        let id1 = CircuitId::new();
        let id2 = CircuitId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_circuit_health_new() {
        let config = CircuitConfig::default();
        let info = CircuitInfo::new(None);
        assert_eq!(info.health(&config), CircuitHealth::Healthy);
    }

    #[test]
    fn test_circuit_manager_get_or_create() {
        let manager = CircuitManager::default();
        let id1 = manager.get_or_create("example.com:443", None);
        let id2 = manager.get_or_create("example.com:443", None);
        assert_eq!(id1, id2); // Same destination = same circuit
    }
}
