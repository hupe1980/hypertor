//! Backpressure and flow control.
//!
//! Provides mechanisms for handling overload conditions gracefully,
//! including load shedding, request queuing limits, and adaptive throttling.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};
use tokio::sync::Semaphore;

/// Backpressure configuration.
#[derive(Debug, Clone)]
pub struct BackpressureConfig {
    /// Maximum concurrent requests
    pub max_concurrent: usize,
    /// Maximum queue depth
    pub max_queue_depth: usize,
    /// Target latency for adaptive throttling
    pub target_latency: Duration,
    /// Load shedding threshold (0.0-1.0)
    pub shed_threshold: f64,
    /// Window for calculating metrics
    pub metrics_window: Duration,
    /// Enable adaptive concurrency
    pub adaptive_concurrency: bool,
}

impl Default for BackpressureConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 100,
            max_queue_depth: 1000,
            target_latency: Duration::from_secs(5),
            shed_threshold: 0.9,
            metrics_window: Duration::from_secs(60),
            adaptive_concurrency: true,
        }
    }
}

impl BackpressureConfig {
    /// Create a new configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum concurrent requests.
    #[must_use]
    pub fn with_max_concurrent(mut self, max: usize) -> Self {
        self.max_concurrent = max;
        self
    }

    /// Set maximum queue depth.
    #[must_use]
    pub fn with_max_queue_depth(mut self, max: usize) -> Self {
        self.max_queue_depth = max;
        self
    }

    /// Set target latency.
    #[must_use]
    pub fn with_target_latency(mut self, latency: Duration) -> Self {
        self.target_latency = latency;
        self
    }

    /// Enable or disable adaptive concurrency.
    #[must_use]
    pub fn with_adaptive_concurrency(mut self, enabled: bool) -> Self {
        self.adaptive_concurrency = enabled;
        self
    }

    /// Set shed threshold.
    #[must_use]
    pub fn with_shed_threshold(mut self, threshold: f64) -> Self {
        self.shed_threshold = threshold;
        self
    }

    /// Create a configuration for high throughput.
    pub fn high_throughput() -> Self {
        Self {
            max_concurrent: 500,
            max_queue_depth: 5000,
            target_latency: Duration::from_secs(10),
            shed_threshold: 0.95,
            metrics_window: Duration::from_secs(30),
            adaptive_concurrency: true,
        }
    }

    /// Create a configuration for low latency.
    pub fn low_latency() -> Self {
        Self {
            max_concurrent: 50,
            max_queue_depth: 100,
            target_latency: Duration::from_secs(2),
            shed_threshold: 0.8,
            metrics_window: Duration::from_secs(15),
            adaptive_concurrency: true,
        }
    }
}

/// Latency sample for AIMD algorithm.
#[derive(Debug, Clone)]
struct LatencySample {
    latency: Duration,
    timestamp: Instant,
}

/// Result of attempting to acquire a permit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcquireResult {
    /// Permit acquired
    Acquired,
    /// Request queued (queue position)
    Queued(usize),
    /// Request shed (overloaded)
    Shed,
}

/// RAII guard for a backpressure permit.
#[derive(Debug)]
pub struct BackpressurePermit {
    controller: Arc<BackpressureController>,
    start_time: Instant,
    completed: bool,
}

impl BackpressurePermit {
    /// Record completion with a latency sample.
    pub fn complete(mut self, success: bool) {
        self.completed = true;
        let latency = self.start_time.elapsed();
        self.controller.record_completion(latency, success);
    }
}

impl Drop for BackpressurePermit {
    fn drop(&mut self) {
        if !self.completed {
            // Only decrement if not already done via complete()
            self.controller.in_flight.fetch_sub(1, Ordering::Relaxed);
            self.controller.semaphore.add_permits(1);
        }
    }
}

/// Backpressure controller implementing AIMD (Additive Increase Multiplicative Decrease).
#[derive(Debug)]
pub struct BackpressureController {
    config: BackpressureConfig,
    /// Semaphore for limiting concurrency
    semaphore: Arc<Semaphore>,
    /// Current in-flight requests
    in_flight: AtomicUsize,
    /// Current queue depth
    queue_depth: AtomicUsize,
    /// Current adaptive limit
    current_limit: AtomicUsize,
    /// Total requests
    total_requests: AtomicU64,
    /// Shed requests
    shed_requests: AtomicU64,
    /// Latency samples for adaptation
    samples: Mutex<Vec<LatencySample>>,
    /// Last adaptation time
    last_adaptation: RwLock<Instant>,
}

impl BackpressureController {
    /// Create a new backpressure controller.
    pub fn new(config: BackpressureConfig) -> Arc<Self> {
        let initial_limit = config.max_concurrent;
        Arc::new(Self {
            semaphore: Arc::new(Semaphore::new(config.max_concurrent)),
            in_flight: AtomicUsize::new(0),
            queue_depth: AtomicUsize::new(0),
            current_limit: AtomicUsize::new(initial_limit),
            total_requests: AtomicU64::new(0),
            shed_requests: AtomicU64::new(0),
            samples: Mutex::new(Vec::new()),
            last_adaptation: RwLock::new(Instant::now()),
            config,
        })
    }

    /// Try to acquire a permit for processing a request.
    pub async fn acquire(self: &Arc<Self>) -> Result<BackpressurePermit, BackpressureError> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        // Check load shedding
        let load = self.load_factor();
        if load >= self.config.shed_threshold {
            self.shed_requests.fetch_add(1, Ordering::Relaxed);
            return Err(BackpressureError::Overloaded { load_factor: load });
        }

        // Check queue depth
        let queue = self.queue_depth.fetch_add(1, Ordering::Relaxed);
        if queue >= self.config.max_queue_depth {
            self.queue_depth.fetch_sub(1, Ordering::Relaxed);
            self.shed_requests.fetch_add(1, Ordering::Relaxed);
            return Err(BackpressureError::QueueFull {
                depth: queue,
                max: self.config.max_queue_depth,
            });
        }

        // Wait for semaphore
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| BackpressureError::Closed)?;

        self.queue_depth.fetch_sub(1, Ordering::Relaxed);
        self.in_flight.fetch_add(1, Ordering::Relaxed);

        // Forget the permit since we track manually
        std::mem::forget(_permit);

        Ok(BackpressurePermit {
            controller: Arc::clone(self),
            start_time: Instant::now(),
            completed: false,
        })
    }

    /// Try to acquire immediately without waiting.
    pub fn try_acquire(self: &Arc<Self>) -> Result<BackpressurePermit, BackpressureError> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        // Check load shedding
        let load = self.load_factor();
        if load >= self.config.shed_threshold {
            self.shed_requests.fetch_add(1, Ordering::Relaxed);
            return Err(BackpressureError::Overloaded { load_factor: load });
        }

        // Try to acquire semaphore
        let _permit = self
            .semaphore
            .try_acquire()
            .map_err(|_| BackpressureError::WouldBlock {
                in_flight: self.in_flight.load(Ordering::Relaxed),
            })?;

        self.in_flight.fetch_add(1, Ordering::Relaxed);

        // Forget the permit since we track manually
        std::mem::forget(_permit);

        Ok(BackpressurePermit {
            controller: Arc::clone(self),
            start_time: Instant::now(),
            completed: false,
        })
    }

    /// Record completion and adapt concurrency.
    fn record_completion(&self, latency: Duration, success: bool) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
        self.semaphore.add_permits(1);

        if !self.config.adaptive_concurrency {
            return;
        }

        // Add sample
        {
            let mut samples = self.samples.lock();
            samples.push(LatencySample {
                latency,
                timestamp: Instant::now(),
            });

            // Clean old samples
            let cutoff = Instant::now() - self.config.metrics_window;
            samples.retain(|s| s.timestamp > cutoff);
        }

        // Adapt concurrency periodically
        let should_adapt = {
            let last = self.last_adaptation.read();
            last.elapsed() > Duration::from_secs(1)
        };

        if should_adapt {
            self.adapt_concurrency(success);
        }
    }

    /// Adapt concurrency using AIMD algorithm.
    fn adapt_concurrency(&self, success: bool) {
        *self.last_adaptation.write() = Instant::now();

        let samples = self.samples.lock();
        if samples.len() < 10 {
            return;
        }

        let avg_latency: Duration =
            samples.iter().map(|s| s.latency).sum::<Duration>() / samples.len() as u32;

        let current = self.current_limit.load(Ordering::Relaxed);

        let new_limit = if !success || avg_latency > self.config.target_latency {
            // Multiplicative decrease
            (current * 3 / 4).max(1)
        } else if avg_latency < self.config.target_latency / 2 {
            // Additive increase
            current.saturating_add(1).min(self.config.max_concurrent)
        } else {
            current
        };

        if new_limit != current {
            self.current_limit.store(new_limit, Ordering::Relaxed);
            // Adjust semaphore permits
            if new_limit > current {
                self.semaphore.add_permits(new_limit - current);
            }
            // For decrease, we just wait for permits to not be returned
        }
    }

    /// Get current load factor (0.0-1.0).
    pub fn load_factor(&self) -> f64 {
        let in_flight = self.in_flight.load(Ordering::Relaxed);
        let limit = self.current_limit.load(Ordering::Relaxed);
        if limit == 0 {
            return 1.0;
        }
        in_flight as f64 / limit as f64
    }

    /// Get current statistics.
    pub fn stats(&self) -> BackpressureStats {
        let samples = self.samples.lock();
        let avg_latency = if samples.is_empty() {
            Duration::ZERO
        } else {
            samples.iter().map(|s| s.latency).sum::<Duration>() / samples.len() as u32
        };

        let p99_latency = if samples.len() >= 100 {
            let mut latencies: Vec<_> = samples.iter().map(|s| s.latency).collect();
            latencies.sort();
            latencies[latencies.len() * 99 / 100]
        } else {
            avg_latency
        };

        BackpressureStats {
            in_flight: self.in_flight.load(Ordering::Relaxed),
            queue_depth: self.queue_depth.load(Ordering::Relaxed),
            current_limit: self.current_limit.load(Ordering::Relaxed),
            max_limit: self.config.max_concurrent,
            total_requests: self.total_requests.load(Ordering::Relaxed),
            shed_requests: self.shed_requests.load(Ordering::Relaxed),
            load_factor: self.load_factor(),
            avg_latency,
            p99_latency,
        }
    }

    /// Reset statistics.
    pub fn reset_stats(&self) {
        self.total_requests.store(0, Ordering::Relaxed);
        self.shed_requests.store(0, Ordering::Relaxed);
        self.samples.lock().clear();
    }
}

/// Backpressure error.
#[derive(Debug, Clone, thiserror::Error)]
pub enum BackpressureError {
    /// System is overloaded
    #[error("system overloaded, load factor: {load_factor:.2}")]
    Overloaded {
        /// Current load factor
        load_factor: f64,
    },

    /// Queue is full
    #[error("queue full, depth: {depth}, max: {max}")]
    QueueFull {
        /// Current depth
        depth: usize,
        /// Maximum depth
        max: usize,
    },

    /// Would block (non-blocking acquire)
    #[error("would block, {in_flight} requests in flight")]
    WouldBlock {
        /// Current in-flight
        in_flight: usize,
    },

    /// Controller is closed
    #[error("backpressure controller closed")]
    Closed,
}

/// Backpressure statistics.
#[derive(Debug, Clone)]
pub struct BackpressureStats {
    /// Current in-flight requests
    pub in_flight: usize,
    /// Current queue depth
    pub queue_depth: usize,
    /// Current adaptive limit
    pub current_limit: usize,
    /// Maximum configured limit
    pub max_limit: usize,
    /// Total requests received
    pub total_requests: u64,
    /// Requests shed due to overload
    pub shed_requests: u64,
    /// Current load factor
    pub load_factor: f64,
    /// Average latency
    pub avg_latency: Duration,
    /// P99 latency
    pub p99_latency: Duration,
}

impl BackpressureStats {
    /// Calculate shed rate.
    pub fn shed_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 0.0;
        }
        self.shed_requests as f64 / self.total_requests as f64
    }

    /// Check if system is healthy.
    pub fn is_healthy(&self) -> bool {
        self.load_factor < 0.8 && self.shed_rate() < 0.01
    }
}

/// Load shedder for selective request dropping.
#[derive(Debug)]
pub struct LoadShedder {
    /// Priority threshold for shedding
    threshold: AtomicUsize,
    /// Load factor from controller
    controller: Arc<BackpressureController>,
}

impl LoadShedder {
    /// Create a new load shedder.
    pub fn new(controller: Arc<BackpressureController>) -> Self {
        Self {
            threshold: AtomicUsize::new(0),
            controller,
        }
    }

    /// Update threshold based on load.
    pub fn update(&self) {
        let load = self.controller.load_factor();
        // Higher load = higher threshold = shed more low priority
        let threshold = if load > 0.9 {
            8 // Shed all but critical
        } else if load > 0.8 {
            5 // Shed low priority
        } else if load > 0.7 {
            3 // Shed very low priority
        } else {
            0 // Accept all
        };
        self.threshold.store(threshold, Ordering::Relaxed);
    }

    /// Check if a request with given priority should be accepted.
    /// Priority: 0 = lowest, 10 = highest (critical)
    pub fn should_accept(&self, priority: u8) -> bool {
        let threshold = self.threshold.load(Ordering::Relaxed);
        priority as usize >= threshold
    }

    /// Get current threshold.
    pub fn threshold(&self) -> usize {
        self.threshold.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[tokio::test]
    async fn test_backpressure_acquire() {
        let config = BackpressureConfig::default().with_max_concurrent(5);
        let controller = BackpressureController::new(config);

        // Should be able to acquire permits
        let permits: Vec<_> = (0..3).map(|_| controller.try_acquire().unwrap()).collect();

        assert_eq!(controller.in_flight.load(Ordering::Relaxed), 3);

        // Complete them
        for permit in permits {
            permit.complete(true);
        }

        assert_eq!(controller.in_flight.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_backpressure_limit() {
        let config = BackpressureConfig::default().with_max_concurrent(2);
        let controller = BackpressureController::new(config);

        // Acquire 2 permits
        let _p1 = controller.try_acquire().unwrap();
        let _p2 = controller.try_acquire().unwrap();

        // Third should fail
        let result = controller.try_acquire();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_load_shedding() {
        let config = BackpressureConfig::default()
            .with_max_concurrent(10)
            .with_shed_threshold(0.5);

        let controller = BackpressureController::new(config);

        // Acquire enough to trigger shedding
        let mut permits = Vec::new();
        for _ in 0..5 {
            permits.push(controller.try_acquire().unwrap());
        }

        // Load factor should be 0.5, at threshold
        let load = controller.load_factor();
        assert!(load >= 0.5);
    }

    #[test]
    fn test_load_shedder() {
        let config = BackpressureConfig::default().with_max_concurrent(10);
        let controller = BackpressureController::new(config);
        let shedder = LoadShedder::new(Arc::clone(&controller));

        // At low load, accept all
        shedder.update();
        assert!(shedder.should_accept(0));
        assert!(shedder.should_accept(10));
    }

    #[test]
    fn test_stats() {
        let config = BackpressureConfig::default().with_max_concurrent(100);
        let controller = BackpressureController::new(config);

        let stats = controller.stats();
        assert_eq!(stats.in_flight, 0);
        assert_eq!(stats.max_limit, 100);
        assert!(stats.is_healthy());
    }
}
