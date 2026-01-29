//! Token bucket rate limiter.
//!
//! Provides per-host rate limiting using the token bucket algorithm.
//! Supports burst allowance and graceful degradation.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// Token bucket for rate limiting.
#[derive(Debug)]
pub struct TokenBucket {
    /// Maximum tokens (burst capacity)
    capacity: u32,
    /// Current token count
    tokens: f64,
    /// Tokens added per second
    rate: f64,
    /// Last refill time
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a new token bucket.
    ///
    /// # Arguments
    /// * `capacity` - Maximum tokens (burst capacity)
    /// * `rate` - Tokens per second
    pub fn new(capacity: u32, rate: f64) -> Self {
        Self {
            capacity,
            tokens: capacity as f64,
            rate,
            last_refill: Instant::now(),
        }
    }

    /// Refill tokens based on elapsed time.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let new_tokens = elapsed.as_secs_f64() * self.rate;
        self.tokens = (self.tokens + new_tokens).min(self.capacity as f64);
        self.last_refill = now;
    }

    /// Try to acquire a token. Returns true if successful.
    pub fn try_acquire(&mut self) -> bool {
        self.try_acquire_n(1)
    }

    /// Try to acquire N tokens. Returns true if successful.
    pub fn try_acquire_n(&mut self, n: u32) -> bool {
        self.refill();
        let n = n as f64;
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }

    /// Get the time until N tokens are available.
    pub fn time_until_available(&mut self, n: u32) -> Duration {
        self.refill();
        let n = n as f64;
        if self.tokens >= n {
            return Duration::ZERO;
        }
        let needed = n - self.tokens;
        Duration::from_secs_f64(needed / self.rate)
    }

    /// Get current token count.
    pub fn available(&mut self) -> u32 {
        self.refill();
        self.tokens as u32
    }

    /// Get bucket capacity.
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Get refill rate.
    pub fn rate(&self) -> f64 {
        self.rate
    }
}

/// Rate limiter configuration.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Default requests per second
    pub default_rate: f64,
    /// Default burst capacity
    pub default_burst: u32,
    /// Per-host overrides
    pub host_limits: HashMap<String, (f64, u32)>,
    /// Whether to wait or reject when rate limited
    pub wait_on_limit: bool,
    /// Maximum wait time before rejecting
    pub max_wait: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            default_rate: 10.0, // 10 requests/sec
            default_burst: 20,  // Allow burst of 20
            host_limits: HashMap::new(),
            wait_on_limit: true,
            max_wait: Duration::from_secs(30),
        }
    }
}

impl RateLimitConfig {
    /// Create a new configuration.
    pub fn new(rate: f64, burst: u32) -> Self {
        Self {
            default_rate: rate,
            default_burst: burst,
            ..Default::default()
        }
    }

    /// Add a per-host rate limit.
    #[must_use]
    pub fn with_host_limit(mut self, host: &str, rate: f64, burst: u32) -> Self {
        self.host_limits.insert(host.to_string(), (rate, burst));
        self
    }

    /// Set whether to wait when rate limited.
    #[must_use]
    pub fn with_wait_on_limit(mut self, wait: bool) -> Self {
        self.wait_on_limit = wait;
        self
    }

    /// Set maximum wait time.
    #[must_use]
    pub fn with_max_wait(mut self, duration: Duration) -> Self {
        self.max_wait = duration;
        self
    }

    /// Get rate limit for a host.
    pub fn get_limit(&self, host: &str) -> (f64, u32) {
        self.host_limits
            .get(host)
            .copied()
            .unwrap_or((self.default_rate, self.default_burst))
    }
}

/// Per-host rate limiter.
#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimitConfig,
    buckets: Arc<Mutex<HashMap<String, TokenBucket>>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(RateLimitConfig::default())
    }
}

impl RateLimiter {
    /// Create a new rate limiter.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Try to acquire a permit for a host.
    pub fn try_acquire(&self, host: &str) -> bool {
        let mut buckets = self.buckets.lock();
        let (rate, burst) = self.config.get_limit(host);
        let bucket = buckets
            .entry(host.to_string())
            .or_insert_with(|| TokenBucket::new(burst, rate));
        bucket.try_acquire()
    }

    /// Get time until a permit is available.
    pub fn time_until_available(&self, host: &str) -> Duration {
        let mut buckets = self.buckets.lock();
        let (rate, burst) = self.config.get_limit(host);
        let bucket = buckets
            .entry(host.to_string())
            .or_insert_with(|| TokenBucket::new(burst, rate));
        bucket.time_until_available(1)
    }

    /// Acquire a permit, waiting if necessary.
    pub async fn acquire(&self, host: &str) -> RateLimitResult {
        if self.try_acquire(host) {
            return RateLimitResult::Acquired;
        }

        if !self.config.wait_on_limit {
            return RateLimitResult::Rejected;
        }

        let wait_time = self.time_until_available(host);
        if wait_time > self.config.max_wait {
            return RateLimitResult::Rejected;
        }

        tokio::time::sleep(wait_time).await;

        if self.try_acquire(host) {
            RateLimitResult::AcquiredAfterWait(wait_time)
        } else {
            RateLimitResult::Rejected
        }
    }

    /// Get current available tokens for a host.
    pub fn available(&self, host: &str) -> u32 {
        let mut buckets = self.buckets.lock();
        if let Some(bucket) = buckets.get_mut(host) {
            bucket.available()
        } else {
            let (_, burst) = self.config.get_limit(host);
            burst
        }
    }

    /// Clean up stale buckets.
    pub fn cleanup(&self, max_idle: Duration) {
        let mut buckets = self.buckets.lock();
        let now = Instant::now();
        buckets.retain(|_, bucket| now.duration_since(bucket.last_refill) < max_idle);
    }

    /// Get the number of tracked hosts.
    pub fn host_count(&self) -> usize {
        self.buckets.lock().len()
    }
}

/// Result of rate limit acquisition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitResult {
    /// Permit acquired immediately
    Acquired,
    /// Permit acquired after waiting
    AcquiredAfterWait(Duration),
    /// Request rejected due to rate limit
    Rejected,
}

impl RateLimitResult {
    /// Check if the permit was acquired.
    pub fn is_acquired(&self) -> bool {
        matches!(self, Self::Acquired | Self::AcquiredAfterWait(_))
    }

    /// Check if the request was rejected.
    pub fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected)
    }
}

/// Sliding window rate limiter for more accurate limiting.
#[derive(Debug)]
pub struct SlidingWindowLimiter {
    /// Window size
    window: Duration,
    /// Maximum requests per window
    max_requests: u32,
    /// Request timestamps per host
    requests: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl SlidingWindowLimiter {
    /// Create a new sliding window limiter.
    pub fn new(window: Duration, max_requests: u32) -> Self {
        Self {
            window,
            max_requests,
            requests: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Try to acquire a permit.
    pub fn try_acquire(&self, host: &str) -> bool {
        let mut requests = self.requests.lock();
        let timestamps = requests.entry(host.to_string()).or_default();

        // Remove old timestamps
        let cutoff = Instant::now() - self.window;
        timestamps.retain(|&t| t > cutoff);

        if timestamps.len() < self.max_requests as usize {
            timestamps.push(Instant::now());
            true
        } else {
            false
        }
    }

    /// Get the number of requests in the current window.
    pub fn current_count(&self, host: &str) -> u32 {
        let mut requests = self.requests.lock();
        let timestamps = requests.entry(host.to_string()).or_default();

        let cutoff = Instant::now() - self.window;
        timestamps.retain(|&t| t > cutoff);
        timestamps.len() as u32
    }

    /// Clean up stale entries.
    pub fn cleanup(&self) {
        let mut requests = self.requests.lock();
        let cutoff = Instant::now() - self.window;
        for timestamps in requests.values_mut() {
            timestamps.retain(|&t| t > cutoff);
        }
        requests.retain(|_, v| !v.is_empty());
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(10, 5.0);

        assert_eq!(bucket.available(), 10);
        assert!(bucket.try_acquire());
        assert_eq!(bucket.available(), 9);

        // Acquire all tokens
        for _ in 0..9 {
            assert!(bucket.try_acquire());
        }
        assert!(!bucket.try_acquire());
    }

    #[test]
    fn test_token_bucket_refill() {
        let mut bucket = TokenBucket::new(10, 100.0); // 100 tokens/sec

        // Drain bucket
        while bucket.try_acquire() {}

        // Wait a bit for refill
        std::thread::sleep(Duration::from_millis(50));

        // Should have some tokens now
        assert!(bucket.available() > 0);
    }

    #[test]
    fn test_rate_limiter() {
        let config = RateLimitConfig::new(100.0, 10).with_host_limit("slow.com", 1.0, 2);
        let limiter = RateLimiter::new(config);

        // Fast host
        for _ in 0..10 {
            assert!(limiter.try_acquire("fast.com"));
        }

        // Slow host
        assert!(limiter.try_acquire("slow.com"));
        assert!(limiter.try_acquire("slow.com"));
        assert!(!limiter.try_acquire("slow.com"));
    }

    #[test]
    fn test_sliding_window() {
        let limiter = SlidingWindowLimiter::new(Duration::from_secs(1), 5);

        for _ in 0..5 {
            assert!(limiter.try_acquire("test.com"));
        }
        assert!(!limiter.try_acquire("test.com"));

        assert_eq!(limiter.current_count("test.com"), 5);
    }

    #[tokio::test]
    async fn test_rate_limiter_acquire() {
        let config = RateLimitConfig::new(100.0, 2)
            .with_wait_on_limit(true)
            .with_max_wait(Duration::from_millis(100));
        let limiter = RateLimiter::new(config);

        // Drain tokens
        limiter.try_acquire("test.com");
        limiter.try_acquire("test.com");

        // Should wait and acquire
        let result = limiter.acquire("test.com").await;
        assert!(result.is_acquired());
    }
}
