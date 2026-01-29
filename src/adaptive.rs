//! Adaptive retry strategy.
//!
//! Provides intelligent retry strategies that adapt based on
//! observed circuit and network conditions.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::RwLock;

/// Adaptive retry configuration.
#[derive(Debug, Clone)]
pub struct AdaptiveRetryConfig {
    /// Minimum retry delay
    pub min_delay: Duration,
    /// Maximum retry delay
    pub max_delay: Duration,
    /// Maximum retry attempts
    pub max_attempts: u32,
    /// Target success rate to aim for
    pub target_success_rate: f64,
    /// Window size for calculating statistics
    pub stats_window: usize,
    /// Learning rate for adaptation
    pub learning_rate: f64,
}

impl Default for AdaptiveRetryConfig {
    fn default() -> Self {
        Self {
            min_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(60),
            max_attempts: 5,
            target_success_rate: 0.95,
            stats_window: 100,
            learning_rate: 0.1,
        }
    }
}

impl AdaptiveRetryConfig {
    /// Create a new configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set minimum delay.
    #[must_use]
    pub fn with_min_delay(mut self, delay: Duration) -> Self {
        self.min_delay = delay;
        self
    }

    /// Set maximum delay.
    #[must_use]
    pub fn with_max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// Set maximum attempts.
    #[must_use]
    pub fn with_max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = attempts;
        self
    }

    /// Create an aggressive configuration (faster retries).
    pub fn aggressive() -> Self {
        Self {
            min_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(10),
            max_attempts: 10,
            target_success_rate: 0.99,
            stats_window: 50,
            learning_rate: 0.2,
        }
    }

    /// Create a conservative configuration (slower retries).
    pub fn conservative() -> Self {
        Self {
            min_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(120),
            max_attempts: 3,
            target_success_rate: 0.90,
            stats_window: 200,
            learning_rate: 0.05,
        }
    }
}

/// Outcome of a request attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// Request succeeded
    Success,
    /// Transient failure (retry may help)
    TransientFailure,
    /// Permanent failure (don't retry)
    PermanentFailure,
    /// Timeout
    Timeout,
    /// Rate limited
    RateLimited,
}

impl AttemptOutcome {
    /// Check if this outcome is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::TransientFailure | Self::Timeout | Self::RateLimited
        )
    }

    /// Get a base multiplier for this outcome type.
    pub fn delay_multiplier(&self) -> f64 {
        match self {
            Self::Success => 1.0,
            Self::TransientFailure => 1.5,
            Self::Timeout => 2.0,
            Self::RateLimited => 3.0, // Back off more for rate limits
            Self::PermanentFailure => 1.0,
        }
    }
}

/// Record of a single attempt.
#[derive(Debug, Clone)]
struct AttemptRecord {
    outcome: AttemptOutcome,
    latency: Duration,
}

/// Adaptive retry strategy that learns from outcomes.
#[derive(Debug)]
pub struct AdaptiveRetry {
    config: AdaptiveRetryConfig,
    /// Recent attempt history
    history: RwLock<VecDeque<AttemptRecord>>,
    /// Current delay multiplier (adapted over time)
    delay_multiplier: RwLock<f64>,
    /// Total attempts
    total_attempts: AtomicU64,
    /// Total successes
    total_successes: AtomicU64,
    /// Current base delay
    current_delay: RwLock<Duration>,
}

impl AdaptiveRetry {
    /// Create a new adaptive retry strategy.
    pub fn new(config: AdaptiveRetryConfig) -> Self {
        let initial_delay = config.min_delay;
        Self {
            config,
            history: RwLock::new(VecDeque::new()),
            delay_multiplier: RwLock::new(1.0),
            total_attempts: AtomicU64::new(0),
            total_successes: AtomicU64::new(0),
            current_delay: RwLock::new(initial_delay),
        }
    }

    /// Record an attempt outcome.
    pub fn record_outcome(&self, outcome: AttemptOutcome, latency: Duration) {
        self.total_attempts.fetch_add(1, Ordering::Relaxed);
        if outcome == AttemptOutcome::Success {
            self.total_successes.fetch_add(1, Ordering::Relaxed);
        }

        let record = AttemptRecord { outcome, latency };

        // Update history
        {
            let mut history = self.history.write();
            history.push_back(record);
            while history.len() > self.config.stats_window {
                history.pop_front();
            }
        }

        // Adapt based on recent performance
        self.adapt();
    }

    /// Adapt the retry parameters based on observed outcomes.
    fn adapt(&self) {
        let history = self.history.read();
        if history.len() < 10 {
            return; // Not enough data
        }

        // Calculate recent success rate
        let successes = history
            .iter()
            .filter(|r| r.outcome == AttemptOutcome::Success)
            .count();
        let success_rate = successes as f64 / history.len() as f64;

        // Calculate average latency of successful requests
        let successful_latencies: Vec<_> = history
            .iter()
            .filter(|r| r.outcome == AttemptOutcome::Success)
            .map(|r| r.latency)
            .collect();

        let avg_latency = if successful_latencies.is_empty() {
            self.config.min_delay
        } else {
            let total: Duration = successful_latencies.iter().sum();
            total / successful_latencies.len() as u32
        };

        // Adjust delay multiplier based on success rate vs target
        let rate_diff = self.config.target_success_rate - success_rate;
        let adjustment = rate_diff * self.config.learning_rate;

        {
            let mut multiplier = self.delay_multiplier.write();
            *multiplier = (*multiplier * (1.0 + adjustment)).clamp(0.5, 4.0);
        }

        // Update base delay based on observed latency
        {
            let mut current = self.current_delay.write();
            // Base delay should be a fraction of average successful latency
            let target_delay = avg_latency / 4;
            let new_delay = Duration::from_secs_f64(
                current.as_secs_f64() * (1.0 - self.config.learning_rate)
                    + target_delay.as_secs_f64() * self.config.learning_rate,
            );
            *current = new_delay.clamp(self.config.min_delay, self.config.max_delay);
        }
    }

    /// Get the delay for a specific attempt number.
    pub fn get_delay(&self, attempt: u32, last_outcome: Option<AttemptOutcome>) -> Duration {
        let base = *self.current_delay.read();
        let multiplier = *self.delay_multiplier.read();

        // Exponential backoff
        let exp_factor = 2.0_f64.powi(attempt.saturating_sub(1) as i32);

        // Outcome-specific adjustment
        let outcome_factor = last_outcome.map(|o| o.delay_multiplier()).unwrap_or(1.0);

        // Add jitter (±25%)
        let jitter = 0.75 + (self.total_attempts.load(Ordering::Relaxed) % 50) as f64 / 100.0;

        let delay = base.as_secs_f64() * multiplier * exp_factor * outcome_factor * jitter;
        Duration::from_secs_f64(delay).clamp(self.config.min_delay, self.config.max_delay)
    }

    /// Check if another retry should be attempted.
    pub fn should_retry(&self, attempt: u32, outcome: AttemptOutcome) -> RetryDecision {
        if !outcome.is_retryable() {
            return RetryDecision::DoNotRetry;
        }

        if attempt >= self.config.max_attempts {
            return RetryDecision::MaxAttemptsReached;
        }

        let delay = self.get_delay(attempt + 1, Some(outcome));
        RetryDecision::Retry { delay }
    }

    /// Get current statistics.
    pub fn stats(&self) -> AdaptiveRetryStats {
        let history = self.history.read();
        let recent_successes = history
            .iter()
            .filter(|r| r.outcome == AttemptOutcome::Success)
            .count();

        AdaptiveRetryStats {
            total_attempts: self.total_attempts.load(Ordering::Relaxed),
            total_successes: self.total_successes.load(Ordering::Relaxed),
            recent_success_rate: if history.is_empty() {
                1.0
            } else {
                recent_successes as f64 / history.len() as f64
            },
            current_delay: *self.current_delay.read(),
            delay_multiplier: *self.delay_multiplier.read(),
            history_size: history.len(),
        }
    }

    /// Reset the adaptive state.
    pub fn reset(&self) {
        self.history.write().clear();
        *self.delay_multiplier.write() = 1.0;
        *self.current_delay.write() = self.config.min_delay;
    }
}

impl Default for AdaptiveRetry {
    fn default() -> Self {
        Self::new(AdaptiveRetryConfig::default())
    }
}

/// Decision on whether to retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryDecision {
    /// Do not retry (permanent failure or non-retryable)
    DoNotRetry,
    /// Max attempts reached
    MaxAttemptsReached,
    /// Retry with the given delay
    Retry {
        /// Delay before retrying
        delay: Duration,
    },
}

impl RetryDecision {
    /// Check if we should retry.
    pub fn should_retry(&self) -> bool {
        matches!(self, Self::Retry { .. })
    }

    /// Get the delay if retrying.
    pub fn delay(&self) -> Option<Duration> {
        match self {
            Self::Retry { delay } => Some(*delay),
            _ => None,
        }
    }
}

/// Statistics about the adaptive retry.
#[derive(Debug, Clone)]
pub struct AdaptiveRetryStats {
    /// Total attempts made
    pub total_attempts: u64,
    /// Total successes
    pub total_successes: u64,
    /// Recent success rate
    pub recent_success_rate: f64,
    /// Current base delay
    pub current_delay: Duration,
    /// Current delay multiplier
    pub delay_multiplier: f64,
    /// History window size
    pub history_size: usize,
}

impl AdaptiveRetryStats {
    /// Get overall success rate.
    pub fn overall_success_rate(&self) -> f64 {
        if self.total_attempts == 0 {
            return 1.0;
        }
        self.total_successes as f64 / self.total_attempts as f64
    }
}

/// Per-host adaptive retry manager.
#[derive(Debug)]
pub struct AdaptiveRetryManager {
    config: AdaptiveRetryConfig,
    strategies: RwLock<std::collections::HashMap<String, Arc<AdaptiveRetry>>>,
}

impl AdaptiveRetryManager {
    /// Create a new manager.
    pub fn new(config: AdaptiveRetryConfig) -> Self {
        Self {
            config,
            strategies: RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Get or create strategy for a host.
    pub fn get(&self, host: &str) -> Arc<AdaptiveRetry> {
        {
            let strategies = self.strategies.read();
            if let Some(strategy) = strategies.get(host) {
                return Arc::clone(strategy);
            }
        }

        let mut strategies = self.strategies.write();
        strategies
            .entry(host.to_string())
            .or_insert_with(|| Arc::new(AdaptiveRetry::new(self.config.clone())))
            .clone()
    }

    /// Record outcome for a host.
    pub fn record_outcome(&self, host: &str, outcome: AttemptOutcome, latency: Duration) {
        self.get(host).record_outcome(outcome, latency);
    }

    /// Get delay for a host.
    pub fn get_delay(
        &self,
        host: &str,
        attempt: u32,
        last_outcome: Option<AttemptOutcome>,
    ) -> Duration {
        self.get(host).get_delay(attempt, last_outcome)
    }

    /// Check if should retry for a host.
    pub fn should_retry(&self, host: &str, attempt: u32, outcome: AttemptOutcome) -> RetryDecision {
        self.get(host).should_retry(attempt, outcome)
    }

    /// Get stats for all hosts.
    pub fn all_stats(&self) -> Vec<(String, AdaptiveRetryStats)> {
        let strategies = self.strategies.read();
        strategies
            .iter()
            .map(|(h, s)| (h.clone(), s.stats()))
            .collect()
    }
}

impl Default for AdaptiveRetryManager {
    fn default() -> Self {
        Self::new(AdaptiveRetryConfig::default())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_adaptive_retry_initial() {
        let retry = AdaptiveRetry::default();
        let delay = retry.get_delay(1, None);

        assert!(delay >= retry.config.min_delay);
        assert!(delay <= retry.config.max_delay);
    }

    #[test]
    fn test_adaptive_retry_backoff() {
        let retry = AdaptiveRetry::default();

        let delay1 = retry.get_delay(1, None);
        let delay2 = retry.get_delay(2, None);
        let delay3 = retry.get_delay(3, None);

        // Should increase with attempts
        assert!(delay2 > delay1);
        assert!(delay3 > delay2);
    }

    #[test]
    fn test_adaptive_retry_outcome_affects_delay() {
        let retry = AdaptiveRetry::default();

        let delay_transient = retry.get_delay(2, Some(AttemptOutcome::TransientFailure));
        let delay_rate_limit = retry.get_delay(2, Some(AttemptOutcome::RateLimited));

        // Rate limited should have longer delay
        assert!(delay_rate_limit > delay_transient);
    }

    #[test]
    fn test_should_retry() {
        let retry = AdaptiveRetry::default();

        // Transient failures should retry
        let decision = retry.should_retry(1, AttemptOutcome::TransientFailure);
        assert!(decision.should_retry());

        // Permanent failures should not
        let decision = retry.should_retry(1, AttemptOutcome::PermanentFailure);
        assert!(!decision.should_retry());

        // Max attempts should stop
        let decision = retry.should_retry(10, AttemptOutcome::TransientFailure);
        assert!(!decision.should_retry());
    }

    #[test]
    fn test_adaptive_learning() {
        let retry = AdaptiveRetry::default();

        // Record many successful attempts
        for _ in 0..50 {
            retry.record_outcome(AttemptOutcome::Success, Duration::from_millis(100));
        }

        let stats = retry.stats();
        assert!(stats.recent_success_rate > 0.9);

        // Record some failures
        for _ in 0..20 {
            retry.record_outcome(AttemptOutcome::TransientFailure, Duration::from_millis(500));
        }

        let stats_after = retry.stats();
        // Multiplier should have increased due to failures
        assert!(stats_after.delay_multiplier >= stats.delay_multiplier);
    }

    #[test]
    fn test_manager() {
        let manager = AdaptiveRetryManager::default();

        manager.record_outcome(
            "host1.onion",
            AttemptOutcome::Success,
            Duration::from_millis(100),
        );
        manager.record_outcome(
            "host2.onion",
            AttemptOutcome::TransientFailure,
            Duration::from_millis(500),
        );

        let stats = manager.all_stats();
        assert_eq!(stats.len(), 2);
    }
}
