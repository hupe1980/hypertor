//! Retry middleware for automatic request retries
//!
//! Provides configurable retry logic with exponential backoff
//! for transient failures.

use std::time::Duration;
use tokio::time::sleep;
use tracing::warn;

use crate::error::{Error, Result};

/// Retry configuration
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Initial delay between retries
    pub initial_delay: Duration,
    /// Maximum delay between retries
    pub max_delay: Duration,
    /// Exponential backoff multiplier
    pub backoff_multiplier: f64,
    /// Whether to add jitter to delays
    pub jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            backoff_multiplier: 2.0,
            jitter: true,
        }
    }
}

impl RetryConfig {
    /// Create a new retry config with no retries
    pub fn none() -> Self {
        Self {
            max_retries: 0,
            ..Default::default()
        }
    }

    /// Create an aggressive retry config for unreliable networks
    pub fn aggressive() -> Self {
        Self {
            max_retries: 5,
            initial_delay: Duration::from_millis(200),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            jitter: true,
        }
    }

    /// Calculate delay for a given attempt number
    fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let base_delay =
            self.initial_delay.as_millis() as f64 * self.backoff_multiplier.powi(attempt as i32);

        let delay_ms = base_delay.min(self.max_delay.as_millis() as f64);

        let delay_ms = if self.jitter {
            // Add up to 25% jitter
            let jitter = delay_ms * 0.25 * rand_simple();
            delay_ms + jitter
        } else {
            delay_ms
        };

        Duration::from_millis(delay_ms as u64)
    }
}

/// Simple pseudo-random number for jitter (no external dependency)
fn rand_simple() -> f64 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos % 1000) as f64 / 1000.0
}

/// Execute a future with retry logic
pub async fn with_retry<F, Fut, T>(config: &RetryConfig, mut f: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut last_error = None;

    for attempt in 0..=config.max_retries {
        match f().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                if !e.is_retryable() {
                    return Err(e);
                }

                if attempt < config.max_retries {
                    let delay = config.delay_for_attempt(attempt);
                    warn!(
                        attempt = attempt + 1,
                        max_retries = config.max_retries,
                        delay_ms = delay.as_millis(),
                        error = %e,
                        "Request failed, retrying"
                    );
                    sleep(delay).await;
                }

                last_error = Some(e);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| Error::http("unknown retry error")))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
    }

    #[test]
    fn test_delay_calculation() {
        let config = RetryConfig {
            initial_delay: Duration::from_millis(100),
            backoff_multiplier: 2.0,
            jitter: false,
            ..Default::default()
        };

        assert_eq!(config.delay_for_attempt(0), Duration::from_millis(100));
        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(200));
        assert_eq!(config.delay_for_attempt(2), Duration::from_millis(400));
    }

    #[tokio::test]
    async fn test_with_retry_success() {
        let config = RetryConfig::default();
        let result = with_retry(&config, || async { Ok::<_, Error>(42) }).await;
        assert_eq!(result.unwrap(), 42);
    }
}
