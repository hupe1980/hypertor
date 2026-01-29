//! Secure API Client Example - Production-Ready Tor Client
//!
//! This example demonstrates a production-grade Tor HTTP client with:
//! - Automatic retries with exponential backoff
//! - Circuit breaker pattern
//! - Rate limiting
//! - Simple in-memory caching
//! - Comprehensive error handling
//!
//! Run with: cargo run --example secure_api_client

use hypertor::{
    BreakerConfig, CircuitBreaker, RateLimitConfig, RateLimiter, Result, RetryConfig, TorClient,
    retry::with_retry,
};
use std::collections::HashMap;
use std::time::{Duration, Instant};

// =============================================================================
// Types
// =============================================================================

#[derive(Debug)]
struct ApiResponse {
    success: bool,
    data: Option<serde_json::Value>,
    error: Option<String>,
    latency_ms: u128,
    cached: bool,
}

#[derive(Default)]
struct ClientStats {
    requests: usize,
    successes: usize,
    failures: usize,
    cache_hits: usize,
    retries: usize,
}

/// Simple in-memory cache with TTL
struct SimpleCache {
    entries: parking_lot::Mutex<HashMap<String, (serde_json::Value, Instant)>>,
    ttl: Duration,
}

impl SimpleCache {
    fn new(ttl: Duration) -> Self {
        Self {
            entries: parking_lot::Mutex::new(HashMap::new()),
            ttl,
        }
    }

    fn get(&self, key: &str) -> Option<serde_json::Value> {
        let mut entries = self.entries.lock();
        if let Some((value, cached_at)) = entries.get(key) {
            if cached_at.elapsed() < self.ttl {
                return Some(value.clone());
            }
            entries.remove(key);
        }
        None
    }

    fn set(&self, key: String, value: serde_json::Value) {
        let mut entries = self.entries.lock();
        entries.insert(key, (value, Instant::now()));
    }
}

// =============================================================================
// Secure API Client
// =============================================================================

/// Production-grade Tor API client with resilience patterns
struct SecureApiClient {
    client: TorClient,
    base_url: String,
    cache: SimpleCache,
    circuit_breaker: CircuitBreaker,
    rate_limiter: RateLimiter,
    retry_config: RetryConfig,
    stats: parking_lot::Mutex<ClientStats>,
}

impl SecureApiClient {
    /// Create a new secure API client
    async fn new(base_url: &str) -> Result<Self> {
        let client = TorClient::new().await?;

        // Simple cache with 60 second TTL
        let cache = SimpleCache::new(Duration::from_secs(60));

        // Configure circuit breaker
        let circuit_breaker = CircuitBreaker::new(BreakerConfig {
            failure_threshold: 5,
            reset_timeout: Duration::from_secs(30),
            ..Default::default()
        });

        // Configure rate limiter (10 requests per second)
        let rate_limiter = RateLimiter::new(RateLimitConfig {
            default_rate: 10.0,
            default_burst: 10,
            ..Default::default()
        });

        // Configure retry with exponential backoff
        let retry_config = RetryConfig {
            max_retries: 3,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            ..Default::default()
        };

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            cache,
            circuit_breaker,
            rate_limiter,
            retry_config,
            stats: parking_lot::Mutex::new(ClientStats::default()),
        })
    }

    /// Make a GET request with full resilience stack
    async fn get(&self, endpoint: &str, use_cache: bool) -> ApiResponse {
        let url = format!("{}/{}", self.base_url, endpoint.trim_start_matches('/'));
        let cache_key = format!("GET:{}", url);

        // Check cache first
        if use_cache {
            if let Some(cached) = self.cache.get(&cache_key) {
                self.stats.lock().cache_hits += 1;
                return ApiResponse {
                    success: true,
                    data: Some(cached),
                    error: None,
                    latency_ms: 0,
                    cached: true,
                };
            }
        }

        // Check circuit breaker
        if !self.circuit_breaker.allow_request().is_allowed() {
            return ApiResponse {
                success: false,
                data: None,
                error: Some("Circuit breaker is open - service unavailable".to_string()),
                latency_ms: 0,
                cached: false,
            };
        }

        // Rate limiting (use base_url as host key)
        if !self
            .rate_limiter
            .acquire(&self.base_url)
            .await
            .is_acquired()
        {
            return ApiResponse {
                success: false,
                data: None,
                error: Some("Rate limit exceeded".to_string()),
                latency_ms: 0,
                cached: false,
            };
        }

        self.stats.lock().requests += 1;
        let start = Instant::now();

        // Execute with retry
        let result = with_retry(&self.retry_config, || async {
            self.client.get(&url)?.send().await
        })
        .await;

        let latency_ms = start.elapsed().as_millis();

        match result {
            Ok(response) => {
                let status = response.status();

                if status.is_server_error() {
                    self.circuit_breaker.record_failure();
                    self.stats.lock().failures += 1;
                    return ApiResponse {
                        success: false,
                        data: None,
                        error: Some(format!("Server error: {}", status)),
                        latency_ms,
                        cached: false,
                    };
                }

                if status.is_client_error() {
                    return ApiResponse {
                        success: false,
                        data: None,
                        error: Some(format!("Client error: {}", status)),
                        latency_ms,
                        cached: false,
                    };
                }

                // Success
                self.circuit_breaker.record_success();
                self.stats.lock().successes += 1;

                let data: Option<serde_json::Value> = response
                    .text()
                    .ok()
                    .and_then(|t| serde_json::from_str(&t).ok());

                // Cache the response
                if use_cache {
                    if let Some(ref d) = data {
                        self.cache.set(cache_key, d.clone());
                    }
                }

                ApiResponse {
                    success: true,
                    data,
                    error: None,
                    latency_ms,
                    cached: false,
                }
            }
            Err(e) => {
                self.circuit_breaker.record_failure();
                self.stats.lock().failures += 1;
                ApiResponse {
                    success: false,
                    data: None,
                    error: Some(format!("Request failed: {}", e)),
                    latency_ms,
                    cached: false,
                }
            }
        }
    }

    /// Make a POST request with resilience stack
    async fn post(&self, endpoint: &str, body: serde_json::Value) -> ApiResponse {
        let url = format!("{}/{}", self.base_url, endpoint.trim_start_matches('/'));

        // Check circuit breaker
        if !self.circuit_breaker.allow_request().is_allowed() {
            return ApiResponse {
                success: false,
                data: None,
                error: Some("Circuit breaker is open".to_string()),
                latency_ms: 0,
                cached: false,
            };
        }

        // Rate limiting
        if !self
            .rate_limiter
            .acquire(&self.base_url)
            .await
            .is_acquired()
        {
            return ApiResponse {
                success: false,
                data: None,
                error: Some("Rate limit exceeded".to_string()),
                latency_ms: 0,
                cached: false,
            };
        }

        self.stats.lock().requests += 1;
        let start = Instant::now();

        let json_str = serde_json::to_string(&body).unwrap_or_default();

        let result = with_retry(&self.retry_config, || async {
            self.client.post(&url)?.json(&json_str).send().await
        })
        .await;

        let latency_ms = start.elapsed().as_millis();

        match result {
            Ok(response) => {
                let status = response.status();

                if status.is_server_error() {
                    self.circuit_breaker.record_failure();
                    self.stats.lock().failures += 1;
                    return ApiResponse {
                        success: false,
                        data: None,
                        error: Some(format!("Server error: {}", status)),
                        latency_ms,
                        cached: false,
                    };
                }

                self.circuit_breaker.record_success();
                self.stats.lock().successes += 1;

                let data: Option<serde_json::Value> = response
                    .text()
                    .ok()
                    .and_then(|t| serde_json::from_str(&t).ok());

                ApiResponse {
                    success: !status.is_client_error(),
                    data,
                    error: if status.is_client_error() {
                        Some(format!("Client error: {}", status))
                    } else {
                        None
                    },
                    latency_ms,
                    cached: false,
                }
            }
            Err(e) => {
                self.circuit_breaker.record_failure();
                self.stats.lock().failures += 1;
                ApiResponse {
                    success: false,
                    data: None,
                    error: Some(format!("Request failed: {}", e)),
                    latency_ms,
                    cached: false,
                }
            }
        }
    }

    /// Print client statistics
    fn print_stats(&self) {
        let stats = self.stats.lock();
        let total = stats.requests;

        if total == 0 {
            println!("   No requests made");
            return;
        }

        let success_rate = (stats.successes as f64 / total as f64) * 100.0;
        let cache_total = total + stats.cache_hits;
        let cache_rate = if cache_total > 0 {
            (stats.cache_hits as f64 / cache_total as f64) * 100.0
        } else {
            0.0
        };

        println!("   📊 Statistics:");
        println!("      Total Requests: {}", total);
        println!(
            "      Successes: {} ({:.1}%)",
            stats.successes, success_rate
        );
        println!("      Failures: {}", stats.failures);
        println!(
            "      Cache Hits: {} ({:.1}%)",
            stats.cache_hits, cache_rate
        );
        println!("      Retries: {}", stats.retries);
    }
}

// =============================================================================
// Main
// =============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("🧅 hypertor - Secure API Client Example");
    println!("========================================");
    println!();
    println!("Note: Tor network requests can be slow. Please be patient.");
    println!();

    // Create secure client
    println!("Creating secure Tor client...");
    let client = SecureApiClient::new("https://httpbin.org").await?;
    println!("✅ Client ready!");
    println!();

    // Test 1: Basic GET
    println!("📡 Test 1: Basic GET request");
    let resp = client.get("/ip", true).await;
    if resp.success {
        println!("   ✅ Your Tor IP: {:?}", resp.data);
        println!("   ⏱️  Latency: {}ms", resp.latency_ms);
    } else {
        println!("   ❌ Error: {:?}", resp.error);
    }

    // Test 2: Cached request
    println!();
    println!("📡 Test 2: Cached request (same endpoint)");
    let resp = client.get("/ip", true).await;
    if resp.cached {
        println!("   ✅ Cache hit! Instant response");
        println!("   📦 Cached data: {:?}", resp.data);
    } else {
        println!("   ⏱️  Latency: {}ms", resp.latency_ms);
    }

    // Test 3: POST with JSON
    println!();
    println!("📡 Test 3: POST JSON data");
    let resp = client
        .post(
            "/post",
            serde_json::json!({
                "secret_message": "Hello from Tor!",
                "anonymous": true
            }),
        )
        .await;
    if resp.success {
        println!("   ✅ Response received");
        println!("   ⏱️  Latency: {}ms", resp.latency_ms);
    } else {
        println!("   ❌ Error: {:?}", resp.error);
    }

    // Print statistics
    println!();
    println!("----------------------------------------");
    client.print_stats();

    println!();
    println!("✅ Secure API Client demo completed!");

    Ok(())
}
