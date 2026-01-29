//! Integration tests for hypertor
//!
//! Minimal API verification tests that ensure core types exist and compile.

use hypertor::*;
use std::time::Duration;

// ============================================================================
// Configuration Tests
// ============================================================================

#[test]
fn test_config_builder() {
    let config = Config::builder()
        .timeout(Duration::from_secs(30))
        .max_connections(10)
        .user_agent("hypertor-test/1.0")
        .build();
    assert!(config.is_ok());
}

#[test]
fn test_isolation_levels() {
    let levels = vec![
        IsolationLevel::None,
        IsolationLevel::ByHost,
        IsolationLevel::PerRequest,
    ];
    assert_eq!(levels.len(), 3);
}

#[test]
fn test_retry_config() {
    let config = RetryConfig::default();
    assert!(config.max_retries > 0);
}

// ============================================================================
// OnionApp Tests
// ============================================================================

#[test]
fn test_onion_app_creation() {
    let app = OnionApp::new();
    let stats = app.stats();
    assert_eq!(stats.total_requests, 0);
}

// ============================================================================
// Security Tests (REAL arti integration)
// ============================================================================

#[test]
fn test_security_levels() {
    let _standard = SecurityLevel::Standard;
    let _enhanced = SecurityLevel::Enhanced;
    let _maximum = SecurityLevel::Maximum;
}

#[test]
fn test_client_security_config() {
    let config = ClientSecurityConfig::maximum();
    assert!(config.strict_isolation);
}

#[test]
fn test_service_security_config() {
    let config = ServiceSecurityConfig::maximum();
    assert!(config.enable_pow);
}

#[test]
fn test_security_to_onion_config() {
    let hs_config = HsConfig::new("test-service")
        .with_pow()
        .rate_limit_at_intro(10.0, 20)
        .max_streams_per_circuit(100);
    assert!(hs_config.enable_pow);
}

// ============================================================================
// Vanguard Tests (REAL arti integration)
// ============================================================================

#[test]
fn test_vanguard_modes() {
    let _disabled = VanguardMode::Disabled;
    let _lite = VanguardMode::Lite;
    let _full = VanguardMode::Full;
}

// ============================================================================
// WebSocket Tests
// ============================================================================

#[test]
fn test_websocket_frame() {
    let frame = Frame::text("hello");
    let encoded = frame.encode();
    assert!(!encoded.is_empty());
}

#[test]
fn test_websocket_config() {
    let config = WebSocketConfig::tor_optimized();
    assert!(config.max_frame_size > 0);
}

// ============================================================================
// HTTP/2 Tests
// ============================================================================

#[test]
fn test_http2_config() {
    let config = Http2Config::default();
    assert!(config.settings.max_concurrent_streams > 0);
}

#[test]
fn test_http2_settings() {
    let settings = Http2Settings::default();
    let encoded = settings.encode();
    assert!(!encoded.is_empty());
}

// ============================================================================
// Prometheus Tests
// ============================================================================

#[test]
fn test_metrics_registry() {
    let registry = MetricsRegistry::new("test");
    let counter = registry.counter("requests", "Total requests");
    counter.inc();
    let export = registry.export();
    assert!(export.contains("test_requests"));
}

#[test]
fn test_tor_metrics() {
    let metrics = TorMetrics::new();
    metrics.record_request("GET", 200, 1.5, 100, 5000);
    let export = metrics.export();
    assert!(export.contains("hypertor"));
}

// ============================================================================
// DNS-over-HTTPS Tests
// ============================================================================

#[test]
fn test_doh_providers() {
    let providers = vec![
        DohProvider::Cloudflare,
        DohProvider::Google,
        DohProvider::Quad9,
    ];
    assert_eq!(providers.len(), 3);
}

#[test]
fn test_record_types() {
    let types = vec![RecordType::A, RecordType::AAAA];
    assert_eq!(types.len(), 2);
}

// ============================================================================
// Onion Service Tests (REAL arti integration)
// ============================================================================

#[test]
fn test_hs_config() {
    let config = HsConfig::new("test-service");
    assert_eq!(config.nickname, "test-service");
}

#[test]
fn test_hs_config_with_hardening() {
    let config = HsConfig::new("secure-service")
        .with_pow()
        .pow_queue_depth(16000)
        .rate_limit_at_intro(10.0, 20)
        .max_streams_per_circuit(100)
        .num_intro_points(5);

    assert!(config.enable_pow);
    assert_eq!(config.pow_queue_depth, Some(16000));
    assert_eq!(config.max_streams_per_circuit, 100);
    assert_eq!(config.num_intro_points, 5);
}

#[test]
fn test_hs_high_security_preset() {
    let config = HsConfig::high_security();
    assert!(config.enable_pow);
    assert!(config.rate_limit_at_intro.is_some());
}

#[test]
fn test_client_auth_modes() {
    let modes = vec![
        ClientAuthMode::None,
        ClientAuthMode::Basic,
        ClientAuthMode::Stealth,
    ];
    assert_eq!(modes.len(), 3);
}

// ============================================================================
// Resilience Tests
// ============================================================================

#[test]
fn test_circuit_breaker() {
    let breaker = CircuitBreaker::new(BreakerConfig::default());
    assert_eq!(breaker.state(), BreakerState::Closed);
}

#[test]
fn test_adaptive_retry() {
    let config = AdaptiveRetryConfig::default();
    let retry = AdaptiveRetry::new(config);
    let stats = retry.stats();
    assert_eq!(stats.total_attempts, 0);
}

#[test]
fn test_backpressure() {
    let config = BackpressureConfig::default();
    let controller = BackpressureController::new(config);
    let stats = controller.stats();
    assert_eq!(stats.in_flight, 0);
}

// ============================================================================
// Performance Tests
// ============================================================================

#[test]
fn test_http_cache() {
    let config = CacheConfig::default();
    let cache = HttpCache::new(config);
    let stats = cache.stats();
    assert_eq!(stats.entries, 0);
}

#[test]
fn test_priority_queue() {
    let config = QueueConfig::default();
    let queue: PriorityQueue<String> = PriorityQueue::new(config);
    let stats = queue.stats();
    assert_eq!(stats.current_size, 0);
}
