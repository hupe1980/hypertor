//! Criterion benchmark suite for hypertor
//!
//! Run benchmarks: cargo bench
//! Generate HTML report: cargo bench --bench benchmarks -- --verbose
//!
//! Results are saved to: target/criterion/

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use std::time::Duration;

// Import hypertor modules for benchmarking
#[allow(unused_imports)]
use hypertor::{
    AdaptiveRetry,
    AdaptiveRetryConfig,
    BackpressureConfig,
    BackpressureController,
    // Core types
    Body,
    BreakerConfig,
    CacheConfig,
    CacheControl,
    CircuitBreaker,
    ClientSecurityConfig,
    CloseCode,
    ConfigBuilder,
    DedupConfig,
    Deduplicator,
    // DNS
    DnsCache,
    // Protocols
    Frame as WsFrame,
    FrameFlags,
    FrameHeader,
    FrameType,
    Hpack,
    Http2Config,
    Http2Connection,
    // Performance
    HttpCache,
    IsolationLevel,
    IsolationToken,
    // Metrics
    MetricsRegistry,
    Priority,
    PriorityQueue,
    QueueConfig,
    RateLimitConfig,
    // Resilience
    RetryConfig,
    // Security (config presets only - actual security is in arti)
    SecurityLevel,
    ServiceSecurityConfig,
    TokenBucket,
    TorMetrics,
};

// ============================================================================
// CORE CONFIGURATION BENCHMARKS
// ============================================================================

fn bench_config_builder(c: &mut Criterion) {
    let mut group = c.benchmark_group("config");

    group.bench_function("builder_simple", |b| {
        b.iter(|| {
            black_box(
                ConfigBuilder::new()
                    .timeout(Duration::from_secs(30))
                    .build(),
            )
        })
    });

    group.bench_function("builder_full", |b| {
        b.iter(|| {
            black_box(
                ConfigBuilder::new()
                    .timeout(Duration::from_secs(30))
                    .max_connections(100)
                    .isolation(IsolationLevel::ByHost)
                    .build(),
            )
        })
    });

    group.bench_function("isolation_token_new", |b| {
        b.iter(|| black_box(IsolationToken::new()))
    });

    group.finish();
}

// ============================================================================
// SECURITY CONFIG BENCHMARKS
// ============================================================================

fn bench_security_presets(c: &mut Criterion) {
    let mut group = c.benchmark_group("security_presets");

    // Security level presets
    group.bench_function("level_standard", |b| {
        b.iter(|| black_box(SecurityLevel::Standard.vanguard_mode()))
    });

    group.bench_function("level_maximum", |b| {
        b.iter(|| black_box(SecurityLevel::Maximum.vanguard_mode()))
    });

    // Service security config
    group.bench_function("service_standard", |b| {
        b.iter(|| black_box(ServiceSecurityConfig::standard()))
    });

    group.bench_function("service_maximum", |b| {
        b.iter(|| black_box(ServiceSecurityConfig::maximum()))
    });

    // Client security config
    group.bench_function("client_enhanced", |b| {
        b.iter(|| black_box(ClientSecurityConfig::enhanced()))
    });

    group.bench_function("to_onion_config", |b| {
        let config = ServiceSecurityConfig::maximum();
        b.iter(|| black_box(config.to_onion_config("bench-service")))
    });

    group.finish();
}

// ============================================================================
// RESILIENCE BENCHMARKS
// ============================================================================

fn bench_resilience(c: &mut Criterion) {
    let mut group = c.benchmark_group("resilience");

    // Circuit Breaker
    group.bench_function("breaker_state", |b| {
        let breaker = CircuitBreaker::new(BreakerConfig::default());
        b.iter(|| black_box(breaker.state()))
    });

    group.bench_function("breaker_allow_request", |b| {
        let breaker = CircuitBreaker::new(BreakerConfig::default());
        b.iter(|| black_box(breaker.allow_request()))
    });

    group.bench_function("breaker_record_success", |b| {
        let breaker = CircuitBreaker::new(BreakerConfig::default());
        b.iter(|| {
            breaker.record_success();
            black_box(())
        })
    });

    // Backpressure Controller
    group.bench_function("backpressure_try_acquire", |b| {
        let controller = BackpressureController::new(BackpressureConfig::default());
        b.iter(|| {
            let result = controller.try_acquire();
            // Release if acquired
            drop(result);
            black_box(())
        })
    });

    // Adaptive Retry
    group.bench_function("adaptive_retry_should_retry", |b| {
        let adaptive = AdaptiveRetry::new(AdaptiveRetryConfig::default());
        b.iter(|| black_box(adaptive.should_retry(1, hypertor::AttemptOutcome::TransientFailure)))
    });

    group.bench_function("adaptive_retry_get_delay", |b| {
        let adaptive = AdaptiveRetry::new(AdaptiveRetryConfig::default());
        b.iter(|| black_box(adaptive.get_delay(1, None)))
    });

    // RetryConfig
    group.bench_function("retry_config_default", |b| {
        b.iter(|| black_box(RetryConfig::default()))
    });

    group.finish();
}

// ============================================================================
// PERFORMANCE/CACHE BENCHMARKS
// ============================================================================

fn bench_cache(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache");

    // HTTP Cache
    group.bench_function("cache_create", |b| {
        b.iter(|| black_box(HttpCache::new(CacheConfig::default())))
    });

    // Cache control creation
    group.bench_function("cache_control_default", |b| {
        b.iter(|| black_box(CacheControl::default()))
    });

    group.bench_function("cache_control_cacheable", |b| {
        b.iter(|| black_box(CacheControl::default().is_cacheable()))
    });

    // DNS Cache
    group.bench_function("dns_cache_create", |b| {
        b.iter(|| black_box(DnsCache::new()))
    });

    group.finish();
}

// ============================================================================
// PRIORITY QUEUE BENCHMARKS
// ============================================================================

fn bench_queue(c: &mut Criterion) {
    let mut group = c.benchmark_group("queue");

    // Queue operations
    group.bench_function("queue_push", |b| {
        let queue: PriorityQueue<String> = PriorityQueue::new(QueueConfig::default());
        b.iter(|| {
            let _ = black_box(queue.push("test".to_string()));
        })
    });

    group.bench_function("queue_push_with_priority", |b| {
        let queue: PriorityQueue<String> = PriorityQueue::new(QueueConfig::default());
        b.iter(|| {
            let _ = black_box(queue.push_with_priority("test".to_string(), Priority::High));
        })
    });

    group.bench_function("queue_pop_many", |b| {
        let queue: PriorityQueue<i32> = PriorityQueue::new(QueueConfig::default());
        // Pre-fill
        for i in 0..100 {
            let _ = queue.push(i);
        }
        b.iter(|| {
            if queue.is_empty() {
                for i in 0..100 {
                    let _ = queue.push(i);
                }
            }
            black_box(queue.pop())
        })
    });

    // Token Bucket
    group.bench_function("token_bucket_acquire", |b| {
        let mut bucket = TokenBucket::new(1000, 100.0); // 1000 capacity, 100/sec refill
        b.iter(|| black_box(bucket.try_acquire()))
    });

    group.finish();
}

// ============================================================================
// DEDUPLICATION BENCHMARKS
// ============================================================================

fn bench_dedup(c: &mut Criterion) {
    let mut group = c.benchmark_group("dedup");

    group.bench_function("dedup_create", |b| {
        b.iter(|| black_box(Deduplicator::new(DedupConfig::default())))
    });

    group.finish();
}

// ============================================================================
// WEBSOCKET BENCHMARKS
// ============================================================================

fn bench_websocket(c: &mut Criterion) {
    let mut group = c.benchmark_group("websocket");

    // Frame creation
    group.bench_function("frame_text", |b| {
        b.iter(|| black_box(WsFrame::text("Hello, World!")))
    });

    group.bench_function("frame_binary_small", |b| {
        let data = vec![0u8; 64];
        b.iter(|| black_box(WsFrame::binary(data.clone())))
    });

    group.bench_function("frame_binary_large", |b| {
        let data = vec![0u8; 65536];
        b.iter(|| black_box(WsFrame::binary(data.clone())))
    });

    // Frame encoding
    group.bench_function("frame_encode_text", |b| {
        let frame = WsFrame::text("Hello, Tor WebSocket!");
        b.iter(|| black_box(frame.encode()))
    });

    group.throughput(Throughput::Bytes(65536));
    group.bench_function("frame_encode_binary_64k", |b| {
        let frame = WsFrame::binary(vec![0u8; 65536]);
        b.iter(|| black_box(frame.encode()))
    });

    // Close frame
    group.bench_function("frame_close", |b| {
        b.iter(|| black_box(WsFrame::close(CloseCode::Normal, "goodbye")))
    });

    // Key generation
    group.bench_function("generate_client_key", |b| {
        b.iter(|| black_box(hypertor::websocket::generate_client_key()))
    });

    group.bench_function("generate_accept_key", |b| {
        let client_key = hypertor::websocket::generate_client_key();
        b.iter(|| black_box(hypertor::websocket::generate_accept_key(&client_key)))
    });

    group.finish();
}

// ============================================================================
// HTTP/2 BENCHMARKS
// ============================================================================

fn bench_http2(c: &mut Criterion) {
    let mut group = c.benchmark_group("http2");

    // Config creation
    group.bench_function("config_default", |b| {
        b.iter(|| black_box(Http2Config::default()))
    });

    group.bench_function("config_tor_optimized", |b| {
        b.iter(|| black_box(Http2Config::tor_optimized()))
    });

    // Connection creation
    group.bench_function("connection_client", |b| {
        b.iter(|| black_box(Http2Connection::client(Http2Config::default())))
    });

    // HPACK header compression
    group.bench_function("hpack_encode_simple", |b| {
        let mut hpack = Hpack::new(4096);
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/".to_string()),
            (":authority".to_string(), "example.onion".to_string()),
        ];
        b.iter(|| black_box(hpack.encode(&headers)))
    });

    group.bench_function("hpack_encode_many", |b| {
        let mut hpack = Hpack::new(4096);
        let headers = vec![
            (":method".to_string(), "POST".to_string()),
            (":path".to_string(), "/api/v1/users".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.onion".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
            ("accept".to_string(), "application/json".to_string()),
            ("user-agent".to_string(), "hypertor/0.3.0".to_string()),
            ("x-request-id".to_string(), "abc123".to_string()),
        ];
        b.iter(|| black_box(hpack.encode(&headers)))
    });

    // Frame header parsing
    group.bench_function("frame_header_create", |b| {
        b.iter(|| {
            black_box(FrameHeader::new(
                FrameType::Headers,
                FrameFlags::END_HEADERS,
                1,
            ))
        })
    });

    group.finish();
}

// ============================================================================
// PROMETHEUS METRICS BENCHMARKS
// ============================================================================

fn bench_prometheus(c: &mut Criterion) {
    let mut group = c.benchmark_group("prometheus");

    // Registry creation
    group.bench_function("registry_create", |b| {
        b.iter(|| black_box(MetricsRegistry::new("bench")))
    });

    // Counter operations
    group.bench_function("counter_inc", |b| {
        let registry = MetricsRegistry::new("bench");
        let counter = registry.counter("requests", "Total requests");
        b.iter(|| {
            counter.inc();
            black_box(())
        })
    });

    group.bench_function("counter_inc_with_labels", |b| {
        let registry = MetricsRegistry::new("bench");
        let counter = registry.counter("requests", "Total requests");
        b.iter(|| {
            counter.inc_with_labels(&[("method", "GET"), ("status", "200")]);
            black_box(())
        })
    });

    // Gauge operations
    group.bench_function("gauge_set", |b| {
        let registry = MetricsRegistry::new("bench");
        let gauge = registry.gauge("connections", "Active connections");
        let mut val = 0i64;
        b.iter(|| {
            val = (val + 1) % 1000;
            gauge.set(val);
            black_box(())
        })
    });

    // Histogram operations
    group.bench_function("histogram_observe", |b| {
        let registry = MetricsRegistry::new("bench");
        let histogram = registry.tor_histogram("latency", "Request latency");
        let mut val = 0.0f64;
        b.iter(|| {
            val = (val + 0.001) % 10.0;
            histogram.observe(val);
            black_box(())
        })
    });

    // TorMetrics (pre-defined)
    group.bench_function("tor_metrics_record_request", |b| {
        let metrics = TorMetrics::new();
        let mut status = 200u16;
        b.iter(|| {
            status = if status == 200 { 404 } else { 200 };
            metrics.record_request("GET", status, 0.5, 100, 1000);
            black_box(())
        })
    });

    // Export
    group.bench_function("export", |b| {
        let metrics = TorMetrics::new();
        // Record some data
        for _ in 0..100 {
            metrics.record_request("GET", 200, 0.5, 100, 1000);
        }
        b.iter(|| black_box(metrics.export()))
    });

    group.finish();
}

// ============================================================================
// SECURITY CONFIG BENCHMARKS
// ============================================================================

// Note: Old fake security benchmarks removed.
// Real security (PoW, rate limiting, etc.) is handled by arti.
// We only benchmark our config preset creation which is fast.

// ============================================================================
// BODY BENCHMARKS
// ============================================================================

fn bench_body(c: &mut Criterion) {
    let mut group = c.benchmark_group("body");

    group.bench_function("body_empty", |b| b.iter(|| black_box(Body::empty())));

    group.bench_function("body_text_small", |b| {
        b.iter(|| black_box(Body::text("Hello, World!")))
    });

    group.bench_function("body_text_large", |b| {
        let data = "x".repeat(10000);
        b.iter(|| black_box(Body::text(data.clone())))
    });

    group.bench_function("body_json_small", |b| {
        b.iter(|| black_box(Body::json(r#"{"key":"value"}"#)))
    });

    group.bench_function("body_raw_small", |b| {
        let data = vec![0u8; 64];
        b.iter(|| black_box(Body::raw(data.clone(), "application/octet-stream")))
    });

    group.throughput(Throughput::Bytes(65536));
    group.bench_function("body_raw_64k", |b| {
        let data = vec![0u8; 65536];
        b.iter(|| black_box(Body::raw(data.clone(), "application/octet-stream")))
    });

    group.finish();
}

// ============================================================================
// CRITERION GROUPS
// ============================================================================

criterion_group!(
    name = core_benches;
    config = Criterion::default()
        .significance_level(0.05)
        .sample_size(100)
        .measurement_time(Duration::from_secs(5));
    targets =
        bench_config_builder,
        bench_body,
);

criterion_group!(
    name = security_benches;
    config = Criterion::default()
        .significance_level(0.05)
        .sample_size(100)
        .measurement_time(Duration::from_secs(5));
    targets =
        bench_security_presets,
);

criterion_group!(
    name = network_benches;
    config = Criterion::default()
        .significance_level(0.05)
        .sample_size(100)
        .measurement_time(Duration::from_secs(5));
    targets =
        bench_websocket,
        bench_http2,
);

criterion_group!(
    name = performance_benches;
    config = Criterion::default()
        .significance_level(0.05)
        .sample_size(100)
        .measurement_time(Duration::from_secs(5));
    targets =
        bench_cache,
        bench_queue,
        bench_dedup,
        bench_resilience,
);

criterion_group!(
    name = observability_benches;
    config = Criterion::default()
        .significance_level(0.05)
        .sample_size(100)
        .measurement_time(Duration::from_secs(5));
    targets =
        bench_prometheus,
);

criterion_main!(
    core_benches,
    security_benches,
    network_benches,
    performance_benches,
    observability_benches,
);
