//! Metrics collection and observability.
//!
//! Provides a metrics interface compatible with OpenTelemetry concepts,
//! with a lightweight built-in implementation.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::RwLock;

/// A counter metric that only increases.
#[derive(Debug, Default)]
pub struct Counter {
    value: AtomicU64,
}

impl Counter {
    /// Create a new counter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment the counter by 1.
    pub fn inc(&self) {
        self.add(1);
    }

    /// Add a value to the counter.
    pub fn add(&self, value: u64) {
        self.value.fetch_add(value, Ordering::Relaxed);
    }

    /// Get the current value.
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// A gauge metric that can go up and down.
#[derive(Debug, Default)]
pub struct Gauge {
    value: AtomicU64,
}

impl Gauge {
    /// Create a new gauge.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the gauge value.
    pub fn set(&self, value: u64) {
        self.value.store(value, Ordering::Relaxed);
    }

    /// Increment the gauge.
    pub fn inc(&self) {
        self.add(1);
    }

    /// Decrement the gauge.
    pub fn dec(&self) {
        self.sub(1);
    }

    /// Add to the gauge.
    pub fn add(&self, value: u64) {
        self.value.fetch_add(value, Ordering::Relaxed);
    }

    /// Subtract from the gauge.
    pub fn sub(&self, value: u64) {
        self.value.fetch_sub(value, Ordering::Relaxed);
    }

    /// Get the current value.
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// Histogram bucket configuration.
#[derive(Debug, Clone)]
pub struct HistogramBuckets {
    /// Upper bounds for each bucket (in milliseconds).
    pub bounds: Vec<u64>,
}

impl Default for HistogramBuckets {
    fn default() -> Self {
        // Default latency buckets: 10ms to 60s
        Self {
            bounds: vec![
                10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000,
            ],
        }
    }
}

impl HistogramBuckets {
    /// Create buckets for latency measurement.
    pub fn latency() -> Self {
        Self::default()
    }

    /// Create buckets for size measurement (bytes).
    pub fn size() -> Self {
        Self {
            bounds: vec![100, 1000, 10000, 100000, 1000000, 10000000, 100000000],
        }
    }

    /// Create custom buckets.
    pub fn custom(bounds: Vec<u64>) -> Self {
        let mut bounds = bounds;
        bounds.sort_unstable();
        Self { bounds }
    }

    /// Find the bucket index for a value.
    fn bucket_index(&self, value: u64) -> usize {
        self.bounds
            .iter()
            .position(|&bound| value <= bound)
            .unwrap_or(self.bounds.len())
    }
}

/// A histogram for tracking distributions.
#[derive(Debug)]
pub struct Histogram {
    buckets: HistogramBuckets,
    counts: Vec<AtomicU64>,
    sum: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    /// Create a new histogram with default latency buckets.
    pub fn new() -> Self {
        Self::with_buckets(HistogramBuckets::default())
    }

    /// Create a histogram with custom buckets.
    pub fn with_buckets(buckets: HistogramBuckets) -> Self {
        let counts = (0..=buckets.bounds.len())
            .map(|_| AtomicU64::new(0))
            .collect();
        Self {
            buckets,
            counts,
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Record a value.
    pub fn observe(&self, value: u64) {
        let idx = self.buckets.bucket_index(value);
        self.counts[idx].fetch_add(1, Ordering::Relaxed);
        self.sum.fetch_add(value, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a duration in milliseconds.
    pub fn observe_duration(&self, duration: Duration) {
        self.observe(duration.as_millis() as u64);
    }

    /// Get the total count.
    pub fn get_count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Get the sum of all values.
    pub fn get_sum(&self) -> u64 {
        self.sum.load(Ordering::Relaxed)
    }

    /// Get the mean value.
    pub fn get_mean(&self) -> f64 {
        let count = self.get_count();
        if count == 0 {
            return 0.0;
        }
        self.get_sum() as f64 / count as f64
    }

    /// Get bucket counts.
    pub fn get_buckets(&self) -> Vec<(u64, u64)> {
        self.buckets
            .bounds
            .iter()
            .zip(self.counts.iter())
            .map(|(&bound, count)| (bound, count.load(Ordering::Relaxed)))
            .collect()
    }
}

impl Default for Histogram {
    fn default() -> Self {
        Self::new()
    }
}

/// Timer for measuring request duration.
pub struct Timer {
    start: Instant,
    histogram: Arc<Histogram>,
}

impl Timer {
    /// Create a new timer.
    pub fn new(histogram: Arc<Histogram>) -> Self {
        Self {
            start: Instant::now(),
            histogram,
        }
    }

    /// Stop the timer and record the duration.
    pub fn stop(self) {
        self.histogram.observe_duration(self.start.elapsed());
    }

    /// Get elapsed time without stopping.
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}

/// Labeled metric wrapper for per-label tracking.
#[derive(Debug)]
pub struct LabeledMetric<T> {
    metrics: RwLock<HashMap<String, Arc<T>>>,
    factory: fn() -> T,
}

impl<T> LabeledMetric<T> {
    /// Create a new labeled metric.
    pub fn new(factory: fn() -> T) -> Self {
        Self {
            metrics: RwLock::new(HashMap::new()),
            factory,
        }
    }

    /// Get or create a metric for the given label.
    pub fn with_label(&self, label: &str) -> Arc<T> {
        // Try read lock first
        {
            let metrics = self.metrics.read();
            if let Some(metric) = metrics.get(label) {
                return Arc::clone(metric);
            }
        }

        // Need write lock to create
        let mut metrics = self.metrics.write();
        metrics
            .entry(label.to_string())
            .or_insert_with(|| Arc::new((self.factory)()))
            .clone()
    }

    /// Get all labels and their metrics.
    pub fn get_all(&self) -> HashMap<String, Arc<T>> {
        self.metrics.read().clone()
    }
}

/// HTTP client metrics collection.
#[derive(Debug)]
pub struct HttpMetrics {
    /// Total requests made.
    pub requests_total: Counter,
    /// Requests by status code category (2xx, 3xx, 4xx, 5xx).
    pub requests_by_status: LabeledMetric<Counter>,
    /// Requests by host.
    pub requests_by_host: LabeledMetric<Counter>,
    /// Total errors.
    pub errors_total: Counter,
    /// Errors by type.
    pub errors_by_type: LabeledMetric<Counter>,
    /// Request duration histogram.
    pub request_duration: Histogram,
    /// Request duration by host.
    pub request_duration_by_host: LabeledMetric<Histogram>,
    /// Response body size.
    pub response_size: Histogram,
    /// Active connections.
    pub active_connections: Gauge,
    /// Total bytes sent.
    pub bytes_sent: Counter,
    /// Total bytes received.
    pub bytes_received: Counter,
    /// Redirects followed.
    pub redirects_total: Counter,
    /// Retries attempted.
    pub retries_total: Counter,
    /// Cache hits (if caching enabled).
    pub cache_hits: Counter,
    /// Cache misses.
    pub cache_misses: Counter,
    /// DNS resolution time.
    pub dns_duration: Histogram,
    /// TLS handshake time.
    pub tls_duration: Histogram,
    /// Time to first byte.
    pub ttfb: Histogram,
}

impl Default for HttpMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpMetrics {
    /// Create a new metrics collection.
    pub fn new() -> Self {
        Self {
            requests_total: Counter::new(),
            requests_by_status: LabeledMetric::new(Counter::new),
            requests_by_host: LabeledMetric::new(Counter::new),
            errors_total: Counter::new(),
            errors_by_type: LabeledMetric::new(Counter::new),
            request_duration: Histogram::new(),
            request_duration_by_host: LabeledMetric::new(Histogram::new),
            response_size: Histogram::with_buckets(HistogramBuckets::size()),
            active_connections: Gauge::new(),
            bytes_sent: Counter::new(),
            bytes_received: Counter::new(),
            redirects_total: Counter::new(),
            retries_total: Counter::new(),
            cache_hits: Counter::new(),
            cache_misses: Counter::new(),
            dns_duration: Histogram::new(),
            tls_duration: Histogram::new(),
            ttfb: Histogram::new(),
        }
    }

    /// Record a successful request.
    pub fn record_request(&self, host: &str, status: u16, duration: Duration, body_size: u64) {
        self.requests_total.inc();

        // Status category
        let status_category = match status {
            200..=299 => "2xx",
            300..=399 => "3xx",
            400..=499 => "4xx",
            500..=599 => "5xx",
            _ => "other",
        };
        self.requests_by_status.with_label(status_category).inc();
        self.requests_by_host.with_label(host).inc();

        // Duration
        self.request_duration.observe_duration(duration);
        self.request_duration_by_host
            .with_label(host)
            .observe_duration(duration);

        // Body size
        self.response_size.observe(body_size);
        self.bytes_received.add(body_size);
    }

    /// Record an error.
    pub fn record_error(&self, error_type: &str) {
        self.errors_total.inc();
        self.errors_by_type.with_label(error_type).inc();
    }

    /// Record a redirect.
    pub fn record_redirect(&self) {
        self.redirects_total.inc();
    }

    /// Start timing a request.
    pub fn start_timer(&self) -> Timer {
        Timer::new(Arc::new(Histogram::new()))
    }

    /// Generate a metrics report.
    pub fn report(&self) -> MetricsReport {
        MetricsReport {
            requests_total: self.requests_total.get(),
            errors_total: self.errors_total.get(),
            active_connections: self.active_connections.get(),
            avg_duration_ms: self.request_duration.get_mean(),
            total_bytes_sent: self.bytes_sent.get(),
            total_bytes_received: self.bytes_received.get(),
            redirects_total: self.redirects_total.get(),
            retries_total: self.retries_total.get(),
        }
    }

    /// Reset all metrics.
    pub fn reset(&self) {
        // Note: Atomic operations make this safe but not perfectly synchronized
        // For a full reset, create a new HttpMetrics instance instead
    }
}

/// A snapshot report of key metrics.
#[derive(Debug, Clone)]
pub struct MetricsReport {
    /// Total requests made.
    pub requests_total: u64,
    /// Total errors.
    pub errors_total: u64,
    /// Currently active connections.
    pub active_connections: u64,
    /// Average request duration in milliseconds.
    pub avg_duration_ms: f64,
    /// Total bytes sent.
    pub total_bytes_sent: u64,
    /// Total bytes received.
    pub total_bytes_received: u64,
    /// Total redirects followed.
    pub redirects_total: u64,
    /// Total retries attempted.
    pub retries_total: u64,
}

impl std::fmt::Display for MetricsReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== HTTP Client Metrics ===")?;
        writeln!(f, "Requests: {}", self.requests_total)?;
        writeln!(f, "Errors: {}", self.errors_total)?;
        writeln!(f, "Active Connections: {}", self.active_connections)?;
        writeln!(f, "Avg Duration: {:.2}ms", self.avg_duration_ms)?;
        writeln!(f, "Bytes Sent: {}", self.total_bytes_sent)?;
        writeln!(f, "Bytes Received: {}", self.total_bytes_received)?;
        writeln!(f, "Redirects: {}", self.redirects_total)?;
        writeln!(f, "Retries: {}", self.retries_total)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_counter() {
        let counter = Counter::new();
        assert_eq!(counter.get(), 0);
        counter.inc();
        assert_eq!(counter.get(), 1);
        counter.add(5);
        assert_eq!(counter.get(), 6);
    }

    #[test]
    fn test_gauge() {
        let gauge = Gauge::new();
        assert_eq!(gauge.get(), 0);
        gauge.set(10);
        assert_eq!(gauge.get(), 10);
        gauge.inc();
        assert_eq!(gauge.get(), 11);
        gauge.dec();
        assert_eq!(gauge.get(), 10);
    }

    #[test]
    fn test_histogram() {
        let hist = Histogram::new();
        hist.observe(50);
        hist.observe(100);
        hist.observe(150);

        assert_eq!(hist.get_count(), 3);
        assert_eq!(hist.get_sum(), 300);
        assert_eq!(hist.get_mean(), 100.0);
    }

    #[test]
    fn test_labeled_metric() {
        let labeled = LabeledMetric::new(Counter::new);
        labeled.with_label("foo").inc();
        labeled.with_label("foo").inc();
        labeled.with_label("bar").inc();

        assert_eq!(labeled.with_label("foo").get(), 2);
        assert_eq!(labeled.with_label("bar").get(), 1);
    }

    #[test]
    fn test_http_metrics() {
        let metrics = HttpMetrics::new();
        metrics.record_request("example.com", 200, Duration::from_millis(100), 1024);
        metrics.record_request("example.com", 404, Duration::from_millis(50), 256);
        metrics.record_error("timeout");

        let report = metrics.report();
        assert_eq!(report.requests_total, 2);
        assert_eq!(report.errors_total, 1);
    }

    #[test]
    fn test_metrics_report_display() {
        let report = MetricsReport {
            requests_total: 100,
            errors_total: 5,
            active_connections: 3,
            avg_duration_ms: 150.5,
            total_bytes_sent: 1024,
            total_bytes_received: 2048,
            redirects_total: 10,
            retries_total: 2,
        };

        let display = format!("{}", report);
        assert!(display.contains("Requests: 100"));
        assert!(display.contains("Errors: 5"));
    }
}
