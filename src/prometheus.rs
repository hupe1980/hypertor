//! Prometheus Metrics Export
//!
//! This module provides Prometheus-compatible metrics export for production
//! observability. It supports counters, gauges, histograms, and summaries
//! with labels and proper formatting.
//!
//! # Features
//!
//! - **Counter**: Monotonically increasing values (requests, bytes, errors)
//! - **Gauge**: Values that can go up/down (connections, queue depth)
//! - **Histogram**: Distribution of values with configurable buckets
//! - **Summary**: Quantile calculations (p50, p95, p99)
//! - **Labels**: Dimensional metrics with key-value pairs
//! - **Registry**: Central collection of all metrics
//! - **HTTP Endpoint**: Ready-to-use `/metrics` handler
//!
//! # Example
//!
//! ```rust,ignore
//! use hypertor::prometheus::{Registry, Counter, Histogram, Labels};
//!
//! let registry = Registry::new("hypertor");
//!
//! // Create metrics
//! let requests = registry.counter("http_requests_total", "Total HTTP requests");
//! let latency = registry.histogram("http_request_duration_seconds", "Request latency");
//!
//! // Record values
//! requests.inc_with_labels(&[("method", "GET"), ("status", "200")]);
//! latency.observe(0.123);
//!
//! // Export
//! let output = registry.export();
//! ```

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Instant;

use parking_lot::RwLock;

// ============================================================================
// Labels
// ============================================================================

/// Metric labels (dimensions)
pub type Labels = Vec<(String, String)>;

/// Convert label slice to owned labels
pub fn labels(pairs: &[(&str, &str)]) -> Labels {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Format labels for Prometheus output
fn format_labels(labels: &Labels) -> String {
    if labels.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = labels
        .iter()
        .map(|(k, v)| format!("{}=\"{}\"", k, escape_label_value(v)))
        .collect();
    format!("{{{}}}", parts.join(","))
}

/// Escape special characters in label values
fn escape_label_value(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

// ============================================================================
// Counter
// ============================================================================

/// A Prometheus counter metric
#[derive(Debug)]
pub struct PrometheusCounter {
    /// Metric name
    name: String,
    /// Help text
    help: String,
    /// Values by label set
    values: RwLock<HashMap<Labels, AtomicU64>>,
}

impl PrometheusCounter {
    /// Create a new counter
    pub fn new(name: impl Into<String>, help: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            help: help.into(),
            values: RwLock::new(HashMap::new()),
        }
    }

    /// Increment by 1
    pub fn inc(&self) {
        self.add(1);
    }

    /// Add a value
    pub fn add(&self, value: u64) {
        self.add_with_labels(value, &[]);
    }

    /// Increment by 1 with labels
    pub fn inc_with_labels(&self, label_pairs: &[(&str, &str)]) {
        self.add_with_labels(1, label_pairs);
    }

    /// Add a value with labels
    pub fn add_with_labels(&self, value: u64, label_pairs: &[(&str, &str)]) {
        let labels = labels(label_pairs);
        let mut values = self.values.write();

        if let Some(counter) = values.get(&labels) {
            counter.fetch_add(value, Ordering::Relaxed);
        } else {
            let counter = AtomicU64::new(value);
            values.insert(labels, counter);
        }
    }

    /// Get value for specific labels
    pub fn get(&self, label_pairs: &[(&str, &str)]) -> u64 {
        let labels = labels(label_pairs);
        let values = self.values.read();
        values
            .get(&labels)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Export to Prometheus format
    pub fn export(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("# HELP {} {}\n", self.name, self.help));
        output.push_str(&format!("# TYPE {} counter\n", self.name));

        let values = self.values.read();
        for (labels, value) in values.iter() {
            let label_str = format_labels(labels);
            output.push_str(&format!(
                "{}{} {}\n",
                self.name,
                label_str,
                value.load(Ordering::Relaxed)
            ));
        }

        output
    }
}

// ============================================================================
// Gauge
// ============================================================================

/// A Prometheus gauge metric
#[derive(Debug)]
pub struct PrometheusGauge {
    /// Metric name
    name: String,
    /// Help text
    help: String,
    /// Values by label set
    values: RwLock<HashMap<Labels, AtomicI64>>,
}

impl PrometheusGauge {
    /// Create a new gauge
    pub fn new(name: impl Into<String>, help: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            help: help.into(),
            values: RwLock::new(HashMap::new()),
        }
    }

    /// Set the gauge value
    pub fn set(&self, value: i64) {
        self.set_with_labels(value, &[]);
    }

    /// Set with labels
    pub fn set_with_labels(&self, value: i64, label_pairs: &[(&str, &str)]) {
        let labels = labels(label_pairs);
        let mut values = self.values.write();

        if let Some(gauge) = values.get(&labels) {
            gauge.store(value, Ordering::Relaxed);
        } else {
            let gauge = AtomicI64::new(value);
            values.insert(labels, gauge);
        }
    }

    /// Increment by 1
    pub fn inc(&self) {
        self.add(1);
    }

    /// Decrement by 1
    pub fn dec(&self) {
        self.add(-1);
    }

    /// Add to the gauge
    pub fn add(&self, value: i64) {
        self.add_with_labels(value, &[]);
    }

    /// Add with labels
    pub fn add_with_labels(&self, value: i64, label_pairs: &[(&str, &str)]) {
        let labels = labels(label_pairs);
        let mut values = self.values.write();

        if let Some(gauge) = values.get(&labels) {
            gauge.fetch_add(value, Ordering::Relaxed);
        } else {
            let gauge = AtomicI64::new(value);
            values.insert(labels, gauge);
        }
    }

    /// Get value for specific labels
    pub fn get(&self, label_pairs: &[(&str, &str)]) -> i64 {
        let labels = labels(label_pairs);
        let values = self.values.read();
        values
            .get(&labels)
            .map(|g| g.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Export to Prometheus format
    pub fn export(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("# HELP {} {}\n", self.name, self.help));
        output.push_str(&format!("# TYPE {} gauge\n", self.name));

        let values = self.values.read();
        for (labels, value) in values.iter() {
            let label_str = format_labels(labels);
            output.push_str(&format!(
                "{}{} {}\n",
                self.name,
                label_str,
                value.load(Ordering::Relaxed)
            ));
        }

        output
    }
}

// ============================================================================
// Histogram
// ============================================================================

/// Default histogram buckets for latency (seconds)
pub fn default_latency_buckets() -> Vec<f64> {
    vec![
        0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ]
}

/// Default histogram buckets for Tor latency (higher values)
pub fn tor_latency_buckets() -> Vec<f64> {
    vec![
        0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0,
    ]
}

/// Default histogram buckets for sizes (bytes)
pub fn size_buckets() -> Vec<f64> {
    vec![
        100.0,
        1000.0,
        10000.0,
        100000.0,
        1000000.0,
        10000000.0,
        100000000.0,
    ]
}

/// Histogram data for a single label set
#[derive(Debug)]
struct HistogramData {
    /// Bucket counts (index corresponds to bucket bound)
    buckets: Vec<AtomicU64>,
    /// Sum of all observed values
    sum: AtomicU64,
    /// Total observation count
    count: AtomicU64,
}

impl HistogramData {
    fn new(num_buckets: usize) -> Self {
        Self {
            buckets: (0..num_buckets).map(|_| AtomicU64::new(0)).collect(),
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    fn observe(&self, value: f64, bounds: &[f64]) {
        // Update sum (store as integer micros for atomicity)
        let micros = (value * 1_000_000.0) as u64;
        self.sum.fetch_add(micros, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);

        // Update buckets
        for (i, bound) in bounds.iter().enumerate() {
            if value <= *bound {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        // +Inf bucket (last one)
        if let Some(last) = self.buckets.last() {
            last.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// A Prometheus histogram metric
#[derive(Debug)]
pub struct PrometheusHistogram {
    /// Metric name
    name: String,
    /// Help text
    help: String,
    /// Bucket upper bounds
    bounds: Vec<f64>,
    /// Data by label set
    data: RwLock<HashMap<Labels, HistogramData>>,
}

impl PrometheusHistogram {
    /// Create a new histogram with default latency buckets
    pub fn new(name: impl Into<String>, help: impl Into<String>) -> Self {
        Self::with_buckets(name, help, default_latency_buckets())
    }

    /// Create with custom buckets
    pub fn with_buckets(
        name: impl Into<String>,
        help: impl Into<String>,
        buckets: Vec<f64>,
    ) -> Self {
        Self {
            name: name.into(),
            help: help.into(),
            bounds: buckets,
            data: RwLock::new(HashMap::new()),
        }
    }

    /// Create with Tor-optimized latency buckets
    pub fn tor_latency(name: impl Into<String>, help: impl Into<String>) -> Self {
        Self::with_buckets(name, help, tor_latency_buckets())
    }

    /// Observe a value
    pub fn observe(&self, value: f64) {
        self.observe_with_labels(value, &[]);
    }

    /// Observe with labels
    pub fn observe_with_labels(&self, value: f64, label_pairs: &[(&str, &str)]) {
        let labels = labels(label_pairs);
        let mut data = self.data.write();

        if let Some(hist) = data.get(&labels) {
            hist.observe(value, &self.bounds);
        } else {
            let hist = HistogramData::new(self.bounds.len() + 1); // +1 for +Inf
            hist.observe(value, &self.bounds);
            data.insert(labels, hist);
        }
    }

    /// Time a closure and record the duration
    pub fn time<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let start = Instant::now();
        let result = f();
        self.observe(start.elapsed().as_secs_f64());
        result
    }

    /// Create a timer that records on drop
    pub fn start_timer(&self) -> HistogramTimer<'_> {
        HistogramTimer {
            histogram: self,
            start: Instant::now(),
            labels: vec![],
        }
    }

    /// Create a timer with labels
    pub fn start_timer_with_labels(&self, label_pairs: &[(&str, &str)]) -> HistogramTimer<'_> {
        HistogramTimer {
            histogram: self,
            start: Instant::now(),
            labels: labels(label_pairs),
        }
    }

    /// Export to Prometheus format
    pub fn export(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("# HELP {} {}\n", self.name, self.help));
        output.push_str(&format!("# TYPE {} histogram\n", self.name));

        let data = self.data.read();
        for (labels, hist) in data.iter() {
            let base_labels = format_labels(labels);

            // Output bucket counts
            let mut cumulative = 0u64;
            for (i, bound) in self.bounds.iter().enumerate() {
                cumulative += hist.buckets[i].load(Ordering::Relaxed);
                let mut bucket_labels = labels.clone();
                bucket_labels.push(("le".to_string(), format!("{}", bound)));
                output.push_str(&format!(
                    "{}_bucket{} {}\n",
                    self.name,
                    format_labels(&bucket_labels),
                    cumulative
                ));
            }

            // +Inf bucket
            let total = hist.count.load(Ordering::Relaxed);
            let mut inf_labels = labels.clone();
            inf_labels.push(("le".to_string(), "+Inf".to_string()));
            output.push_str(&format!(
                "{}_bucket{} {}\n",
                self.name,
                format_labels(&inf_labels),
                total
            ));

            // Sum and count
            let sum = hist.sum.load(Ordering::Relaxed) as f64 / 1_000_000.0;
            output.push_str(&format!("{}_sum{} {}\n", self.name, base_labels, sum));
            output.push_str(&format!("{}_count{} {}\n", self.name, base_labels, total));
        }

        output
    }
}

/// Timer that records to histogram on drop
pub struct HistogramTimer<'a> {
    histogram: &'a PrometheusHistogram,
    start: Instant,
    labels: Labels,
}

impl Drop for HistogramTimer<'_> {
    fn drop(&mut self) {
        let duration = self.start.elapsed().as_secs_f64();
        let label_pairs: Vec<(&str, &str)> = self
            .labels
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        self.histogram.observe_with_labels(duration, &label_pairs);
    }
}

// ============================================================================
// Summary (Quantiles)
// ============================================================================

/// A Prometheus summary metric with quantile calculation
#[derive(Debug)]
pub struct PrometheusSummary {
    /// Metric name
    name: String,
    /// Help text
    help: String,
    /// Quantiles to calculate (e.g., 0.5, 0.9, 0.99)
    quantiles: Vec<f64>,
    /// Observations (windowed)
    data: RwLock<HashMap<Labels, SummaryData>>,
    /// Max observations to keep
    max_observations: usize,
}

#[derive(Debug)]
struct SummaryData {
    observations: Vec<f64>,
    sum: f64,
    count: u64,
}

impl SummaryData {
    fn new() -> Self {
        Self {
            observations: Vec::new(),
            sum: 0.0,
            count: 0,
        }
    }

    fn observe(&mut self, value: f64, max_obs: usize) {
        self.observations.push(value);
        self.sum += value;
        self.count += 1;

        // Keep window size bounded
        if self.observations.len() > max_obs {
            let removed = self.observations.remove(0);
            self.sum -= removed;
        }
    }

    fn quantile(&self, q: f64) -> f64 {
        if self.observations.is_empty() {
            return 0.0;
        }

        let mut sorted = self.observations.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let idx = ((sorted.len() - 1) as f64 * q) as usize;
        sorted[idx.min(sorted.len() - 1)]
    }
}

impl PrometheusSummary {
    /// Create a new summary with default quantiles (0.5, 0.9, 0.99)
    pub fn new(name: impl Into<String>, help: impl Into<String>) -> Self {
        Self::with_quantiles(name, help, vec![0.5, 0.9, 0.99])
    }

    /// Create with custom quantiles
    pub fn with_quantiles(
        name: impl Into<String>,
        help: impl Into<String>,
        quantiles: Vec<f64>,
    ) -> Self {
        Self {
            name: name.into(),
            help: help.into(),
            quantiles,
            data: RwLock::new(HashMap::new()),
            max_observations: 1000,
        }
    }

    /// Observe a value
    pub fn observe(&self, value: f64) {
        self.observe_with_labels(value, &[]);
    }

    /// Observe with labels
    pub fn observe_with_labels(&self, value: f64, label_pairs: &[(&str, &str)]) {
        let labels = labels(label_pairs);
        let mut data = self.data.write();

        let summary = data.entry(labels).or_insert_with(SummaryData::new);
        summary.observe(value, self.max_observations);
    }

    /// Export to Prometheus format
    pub fn export(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("# HELP {} {}\n", self.name, self.help));
        output.push_str(&format!("# TYPE {} summary\n", self.name));

        let data = self.data.read();
        for (labels, summary) in data.iter() {
            let base_labels = format_labels(labels);

            // Output quantiles
            for &q in &self.quantiles {
                let mut q_labels = labels.clone();
                q_labels.push(("quantile".to_string(), format!("{}", q)));
                output.push_str(&format!(
                    "{}{} {}\n",
                    self.name,
                    format_labels(&q_labels),
                    summary.quantile(q)
                ));
            }

            // Sum and count
            output.push_str(&format!(
                "{}_sum{} {}\n",
                self.name, base_labels, summary.sum
            ));
            output.push_str(&format!(
                "{}_count{} {}\n",
                self.name, base_labels, summary.count
            ));
        }

        output
    }
}

// ============================================================================
// Registry
// ============================================================================

/// Central metrics registry
#[derive(Debug)]
pub struct MetricsRegistry {
    /// Namespace prefix for all metrics
    namespace: String,
    /// Counters
    counters: RwLock<HashMap<String, Arc<PrometheusCounter>>>,
    /// Gauges
    gauges: RwLock<HashMap<String, Arc<PrometheusGauge>>>,
    /// Histograms
    histograms: RwLock<HashMap<String, Arc<PrometheusHistogram>>>,
    /// Summaries
    summaries: RwLock<HashMap<String, Arc<PrometheusSummary>>>,
}

impl MetricsRegistry {
    /// Create a new registry with namespace
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            counters: RwLock::new(HashMap::new()),
            gauges: RwLock::new(HashMap::new()),
            histograms: RwLock::new(HashMap::new()),
            summaries: RwLock::new(HashMap::new()),
        }
    }

    /// Get full metric name with namespace
    fn full_name(&self, name: &str) -> String {
        if self.namespace.is_empty() {
            name.to_string()
        } else {
            format!("{}_{}", self.namespace, name)
        }
    }

    /// Register or get a counter
    pub fn counter(&self, name: &str, help: &str) -> Arc<PrometheusCounter> {
        let full_name = self.full_name(name);
        let mut counters = self.counters.write();

        if let Some(counter) = counters.get(&full_name) {
            return counter.clone();
        }

        let counter = Arc::new(PrometheusCounter::new(&full_name, help));
        counters.insert(full_name, counter.clone());
        counter
    }

    /// Register or get a gauge
    pub fn gauge(&self, name: &str, help: &str) -> Arc<PrometheusGauge> {
        let full_name = self.full_name(name);
        let mut gauges = self.gauges.write();

        if let Some(gauge) = gauges.get(&full_name) {
            return gauge.clone();
        }

        let gauge = Arc::new(PrometheusGauge::new(&full_name, help));
        gauges.insert(full_name, gauge.clone());
        gauge
    }

    /// Register or get a histogram
    pub fn histogram(&self, name: &str, help: &str) -> Arc<PrometheusHistogram> {
        let full_name = self.full_name(name);
        let mut histograms = self.histograms.write();

        if let Some(hist) = histograms.get(&full_name) {
            return hist.clone();
        }

        let hist = Arc::new(PrometheusHistogram::new(&full_name, help));
        histograms.insert(full_name, hist.clone());
        hist
    }

    /// Register or get a histogram with Tor latency buckets
    pub fn tor_histogram(&self, name: &str, help: &str) -> Arc<PrometheusHistogram> {
        let full_name = self.full_name(name);
        let mut histograms = self.histograms.write();

        if let Some(hist) = histograms.get(&full_name) {
            return hist.clone();
        }

        let hist = Arc::new(PrometheusHistogram::tor_latency(&full_name, help));
        histograms.insert(full_name, hist.clone());
        hist
    }

    /// Register or get a summary
    pub fn summary(&self, name: &str, help: &str) -> Arc<PrometheusSummary> {
        let full_name = self.full_name(name);
        let mut summaries = self.summaries.write();

        if let Some(summary) = summaries.get(&full_name) {
            return summary.clone();
        }

        let summary = Arc::new(PrometheusSummary::new(&full_name, help));
        summaries.insert(full_name, summary.clone());
        summary
    }

    /// Export all metrics in Prometheus format
    pub fn export(&self) -> String {
        let mut output = String::new();

        // Export counters
        for counter in self.counters.read().values() {
            output.push_str(&counter.export());
        }

        // Export gauges
        for gauge in self.gauges.read().values() {
            output.push_str(&gauge.export());
        }

        // Export histograms
        for histogram in self.histograms.read().values() {
            output.push_str(&histogram.export());
        }

        // Export summaries
        for summary in self.summaries.read().values() {
            output.push_str(&summary.export());
        }

        output
    }

    /// Get metrics count
    pub fn metrics_count(&self) -> usize {
        self.counters.read().len()
            + self.gauges.read().len()
            + self.histograms.read().len()
            + self.summaries.read().len()
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new("")
    }
}

// ============================================================================
// Pre-defined Tor Metrics
// ============================================================================

/// Pre-defined metrics for Tor operations
#[derive(Debug)]
pub struct TorMetrics {
    /// Registry
    pub registry: MetricsRegistry,

    // Requests
    /// Total HTTP requests
    pub http_requests_total: Arc<PrometheusCounter>,
    /// HTTP request duration
    pub http_request_duration_seconds: Arc<PrometheusHistogram>,
    /// HTTP request size
    pub http_request_size_bytes: Arc<PrometheusHistogram>,
    /// HTTP response size
    pub http_response_size_bytes: Arc<PrometheusHistogram>,

    // Circuits
    /// Circuit build attempts
    pub circuit_build_total: Arc<PrometheusCounter>,
    /// Circuit build duration
    pub circuit_build_duration_seconds: Arc<PrometheusHistogram>,
    /// Active circuits
    pub circuits_active: Arc<PrometheusGauge>,
    /// Circuit failures
    pub circuit_failures_total: Arc<PrometheusCounter>,

    // Connections
    /// Active connections
    pub connections_active: Arc<PrometheusGauge>,
    /// Connection pool size
    pub connection_pool_size: Arc<PrometheusGauge>,
    /// Connection errors
    pub connection_errors_total: Arc<PrometheusCounter>,

    // Bandwidth
    /// Bytes sent
    pub bytes_sent_total: Arc<PrometheusCounter>,
    /// Bytes received
    pub bytes_received_total: Arc<PrometheusCounter>,

    // Onion Services
    /// Onion service requests
    pub onion_requests_total: Arc<PrometheusCounter>,
    /// Onion service response time
    pub onion_response_duration_seconds: Arc<PrometheusHistogram>,

    // Security
    /// PoW challenges solved
    pub pow_challenges_solved: Arc<PrometheusCounter>,
    /// PoW solve duration
    pub pow_solve_duration_seconds: Arc<PrometheusHistogram>,
    /// Blocked requests (rate limit, etc.)
    pub blocked_requests_total: Arc<PrometheusCounter>,

    // Bridges
    /// Bridge connection attempts
    pub bridge_connections_total: Arc<PrometheusCounter>,
    /// Active bridge
    pub bridge_active: Arc<PrometheusGauge>,
}

impl TorMetrics {
    /// Create a new set of Tor metrics
    pub fn new() -> Self {
        let registry = MetricsRegistry::new("hypertor");

        // HTTP metrics
        let http_requests_total =
            registry.counter("http_requests_total", "Total number of HTTP requests");
        let http_request_duration_seconds = registry.tor_histogram(
            "http_request_duration_seconds",
            "HTTP request duration in seconds",
        );
        let http_request_size_bytes = Arc::new(PrometheusHistogram::with_buckets(
            "hypertor_http_request_size_bytes",
            "HTTP request size in bytes",
            size_buckets(),
        ));
        let http_response_size_bytes = Arc::new(PrometheusHistogram::with_buckets(
            "hypertor_http_response_size_bytes",
            "HTTP response size in bytes",
            size_buckets(),
        ));

        // Circuit metrics
        let circuit_build_total =
            registry.counter("circuit_build_total", "Total circuit build attempts");
        let circuit_build_duration_seconds = registry.tor_histogram(
            "circuit_build_duration_seconds",
            "Circuit build duration in seconds",
        );
        let circuits_active = registry.gauge("circuits_active", "Number of active circuits");
        let circuit_failures_total =
            registry.counter("circuit_failures_total", "Total circuit failures");

        // Connection metrics
        let connections_active =
            registry.gauge("connections_active", "Number of active connections");
        let connection_pool_size =
            registry.gauge("connection_pool_size", "Size of connection pool");
        let connection_errors_total =
            registry.counter("connection_errors_total", "Total connection errors");

        // Bandwidth metrics
        let bytes_sent_total = registry.counter("bytes_sent_total", "Total bytes sent");
        let bytes_received_total = registry.counter("bytes_received_total", "Total bytes received");

        // Onion service metrics
        let onion_requests_total =
            registry.counter("onion_requests_total", "Total onion service requests");
        let onion_response_duration_seconds = registry.tor_histogram(
            "onion_response_duration_seconds",
            "Onion service response duration",
        );

        // Security metrics
        let pow_challenges_solved =
            registry.counter("pow_challenges_solved", "Total PoW challenges solved");
        let pow_solve_duration_seconds = registry.histogram(
            "pow_solve_duration_seconds",
            "PoW solve duration in seconds",
        );
        let blocked_requests_total =
            registry.counter("blocked_requests_total", "Total blocked requests");

        // Bridge metrics
        let bridge_connections_total = registry.counter(
            "bridge_connections_total",
            "Total bridge connection attempts",
        );
        let bridge_active =
            registry.gauge("bridge_active", "Currently active bridge (1=yes, 0=no)");

        Self {
            registry,
            http_requests_total,
            http_request_duration_seconds,
            http_request_size_bytes,
            http_response_size_bytes,
            circuit_build_total,
            circuit_build_duration_seconds,
            circuits_active,
            circuit_failures_total,
            connections_active,
            connection_pool_size,
            connection_errors_total,
            bytes_sent_total,
            bytes_received_total,
            onion_requests_total,
            onion_response_duration_seconds,
            pow_challenges_solved,
            pow_solve_duration_seconds,
            blocked_requests_total,
            bridge_connections_total,
            bridge_active,
        }
    }

    /// Export all metrics
    pub fn export(&self) -> String {
        let mut output = self.registry.export();

        // Add histogram exports not in registry
        output.push_str(&self.http_request_size_bytes.export());
        output.push_str(&self.http_response_size_bytes.export());

        output
    }

    /// Record an HTTP request
    pub fn record_request(
        &self,
        method: &str,
        status: u16,
        duration_secs: f64,
        request_bytes: u64,
        response_bytes: u64,
    ) {
        let status_str = status.to_string();
        let labels = &[("method", method), ("status", &status_str)];

        self.http_requests_total.inc_with_labels(labels);
        self.http_request_duration_seconds
            .observe_with_labels(duration_secs, labels);
        self.http_request_size_bytes.observe(request_bytes as f64);
        self.http_response_size_bytes.observe(response_bytes as f64);
        self.bytes_sent_total.add(request_bytes);
        self.bytes_received_total.add(response_bytes);
    }

    /// Record a circuit build
    pub fn record_circuit_build(&self, success: bool, duration_secs: f64) {
        let result = if success { "success" } else { "failure" };
        self.circuit_build_total
            .inc_with_labels(&[("result", result)]);
        self.circuit_build_duration_seconds.observe(duration_secs);

        if !success {
            self.circuit_failures_total.inc();
        }
    }
}

impl Default for TorMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global Metrics Instance
// ============================================================================

use std::sync::OnceLock;

static GLOBAL_METRICS: OnceLock<TorMetrics> = OnceLock::new();

/// Get the global metrics instance
pub fn global_metrics() -> &'static TorMetrics {
    GLOBAL_METRICS.get_or_init(TorMetrics::new)
}

/// Export global metrics in Prometheus format
pub fn export_metrics() -> String {
    global_metrics().export()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter() {
        let counter = PrometheusCounter::new("test_counter", "A test counter");
        counter.inc();
        counter.add(5);
        assert_eq!(counter.get(&[]), 6);

        let export = counter.export();
        assert!(export.contains("# TYPE test_counter counter"));
        assert!(export.contains("test_counter 6"));
    }

    #[test]
    fn test_counter_with_labels() {
        let counter = PrometheusCounter::new("requests", "Requests");
        counter.inc_with_labels(&[("method", "GET"), ("status", "200")]);
        counter.inc_with_labels(&[("method", "POST"), ("status", "201")]);
        counter.inc_with_labels(&[("method", "GET"), ("status", "200")]);

        assert_eq!(counter.get(&[("method", "GET"), ("status", "200")]), 2);
        assert_eq!(counter.get(&[("method", "POST"), ("status", "201")]), 1);
    }

    #[test]
    fn test_gauge() {
        let gauge = PrometheusGauge::new("test_gauge", "A test gauge");
        gauge.set(10);
        assert_eq!(gauge.get(&[]), 10);

        gauge.inc();
        assert_eq!(gauge.get(&[]), 11);

        gauge.dec();
        assert_eq!(gauge.get(&[]), 10);
    }

    #[test]
    fn test_histogram() {
        let hist = PrometheusHistogram::new("latency", "Latency");
        hist.observe(0.05);
        hist.observe(0.15);
        hist.observe(0.5);

        let export = hist.export();
        assert!(export.contains("# TYPE latency histogram"));
        assert!(export.contains("latency_bucket"));
        assert!(export.contains("latency_sum"));
        assert!(export.contains("latency_count"));
    }

    #[test]
    fn test_histogram_timer() {
        let hist = PrometheusHistogram::new("duration", "Duration");
        {
            let _timer = hist.start_timer();
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let export = hist.export();
        assert!(export.contains("duration_count 1"));
    }

    #[test]
    fn test_summary() {
        let summary = PrometheusSummary::new("response_time", "Response time");
        for i in 1..=100 {
            summary.observe(i as f64);
        }

        let export = summary.export();
        assert!(export.contains("# TYPE response_time summary"));
        assert!(export.contains("quantile=\"0.5\""));
        assert!(export.contains("quantile=\"0.99\""));
    }

    #[test]
    fn test_registry() {
        let registry = MetricsRegistry::new("myapp");

        let counter = registry.counter("requests", "Total requests");
        counter.inc();

        let gauge = registry.gauge("connections", "Active connections");
        gauge.set(5);

        let export = registry.export();
        assert!(export.contains("myapp_requests"));
        assert!(export.contains("myapp_connections"));
    }

    #[test]
    fn test_tor_metrics() {
        let metrics = TorMetrics::new();

        metrics.record_request("GET", 200, 1.5, 100, 5000);
        metrics.record_circuit_build(true, 2.0);
        metrics.circuits_active.set(3);

        let export = metrics.export();
        assert!(export.contains("hypertor_http_requests_total"));
        assert!(export.contains("hypertor_circuit_build_total"));
        assert!(export.contains("hypertor_circuits_active"));
    }

    #[test]
    fn test_label_escaping() {
        let escaped = escape_label_value("test\"value\nwith\\special");
        assert_eq!(escaped, "test\\\"value\\nwith\\\\special");
    }

    #[test]
    fn test_global_metrics() {
        let metrics = global_metrics();
        metrics.http_requests_total.inc();

        let export = export_metrics();
        assert!(export.contains("hypertor_http_requests_total"));
    }
}
