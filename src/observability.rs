//! Unified Observability Abstraction
//!
//! This module provides a backend-agnostic metrics interface supporting both
//! Prometheus and OpenTelemetry exporters. The abstraction allows switching
//! between backends without changing application code.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     Application Code                        │
//! │  metrics.counter("requests").inc_with_labels(&[...])       │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!                              ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                   MetricsBackend Trait                       │
//! │  counter() / gauge() / histogram() / summary()              │
//! └─────────────────────────────────────────────────────────────┘
//!                    │                    │
//!          ┌─────────┴─────────┐          │
//!          ▼                   ▼          ▼
//! ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
//! │   Prometheus    │ │  OpenTelemetry  │ │      Noop       │
//! │    Backend      │ │    Backend      │ │    Backend      │
//! └─────────────────┘ └─────────────────┘ └─────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use hypertor::observability::{Metrics, MetricsConfig, Backend};
//!
//! // Create metrics with Prometheus backend
//! let metrics = Metrics::new(MetricsConfig::prometheus("hypertor"));
//!
//! // Create metrics with OpenTelemetry backend
//! let metrics = Metrics::new(MetricsConfig::opentelemetry("hypertor"));
//!
//! // Use the same API regardless of backend
//! let counter = metrics.counter("http_requests_total", "Total HTTP requests");
//! counter.inc();
//! counter.inc_with_labels(&[("method", "GET"), ("status", "200")]);
//!
//! let histogram = metrics.histogram("request_duration_seconds", "Request duration");
//! histogram.observe(0.123);
//!
//! // Export (format depends on backend)
//! let output = metrics.export();
//! ```

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::RwLock;

// ============================================================================
// Core Traits - Backend Agnostic Interface
// ============================================================================

/// A counter metric that only increases.
pub trait CounterTrait: Send + Sync {
    /// Increment by 1.
    fn inc(&self);

    /// Add a value.
    fn add(&self, value: u64);

    /// Increment with labels.
    fn inc_with_labels(&self, labels: &[(&str, &str)]);

    /// Add with labels.
    fn add_with_labels(&self, value: u64, labels: &[(&str, &str)]);

    /// Get value (may not be supported by all backends).
    fn get(&self) -> u64 {
        0
    }

    /// Get value with labels.
    fn get_with_labels(&self, labels: &[(&str, &str)]) -> u64 {
        let _ = labels;
        0
    }
}

/// A gauge metric that can go up or down.
pub trait GaugeTrait: Send + Sync {
    /// Set the value.
    fn set(&self, value: i64);

    /// Set with labels.
    fn set_with_labels(&self, value: i64, labels: &[(&str, &str)]);

    /// Increment by 1.
    fn inc(&self);

    /// Decrement by 1.
    fn dec(&self);

    /// Add to the value.
    fn add(&self, value: i64);

    /// Add with labels.
    fn add_with_labels(&self, value: i64, labels: &[(&str, &str)]);

    /// Get value.
    fn get(&self) -> i64 {
        0
    }
}

/// A histogram for distribution tracking.
pub trait HistogramTrait: Send + Sync {
    /// Observe a value.
    fn observe(&self, value: f64);

    /// Observe with labels.
    fn observe_with_labels(&self, value: f64, labels: &[(&str, &str)]);

    /// Record a duration.
    fn observe_duration(&self, duration: Duration) {
        self.observe(duration.as_secs_f64());
    }

    /// Start a timer that records on drop.
    fn start_timer(&self) -> Box<dyn TimerTrait + '_>;

    /// Start a timer with labels.
    fn start_timer_with_labels(&self, labels: &[(&str, &str)]) -> Box<dyn TimerTrait + '_>;
}

/// A timer that records to a histogram on drop.
pub trait TimerTrait: Send {
    /// Get elapsed time without stopping.
    fn elapsed(&self) -> Duration;

    /// Stop the timer and record (happens automatically on drop).
    fn stop(self: Box<Self>);
}

/// A summary for quantile calculations.
pub trait SummaryTrait: Send + Sync {
    /// Observe a value.
    fn observe(&self, value: f64);

    /// Observe with labels.
    fn observe_with_labels(&self, value: f64, labels: &[(&str, &str)]);
}

/// Metrics backend trait - implement this for custom backends.
pub trait MetricsBackend: Send + Sync {
    /// Create a counter.
    fn counter(&self, name: &str, help: &str) -> Arc<dyn CounterTrait>;

    /// Create a gauge.
    fn gauge(&self, name: &str, help: &str) -> Arc<dyn GaugeTrait>;

    /// Create a histogram with default buckets.
    fn histogram(&self, name: &str, help: &str) -> Arc<dyn HistogramTrait>;

    /// Create a histogram with custom buckets.
    fn histogram_with_buckets(
        &self,
        name: &str,
        help: &str,
        buckets: Vec<f64>,
    ) -> Arc<dyn HistogramTrait>;

    /// Create a summary.
    fn summary(&self, name: &str, help: &str) -> Arc<dyn SummaryTrait>;

    /// Export metrics in the backend's native format.
    fn export(&self) -> String;

    /// Export metrics in OpenTelemetry JSON format.
    fn export_otlp_json(&self) -> String {
        "{}".to_string()
    }

    /// Get the backend name.
    fn name(&self) -> &'static str;
}

// ============================================================================
// Backend Selection
// ============================================================================

/// Backend selection for metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// Prometheus text format export.
    Prometheus,
    /// OpenTelemetry (OTLP) export.
    OpenTelemetry,
    /// No-op backend (metrics discarded).
    Noop,
}

/// Configuration for metrics system.
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// Namespace prefix for all metrics.
    pub namespace: String,
    /// Backend to use.
    pub backend: Backend,
    /// Default histogram buckets for latency (seconds).
    pub latency_buckets: Vec<f64>,
    /// OpenTelemetry endpoint (for OTLP export).
    pub otlp_endpoint: Option<String>,
}

impl MetricsConfig {
    /// Create config for Prometheus backend.
    pub fn prometheus(namespace: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            backend: Backend::Prometheus,
            latency_buckets: default_latency_buckets(),
            otlp_endpoint: None,
        }
    }

    /// Create config for OpenTelemetry backend.
    pub fn opentelemetry(namespace: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            backend: Backend::OpenTelemetry,
            latency_buckets: default_latency_buckets(),
            otlp_endpoint: None,
        }
    }

    /// Create config for Noop backend.
    pub fn noop() -> Self {
        Self {
            namespace: String::new(),
            backend: Backend::Noop,
            latency_buckets: vec![],
            otlp_endpoint: None,
        }
    }

    /// Set OTLP endpoint for OpenTelemetry.
    pub fn with_otlp_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.otlp_endpoint = Some(endpoint.into());
        self
    }

    /// Set custom latency buckets.
    pub fn with_latency_buckets(mut self, buckets: Vec<f64>) -> Self {
        self.latency_buckets = buckets;
        self
    }
}

/// Default histogram buckets for latency (seconds).
pub fn default_latency_buckets() -> Vec<f64> {
    vec![
        0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ]
}

/// Tor-optimized histogram buckets (higher latency tolerance).
pub fn tor_latency_buckets() -> Vec<f64> {
    vec![
        0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0,
    ]
}

/// Size buckets for byte measurements.
pub fn size_buckets() -> Vec<f64> {
    vec![
        100.0,
        1000.0,
        10_000.0,
        100_000.0,
        1_000_000.0,
        10_000_000.0,
        100_000_000.0,
    ]
}

// ============================================================================
// Prometheus Backend Implementation
// ============================================================================

/// Prometheus metrics backend.
#[derive(Debug)]
pub struct PrometheusBackend {
    namespace: String,
    counters: RwLock<HashMap<String, Arc<PrometheusCounter>>>,
    gauges: RwLock<HashMap<String, Arc<PrometheusGauge>>>,
    histograms: RwLock<HashMap<String, Arc<PrometheusHistogram>>>,
    summaries: RwLock<HashMap<String, Arc<PrometheusSummary>>>,
}

impl PrometheusBackend {
    /// Create a new Prometheus backend.
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            counters: RwLock::new(HashMap::new()),
            gauges: RwLock::new(HashMap::new()),
            histograms: RwLock::new(HashMap::new()),
            summaries: RwLock::new(HashMap::new()),
        }
    }

    fn full_name(&self, name: &str) -> String {
        if self.namespace.is_empty() {
            name.to_string()
        } else {
            format!("{}_{}", self.namespace, name)
        }
    }
}

impl MetricsBackend for PrometheusBackend {
    fn counter(&self, name: &str, help: &str) -> Arc<dyn CounterTrait> {
        let full_name = self.full_name(name);
        let mut counters = self.counters.write();

        if let Some(counter) = counters.get(&full_name) {
            return counter.clone();
        }

        let counter = Arc::new(PrometheusCounter::new(&full_name, help));
        counters.insert(full_name, counter.clone());
        counter
    }

    fn gauge(&self, name: &str, help: &str) -> Arc<dyn GaugeTrait> {
        let full_name = self.full_name(name);
        let mut gauges = self.gauges.write();

        if let Some(gauge) = gauges.get(&full_name) {
            return gauge.clone();
        }

        let gauge = Arc::new(PrometheusGauge::new(&full_name, help));
        gauges.insert(full_name, gauge.clone());
        gauge
    }

    fn histogram(&self, name: &str, help: &str) -> Arc<dyn HistogramTrait> {
        self.histogram_with_buckets(name, help, default_latency_buckets())
    }

    fn histogram_with_buckets(
        &self,
        name: &str,
        help: &str,
        buckets: Vec<f64>,
    ) -> Arc<dyn HistogramTrait> {
        let full_name = self.full_name(name);
        let mut histograms = self.histograms.write();

        if let Some(hist) = histograms.get(&full_name) {
            return hist.clone();
        }

        let hist = Arc::new(PrometheusHistogram::with_buckets(&full_name, help, buckets));
        histograms.insert(full_name, hist.clone());
        hist
    }

    fn summary(&self, name: &str, help: &str) -> Arc<dyn SummaryTrait> {
        let full_name = self.full_name(name);
        let mut summaries = self.summaries.write();

        if let Some(summary) = summaries.get(&full_name) {
            return summary.clone();
        }

        let summary = Arc::new(PrometheusSummary::new(&full_name, help));
        summaries.insert(full_name, summary.clone());
        summary
    }

    fn export(&self) -> String {
        let mut output = String::new();

        for counter in self.counters.read().values() {
            output.push_str(&counter.export());
        }
        for gauge in self.gauges.read().values() {
            output.push_str(&gauge.export());
        }
        for histogram in self.histograms.read().values() {
            output.push_str(&histogram.export());
        }
        for summary in self.summaries.read().values() {
            output.push_str(&summary.export());
        }

        output
    }

    fn name(&self) -> &'static str {
        "prometheus"
    }
}

// Prometheus-specific implementations

/// Prometheus counter implementation.
#[derive(Debug)]
pub struct PrometheusCounter {
    name: String,
    help: String,
    values: RwLock<HashMap<Labels, AtomicU64>>,
}

type Labels = Vec<(String, String)>;

fn to_labels(pairs: &[(&str, &str)]) -> Labels {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

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

fn escape_label_value(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

impl PrometheusCounter {
    /// Create a new Prometheus counter.
    pub fn new(name: impl Into<String>, help: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            help: help.into(),
            values: RwLock::new(HashMap::new()),
        }
    }

    /// Export in Prometheus text format.
    pub fn export(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("# HELP {} {}\n", self.name, self.help));
        output.push_str(&format!("# TYPE {} counter\n", self.name));

        let values = self.values.read();
        for (labels, value) in values.iter() {
            output.push_str(&format!(
                "{}{} {}\n",
                self.name,
                format_labels(labels),
                value.load(Ordering::Relaxed)
            ));
        }
        output
    }
}

impl CounterTrait for PrometheusCounter {
    fn inc(&self) {
        self.add(1);
    }

    fn add(&self, value: u64) {
        self.add_with_labels(value, &[]);
    }

    fn inc_with_labels(&self, labels: &[(&str, &str)]) {
        self.add_with_labels(1, labels);
    }

    fn add_with_labels(&self, value: u64, label_pairs: &[(&str, &str)]) {
        let labels = to_labels(label_pairs);
        let mut values = self.values.write();

        if let Some(counter) = values.get(&labels) {
            counter.fetch_add(value, Ordering::Relaxed);
        } else {
            values.insert(labels, AtomicU64::new(value));
        }
    }

    fn get(&self) -> u64 {
        self.get_with_labels(&[])
    }

    fn get_with_labels(&self, label_pairs: &[(&str, &str)]) -> u64 {
        let labels = to_labels(label_pairs);
        let values = self.values.read();
        values
            .get(&labels)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
}

/// Prometheus gauge implementation.
#[derive(Debug)]
pub struct PrometheusGauge {
    name: String,
    help: String,
    values: RwLock<HashMap<Labels, AtomicI64>>,
}

impl PrometheusGauge {
    /// Create a new Prometheus gauge.
    pub fn new(name: impl Into<String>, help: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            help: help.into(),
            values: RwLock::new(HashMap::new()),
        }
    }

    /// Export in Prometheus text format.
    pub fn export(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("# HELP {} {}\n", self.name, self.help));
        output.push_str(&format!("# TYPE {} gauge\n", self.name));

        let values = self.values.read();
        for (labels, value) in values.iter() {
            output.push_str(&format!(
                "{}{} {}\n",
                self.name,
                format_labels(labels),
                value.load(Ordering::Relaxed)
            ));
        }
        output
    }
}

impl GaugeTrait for PrometheusGauge {
    fn set(&self, value: i64) {
        self.set_with_labels(value, &[]);
    }

    fn set_with_labels(&self, value: i64, label_pairs: &[(&str, &str)]) {
        let labels = to_labels(label_pairs);
        let mut values = self.values.write();

        if let Some(gauge) = values.get(&labels) {
            gauge.store(value, Ordering::Relaxed);
        } else {
            values.insert(labels, AtomicI64::new(value));
        }
    }

    fn inc(&self) {
        self.add(1);
    }

    fn dec(&self) {
        self.add(-1);
    }

    fn add(&self, value: i64) {
        self.add_with_labels(value, &[]);
    }

    fn add_with_labels(&self, value: i64, label_pairs: &[(&str, &str)]) {
        let labels = to_labels(label_pairs);
        let mut values = self.values.write();

        if let Some(gauge) = values.get(&labels) {
            gauge.fetch_add(value, Ordering::Relaxed);
        } else {
            values.insert(labels, AtomicI64::new(value));
        }
    }

    fn get(&self) -> i64 {
        let values = self.values.read();
        values
            .get(&vec![])
            .map(|g| g.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
}

/// Prometheus histogram implementation.
#[derive(Debug)]
pub struct PrometheusHistogram {
    name: String,
    help: String,
    bounds: Vec<f64>,
    data: RwLock<HashMap<Labels, HistogramData>>,
}

#[derive(Debug)]
struct HistogramData {
    buckets: Vec<AtomicU64>,
    sum: AtomicU64,
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
        let micros = (value * 1_000_000.0) as u64;
        self.sum.fetch_add(micros, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);

        for (i, bound) in bounds.iter().enumerate() {
            if value <= *bound {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        if let Some(last) = self.buckets.last() {
            last.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl PrometheusHistogram {
    /// Create a new histogram with default latency buckets.
    pub fn new(name: impl Into<String>, help: impl Into<String>) -> Self {
        Self::with_buckets(name, help, default_latency_buckets())
    }

    /// Create with custom buckets.
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

    /// Export in Prometheus text format.
    pub fn export(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("# HELP {} {}\n", self.name, self.help));
        output.push_str(&format!("# TYPE {} histogram\n", self.name));

        let data = self.data.read();
        for (labels, hist) in data.iter() {
            let base_labels = format_labels(labels);

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

            let total = hist.count.load(Ordering::Relaxed);
            let mut inf_labels = labels.clone();
            inf_labels.push(("le".to_string(), "+Inf".to_string()));
            output.push_str(&format!(
                "{}_bucket{} {}\n",
                self.name,
                format_labels(&inf_labels),
                total
            ));

            let sum = hist.sum.load(Ordering::Relaxed) as f64 / 1_000_000.0;
            output.push_str(&format!("{}_sum{} {}\n", self.name, base_labels, sum));
            output.push_str(&format!("{}_count{} {}\n", self.name, base_labels, total));
        }
        output
    }
}

impl HistogramTrait for PrometheusHistogram {
    fn observe(&self, value: f64) {
        self.observe_with_labels(value, &[]);
    }

    fn observe_with_labels(&self, value: f64, label_pairs: &[(&str, &str)]) {
        let labels = to_labels(label_pairs);
        let mut data = self.data.write();

        if let Some(hist) = data.get(&labels) {
            hist.observe(value, &self.bounds);
        } else {
            let hist = HistogramData::new(self.bounds.len() + 1);
            hist.observe(value, &self.bounds);
            data.insert(labels, hist);
        }
    }

    fn start_timer(&self) -> Box<dyn TimerTrait + '_> {
        Box::new(PrometheusTimer {
            histogram: self,
            start: Instant::now(),
            labels: vec![],
        })
    }

    fn start_timer_with_labels(&self, label_pairs: &[(&str, &str)]) -> Box<dyn TimerTrait + '_> {
        Box::new(PrometheusTimer {
            histogram: self,
            start: Instant::now(),
            labels: to_labels(label_pairs),
        })
    }
}

struct PrometheusTimer<'a> {
    histogram: &'a PrometheusHistogram,
    start: Instant,
    labels: Labels,
}

impl TimerTrait for PrometheusTimer<'_> {
    fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    fn stop(self: Box<Self>) {
        let label_pairs: Vec<(&str, &str)> = self
            .labels
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        self.histogram
            .observe_with_labels(self.start.elapsed().as_secs_f64(), &label_pairs);
    }
}

impl Drop for PrometheusTimer<'_> {
    fn drop(&mut self) {
        let label_pairs: Vec<(&str, &str)> = self
            .labels
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        self.histogram
            .observe_with_labels(self.start.elapsed().as_secs_f64(), &label_pairs);
    }
}

/// Prometheus summary implementation.
#[derive(Debug)]
pub struct PrometheusSummary {
    name: String,
    help: String,
    quantiles: Vec<f64>,
    data: RwLock<HashMap<Labels, SummaryData>>,
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
    /// Create a new summary with default quantiles (0.5, 0.9, 0.99).
    pub fn new(name: impl Into<String>, help: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            help: help.into(),
            quantiles: vec![0.5, 0.9, 0.99],
            data: RwLock::new(HashMap::new()),
            max_observations: 1000,
        }
    }

    /// Export in Prometheus text format.
    pub fn export(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("# HELP {} {}\n", self.name, self.help));
        output.push_str(&format!("# TYPE {} summary\n", self.name));

        let data = self.data.read();
        for (labels, summary) in data.iter() {
            let base_labels = format_labels(labels);

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

impl SummaryTrait for PrometheusSummary {
    fn observe(&self, value: f64) {
        self.observe_with_labels(value, &[]);
    }

    fn observe_with_labels(&self, value: f64, label_pairs: &[(&str, &str)]) {
        let labels = to_labels(label_pairs);
        let mut data = self.data.write();
        let summary = data.entry(labels).or_insert_with(SummaryData::new);
        summary.observe(value, self.max_observations);
    }
}

// ============================================================================
// OpenTelemetry Backend Implementation
// ============================================================================

/// OpenTelemetry metrics backend.
///
/// This backend stores metrics in OpenTelemetry's semantic conventions
/// and can export to OTLP JSON format for compatibility with OTel collectors.
#[derive(Debug)]
pub struct OpenTelemetryBackend {
    namespace: String,
    counters: RwLock<HashMap<String, Arc<OtelCounter>>>,
    gauges: RwLock<HashMap<String, Arc<OtelGauge>>>,
    histograms: RwLock<HashMap<String, Arc<OtelHistogram>>>,
    summaries: RwLock<HashMap<String, Arc<OtelSummary>>>,
}

impl OpenTelemetryBackend {
    /// Create a new OpenTelemetry backend.
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            counters: RwLock::new(HashMap::new()),
            gauges: RwLock::new(HashMap::new()),
            histograms: RwLock::new(HashMap::new()),
            summaries: RwLock::new(HashMap::new()),
        }
    }

    fn full_name(&self, name: &str) -> String {
        if self.namespace.is_empty() {
            name.to_string()
        } else {
            format!("{}.{}", self.namespace, name)
        }
    }
}

impl MetricsBackend for OpenTelemetryBackend {
    fn counter(&self, name: &str, help: &str) -> Arc<dyn CounterTrait> {
        let full_name = self.full_name(name);
        let mut counters = self.counters.write();

        if let Some(counter) = counters.get(&full_name) {
            return counter.clone();
        }

        let counter = Arc::new(OtelCounter::new(&full_name, help));
        counters.insert(full_name, counter.clone());
        counter
    }

    fn gauge(&self, name: &str, help: &str) -> Arc<dyn GaugeTrait> {
        let full_name = self.full_name(name);
        let mut gauges = self.gauges.write();

        if let Some(gauge) = gauges.get(&full_name) {
            return gauge.clone();
        }

        let gauge = Arc::new(OtelGauge::new(&full_name, help));
        gauges.insert(full_name, gauge.clone());
        gauge
    }

    fn histogram(&self, name: &str, help: &str) -> Arc<dyn HistogramTrait> {
        self.histogram_with_buckets(name, help, default_latency_buckets())
    }

    fn histogram_with_buckets(
        &self,
        name: &str,
        help: &str,
        buckets: Vec<f64>,
    ) -> Arc<dyn HistogramTrait> {
        let full_name = self.full_name(name);
        let mut histograms = self.histograms.write();

        if let Some(hist) = histograms.get(&full_name) {
            return hist.clone();
        }

        let hist = Arc::new(OtelHistogram::with_buckets(&full_name, help, buckets));
        histograms.insert(full_name, hist.clone());
        hist
    }

    fn summary(&self, name: &str, help: &str) -> Arc<dyn SummaryTrait> {
        let full_name = self.full_name(name);
        let mut summaries = self.summaries.write();

        if let Some(summary) = summaries.get(&full_name) {
            return summary.clone();
        }

        let summary = Arc::new(OtelSummary::new(&full_name, help));
        summaries.insert(full_name, summary.clone());
        summary
    }

    fn export(&self) -> String {
        // Export as OTLP JSON for compatibility
        self.export_otlp_json()
    }

    fn export_otlp_json(&self) -> String {
        let mut metrics = Vec::new();

        // Export counters
        for counter in self.counters.read().values() {
            metrics.push(counter.to_otlp_json());
        }

        // Export gauges
        for gauge in self.gauges.read().values() {
            metrics.push(gauge.to_otlp_json());
        }

        // Export histograms
        for histogram in self.histograms.read().values() {
            metrics.push(histogram.to_otlp_json());
        }

        format!(
            r#"{{"resourceMetrics":[{{"scopeMetrics":[{{"metrics":[{}]}}]}}]}}"#,
            metrics.join(",")
        )
    }

    fn name(&self) -> &'static str {
        "opentelemetry"
    }
}

// OpenTelemetry-specific implementations

/// OpenTelemetry counter implementation.
#[derive(Debug)]
pub struct OtelCounter {
    name: String,
    description: String,
    values: RwLock<HashMap<Labels, AtomicU64>>,
}

impl OtelCounter {
    /// Create a new OpenTelemetry counter.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            values: RwLock::new(HashMap::new()),
        }
    }

    /// Export as OTLP JSON.
    pub fn to_otlp_json(&self) -> String {
        let values = self.values.read();
        let mut data_points = Vec::new();

        for (labels, value) in values.iter() {
            let attrs: Vec<String> = labels
                .iter()
                .map(|(k, v)| format!(r#"{{"key":"{}","value":{{"stringValue":"{}"}}}}"#, k, v))
                .collect();

            data_points.push(format!(
                r#"{{"asInt":"{}","attributes":[{}]}}"#,
                value.load(Ordering::Relaxed),
                attrs.join(",")
            ));
        }

        format!(
            r#"{{"name":"{}","description":"{}","sum":{{"dataPoints":[{}],"isMonotonic":true}}}}"#,
            self.name,
            self.description,
            data_points.join(",")
        )
    }
}

impl CounterTrait for OtelCounter {
    fn inc(&self) {
        self.add(1);
    }

    fn add(&self, value: u64) {
        self.add_with_labels(value, &[]);
    }

    fn inc_with_labels(&self, labels: &[(&str, &str)]) {
        self.add_with_labels(1, labels);
    }

    fn add_with_labels(&self, value: u64, label_pairs: &[(&str, &str)]) {
        let labels = to_labels(label_pairs);
        let mut values = self.values.write();

        if let Some(counter) = values.get(&labels) {
            counter.fetch_add(value, Ordering::Relaxed);
        } else {
            values.insert(labels, AtomicU64::new(value));
        }
    }

    fn get(&self) -> u64 {
        self.get_with_labels(&[])
    }

    fn get_with_labels(&self, label_pairs: &[(&str, &str)]) -> u64 {
        let labels = to_labels(label_pairs);
        let values = self.values.read();
        values
            .get(&labels)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
}

/// OpenTelemetry gauge implementation.
#[derive(Debug)]
pub struct OtelGauge {
    name: String,
    description: String,
    values: RwLock<HashMap<Labels, AtomicI64>>,
}

impl OtelGauge {
    /// Create a new OpenTelemetry gauge.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            values: RwLock::new(HashMap::new()),
        }
    }

    /// Export as OTLP JSON.
    pub fn to_otlp_json(&self) -> String {
        let values = self.values.read();
        let mut data_points = Vec::new();

        for (labels, value) in values.iter() {
            let attrs: Vec<String> = labels
                .iter()
                .map(|(k, v)| format!(r#"{{"key":"{}","value":{{"stringValue":"{}"}}}}"#, k, v))
                .collect();

            data_points.push(format!(
                r#"{{"asInt":"{}","attributes":[{}]}}"#,
                value.load(Ordering::Relaxed),
                attrs.join(",")
            ));
        }

        format!(
            r#"{{"name":"{}","description":"{}","gauge":{{"dataPoints":[{}]}}}}"#,
            self.name,
            self.description,
            data_points.join(",")
        )
    }
}

impl GaugeTrait for OtelGauge {
    fn set(&self, value: i64) {
        self.set_with_labels(value, &[]);
    }

    fn set_with_labels(&self, value: i64, label_pairs: &[(&str, &str)]) {
        let labels = to_labels(label_pairs);
        let mut values = self.values.write();

        if let Some(gauge) = values.get(&labels) {
            gauge.store(value, Ordering::Relaxed);
        } else {
            values.insert(labels, AtomicI64::new(value));
        }
    }

    fn inc(&self) {
        self.add(1);
    }

    fn dec(&self) {
        self.add(-1);
    }

    fn add(&self, value: i64) {
        self.add_with_labels(value, &[]);
    }

    fn add_with_labels(&self, value: i64, label_pairs: &[(&str, &str)]) {
        let labels = to_labels(label_pairs);
        let mut values = self.values.write();

        if let Some(gauge) = values.get(&labels) {
            gauge.fetch_add(value, Ordering::Relaxed);
        } else {
            values.insert(labels, AtomicI64::new(value));
        }
    }

    fn get(&self) -> i64 {
        let values = self.values.read();
        values
            .get(&vec![])
            .map(|g| g.load(Ordering::Relaxed))
            .unwrap_or(0)
    }
}

/// OpenTelemetry histogram implementation.
#[derive(Debug)]
pub struct OtelHistogram {
    name: String,
    description: String,
    bounds: Vec<f64>,
    data: RwLock<HashMap<Labels, OtelHistogramData>>,
}

#[derive(Debug)]
struct OtelHistogramData {
    bucket_counts: Vec<AtomicU64>,
    sum: AtomicU64,
    count: AtomicU64,
    min: AtomicU64,
    max: AtomicU64,
}

impl OtelHistogramData {
    fn new(num_buckets: usize) -> Self {
        Self {
            bucket_counts: (0..=num_buckets).map(|_| AtomicU64::new(0)).collect(),
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
            min: AtomicU64::new(u64::MAX),
            max: AtomicU64::new(0),
        }
    }

    fn observe(&self, value: f64, bounds: &[f64]) {
        let micros = (value * 1_000_000.0) as u64;
        self.sum.fetch_add(micros, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);

        // Update min/max
        self.min.fetch_min(micros, Ordering::Relaxed);
        self.max.fetch_max(micros, Ordering::Relaxed);

        // Find bucket
        let bucket_idx = bounds
            .iter()
            .position(|&b| value <= b)
            .unwrap_or(bounds.len());
        self.bucket_counts[bucket_idx].fetch_add(1, Ordering::Relaxed);
    }
}

impl OtelHistogram {
    /// Create a new histogram with default latency buckets.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self::with_buckets(name, description, default_latency_buckets())
    }

    /// Create with custom buckets.
    pub fn with_buckets(
        name: impl Into<String>,
        description: impl Into<String>,
        buckets: Vec<f64>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            bounds: buckets,
            data: RwLock::new(HashMap::new()),
        }
    }

    /// Export as OTLP JSON.
    pub fn to_otlp_json(&self) -> String {
        let data = self.data.read();
        let mut data_points = Vec::new();

        for (labels, hist) in data.iter() {
            let attrs: Vec<String> = labels
                .iter()
                .map(|(k, v)| format!(r#"{{"key":"{}","value":{{"stringValue":"{}"}}}}"#, k, v))
                .collect();

            let bucket_counts: Vec<String> = hist
                .bucket_counts
                .iter()
                .map(|c| c.load(Ordering::Relaxed).to_string())
                .collect();

            let bounds_json: Vec<String> = self.bounds.iter().map(|b| b.to_string()).collect();

            data_points.push(format!(
                r#"{{"count":"{}","sum":{},"bucketCounts":[{}],"explicitBounds":[{}],"attributes":[{}]}}"#,
                hist.count.load(Ordering::Relaxed),
                hist.sum.load(Ordering::Relaxed) as f64 / 1_000_000.0,
                bucket_counts.join(","),
                bounds_json.join(","),
                attrs.join(",")
            ));
        }

        format!(
            r#"{{"name":"{}","description":"{}","histogram":{{"dataPoints":[{}]}}}}"#,
            self.name,
            self.description,
            data_points.join(",")
        )
    }
}

impl HistogramTrait for OtelHistogram {
    fn observe(&self, value: f64) {
        self.observe_with_labels(value, &[]);
    }

    fn observe_with_labels(&self, value: f64, label_pairs: &[(&str, &str)]) {
        let labels = to_labels(label_pairs);
        let mut data = self.data.write();

        if let Some(hist) = data.get(&labels) {
            hist.observe(value, &self.bounds);
        } else {
            let hist = OtelHistogramData::new(self.bounds.len());
            hist.observe(value, &self.bounds);
            data.insert(labels, hist);
        }
    }

    fn start_timer(&self) -> Box<dyn TimerTrait + '_> {
        Box::new(OtelTimer {
            histogram: self,
            start: Instant::now(),
            labels: vec![],
        })
    }

    fn start_timer_with_labels(&self, label_pairs: &[(&str, &str)]) -> Box<dyn TimerTrait + '_> {
        Box::new(OtelTimer {
            histogram: self,
            start: Instant::now(),
            labels: to_labels(label_pairs),
        })
    }
}

struct OtelTimer<'a> {
    histogram: &'a OtelHistogram,
    start: Instant,
    labels: Labels,
}

impl TimerTrait for OtelTimer<'_> {
    fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    fn stop(self: Box<Self>) {
        // Drop handles this
    }
}

impl Drop for OtelTimer<'_> {
    fn drop(&mut self) {
        let label_pairs: Vec<(&str, &str)> = self
            .labels
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        self.histogram
            .observe_with_labels(self.start.elapsed().as_secs_f64(), &label_pairs);
    }
}

/// OpenTelemetry summary implementation.
#[derive(Debug)]
pub struct OtelSummary {
    name: String,
    description: String,
    quantiles: Vec<f64>,
    data: RwLock<HashMap<Labels, SummaryData>>,
    max_observations: usize,
}

impl OtelSummary {
    /// Create a new summary with default quantiles (0.5, 0.9, 0.99).
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            quantiles: vec![0.5, 0.9, 0.99],
            data: RwLock::new(HashMap::new()),
            max_observations: 1000,
        }
    }
}

impl SummaryTrait for OtelSummary {
    fn observe(&self, value: f64) {
        self.observe_with_labels(value, &[]);
    }

    fn observe_with_labels(&self, value: f64, label_pairs: &[(&str, &str)]) {
        let labels = to_labels(label_pairs);
        let mut data = self.data.write();
        let summary = data.entry(labels).or_insert_with(SummaryData::new);
        summary.observe(value, self.max_observations);
    }
}

// ============================================================================
// Noop Backend Implementation
// ============================================================================

/// No-op metrics backend (metrics discarded).
#[derive(Debug, Default)]
pub struct NoopBackend;

impl NoopBackend {
    /// Create a new no-op backend.
    pub fn new() -> Self {
        Self
    }
}

impl MetricsBackend for NoopBackend {
    fn counter(&self, _name: &str, _help: &str) -> Arc<dyn CounterTrait> {
        Arc::new(NoopCounter)
    }

    fn gauge(&self, _name: &str, _help: &str) -> Arc<dyn GaugeTrait> {
        Arc::new(NoopGauge)
    }

    fn histogram(&self, _name: &str, _help: &str) -> Arc<dyn HistogramTrait> {
        Arc::new(NoopHistogram)
    }

    fn histogram_with_buckets(
        &self,
        _name: &str,
        _help: &str,
        _buckets: Vec<f64>,
    ) -> Arc<dyn HistogramTrait> {
        Arc::new(NoopHistogram)
    }

    fn summary(&self, _name: &str, _help: &str) -> Arc<dyn SummaryTrait> {
        Arc::new(NoopSummary)
    }

    fn export(&self) -> String {
        String::new()
    }

    fn name(&self) -> &'static str {
        "noop"
    }
}

#[derive(Debug)]
struct NoopCounter;

impl CounterTrait for NoopCounter {
    fn inc(&self) {}
    fn add(&self, _: u64) {}
    fn inc_with_labels(&self, _: &[(&str, &str)]) {}
    fn add_with_labels(&self, _: u64, _: &[(&str, &str)]) {}
}

#[derive(Debug)]
struct NoopGauge;

impl GaugeTrait for NoopGauge {
    fn set(&self, _: i64) {}
    fn set_with_labels(&self, _: i64, _: &[(&str, &str)]) {}
    fn inc(&self) {}
    fn dec(&self) {}
    fn add(&self, _: i64) {}
    fn add_with_labels(&self, _: i64, _: &[(&str, &str)]) {}
}

#[derive(Debug)]
struct NoopHistogram;

impl HistogramTrait for NoopHistogram {
    fn observe(&self, _: f64) {}
    fn observe_with_labels(&self, _: f64, _: &[(&str, &str)]) {}
    fn start_timer(&self) -> Box<dyn TimerTrait + '_> {
        Box::new(NoopTimer(Instant::now()))
    }
    fn start_timer_with_labels(&self, _: &[(&str, &str)]) -> Box<dyn TimerTrait + '_> {
        Box::new(NoopTimer(Instant::now()))
    }
}

struct NoopTimer(Instant);

impl TimerTrait for NoopTimer {
    fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }
    fn stop(self: Box<Self>) {}
}

#[derive(Debug)]
struct NoopSummary;

impl SummaryTrait for NoopSummary {
    fn observe(&self, _: f64) {}
    fn observe_with_labels(&self, _: f64, _: &[(&str, &str)]) {}
}

// ============================================================================
// Unified Metrics Interface
// ============================================================================

/// Unified metrics interface supporting multiple backends.
///
/// # Example
///
/// ```rust,ignore
/// use hypertor::observability::{Metrics, MetricsConfig};
///
/// // Prometheus backend
/// let prom_metrics = Metrics::new(MetricsConfig::prometheus("hypertor"));
///
/// // OpenTelemetry backend  
/// let otel_metrics = Metrics::new(MetricsConfig::opentelemetry("hypertor"));
///
/// // Same API for both
/// let counter = prom_metrics.counter("requests_total", "Total requests");
/// counter.inc();
/// ```
pub struct Metrics {
    backend: Arc<dyn MetricsBackend>,
}

impl std::fmt::Debug for Metrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Metrics")
            .field("backend", &self.backend.name())
            .finish()
    }
}

impl Metrics {
    /// Create metrics with the specified configuration.
    pub fn new(config: MetricsConfig) -> Self {
        let backend: Arc<dyn MetricsBackend> = match config.backend {
            Backend::Prometheus => Arc::new(PrometheusBackend::new(&config.namespace)),
            Backend::OpenTelemetry => Arc::new(OpenTelemetryBackend::new(&config.namespace)),
            Backend::Noop => Arc::new(NoopBackend::new()),
        };
        Self { backend }
    }

    /// Create metrics with Prometheus backend.
    pub fn prometheus(namespace: impl Into<String>) -> Self {
        Self::new(MetricsConfig::prometheus(namespace))
    }

    /// Create metrics with OpenTelemetry backend.
    pub fn opentelemetry(namespace: impl Into<String>) -> Self {
        Self::new(MetricsConfig::opentelemetry(namespace))
    }

    /// Create metrics with Noop backend (for testing).
    pub fn noop() -> Self {
        Self::new(MetricsConfig::noop())
    }

    /// Create a counter metric.
    pub fn counter(&self, name: &str, help: &str) -> Arc<dyn CounterTrait> {
        self.backend.counter(name, help)
    }

    /// Create a gauge metric.
    pub fn gauge(&self, name: &str, help: &str) -> Arc<dyn GaugeTrait> {
        self.backend.gauge(name, help)
    }

    /// Create a histogram metric with default buckets.
    pub fn histogram(&self, name: &str, help: &str) -> Arc<dyn HistogramTrait> {
        self.backend.histogram(name, help)
    }

    /// Create a histogram with custom buckets.
    pub fn histogram_with_buckets(
        &self,
        name: &str,
        help: &str,
        buckets: Vec<f64>,
    ) -> Arc<dyn HistogramTrait> {
        self.backend.histogram_with_buckets(name, help, buckets)
    }

    /// Create a histogram with Tor-optimized buckets.
    pub fn tor_histogram(&self, name: &str, help: &str) -> Arc<dyn HistogramTrait> {
        self.backend
            .histogram_with_buckets(name, help, tor_latency_buckets())
    }

    /// Create a summary metric.
    pub fn summary(&self, name: &str, help: &str) -> Arc<dyn SummaryTrait> {
        self.backend.summary(name, help)
    }

    /// Export metrics in the backend's native format.
    pub fn export(&self) -> String {
        self.backend.export()
    }

    /// Export metrics in OTLP JSON format.
    pub fn export_otlp_json(&self) -> String {
        self.backend.export_otlp_json()
    }

    /// Get the backend name.
    pub fn backend_name(&self) -> &'static str {
        self.backend.name()
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::prometheus("hypertor")
    }
}

// ============================================================================
// Pre-defined Tor Metrics (Backend Agnostic)
// ============================================================================

/// Pre-defined metrics for Tor operations.
///
/// Uses the unified backend interface, so works with both Prometheus and OpenTelemetry.
pub struct TorMetrics {
    /// The underlying metrics interface.
    pub metrics: Metrics,

    /// Total HTTP requests made over Tor.
    pub http_requests_total: Arc<dyn CounterTrait>,
    /// HTTP request duration in seconds.
    pub http_request_duration_seconds: Arc<dyn HistogramTrait>,
    /// HTTP request size in bytes.
    pub http_request_size_bytes: Arc<dyn HistogramTrait>,
    /// HTTP response size in bytes.
    pub http_response_size_bytes: Arc<dyn HistogramTrait>,

    /// Total Tor circuits built.
    pub circuit_build_total: Arc<dyn CounterTrait>,
    /// Circuit build duration in seconds.
    pub circuit_build_duration_seconds: Arc<dyn HistogramTrait>,
    /// Number of active Tor circuits.
    pub circuits_active: Arc<dyn GaugeTrait>,
    /// Total circuit build failures.
    pub circuit_failures_total: Arc<dyn CounterTrait>,

    /// Number of active connections.
    pub connections_active: Arc<dyn GaugeTrait>,
    /// Connection pool size.
    pub connection_pool_size: Arc<dyn GaugeTrait>,
    /// Total connection errors.
    pub connection_errors_total: Arc<dyn CounterTrait>,

    /// Total bytes sent over Tor.
    pub bytes_sent_total: Arc<dyn CounterTrait>,
    /// Total bytes received over Tor.
    pub bytes_received_total: Arc<dyn CounterTrait>,

    /// Total requests to onion services.
    pub onion_requests_total: Arc<dyn CounterTrait>,
    /// Onion service response duration in seconds.
    pub onion_response_duration_seconds: Arc<dyn HistogramTrait>,

    /// Total PoW challenges solved.
    pub pow_challenges_solved: Arc<dyn CounterTrait>,
    /// PoW solve duration in seconds.
    pub pow_solve_duration_seconds: Arc<dyn HistogramTrait>,
    /// Total blocked requests.
    pub blocked_requests_total: Arc<dyn CounterTrait>,

    /// Total bridge connections.
    pub bridge_connections_total: Arc<dyn CounterTrait>,
    /// Number of active bridges.
    pub bridge_active: Arc<dyn GaugeTrait>,
}

impl std::fmt::Debug for TorMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TorMetrics")
            .field("backend", &self.metrics.backend_name())
            .finish()
    }
}

impl TorMetrics {
    /// Create with default Prometheus backend.
    pub fn new() -> Self {
        Self::with_config(MetricsConfig::prometheus("hypertor"))
    }

    /// Create with OpenTelemetry backend.
    pub fn opentelemetry() -> Self {
        Self::with_config(MetricsConfig::opentelemetry("hypertor"))
    }

    /// Create with custom configuration.
    pub fn with_config(config: MetricsConfig) -> Self {
        let metrics = Metrics::new(config);

        Self {
            http_requests_total: metrics.counter("http_requests_total", "Total HTTP requests"),
            http_request_duration_seconds: metrics
                .tor_histogram("http_request_duration_seconds", "HTTP request duration"),
            http_request_size_bytes: metrics.histogram_with_buckets(
                "http_request_size_bytes",
                "HTTP request size",
                size_buckets(),
            ),
            http_response_size_bytes: metrics.histogram_with_buckets(
                "http_response_size_bytes",
                "HTTP response size",
                size_buckets(),
            ),

            circuit_build_total: metrics.counter("circuit_build_total", "Total circuit builds"),
            circuit_build_duration_seconds: metrics
                .tor_histogram("circuit_build_duration_seconds", "Circuit build duration"),
            circuits_active: metrics.gauge("circuits_active", "Active circuits"),
            circuit_failures_total: metrics.counter("circuit_failures_total", "Circuit failures"),

            connections_active: metrics.gauge("connections_active", "Active connections"),
            connection_pool_size: metrics.gauge("connection_pool_size", "Connection pool size"),
            connection_errors_total: metrics
                .counter("connection_errors_total", "Connection errors"),

            bytes_sent_total: metrics.counter("bytes_sent_total", "Bytes sent"),
            bytes_received_total: metrics.counter("bytes_received_total", "Bytes received"),

            onion_requests_total: metrics.counter("onion_requests_total", "Onion service requests"),
            onion_response_duration_seconds: metrics
                .tor_histogram("onion_response_duration_seconds", "Onion response duration"),

            pow_challenges_solved: metrics
                .counter("pow_challenges_solved", "PoW challenges solved"),
            pow_solve_duration_seconds: metrics
                .histogram("pow_solve_duration_seconds", "PoW solve duration"),
            blocked_requests_total: metrics.counter("blocked_requests_total", "Blocked requests"),

            bridge_connections_total: metrics
                .counter("bridge_connections_total", "Bridge connections"),
            bridge_active: metrics.gauge("bridge_active", "Active bridge"),

            metrics,
        }
    }

    /// Export all metrics.
    pub fn export(&self) -> String {
        self.metrics.export()
    }

    /// Export in OTLP JSON format.
    pub fn export_otlp_json(&self) -> String {
        self.metrics.export_otlp_json()
    }

    /// Record an HTTP request.
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

    /// Record a circuit build.
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
// Global Instance
// ============================================================================

use std::sync::OnceLock;

static GLOBAL_METRICS: OnceLock<TorMetrics> = OnceLock::new();

/// Get the global metrics instance (Prometheus backend by default).
pub fn global_metrics() -> &'static TorMetrics {
    GLOBAL_METRICS.get_or_init(TorMetrics::new)
}

/// Export global metrics in the backend's native format.
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
    fn test_prometheus_counter() {
        let metrics = Metrics::prometheus("test");
        let counter = metrics.counter("requests_total", "Total requests");

        counter.inc();
        counter.add(5);
        assert_eq!(counter.get(), 6);

        counter.inc_with_labels(&[("method", "GET")]);
        assert_eq!(counter.get_with_labels(&[("method", "GET")]), 1);
    }

    #[test]
    fn test_prometheus_gauge() {
        let metrics = Metrics::prometheus("test");
        let gauge = metrics.gauge("connections", "Active connections");

        gauge.set(10);
        assert_eq!(gauge.get(), 10);

        gauge.inc();
        assert_eq!(gauge.get(), 11);

        gauge.dec();
        assert_eq!(gauge.get(), 10);
    }

    #[test]
    fn test_prometheus_histogram() {
        let metrics = Metrics::prometheus("test");
        let hist = metrics.histogram("latency", "Latency");

        hist.observe(0.1);
        hist.observe(0.5);
        hist.observe(1.0);

        let export = metrics.export();
        assert!(export.contains("test_latency_bucket"));
        assert!(export.contains("test_latency_sum"));
        assert!(export.contains("test_latency_count"));
    }

    #[test]
    fn test_opentelemetry_counter() {
        let metrics = Metrics::opentelemetry("test");
        let counter = metrics.counter("requests_total", "Total requests");

        counter.inc();
        counter.add(5);
        assert_eq!(counter.get(), 6);
    }

    #[test]
    fn test_opentelemetry_export() {
        let metrics = Metrics::opentelemetry("test");
        let counter = metrics.counter("requests", "Requests");
        counter.inc();

        let export = metrics.export();
        assert!(export.contains("resourceMetrics"));
        assert!(export.contains("test.requests"));
    }

    #[test]
    fn test_noop_backend() {
        let metrics = Metrics::noop();
        let counter = metrics.counter("requests", "Requests");

        counter.inc();
        assert_eq!(counter.get(), 0); // Noop always returns 0

        let export = metrics.export();
        assert!(export.is_empty());
    }

    #[test]
    fn test_backend_switching() {
        // Same code works with different backends
        fn record_metrics(metrics: &Metrics) {
            let counter = metrics.counter("test_counter", "Test");
            counter.inc();

            let hist = metrics.histogram("test_hist", "Test");
            hist.observe(0.5);
        }

        // Prometheus
        let prom = Metrics::prometheus("app");
        record_metrics(&prom);
        assert!(prom.export().contains("# TYPE"));

        // OpenTelemetry
        let otel = Metrics::opentelemetry("app");
        record_metrics(&otel);
        assert!(otel.export().contains("resourceMetrics"));

        // Noop
        let noop = Metrics::noop();
        record_metrics(&noop);
        assert!(noop.export().is_empty());
    }

    #[test]
    fn test_tor_metrics_prometheus() {
        let metrics = TorMetrics::new();

        metrics.record_request("GET", 200, 1.5, 100, 5000);
        metrics.record_circuit_build(true, 2.0);
        metrics.circuits_active.set(3);

        let export = metrics.export();
        assert!(export.contains("hypertor_http_requests_total"));
        assert!(export.contains("hypertor_circuits_active"));
    }

    #[test]
    fn test_tor_metrics_opentelemetry() {
        let metrics = TorMetrics::opentelemetry();

        metrics.record_request("GET", 200, 1.5, 100, 5000);

        let export = metrics.export();
        assert!(export.contains("resourceMetrics"));
        assert!(export.contains("hypertor.http_requests_total"));
    }

    #[test]
    fn test_histogram_timer() {
        let metrics = Metrics::prometheus("test");
        let hist = metrics.histogram("duration", "Duration");

        {
            let _timer = hist.start_timer();
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let export = metrics.export();
        assert!(export.contains("test_duration_count 1"));
    }

    #[test]
    fn test_global_metrics() {
        let metrics = global_metrics();
        metrics.http_requests_total.inc();

        let export = export_metrics();
        assert!(export.contains("hypertor_http_requests_total"));
    }
}
