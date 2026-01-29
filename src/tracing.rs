//! Distributed tracing support.
//!
//! Provides request tracing with spans for observability and debugging.
//! Compatible with OpenTelemetry concepts.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use parking_lot::RwLock;

/// Unique trace identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraceId(u64);

impl TraceId {
    /// Generate a new trace ID.
    pub fn generate() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        // Mix in timestamp for better distribution
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        Self(id ^ (now & 0xFFFF_FFFF_0000_0000))
    }

    /// Create from a raw value.
    pub fn from_raw(value: u64) -> Self {
        Self(value)
    }

    /// Get the raw value.
    pub fn as_raw(&self) -> u64 {
        self.0
    }

    /// Convert to hex string for propagation.
    pub fn to_hex(&self) -> String {
        format!("{:016x}", self.0)
    }

    /// Parse from hex string.
    pub fn from_hex(s: &str) -> Option<Self> {
        u64::from_str_radix(s, 16).ok().map(Self)
    }
}

impl std::fmt::Display for TraceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// Unique span identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SpanId(u64);

impl SpanId {
    /// Generate a new span ID.
    pub fn generate() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    /// Create from a raw value.
    pub fn from_raw(value: u64) -> Self {
        Self(value)
    }

    /// Get the raw value.
    pub fn as_raw(&self) -> u64 {
        self.0
    }

    /// Convert to hex string.
    pub fn to_hex(&self) -> String {
        format!("{:016x}", self.0)
    }
}

impl std::fmt::Display for SpanId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

/// Span status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanStatus {
    /// Span completed successfully
    Ok,
    /// Span completed with an error
    Error,
    /// Span is still in progress
    InProgress,
    /// Span was cancelled
    Cancelled,
}

/// Span kind (type of operation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpanKind {
    /// Internal operation
    #[default]
    Internal,
    /// Outgoing request (client)
    Client,
    /// Incoming request (server)
    Server,
    /// Async producer
    Producer,
    /// Async consumer
    Consumer,
}

/// A span representing a unit of work.
#[derive(Debug)]
pub struct Span {
    /// Trace this span belongs to
    pub trace_id: TraceId,
    /// Unique span identifier
    pub span_id: SpanId,
    /// Parent span (if any)
    pub parent_id: Option<SpanId>,
    /// Operation name
    pub name: String,
    /// Span kind
    pub kind: SpanKind,
    /// Start time
    pub start_time: Instant,
    /// End time (if finished)
    pub end_time: Option<Instant>,
    /// Status
    pub status: SpanStatus,
    /// Attributes/tags
    pub attributes: HashMap<String, AttributeValue>,
    /// Events/logs
    pub events: Vec<SpanEvent>,
}

impl Span {
    /// Create a new span.
    pub fn new(trace_id: TraceId, name: impl Into<String>) -> Self {
        Self {
            trace_id,
            span_id: SpanId::generate(),
            parent_id: None,
            name: name.into(),
            kind: SpanKind::default(),
            start_time: Instant::now(),
            end_time: None,
            status: SpanStatus::InProgress,
            attributes: HashMap::new(),
            events: Vec::new(),
        }
    }

    /// Create a child span.
    pub fn child(&self, name: impl Into<String>) -> Self {
        Self {
            trace_id: self.trace_id,
            span_id: SpanId::generate(),
            parent_id: Some(self.span_id),
            name: name.into(),
            kind: SpanKind::default(),
            start_time: Instant::now(),
            end_time: None,
            status: SpanStatus::InProgress,
            attributes: HashMap::new(),
            events: Vec::new(),
        }
    }

    /// Set the span kind.
    #[must_use]
    pub fn with_kind(mut self, kind: SpanKind) -> Self {
        self.kind = kind;
        self
    }

    /// Set an attribute.
    pub fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<AttributeValue>) {
        self.attributes.insert(key.into(), value.into());
    }

    /// Add an event.
    pub fn add_event(&mut self, name: impl Into<String>) {
        self.events.push(SpanEvent {
            name: name.into(),
            timestamp: Instant::now(),
            attributes: HashMap::new(),
        });
    }

    /// Add an event with attributes.
    pub fn add_event_with_attrs(
        &mut self,
        name: impl Into<String>,
        attrs: HashMap<String, AttributeValue>,
    ) {
        self.events.push(SpanEvent {
            name: name.into(),
            timestamp: Instant::now(),
            attributes: attrs,
        });
    }

    /// Record an error.
    pub fn record_error(&mut self, error: &str) {
        self.status = SpanStatus::Error;
        self.set_attribute("error", true);
        self.set_attribute("error.message", error.to_string());
        self.add_event("exception");
    }

    /// Mark span as successful.
    pub fn set_ok(&mut self) {
        self.status = SpanStatus::Ok;
    }

    /// End the span.
    pub fn end(&mut self) {
        self.end_time = Some(Instant::now());
        if self.status == SpanStatus::InProgress {
            self.status = SpanStatus::Ok;
        }
    }

    /// Get span duration.
    pub fn duration(&self) -> Duration {
        match self.end_time {
            Some(end) => end.duration_since(self.start_time),
            None => self.start_time.elapsed(),
        }
    }

    /// Check if span is still active.
    pub fn is_active(&self) -> bool {
        self.end_time.is_none()
    }
}

/// Attribute value types.
#[derive(Debug, Clone, PartialEq)]
pub enum AttributeValue {
    /// String value
    String(String),
    /// Integer value
    Int(i64),
    /// Float value
    Float(f64),
    /// Boolean value
    Bool(bool),
    /// String array
    StringArray(Vec<String>),
}

impl From<&str> for AttributeValue {
    fn from(s: &str) -> Self {
        Self::String(s.to_string())
    }
}

impl From<String> for AttributeValue {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<i64> for AttributeValue {
    fn from(i: i64) -> Self {
        Self::Int(i)
    }
}

impl From<i32> for AttributeValue {
    fn from(i: i32) -> Self {
        Self::Int(i64::from(i))
    }
}

impl From<f64> for AttributeValue {
    fn from(f: f64) -> Self {
        Self::Float(f)
    }
}

impl From<bool> for AttributeValue {
    fn from(b: bool) -> Self {
        Self::Bool(b)
    }
}

/// Event within a span.
#[derive(Debug, Clone)]
pub struct SpanEvent {
    /// Event name
    pub name: String,
    /// When the event occurred
    pub timestamp: Instant,
    /// Event attributes
    pub attributes: HashMap<String, AttributeValue>,
}

/// Trace context for propagation.
#[derive(Debug, Clone)]
pub struct TraceContext {
    /// Trace identifier
    pub trace_id: TraceId,
    /// Current span identifier
    pub span_id: SpanId,
    /// Trace flags (sampling, etc.)
    pub flags: u8,
}

impl TraceContext {
    /// Create a new trace context.
    pub fn new(trace_id: TraceId, span_id: SpanId) -> Self {
        Self {
            trace_id,
            span_id,
            flags: 0x01, // Sampled by default
        }
    }

    /// Check if the trace is sampled.
    pub fn is_sampled(&self) -> bool {
        (self.flags & 0x01) != 0
    }

    /// Format for W3C traceparent header.
    pub fn to_traceparent(&self) -> String {
        format!(
            "00-{:032x}-{:016x}-{:02x}",
            self.trace_id.0 as u128, self.span_id.0, self.flags
        )
    }

    /// Parse from W3C traceparent header.
    pub fn from_traceparent(header: &str) -> Option<Self> {
        let parts: Vec<&str> = header.split('-').collect();
        if parts.len() != 4 || parts[0] != "00" {
            return None;
        }

        let trace_id = u128::from_str_radix(parts[1], 16).ok()? as u64;
        let span_id = u64::from_str_radix(parts[2], 16).ok()?;
        let flags = u8::from_str_radix(parts[3], 16).ok()?;

        Some(Self {
            trace_id: TraceId(trace_id),
            span_id: SpanId(span_id),
            flags,
        })
    }
}

/// Request tracer for collecting spans.
#[derive(Debug, Default)]
pub struct Tracer {
    spans: Arc<RwLock<Vec<Span>>>,
    active_traces: Arc<RwLock<HashMap<TraceId, Vec<SpanId>>>>,
}

impl Tracer {
    /// Create a new tracer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a new trace.
    pub fn start_trace(&self, name: impl Into<String>) -> Span {
        let trace_id = TraceId::generate();
        let span = Span::new(trace_id, name).with_kind(SpanKind::Client);

        let mut active = self.active_traces.write();
        active.entry(trace_id).or_default().push(span.span_id);

        span
    }

    /// Start a span with an existing trace context.
    pub fn start_span(&self, ctx: &TraceContext, name: impl Into<String>) -> Span {
        let mut span = Span::new(ctx.trace_id, name);
        span.parent_id = Some(ctx.span_id);

        let mut active = self.active_traces.write();
        active.entry(ctx.trace_id).or_default().push(span.span_id);

        span
    }

    /// End and record a span.
    pub fn end_span(&self, mut span: Span) {
        span.end();

        // Remove from active
        let mut active = self.active_traces.write();
        if let Some(spans) = active.get_mut(&span.trace_id) {
            spans.retain(|&id| id != span.span_id);
            if spans.is_empty() {
                active.remove(&span.trace_id);
            }
        }

        // Store completed span
        self.spans.write().push(span);
    }

    /// Get all completed spans.
    pub fn get_spans(&self) -> Vec<Span> {
        // Can't clone Span easily, so return count for now
        let spans = self.spans.read();
        spans
            .iter()
            .map(|s| Span {
                trace_id: s.trace_id,
                span_id: s.span_id,
                parent_id: s.parent_id,
                name: s.name.clone(),
                kind: s.kind,
                start_time: s.start_time,
                end_time: s.end_time,
                status: s.status,
                attributes: s.attributes.clone(),
                events: s.events.clone(),
            })
            .collect()
    }

    /// Get span count.
    pub fn span_count(&self) -> usize {
        self.spans.read().len()
    }

    /// Clear all spans.
    pub fn clear(&self) {
        self.spans.write().clear();
    }

    /// Get active trace count.
    pub fn active_trace_count(&self) -> usize {
        self.active_traces.read().len()
    }
}

/// HTTP-specific span attributes.
pub mod http {
    use super::*;

    /// Set standard HTTP request attributes.
    pub fn set_request_attrs(span: &mut Span, method: &str, url: &str, host: &str) {
        span.set_attribute("http.method", method.to_string());
        span.set_attribute("http.url", url.to_string());
        span.set_attribute("http.host", host.to_string());
        span.set_attribute(
            "http.scheme",
            if url.starts_with("https") {
                "https"
            } else {
                "http"
            },
        );
    }

    /// Set standard HTTP response attributes.
    pub fn set_response_attrs(span: &mut Span, status_code: u16, content_length: Option<u64>) {
        span.set_attribute("http.status_code", i64::from(status_code));
        if let Some(len) = content_length {
            span.set_attribute("http.response_content_length", len as i64);
        }
        if status_code >= 400 {
            span.status = SpanStatus::Error;
        }
    }

    /// Set Tor-specific attributes.
    pub fn set_tor_attrs(span: &mut Span, circuit_id: Option<&str>, is_onion: bool) {
        span.set_attribute("tor.is_onion", is_onion);
        if let Some(id) = circuit_id {
            span.set_attribute("tor.circuit_id", id.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_trace_id() {
        let id1 = TraceId::generate();
        let id2 = TraceId::generate();
        assert_ne!(id1, id2);

        let hex = id1.to_hex();
        let parsed = TraceId::from_hex(&hex).unwrap();
        assert_eq!(id1, parsed);
    }

    #[test]
    fn test_span() {
        let trace_id = TraceId::generate();
        let mut span = Span::new(trace_id, "test_operation");
        span.set_attribute("key", "value");
        span.add_event("started");

        assert!(span.is_active());
        span.end();
        assert!(!span.is_active());
        assert_eq!(span.status, SpanStatus::Ok);
    }

    #[test]
    fn test_child_span() {
        let trace_id = TraceId::generate();
        let parent = Span::new(trace_id, "parent");
        let child = parent.child("child");

        assert_eq!(child.trace_id, parent.trace_id);
        assert_eq!(child.parent_id, Some(parent.span_id));
    }

    #[test]
    fn test_trace_context() {
        let ctx = TraceContext::new(TraceId::generate(), SpanId::generate());
        let header = ctx.to_traceparent();
        let parsed = TraceContext::from_traceparent(&header).unwrap();

        assert_eq!(ctx.trace_id, parsed.trace_id);
        assert_eq!(ctx.span_id, parsed.span_id);
    }

    #[test]
    fn test_tracer() {
        let tracer = Tracer::new();

        let span = tracer.start_trace("request");
        assert_eq!(tracer.active_trace_count(), 1);

        tracer.end_span(span);
        assert_eq!(tracer.active_trace_count(), 0);
        assert_eq!(tracer.span_count(), 1);
    }
}
