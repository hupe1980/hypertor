//! Request hooks and interceptors.
//!
//! Provides a powerful system for intercepting and modifying requests
//! and responses at various stages of the request lifecycle.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri};

use crate::error::Result;

/// Request context passed to hooks.
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// Request method
    pub method: Method,
    /// Request URI
    pub uri: Uri,
    /// Request headers (mutable in pre-request hooks)
    pub headers: HeaderMap,
    /// Request body (if any)
    pub body: Option<Bytes>,
    /// Timestamp when request was initiated
    pub started_at: Instant,
    /// Custom metadata for passing data between hooks
    pub metadata: Metadata,
}

impl RequestContext {
    /// Create a new request context.
    pub fn new(method: Method, uri: Uri) -> Self {
        Self {
            method,
            uri,
            headers: HeaderMap::new(),
            body: None,
            started_at: Instant::now(),
            metadata: Metadata::new(),
        }
    }

    /// Get elapsed time since request started.
    pub fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }
}

/// Response context passed to hooks.
#[derive(Debug, Clone)]
pub struct ResponseContext {
    /// Response status code
    pub status: StatusCode,
    /// Response headers
    pub headers: HeaderMap,
    /// Response body size (if known)
    pub body_size: Option<usize>,
    /// Time taken for the request
    pub duration: Duration,
    /// The original request context
    pub request: RequestContext,
}

/// Error context passed to error hooks.
#[derive(Debug)]
pub struct ErrorContext {
    /// The error that occurred
    pub error: crate::error::Error,
    /// The original request context
    pub request: RequestContext,
    /// Time elapsed when error occurred
    pub duration: Duration,
    /// Whether the request should be retried
    pub should_retry: bool,
}

/// Custom metadata storage for hooks to share data.
#[derive(Debug, Clone, Default)]
pub struct Metadata {
    entries: Vec<(String, String)>,
}

impl Metadata {
    /// Create empty metadata.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a metadata value.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        let key = key.into();
        // Update existing or insert new
        if let Some(entry) = self.entries.iter_mut().find(|(k, _)| k == &key) {
            entry.1 = value.into();
        } else {
            self.entries.push((key, value.into()));
        }
    }

    /// Get a metadata value.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Check if a key exists.
    pub fn contains(&self, key: &str) -> bool {
        self.entries.iter().any(|(k, _)| k == key)
    }

    /// Remove a metadata value.
    pub fn remove(&mut self, key: &str) -> Option<String> {
        if let Some(idx) = self.entries.iter().position(|(k, _)| k == key) {
            Some(self.entries.remove(idx).1)
        } else {
            None
        }
    }
}

/// Type alias for async hook futures.
pub type HookFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// Hook that runs before a request is sent.
pub trait PreRequestHook: Send + Sync {
    /// Called before the request is sent.
    ///
    /// Can modify the request context (headers, body, etc.).
    /// Return `Ok(())` to continue, `Err` to abort the request.
    fn on_request(&self, ctx: &mut RequestContext) -> Result<()>;
}

/// Hook that runs after a successful response.
pub trait PostResponseHook: Send + Sync {
    /// Called after a successful response is received.
    fn on_response(&self, ctx: &ResponseContext);
}

/// Hook that runs when an error occurs.
pub trait ErrorHook: Send + Sync {
    /// Called when an error occurs.
    ///
    /// Can set `ctx.should_retry = true` to signal retry.
    fn on_error(&self, ctx: &mut ErrorContext);
}

/// Async version of pre-request hook.
pub trait AsyncPreRequestHook: Send + Sync {
    /// Called before the request is sent (async).
    fn on_request(&self, ctx: &mut RequestContext) -> HookFuture<Result<()>>;
}

/// Collection of hooks for a client.
#[derive(Default)]
pub struct Hooks {
    pre_request: Vec<Arc<dyn PreRequestHook>>,
    post_response: Vec<Arc<dyn PostResponseHook>>,
    error: Vec<Arc<dyn ErrorHook>>,
}

impl Hooks {
    /// Create an empty hook collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a pre-request hook.
    pub fn add_pre_request(&mut self, hook: impl PreRequestHook + 'static) {
        self.pre_request.push(Arc::new(hook));
    }

    /// Add a post-response hook.
    pub fn add_post_response(&mut self, hook: impl PostResponseHook + 'static) {
        self.post_response.push(Arc::new(hook));
    }

    /// Add an error hook.
    pub fn add_error(&mut self, hook: impl ErrorHook + 'static) {
        self.error.push(Arc::new(hook));
    }

    /// Run all pre-request hooks.
    pub fn run_pre_request(&self, ctx: &mut RequestContext) -> Result<()> {
        for hook in &self.pre_request {
            hook.on_request(ctx)?;
        }
        Ok(())
    }

    /// Run all post-response hooks.
    pub fn run_post_response(&self, ctx: &ResponseContext) {
        for hook in &self.post_response {
            hook.on_response(ctx);
        }
    }

    /// Run all error hooks.
    pub fn run_error(&self, ctx: &mut ErrorContext) {
        for hook in &self.error {
            hook.on_error(ctx);
        }
    }

    /// Check if there are any hooks registered.
    pub fn is_empty(&self) -> bool {
        self.pre_request.is_empty() && self.post_response.is_empty() && self.error.is_empty()
    }
}

// ============================================================================
// Built-in Hooks
// ============================================================================

/// Hook that logs all requests.
#[derive(Debug, Default)]
pub struct LoggingHook {
    log_headers: bool,
    log_body: bool,
}

impl LoggingHook {
    /// Create a new logging hook.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable header logging.
    #[must_use]
    pub fn with_headers(mut self) -> Self {
        self.log_headers = true;
        self
    }

    /// Enable body logging.
    #[must_use]
    pub fn with_body(mut self) -> Self {
        self.log_body = true;
        self
    }
}

impl PreRequestHook for LoggingHook {
    fn on_request(&self, ctx: &mut RequestContext) -> Result<()> {
        tracing::info!(
            method = %ctx.method,
            uri = %ctx.uri,
            "Starting request"
        );
        if self.log_headers {
            tracing::debug!(headers = ?ctx.headers, "Request headers");
        }
        Ok(())
    }
}

impl PostResponseHook for LoggingHook {
    fn on_response(&self, ctx: &ResponseContext) {
        tracing::info!(
            method = %ctx.request.method,
            uri = %ctx.request.uri,
            status = %ctx.status,
            duration_ms = ctx.duration.as_millis(),
            "Request completed"
        );
    }
}

impl ErrorHook for LoggingHook {
    fn on_error(&self, ctx: &mut ErrorContext) {
        tracing::error!(
            method = %ctx.request.method,
            uri = %ctx.request.uri,
            error = %ctx.error,
            duration_ms = ctx.duration.as_millis(),
            "Request failed"
        );
    }
}

/// Hook that adds custom headers to all requests.
#[derive(Debug, Clone)]
pub struct HeaderInjector {
    headers: HeaderMap,
}

impl HeaderInjector {
    /// Create a new header injector.
    pub fn new() -> Self {
        Self {
            headers: HeaderMap::new(),
        }
    }

    /// Add a header to inject.
    pub fn add(mut self, name: http::header::HeaderName, value: http::header::HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }
}

impl Default for HeaderInjector {
    fn default() -> Self {
        Self::new()
    }
}

impl PreRequestHook for HeaderInjector {
    fn on_request(&self, ctx: &mut RequestContext) -> Result<()> {
        for (name, value) in &self.headers {
            ctx.headers.insert(name.clone(), value.clone());
        }
        Ok(())
    }
}

/// Hook that tracks request metrics.
#[derive(Debug, Default)]
pub struct MetricsHook {
    // In a real implementation, this would integrate with a metrics system
    // like prometheus or opentelemetry
}

impl MetricsHook {
    /// Create a new metrics hook.
    pub fn new() -> Self {
        Self::default()
    }
}

impl PostResponseHook for MetricsHook {
    fn on_response(&self, ctx: &ResponseContext) {
        // Record metrics
        let labels = [
            ("method", ctx.request.method.as_str()),
            ("status", ctx.status.as_str()),
        ];

        tracing::trace!(
            labels = ?labels,
            duration_ms = ctx.duration.as_millis(),
            body_size = ctx.body_size,
            "Recording metrics"
        );
    }
}

impl ErrorHook for MetricsHook {
    fn on_error(&self, ctx: &mut ErrorContext) {
        tracing::trace!(
            method = %ctx.request.method,
            error = %ctx.error,
            "Recording error metric"
        );
    }
}

/// Hook that enforces rate limiting by aborting requests.
#[derive(Debug)]
pub struct RateLimitHook {
    domain_pattern: Option<String>,
}

impl RateLimitHook {
    /// Create a rate limit hook for all domains.
    pub fn new() -> Self {
        Self {
            domain_pattern: None,
        }
    }

    /// Create a rate limit hook for a specific domain pattern.
    pub fn for_domain(pattern: impl Into<String>) -> Self {
        Self {
            domain_pattern: Some(pattern.into()),
        }
    }

    fn matches_domain(&self, uri: &Uri) -> bool {
        match (&self.domain_pattern, uri.host()) {
            (Some(pattern), Some(host)) => host.contains(pattern.as_str()),
            (None, _) => true,
            (_, None) => false,
        }
    }
}

impl Default for RateLimitHook {
    fn default() -> Self {
        Self::new()
    }
}

impl PreRequestHook for RateLimitHook {
    fn on_request(&self, ctx: &mut RequestContext) -> Result<()> {
        if self.matches_domain(&ctx.uri) {
            // In a real implementation, this would check actual rate limits
            // and potentially return an error or delay
            ctx.metadata.set("rate_limited_check", "true");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use http::Method;

    #[test]
    fn test_metadata() {
        let mut meta = Metadata::new();
        meta.set("key1", "value1");
        meta.set("key2", "value2");

        assert_eq!(meta.get("key1"), Some("value1"));
        assert!(meta.contains("key2"));
        assert!(!meta.contains("key3"));

        meta.remove("key1");
        assert!(!meta.contains("key1"));
    }

    #[test]
    fn test_request_context() {
        let ctx = RequestContext::new(Method::GET, "https://example.com".parse().unwrap());

        assert_eq!(ctx.method, Method::GET);
        assert!(ctx.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn test_hooks_chain() {
        let mut hooks = Hooks::new();
        hooks.add_pre_request(LoggingHook::new());
        hooks.add_pre_request(HeaderInjector::new());

        let mut ctx = RequestContext::new(Method::GET, "https://example.com".parse().unwrap());

        // Should run without error
        hooks.run_pre_request(&mut ctx).unwrap();
    }

    #[test]
    fn test_header_injector() {
        let injector = HeaderInjector::new().add(
            http::header::ACCEPT,
            http::header::HeaderValue::from_static("application/json"),
        );

        let mut ctx = RequestContext::new(Method::GET, "https://example.com".parse().unwrap());

        injector.on_request(&mut ctx).unwrap();
        assert!(ctx.headers.contains_key(http::header::ACCEPT));
    }
}
