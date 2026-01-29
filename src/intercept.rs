//! HTTP Interception API (MITM Proxy).
//!
//! Provides Burp Suite-like request/response interception capabilities
//! for security testing and traffic analysis over Tor.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, Version, header::HeaderName};
use parking_lot::{Mutex, RwLock};

/// Unique identifier for intercepted requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InterceptId(pub u64);

impl std::fmt::Display for InterceptId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "intercept-{}", self.0)
    }
}

/// Interception configuration.
#[derive(Debug, Clone)]
pub struct InterceptConfig {
    /// Enable request interception
    pub intercept_requests: bool,
    /// Enable response interception
    pub intercept_responses: bool,
    /// Maximum body size to capture (0 = unlimited)
    pub max_body_size: usize,
    /// URL patterns to intercept (regex)
    pub url_patterns: Vec<String>,
    /// Methods to intercept (empty = all)
    pub methods: Vec<Method>,
    /// Enable SSL/TLS interception
    pub intercept_tls: bool,
    /// Log all traffic
    pub log_traffic: bool,
}

impl Default for InterceptConfig {
    fn default() -> Self {
        Self {
            intercept_requests: true,
            intercept_responses: true,
            max_body_size: 10 * 1024 * 1024, // 10MB
            url_patterns: Vec::new(),
            methods: Vec::new(),
            intercept_tls: true,
            log_traffic: false,
        }
    }
}

impl InterceptConfig {
    /// Create a new configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable request interception.
    #[must_use]
    pub fn with_request_intercept(mut self, enabled: bool) -> Self {
        self.intercept_requests = enabled;
        self
    }

    /// Enable response interception.
    #[must_use]
    pub fn with_response_intercept(mut self, enabled: bool) -> Self {
        self.intercept_responses = enabled;
        self
    }

    /// Add URL pattern to intercept.
    #[must_use]
    pub fn with_url_pattern(mut self, pattern: &str) -> Self {
        self.url_patterns.push(pattern.to_string());
        self
    }

    /// Add method to intercept.
    #[must_use]
    pub fn with_method(mut self, method: Method) -> Self {
        self.methods.push(method);
        self
    }

    /// Create a passive configuration (logging only).
    pub fn passive() -> Self {
        Self {
            intercept_requests: false,
            intercept_responses: false,
            max_body_size: 10 * 1024 * 1024,
            url_patterns: Vec::new(),
            methods: Vec::new(),
            intercept_tls: false,
            log_traffic: true,
        }
    }

    /// Create an active configuration (full interception).
    pub fn active() -> Self {
        Self {
            intercept_requests: true,
            intercept_responses: true,
            max_body_size: 50 * 1024 * 1024,
            url_patterns: Vec::new(),
            methods: Vec::new(),
            intercept_tls: true,
            log_traffic: true,
        }
    }
}

/// An intercepted HTTP request.
#[derive(Debug, Clone)]
pub struct InterceptedRequest {
    /// Unique identifier
    pub id: InterceptId,
    /// HTTP method
    pub method: Method,
    /// Request URI
    pub uri: Uri,
    /// HTTP version
    pub version: Version,
    /// Request headers
    pub headers: HeaderMap,
    /// Request body
    pub body: Vec<u8>,
    /// Timestamp
    pub timestamp: Instant,
    /// Client address (if known)
    pub client_addr: Option<String>,
    /// Was TLS used
    pub is_tls: bool,
}

impl InterceptedRequest {
    /// Create a new intercepted request.
    pub fn new(id: InterceptId, method: Method, uri: Uri) -> Self {
        Self {
            id,
            method,
            uri,
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
            body: Vec::new(),
            timestamp: Instant::now(),
            client_addr: None,
            is_tls: false,
        }
    }

    /// Set HTTP version.
    #[must_use]
    pub fn with_version(mut self, version: Version) -> Self {
        self.version = version;
        self
    }

    /// Set headers.
    #[must_use]
    pub fn with_headers(mut self, headers: HeaderMap) -> Self {
        self.headers = headers;
        self
    }

    /// Set body.
    #[must_use]
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Get header value.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// Get body as string.
    pub fn body_text(&self) -> Option<String> {
        String::from_utf8(self.body.clone()).ok()
    }

    /// Get content type.
    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }

    /// Check if body is JSON.
    pub fn is_json(&self) -> bool {
        self.content_type()
            .map(|ct| ct.contains("application/json"))
            .unwrap_or(false)
    }

    /// Get host from URI or headers.
    pub fn host(&self) -> Option<String> {
        self.uri
            .host()
            .map(String::from)
            .or_else(|| self.header("host").map(String::from))
    }
}

/// An intercepted HTTP response.
#[derive(Debug, Clone)]
pub struct InterceptedResponse {
    /// Request ID this responds to
    pub request_id: InterceptId,
    /// HTTP status code
    pub status: StatusCode,
    /// HTTP version
    pub version: Version,
    /// Response headers
    pub headers: HeaderMap,
    /// Response body
    pub body: Vec<u8>,
    /// Timestamp
    pub timestamp: Instant,
    /// Response time (from request)
    pub response_time: std::time::Duration,
}

impl InterceptedResponse {
    /// Create a new intercepted response.
    pub fn new(
        request_id: InterceptId,
        status: StatusCode,
        response_time: std::time::Duration,
    ) -> Self {
        Self {
            request_id,
            status,
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
            body: Vec::new(),
            timestamp: Instant::now(),
            response_time,
        }
    }

    /// Set headers.
    #[must_use]
    pub fn with_headers(mut self, headers: HeaderMap) -> Self {
        self.headers = headers;
        self
    }

    /// Set body.
    #[must_use]
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Get header value.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// Get body as string.
    pub fn body_text(&self) -> Option<String> {
        String::from_utf8(self.body.clone()).ok()
    }

    /// Check if response indicates success.
    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }
}

/// Action to take on intercepted request.
#[derive(Debug, Clone)]
pub enum RequestAction {
    /// Forward request as-is
    Forward,
    /// Forward with modifications
    Modify(ModifiedRequest),
    /// Drop the request
    Drop,
    /// Respond immediately without forwarding
    Respond(InterceptedResponse),
}

/// Action to take on intercepted response.
#[derive(Debug, Clone)]
pub enum ResponseAction {
    /// Forward response as-is
    Forward,
    /// Forward with modifications
    Modify(ModifiedResponse),
    /// Drop the response
    Drop,
}

/// Modified request data.
#[derive(Debug, Clone)]
pub struct ModifiedRequest {
    /// New method (optional)
    pub method: Option<Method>,
    /// New URI (optional)
    pub uri: Option<Uri>,
    /// Headers to add/replace
    pub set_headers: HashMap<String, String>,
    /// Headers to remove
    pub remove_headers: Vec<String>,
    /// New body (optional)
    pub body: Option<Vec<u8>>,
}

impl ModifiedRequest {
    /// Create empty modification.
    pub fn new() -> Self {
        Self {
            method: None,
            uri: None,
            set_headers: HashMap::new(),
            remove_headers: Vec::new(),
            body: None,
        }
    }

    /// Set new method.
    #[must_use]
    pub fn with_method(mut self, method: Method) -> Self {
        self.method = Some(method);
        self
    }

    /// Set new URI.
    #[must_use]
    pub fn with_uri(mut self, uri: Uri) -> Self {
        self.uri = Some(uri);
        self
    }

    /// Set header.
    #[must_use]
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.set_headers.insert(name.to_string(), value.to_string());
        self
    }

    /// Remove header.
    #[must_use]
    pub fn without_header(mut self, name: &str) -> Self {
        self.remove_headers.push(name.to_string());
        self
    }

    /// Set new body.
    #[must_use]
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    /// Apply modifications to request.
    pub fn apply(&self, mut request: InterceptedRequest) -> InterceptedRequest {
        if let Some(method) = &self.method {
            request.method = method.clone();
        }
        if let Some(uri) = &self.uri {
            request.uri = uri.clone();
        }
        for name in &self.remove_headers {
            if let Ok(header_name) = HeaderName::try_from(name.as_str()) {
                request.headers.remove(&header_name);
            }
        }
        for (name, value) in &self.set_headers {
            if let (Ok(header_name), Ok(header_value)) = (
                HeaderName::try_from(name.as_str()),
                HeaderValue::try_from(value.as_str()),
            ) {
                request.headers.insert(header_name, header_value);
            }
        }
        if let Some(body) = &self.body {
            request.body = body.clone();
        }
        request
    }
}

impl Default for ModifiedRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// Modified response data.
#[derive(Debug, Clone)]
pub struct ModifiedResponse {
    /// New status code (optional)
    pub status: Option<StatusCode>,
    /// Headers to add/replace
    pub set_headers: HashMap<String, String>,
    /// Headers to remove
    pub remove_headers: Vec<String>,
    /// New body (optional)
    pub body: Option<Vec<u8>>,
}

impl ModifiedResponse {
    /// Create empty modification.
    pub fn new() -> Self {
        Self {
            status: None,
            set_headers: HashMap::new(),
            remove_headers: Vec::new(),
            body: None,
        }
    }

    /// Set new status.
    #[must_use]
    pub fn with_status(mut self, status: StatusCode) -> Self {
        self.status = Some(status);
        self
    }

    /// Set header.
    #[must_use]
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.set_headers.insert(name.to_string(), value.to_string());
        self
    }

    /// Remove header.
    #[must_use]
    pub fn without_header(mut self, name: &str) -> Self {
        self.remove_headers.push(name.to_string());
        self
    }

    /// Set new body.
    #[must_use]
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    /// Apply modifications to response.
    pub fn apply(&self, mut response: InterceptedResponse) -> InterceptedResponse {
        if let Some(status) = &self.status {
            response.status = *status;
        }
        for name in &self.remove_headers {
            if let Ok(header_name) = HeaderName::try_from(name.as_str()) {
                response.headers.remove(&header_name);
            }
        }
        for (name, value) in &self.set_headers {
            if let (Ok(header_name), Ok(header_value)) = (
                HeaderName::try_from(name.as_str()),
                HeaderValue::try_from(value.as_str()),
            ) {
                response.headers.insert(header_name, header_value);
            }
        }
        if let Some(body) = &self.body {
            response.body = body.clone();
        }
        response
    }
}

impl Default for ModifiedResponse {
    fn default() -> Self {
        Self::new()
    }
}

/// Request interceptor trait.
pub trait RequestInterceptor: Send + Sync {
    /// Called when a request is intercepted.
    fn intercept(&self, request: &InterceptedRequest) -> RequestAction;
}

/// Response interceptor trait.
pub trait ResponseInterceptor: Send + Sync {
    /// Called when a response is intercepted.
    fn intercept(
        &self,
        request: &InterceptedRequest,
        response: &InterceptedResponse,
    ) -> ResponseAction;
}

/// Function-based request interceptor.
pub struct FnRequestInterceptor<F>
where
    F: Fn(&InterceptedRequest) -> RequestAction + Send + Sync,
{
    f: F,
}

impl<F> FnRequestInterceptor<F>
where
    F: Fn(&InterceptedRequest) -> RequestAction + Send + Sync,
{
    /// Create a new function interceptor.
    pub fn new(f: F) -> Self {
        Self { f }
    }
}

impl<F> RequestInterceptor for FnRequestInterceptor<F>
where
    F: Fn(&InterceptedRequest) -> RequestAction + Send + Sync,
{
    fn intercept(&self, request: &InterceptedRequest) -> RequestAction {
        (self.f)(request)
    }
}

/// Function-based response interceptor.
pub struct FnResponseInterceptor<F>
where
    F: Fn(&InterceptedRequest, &InterceptedResponse) -> ResponseAction + Send + Sync,
{
    f: F,
}

impl<F> FnResponseInterceptor<F>
where
    F: Fn(&InterceptedRequest, &InterceptedResponse) -> ResponseAction + Send + Sync,
{
    /// Create a new function interceptor.
    pub fn new(f: F) -> Self {
        Self { f }
    }
}

impl<F> ResponseInterceptor for FnResponseInterceptor<F>
where
    F: Fn(&InterceptedRequest, &InterceptedResponse) -> ResponseAction + Send + Sync,
{
    fn intercept(
        &self,
        request: &InterceptedRequest,
        response: &InterceptedResponse,
    ) -> ResponseAction {
        (self.f)(request, response)
    }
}

/// A captured HTTP exchange (request + response).
#[derive(Debug, Clone)]
pub struct HttpExchange {
    /// The request
    pub request: InterceptedRequest,
    /// The response (if received)
    pub response: Option<InterceptedResponse>,
    /// Any notes/annotations
    pub notes: Vec<String>,
    /// Tags for filtering
    pub tags: Vec<String>,
}

impl HttpExchange {
    /// Create a new exchange.
    pub fn new(request: InterceptedRequest) -> Self {
        Self {
            request,
            response: None,
            notes: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Set response.
    pub fn with_response(mut self, response: InterceptedResponse) -> Self {
        self.response = Some(response);
        self
    }

    /// Add note.
    pub fn add_note(&mut self, note: &str) {
        self.notes.push(note.to_string());
    }

    /// Add tag.
    pub fn add_tag(&mut self, tag: &str) {
        self.tags.push(tag.to_string());
    }

    /// Check if has tag.
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }
}

/// HTTP history storage.
#[derive(Debug)]
pub struct HttpHistory {
    exchanges: RwLock<Vec<HttpExchange>>,
    max_size: usize,
}

impl HttpHistory {
    /// Create a new history.
    pub fn new(max_size: usize) -> Self {
        Self {
            exchanges: RwLock::new(Vec::new()),
            max_size,
        }
    }

    /// Add exchange to history.
    pub fn add(&self, exchange: HttpExchange) {
        let mut exchanges = self.exchanges.write();
        if exchanges.len() >= self.max_size {
            exchanges.remove(0);
        }
        exchanges.push(exchange);
    }

    /// Get exchange by request ID.
    pub fn get(&self, id: InterceptId) -> Option<HttpExchange> {
        let exchanges = self.exchanges.read();
        exchanges.iter().find(|e| e.request.id == id).cloned()
    }

    /// Get all exchanges.
    pub fn all(&self) -> Vec<HttpExchange> {
        self.exchanges.read().clone()
    }

    /// Filter exchanges by predicate.
    pub fn filter<F>(&self, predicate: F) -> Vec<HttpExchange>
    where
        F: Fn(&HttpExchange) -> bool,
    {
        self.exchanges
            .read()
            .iter()
            .filter(|e| predicate(e))
            .cloned()
            .collect()
    }

    /// Filter by host.
    pub fn by_host(&self, host: &str) -> Vec<HttpExchange> {
        self.filter(|e| e.request.host().as_deref() == Some(host))
    }

    /// Filter by method.
    pub fn by_method(&self, method: &Method) -> Vec<HttpExchange> {
        self.filter(|e| e.request.method == *method)
    }

    /// Filter by tag.
    pub fn by_tag(&self, tag: &str) -> Vec<HttpExchange> {
        self.filter(|e| e.has_tag(tag))
    }

    /// Clear history.
    pub fn clear(&self) {
        self.exchanges.write().clear();
    }

    /// Get history size.
    pub fn len(&self) -> usize {
        self.exchanges.read().len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.exchanges.read().is_empty()
    }
}

impl Default for HttpHistory {
    fn default() -> Self {
        Self::new(10000)
    }
}

/// The interception proxy.
pub struct InterceptProxy {
    config: InterceptConfig,
    id_counter: AtomicU64,
    request_interceptors: RwLock<Vec<Arc<dyn RequestInterceptor>>>,
    response_interceptors: RwLock<Vec<Arc<dyn ResponseInterceptor>>>,
    history: Arc<HttpHistory>,
    pending_requests: Mutex<HashMap<InterceptId, InterceptedRequest>>,
}

impl std::fmt::Debug for InterceptProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterceptProxy")
            .field("config", &self.config)
            .field("id_counter", &self.id_counter)
            .field(
                "request_interceptors_count",
                &self.request_interceptors.read().len(),
            )
            .field(
                "response_interceptors_count",
                &self.response_interceptors.read().len(),
            )
            .field("history", &self.history)
            .finish()
    }
}

impl InterceptProxy {
    /// Create a new interception proxy.
    pub fn new(config: InterceptConfig) -> Self {
        Self {
            config,
            id_counter: AtomicU64::new(1),
            request_interceptors: RwLock::new(Vec::new()),
            response_interceptors: RwLock::new(Vec::new()),
            history: Arc::new(HttpHistory::default()),
            pending_requests: Mutex::new(HashMap::new()),
        }
    }

    /// Add request interceptor.
    pub fn add_request_interceptor<I: RequestInterceptor + 'static>(&self, interceptor: I) {
        self.request_interceptors
            .write()
            .push(Arc::new(interceptor));
    }

    /// Add response interceptor.
    pub fn add_response_interceptor<I: ResponseInterceptor + 'static>(&self, interceptor: I) {
        self.response_interceptors
            .write()
            .push(Arc::new(interceptor));
    }

    /// Generate next intercept ID.
    pub fn next_id(&self) -> InterceptId {
        InterceptId(self.id_counter.fetch_add(1, Ordering::Relaxed))
    }

    /// Intercept a request.
    pub fn intercept_request(
        &self,
        mut request: InterceptedRequest,
    ) -> (InterceptedRequest, RequestAction) {
        // Store for later response correlation
        self.pending_requests
            .lock()
            .insert(request.id, request.clone());

        // Run through interceptors
        let interceptors = self.request_interceptors.read();
        for interceptor in interceptors.iter() {
            match interceptor.intercept(&request) {
                RequestAction::Forward => continue,
                RequestAction::Modify(mods) => {
                    request = mods.apply(request);
                }
                action @ (RequestAction::Drop | RequestAction::Respond(_)) => {
                    return (request, action);
                }
            }
        }

        (request, RequestAction::Forward)
    }

    /// Intercept a response.
    pub fn intercept_response(
        &self,
        request_id: InterceptId,
        mut response: InterceptedResponse,
    ) -> (InterceptedResponse, ResponseAction) {
        let request = self.pending_requests.lock().remove(&request_id);

        if let Some(req) = &request {
            // Run through interceptors
            let interceptors = self.response_interceptors.read();
            for interceptor in interceptors.iter() {
                match interceptor.intercept(req, &response) {
                    ResponseAction::Forward => continue,
                    ResponseAction::Modify(mods) => {
                        response = mods.apply(response);
                    }
                    ResponseAction::Drop => {
                        return (response, ResponseAction::Drop);
                    }
                }
            }

            // Add to history
            let exchange = HttpExchange::new(req.clone()).with_response(response.clone());
            self.history.add(exchange);
        }

        (response, ResponseAction::Forward)
    }

    /// Get history.
    pub fn history(&self) -> &Arc<HttpHistory> {
        &self.history
    }

    /// Get configuration.
    pub fn config(&self) -> &InterceptConfig {
        &self.config
    }
}

impl Default for InterceptProxy {
    fn default() -> Self {
        Self::new(InterceptConfig::default())
    }
}

/// Interception statistics.
#[derive(Debug, Clone, Default)]
pub struct InterceptStats {
    /// Total requests intercepted
    pub requests_intercepted: u64,
    /// Total responses intercepted
    pub responses_intercepted: u64,
    /// Requests modified
    pub requests_modified: u64,
    /// Responses modified
    pub responses_modified: u64,
    /// Requests dropped
    pub requests_dropped: u64,
    /// Responses dropped
    pub responses_dropped: u64,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_intercept_id() {
        let proxy = InterceptProxy::default();
        let id1 = proxy.next_id();
        let id2 = proxy.next_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_intercepted_request() {
        let id = InterceptId(1);
        let req = InterceptedRequest::new(
            id,
            Method::GET,
            Uri::from_static("http://example.onion/test"),
        )
        .with_body(b"test body".to_vec());

        assert_eq!(req.body_text(), Some("test body".to_string()));
    }

    #[test]
    fn test_modified_request() {
        let id = InterceptId(1);
        let req =
            InterceptedRequest::new(id, Method::GET, Uri::from_static("http://example.onion/"));

        let mods = ModifiedRequest::new()
            .with_method(Method::POST)
            .with_header("X-Custom", "value");

        let modified = mods.apply(req);
        assert_eq!(modified.method, Method::POST);
        assert_eq!(modified.header("x-custom"), Some("value"));
    }

    #[test]
    fn test_http_history() {
        let history = HttpHistory::new(100);

        let req = InterceptedRequest::new(
            InterceptId(1),
            Method::GET,
            Uri::from_static("http://example.onion/"),
        );
        let exchange = HttpExchange::new(req);

        history.add(exchange);
        assert_eq!(history.len(), 1);

        let retrieved = history.get(InterceptId(1));
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_fn_interceptor() {
        let interceptor = FnRequestInterceptor::new(|req| {
            if req.method == Method::POST {
                RequestAction::Drop
            } else {
                RequestAction::Forward
            }
        });

        let req = InterceptedRequest::new(
            InterceptId(1),
            Method::POST,
            Uri::from_static("http://example.onion/"),
        );
        let action = interceptor.intercept(&req);
        assert!(matches!(action, RequestAction::Drop));
    }
}
