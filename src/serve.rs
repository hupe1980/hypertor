//! FastAPI-like onion service framework.
//!
//! Provides an incredibly simple way to host .onion services with a
//! familiar, decorator-based API inspired by FastAPI, Flask, and axum.
//!
//! # Rust Example
//!
//! ```rust,ignore
//! use hypertor::serve::{OnionApp, get, post, Json};
//! use serde_json::json;
//!
//! #[tokio::main]
//! async fn main() {
//!     let app = OnionApp::new()
//!         .route("/", get(home))
//!         .route("/api/echo", post(echo))
//!         .route("/health", get(|| async { "OK" }));
//!     
//!     app.run().await.unwrap();
//! }
//!
//! async fn home() -> &'static str {
//!     "Welcome to my onion service!"
//! }
//!
//! async fn echo(Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
//!     Json(json!({"received": body}))
//! }
//! ```
//!
//! # Python Example
//!
//! ```python
//! from hypertor import OnionApp
//!
//! app = OnionApp()
//!
//! @app.route("/")
//! def home():
//!     return "Welcome to my onion service!"
//!
//! @app.route("/api/echo", methods=["POST"])
//! def echo(request):
//!     return {"received": request.json()}
//!
//! app.run()  # Prints: Service available at: xyz...xyz.onion
//! ```

// Allow dead code for now - OnionApp is WIP
#![allow(dead_code)]

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::RwLock;

use crate::error::{Error, Result};

// Re-export for convenience
pub use http::Method;

/// JSON extractor and response type.
#[derive(Debug, Clone)]
pub struct Json<T>(pub T);

impl<T> Json<T> {
    /// Create new JSON wrapper.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Get inner value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

/// Request context passed to handlers.
#[derive(Debug, Clone)]
pub struct Request {
    /// HTTP method
    pub method: Method,
    /// Request path
    pub path: String,
    /// Query parameters
    pub query: HashMap<String, String>,
    /// Request headers
    pub headers: HashMap<String, String>,
    /// Request body bytes
    pub body: Vec<u8>,
    /// Path parameters (from route patterns)
    pub params: HashMap<String, String>,
    /// Client address (through Tor, so always 127.0.0.1)
    pub remote_addr: SocketAddr,
}

impl Request {
    /// Create new request.
    pub fn new(method: Method, path: &str) -> Self {
        Self {
            method,
            path: path.to_string(),
            query: HashMap::new(),
            headers: HashMap::new(),
            body: Vec::new(),
            params: HashMap::new(),
            remote_addr: "127.0.0.1:0"
                .parse()
                .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 0))),
        }
    }

    /// Get body as string.
    pub fn text(&self) -> Result<String> {
        String::from_utf8(self.body.clone()).map_err(|e| Error::Protocol(e.to_string()))
    }

    /// Parse body as JSON.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body)
            .map_err(|e| Error::Protocol(format!("JSON parse error: {}", e)))
    }

    /// Get header value.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_lowercase()).map(|s| s.as_str())
    }

    /// Get query parameter.
    pub fn query_param(&self, name: &str) -> Option<&str> {
        self.query.get(name).map(|s| s.as_str())
    }

    /// Get path parameter.
    pub fn path_param(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(|s| s.as_str())
    }
}

/// Response to send back to client.
#[derive(Debug, Clone)]
pub struct Response {
    /// HTTP status code
    pub status: u16,
    /// Response headers
    pub headers: HashMap<String, String>,
    /// Response body
    pub body: Vec<u8>,
}

impl Response {
    /// Create new response with status.
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    /// Create 200 OK response.
    pub fn ok() -> Self {
        Self::new(200)
    }

    /// Create response with body.
    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Create response with text body.
    pub fn text(body: impl Into<String>) -> Self {
        let body = body.into();
        Self::new(200)
            .with_header("Content-Type", "text/plain; charset=utf-8")
            .with_body(body.into_bytes())
    }

    /// Create response with HTML body.
    pub fn html(body: impl Into<String>) -> Self {
        let body = body.into();
        Self::new(200)
            .with_header("Content-Type", "text/html; charset=utf-8")
            .with_body(body.into_bytes())
    }

    /// Create response with JSON body.
    pub fn json<T: serde::Serialize>(value: &T) -> Result<Self> {
        let body = serde_json::to_vec(value)
            .map_err(|e| Error::Protocol(format!("JSON serialize error: {}", e)))?;
        Ok(Self::new(200)
            .with_header("Content-Type", "application/json")
            .with_body(body))
    }

    /// Add header.
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_string(), value.to_string());
        self
    }

    /// Set status code.
    pub fn with_status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }

    /// Create 404 Not Found.
    pub fn not_found() -> Self {
        Self::new(404).with_body(b"Not Found".to_vec())
    }

    /// Create 500 Internal Server Error.
    pub fn internal_error(message: &str) -> Self {
        Self::new(500).with_body(message.as_bytes().to_vec())
    }

    /// Create redirect response.
    pub fn redirect(location: &str) -> Self {
        Self::new(302).with_header("Location", location)
    }
}

// Allow converting various types to Response
impl From<&str> for Response {
    fn from(s: &str) -> Self {
        Response::text(s)
    }
}

impl From<String> for Response {
    fn from(s: String) -> Self {
        Response::text(s)
    }
}

impl From<Vec<u8>> for Response {
    fn from(body: Vec<u8>) -> Self {
        Response::ok().with_body(body)
    }
}

impl<T: serde::Serialize> From<Json<T>> for Response {
    fn from(json: Json<T>) -> Self {
        Response::json(&json.0).unwrap_or_else(|_| Response::internal_error("JSON error"))
    }
}

/// Handler function type.
pub type BoxedHandler =
    Arc<dyn Fn(Request) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync>;

/// Route definition.
#[derive(Clone)]
struct Route {
    /// HTTP method
    method: Method,
    /// Path pattern (e.g., "/users/{id}")
    pattern: String,
    /// Compiled pattern segments
    segments: Vec<PathSegment>,
    /// Handler function
    handler: BoxedHandler,
}

/// Path segment for matching.
#[derive(Debug, Clone)]
enum PathSegment {
    /// Literal text
    Literal(String),
    /// Parameter capture (e.g., {id})
    Param(String),
    /// Wildcard (matches anything remaining)
    Wildcard,
}

impl Route {
    /// Create new route.
    fn new(method: Method, pattern: &str, handler: BoxedHandler) -> Self {
        let segments = Self::parse_pattern(pattern);
        Self {
            method,
            pattern: pattern.to_string(),
            segments,
            handler,
        }
    }

    /// Parse path pattern into segments.
    fn parse_pattern(pattern: &str) -> Vec<PathSegment> {
        pattern
            .trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|s| {
                if s == "*" || s == "**" {
                    PathSegment::Wildcard
                } else if s.starts_with('{') && s.ends_with('}') {
                    let name = s[1..s.len() - 1].to_string();
                    PathSegment::Param(name)
                } else {
                    PathSegment::Literal(s.to_string())
                }
            })
            .collect()
    }

    /// Check if path matches and extract parameters.
    fn matches(&self, method: &Method, path: &str) -> Option<HashMap<String, String>> {
        if self.method != *method {
            return None;
        }

        let path_parts: Vec<&str> = path
            .trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        let mut params = HashMap::new();
        let mut path_idx = 0;

        for segment in &self.segments {
            match segment {
                PathSegment::Literal(lit) => {
                    if path_idx >= path_parts.len() || path_parts[path_idx] != lit {
                        return None;
                    }
                    path_idx += 1;
                }
                PathSegment::Param(name) => {
                    if path_idx >= path_parts.len() {
                        return None;
                    }
                    params.insert(name.clone(), path_parts[path_idx].to_string());
                    path_idx += 1;
                }
                PathSegment::Wildcard => {
                    // Match everything remaining
                    let remaining: Vec<&str> = path_parts[path_idx..].to_vec();
                    params.insert("*".to_string(), remaining.join("/"));
                    return Some(params);
                }
            }
        }

        // All segments matched and path fully consumed
        if path_idx == path_parts.len() {
            Some(params)
        } else {
            None
        }
    }
}

/// Middleware function type.
pub type MiddlewareFn = Box<
    dyn Fn(Request, MiddlewareNext) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync,
>;

/// Handler type for middleware next.
pub type NextHandler =
    Arc<dyn Fn(Request) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync>;

/// Next middleware in chain.
pub struct MiddlewareNext {
    handler: NextHandler,
}

impl MiddlewareNext {
    /// Call next handler.
    pub async fn run(self, request: Request) -> Response {
        (self.handler)(request).await
    }
}

/// Configuration for the onion app.
#[derive(Debug, Clone)]
pub struct OnionAppConfig {
    /// Service nickname (for persistent identity via arti's key management)
    pub nickname: String,
    /// Port to listen on (virtual port on .onion)
    pub port: u16,
    /// Local port to bind to
    pub local_port: u16,
    /// Request timeout
    pub request_timeout: Duration,
    /// Max request body size
    pub max_body_size: usize,
    /// Enable request logging
    pub log_requests: bool,
    /// Custom server header
    pub server_header: Option<String>,
}

impl Default for OnionAppConfig {
    fn default() -> Self {
        Self {
            nickname: "hypertor-service".to_string(),
            port: 80,
            local_port: 8080,
            request_timeout: Duration::from_secs(30),
            max_body_size: 10 * 1024 * 1024, // 10MB
            log_requests: true,
            server_header: None, // Don't leak server info by default
        }
    }
}

impl OnionAppConfig {
    /// Create new config.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set service nickname (for persistent identity).
    ///
    /// Using the same nickname across restarts gives you the same .onion address,
    /// as arti stores keys in its state directory keyed by nickname.
    pub fn with_nickname(mut self, nickname: impl Into<String>) -> Self {
        self.nickname = nickname.into();
        self
    }

    /// Set virtual port.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set local port.
    pub fn with_local_port(mut self, port: u16) -> Self {
        self.local_port = port;
        self
    }

    /// Set request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Set max body size.
    pub fn with_max_body_size(mut self, size: usize) -> Self {
        self.max_body_size = size;
        self
    }

    /// Enable/disable request logging.
    pub fn with_logging(mut self, enabled: bool) -> Self {
        self.log_requests = enabled;
        self
    }
}

/// Onion service application - FastAPI-style framework.
pub struct OnionApp {
    /// Configuration
    config: OnionAppConfig,
    /// Routes
    routes: Vec<Route>,
    /// Middleware stack
    middleware: Vec<MiddlewareFn>,
    /// Static file directory
    static_dir: Option<PathBuf>,
    /// 404 handler
    not_found_handler: Option<BoxedHandler>,
    /// Error handler
    error_handler: Option<Box<dyn Fn(Error) -> Response + Send + Sync>>,
    /// Running onion address (available after start)
    onion_address: Arc<RwLock<Option<String>>>,
    /// Running flag
    running: Arc<AtomicBool>,
    /// Request counter
    request_count: Arc<AtomicU64>,
    /// Stats
    stats: Arc<RwLock<AppStats>>,
}

/// Application statistics.
#[derive(Debug, Clone, Default)]
pub struct AppStats {
    /// Total requests served
    pub total_requests: u64,
    /// Successful responses (2xx)
    pub success_count: u64,
    /// Client errors (4xx)
    pub client_error_count: u64,
    /// Server errors (5xx)
    pub server_error_count: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Average response time (ms)
    pub avg_response_time_ms: f64,
    /// Start time
    pub started_at: Option<Instant>,
    /// Uptime in seconds
    pub uptime_secs: u64,
}

impl OnionApp {
    /// Create new onion app with default config.
    pub fn new() -> Self {
        Self::with_config(OnionAppConfig::default())
    }

    /// Create new onion app with custom config.
    pub fn with_config(config: OnionAppConfig) -> Self {
        Self {
            config,
            routes: Vec::new(),
            middleware: Vec::new(),
            static_dir: None,
            not_found_handler: None,
            error_handler: None,
            onion_address: Arc::new(RwLock::new(None)),
            running: Arc::new(AtomicBool::new(false)),
            request_count: Arc::new(AtomicU64::new(0)),
            stats: Arc::new(RwLock::new(AppStats::default())),
        }
    }

    /// Add a route with handler.
    pub fn route<H, T>(mut self, path: &str, handler: MethodHandler<H, T>) -> Self
    where
        H: Handler<T> + 'static,
        T: 'static,
    {
        let boxed = handler.handler.into_boxed();
        self.routes.push(Route::new(handler.method, path, boxed));
        self
    }

    /// Add GET route.
    pub fn get<H, T>(self, path: &str, handler: H) -> Self
    where
        H: Handler<T> + 'static,
        T: 'static,
    {
        self.route(path, get(handler))
    }

    /// Add POST route.
    pub fn post<H, T>(self, path: &str, handler: H) -> Self
    where
        H: Handler<T> + 'static,
        T: 'static,
    {
        self.route(path, post(handler))
    }

    /// Add PUT route.
    pub fn put<H, T>(self, path: &str, handler: H) -> Self
    where
        H: Handler<T> + 'static,
        T: 'static,
    {
        self.route(path, put(handler))
    }

    /// Add DELETE route.
    pub fn delete<H, T>(self, path: &str, handler: H) -> Self
    where
        H: Handler<T> + 'static,
        T: 'static,
    {
        self.route(path, delete(handler))
    }

    /// Add PATCH route.
    pub fn patch<H, T>(self, path: &str, handler: H) -> Self
    where
        H: Handler<T> + 'static,
        T: 'static,
    {
        self.route(path, patch(handler))
    }

    /// Serve static files from directory.
    pub fn static_files(mut self, path: impl Into<PathBuf>) -> Self {
        self.static_dir = Some(path.into());
        self
    }

    /// Set custom 404 handler.
    pub fn not_found<H, T>(mut self, handler: H) -> Self
    where
        H: Handler<T> + 'static,
        T: 'static,
    {
        self.not_found_handler = Some(handler.into_boxed());
        self
    }

    /// Set error handler.
    pub fn on_error<F>(mut self, handler: F) -> Self
    where
        F: Fn(Error) -> Response + Send + Sync + 'static,
    {
        self.error_handler = Some(Box::new(handler));
        self
    }

    /// Get the .onion address (available after run() is called).
    ///
    /// Returns None if the service hasn't started yet.
    pub fn address(&self) -> Option<String> {
        self.onion_address.read().clone()
    }

    /// Get the service nickname.
    pub fn nickname(&self) -> &str {
        &self.config.nickname
    }

    /// Get application stats.
    pub fn stats(&self) -> AppStats {
        let mut stats = self.stats.read().clone();
        if let Some(started) = stats.started_at {
            stats.uptime_secs = started.elapsed().as_secs();
        }
        stats
    }

    /// Check if running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Stop the service.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Run the onion service (blocking).
    ///
    /// The service uses the configured nickname for persistent identity.
    /// Arti manages the actual Ed25519 keys in its state directory - using
    /// the same nickname across restarts gives you the same .onion address.
    pub async fn run(self) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);
        self.stats.write().started_at = Some(Instant::now());

        // Create the underlying onion service using nickname
        let service_config = crate::onion_service::OnionServiceConfig::new(&self.config.nickname)
            .port(self.config.port);
        let mut service = crate::onion_service::OnionService::new(service_config);

        // Start the Tor onion service - arti generates/loads real keys
        let onion_addr = service.start().await?;

        // Store the real address
        *self.onion_address.write() = Some(onion_addr.clone());

        println!("╔════════════════════════════════════════════════════════════════════╗");
        println!("║                    🧅 Onion Service Started                        ║");
        println!("╠════════════════════════════════════════════════════════════════════╣");
        println!("║ Address: {}", onion_addr);
        println!("║ Nickname: {}", self.config.nickname);
        println!("║ Port: {}", self.config.port);
        println!("║ Routes: {}", self.routes.len());
        println!("║ State: {}", service.state());
        println!("╚════════════════════════════════════════════════════════════════════╝");

        // Main service loop - accept and handle connections
        while self.running.load(Ordering::SeqCst) {
            // Accept incoming connections (timeout to check running flag)
            tokio::select! {
                stream = service.accept() => {
                    if let Some(stream) = stream {
                        // Spawn handler for this connection
                        let routes = self.routes.clone();
                        let static_dir = self.static_dir.clone();
                        let not_found = self.not_found_handler.clone();
                        let stats = self.stats.clone();
                        let request_count = self.request_count.clone();

                        tokio::spawn(async move {
                            Self::handle_connection(
                                stream,
                                routes,
                                static_dir,
                                not_found,
                                stats,
                                request_count,
                            ).await;
                        });
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    // Check if we should stop
                    if !self.running.load(Ordering::SeqCst) {
                        break;
                    }
                }
            }
        }

        // Graceful shutdown
        service.stop().await?;
        println!("Onion service stopped.");
        Ok(())
    }

    /// Handle incoming request (internal).
    async fn handle_request(&self, mut request: Request) -> Response {
        self.request_count.fetch_add(1, Ordering::Relaxed);
        let start = Instant::now();

        // Find matching route
        for route in &self.routes {
            if let Some(params) = route.matches(&request.method, &request.path) {
                request.params = params;
                let response = (route.handler)(request).await;
                self.record_response(&response, start);
                return response;
            }
        }

        // Try static files
        if let Some(ref static_dir) = self.static_dir {
            let file_path = static_dir.join(request.path.trim_start_matches('/'));
            if file_path.exists() && file_path.is_file() {
                if let Ok(content) = std::fs::read(&file_path) {
                    let mime = mime_guess::from_path(&file_path)
                        .first_or_octet_stream()
                        .to_string();
                    let response = Response::ok()
                        .with_header("Content-Type", &mime)
                        .with_body(content);
                    self.record_response(&response, start);
                    return response;
                }
            }
        }

        // Custom 404 or default
        let response = if let Some(ref handler) = self.not_found_handler {
            handler(request).await
        } else {
            Response::not_found()
        };
        self.record_response(&response, start);
        response
    }

    /// Record response stats.
    fn record_response(&self, response: &Response, start: Instant) {
        let mut stats = self.stats.write();
        stats.total_requests += 1;
        stats.bytes_sent += response.body.len() as u64;

        match response.status {
            200..=299 => stats.success_count += 1,
            400..=499 => stats.client_error_count += 1,
            500..=599 => stats.server_error_count += 1,
            _ => {}
        }

        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
        let n = stats.total_requests as f64;
        stats.avg_response_time_ms = (stats.avg_response_time_ms * (n - 1.0) + elapsed_ms) / n;
    }

    /// Handle a connection from the onion service.
    async fn handle_connection(
        mut stream: crate::onion_service::OnionStream,
        routes: Vec<Route>,
        static_dir: Option<PathBuf>,
        not_found: Option<BoxedHandler>,
        stats: Arc<RwLock<AppStats>>,
        request_count: Arc<AtomicU64>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        request_count.fetch_add(1, Ordering::Relaxed);
        let start = Instant::now();

        // Read HTTP request from stream
        let mut buffer = vec![0u8; 8192];
        let n = stream.read(&mut buffer).await.unwrap_or(0);

        if n == 0 {
            return;
        }

        // Parse HTTP request (simplified)
        let request_str = String::from_utf8_lossy(&buffer[..n]);
        let lines: Vec<&str> = request_str.lines().collect();

        if lines.is_empty() {
            return;
        }

        // Parse request line
        let parts: Vec<&str> = lines[0].split_whitespace().collect();
        if parts.len() < 2 {
            return;
        }

        let method = match parts[0].to_uppercase().as_str() {
            "GET" => Method::GET,
            "POST" => Method::POST,
            "PUT" => Method::PUT,
            "DELETE" => Method::DELETE,
            "PATCH" => Method::PATCH,
            "HEAD" => Method::HEAD,
            "OPTIONS" => Method::OPTIONS,
            _ => return,
        };

        let path = parts[1].to_string();
        let mut request = Request::new(method.clone(), &path);

        // Parse headers
        let mut body_start = 0;
        for (i, line) in lines.iter().enumerate().skip(1) {
            if line.is_empty() {
                body_start = i + 1;
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                request
                    .headers
                    .insert(name.trim().to_lowercase(), value.trim().to_string());
            }
        }

        // Parse body if present
        if body_start < lines.len() {
            request.body = lines[body_start..].join("\n").into_bytes();
        }

        // Find matching route
        let response = {
            let mut matched = false;
            let mut response = Response::not_found();

            for route in &routes {
                if let Some(params) = route.matches(&method, &path) {
                    request.params = params;
                    response = (route.handler)(request.clone()).await;
                    matched = true;
                    break;
                }
            }

            // Try static files
            if !matched {
                if let Some(ref static_dir) = static_dir {
                    let file_path = static_dir.join(path.trim_start_matches('/'));
                    if file_path.exists() && file_path.is_file() {
                        if let Ok(content) = std::fs::read(&file_path) {
                            let mime = mime_guess::from_path(&file_path)
                                .first_or_octet_stream()
                                .to_string();
                            response = Response::ok()
                                .with_header("Content-Type", &mime)
                                .with_body(content);
                            matched = true;
                        }
                    }
                }
            }

            // Custom 404
            if !matched {
                if let Some(ref handler) = not_found {
                    response = handler(request).await;
                }
            }

            response
        };

        // Record stats
        {
            let mut s = stats.write();
            s.total_requests += 1;
            s.bytes_sent += response.body.len() as u64;

            match response.status {
                200..=299 => s.success_count += 1,
                400..=499 => s.client_error_count += 1,
                500..=599 => s.server_error_count += 1,
                _ => {}
            }

            let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
            let n = s.total_requests as f64;
            s.avg_response_time_ms = (s.avg_response_time_ms * (n - 1.0) + elapsed_ms) / n;
        }

        // Write HTTP response
        let status_text = match response.status {
            200 => "OK",
            201 => "Created",
            204 => "No Content",
            301 => "Moved Permanently",
            302 => "Found",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "Unknown",
        };

        let mut response_bytes = format!("HTTP/1.1 {} {}\r\n", response.status, status_text);

        for (name, value) in &response.headers {
            response_bytes.push_str(&format!("{}: {}\r\n", name, value));
        }
        response_bytes.push_str(&format!("Content-Length: {}\r\n", response.body.len()));
        response_bytes.push_str("\r\n");

        let _ = stream.write(response_bytes.as_bytes()).await;
        let _ = stream.write(&response.body).await;
    }
}

impl Default for OnionApp {
    fn default() -> Self {
        Self::new()
    }
}

/// Handler trait for route handlers.
pub trait Handler<T>: Clone + Send + Sync + 'static {
    /// Handle request and return response.
    fn call(&self, req: Request) -> Pin<Box<dyn Future<Output = Response> + Send>>;

    /// Convert to boxed handler.
    fn into_boxed(self) -> BoxedHandler
    where
        Self: Sized,
    {
        Arc::new(move |req| self.call(req))
    }
}

// Implement Handler for no-arg async functions returning Response
impl<F, Fut> Handler<()> for F
where
    F: Fn() -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    fn call(&self, _req: Request) -> Pin<Box<dyn Future<Output = Response> + Send>> {
        Box::pin(self())
    }
}

// Handler with Request parameter returning Response
impl<F, Fut> Handler<Request> for F
where
    F: Fn(Request) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    fn call(&self, req: Request) -> Pin<Box<dyn Future<Output = Response> + Send>> {
        Box::pin(self(req))
    }
}

/// Method handler wrapper.
pub struct MethodHandler<H, T> {
    method: Method,
    handler: H,
    _marker: std::marker::PhantomData<T>,
}

/// Create GET handler.
pub fn get<H, T>(handler: H) -> MethodHandler<H, T>
where
    H: Handler<T>,
{
    MethodHandler {
        method: Method::GET,
        handler,
        _marker: std::marker::PhantomData,
    }
}

/// Create POST handler.
pub fn post<H, T>(handler: H) -> MethodHandler<H, T>
where
    H: Handler<T>,
{
    MethodHandler {
        method: Method::POST,
        handler,
        _marker: std::marker::PhantomData,
    }
}

/// Create PUT handler.
pub fn put<H, T>(handler: H) -> MethodHandler<H, T>
where
    H: Handler<T>,
{
    MethodHandler {
        method: Method::PUT,
        handler,
        _marker: std::marker::PhantomData,
    }
}

/// Create DELETE handler.
pub fn delete<H, T>(handler: H) -> MethodHandler<H, T>
where
    H: Handler<T>,
{
    MethodHandler {
        method: Method::DELETE,
        handler,
        _marker: std::marker::PhantomData,
    }
}

/// Create PATCH handler.
pub fn patch<H, T>(handler: H) -> MethodHandler<H, T>
where
    H: Handler<T>,
{
    MethodHandler {
        method: Method::PATCH,
        handler,
        _marker: std::marker::PhantomData,
    }
}

/// Create HEAD handler.
pub fn head<H, T>(handler: H) -> MethodHandler<H, T>
where
    H: Handler<T>,
{
    MethodHandler {
        method: Method::HEAD,
        handler,
        _marker: std::marker::PhantomData,
    }
}

/// Create OPTIONS handler.
pub fn options<H, T>(handler: H) -> MethodHandler<H, T>
where
    H: Handler<T>,
{
    MethodHandler {
        method: Method::OPTIONS,
        handler,
        _marker: std::marker::PhantomData,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_route_matching() {
        let route = Route::new(
            Method::GET,
            "/users/{id}",
            Arc::new(|_| Box::pin(async { Response::ok() })),
        );

        // Should match
        let params = route.matches(&Method::GET, "/users/123");
        assert!(params.is_some());
        assert_eq!(params.as_ref().unwrap().get("id"), Some(&"123".to_string()));

        // Should not match wrong method
        let params = route.matches(&Method::POST, "/users/123");
        assert!(params.is_none());

        // Should not match wrong path
        let params = route.matches(&Method::GET, "/posts/123");
        assert!(params.is_none());
    }

    #[test]
    fn test_wildcard_route() {
        let route = Route::new(
            Method::GET,
            "/files/*",
            Arc::new(|_| Box::pin(async { Response::ok() })),
        );

        let params = route.matches(&Method::GET, "/files/path/to/file.txt");
        assert!(params.is_some());
        assert_eq!(
            params.as_ref().unwrap().get("*"),
            Some(&"path/to/file.txt".to_string())
        );
    }

    #[test]
    fn test_response_builders() {
        let text = Response::text("Hello");
        assert_eq!(text.status, 200);
        assert_eq!(text.body, b"Hello");

        let html = Response::html("<h1>Hi</h1>");
        assert_eq!(
            html.headers.get("Content-Type"),
            Some(&"text/html; charset=utf-8".to_string())
        );

        let json = Response::json(&serde_json::json!({"key": "value"})).unwrap();
        assert_eq!(
            json.headers.get("Content-Type"),
            Some(&"application/json".to_string())
        );

        let not_found = Response::not_found();
        assert_eq!(not_found.status, 404);

        let redirect = Response::redirect("/new-location");
        assert_eq!(redirect.status, 302);
        assert_eq!(
            redirect.headers.get("Location"),
            Some(&"/new-location".to_string())
        );
    }

    #[test]
    fn test_request() {
        let mut request = Request::new(Method::GET, "/test");
        request
            .headers
            .insert("content-type".to_string(), "application/json".to_string());
        request.query.insert("page".to_string(), "1".to_string());
        request.params.insert("id".to_string(), "123".to_string());

        assert_eq!(request.header("Content-Type"), Some("application/json"));
        assert_eq!(request.query_param("page"), Some("1"));
        assert_eq!(request.path_param("id"), Some("123"));
    }

    #[test]
    fn test_onion_app_builder() {
        async fn home(_req: Request) -> Response {
            Response::text("Home")
        }
        async fn api(_req: Request) -> Response {
            Response::ok()
        }

        let app = OnionApp::new()
            .route("/", get(home))
            .route("/api", post(api));

        assert_eq!(app.routes.len(), 2);
    }

    #[test]
    fn test_config_builder() {
        let config = OnionAppConfig::new()
            .with_port(443)
            .with_local_port(8443)
            .with_timeout(Duration::from_secs(60))
            .with_max_body_size(1024 * 1024);

        assert_eq!(config.port, 443);
        assert_eq!(config.local_port, 8443);
        assert_eq!(config.request_timeout, Duration::from_secs(60));
        assert_eq!(config.max_body_size, 1024 * 1024);
    }
}
