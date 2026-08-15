//! A small HTTP framework for onion services.
//!
//! [`OnionApp`] serves HTTP over the streams an [`OnionService`] accepts. The
//! HTTP itself is hyper's, so request parsing, chunked bodies, keep-alive and
//! HTTP/2 all behave the way they do in any other hyper server.
//!
//! ```rust,no_run
//! use hypertor::{OnionApp, ServeResponse};
//!
//! # async fn demo() -> hypertor::Result<()> {
//! let app = OnionApp::new()
//!     .get("/", |_req| async { ServeResponse::text("hello from .onion") })
//!     .get("/health", |_req| async {
//!         ServeResponse::json(&serde_json::json!({"status": "ok"}))
//!     });
//!
//! let service = app.serve("my-service").await?;
//! println!("live at {}", service.onion_address());
//! service.wait().await
//! # }
//! ```

use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use tracing::{debug, warn};

use crate::error::{Error, Result};
use crate::onion_service::{OnionService, OnionServiceBuilder};

/// Default cap on an inbound request body.
const DEFAULT_MAX_BODY: usize = 2 * 1024 * 1024;

// ============================================================================
// Request
// ============================================================================

/// An inbound request.
#[derive(Debug)]
pub struct Request {
    method: Method,
    path: String,
    query: HashMap<String, String>,
    params: HashMap<String, String>,
    headers: HeaderMap,
    body: Bytes,
}

impl Request {
    /// The HTTP method.
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// The path, without the query string.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// A decoded query parameter.
    pub fn query(&self, name: &str) -> Option<&str> {
        self.query.get(name).map(String::as_str)
    }

    /// All decoded query parameters.
    pub fn queries(&self) -> &HashMap<String, String> {
        &self.query
    }

    /// A path parameter captured by a route pattern such as `/users/{id}`.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(String::as_str)
    }

    /// The request headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// A single header value.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// The raw body.
    pub fn body(&self) -> &Bytes {
        &self.body
    }

    /// The body as UTF-8 text.
    pub fn text(&self) -> Result<String> {
        std::str::from_utf8(&self.body)
            .map(str::to_owned)
            .map_err(|e| Error::decode(format!("request body is not valid UTF-8: {e}")))
    }

    /// The body deserialised from JSON.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body)
            .map_err(|e| Error::decode(format!("request body is not valid JSON: {e}")))
    }
}

// ============================================================================
// Response
// ============================================================================

/// An outbound response.
#[derive(Debug, Clone)]
pub struct Response {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Response {
    /// A response with the given status and an empty body.
    pub fn status(status: StatusCode) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            body: Bytes::new(),
        }
    }

    /// `200 OK` with a `text/plain` body.
    pub fn text(body: impl Into<Bytes>) -> Self {
        Self::status(StatusCode::OK)
            .with_content_type("text/plain; charset=utf-8")
            .with_body(body)
    }

    /// `200 OK` with an `text/html` body.
    pub fn html(body: impl Into<Bytes>) -> Self {
        Self::status(StatusCode::OK)
            .with_content_type("text/html; charset=utf-8")
            .with_body(body)
    }

    /// `200 OK` with `value` serialised as JSON.
    ///
    /// Serialisation failures become a `500`, logged server-side, rather than a
    /// panic or a silently empty body.
    pub fn json<T: serde::Serialize + ?Sized>(value: &T) -> Self {
        match serde_json::to_vec(value) {
            Ok(bytes) => Self::status(StatusCode::OK)
                .with_content_type("application/json")
                .with_body(bytes),
            Err(e) => {
                warn!(error = %e, "handler produced unserialisable JSON");
                Self::status(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }

    /// `200 OK` with a body that is already serialised JSON.
    pub fn json_raw(body: impl Into<Bytes>) -> Self {
        Self::status(StatusCode::OK)
            .with_content_type("application/json")
            .with_body(body)
    }

    /// `404 Not Found`.
    pub fn not_found() -> Self {
        Self::status(StatusCode::NOT_FOUND).with_body("not found")
    }

    /// Set the body.
    pub fn with_body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }

    /// Set the `Content-Type`.
    pub fn with_content_type(self, value: &str) -> Self {
        self.with_header(http::header::CONTENT_TYPE, value)
    }

    /// Set a header.
    ///
    /// Values that are not valid HTTP header content — anything containing CR
    /// or LF — are rejected here rather than written to the socket. Writing
    /// them would let any handler that echoes user input split the response and
    /// inject headers or a second response entirely.
    pub fn with_header<K>(mut self, name: K, value: &str) -> Self
    where
        K: TryInto<HeaderName>,
    {
        match (name.try_into(), HeaderValue::from_str(value)) {
            (Ok(name), Ok(value)) => {
                self.headers.insert(name, value);
            }
            _ => warn!("refusing to set a header with an invalid name or value"),
        }
        self
    }

    /// Set the status code.
    pub fn with_status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    fn into_hyper(self) -> hyper::Response<Full<Bytes>> {
        let mut response = hyper::Response::builder().status(self.status);

        if let Some(headers) = response.headers_mut() {
            *headers = self.headers;
        }

        response.body(Full::new(self.body)).unwrap_or_else(|_| {
            hyper::Response::new(Full::new(Bytes::from_static(b"internal error")))
        })
    }
}

// ============================================================================
// Routing
// ============================================================================

type BoxFuture = Pin<Box<dyn Future<Output = Response> + Send>>;
type BoxHandler = Arc<dyn Fn(Request) -> BoxFuture + Send + Sync>;

/// One route: a method, a pattern and a handler.
struct Route {
    method: Method,
    segments: Vec<Segment>,
    handler: BoxHandler,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    /// A literal path segment.
    Literal(String),
    /// A capture such as `{id}`.
    Param(String),
}

fn parse_pattern(pattern: &str) -> Vec<Segment> {
    pattern
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| {
            if let Some(name) = s.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                Segment::Param(name.to_string())
            } else if let Some(name) = s.strip_prefix(':') {
                Segment::Param(name.to_string())
            } else {
                Segment::Literal(s.to_string())
            }
        })
        .collect()
}

impl Route {
    fn matches(&self, method: &Method, path: &str) -> Option<HashMap<String, String>> {
        if self.method != method {
            // A HEAD request is served by the GET handler; hyper drops the body.
            if !(method == Method::HEAD && self.method == Method::GET) {
                return None;
            }
        }

        let actual: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if actual.len() != self.segments.len() {
            return None;
        }

        let mut params = HashMap::new();
        for (segment, value) in self.segments.iter().zip(actual) {
            match segment {
                Segment::Literal(expected) if expected == value => {}
                Segment::Literal(_) => return None,
                Segment::Param(name) => {
                    params.insert(name.clone(), percent_decode(value));
                }
            }
        }
        Some(params)
    }
}

fn percent_decode(input: &str) -> String {
    percent_encoding::percent_decode_str(input)
        .decode_utf8_lossy()
        .into_owned()
}

// ============================================================================
// App
// ============================================================================

/// An HTTP application served over an onion service.
pub struct OnionApp {
    routes: Vec<Route>,
    static_dir: Option<PathBuf>,
    max_body_size: usize,
    fallback: Option<BoxHandler>,
}

impl Default for OnionApp {
    fn default() -> Self {
        Self::new()
    }
}

impl OnionApp {
    /// An app with no routes.
    pub fn new() -> Self {
        Self {
            routes: Vec::new(),
            static_dir: None,
            max_body_size: DEFAULT_MAX_BODY,
            fallback: None,
        }
    }

    /// Register a handler for a method and path pattern.
    ///
    /// Patterns may capture segments: `/users/{id}` makes `id` available via
    /// [`Request::param`].
    pub fn route<H, F>(mut self, method: Method, pattern: &str, handler: H) -> Self
    where
        H: Fn(Request) -> F + Send + Sync + 'static,
        F: Future<Output = Response> + Send + 'static,
    {
        self.routes.push(Route {
            method,
            segments: parse_pattern(pattern),
            handler: Arc::new(move |req| Box::pin(handler(req))),
        });
        self
    }

    /// Register a `GET` handler.
    pub fn get<H, F>(self, pattern: &str, handler: H) -> Self
    where
        H: Fn(Request) -> F + Send + Sync + 'static,
        F: Future<Output = Response> + Send + 'static,
    {
        self.route(Method::GET, pattern, handler)
    }

    /// Register a `POST` handler.
    pub fn post<H, F>(self, pattern: &str, handler: H) -> Self
    where
        H: Fn(Request) -> F + Send + Sync + 'static,
        F: Future<Output = Response> + Send + 'static,
    {
        self.route(Method::POST, pattern, handler)
    }

    /// Register a `PUT` handler.
    pub fn put<H, F>(self, pattern: &str, handler: H) -> Self
    where
        H: Fn(Request) -> F + Send + Sync + 'static,
        F: Future<Output = Response> + Send + 'static,
    {
        self.route(Method::PUT, pattern, handler)
    }

    /// Register a `DELETE` handler.
    pub fn delete<H, F>(self, pattern: &str, handler: H) -> Self
    where
        H: Fn(Request) -> F + Send + Sync + 'static,
        F: Future<Output = Response> + Send + 'static,
    {
        self.route(Method::DELETE, pattern, handler)
    }

    /// Handle anything no route matched.
    pub fn fallback<H, F>(mut self, handler: H) -> Self
    where
        H: Fn(Request) -> F + Send + Sync + 'static,
        F: Future<Output = Response> + Send + 'static,
    {
        self.fallback = Some(Arc::new(move |req| Box::pin(handler(req))));
        self
    }

    /// Serve files from a directory for requests no route matched.
    ///
    /// Paths are resolved and confirmed to stay inside `dir`, so `..` segments
    /// and symlinks pointing outside cannot be used to read arbitrary files.
    pub fn static_files(mut self, dir: impl Into<PathBuf>) -> Self {
        self.static_dir = Some(dir.into());
        self
    }

    /// Cap the size of an inbound request body.
    pub fn max_body_size(mut self, bytes: usize) -> Self {
        self.max_body_size = bytes;
        self
    }

    /// Launch an onion service and serve this app on it.
    ///
    /// For control over the service — a persistent state directory, hardening,
    /// client authorisation — build it yourself and use
    /// [`serve_on`](Self::serve_on).
    pub async fn serve(self, nickname: &str) -> Result<ServingApp> {
        let service = OnionServiceBuilder::new()
            .nickname(nickname)?
            .launch()
            .await?;
        self.serve_on(service).await
    }

    /// Serve this app on an already-launched onion service.
    pub async fn serve_on(self, service: OnionService) -> Result<ServingApp> {
        let address = service.onion_address().to_string();
        let app = Arc::new(self);

        let task = tokio::spawn(async move {
            let mut service = service;
            while let Some(stream) = service.accept().await {
                let app = Arc::clone(&app);

                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = hyper::service::service_fn(move |req| {
                        let app = Arc::clone(&app);
                        async move { Ok::<_, std::convert::Infallible>(app.dispatch(req).await) }
                    });

                    // hyper owns request parsing, framing, chunked bodies and
                    // keep-alive. A connection error is that client's problem
                    // and must not disturb any other.
                    if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                        debug!(error = %e, "connection closed with an error");
                    }
                });
            }
        });

        Ok(ServingApp { address, task })
    }

    async fn dispatch(&self, req: hyper::Request<Incoming>) -> hyper::Response<Full<Bytes>> {
        let (parts, body) = req.into_parts();

        let path = parts.uri.path().to_string();
        let query = parts
            .uri
            .query()
            .map(|q| {
                form_urlencoded::parse(q.as_bytes())
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect()
            })
            .unwrap_or_default();

        // Read the body with a hard cap, so a client cannot make the service
        // allocate without bound.
        let body = match read_body(body, self.max_body_size).await {
            Ok(bytes) => bytes,
            Err(response) => return response.into_hyper(),
        };

        let mut request = Request {
            method: parts.method.clone(),
            path: path.clone(),
            query,
            params: HashMap::new(),
            headers: parts.headers,
            body,
        };

        for route in &self.routes {
            if let Some(params) = route.matches(&parts.method, &path) {
                request.params = params;
                return (route.handler)(request).await.into_hyper();
            }
        }

        if let Some(dir) = &self.static_dir
            && matches!(parts.method, Method::GET | Method::HEAD)
            && let Some(response) = serve_static(dir, &path).await
        {
            return response.into_hyper();
        }

        match &self.fallback {
            Some(handler) => handler(request).await.into_hyper(),
            None => Response::not_found().into_hyper(),
        }
    }
}

async fn read_body(body: Incoming, limit: usize) -> std::result::Result<Bytes, Response> {
    use http_body_util::Limited;

    match Limited::new(body, limit).collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(_) => {
            Err(Response::status(StatusCode::PAYLOAD_TOO_LARGE).with_body("request body too large"))
        }
    }
}

/// Serve a file from `dir`, refusing anything that escapes it.
async fn serve_static(dir: &Path, request_path: &str) -> Option<Response> {
    let relative = percent_decode(request_path.trim_start_matches('/'));

    // Reject traversal before touching the filesystem. `Path::join` resolves
    // `..` lexically, so joining an attacker-controlled path is how a static
    // file handler turns into an arbitrary file read.
    let candidate = Path::new(&relative);
    if candidate.is_absolute()
        || candidate
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        debug!("refused a static path containing traversal components");
        return None;
    }

    let root = tokio::fs::canonicalize(dir).await.ok()?;
    let full = tokio::fs::canonicalize(root.join(candidate)).await.ok()?;

    // Canonicalisation resolves symlinks, so this also catches a link inside
    // the directory pointing somewhere outside it.
    if !full.starts_with(&root) {
        debug!("refused a static path resolving outside the root");
        return None;
    }

    let metadata = tokio::fs::metadata(&full).await.ok()?;
    if !metadata.is_file() {
        return None;
    }

    let content = tokio::fs::read(&full).await.ok()?;
    let mime = mime_guess::from_path(&full).first_or_octet_stream();

    Some(
        Response::status(StatusCode::OK)
            .with_content_type(mime.as_ref())
            .with_body(content),
    )
}

/// A running [`OnionApp`].
pub struct ServingApp {
    address: String,
    task: tokio::task::JoinHandle<()>,
}

impl ServingApp {
    /// The `.onion` address this app is reachable at.
    pub fn onion_address(&self) -> &str {
        &self.address
    }

    /// Serve until the service stops.
    pub async fn wait(self) -> Result<()> {
        self.task
            .await
            .map_err(|e| Error::onion(format!("the serving task failed: {e}")))
    }

    /// Stop serving.
    pub fn shutdown(self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(method: Method, pattern: &str) -> Route {
        Route {
            method,
            segments: parse_pattern(pattern),
            handler: Arc::new(|_| Box::pin(async { Response::text("ok") })),
        }
    }

    #[test]
    fn matches_literal_paths() {
        let r = route(Method::GET, "/health");
        assert!(r.matches(&Method::GET, "/health").is_some());
        assert!(r.matches(&Method::GET, "/health/").is_some());
        assert!(r.matches(&Method::POST, "/health").is_none());
        assert!(r.matches(&Method::GET, "/other").is_none());
    }

    #[test]
    fn captures_path_parameters() {
        let r = route(Method::GET, "/users/{id}/posts/{post}");
        let params = r
            .matches(&Method::GET, "/users/42/posts/hello")
            .expect("matches");
        assert_eq!(params["id"], "42");
        assert_eq!(params["post"], "hello");
    }

    #[test]
    fn percent_decodes_captured_parameters() {
        let r = route(Method::GET, "/search/{term}");
        let params = r
            .matches(&Method::GET, "/search/rust%20tor")
            .expect("matches");
        assert_eq!(params["term"], "rust tor");
    }

    #[test]
    fn segment_counts_must_agree() {
        let r = route(Method::GET, "/users/{id}");
        assert!(r.matches(&Method::GET, "/users").is_none());
        assert!(r.matches(&Method::GET, "/users/1/extra").is_none());
    }

    #[test]
    fn head_is_served_by_the_get_route() {
        let r = route(Method::GET, "/");
        assert!(r.matches(&Method::HEAD, "/").is_some());
    }

    #[test]
    fn colon_style_patterns_also_capture() {
        let r = route(Method::GET, "/users/:id");
        let params = r.matches(&Method::GET, "/users/7").expect("matches");
        assert_eq!(params["id"], "7");
    }

    #[test]
    fn header_values_containing_crlf_are_refused() {
        // Otherwise a handler echoing user input could split the response.
        let response = Response::text("body").with_header("x-echo", "value\r\nX-Injected: yes");
        assert!(response.headers.get("x-echo").is_none());
    }

    #[test]
    fn valid_headers_are_kept() {
        let response = Response::text("body").with_header("x-echo", "clean value");
        assert_eq!(
            response.headers.get("x-echo").unwrap().to_str().unwrap(),
            "clean value"
        );
    }

    #[tokio::test]
    async fn static_files_refuse_traversal() {
        let dir = std::env::temp_dir().join("hypertor-static-test");
        tokio::fs::create_dir_all(&dir).await.expect("create dir");
        tokio::fs::write(dir.join("public.txt"), b"public")
            .await
            .expect("write");

        assert!(
            serve_static(&dir, "/public.txt").await.is_some(),
            "a legitimate file must still be served"
        );

        for attack in [
            "/../../../../etc/passwd",
            "/..%2f..%2f..%2fetc/passwd",
            "/%2e%2e/%2e%2e/etc/passwd",
            "//etc/passwd",
            "/./../../etc/passwd",
        ] {
            assert!(
                serve_static(&dir, attack).await.is_none(),
                "traversal must be refused: {attack}"
            );
        }

        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn static_files_refuse_directories() {
        let dir = std::env::temp_dir().join("hypertor-static-dir-test");
        tokio::fs::create_dir_all(dir.join("sub"))
            .await
            .expect("create");
        assert!(serve_static(&dir, "/sub").await.is_none());
        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[test]
    fn json_responses_set_their_content_type() {
        let response = Response::json(&serde_json::json!({"ok": true}));
        assert_eq!(
            response.headers.get(http::header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(response.body, Bytes::from_static(br#"{"ok":true}"#));
    }
}
