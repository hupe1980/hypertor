//! A small HTTP framework for onion services.
//!
//! [`OnionApp`] serves HTTP over the streams an [`OnionService`] accepts. The
//! HTTP itself is hyper's, so request parsing, chunked bodies and keep-alive
//! behave the way they do in any other hyper server.
//!
//! Both HTTP/1.1 and HTTP/2 are served on the same virtual port. There is no
//! TLS inside an onion connection — Tor already provides the encryption and
//! authentication — so there is no ALPN either, and h2c is negotiated by
//! detecting the HTTP/2 connection preface.
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
use std::convert::Infallible;
use std::future::Future;
use std::hash::{BuildHasher, RandomState};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::TryStreamExt;
use http::header::{CONTENT_LENGTH, ETAG, IF_NONE_MATCH, X_CONTENT_TYPE_OPTIONS};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use crate::error::{Error, Result};
use crate::onion_service::{OnionService, OnionServiceBuilder};

/// The body type an [`OnionApp`] hands to hyper.
///
/// Boxed because a response body is either a buffer or a file being read off
/// disk, and the second must not be materialised in memory just to be written
/// to a socket.
type ServeBody = BoxBody<Bytes, std::io::Error>;

/// Default cap on an inbound request body.
const DEFAULT_MAX_BODY: usize = 2 * 1024 * 1024;

/// Default deadline for a client to finish sending its request headers.
///
/// Without one, a client that opens a stream and then falls silent holds a
/// connection slot forever. That is the classic slowloris, and it is cheaper to
/// mount against an onion service than against a clearnet host, because the
/// attacker's address is hidden by the same network that hides yours.
const DEFAULT_HEADER_TIMEOUT: Duration = Duration::from_secs(30);

/// Default cap on connections being served at once.
const DEFAULT_MAX_CONNECTIONS: usize = 256;

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

    /// All path parameters captured by the route pattern.
    pub fn params(&self) -> &HashMap<String, String> {
        &self.params
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
pub struct Response {
    status: StatusCode,
    headers: HeaderMap,
    body: Body,
}

/// Where a response's bytes come from.
enum Body {
    /// Held in memory.
    Bytes(Bytes),
    /// Produced lazily, with its length when that is known up front.
    Stream { inner: ServeBody, len: Option<u64> },
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out = f.debug_struct("Response");
        out.field("status", &self.status)
            .field("headers", &self.headers);
        match &self.body {
            Body::Bytes(bytes) => out.field("body", bytes),
            Body::Stream { len, .. } => out.field("body_stream_len", len),
        };
        out.finish()
    }
}

impl Response {
    /// A response with the given status and an empty body.
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            body: Body::Bytes(Bytes::new()),
        }
    }

    /// The status code.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The response headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// `200 OK` with a `text/plain` body.
    pub fn text(body: impl Into<Bytes>) -> Self {
        Self::new(StatusCode::OK)
            .with_content_type("text/plain; charset=utf-8")
            .with_body(body)
    }

    /// `200 OK` with an `text/html` body.
    pub fn html(body: impl Into<Bytes>) -> Self {
        Self::new(StatusCode::OK)
            .with_content_type("text/html; charset=utf-8")
            .with_body(body)
    }

    /// `200 OK` with `value` serialised as JSON.
    ///
    /// Serialisation failures become a `500`, logged server-side, rather than a
    /// panic or a silently empty body.
    pub fn json<T: serde::Serialize + ?Sized>(value: &T) -> Self {
        match serde_json::to_vec(value) {
            Ok(bytes) => Self::new(StatusCode::OK)
                .with_content_type("application/json")
                .with_body(bytes),
            Err(e) => {
                warn!(error = %e, "handler produced unserialisable JSON");
                Self::new(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }

    /// `200 OK` with a body that is already serialised JSON.
    pub fn json_raw(body: impl Into<Bytes>) -> Self {
        Self::new(StatusCode::OK)
            .with_content_type("application/json")
            .with_body(body)
    }

    /// `404 Not Found`.
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND).with_body("not found")
    }

    /// Set the body.
    pub fn with_body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = Body::Bytes(body.into());
        self
    }

    /// Stream the body from a file, without reading it into memory.
    ///
    /// The length is read up front and sent as the `Content-Length`. Use this
    /// for anything large: an onion service that buffers whole files can be
    /// made to exhaust its own memory by a handful of concurrent requests, and
    /// the attacker's address is hidden by the same network that hides yours.
    ///
    /// The `Content-Type` is guessed from the extension; override it afterwards
    /// with [`with_content_type`](Self::with_content_type) if you know better.
    pub async fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let file = tokio::fs::File::open(path).await?;
        let len = file.metadata().await?.len();
        let mime = mime_guess::from_path(path).first_or_octet_stream();

        Ok(Self::new(StatusCode::OK)
            .with_content_type(mime.as_ref())
            .with_stream(file_body(file), Some(len)))
    }

    /// Stream the body from an arbitrary [`http_body::Body`].
    ///
    /// Pass `len` when the total is known so a `Content-Length` can be sent;
    /// otherwise the response is chunked.
    pub fn with_stream(mut self, body: ServeBody, len: Option<u64>) -> Self {
        self.body = Body::Stream { inner: body, len };
        self
    }

    /// The in-memory body, if this response holds one.
    ///
    /// `None` for a streamed body, which cannot be inspected without consuming
    /// it.
    pub fn body(&self) -> Option<&Bytes> {
        match &self.body {
            Body::Bytes(bytes) => Some(bytes),
            Body::Stream { .. } => None,
        }
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

    fn into_hyper(self) -> hyper::Response<ServeBody> {
        let mut headers = self.headers;

        let body = match self.body {
            Body::Bytes(bytes) => bytes_body(bytes),
            Body::Stream { inner, len } => {
                // hyper can only derive a Content-Length from a body whose size
                // is known exactly, which a stream's is not. Declaring it here
                // keeps a streamed file from falling back to chunked encoding.
                if let Some(len) = len {
                    headers.insert(CONTENT_LENGTH, HeaderValue::from(len));
                }
                inner
            }
        };

        let mut response = hyper::Response::new(body);
        *response.status_mut() = self.status;
        *response.headers_mut() = headers;
        response
    }
}

/// An in-memory body, in the shape hyper wants.
fn bytes_body(bytes: Bytes) -> ServeBody {
    Full::new(bytes).map_err(|e: Infallible| match e {}).boxed()
}

/// A file, read incrementally.
fn file_body(file: tokio::fs::File) -> ServeBody {
    StreamBody::new(tokio_util::io::ReaderStream::new(file).map_ok(http_body::Frame::data)).boxed()
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

/// How well one route matched a request.
#[derive(Debug, PartialEq, Eq)]
enum RouteMatch {
    /// Method and path both matched, capturing these parameters. The count is
    /// how many segments matched literally, which is how ties are broken.
    Full(HashMap<String, String>, usize),
    /// The path matched but the method did not — a `405`, not a `404`.
    PathOnly,
    /// Not this route.
    None,
}

impl Route {
    fn matches(&self, method: &Method, path: &str) -> RouteMatch {
        let actual: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if actual.len() != self.segments.len() {
            return RouteMatch::None;
        }

        let mut params = HashMap::new();
        let mut literals = 0usize;
        for (segment, value) in self.segments.iter().zip(actual) {
            match segment {
                Segment::Literal(expected) if expected == value => literals += 1,
                Segment::Literal(_) => return RouteMatch::None,
                Segment::Param(name) => {
                    params.insert(name.clone(), percent_decode(value));
                }
            }
        }

        // A HEAD request is served by the GET handler; hyper drops the body.
        if self.method == method || (method == Method::HEAD && self.method == Method::GET) {
            RouteMatch::Full(params, literals)
        } else {
            RouteMatch::PathOnly
        }
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
    header_timeout: Duration,
    max_connections: usize,
    fallback: Option<BoxHandler>,
    date_header: bool,
    /// Keys the static-file `ETag`, so it cannot be reproduced off-host.
    etag_key: RandomState,
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
            header_timeout: DEFAULT_HEADER_TIMEOUT,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            fallback: None,
            date_header: false,
            etag_key: RandomState::new(),
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

    /// How long a client may take to finish sending its request headers.
    ///
    /// Defaults to 30 seconds. Tor adds latency, so a value tuned for a
    /// clearnet server will be too tight here; setting it to zero disables the
    /// deadline entirely and re-opens the service to slowloris.
    pub fn header_timeout(mut self, timeout: Duration) -> Self {
        self.header_timeout = timeout;
        self
    }

    /// Cap the number of connections served at once.
    ///
    /// Defaults to 256. Connections beyond the cap wait rather than being
    /// refused, so a burst is smoothed instead of dropped.
    pub fn max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Send a `Date` header on every response. **Off by default.**
    ///
    /// A `Date` header publishes the server's clock, once per request, to
    /// anyone who asks. Murdoch's clock-skew attack (CCS 2006) deanonymises a
    /// hidden service by inducing load on it — which warms the quartz crystal
    /// and shifts its clock skew — and then requesting timestamps from
    /// candidate machines until one shows the matching drift. A service that
    /// answers no timestamp does not participate in that.
    ///
    /// The counter-argument is hypertor's own: behaving differently from other
    /// implementations is itself a fingerprint, and nginx and Apache both send
    /// `Date`. It is weighed differently here. At the Tor protocol layer there
    /// is a single normal behaviour to blend into, which is why
    /// [`OnionService`] answers only `BEGIN`; at the HTTP layer onion services
    /// are already wildly heterogeneous, so the blending is worth little while
    /// the clock oracle is worth a great deal.
    ///
    /// Turn it on if you are fronting something that needs RFC-conformant
    /// caching and you accept that trade.
    pub fn date_header(mut self, enabled: bool) -> Self {
        self.date_header = enabled;
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

    /// Serve this app on a single already-accepted connection.
    ///
    /// [`serve_on`](Self::serve_on) is what you want for an onion service. This
    /// is the seam underneath it: it serves one stream and returns when that
    /// stream closes, which makes an `OnionApp` usable over any transport —
    /// a Unix socket, a TCP listener during development, or an in-memory pipe
    /// in your own tests.
    ///
    /// ```rust,no_run
    /// use hypertor::{OnionApp, ServeResponse};
    ///
    /// # async fn demo() -> hypertor::Result<()> {
    /// let app = OnionApp::new().get("/", |_| async { ServeResponse::text("hi") });
    ///
    /// let (client, server) = tokio::io::duplex(64 * 1024);
    /// tokio::spawn(async move { app.serve_connection(server).await });
    /// // `client` now speaks HTTP to the app.
    /// # Ok(())
    /// # }
    /// ```
    pub async fn serve_connection<I>(self, io: I) -> Result<()>
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let header_timeout = self.header_timeout;
        let date_header = self.date_header;
        let app = Arc::new(self);

        let mut builder = auto::Builder::new(TokioExecutor::new());
        configure(&mut builder, header_timeout, date_header);

        builder
            .serve_connection(
                TokioIo::new(io),
                hyper::service::service_fn(move |req| {
                    let app = Arc::clone(&app);
                    async move { Ok::<_, std::convert::Infallible>(app.dispatch(req).await) }
                }),
            )
            .await
            .map_err(|e| Error::onion(format!("connection failed: {e}")))
    }

    /// Serve this app on an already-launched onion service.
    ///
    /// Both HTTP/1.1 and HTTP/2 are served on the same virtual port: hyper
    /// detects the HTTP/2 connection preface and switches protocol accordingly.
    /// There is no TLS and therefore no ALPN inside an onion connection — Tor
    /// already provides the encryption and authentication — so preface
    /// detection is how h2c is negotiated here.
    pub async fn serve_on(self, service: OnionService) -> Result<ServingApp> {
        let address = service.onion_address().to_string();

        let header_timeout = self.header_timeout;
        let date_header = self.date_header;
        let permits = Arc::new(Semaphore::new(self.max_connections));
        let app = Arc::new(self);

        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();

        let task = tokio::spawn(async move {
            let graceful = GracefulShutdown::new();
            let mut service = service;

            let mut builder = auto::Builder::new(TokioExecutor::new());
            configure(&mut builder, header_timeout, date_header);
            let builder = Arc::new(builder);

            loop {
                let stream = tokio::select! {
                    biased;
                    _ = &mut stop_rx => break,
                    stream = service.accept() => match stream {
                        Some(stream) => stream,
                        None => break,
                    },
                };

                // Also racing the stop signal: at the connection cap this waits
                // for a slot, and a shutdown requested in that window used to be
                // ignored until some client happened to disconnect.
                let permit = tokio::select! {
                    biased;
                    _ = &mut stop_rx => break,
                    permit = Arc::clone(&permits).acquire_owned() => match permit {
                        Ok(permit) => permit,
                        Err(_) => break,
                    },
                };

                let app = Arc::clone(&app);
                let builder = Arc::clone(&builder);
                let connection = builder.serve_connection(
                    TokioIo::new(stream),
                    hyper::service::service_fn(move |req| {
                        let app = Arc::clone(&app);
                        async move { Ok::<_, std::convert::Infallible>(app.dispatch(req).await) }
                    }),
                );

                // Watched, so a shutdown lets in-flight requests finish instead
                // of cutting them off mid-response.
                let watched = graceful.watch(connection.into_owned());

                tokio::spawn(async move {
                    let _permit = permit;
                    // A connection error is that client's problem and must not
                    // disturb any other.
                    if let Err(e) = watched.await {
                        debug!(error = %e, "connection closed with an error");
                    }
                });
            }

            // Bounded, so a client holding a connection open cannot stop the
            // service from ever exiting.
            tokio::select! {
                _ = graceful.shutdown() => debug!("all connections finished"),
                _ = tokio::time::sleep(Duration::from_secs(10)) => {
                    debug!("giving up on connections that would not finish")
                }
            }
        });

        Ok(ServingApp {
            address,
            task,
            stop: Some(stop_tx),
        })
    }

    /// Route one request.
    ///
    /// Generic over the body type so the whole pipeline — matching, `405`
    /// handling, body limits, static files — can be tested without an onion
    /// service; `Incoming` cannot be constructed outside hyper.
    async fn dispatch<B>(&self, req: hyper::Request<B>) -> hyper::Response<ServeBody>
    where
        B: http_body::Body<Data = Bytes>,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
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

        // Match before reading the body: a request to a path that does not
        // exist should not be allowed to make the service buffer megabytes
        // first.
        let matched = self.match_route(&parts.method, &path);

        if let Match::MethodNotAllowed(allowed) = &matched {
            return Response::new(StatusCode::METHOD_NOT_ALLOWED)
                .with_header(http::header::ALLOW, &allowed.join(", "))
                .with_body("method not allowed")
                .into_hyper();
        }

        // Static files never have a request body worth reading.
        if matches!(matched, Match::None)
            && let Some(dir) = &self.static_dir
            && matches!(parts.method, Method::GET | Method::HEAD)
            && let Some(response) = serve_static(
                dir,
                &path,
                &parts.headers,
                parts.method == Method::HEAD,
                &self.etag_key,
            )
            .await
        {
            return response.into_hyper();
        }

        // Read the body with a hard cap, so a client cannot make the service
        // allocate without bound.
        let body = match read_body(body, self.max_body_size).await {
            Ok(bytes) => bytes,
            Err(response) => return response.into_hyper(),
        };

        let mut request = Request {
            method: parts.method,
            path,
            query,
            params: HashMap::new(),
            headers: parts.headers,
            body,
        };

        match matched {
            Match::Route(index, params) => {
                request.params = params;
                (self.routes[index].handler)(request).await.into_hyper()
            }
            Match::MethodNotAllowed(_) => unreachable!("handled above"),
            Match::None => match &self.fallback {
                Some(handler) => handler(request).await.into_hyper(),
                None => Response::not_found().into_hyper(),
            },
        }
    }

    /// Find the route for a request, distinguishing "no such path" from
    /// "wrong method for this path".
    ///
    /// Where several routes match, the one matching the most segments
    /// *literally* wins. Registration order deciding it instead is the classic
    /// router footgun: `/users/{id}` registered first would swallow every
    /// request to `/users/me`, and the only symptom is a handler that is never
    /// called.
    fn match_route(&self, method: &Method, path: &str) -> Match {
        let mut allowed: Vec<String> = Vec::new();
        let mut best: Option<(usize, HashMap<String, String>, usize)> = None;

        for (index, route) in self.routes.iter().enumerate() {
            match route.matches(method, path) {
                RouteMatch::Full(params, literals) => {
                    if best.as_ref().is_none_or(|(_, _, best)| literals > *best) {
                        best = Some((index, params, literals));
                    }
                }
                RouteMatch::PathOnly => {
                    let name = route.method.as_str().to_string();
                    if !allowed.contains(&name) {
                        allowed.push(name);
                    }
                }
                RouteMatch::None => {}
            }
        }

        if let Some((index, params, _)) = best {
            return Match::Route(index, params);
        }

        if allowed.is_empty() {
            Match::None
        } else {
            // A 404 here would tell the client the path does not exist, which
            // is false and makes the API harder to use than it needs to be.
            //
            // `Allow` lists what the resource actually serves. HEAD is included
            // because a GET route answers it; OPTIONS is not, because nothing
            // handles it unless the app registered a route for it.
            if allowed.iter().any(|m| m == "GET") && !allowed.iter().any(|m| m == "HEAD") {
                allowed.push("HEAD".to_string());
            }
            Match::MethodNotAllowed(allowed)
        }
    }
}

/// Apply hypertor's server defaults to a hyper connection builder.
///
/// The timer is not optional: hyper *panics* when a read timeout is configured
/// without one, so forgetting it would take down the service on its first
/// connection rather than degrading gracefully.
fn configure(
    builder: &mut auto::Builder<TokioExecutor>,
    header_timeout: Duration,
    date_header: bool,
) {
    builder.http1().timer(TokioTimer::new());
    builder.http2().timer(TokioTimer::new());

    // See `OnionApp::date_header`: a timestamp on every response is the oracle
    // a clock-skew attack reads.
    if !date_header {
        builder.http1().auto_date_header(false);
        builder.http2().auto_date_header(false);
    }

    if !header_timeout.is_zero() {
        builder.http1().header_read_timeout(header_timeout);
    }
}

/// The outcome of matching a request against every route.
enum Match {
    /// Route index, and the captured path parameters.
    Route(usize, HashMap<String, String>),
    /// The path exists but not for this method; these methods are allowed.
    MethodNotAllowed(Vec<String>),
    /// No route claimed this path.
    None,
}

async fn read_body<B>(body: B, limit: usize) -> std::result::Result<Bytes, Response>
where
    B: http_body::Body<Data = Bytes>,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    use http_body_util::Limited;

    match Limited::new(body, limit).collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(_) => {
            Err(Response::new(StatusCode::PAYLOAD_TOO_LARGE).with_body("request body too large"))
        }
    }
}

/// Serve a file from `dir`, refusing anything that escapes it.
///
/// The body is streamed off disk rather than buffered: an onion service that
/// read whole files into memory could be made to exhaust it by a handful of
/// concurrent requests, and over Tor the requester's address is hidden by the
/// same network that hides the operator's.
async fn serve_static(
    dir: &Path,
    request_path: &str,
    request_headers: &HeaderMap,
    head_only: bool,
    etag_key: &RandomState,
) -> Option<Response> {
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
    let mut full = tokio::fs::canonicalize(root.join(candidate)).await.ok()?;

    // Canonicalisation resolves symlinks, so this also catches a link inside
    // the directory pointing somewhere outside it.
    if !full.starts_with(&root) {
        debug!("refused a static path resolving outside the root");
        return None;
    }

    let mut metadata = tokio::fs::metadata(&full).await.ok()?;

    // A directory serves its index. Listing its contents instead would leak
    // filenames the operator never chose to publish.
    if metadata.is_dir() {
        full = tokio::fs::canonicalize(full.join("index.html"))
            .await
            .ok()?;
        if !full.starts_with(&root) {
            return None;
        }
        metadata = tokio::fs::metadata(&full).await.ok()?;
    }

    if !metadata.is_file() {
        return None;
    }

    let etag = etag_for(etag_key, &metadata);
    let mime = mime_guess::from_path(&full).first_or_octet_stream();

    // A conditional request that already has this version costs one small
    // response instead of the whole file. Bandwidth is the scarce resource on
    // an onion circuit, so this is worth more here than on the clearnet.
    if let Some(etag) = &etag
        && if_none_match_satisfied(request_headers, etag)
    {
        return Some(Response::new(StatusCode::NOT_MODIFIED).with_header(ETAG, etag));
    }

    // The content type is guessed from the extension, so a browser must not be
    // allowed to second-guess it: sniffing turns an uploaded `.txt` into script.
    let mut response = Response::new(StatusCode::OK)
        .with_content_type(mime.as_ref())
        .with_header(X_CONTENT_TYPE_OPTIONS, "nosniff");
    if let Some(etag) = &etag {
        response = response.with_header(ETAG, etag);
    }

    // A HEAD answer must carry the same metadata as the GET but none of the
    // bytes, so the file is never opened at all.
    if head_only {
        return Some(response.with_header(CONTENT_LENGTH, &metadata.len().to_string()));
    }

    let file = tokio::fs::File::open(&full).await.ok()?;
    Some(response.with_stream(file_body(file), Some(metadata.len())))
}

/// A validator for a file, keyed to this process.
///
/// # Why not the usual `mtime-size` validator
///
/// nginx and every other static file server builds an `ETag` out of the file's
/// modification time and size, in the clear. For an onion service that is a
/// deanonymisation aid on two counts, and OnionScan's survey of the dark web
/// found `ETag` and `Last-Modified` among the headers most useful for matching
/// a hidden service to the ordinary host serving the same files:
///
/// - it is **reproducible from the file**, so an attacker holding a candidate
///   clearnet server can confirm the two are the same machine by comparing
///   validators;
/// - it **contains a timestamp**, and Murdoch's clock-skew attack (CCS 2006)
///   works precisely by inducing load on a hidden service and then asking
///   candidate servers for timestamps to match the resulting skew.
///
/// Hashing `(mtime, len)` under a key generated when the app starts keeps the
/// validator doing its job — it still changes exactly when the file changes —
/// while making it useless to anyone who does not hold the key. `RandomState`
/// is SipHash with a per-instance random key, so the input cannot be recovered
/// from the output and two services serving identical files publish unrelated
/// validators.
///
/// The cost is that validators change when the process restarts, so caches
/// revalidate once afterwards. That is a fair price, and no `Last-Modified` is
/// sent at all.
fn etag_for(key: &RandomState, metadata: &std::fs::Metadata) -> Option<String> {
    let modified = metadata
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;

    let validator = key.hash_one((modified.as_secs(), modified.subsec_nanos(), metadata.len()));
    Some(format!("\"{validator:016x}\""))
}

/// Whether an `If-None-Match` header covers `etag`, per RFC 9110 §13.1.2.
///
/// Every line of the field is considered: RFC 9110 §5.2 makes repeated field
/// lines equivalent to one comma-joined line, and reading only the first would
/// resend an unchanged file — over a Tor circuit, where bandwidth is the scarce
/// resource — to any client that happens to spell the field over two lines.
fn if_none_match_satisfied(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get_all(IF_NONE_MATCH)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|value| {
            value.trim() == "*"
                || value.split(',').any(|candidate| {
                    // Comparison is weak here, so `W/"x"` and `"x"` are the
                    // same validator.
                    candidate
                        .trim()
                        .strip_prefix("W/")
                        .unwrap_or(candidate.trim())
                        == etag
                })
        })
}

/// A running [`OnionApp`].
pub struct ServingApp {
    address: String,
    task: tokio::task::JoinHandle<()>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl ServingApp {
    /// The `.onion` address this app is reachable at.
    pub fn onion_address(&self) -> &str {
        &self.address
    }

    /// Whether the service has stopped serving.
    ///
    /// Useful for supervising the service from a loop that has other work to
    /// do — a signal check, a health probe — rather than parking on
    /// [`wait`](Self::wait).
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    /// Serve until the service stops.
    pub async fn wait(self) -> Result<()> {
        self.task
            .await
            .map_err(|e| Error::onion(format!("the serving task failed: {e}")))
    }

    /// Stop accepting new connections and let in-flight requests finish.
    ///
    /// Returns once every connection has closed, or after ten seconds — a
    /// client is not allowed to keep the service alive indefinitely by never
    /// finishing its request.
    pub async fn shutdown(mut self) -> Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.wait().await
    }

    /// Stop serving immediately, dropping connections mid-response.
    ///
    /// Prefer [`shutdown`](Self::shutdown) unless you need the process gone
    /// now.
    pub fn abort(self) {
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

    fn params(m: RouteMatch) -> HashMap<String, String> {
        match m {
            RouteMatch::Full(params, _) => params,
            other => panic!("expected a full match, got {other:?}"),
        }
    }

    // ---- routing -----------------------------------------------------------

    #[test]
    fn matches_literal_paths() {
        let r = route(Method::GET, "/health");
        assert!(matches!(
            r.matches(&Method::GET, "/health"),
            RouteMatch::Full(..)
        ));
        assert!(matches!(
            r.matches(&Method::GET, "/health/"),
            RouteMatch::Full(..)
        ));
        assert_eq!(r.matches(&Method::POST, "/health"), RouteMatch::PathOnly);
        assert_eq!(r.matches(&Method::GET, "/other"), RouteMatch::None);
    }

    #[test]
    fn captures_path_parameters() {
        let r = route(Method::GET, "/users/{id}/posts/{post}");
        let params = params(r.matches(&Method::GET, "/users/42/posts/hello"));
        assert_eq!(params["id"], "42");
        assert_eq!(params["post"], "hello");
    }

    #[test]
    fn percent_decodes_captured_parameters() {
        let r = route(Method::GET, "/search/{term}");
        let params = params(r.matches(&Method::GET, "/search/rust%20tor"));
        assert_eq!(params["term"], "rust tor");
    }

    #[test]
    fn segment_counts_must_agree() {
        let r = route(Method::GET, "/users/{id}");
        assert_eq!(r.matches(&Method::GET, "/users"), RouteMatch::None);
        assert_eq!(r.matches(&Method::GET, "/users/1/extra"), RouteMatch::None);
    }

    #[test]
    fn head_is_served_by_the_get_route() {
        let r = route(Method::GET, "/");
        assert!(matches!(
            r.matches(&Method::HEAD, "/"),
            RouteMatch::Full(..)
        ));
    }

    #[test]
    fn colon_style_patterns_also_capture() {
        let r = route(Method::GET, "/users/:id");
        let params = params(r.matches(&Method::GET, "/users/7"));
        assert_eq!(params["id"], "7");
    }

    // ---- dispatch ----------------------------------------------------------

    fn app() -> OnionApp {
        OnionApp::new()
            .get("/", |_| async { Response::text("root") })
            .get("/users/{id}", |req| async move {
                Response::text(req.param("id").unwrap_or_default().to_string())
            })
            .post("/users", |req| async move {
                Response::json(&serde_json::json!({ "len": req.body().len() }))
            })
    }

    async fn call(
        app: &OnionApp,
        method: Method,
        path: &str,
        body: &[u8],
    ) -> hyper::Response<ServeBody> {
        let request = hyper::Request::builder()
            .method(method)
            .uri(path)
            .body(Full::new(Bytes::copy_from_slice(body)))
            .expect("valid request");
        app.dispatch(request).await
    }

    async fn body_of(response: hyper::Response<ServeBody>) -> Bytes {
        response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes()
    }

    #[tokio::test]
    async fn dispatches_to_the_matching_route() {
        let response = call(&app(), Method::GET, "/users/42", b"").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(&body_of(response).await[..], b"42");
    }

    #[tokio::test]
    async fn a_literal_route_wins_over_a_parameter_that_was_registered_first() {
        // Registration order deciding this is the classic router footgun:
        // `/users/me` would never be reached, and nothing would say so.
        let app = OnionApp::new()
            .get("/users/{id}", |_| async { Response::text("by id") })
            .get("/users/me", |_| async { Response::text("me") });

        let response = call(&app, Method::GET, "/users/me", b"").await;
        assert_eq!(&body_of(response).await[..], b"me");

        let response = call(&app, Method::GET, "/users/42", b"").await;
        assert_eq!(&body_of(response).await[..], b"by id");
    }

    #[tokio::test]
    async fn an_unknown_path_is_a_404() {
        let response = call(&app(), Method::GET, "/nope", b"").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_known_path_with_the_wrong_method_is_a_405() {
        // A 404 here would claim the path does not exist, which is a lie and
        // sends the caller looking in the wrong place.
        let response = call(&app(), Method::DELETE, "/users/42", b"").await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

        let allow = response
            .headers()
            .get(http::header::ALLOW)
            .expect("RFC 9110 requires Allow on a 405")
            .to_str()
            .unwrap()
            .to_string();
        assert!(allow.contains("GET"), "got: {allow}");
        assert!(allow.contains("HEAD"), "got: {allow}");
    }

    #[tokio::test]
    async fn an_oversized_body_is_a_413() {
        let app = app().max_body_size(8);
        let response = call(&app, Method::POST, "/users", &[b'x'; 64]).await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn a_body_within_the_limit_reaches_the_handler() {
        let app = app().max_body_size(64);
        let response = call(&app, Method::POST, "/users", b"hello").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(&body_of(response).await[..], br#"{"len":5}"#);
    }

    #[tokio::test]
    async fn the_fallback_catches_unrouted_paths() {
        let app = app().fallback(|_| async { Response::new(StatusCode::IM_A_TEAPOT) });
        let response = call(&app, Method::GET, "/anything", b"").await;
        assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
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

    // ---- static files ------------------------------------------------------

    /// A scratch directory, removed when the guard drops.
    struct Scratch(PathBuf);

    impl Scratch {
        async fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(name);
            tokio::fs::remove_dir_all(&dir).await.ok();
            tokio::fs::create_dir_all(&dir).await.expect("create dir");
            Self(dir)
        }

        async fn write(&self, path: &str, contents: &[u8]) {
            let full = self.0.join(path);
            if let Some(parent) = full.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .expect("create parent");
            }
            tokio::fs::write(full, contents).await.expect("write");
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    /// Serve a static path with no conditional headers.
    async fn statically(dir: &Path, path: &str) -> Option<Response> {
        serve_static(dir, path, &HeaderMap::new(), false, &RandomState::new()).await
    }

    /// Read a response's body, whether it is buffered or streamed.
    async fn drain(response: Response) -> Bytes {
        response
            .into_hyper()
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes()
    }

    #[tokio::test]
    async fn static_files_refuse_traversal() {
        let dir = Scratch::new("hypertor-static-test").await;
        dir.write("public.txt", b"public").await;

        assert!(
            statically(&dir.0, "/public.txt").await.is_some(),
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
                statically(&dir.0, attack).await.is_none(),
                "traversal must be refused: {attack}"
            );
        }
    }

    #[tokio::test]
    async fn a_directory_without_an_index_is_not_listed() {
        // Listing would publish filenames the operator never chose to expose.
        let dir = Scratch::new("hypertor-static-dir-test").await;
        dir.write("sub/secret.txt", b"x").await;

        assert!(statically(&dir.0, "/sub").await.is_none());
    }

    #[tokio::test]
    async fn a_directory_serves_its_index() {
        let dir = Scratch::new("hypertor-static-index-test").await;
        dir.write("sub/index.html", b"<h1>hi</h1>").await;

        let response = statically(&dir.0, "/sub").await.expect("serves the index");
        assert_eq!(
            response.headers.get(http::header::CONTENT_TYPE).unwrap(),
            "text/html"
        );
        assert_eq!(&drain(response).await[..], b"<h1>hi</h1>");
    }

    #[tokio::test]
    async fn a_static_file_is_streamed_rather_than_buffered() {
        // Buffering is how a handful of concurrent requests for a large file
        // exhaust an onion service's memory.
        let dir = Scratch::new("hypertor-static-stream-test").await;
        dir.write("big.bin", &vec![b'x'; 128 * 1024]).await;

        let response = statically(&dir.0, "/big.bin").await.expect("serves");
        assert!(
            response.body().is_none(),
            "the file must not have been read into memory"
        );

        let hyper = response.into_hyper();
        assert_eq!(
            hyper.headers().get(CONTENT_LENGTH).unwrap(),
            "131072",
            "a streamed body still has to declare its length"
        );
        let body = hyper.into_body().collect().await.expect("body").to_bytes();
        assert_eq!(body.len(), 128 * 1024);
    }

    #[tokio::test]
    async fn a_matching_if_none_match_gets_a_304_and_no_body() {
        let dir = Scratch::new("hypertor-static-etag-test").await;
        dir.write("page.html", b"<p>hello</p>").await;

        let key = RandomState::new();
        let first = serve_static(&dir.0, "/page.html", &HeaderMap::new(), false, &key)
            .await
            .expect("serves");
        let etag = first
            .headers
            .get(ETAG)
            .expect("a static file must carry a validator")
            .to_str()
            .unwrap()
            .to_string();

        let mut conditional = HeaderMap::new();
        conditional.insert(IF_NONE_MATCH, etag.parse().unwrap());

        let second = serve_static(&dir.0, "/page.html", &conditional, false, &key)
            .await
            .expect("serves");

        assert_eq!(second.status, StatusCode::NOT_MODIFIED);
        assert!(
            drain(second).await.is_empty(),
            "a 304 must not resend the body over a Tor circuit"
        );
    }

    #[tokio::test]
    async fn the_etag_leaks_neither_the_mtime_nor_the_size() {
        // OnionScan's dark-web survey found `ETag` among the headers most
        // useful for matching a hidden service to the ordinary host serving the
        // same files, and the usual `mtime-size` validator is reproducible by
        // anyone holding a copy of the file.
        let dir = Scratch::new("hypertor-static-etag-opaque-test").await;
        dir.write("page.html", b"<p>hello</p>").await;

        let metadata = tokio::fs::metadata(dir.0.join("page.html"))
            .await
            .expect("stat");
        let mtime = metadata
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();

        let response = statically(&dir.0, "/page.html").await.expect("serves");
        let etag = response.headers.get(ETAG).unwrap().to_str().unwrap();

        // The property is *derivability*, not the absence of some substring:
        // what must not hold is that an attacker with a copy of the file can
        // compute the validator. So compare against the validator nginx and
        // friends would have produced from exactly that information.
        let reproducible = format!(
            "\"{:x}-{:x}-{:x}\"",
            mtime.as_secs(),
            mtime.subsec_nanos(),
            metadata.len()
        );
        assert_ne!(
            etag, reproducible,
            "the validator is the usual mtime-size one, which anyone holding a \
             copy of the file can recompute"
        );
    }

    #[tokio::test]
    async fn one_service_keeps_the_same_validator_for_an_unchanged_file() {
        // Keying the validator must not break what it is for: a client that
        // revalidates has to get its 304.
        let dir = Scratch::new("hypertor-static-etag-stable-test").await;
        dir.write("page.html", b"<p>hello</p>").await;

        let key = RandomState::new();
        let read = async |key: &RandomState| {
            serve_static(&dir.0, "/page.html", &HeaderMap::new(), false, key)
                .await
                .expect("serves")
                .headers
                .get(ETAG)
                .expect("validator")
                .to_str()
                .unwrap()
                .to_string()
        };

        assert_eq!(read(&key).await, read(&key).await);
    }

    #[tokio::test]
    async fn two_services_publish_unrelated_validators_for_one_file() {
        // Otherwise the same file served from a .onion and from a clearnet host
        // announces that the two are the same machine.
        let dir = Scratch::new("hypertor-static-etag-distinct-test").await;
        dir.write("page.html", b"<p>hello</p>").await;

        let one = serve_static(
            &dir.0,
            "/page.html",
            &HeaderMap::new(),
            false,
            &RandomState::new(),
        )
        .await
        .expect("serves");
        let two = serve_static(
            &dir.0,
            "/page.html",
            &HeaderMap::new(),
            false,
            &RandomState::new(),
        )
        .await
        .expect("serves");

        assert_ne!(one.headers.get(ETAG), two.headers.get(ETAG));
    }

    #[tokio::test]
    async fn static_files_forbid_content_type_sniffing() {
        let dir = Scratch::new("hypertor-static-nosniff-test").await;
        dir.write("note.txt", b"not html").await;

        let response = statically(&dir.0, "/note.txt").await.expect("serves");
        assert_eq!(
            response.headers.get(X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff"
        );
    }

    #[test]
    fn if_none_match_is_read_across_every_header_line() {
        // RFC 9110 §5.2: repeated field lines mean the comma-joined value.
        // Reading only the first would resend an unchanged file — over a Tor
        // circuit, where bandwidth is the scarce resource — to any client that
        // happens to spell the field over two lines.
        let mut headers = HeaderMap::new();
        headers.append(IF_NONE_MATCH, "\"other\"".parse().unwrap());
        headers.append(IF_NONE_MATCH, "\"wanted\"".parse().unwrap());

        assert!(if_none_match_satisfied(&headers, "\"wanted\""));
        assert!(!if_none_match_satisfied(&headers, "\"absent\""));
    }

    #[test]
    fn if_none_match_compares_weakly_and_honours_a_wildcard() {
        let mut headers = HeaderMap::new();
        headers.insert(IF_NONE_MATCH, "W/\"tagged\", \"other\"".parse().unwrap());
        assert!(
            if_none_match_satisfied(&headers, "\"tagged\""),
            "W/\"x\" and \"x\" are the same validator under weak comparison"
        );

        let mut wildcard = HeaderMap::new();
        wildcard.insert(IF_NONE_MATCH, "*".parse().unwrap());
        assert!(if_none_match_satisfied(&wildcard, "\"anything\""));

        assert!(
            !if_none_match_satisfied(&HeaderMap::new(), "\"x\""),
            "an absent field conditions nothing"
        );
    }

    #[tokio::test]
    async fn a_stale_if_none_match_gets_the_file() {
        let dir = Scratch::new("hypertor-static-stale-test").await;
        dir.write("page.html", b"<p>hello</p>").await;

        let mut stale = HeaderMap::new();
        stale.insert(IF_NONE_MATCH, "\"something-else\"".parse().unwrap());

        let response = serve_static(&dir.0, "/page.html", &stale, false, &RandomState::new())
            .await
            .expect("serves");
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(&drain(response).await[..], b"<p>hello</p>");
    }

    #[tokio::test]
    async fn a_head_request_never_opens_the_file() {
        let dir = Scratch::new("hypertor-static-head-test").await;
        dir.write("page.html", b"<p>hello</p>").await;

        let response = serve_static(
            &dir.0,
            "/page.html",
            &HeaderMap::new(),
            true,
            &RandomState::new(),
        )
        .await
        .expect("serves");

        assert_eq!(
            response.headers.get(CONTENT_LENGTH).unwrap(),
            "12",
            "HEAD must report the length it would have sent"
        );
        assert!(drain(response).await.is_empty());
    }

    // ---- responses ---------------------------------------------------------

    #[test]
    fn json_responses_set_their_content_type() {
        let response = Response::json(&serde_json::json!({"ok": true}));
        assert_eq!(
            response.headers.get(http::header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            response.body().unwrap(),
            &Bytes::from_static(br#"{"ok":true}"#)
        );
    }
}
