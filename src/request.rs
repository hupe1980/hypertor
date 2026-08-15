//! Building and sending requests.

use std::time::Duration;

use bytes::Bytes;
use http::header::{ACCEPT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HOST, LOCATION, USER_AGENT};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri};
use tracing::debug;

use crate::body::{self, Body, Encoding};
use crate::client::TorClient;
use crate::error::{Error, Result};
use crate::isolation::IsolationToken;
use crate::redirect::{RedirectAction, RedirectPolicy, resolve, strip_sensitive_headers};
use crate::response::{Head, Response, Streaming};

/// A request under construction.
///
/// Created by [`TorClient::get`] and friends. Nothing is sent until
/// [`send`](Self::send) or [`send_streaming`](Self::send_streaming) is called.
pub struct RequestBuilder {
    client: TorClient,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
    isolation: Option<IsolationToken>,
    timeout: Option<Duration>,
    /// Deferred error from an infallible-looking setter such as `json`.
    error: Option<Error>,
}

impl RequestBuilder {
    pub(crate) fn new(client: TorClient, method: Method, uri: Uri) -> Self {
        Self {
            client,
            method,
            uri,
            headers: HeaderMap::new(),
            body: Body::empty(),
            isolation: None,
            timeout: None,
            error: None,
        }
    }

    /// Set a header, replacing any existing value.
    pub fn header<K, V>(mut self, name: K, value: V) -> Self
    where
        K: TryInto<HeaderName>,
        V: TryInto<HeaderValue>,
    {
        match (name.try_into(), value.try_into()) {
            (Ok(name), Ok(value)) => {
                self.headers.insert(name, value);
            }
            _ => {
                // Report rather than silently dropping: a missing auth header
                // that never errors is a debugging nightmare.
                self.fail(Error::invalid_request(
                    "header name or value is not valid in HTTP",
                ));
            }
        }
        self
    }

    /// Add a header, keeping any value already set for that name.
    ///
    /// [`header`](Self::header) replaces, which is what you want almost always.
    /// This is for the handful of headers that are legitimately repeated —
    /// `Accept`, `Link`, `Via` — where replacing would silently discard the
    /// earlier value.
    pub fn append_header<K, V>(mut self, name: K, value: V) -> Self
    where
        K: TryInto<HeaderName>,
        V: TryInto<HeaderValue>,
    {
        match (name.try_into(), value.try_into()) {
            (Ok(name), Ok(value)) => {
                self.headers.append(name, value);
            }
            _ => {
                self.fail(Error::invalid_request(
                    "header name or value is not valid in HTTP",
                ));
            }
        }
        self
    }

    /// Merge in several headers at once.
    ///
    /// A name present in `headers` replaces whatever this builder had for it,
    /// but repeated values of one name inside `headers` are all kept.
    pub fn headers(mut self, headers: HeaderMap) -> Self {
        merge(&mut self.headers, &headers);
        self
    }

    /// Set the request body.
    ///
    /// Accepts anything that converts into a [`Body`] — `Bytes`, `Vec<u8>`,
    /// `String` — or a [`Body`] built from a stream or a file.
    pub fn body(mut self, body: impl Into<Body>) -> Self {
        self.body = body.into();
        self
    }

    /// Serialise `value` as JSON and set `Content-Type: application/json`.
    pub fn json<T: serde::Serialize + ?Sized>(mut self, value: &T) -> Self {
        match serde_json::to_vec(value) {
            Ok(bytes) => {
                self.headers
                    .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                self.body = Body::bytes(bytes);
            }
            Err(e) => self.fail(Error::invalid_request(format!(
                "request body could not be serialised as JSON: {e}"
            ))),
        }
        self
    }

    /// Set a form-urlencoded body.
    pub fn form<K, V>(mut self, pairs: impl IntoIterator<Item = (K, V)>) -> Self
    where
        K: AsRef<str>,
        V: AsRef<str>,
    {
        self.headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        self.body = Body::bytes(body::form_encode(pairs));
        self
    }

    /// Set a `text/plain` body.
    pub fn text(mut self, text: impl Into<Bytes>) -> Self {
        self.headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        self.body = Body::bytes(text.into());
        self
    }

    /// Append query parameters to the URL.
    pub fn query<K, V>(mut self, pairs: impl IntoIterator<Item = (K, V)>) -> Self
    where
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let encoded = body::form_encode(pairs);
        if encoded.is_empty() {
            return self;
        }

        let mut parts = self.uri.clone().into_parts();
        let path = self.uri.path();
        let merged = match self.uri.query() {
            Some(existing) if !existing.is_empty() => {
                format!("{path}?{existing}&{encoded}")
            }
            _ => format!("{path}?{encoded}"),
        };

        match merged.parse() {
            Ok(pq) => {
                parts.path_and_query = Some(pq);
                match Uri::from_parts(parts) {
                    Ok(uri) => self.uri = uri,
                    Err(e) => self.fail(Error::invalid_url(format!("query parameters: {e}"))),
                }
            }
            Err(e) => self.fail(Error::invalid_url(format!("query parameters: {e}"))),
        }
        self
    }

    /// Send this request on a specific isolation group.
    ///
    /// Overrides the client-wide [`IsolationLevel`](crate::IsolationLevel).
    pub fn isolation(mut self, token: IsolationToken) -> Self {
        self.isolation = Some(token);
        self
    }

    /// Override the client's timeout for this request.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set HTTP Basic authentication.
    pub fn basic_auth(mut self, username: &str, password: &str) -> Self {
        match body::basic_auth(username, password) {
            Ok(value) => {
                self.headers.insert(http::header::AUTHORIZATION, value);
            }
            Err(e) => self.fail(e),
        }
        self
    }

    /// Set a Bearer token.
    pub fn bearer_auth(mut self, token: &str) -> Self {
        match body::bearer_auth(token) {
            Ok(value) => {
                self.headers.insert(http::header::AUTHORIZATION, value);
            }
            Err(e) => self.fail(e),
        }
        self
    }

    /// The URI this request will be sent to.
    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    /// The method this request will use.
    pub fn method(&self) -> &Method {
        &self.method
    }

    fn fail(&mut self, error: Error) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }

    /// Send the request and read the whole response into memory.
    ///
    /// The timeout covers the whole operation: circuit setup, the request,
    /// every redirect it follows, and reading the body. The body is bounded by
    /// `max_response_size`; use [`send_streaming`](Self::send_streaming) for
    /// anything larger.
    pub async fn send(self) -> Result<Response> {
        let timeout = self.effective_timeout();

        tokio::time::timeout(timeout, async move {
            self.send_streaming_inner().await?.buffered().await
        })
        .await
        .map_err(|_| Error::timeout("request", timeout))?
    }

    /// Send the request and return as soon as the response headers arrive.
    ///
    /// The body is read on demand, so a large download never has to fit in
    /// memory. The timeout covers everything up to and including the headers;
    /// reading the body afterwards is not bounded by it.
    pub async fn send_streaming(self) -> Result<Streaming> {
        let timeout = self.effective_timeout();

        tokio::time::timeout(timeout, self.send_streaming_inner())
            .await
            .map_err(|_| Error::timeout("request", timeout))?
    }

    fn effective_timeout(&self) -> Duration {
        self.timeout.unwrap_or(self.client.config().timeout)
    }

    async fn send_streaming_inner(mut self) -> Result<Streaming> {
        if let Some(error) = self.error.take() {
            return Err(error);
        }

        let config = self.client.config().clone();
        let client = self.client;
        let isolation = self.isolation;
        let headers = self.headers;

        follow_redirects(
            RequestParts {
                method: self.method,
                uri: self.uri,
                headers,
                body: self.body,
            },
            &config.redirect,
            |parts| {
                let client = &client;
                let config = &config;
                async move { send_once(client, config, isolation, parts).await }
            },
        )
        .await
    }
}

// ===========================================================================
// The redirect chain
// ===========================================================================

/// Everything about a request that a redirect can change.
pub(crate) struct RequestParts {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Body,
}

/// Drive a request through its redirect chain.
///
/// Split out from the client so the whole state machine — method rewriting,
/// header stripping, the hop limit, the onion-to-clearnet refusal — is testable
/// without a Tor connection. Redirect handling is exactly the kind of logic
/// that is easy to get subtly wrong and impossible to notice in production.
pub(crate) async fn follow_redirects<R, F, Fut>(
    mut parts: RequestParts,
    policy: &RedirectPolicy,
    send: F,
) -> Result<R>
where
    R: Head,
    F: Fn(RequestParts) -> Fut,
    Fut: Future<Output = Result<R>>,
{
    let mut hops = 0usize;

    loop {
        // A body that can only be sent once cannot survive a redirect, so send
        // a replayable copy and keep the original for the next hop.
        let replay = parts.body.try_clone();
        let sent = RequestParts {
            method: parts.method.clone(),
            uri: parts.uri.clone(),
            headers: parts.headers.clone(),
            body: std::mem::take(&mut parts.body),
        };
        let had_body = !sent.body.is_empty();

        let response = send(sent).await?;

        if !response.status().is_redirection() {
            return Ok(response);
        }

        let Some(location) = response.headers().get(LOCATION) else {
            // A 3xx without Location is not actionable; hand it back.
            return Ok(response);
        };

        let location = location
            .to_str()
            .map_err(|_| Error::http("Location header is not valid ASCII"))?;

        let Some(target) = resolve(&parts.uri, location) else {
            return Err(Error::http(format!(
                "server sent an unusable Location header: {location:?}"
            )));
        };

        match policy.evaluate(&parts.uri, &target) {
            RedirectAction::Stop => return Ok(response),
            RedirectAction::Refuse(reason) => return Err(Error::http(reason)),
            RedirectAction::Follow => {}
            RedirectAction::FollowStripped => strip_sensitive_headers(&mut parts.headers),
        }

        hops += 1;
        if hops > policy.limit() {
            return Err(Error::TooManyRedirects {
                limit: policy.limit(),
            });
        }

        // 303, and by universal convention 301/302, turn the follow-up into a
        // bodiless GET. 307/308 exist precisely to preserve the method.
        let drops_body = match response.status() {
            StatusCode::SEE_OTHER => {
                if parts.method != Method::HEAD {
                    parts.method = Method::GET;
                }
                true
            }
            StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND if parts.method == Method::POST => {
                parts.method = Method::GET;
                true
            }
            _ => false,
        };

        if drops_body {
            parts.headers.remove(CONTENT_TYPE);
            parts.headers.remove(CONTENT_LENGTH);
            parts.body = Body::empty();
        } else if had_body {
            // The method and body are preserved, so the body has to be resent.
            // A stream was consumed by the attempt above and cannot be.
            parts.body = replay.ok_or_else(|| Error::Body {
                message: format!(
                    "cannot follow a {} redirect: the request body is a stream and \
                         has already been sent. Buffer it, or use RedirectPolicy::none() \
                         and follow the redirect yourself",
                    response.status().as_u16()
                ),
                source: None,
            })?;
        }

        // The Host header belongs to the previous origin.
        parts.headers.remove(HOST);

        debug!(status = response.status().as_u16(), "following redirect");
        parts.uri = target;
    }
}

// ===========================================================================
// One request, with retries
// ===========================================================================

/// Send one request, retrying retryable failures on a new connection.
///
/// Under [`IsolationLevel::PerRequest`](crate::IsolationLevel::PerRequest) each
/// attempt also resolves to a fresh isolation token, and therefore a genuinely
/// different circuit; under the other levels the retry stays within the same
/// isolation group. See [`Config::max_retries`](crate::Config::max_retries).
async fn send_once(
    client: &TorClient,
    config: &crate::Config,
    isolation: Option<IsolationToken>,
    parts: RequestParts,
) -> Result<Streaming> {
    // A request is only safe to retry if the method is idempotent *and* the
    // body can be produced again. A stream cannot be rewound.
    let replay = parts.body.try_clone();
    let attempts = if is_idempotent(&parts.method) && replay.is_some() {
        config.max_retries + 1
    } else {
        1
    };

    let mut body = parts.body;
    let mut last_error = None;

    for attempt in 0..attempts {
        if attempt > 0 {
            debug!(attempt, "retrying on a new connection");
        }

        // Resolve isolation per attempt: under PerRequest this gives the retry a
        // genuinely different circuit, which is the entire reason a retry is
        // worth making.
        let pool = client.pool_for(client.isolation_for(&parts.uri, isolation));

        let request = build(config, &parts.method, &parts.uri, &parts.headers, body)?;

        match pool.request(request).await {
            Ok(response) => {
                // A HEAD response describes the body a GET would have returned
                // while sending none of it, so its Content-Length and
                // Content-Encoding must not be read as describing real bytes.
                return if parts.method == Method::HEAD {
                    Streaming::from_head_response(response, config.max_response_size)
                } else {
                    Streaming::from_response(response, config.max_response_size)
                };
            }
            Err(e) => {
                let error = classify(e);
                if !error.is_retryable() || attempt + 1 == attempts {
                    return Err(error);
                }
                last_error = Some(error);
                body = replay
                    .as_ref()
                    .and_then(Body::try_clone)
                    .unwrap_or_else(Body::empty);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| Error::http("request failed with no error recorded")))
}

fn build(
    config: &crate::Config,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: Body,
) -> Result<Request<Body>> {
    let mut request = Request::builder().method(method.clone()).uri(uri.clone());

    let out = request
        .headers_mut()
        .ok_or_else(|| Error::invalid_request("could not build request headers"))?;

    // Defaults first, so an explicit header below replaces rather than
    // duplicates them.
    out.insert(
        USER_AGENT,
        HeaderValue::from_str(&config.user_agent)
            .map_err(|_| Error::config("user_agent is not a valid header value"))?,
    );

    if config.compression {
        out.insert(ACCEPT_ENCODING, Encoding::accept_encoding());
    }

    merge(out, headers);

    // hyper derives Host and Content-Length from the URI and the body itself,
    // and both are forbidden in HTTP/2. Setting them by hand produced
    // duplicates.
    out.remove(HOST);
    out.remove(CONTENT_LENGTH);

    request
        .body(body)
        .map_err(|e| Error::invalid_request(e.to_string()))
}

/// Merge `from` into `into`, replacing per name but preserving repeats.
///
/// The obvious `insert` per pair is wrong: `HeaderMap` iteration yields every
/// value of a repeated name separately, so inserting each in turn keeps only
/// the last and silently drops the rest.
fn merge(into: &mut HeaderMap, from: &HeaderMap) {
    for name in from.keys() {
        into.remove(name);
    }
    for (name, value) in from.iter() {
        into.append(name.clone(), value.clone());
    }
}

/// Whether a method may be retried without changing server state.
fn is_idempotent(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE | Method::PUT | Method::DELETE
    )
}

/// Turn a hyper-util client error into ours.
///
/// Failures raised by our own connector are already `Error` values, just boxed
/// behind hyper's `dyn Error`. Recovering the original variant — rather than
/// flattening everything into a generic HTTP failure — is what keeps
/// [`Error::is_retryable`] and [`Error::is_tor`] meaningful.
fn classify(error: hyper_util::client::legacy::Error) -> Error {
    let mut source: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(&error);

    while let Some(err) = source {
        if let Some(ours) = err.downcast_ref::<Error>() {
            return ours.same_kind();
        }
        source = std::error::Error::source(err);
    }

    if error.is_connect() {
        Error::http_source("could not establish a connection", error)
    } else {
        Error::http_source("request failed", error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn idempotent_methods_are_classified_correctly() {
        assert!(is_idempotent(&Method::GET));
        assert!(is_idempotent(&Method::PUT));
        assert!(is_idempotent(&Method::DELETE));
        // Retrying a POST could charge a card twice.
        assert!(!is_idempotent(&Method::POST));
        assert!(!is_idempotent(&Method::PATCH));
    }

    // ---- header handling ---------------------------------------------------

    fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    fn values<'a>(map: &'a HeaderMap, name: &str) -> Vec<&'a str> {
        map.get_all(name)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect()
    }

    #[test]
    fn merging_preserves_repeated_values_of_one_name() {
        // Iterating a HeaderMap yields repeats separately, so `insert` per pair
        // keeps only the last — which turns "Accept: a, Accept: b" into "b".
        let mut into = HeaderMap::new();
        merge(&mut into, &header_map(&[("accept", "a"), ("accept", "b")]));
        assert_eq!(values(&into, "accept"), vec!["a", "b"]);
    }

    #[test]
    fn merging_replaces_whatever_was_there_for_that_name() {
        let mut into = header_map(&[("user-agent", "default"), ("x-keep", "yes")]);
        merge(&mut into, &header_map(&[("user-agent", "mine")]));

        assert_eq!(values(&into, "user-agent"), vec!["mine"]);
        assert_eq!(values(&into, "x-keep"), vec!["yes"], "untouched names stay");
    }

    #[test]
    fn an_explicit_user_agent_replaces_the_configured_default() {
        let config = crate::Config::default();
        let request = build(
            &config,
            &Method::GET,
            &"http://a.onion/".parse().unwrap(),
            &header_map(&[("user-agent", "mine/1.0")]),
            Body::empty(),
        )
        .expect("builds");

        assert_eq!(
            values(request.headers(), "user-agent"),
            vec!["mine/1.0"],
            "the default must not be left alongside the caller's value"
        );
    }

    #[test]
    fn appended_headers_reach_the_wire_together() {
        let config = crate::Config::default();
        let request = build(
            &config,
            &Method::GET,
            &"http://a.onion/".parse().unwrap(),
            &header_map(&[("accept", "text/plain"), ("accept", "text/html")]),
            Body::empty(),
        )
        .expect("builds");

        assert_eq!(
            values(request.headers(), "accept"),
            vec!["text/plain", "text/html"]
        );
    }

    // ---- redirect chain ----------------------------------------------------
    //
    // Driven against a scripted responder, so the state machine is exercised
    // without a Tor circuit. These are the paths where a mistake silently leaks
    // credentials or takes traffic out of the Tor network.

    /// A response head with no body, for driving `follow_redirects`.
    struct Fake {
        status: StatusCode,
        headers: HeaderMap,
    }

    impl Head for Fake {
        fn status(&self) -> StatusCode {
            self.status
        }
        fn headers(&self) -> &HeaderMap {
            &self.headers
        }
    }

    fn redirect(status: u16, location: &str) -> Fake {
        let mut headers = HeaderMap::new();
        headers.insert(LOCATION, location.parse().unwrap());
        Fake {
            status: StatusCode::from_u16(status).unwrap(),
            headers,
        }
    }

    fn ok() -> Fake {
        Fake {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
        }
    }

    /// What the transport saw for each hop.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Seen {
        method: Method,
        uri: String,
        auth: Option<String>,
        body_len: Option<u64>,
    }

    /// Run a chain against a scripted list of responses.
    async fn run(
        start: RequestParts,
        policy: &RedirectPolicy,
        script: Vec<Fake>,
    ) -> (Result<Fake>, Vec<Seen>) {
        let script = RefCell::new(script.into_iter());
        let seen = RefCell::new(Vec::new());

        let result = follow_redirects(start, policy, |parts| {
            seen.borrow_mut().push(Seen {
                method: parts.method.clone(),
                uri: parts.uri.to_string(),
                auth: parts
                    .headers
                    .get(http::header::AUTHORIZATION)
                    .map(|v| v.to_str().unwrap().to_string()),
                body_len: parts.body.len(),
            });
            let next = script.borrow_mut().next();
            async move { next.ok_or_else(|| Error::http("script exhausted")) }
        })
        .await;

        (result, seen.into_inner())
    }

    fn parts(method: Method, uri: &str) -> RequestParts {
        RequestParts {
            method,
            uri: uri.parse().unwrap(),
            headers: HeaderMap::new(),
            body: Body::empty(),
        }
    }

    fn with_auth(mut parts: RequestParts) -> RequestParts {
        parts.headers.insert(
            http::header::AUTHORIZATION,
            "Bearer secret".parse().unwrap(),
        );
        parts
    }

    #[tokio::test]
    async fn follows_a_same_origin_redirect_and_keeps_credentials() {
        let (result, seen) = run(
            with_auth(parts(Method::GET, "http://a.onion/one")),
            &RedirectPolicy::default(),
            vec![redirect(302, "/two"), ok()],
        )
        .await;

        assert_eq!(result.map(|r| r.status()).unwrap(), StatusCode::OK);
        assert_eq!(seen[1].uri, "http://a.onion/two");
        assert_eq!(seen[1].auth.as_deref(), Some("Bearer secret"));
    }

    #[tokio::test]
    async fn strips_credentials_when_the_origin_changes() {
        let (_, seen) = run(
            with_auth(parts(Method::GET, "http://a.onion/")),
            &RedirectPolicy::default(),
            vec![redirect(302, "http://b.onion/"), ok()],
        )
        .await;

        assert_eq!(
            seen[1].auth, None,
            "a bearer token was replayed to a host the caller never chose"
        );
    }

    #[tokio::test]
    async fn refuses_to_leave_the_tor_network() {
        let (result, seen) = run(
            parts(Method::GET, "http://a.onion/"),
            &RedirectPolicy::default(),
            vec![redirect(302, "https://tracker.example/")],
        )
        .await;

        assert!(result.is_err(), "onion-to-clearnet must not be followed");
        assert_eq!(seen.len(), 1, "the clearnet hop must never be sent");
    }

    #[tokio::test]
    async fn rewrites_post_to_get_on_302_and_drops_the_body() {
        let mut start = parts(Method::POST, "http://a.onion/submit");
        start.body = Body::bytes("payload");

        let (_, seen) = run(
            start,
            &RedirectPolicy::default(),
            vec![redirect(302, "/done"), ok()],
        )
        .await;

        assert_eq!(seen[0].method, Method::POST);
        assert_eq!(seen[0].body_len, Some(7));
        assert_eq!(seen[1].method, Method::GET);
        assert_eq!(seen[1].body_len, Some(0), "the body must not be resent");
    }

    #[tokio::test]
    async fn preserves_the_method_and_body_on_307() {
        let mut start = parts(Method::POST, "http://a.onion/submit");
        start.body = Body::bytes("payload");

        let (_, seen) = run(
            start,
            &RedirectPolicy::default(),
            vec![redirect(307, "/elsewhere"), ok()],
        )
        .await;

        assert_eq!(seen[1].method, Method::POST, "307 exists to preserve this");
        assert_eq!(seen[1].body_len, Some(7), "and to preserve the body");
    }

    #[tokio::test]
    async fn a_streamed_body_cannot_be_replayed_across_a_307() {
        let mut start = parts(Method::POST, "http://a.onion/upload");
        start.body = Body::from_stream(futures::stream::once(async {
            Ok::<_, std::io::Error>(Bytes::from_static(b"chunk"))
        }));

        let (result, _) = run(
            start,
            &RedirectPolicy::default(),
            vec![redirect(307, "/elsewhere"), ok()],
        )
        .await;

        // Silently sending an empty body would be far worse than an error.
        let err = result.err().expect("must refuse");
        assert!(err.to_string().contains("stream"), "unhelpful error: {err}");
    }

    #[tokio::test]
    async fn stops_at_the_hop_limit() {
        let policy = RedirectPolicy::limited(2);
        let script = (0..5).map(|i| redirect(302, &format!("/{i}"))).collect();

        let (result, seen) = run(parts(Method::GET, "http://a.onion/"), &policy, script).await;

        assert!(matches!(result, Err(Error::TooManyRedirects { limit: 2 })));
        assert_eq!(seen.len(), 3, "the initial request plus two hops");
    }

    #[tokio::test]
    async fn a_disabled_policy_returns_the_3xx_untouched() {
        let (result, seen) = run(
            parts(Method::GET, "http://a.onion/"),
            &RedirectPolicy::none(),
            vec![redirect(301, "/elsewhere")],
        )
        .await;

        assert_eq!(
            result.map(|r| r.status()).unwrap(),
            StatusCode::MOVED_PERMANENTLY
        );
        assert_eq!(seen.len(), 1);
    }

    #[tokio::test]
    async fn a_3xx_without_a_location_is_returned_as_is() {
        let (result, seen) = run(
            parts(Method::GET, "http://a.onion/"),
            &RedirectPolicy::default(),
            vec![Fake {
                status: StatusCode::FOUND,
                headers: HeaderMap::new(),
            }],
        )
        .await;

        assert_eq!(result.map(|r| r.status()).unwrap(), StatusCode::FOUND);
        assert_eq!(seen.len(), 1);
    }
}
