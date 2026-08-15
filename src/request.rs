//! Building and sending requests.

use std::time::Duration;

use bytes::Bytes;
use http::header::{ACCEPT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HOST, LOCATION, USER_AGENT};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri};
use tracing::debug;

use crate::body::{self, Encoding};
use crate::client::TorClient;
use crate::error::{Error, Result};
use crate::isolation::IsolationToken;
use crate::redirect::{RedirectAction, resolve, strip_sensitive_headers};
use crate::response::Response;

/// The body type carried through hyper.
pub(crate) type RequestBody = http_body_util::Full<Bytes>;

/// A request under construction.
///
/// Created by [`TorClient::get`] and friends. Nothing is sent until
/// [`send`](Self::send) is called.
pub struct RequestBuilder {
    client: TorClient,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
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
            body: Bytes::new(),
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

    /// Merge in several headers at once.
    pub fn headers(mut self, headers: HeaderMap) -> Self {
        for (name, value) in headers.iter() {
            self.headers.insert(name.clone(), value.clone());
        }
        self
    }

    /// Set a raw body.
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }

    /// Serialise `value` as JSON and set `Content-Type: application/json`.
    pub fn json<T: serde::Serialize + ?Sized>(mut self, value: &T) -> Self {
        match serde_json::to_vec(value) {
            Ok(bytes) => {
                self.headers
                    .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                self.body = Bytes::from(bytes);
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
        self.body = Bytes::from(body::form_encode(pairs));
        self
    }

    /// Set a `text/plain` body.
    pub fn text(mut self, text: impl Into<Bytes>) -> Self {
        self.headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        self.body = text.into();
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

    /// Send the request and read the response.
    ///
    /// The client's timeout covers the whole operation: circuit setup, the
    /// request, every redirect it follows and reading the body.
    pub async fn send(self) -> Result<Response> {
        let timeout = self.timeout.unwrap_or(self.client.config().timeout);

        tokio::time::timeout(timeout, self.send_inner())
            .await
            .map_err(|_| Error::timeout("request", timeout))?
    }

    async fn send_inner(mut self) -> Result<Response> {
        if let Some(error) = self.error.take() {
            return Err(error);
        }

        let config = self.client.config().clone();
        let mut uri = self.uri.clone();
        let mut method = self.method.clone();
        let mut headers = self.headers.clone();
        let mut body = self.body.clone();
        let mut redirects = 0usize;

        loop {
            let response = self
                .send_once(&method, &uri, &headers, body.clone())
                .await?;

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

            let Some(target) = resolve(&uri, location) else {
                return Err(Error::http(format!(
                    "server sent an unusable Location header: {location:?}"
                )));
            };

            match config.redirect.evaluate(&uri, &target) {
                RedirectAction::Stop => return Ok(response),
                RedirectAction::Refuse(reason) => return Err(Error::http(reason)),
                RedirectAction::Follow => {}
                RedirectAction::FollowStripped => strip_sensitive_headers(&mut headers),
            }

            redirects += 1;
            if redirects > config.redirect.limit() {
                return Err(Error::TooManyRedirects {
                    limit: config.redirect.limit(),
                });
            }

            // 303, and by universal convention 301/302, turn the follow-up into
            // a bodiless GET. 307/308 exist precisely to preserve the method.
            match response.status() {
                StatusCode::SEE_OTHER => {
                    if method != Method::HEAD {
                        method = Method::GET;
                    }
                    body = Bytes::new();
                    headers.remove(CONTENT_TYPE);
                    headers.remove(CONTENT_LENGTH);
                }
                StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND if method == Method::POST => {
                    method = Method::GET;
                    body = Bytes::new();
                    headers.remove(CONTENT_TYPE);
                    headers.remove(CONTENT_LENGTH);
                }
                _ => {}
            }

            // The Host header belongs to the previous origin.
            headers.remove(HOST);

            debug!(status = response.status().as_u16(), "following redirect");
            uri = target;
        }
    }

    /// Send one request, retrying retryable failures on a fresh circuit.
    async fn send_once(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        body: Bytes,
    ) -> Result<Response> {
        let config = self.client.config();
        let idempotent = is_idempotent(method);
        let attempts = if idempotent {
            config.max_retries + 1
        } else {
            1
        };

        let mut last_error = None;

        for attempt in 0..attempts {
            if attempt > 0 {
                debug!(attempt, "retrying on a fresh circuit");
            }

            // Resolve isolation per attempt: under PerRequest this gives the
            // retry a genuinely different circuit, which is the entire reason a
            // retry is worth making.
            let isolation = self.client.isolation_for(uri, self.isolation);
            let pool = self.client.pool_for(isolation);

            let request = self.build(method, uri, headers, body.clone())?;

            match pool.request(request).await {
                Ok(response) => {
                    return Response::read(response, config.max_response_size).await;
                }
                Err(e) => {
                    let error = classify(e);
                    if !error.is_retryable() || attempt + 1 == attempts {
                        return Err(error);
                    }
                    last_error = Some(error);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| Error::http("request failed with no error recorded")))
    }

    fn build(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        body: Bytes,
    ) -> Result<Request<RequestBody>> {
        let config = self.client.config();
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

        for (name, value) in headers.iter() {
            out.insert(name.clone(), value.clone());
        }

        // hyper derives Host and Content-Length itself for HTTP/1.1, and they
        // are forbidden in HTTP/2. Setting them by hand produced duplicates.
        out.remove(HOST);
        if body.is_empty() {
            out.remove(CONTENT_LENGTH);
        }

        request
            .body(RequestBody::new(body))
            .map_err(|e| Error::invalid_request(e.to_string()))
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

    #[test]
    fn idempotent_methods_are_classified_correctly() {
        assert!(is_idempotent(&Method::GET));
        assert!(is_idempotent(&Method::PUT));
        assert!(is_idempotent(&Method::DELETE));
        // Retrying a POST could charge a card twice.
        assert!(!is_idempotent(&Method::POST));
        assert!(!is_idempotent(&Method::PATCH));
    }
}
