//! HTTP Request builder
//!
//! Provides a fluent API for constructing HTTP requests with
//! automatic header sanitization and security defaults.

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Uri, header};

use crate::body::{self, Body as EncodedBody};
use crate::client::TorClient;
use crate::compression::Compression;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::isolation::IsolationToken;
use crate::response::Response;

/// Builder for HTTP requests
pub struct RequestBuilder<'a> {
    client: &'a TorClient,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Option<Bytes>,
    isolation_token: Option<IsolationToken>,
    timeout: Option<std::time::Duration>,
    accept_compression: bool,
}

impl<'a> RequestBuilder<'a> {
    /// Create a new request builder
    pub(crate) fn new(client: &'a TorClient, method: Method, uri: Uri) -> Self {
        Self {
            client,
            method,
            uri,
            headers: HeaderMap::new(),
            body: None,
            isolation_token: None,
            timeout: None,
            accept_compression: true, // Enable by default
        }
    }

    /// Add a header to the request
    pub fn header<K, V>(mut self, key: K, value: V) -> Self
    where
        K: TryInto<HeaderName>,
        V: TryInto<HeaderValue>,
    {
        if let (Ok(key), Ok(value)) = (key.try_into(), value.try_into()) {
            self.headers.insert(key, value);
        }
        self
    }

    /// Add multiple headers to the request
    pub fn headers(mut self, headers: HeaderMap) -> Self {
        self.headers.extend(headers);
        self
    }

    /// Set the request body
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Set a JSON request body from any serializable type
    ///
    /// # Example
    /// ```rust,ignore
    /// use serde::Serialize;
    ///
    /// #[derive(Serialize)]
    /// struct User { name: String, email: String }
    ///
    /// client.post("http://example.onion/users")?
    ///     .json(&User { name: "Alice".into(), email: "alice@example.com".into() })
    ///     .send().await?;
    /// ```
    pub fn json<T: serde::Serialize>(mut self, value: &T) -> Self {
        match serde_json::to_vec(value) {
            Ok(data) => {
                self.headers.insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                self.body = Some(Bytes::from(data));
            }
            Err(_) => {
                // Silently fail - error will be caught when building request
                // This matches reqwest behavior
            }
        }
        self
    }

    /// Set a JSON request body from a raw JSON string
    pub fn json_raw(mut self, json_str: impl Into<Bytes>) -> Self {
        let encoded = EncodedBody::json(json_str);
        self.headers
            .insert(header::CONTENT_TYPE, encoded.content_type);
        self.body = Some(encoded.data);
        self
    }

    /// Set a form-urlencoded request body
    pub fn form<I, K, V>(mut self, params: I) -> Result<Self>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let encoded = EncodedBody::form(params)?;
        self.headers
            .insert(header::CONTENT_TYPE, encoded.content_type);
        self.body = Some(encoded.data);
        Ok(self)
    }

    /// Set a plain text request body
    pub fn text(mut self, text: impl Into<Bytes>) -> Self {
        let encoded = EncodedBody::text(text);
        self.headers
            .insert(header::CONTENT_TYPE, encoded.content_type);
        self.body = Some(encoded.data);
        self
    }

    /// Set a custom isolation token for this request
    pub fn isolation(mut self, token: IsolationToken) -> Self {
        self.isolation_token = Some(token);
        self
    }

    /// Add query parameters to the URL
    ///
    /// # Example
    /// ```rust,ignore
    /// client.get("http://example.onion/search")?
    ///     .query(&[("q", "rust"), ("page", "1")])
    ///     .send().await?;
    /// // Results in: http://example.onion/search?q=rust&page=1
    /// ```
    pub fn query<I, K, V>(mut self, params: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let query_string: String = params
            .into_iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    urlencoding::encode(k.as_ref()),
                    urlencoding::encode(v.as_ref())
                )
            })
            .collect::<Vec<_>>()
            .join("&");

        if !query_string.is_empty() {
            let uri_str = self.uri.to_string();
            let new_uri = if uri_str.contains('?') {
                format!("{}&{}", uri_str, query_string)
            } else {
                format!("{}?{}", uri_str, query_string)
            };
            if let Ok(uri) = new_uri.parse() {
                self.uri = uri;
            }
        }
        self
    }

    /// Set a custom timeout for this request
    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set Basic authentication
    pub fn basic_auth(mut self, username: &str, password: &str) -> Self {
        let auth_header = body::basic_auth(username, password);
        self.headers.insert(header::AUTHORIZATION, auth_header);
        self
    }

    /// Set Bearer token authentication
    pub fn bearer_auth(self, token: &str) -> Self {
        self.header(header::AUTHORIZATION, format!("Bearer {}", token))
    }

    /// Disable compression acceptance for this request
    pub fn no_compression(mut self) -> Self {
        self.accept_compression = false;
        self
    }

    /// Build the HTTP request
    fn build_request(&self, config: &Config) -> Result<Request<Bytes>> {
        let mut builder = Request::builder()
            .method(self.method.clone())
            .uri(self.uri.clone());

        // Add default headers
        builder = builder.header(header::USER_AGENT, &config.user_agent);

        // Add compression acceptance
        if self.accept_compression && !self.headers.contains_key(header::ACCEPT_ENCODING) {
            builder = builder.header(header::ACCEPT_ENCODING, Compression::accept_encoding());
        }

        // Add custom headers
        for (key, value) in &self.headers {
            builder = builder.header(key, value);
        }

        // Add Host header if not present
        if !self.headers.contains_key(header::HOST) {
            if let Some(host) = self.uri.host() {
                let host_value = match self.uri.port_u16() {
                    Some(port) if port != 80 && port != 443 => format!("{}:{}", host, port),
                    _ => host.to_string(),
                };
                builder = builder.header(header::HOST, host_value);
            }
        }

        // Add Content-Length if we have a body
        if let Some(ref body) = self.body {
            if !self.headers.contains_key(header::CONTENT_LENGTH) {
                builder = builder.header(header::CONTENT_LENGTH, body.len().to_string());
            }
        }

        // Sanitize headers for privacy
        let request = builder
            .body(self.body.clone().unwrap_or_default())
            .map_err(|e| Error::InvalidRequest {
                message: e.to_string(),
            })?;

        Ok(request)
    }

    /// Send the request and get a response
    pub async fn send(self) -> Result<Response> {
        let timeout = self.timeout.unwrap_or(self.client.config().timeout);

        tokio::time::timeout(timeout, self.client.execute(self))
            .await
            .map_err(|_| Error::timeout("request", timeout))?
    }
}

/// Helper methods for building common request types
impl TorClient {
    /// Create a GET request
    pub fn get(&self, url: &str) -> Result<RequestBuilder<'_>> {
        let uri: Uri = url
            .parse()
            .map_err(|_| Error::invalid_url(url, "invalid URL"))?;
        Ok(RequestBuilder::new(self, Method::GET, uri))
    }

    /// Create a POST request
    pub fn post(&self, url: &str) -> Result<RequestBuilder<'_>> {
        let uri: Uri = url
            .parse()
            .map_err(|_| Error::invalid_url(url, "invalid URL"))?;
        Ok(RequestBuilder::new(self, Method::POST, uri))
    }

    /// Create a PUT request
    pub fn put(&self, url: &str) -> Result<RequestBuilder<'_>> {
        let uri: Uri = url
            .parse()
            .map_err(|_| Error::invalid_url(url, "invalid URL"))?;
        Ok(RequestBuilder::new(self, Method::PUT, uri))
    }

    /// Create a DELETE request
    pub fn delete(&self, url: &str) -> Result<RequestBuilder<'_>> {
        let uri: Uri = url
            .parse()
            .map_err(|_| Error::invalid_url(url, "invalid URL"))?;
        Ok(RequestBuilder::new(self, Method::DELETE, uri))
    }

    /// Create a PATCH request
    pub fn patch(&self, url: &str) -> Result<RequestBuilder<'_>> {
        let uri: Uri = url
            .parse()
            .map_err(|_| Error::invalid_url(url, "invalid URL"))?;
        Ok(RequestBuilder::new(self, Method::PATCH, uri))
    }

    /// Create a HEAD request
    pub fn head(&self, url: &str) -> Result<RequestBuilder<'_>> {
        let uri: Uri = url
            .parse()
            .map_err(|_| Error::invalid_url(url, "invalid URL"))?;
        Ok(RequestBuilder::new(self, Method::HEAD, uri))
    }

    /// Create a request with a custom method
    pub fn request(&self, method: Method, url: &str) -> Result<RequestBuilder<'_>> {
        let uri: Uri = url
            .parse()
            .map_err(|_| Error::invalid_url(url, "invalid URL"))?;
        Ok(RequestBuilder::new(self, method, uri))
    }
}

impl RequestBuilder<'_> {
    /// Get the method
    pub fn get_method(&self) -> &Method {
        &self.method
    }

    /// Get the URI
    pub fn get_uri(&self) -> &Uri {
        &self.uri
    }

    /// Get the headers
    pub fn get_headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Get the body
    pub fn get_body(&self) -> Option<&Bytes> {
        self.body.as_ref()
    }

    /// Get the isolation token
    pub fn get_isolation_token(&self) -> Option<IsolationToken> {
        self.isolation_token
    }

    /// Build the request (for internal use)
    pub(crate) fn into_request(self, config: &Config) -> Result<Request<Bytes>> {
        self.build_request(config)
    }
}
