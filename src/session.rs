//! Session-based HTTP client with cookies and redirects
//!
//! A Session wraps a TorClient with automatic cookie management
//! and redirect following.

use std::sync::Arc;

use http::{Method, Uri, header};
use parking_lot::RwLock;
use tracing::debug;

use crate::body::{self, Body as EncodedBody};
use crate::client::TorClient;
use crate::cookies::CookieJar;
use crate::error::{Error, Result};
use crate::redirect::{
    RedirectAction, RedirectGuard, RedirectPolicy, redirect_method_for_status,
    should_remove_auth_on_redirect,
};
use crate::response::Response;

/// A session with automatic cookie management and redirect following
pub struct Session {
    /// Underlying Tor client
    client: TorClient,
    /// Cookie jar for session persistence
    cookies: Arc<RwLock<CookieJar>>,
    /// Redirect policy
    redirect_policy: RedirectPolicy,
}

impl Session {
    /// Create a new session from a TorClient
    pub fn new(client: TorClient) -> Self {
        Self {
            client,
            cookies: Arc::new(RwLock::new(CookieJar::new())),
            redirect_policy: RedirectPolicy::default(),
        }
    }

    /// Create a session with a specific redirect policy
    #[must_use]
    pub fn with_redirect_policy(mut self, policy: RedirectPolicy) -> Self {
        self.redirect_policy = policy;
        self
    }

    /// Create a session that follows standard redirects (up to 10)
    #[must_use]
    pub fn with_standard_redirects(mut self) -> Self {
        self.redirect_policy = RedirectPolicy::standard();
        self
    }

    /// Get the underlying Tor client
    pub fn client(&self) -> &TorClient {
        &self.client
    }

    /// Get the cookie jar
    pub fn cookies(&self) -> &Arc<RwLock<CookieJar>> {
        &self.cookies
    }

    /// Clear all cookies
    pub fn clear_cookies(&self) {
        self.cookies.write().clear();
    }

    /// Create a GET request
    pub fn get(&self, url: &str) -> Result<SessionRequest<'_>> {
        let uri: Uri = url
            .parse()
            .map_err(|_| Error::invalid_url(url, "invalid URL"))?;
        Ok(SessionRequest::new(self, Method::GET, uri))
    }

    /// Create a POST request
    pub fn post(&self, url: &str) -> Result<SessionRequest<'_>> {
        let uri: Uri = url
            .parse()
            .map_err(|_| Error::invalid_url(url, "invalid URL"))?;
        Ok(SessionRequest::new(self, Method::POST, uri))
    }

    /// Create a PUT request
    pub fn put(&self, url: &str) -> Result<SessionRequest<'_>> {
        let uri: Uri = url
            .parse()
            .map_err(|_| Error::invalid_url(url, "invalid URL"))?;
        Ok(SessionRequest::new(self, Method::PUT, uri))
    }

    /// Create a DELETE request
    pub fn delete(&self, url: &str) -> Result<SessionRequest<'_>> {
        let uri: Uri = url
            .parse()
            .map_err(|_| Error::invalid_url(url, "invalid URL"))?;
        Ok(SessionRequest::new(self, Method::DELETE, uri))
    }

    /// Create a HEAD request
    pub fn head(&self, url: &str) -> Result<SessionRequest<'_>> {
        let uri: Uri = url
            .parse()
            .map_err(|_| Error::invalid_url(url, "invalid URL"))?;
        Ok(SessionRequest::new(self, Method::HEAD, uri))
    }
}

impl Clone for Session {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            cookies: Arc::clone(&self.cookies),
            redirect_policy: self.redirect_policy,
        }
    }
}

/// A request builder for Session that handles cookies and redirects
pub struct SessionRequest<'a> {
    session: &'a Session,
    method: Method,
    uri: Uri,
    headers: http::HeaderMap,
    body: Option<bytes::Bytes>,
    timeout: Option<std::time::Duration>,
    follow_redirects: bool,
}

impl<'a> SessionRequest<'a> {
    fn new(session: &'a Session, method: Method, uri: Uri) -> Self {
        Self {
            session,
            method,
            uri,
            headers: http::HeaderMap::new(),
            body: None,
            timeout: None,
            follow_redirects: session.redirect_policy.should_follow(),
        }
    }

    /// Add a header to the request
    pub fn header<K, V>(mut self, key: K, value: V) -> Self
    where
        K: TryInto<http::header::HeaderName>,
        V: TryInto<http::header::HeaderValue>,
    {
        if let (Ok(key), Ok(value)) = (key.try_into(), value.try_into()) {
            self.headers.insert(key, value);
        }
        self
    }

    /// Set the request body
    pub fn body(mut self, body: impl Into<bytes::Bytes>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Set a JSON body
    pub fn json(mut self, json_str: impl Into<bytes::Bytes>) -> Self {
        let encoded = EncodedBody::json(json_str);
        self.headers
            .insert(header::CONTENT_TYPE, encoded.content_type);
        self.body = Some(encoded.data);
        self
    }

    /// Set a form body
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

    /// Set Basic authentication
    pub fn basic_auth(mut self, username: &str, password: &str) -> Self {
        let auth_header = body::basic_auth(username, password);
        self.headers.insert(header::AUTHORIZATION, auth_header);
        self
    }

    /// Set Bearer authentication
    pub fn bearer_auth(self, token: &str) -> Self {
        self.header(header::AUTHORIZATION, format!("Bearer {}", token))
    }

    /// Set request timeout
    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Don't follow redirects for this request
    pub fn no_redirect(mut self) -> Self {
        self.follow_redirects = false;
        self
    }

    /// Send the request and get a response
    pub async fn send(self) -> Result<Response> {
        let mut current_uri = self.uri.clone();
        let mut current_method = self.method.clone();
        let mut redirect_guard = RedirectGuard::new(
            self.session
                .redirect_policy
                .max_redirects()
                .unwrap_or(u32::MAX),
        );
        let mut request_body = self.body.clone();
        let mut custom_headers = self.headers.clone();

        loop {
            // Build the request
            let mut builder = self
                .session
                .client
                .request(current_method.clone(), &current_uri.to_string())?;

            // Add custom headers
            for (key, value) in &custom_headers {
                builder = builder.header(key, value);
            }

            // Add cookies
            let cookie_header = {
                let cookies = self.session.cookies.read();
                cookies.get_cookie_header(&current_uri)
            };
            if let Some(cookie_str) = cookie_header {
                builder = builder.header(header::COOKIE, cookie_str);
            }

            // Add body if present
            if let Some(ref body) = request_body {
                builder = builder.body(body.clone());
            }

            // Set timeout
            if let Some(timeout) = self.timeout {
                builder = builder.timeout(timeout);
            }

            // Send request
            let response = builder.send().await?;

            // Extract and store cookies
            {
                let cookies = self.session.cookies.write();
                for cookie_str in response.headers().get_all(header::SET_COOKIE) {
                    if let Ok(cookie_str) = cookie_str.to_str() {
                        cookies.add_from_header(cookie_str, &current_uri);
                    }
                }
            }

            // Check for redirects
            if !self.follow_redirects {
                return Ok(response);
            }

            match redirect_guard.check_redirect(&response, &current_uri)? {
                RedirectAction::Follow(new_uri) => {
                    debug!("Following redirect: {} -> {}", current_uri, new_uri);

                    // Remove auth header on cross-origin redirect
                    if should_remove_auth_on_redirect(&current_uri, &new_uri) {
                        custom_headers.remove(header::AUTHORIZATION);
                    }

                    // Update method based on status code
                    current_method = redirect_method_for_status(response.status(), &current_method);

                    // Clear body on method change to GET
                    if current_method == Method::GET {
                        request_body = None;
                    }

                    current_uri = new_uri;
                }
                RedirectAction::Stop => {
                    return Ok(response);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    // Note: These tests require a real TorClient which needs Tor network
    // They would be integration tests in practice

    #[test]
    fn test_session_config() {
        // Just test that the builder pattern works
        let policy = RedirectPolicy::Limited(5);
        assert!(policy.should_follow());
        assert_eq!(policy.max_redirects(), Some(5));
    }
}
