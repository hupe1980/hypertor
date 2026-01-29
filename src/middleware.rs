//! Middleware system for composable request/response processing.
//!
//! Provides a tower-like middleware pattern for intercepting and transforming
//! HTTP requests and responses flowing through the Tor client.

use crate::Result;
use http::{Request, Response};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Type alias for boxed async middleware futures.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Trait for middleware that can process requests before they are sent.
pub trait RequestMiddleware: Send + Sync {
    /// Process a request before it's sent over the network.
    fn process<'a>(&'a self, request: Request<Vec<u8>>) -> BoxFuture<'a, Result<Request<Vec<u8>>>>;

    /// Clone this middleware into a boxed trait object.
    fn clone_box(&self) -> Box<dyn RequestMiddleware>;
}

/// Trait for middleware that can process responses after they are received.
pub trait ResponseMiddleware: Send + Sync {
    /// Process a response after it's received from the network.
    fn process<'a>(
        &'a self,
        response: Response<Vec<u8>>,
    ) -> BoxFuture<'a, Result<Response<Vec<u8>>>>;

    /// Clone this middleware into a boxed trait object.
    fn clone_box(&self) -> Box<dyn ResponseMiddleware>;
}

/// A middleware that adds headers to all requests.
#[derive(Clone)]
pub struct HeaderMiddleware {
    headers: Vec<(String, String)>,
}

impl HeaderMiddleware {
    /// Create a new header middleware with the given headers.
    pub fn new() -> Self {
        Self {
            headers: Vec::new(),
        }
    }

    /// Add a header to be included in all requests.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Add the standard Tor browser headers for anonymity.
    pub fn with_tor_browser_headers(self) -> Self {
        self.with_header(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0",
        )
        .with_header(
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        )
        .with_header("Accept-Language", "en-US,en;q=0.5")
        .with_header("Accept-Encoding", "gzip, deflate")
        .with_header("DNT", "1")
        .with_header("Upgrade-Insecure-Requests", "1")
    }
}

impl Default for HeaderMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

impl RequestMiddleware for HeaderMiddleware {
    fn process<'a>(
        &'a self,
        mut request: Request<Vec<u8>>,
    ) -> BoxFuture<'a, Result<Request<Vec<u8>>>> {
        Box::pin(async move {
            let headers = request.headers_mut();
            for (name, value) in &self.headers {
                if let (Ok(name), Ok(value)) = (
                    http::header::HeaderName::try_from(name.as_str()),
                    http::header::HeaderValue::try_from(value.as_str()),
                ) {
                    headers.insert(name, value);
                }
            }
            Ok(request)
        })
    }

    fn clone_box(&self) -> Box<dyn RequestMiddleware> {
        Box::new(self.clone())
    }
}

/// A middleware that logs requests (for debugging).
#[derive(Clone, Default)]
pub struct LoggingMiddleware {
    log_body: bool,
}

impl LoggingMiddleware {
    /// Create a new logging middleware.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable logging of request bodies.
    pub fn with_body_logging(mut self) -> Self {
        self.log_body = true;
        self
    }
}

impl RequestMiddleware for LoggingMiddleware {
    fn process<'a>(&'a self, request: Request<Vec<u8>>) -> BoxFuture<'a, Result<Request<Vec<u8>>>> {
        let log_body = self.log_body;
        Box::pin(async move {
            tracing::debug!(
                method = %request.method(),
                uri = %request.uri(),
                "Sending request"
            );

            if log_body && !request.body().is_empty() {
                if let Ok(body) = std::str::from_utf8(request.body()) {
                    tracing::trace!(body = %body, "Request body");
                }
            }

            Ok(request)
        })
    }

    fn clone_box(&self) -> Box<dyn RequestMiddleware> {
        Box::new(self.clone())
    }
}

impl ResponseMiddleware for LoggingMiddleware {
    fn process<'a>(
        &'a self,
        response: Response<Vec<u8>>,
    ) -> BoxFuture<'a, Result<Response<Vec<u8>>>> {
        let log_body = self.log_body;
        Box::pin(async move {
            tracing::debug!(
                status = %response.status(),
                "Received response"
            );

            if log_body && !response.body().is_empty() {
                if let Ok(body) = std::str::from_utf8(response.body()) {
                    tracing::trace!(body = %body, "Response body");
                }
            }

            Ok(response)
        })
    }

    fn clone_box(&self) -> Box<dyn ResponseMiddleware> {
        Box::new(self.clone())
    }
}

/// A middleware that enforces rate limiting.
#[derive(Clone)]
pub struct RateLimitMiddleware {
    requests_per_second: f64,
    last_request: Arc<parking_lot::Mutex<std::time::Instant>>,
}

impl RateLimitMiddleware {
    /// Create a new rate limit middleware.
    pub fn new(requests_per_second: f64) -> Self {
        Self {
            requests_per_second,
            last_request: Arc::new(parking_lot::Mutex::new(std::time::Instant::now())),
        }
    }
}

impl RequestMiddleware for RateLimitMiddleware {
    fn process<'a>(&'a self, request: Request<Vec<u8>>) -> BoxFuture<'a, Result<Request<Vec<u8>>>> {
        let min_interval = std::time::Duration::from_secs_f64(1.0 / self.requests_per_second);
        let last_request = self.last_request.clone();

        Box::pin(async move {
            let elapsed = {
                let last = last_request.lock();
                last.elapsed()
            };

            if elapsed < min_interval {
                let sleep_duration = min_interval - elapsed;
                tokio::time::sleep(sleep_duration).await;
            }

            {
                let mut last = last_request.lock();
                *last = std::time::Instant::now();
            }

            Ok(request)
        })
    }

    fn clone_box(&self) -> Box<dyn RequestMiddleware> {
        Box::new(self.clone())
    }
}

/// A middleware stack that applies multiple middlewares in order.
pub struct MiddlewareStack {
    request_middlewares: Vec<Box<dyn RequestMiddleware>>,
    response_middlewares: Vec<Box<dyn ResponseMiddleware>>,
}

impl MiddlewareStack {
    /// Create a new empty middleware stack.
    pub fn new() -> Self {
        Self {
            request_middlewares: Vec::new(),
            response_middlewares: Vec::new(),
        }
    }

    /// Add a request middleware to the stack.
    pub fn with_request<M: RequestMiddleware + 'static>(mut self, middleware: M) -> Self {
        self.request_middlewares.push(Box::new(middleware));
        self
    }

    /// Add a response middleware to the stack.
    pub fn with_response<M: ResponseMiddleware + 'static>(mut self, middleware: M) -> Self {
        self.response_middlewares.push(Box::new(middleware));
        self
    }

    /// Process a request through all request middlewares.
    pub async fn process_request(&self, mut request: Request<Vec<u8>>) -> Result<Request<Vec<u8>>> {
        for middleware in &self.request_middlewares {
            request = middleware.process(request).await?;
        }
        Ok(request)
    }

    /// Process a response through all response middlewares.
    pub async fn process_response(
        &self,
        mut response: Response<Vec<u8>>,
    ) -> Result<Response<Vec<u8>>> {
        for middleware in &self.response_middlewares {
            response = middleware.process(response).await?;
        }
        Ok(response)
    }

    /// Check if the stack has any middlewares.
    pub fn is_empty(&self) -> bool {
        self.request_middlewares.is_empty() && self.response_middlewares.is_empty()
    }
}

impl Default for MiddlewareStack {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for MiddlewareStack {
    fn clone(&self) -> Self {
        Self {
            request_middlewares: self
                .request_middlewares
                .iter()
                .map(|m| m.clone_box())
                .collect(),
            response_middlewares: self
                .response_middlewares
                .iter()
                .map(|m| m.clone_box())
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use http::Method;

    #[tokio::test]
    async fn test_header_middleware() {
        let middleware = HeaderMiddleware::new()
            .with_header("X-Custom", "value")
            .with_header("X-Another", "test");

        let request = Request::builder()
            .method(Method::GET)
            .uri("https://example.com")
            .body(Vec::new())
            .unwrap();

        let processed = middleware.process(request).await.unwrap();
        assert_eq!(processed.headers().get("X-Custom").unwrap(), "value");
        assert_eq!(processed.headers().get("X-Another").unwrap(), "test");
    }

    #[tokio::test]
    async fn test_middleware_stack() {
        let stack = MiddlewareStack::new()
            .with_request(HeaderMiddleware::new().with_header("X-Test", "1"))
            .with_request(LoggingMiddleware::new());

        let request = Request::builder()
            .method(Method::GET)
            .uri("https://example.com")
            .body(Vec::new())
            .unwrap();

        let processed = stack.process_request(request).await.unwrap();
        assert_eq!(processed.headers().get("X-Test").unwrap(), "1");
    }
}
