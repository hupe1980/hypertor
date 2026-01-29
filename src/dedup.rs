//! Request deduplication and coalescing.
//!
//! Coalesces identical in-flight requests to avoid redundant network calls.
//! Multiple callers waiting for the same resource share a single request.

use std::collections::HashMap;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use http::{Method, Uri};
use parking_lot::Mutex;
use tokio::sync::broadcast;

use crate::error::{Error, Result};

/// Key for identifying duplicate requests.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RequestKey {
    method: String,
    uri: String,
    /// Optional body hash for POST/PUT deduplication
    body_hash: Option<u64>,
}

impl RequestKey {
    /// Create a key from method and URI (for GET/HEAD/DELETE).
    pub fn new(method: &Method, uri: &Uri) -> Self {
        Self {
            method: method.to_string(),
            uri: uri.to_string(),
            body_hash: None,
        }
    }

    /// Create a key with body hash (for POST/PUT).
    pub fn with_body(method: &Method, uri: &Uri, body: &[u8]) -> Self {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        body.hash(&mut hasher);
        Self {
            method: method.to_string(),
            uri: uri.to_string(),
            body_hash: Some(hasher.finish()),
        }
    }
}

/// Result that can be shared across waiters.
#[derive(Debug, Clone)]
pub struct SharedResult {
    /// HTTP status code
    pub status: u16,
    /// Response headers (serialized)
    pub headers: Vec<(String, String)>,
    /// Response body
    pub body: Vec<u8>,
}

/// In-flight request tracker.
#[derive(Debug)]
struct InFlight {
    /// When the request started
    started: Instant,
    /// Broadcast channel for result
    sender: broadcast::Sender<SharedResult>,
}

/// Request deduplication configuration.
#[derive(Debug, Clone)]
pub struct DedupConfig {
    /// Whether deduplication is enabled
    pub enabled: bool,
    /// Maximum time to wait for a coalesced request
    pub max_wait: Duration,
    /// Maximum number of waiters per request
    pub max_waiters: usize,
    /// Methods to deduplicate (default: GET, HEAD)
    pub methods: Vec<Method>,
}

impl Default for DedupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_wait: Duration::from_secs(30),
            max_waiters: 100,
            methods: vec![Method::GET, Method::HEAD],
        }
    }
}

impl DedupConfig {
    /// Create a new configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Disable deduplication.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    /// Set maximum wait time.
    #[must_use]
    pub fn with_max_wait(mut self, duration: Duration) -> Self {
        self.max_wait = duration;
        self
    }

    /// Set maximum waiters per request.
    #[must_use]
    pub fn with_max_waiters(mut self, max: usize) -> Self {
        self.max_waiters = max;
        self
    }

    /// Add a method to deduplicate.
    #[must_use]
    pub fn with_method(mut self, method: Method) -> Self {
        if !self.methods.contains(&method) {
            self.methods.push(method);
        }
        self
    }

    /// Check if a method should be deduplicated.
    pub fn should_dedup(&self, method: &Method) -> bool {
        self.enabled && self.methods.contains(method)
    }
}

/// Request deduplicator for coalescing identical requests.
#[derive(Debug)]
pub struct Deduplicator {
    config: DedupConfig,
    in_flight: Arc<Mutex<HashMap<RequestKey, InFlight>>>,
}

impl Default for Deduplicator {
    fn default() -> Self {
        Self::new(DedupConfig::default())
    }
}

impl Deduplicator {
    /// Create a new deduplicator.
    pub fn new(config: DedupConfig) -> Self {
        Self {
            config,
            in_flight: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Check if a request is already in-flight and optionally join it.
    /// Returns Ok(Some(receiver)) if coalesced, Ok(None) if should make new request.
    pub fn try_coalesce(
        &self,
        key: &RequestKey,
    ) -> Result<Option<broadcast::Receiver<SharedResult>>> {
        if !self.config.enabled {
            return Ok(None);
        }

        let mut in_flight = self.in_flight.lock();

        if let Some(flight) = in_flight.get(key) {
            // Check if still valid
            if flight.started.elapsed() < self.config.max_wait {
                // Check waiter limit
                if flight.sender.receiver_count() >= self.config.max_waiters {
                    return Err(Error::Circuit {
                        message: "Too many waiters for coalesced request".to_string(),
                        source: None,
                    });
                }
                return Ok(Some(flight.sender.subscribe()));
            }
            // Expired, remove it
            in_flight.remove(key);
        }

        Ok(None)
    }

    /// Register a new in-flight request.
    pub fn register(&self, key: RequestKey) -> broadcast::Sender<SharedResult> {
        let (sender, _) = broadcast::channel(1);
        let flight = InFlight {
            started: Instant::now(),
            sender: sender.clone(),
        };

        self.in_flight.lock().insert(key, flight);
        sender
    }

    /// Complete an in-flight request.
    pub fn complete(&self, key: &RequestKey, result: SharedResult) {
        let mut in_flight = self.in_flight.lock();
        if let Some(flight) = in_flight.remove(key) {
            // Ignore send errors (no receivers)
            let _ = flight.sender.send(result);
        }
    }

    /// Cancel an in-flight request.
    pub fn cancel(&self, key: &RequestKey) {
        self.in_flight.lock().remove(key);
    }

    /// Get the number of in-flight requests.
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.lock().len()
    }

    /// Clean up expired in-flight requests.
    pub fn cleanup(&self) {
        let mut in_flight = self.in_flight.lock();
        in_flight.retain(|_, flight| flight.started.elapsed() < self.config.max_wait);
    }

    /// Execute a request with deduplication.
    pub async fn execute<F, Fut>(&self, key: RequestKey, make_request: F) -> Result<SharedResult>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<SharedResult>>,
    {
        // Try to coalesce
        if let Some(mut receiver) = self.try_coalesce(&key)? {
            // Wait for the in-flight request
            return receiver.recv().await.map_err(|e| Error::Circuit {
                message: format!("Coalesced request was cancelled: {}", e),
                source: None,
            });
        }

        // Register new in-flight request
        let _sender = self.register(key.clone());

        // Execute the request
        let result = make_request().await;

        match result {
            Ok(shared) => {
                self.complete(&key, shared.clone());
                Ok(shared)
            }
            Err(e) => {
                self.cancel(&key);
                Err(e)
            }
        }
    }
}

/// Future type for coalesced requests.
pub type CoalescedFuture<'a> = Pin<Box<dyn Future<Output = Result<SharedResult>> + Send + 'a>>;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_request_key() {
        let key1 = RequestKey::new(&Method::GET, &"/api/test".parse().unwrap());
        let key2 = RequestKey::new(&Method::GET, &"/api/test".parse().unwrap());
        let key3 = RequestKey::new(&Method::POST, &"/api/test".parse().unwrap());

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_request_key_with_body() {
        let body = b"test body";
        let key1 = RequestKey::with_body(&Method::POST, &"/api".parse().unwrap(), body);
        let key2 = RequestKey::with_body(&Method::POST, &"/api".parse().unwrap(), body);
        let key3 = RequestKey::with_body(&Method::POST, &"/api".parse().unwrap(), b"other");

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_dedup_config() {
        let config = DedupConfig::new()
            .with_max_wait(Duration::from_secs(60))
            .with_max_waiters(50)
            .with_method(Method::POST);

        assert!(config.should_dedup(&Method::GET));
        assert!(config.should_dedup(&Method::POST));
        assert!(!config.should_dedup(&Method::PUT));
    }

    #[test]
    fn test_deduplicator_register() {
        let dedup = Deduplicator::default();
        let key = RequestKey::new(&Method::GET, &"/test".parse().unwrap());

        assert_eq!(dedup.in_flight_count(), 0);
        let _sender = dedup.register(key.clone());
        assert_eq!(dedup.in_flight_count(), 1);

        dedup.cancel(&key);
        assert_eq!(dedup.in_flight_count(), 0);
    }

    #[tokio::test]
    async fn test_deduplicator_coalesce() {
        let dedup = Deduplicator::default();
        let key = RequestKey::new(&Method::GET, &"/test".parse().unwrap());

        // First request - no coalesce
        assert!(dedup.try_coalesce(&key).unwrap().is_none());

        // Register in-flight
        let sender = dedup.register(key.clone());

        // Second request - should coalesce
        let receiver = dedup.try_coalesce(&key).unwrap();
        assert!(receiver.is_some());

        // Complete the request
        let result = SharedResult {
            status: 200,
            headers: vec![],
            body: b"test".to_vec(),
        };
        let _ = sender.send(result.clone());

        // Receiver should get the result
        let mut rx = receiver.unwrap();
        let received = rx.recv().await.unwrap();
        assert_eq!(received.status, 200);
    }
}
