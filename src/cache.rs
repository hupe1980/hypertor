//! HTTP response caching.
//!
//! Provides an in-memory cache for HTTP responses with proper
//! cache control header handling and LRU eviction.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use http::{HeaderMap, Method, StatusCode, Uri, header};
use parking_lot::RwLock;

/// Cache key for identifying cached responses.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    method: String,
    uri: String,
    /// Vary header values
    vary: Vec<(String, String)>,
}

impl CacheKey {
    /// Create a cache key from request parts.
    pub fn new(method: &Method, uri: &Uri) -> Self {
        Self {
            method: method.to_string(),
            uri: uri.to_string(),
            vary: Vec::new(),
        }
    }

    /// Create a cache key with Vary header values.
    pub fn with_vary(method: &Method, uri: &Uri, vary_headers: Vec<(String, String)>) -> Self {
        Self {
            method: method.to_string(),
            uri: uri.to_string(),
            vary: vary_headers,
        }
    }
}

/// Cached response entry.
#[derive(Debug, Clone)]
pub struct CachedResponse {
    /// HTTP status code
    pub status: StatusCode,
    /// Response headers
    pub headers: HeaderMap,
    /// Response body
    pub body: Vec<u8>,
    /// When the response was cached
    pub cached_at: Instant,
    /// When the response expires
    pub expires_at: Option<Instant>,
    /// ETag for conditional requests
    pub etag: Option<String>,
    /// Last-Modified for conditional requests
    pub last_modified: Option<String>,
    /// Size in bytes
    pub size: usize,
}

impl CachedResponse {
    /// Check if the cached response is still fresh.
    pub fn is_fresh(&self) -> bool {
        match self.expires_at {
            Some(expires) => Instant::now() < expires,
            None => false,
        }
    }

    /// Check if the cached response is stale.
    pub fn is_stale(&self) -> bool {
        !self.is_fresh()
    }

    /// Get the age of the cached response.
    pub fn age(&self) -> Duration {
        self.cached_at.elapsed()
    }

    /// Check if conditional validation is possible.
    pub fn can_validate(&self) -> bool {
        self.etag.is_some() || self.last_modified.is_some()
    }
}

/// Cache control directives parsed from headers.
#[derive(Debug, Clone, Default)]
pub struct CacheControl {
    /// no-store: Don't cache at all
    pub no_store: bool,
    /// no-cache: Cache but always validate
    pub no_cache: bool,
    /// private: Don't cache in shared caches
    pub private: bool,
    /// public: Can be cached anywhere
    pub public: bool,
    /// max-age in seconds
    pub max_age: Option<u64>,
    /// s-maxage for shared caches
    pub s_maxage: Option<u64>,
    /// must-revalidate: Must validate when stale
    pub must_revalidate: bool,
    /// immutable: Won't change
    pub immutable: bool,
}

impl CacheControl {
    /// Parse Cache-Control header.
    pub fn parse(headers: &HeaderMap) -> Self {
        let mut cc = Self::default();

        let value = match headers.get(header::CACHE_CONTROL) {
            Some(v) => match v.to_str() {
                Ok(s) => s,
                Err(_) => return cc,
            },
            None => return cc,
        };

        for directive in value.split(',') {
            let directive = directive.trim().to_lowercase();

            if directive == "no-store" {
                cc.no_store = true;
            } else if directive == "no-cache" {
                cc.no_cache = true;
            } else if directive == "private" {
                cc.private = true;
            } else if directive == "public" {
                cc.public = true;
            } else if directive == "must-revalidate" {
                cc.must_revalidate = true;
            } else if directive == "immutable" {
                cc.immutable = true;
            } else if let Some(value) = directive.strip_prefix("max-age=") {
                cc.max_age = value.parse().ok();
            } else if let Some(value) = directive.strip_prefix("s-maxage=") {
                cc.s_maxage = value.parse().ok();
            }
        }

        cc
    }

    /// Check if response can be cached.
    pub fn is_cacheable(&self) -> bool {
        !self.no_store
    }

    /// Get the effective max age.
    pub fn effective_max_age(&self) -> Option<Duration> {
        self.max_age.map(Duration::from_secs)
    }
}

/// Cache configuration.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of entries
    pub max_entries: usize,
    /// Maximum total size in bytes
    pub max_size: usize,
    /// Default TTL when no cache headers present
    pub default_ttl: Duration,
    /// Whether to respect Cache-Control headers
    pub respect_cache_control: bool,
    /// Whether to cache responses without explicit cache headers
    pub cache_heuristically: bool,
    /// Methods that can be cached
    pub cacheable_methods: Vec<Method>,
    /// Status codes that can be cached
    pub cacheable_status: Vec<StatusCode>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 1000,
            max_size: 100 * 1024 * 1024, // 100MB
            default_ttl: Duration::from_secs(300),
            respect_cache_control: true,
            cache_heuristically: true,
            cacheable_methods: vec![Method::GET, Method::HEAD],
            cacheable_status: vec![
                StatusCode::OK,
                StatusCode::NON_AUTHORITATIVE_INFORMATION,
                StatusCode::PARTIAL_CONTENT,
                StatusCode::MULTIPLE_CHOICES,
                StatusCode::MOVED_PERMANENTLY,
                StatusCode::FOUND,
                StatusCode::NOT_MODIFIED,
            ],
        }
    }
}

impl CacheConfig {
    /// Create a new configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Disable caching.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            max_entries: 0,
            max_size: 0,
            ..Default::default()
        }
    }

    /// Set maximum entries.
    #[must_use]
    pub fn with_max_entries(mut self, max: usize) -> Self {
        self.max_entries = max;
        self
    }

    /// Set maximum size.
    #[must_use]
    pub fn with_max_size(mut self, max: usize) -> Self {
        self.max_size = max;
        self
    }

    /// Set default TTL.
    #[must_use]
    pub fn with_default_ttl(mut self, ttl: Duration) -> Self {
        self.default_ttl = ttl;
        self
    }

    /// Check if a method is cacheable.
    pub fn is_method_cacheable(&self, method: &Method) -> bool {
        self.cacheable_methods.contains(method)
    }

    /// Check if a status is cacheable.
    pub fn is_status_cacheable(&self, status: StatusCode) -> bool {
        self.cacheable_status.contains(&status)
    }
}

/// LRU cache entry with access tracking.
#[derive(Debug)]
struct CacheEntry {
    response: CachedResponse,
    last_access: Instant,
    access_count: u64,
}

/// HTTP response cache.
#[derive(Debug)]
pub struct HttpCache {
    config: CacheConfig,
    entries: Arc<RwLock<HashMap<CacheKey, CacheEntry>>>,
    current_size: Arc<RwLock<usize>>,
}

impl Default for HttpCache {
    fn default() -> Self {
        Self::new(CacheConfig::default())
    }
}

impl HttpCache {
    /// Create a new cache.
    pub fn new(config: CacheConfig) -> Self {
        Self {
            config,
            entries: Arc::new(RwLock::new(HashMap::new())),
            current_size: Arc::new(RwLock::new(0)),
        }
    }

    /// Get a cached response.
    pub fn get(&self, key: &CacheKey) -> Option<CachedResponse> {
        let mut entries = self.entries.write();
        if let Some(entry) = entries.get_mut(key) {
            // Update access tracking
            entry.last_access = Instant::now();
            entry.access_count += 1;

            // Check freshness
            if entry.response.is_fresh() {
                return Some(entry.response.clone());
            }

            // Return stale response if it can be validated
            if entry.response.can_validate() {
                return Some(entry.response.clone());
            }

            // Remove stale entry
            let size = entry.response.size;
            entries.remove(key);
            *self.current_size.write() -= size;
        }
        None
    }

    /// Get a cached response without updating access time.
    pub fn peek(&self, key: &CacheKey) -> Option<CachedResponse> {
        let entries = self.entries.read();
        entries.get(key).map(|e| e.response.clone())
    }

    /// Store a response in the cache.
    pub fn put(
        &self,
        key: CacheKey,
        status: StatusCode,
        headers: &HeaderMap,
        body: Vec<u8>,
    ) -> bool {
        // Check if cacheable
        if !self
            .config
            .is_method_cacheable(&key.method.parse().unwrap_or(Method::GET))
        {
            return false;
        }

        if !self.config.is_status_cacheable(status) {
            return false;
        }

        // Parse cache control
        let cc = CacheControl::parse(headers);
        if self.config.respect_cache_control && !cc.is_cacheable() {
            return false;
        }

        // Calculate expiration
        let expires_at = if let Some(max_age) = cc.effective_max_age() {
            Some(Instant::now() + max_age)
        } else if self.config.cache_heuristically {
            Some(Instant::now() + self.config.default_ttl)
        } else {
            None
        };

        let size = body.len() + headers.len() * 64; // Estimate header size

        // Check size limits
        if size > self.config.max_size {
            return false;
        }

        // Evict if needed
        self.evict_if_needed(size);

        let etag = headers
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let last_modified = headers
            .get(header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let response = CachedResponse {
            status,
            headers: headers.clone(),
            body,
            cached_at: Instant::now(),
            expires_at,
            etag,
            last_modified,
            size,
        };

        let entry = CacheEntry {
            response,
            last_access: Instant::now(),
            access_count: 1,
        };

        let mut entries = self.entries.write();
        entries.insert(key, entry);
        *self.current_size.write() += size;

        true
    }

    /// Remove an entry from the cache.
    pub fn remove(&self, key: &CacheKey) -> bool {
        let mut entries = self.entries.write();
        if let Some(entry) = entries.remove(key) {
            *self.current_size.write() -= entry.response.size;
            true
        } else {
            false
        }
    }

    /// Clear the entire cache.
    pub fn clear(&self) {
        let mut entries = self.entries.write();
        entries.clear();
        *self.current_size.write() = 0;
    }

    /// Evict entries if needed to make room.
    fn evict_if_needed(&self, needed_size: usize) {
        let mut entries = self.entries.write();
        let mut current_size = self.current_size.write();

        // Evict until we have room
        while *current_size + needed_size > self.config.max_size
            || entries.len() >= self.config.max_entries
        {
            if entries.is_empty() {
                break;
            }

            // Find LRU entry
            let lru_key = entries
                .iter()
                .min_by_key(|(_, e)| e.last_access)
                .map(|(k, _)| k.clone());

            if let Some(key) = lru_key {
                if let Some(entry) = entries.remove(&key) {
                    *current_size -= entry.response.size;
                }
            } else {
                break;
            }
        }
    }

    /// Get cache statistics.
    pub fn stats(&self) -> CacheStats {
        let entries = self.entries.read();
        let mut fresh = 0;
        let mut stale = 0;
        let mut total_access = 0;

        for entry in entries.values() {
            if entry.response.is_fresh() {
                fresh += 1;
            } else {
                stale += 1;
            }
            total_access += entry.access_count;
        }

        CacheStats {
            entries: entries.len(),
            size: *self.current_size.read(),
            fresh,
            stale,
            total_access,
        }
    }

    /// Remove expired entries.
    pub fn cleanup(&self) {
        let mut entries = self.entries.write();
        let mut current_size = self.current_size.write();

        entries.retain(|_, entry| {
            if entry.response.is_stale() && !entry.response.can_validate() {
                *current_size -= entry.response.size;
                false
            } else {
                true
            }
        });
    }
}

/// Cache statistics.
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Number of entries
    pub entries: usize,
    /// Total size in bytes
    pub size: usize,
    /// Fresh entries
    pub fresh: usize,
    /// Stale entries
    pub stale: usize,
    /// Total access count
    pub total_access: u64,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_cache_control_parse() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CACHE_CONTROL,
            "max-age=3600, public".parse().unwrap(),
        );

        let cc = CacheControl::parse(&headers);
        assert_eq!(cc.max_age, Some(3600));
        assert!(cc.public);
        assert!(!cc.no_store);
    }

    #[test]
    fn test_cache_control_no_store() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());

        let cc = CacheControl::parse(&headers);
        assert!(cc.no_store);
        assert!(!cc.is_cacheable());
    }

    #[test]
    fn test_http_cache_put_get() {
        let cache = HttpCache::default();
        let key = CacheKey::new(&Method::GET, &"/api/test".parse().unwrap());

        let mut headers = HeaderMap::new();
        headers.insert(header::CACHE_CONTROL, "max-age=3600".parse().unwrap());

        assert!(cache.put(key.clone(), StatusCode::OK, &headers, b"test".to_vec()));

        let cached = cache.get(&key);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().body, b"test");
    }

    #[test]
    fn test_http_cache_eviction() {
        let config = CacheConfig::new().with_max_entries(2).with_max_size(1024);
        let cache = HttpCache::new(config);

        let mut headers = HeaderMap::new();
        headers.insert(header::CACHE_CONTROL, "max-age=3600".parse().unwrap());

        for i in 0..3 {
            let key = CacheKey::new(&Method::GET, &format!("/api/{}", i).parse().unwrap());
            cache.put(key, StatusCode::OK, &headers, b"test".to_vec());
        }

        // Should only have 2 entries due to eviction
        assert_eq!(cache.stats().entries, 2);
    }

    #[test]
    fn test_cache_key_with_vary() {
        let key1 = CacheKey::with_vary(
            &Method::GET,
            &"/api".parse().unwrap(),
            vec![("accept".to_string(), "application/json".to_string())],
        );
        let key2 = CacheKey::with_vary(
            &Method::GET,
            &"/api".parse().unwrap(),
            vec![("accept".to_string(), "text/html".to_string())],
        );

        assert_ne!(key1, key2);
    }
}
