//! DNS resolution over Tor.
//!
//! Provides explicit DNS resolution APIs that route all queries through
//! the Tor network to prevent DNS leaks.
//!
//! # Real Tor Integration
//!
//! This module uses `arti_client::TorClient::resolve()` for actual DNS resolution
//! through the Tor network. All queries exit via Tor, preventing DNS leaks.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use arti_client::TorClient as ArtiClient;
use parking_lot::RwLock;
use tor_rtcompat::PreferredRuntime;
use tracing::debug;

use crate::error::{Error, Result};

/// DNS resolution result.
#[derive(Debug, Clone)]
pub struct DnsResult {
    /// The hostname that was resolved
    pub hostname: String,
    /// Resolved IPv4 addresses
    pub ipv4: Vec<Ipv4Addr>,
    /// Resolved IPv6 addresses
    pub ipv6: Vec<Ipv6Addr>,
    /// Time-to-live in seconds
    pub ttl: Option<u32>,
}

impl DnsResult {
    /// Get the first IPv4 address if available.
    pub fn first_ipv4(&self) -> Option<Ipv4Addr> {
        self.ipv4.first().copied()
    }

    /// Get the first IPv6 address if available.
    pub fn first_ipv6(&self) -> Option<Ipv6Addr> {
        self.ipv6.first().copied()
    }

    /// Get the first IP address (prefers IPv4).
    pub fn first_ip(&self) -> Option<IpAddr> {
        self.first_ipv4()
            .map(IpAddr::V4)
            .or_else(|| self.first_ipv6().map(IpAddr::V6))
    }

    /// Get all IP addresses.
    pub fn all_ips(&self) -> Vec<IpAddr> {
        let mut ips: Vec<IpAddr> = self.ipv4.iter().map(|&ip| IpAddr::V4(ip)).collect();
        ips.extend(self.ipv6.iter().map(|&ip| IpAddr::V6(ip)));
        ips
    }

    /// Check if any addresses were resolved.
    pub fn is_empty(&self) -> bool {
        self.ipv4.is_empty() && self.ipv6.is_empty()
    }
}

/// DNS cache entry.
#[derive(Debug, Clone)]
struct CacheEntry {
    result: DnsResult,
    expires_at: std::time::Instant,
}

/// Simple DNS cache for resolved addresses.
#[derive(Debug, Default)]
pub struct DnsCache {
    entries: RwLock<std::collections::HashMap<String, CacheEntry>>,
    default_ttl: Duration,
    max_entries: usize,
}

impl DnsCache {
    /// Create a new DNS cache.
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(std::collections::HashMap::new()),
            default_ttl: Duration::from_secs(300), // 5 minutes
            max_entries: 1000,
        }
    }

    /// Create a cache with custom settings.
    pub fn with_settings(default_ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(std::collections::HashMap::new()),
            default_ttl,
            max_entries,
        }
    }

    /// Look up a hostname in the cache.
    pub fn get(&self, hostname: &str) -> Option<DnsResult> {
        let entries = self.entries.read();
        if let Some(entry) = entries.get(hostname) {
            if entry.expires_at > std::time::Instant::now() {
                return Some(entry.result.clone());
            }
        }
        None
    }

    /// Store a result in the cache.
    pub fn put(&self, result: DnsResult) {
        let ttl = result
            .ttl
            .map(|s| Duration::from_secs(s as u64))
            .unwrap_or(self.default_ttl);

        let entry = CacheEntry {
            result: result.clone(),
            expires_at: std::time::Instant::now() + ttl,
        };

        let mut entries = self.entries.write();

        // Evict expired entries if we're at capacity
        if entries.len() >= self.max_entries {
            let now = std::time::Instant::now();
            entries.retain(|_, e| e.expires_at > now);
        }

        entries.insert(result.hostname.clone(), entry);
    }

    /// Remove a hostname from the cache.
    pub fn remove(&self, hostname: &str) {
        self.entries.write().remove(hostname);
    }

    /// Clear all cached entries.
    pub fn clear(&self) {
        self.entries.write().clear();
    }

    /// Get the number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// Remove expired entries.
    pub fn cleanup(&self) {
        let now = std::time::Instant::now();
        self.entries.write().retain(|_, e| e.expires_at > now);
    }
}

/// DNS resolver that routes queries through Tor.
///
/// All DNS queries are resolved through the Tor network to prevent
/// DNS leaks that could reveal browsing activity.
///
/// # Real Tor Integration
///
/// Uses `arti_client::TorClient::resolve()` for actual DNS resolution.
/// Queries are resolved via Tor exit nodes, never locally.
#[derive(Clone)]
pub struct TorDnsResolver {
    /// Shared arti TorClient for DNS resolution
    tor: Option<Arc<ArtiClient<PreferredRuntime>>>,
    cache: Arc<DnsCache>,
    enable_cache: bool,
}

impl TorDnsResolver {
    /// Create a new DNS resolver with caching enabled.
    ///
    /// Note: This creates a resolver without a Tor client. Use `with_client()`
    /// to create a fully functional resolver that can resolve DNS through Tor.
    pub fn new() -> Self {
        Self {
            tor: None,
            cache: Arc::new(DnsCache::new()),
            enable_cache: true,
        }
    }

    /// Create a resolver with a shared Tor client.
    ///
    /// This is the recommended way to create a resolver, as it can
    /// actually resolve DNS through the Tor network.
    pub fn with_client(tor: Arc<ArtiClient<PreferredRuntime>>) -> Self {
        Self {
            tor: Some(tor),
            cache: Arc::new(DnsCache::new()),
            enable_cache: true,
        }
    }

    /// Create a resolver without caching.
    pub fn without_cache() -> Self {
        Self {
            tor: None,
            cache: Arc::new(DnsCache::new()),
            enable_cache: false,
        }
    }

    /// Create a resolver with a custom cache.
    pub fn with_cache(cache: Arc<DnsCache>) -> Self {
        Self {
            tor: None,
            cache,
            enable_cache: true,
        }
    }

    /// Resolve a hostname to IP addresses through Tor.
    ///
    /// This uses `arti_client::TorClient::resolve()` to perform DNS resolution
    /// through the Tor network, preventing DNS leaks.
    ///
    /// # Real Tor Integration
    ///
    /// When a Tor client is configured (via `with_client()`), this method
    /// calls arti's `resolve()` which sends the DNS query through a Tor
    /// circuit and resolves it via an exit node.
    pub async fn resolve(&self, hostname: &str) -> Result<DnsResult> {
        // Validate hostname
        if hostname.is_empty() {
            return Err(Error::http("empty hostname"));
        }

        // Check cache first
        if self.enable_cache {
            if let Some(cached) = self.cache.get(hostname) {
                debug!(hostname, "DNS cache hit");
                return Ok(cached);
            }
        }

        // Get the Tor client
        let tor = self.tor.as_ref().ok_or_else(|| {
            Error::http(format!(
                "DNS resolution for '{}' requires a configured Tor client (use TorDnsResolver::with_client())",
                hostname
            ))
        })?;

        // Perform actual resolution through Tor using arti's resolve()
        debug!(hostname, "Resolving DNS through Tor");

        let ips = tor
            .resolve(hostname)
            .await
            .map_err(|e| Error::http(format!("DNS resolution failed for '{}': {}", hostname, e)))?;

        // Separate IPv4 and IPv6 addresses
        let mut ipv4 = Vec::new();
        let mut ipv6 = Vec::new();

        for ip in ips {
            match ip {
                IpAddr::V4(v4) => ipv4.push(v4),
                IpAddr::V6(v6) => ipv6.push(v6),
            }
        }

        let result = DnsResult {
            hostname: hostname.to_string(),
            ipv4,
            ipv6,
            ttl: Some(300), // Default 5 minute TTL (arti doesn't expose TTL)
        };

        // Cache the result
        if self.enable_cache {
            self.cache.put(result.clone());
        }

        Ok(result)
    }

    /// Perform reverse DNS lookup through Tor.
    ///
    /// Resolves an IP address to hostnames via the Tor network.
    pub async fn resolve_ptr(&self, ip: IpAddr) -> Result<Vec<String>> {
        let tor = self
            .tor
            .as_ref()
            .ok_or_else(|| Error::http("Reverse DNS lookup requires a configured Tor client"))?;

        debug!(?ip, "Reverse DNS lookup through Tor");

        tor.resolve_ptr(ip)
            .await
            .map_err(|e| Error::http(format!("Reverse DNS lookup failed for '{}': {}", ip, e)))
    }

    /// Check if an address is a valid .onion address.
    pub fn is_onion(hostname: &str) -> bool {
        hostname.ends_with(".onion")
    }

    /// Validate an onion address format.
    pub fn validate_onion(hostname: &str) -> Result<()> {
        if !Self::is_onion(hostname) {
            return Err(Error::http("not an onion address"));
        }

        // Remove .onion suffix
        let addr = hostname.trim_end_matches(".onion");

        // v3 onion addresses are 56 characters (base32 encoded)
        // v2 onion addresses are 16 characters (deprecated)
        if addr.len() == 56 {
            // Validate base32 characters
            if addr.chars().all(|c| c.is_ascii_alphanumeric()) {
                return Ok(());
            }
        } else if addr.len() == 16 {
            // v2 addresses are deprecated but still valid
            return Ok(());
        }

        Err(Error::http(format!(
            "invalid onion address format: {}",
            hostname
        )))
    }

    /// Get the DNS cache.
    pub fn cache(&self) -> &Arc<DnsCache> {
        &self.cache
    }
}

impl Default for TorDnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Reverse DNS lookup result.
#[derive(Debug, Clone)]
pub struct ReverseDnsResult {
    /// The IP address that was looked up
    pub ip: IpAddr,
    /// Resolved hostnames
    pub hostnames: Vec<String>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_dns_result() {
        let result = DnsResult {
            hostname: "example.com".to_string(),
            ipv4: vec!["93.184.216.34".parse().unwrap()],
            ipv6: vec![],
            ttl: Some(300),
        };

        assert!(!result.is_empty());
        assert!(result.first_ipv4().is_some());
        assert!(result.first_ipv6().is_none());
    }

    #[test]
    fn test_dns_cache() {
        let cache = DnsCache::new();

        let result = DnsResult {
            hostname: "example.com".to_string(),
            ipv4: vec!["93.184.216.34".parse().unwrap()],
            ipv6: vec![],
            ttl: Some(300),
        };

        cache.put(result.clone());
        assert_eq!(cache.len(), 1);

        let cached = cache.get("example.com").unwrap();
        assert_eq!(cached.hostname, "example.com");
    }

    #[test]
    fn test_onion_validation() {
        // Valid v3 onion address (56 chars)
        let v3 = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";
        assert!(TorDnsResolver::is_onion(v3));
        assert!(TorDnsResolver::validate_onion(v3).is_ok());

        // Not an onion address
        assert!(!TorDnsResolver::is_onion("example.com"));
        assert!(TorDnsResolver::validate_onion("example.com").is_err());
    }

    #[test]
    fn test_resolver_creation() {
        let resolver = TorDnsResolver::new();
        assert!(resolver.cache().is_empty());

        let resolver_no_cache = TorDnsResolver::without_cache();
        assert!(resolver_no_cache.cache().is_empty());
    }
}
