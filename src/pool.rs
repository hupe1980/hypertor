//! Connection pooling for Tor streams
//!
//! Maintains a pool of warm Tor connections to avoid the 3-5 second
//! overhead of establishing new circuits for each request.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::Semaphore;

use crate::error::{Error, Result};
use crate::stream::TorStream;

/// Key for identifying pooled connections
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct PoolKey {
    /// Target host
    pub host: String,
    /// Target port
    pub port: u16,
    /// Whether TLS is used
    pub is_tls: bool,
}

impl PoolKey {
    /// Create a new pool key
    pub fn new(host: impl Into<String>, port: u16, is_tls: bool) -> Self {
        Self {
            host: host.into(),
            port,
            is_tls,
        }
    }
}

/// A pooled connection with metadata
struct PooledConnection {
    stream: TorStream,
    created_at: Instant,
    last_used: Instant,
}

impl PooledConnection {
    fn new(stream: TorStream) -> Self {
        let now = Instant::now();
        Self {
            stream,
            created_at: now,
            last_used: now,
        }
    }

    fn is_expired(&self, max_age: Duration, idle_timeout: Duration) -> bool {
        let now = Instant::now();
        now.duration_since(self.created_at) > max_age
            || now.duration_since(self.last_used) > idle_timeout
    }
}

/// Configuration for the connection pool
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum number of connections per host
    pub max_connections_per_host: usize,
    /// Maximum total connections
    pub max_total_connections: usize,
    /// Maximum connection age
    pub max_connection_age: Duration,
    /// Idle connection timeout
    pub idle_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_host: 4,
            max_total_connections: 20,
            max_connection_age: Duration::from_secs(300), // 5 minutes
            idle_timeout: Duration::from_secs(60),        // 1 minute
        }
    }
}

/// Connection pool for reusing Tor streams
pub struct ConnectionPool {
    /// Pooled connections by key
    connections: Mutex<HashMap<PoolKey, Vec<PooledConnection>>>,
    /// Semaphore for limiting total connections
    semaphore: Arc<Semaphore>,
    /// Pool configuration
    config: PoolConfig,
}

impl ConnectionPool {
    /// Create a new connection pool
    pub fn new(config: PoolConfig) -> Self {
        Self {
            connections: Mutex::new(HashMap::new()),
            semaphore: Arc::new(Semaphore::new(config.max_total_connections)),
            config,
        }
    }

    /// Try to get an existing connection from the pool
    pub fn get(&self, key: &PoolKey) -> Option<TorStream> {
        let mut connections = self.connections.lock();

        if let Some(pool) = connections.get_mut(key) {
            // Find a non-expired connection
            while let Some(mut conn) = pool.pop() {
                if !conn.is_expired(self.config.max_connection_age, self.config.idle_timeout) {
                    conn.last_used = Instant::now();
                    return Some(conn.stream);
                }
                // Connection expired, drop it (semaphore permit will be released)
            }
        }

        None
    }

    /// Return a connection to the pool
    pub fn put(&self, key: PoolKey, stream: TorStream) {
        let mut connections = self.connections.lock();

        let pool = connections.entry(key).or_default();

        // Don't exceed per-host limit
        if pool.len() < self.config.max_connections_per_host {
            pool.push(PooledConnection::new(stream));
        }
        // If at limit, just drop the connection
    }

    /// Acquire a permit for a new connection
    pub async fn acquire_permit(&self) -> Result<PoolPermit> {
        match tokio::time::timeout(
            Duration::from_secs(30),
            self.semaphore.clone().acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => Ok(PoolPermit { _permit: permit }),
            Ok(Err(_)) => Err(Error::PoolExhausted {
                max_connections: self.config.max_total_connections,
            }),
            Err(_) => Err(Error::timeout("connection pool", Duration::from_secs(30))),
        }
    }

    /// Remove all expired connections
    pub fn cleanup(&self) {
        let mut connections = self.connections.lock();

        for pool in connections.values_mut() {
            pool.retain(|conn| {
                !conn.is_expired(self.config.max_connection_age, self.config.idle_timeout)
            });
        }

        // Remove empty pools
        connections.retain(|_, pool| !pool.is_empty());
    }

    /// Get the number of pooled connections
    pub fn len(&self) -> usize {
        self.connections.lock().values().map(|v| v.len()).sum()
    }

    /// Check if the pool is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all pooled connections
    pub fn clear(&self) {
        self.connections.lock().clear();
    }
}

/// A permit for creating a new connection
pub struct PoolPermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new(PoolConfig::default())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_pool_key_equality() {
        let k1 = PoolKey::new("example.com", 443, true);
        let k2 = PoolKey::new("example.com", 443, true);
        let k3 = PoolKey::new("example.com", 80, false);

        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
    }

    #[test]
    fn test_pool_config_default() {
        let config = PoolConfig::default();
        assert_eq!(config.max_connections_per_host, 4);
        assert_eq!(config.max_total_connections, 20);
    }
}
