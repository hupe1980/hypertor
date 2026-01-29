//! Stream isolation for Tor circuits
//!
//! Stream isolation ensures different activities use different Tor circuits,
//! preventing correlation attacks that could link your actions together.

use std::sync::atomic::{AtomicU64, Ordering};

/// Global counter for generating unique isolation tokens
static ISOLATION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Stream isolation level
///
/// Determines how Tor circuits are shared between requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IsolationLevel {
    /// No isolation - all requests share circuits (fastest, least private)
    #[default]
    None,
    /// Isolate by destination host (requests to different hosts use different circuits)
    ByHost,
    /// Isolate per request (each request gets a new circuit - slowest, most private)
    PerRequest,
    /// Custom isolation token (requests with same token share a circuit)
    Token(IsolationToken),
}

/// Unique token for custom stream isolation
///
/// Requests with the same token will share a Tor circuit.
/// Different tokens guarantee different circuits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IsolationToken(u64);

impl IsolationToken {
    /// Create a new unique isolation token
    pub fn new() -> Self {
        Self(ISOLATION_COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    /// Create a token from a raw value (for testing)
    pub fn from_raw(value: u64) -> Self {
        Self(value)
    }

    /// Get the raw token value
    pub fn as_raw(&self) -> u64 {
        self.0
    }
}

impl Default for IsolationToken {
    fn default() -> Self {
        Self::new()
    }
}

/// A session with its own isolation token
///
/// All requests made through an isolated session share the same Tor circuit,
/// but use a different circuit from other sessions.
#[derive(Debug, Clone)]
pub struct IsolatedSession {
    token: IsolationToken,
}

impl IsolatedSession {
    /// Create a new isolated session
    pub fn new() -> Self {
        Self {
            token: IsolationToken::new(),
        }
    }

    /// Get the isolation token for this session
    pub fn token(&self) -> IsolationToken {
        self.token
    }
}

impl Default for IsolatedSession {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute isolation token based on level and request info
pub fn compute_isolation(level: IsolationLevel, host: Option<&str>) -> Option<IsolationToken> {
    match level {
        IsolationLevel::None => None,
        IsolationLevel::ByHost => {
            // Hash the host to create a deterministic token
            host.map(|h| {
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                h.hash(&mut hasher);
                IsolationToken::from_raw(hasher.finish())
            })
        }
        IsolationLevel::PerRequest => Some(IsolationToken::new()),
        IsolationLevel::Token(token) => Some(token),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_token_uniqueness() {
        let t1 = IsolationToken::new();
        let t2 = IsolationToken::new();
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_compute_isolation_none() {
        let token = compute_isolation(IsolationLevel::None, Some("example.com"));
        assert!(token.is_none());
    }

    #[test]
    fn test_compute_isolation_by_host() {
        let t1 = compute_isolation(IsolationLevel::ByHost, Some("example.com"));
        let t2 = compute_isolation(IsolationLevel::ByHost, Some("example.com"));
        let t3 = compute_isolation(IsolationLevel::ByHost, Some("other.com"));

        assert_eq!(t1, t2); // Same host = same token
        assert_ne!(t1, t3); // Different host = different token
    }

    #[test]
    fn test_compute_isolation_per_request() {
        let t1 = compute_isolation(IsolationLevel::PerRequest, Some("example.com"));
        let t2 = compute_isolation(IsolationLevel::PerRequest, Some("example.com"));

        assert_ne!(t1, t2); // Always different
    }
}
