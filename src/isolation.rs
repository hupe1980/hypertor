//! Circuit isolation.
//!
//! Two requests that travel over the same Tor circuit leave the network from
//! the same exit relay at the same time. Anyone watching that exit can link
//! them. Isolation is how you decide which of your activities are allowed to be
//! linked to each other.
//!
//! ```rust,no_run
//! use hypertor::{IsolationToken, TorClient};
//!
//! # async fn demo() -> hypertor::Result<()> {
//! let client = TorClient::new().await?;
//!
//! // Two personas that must never share an exit relay.
//! let alice = IsolationToken::new();
//! let bob = IsolationToken::new();
//!
//! client.get("http://forum.onion/inbox")?.isolation(alice).send().await?;
//! client.get("http://forum.onion/profile")?.isolation(alice).send().await?;
//! client.get("http://shop.onion/cart")?.isolation(bob).send().await?;
//! # Ok(())
//! # }
//! ```

use std::sync::atomic::{AtomicU64, Ordering};

use arti_client::IsolationToken as ArtiToken;

/// Distinguishes tokens for hashing.
///
/// arti's own `IsolationToken` is deliberately opaque and implements neither
/// `Hash` nor `Ord`, so hypertor carries its own id alongside it to key the
/// per-isolation connection pools.
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

/// How circuits are shared between requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum IsolationLevel {
    /// Share circuits freely. Fastest, and the weakest separation.
    ///
    /// Note that arti still isolates by target port and by the client's own
    /// rules; this only means hypertor adds no isolation of its own.
    None,

    /// One circuit family per destination host.
    ///
    /// A sensible default: requests to `a.onion` never share an exit with
    /// requests to `b.onion`, while repeated requests to the same host reuse a
    /// warm circuit.
    #[default]
    PerHost,

    /// A brand-new circuit for every single request.
    ///
    /// The strongest separation and by far the slowest: each request pays the
    /// full circuit build cost (typically seconds), and connection reuse is
    /// impossible by construction.
    PerRequest,

    /// Use one explicit [`IsolationToken`] for everything.
    Fixed(IsolationToken),
}

/// A handle identifying one circuit-sharing group.
///
/// Requests carrying equal tokens may share a circuit; requests carrying
/// different tokens never do. Tokens are cheap to copy and are only meaningful
/// within one process.
#[derive(Debug, Clone, Copy)]
pub struct IsolationToken {
    id: u64,
    inner: ArtiToken,
}

impl IsolationToken {
    /// Create a token that is distinct from every other token.
    pub fn new() -> Self {
        Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            inner: ArtiToken::new(),
        }
    }

    /// Unused in a build with no outbound-connection feature enabled.
    #[allow(dead_code)]
    pub(crate) fn inner(self) -> ArtiToken {
        self.inner
    }
}

impl PartialEq for IsolationToken {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for IsolationToken {}

impl std::hash::Hash for IsolationToken {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl Default for IsolationToken {
    fn default() -> Self {
        Self::new()
    }
}

impl From<IsolationToken> for ArtiToken {
    fn from(token: IsolationToken) -> Self {
        token.inner
    }
}

/// A group of requests that share one circuit, isolated from everything else.
///
/// A session is just a named [`IsolationToken`]; it holds no connection state
/// and can be cloned freely across tasks.
#[derive(Debug, Clone, Default)]
pub struct IsolatedSession {
    token: IsolationToken,
}

impl IsolatedSession {
    /// Start a new isolated session.
    pub fn new() -> Self {
        Self::default()
    }

    /// The token backing this session.
    pub fn token(&self) -> IsolationToken {
        self.token
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unique() {
        assert_ne!(IsolationToken::new(), IsolationToken::new());
    }

    #[test]
    fn tokens_are_stable_when_copied() {
        let token = IsolationToken::new();
        assert_eq!(token, token);
    }

    #[test]
    fn sessions_do_not_collide() {
        assert_ne!(
            IsolatedSession::new().token(),
            IsolatedSession::new().token()
        );
    }

    #[test]
    fn default_level_isolates_per_host() {
        // A default that shares circuits across every destination would silently
        // link a user's activities; assert the safer default stays put.
        assert_eq!(IsolationLevel::default(), IsolationLevel::PerHost);
    }
}
