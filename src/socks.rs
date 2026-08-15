//! A local SOCKS5 proxy that routes traffic over Tor.
//!
//! Point any SOCKS5-capable program at it and its traffic goes through the Tor
//! network:
//!
//! ```console
//! $ curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
//! ```
//!
//! # Always use `socks5h`, never `socks5`
//!
//! `socks5h://` (curl's `--socks5-hostname`) sends the *hostname* to the proxy
//! and lets Tor resolve it. Plain `socks5://` makes the client resolve the name
//! locally first, which emits a plaintext DNS query from your real IP address
//! for every site you visit — a complete deanonymisation of your browsing, even
//! though the traffic itself is tunnelled.
//!
//! This proxy rejects requests carrying a locally-resolved IP literal unless you
//! opt in, precisely so a misconfigured client fails loudly instead of leaking
//! quietly.
//!
//! # Stream isolation via SOCKS credentials
//!
//! Following Tor's `IsolateSOCKSAuth` convention, connections presenting
//! different SOCKS username/password pairs are placed on different circuits.
//! Any credentials are accepted — they are an isolation label, not a secret:
//!
//! ```console
//! $ curl -x socks5h://alice:x@127.0.0.1:9050 https://example.com   # circuit A
//! $ curl -x socks5h://bob:x@127.0.0.1:9050   https://example.com   # circuit B
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use arti_client::{StreamPrefs, TorClient as ArtiClient};
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tor_rtcompat::PreferredRuntime;
use tracing::{debug, info, warn};

use crate::error::{Error, Result};
use crate::isolation::IsolationToken;

mod wire {
    pub const VERSION: u8 = 0x05;

    pub const AUTH_NONE: u8 = 0x00;
    pub const AUTH_USERPASS: u8 = 0x02;
    pub const AUTH_UNACCEPTABLE: u8 = 0xFF;

    pub const CMD_CONNECT: u8 = 0x01;

    pub const ATYP_IPV4: u8 = 0x01;
    pub const ATYP_DOMAIN: u8 = 0x03;
    pub const ATYP_IPV6: u8 = 0x04;

    pub const REPLY_SUCCESS: u8 = 0x00;
    pub const REPLY_GENERAL_FAILURE: u8 = 0x01;
    pub const REPLY_NOT_ALLOWED: u8 = 0x02;
    pub const REPLY_HOST_UNREACHABLE: u8 = 0x04;
    pub const REPLY_CMD_NOT_SUPPORTED: u8 = 0x07;
    pub const REPLY_ATYP_NOT_SUPPORTED: u8 = 0x08;
}

/// Configuration for the SOCKS5 proxy.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SocksConfig {
    /// Address to listen on. Defaults to `127.0.0.1:9050`.
    pub bind_addr: SocketAddr,
    /// Maximum simultaneous client connections.
    pub max_connections: usize,
    /// Place connections with different SOCKS credentials on different circuits.
    pub isolate_socks_auth: bool,
    /// Accept requests naming a bare IP address rather than a hostname.
    ///
    /// Off by default. An IP literal usually means the client resolved the name
    /// itself, which leaks it outside Tor; see the module documentation.
    pub allow_ip_literals: bool,
    /// Permit binding to an address other than loopback.
    ///
    /// Off by default: a SOCKS proxy reachable from the network is an open
    /// proxy that anyone can route traffic through, attributed to you.
    pub allow_non_loopback_bind: bool,
}

impl Default for SocksConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 9050)),
            max_connections: 256,
            isolate_socks_auth: true,
            allow_ip_literals: false,
            allow_non_loopback_bind: false,
        }
    }
}

/// Maps SOCKS credentials to circuits.
///
/// Extracted so the isolation rules can be tested without bootstrapping Tor.
#[derive(Debug, Default)]
struct IsolationMap {
    entries: Mutex<HashMap<(String, String), IsolationToken>>,
}

/// Cap on remembered credential pairs, so a client cycling credentials cannot
/// grow the map without bound.
const MAX_ISOLATION_ENTRIES: usize = 1024;

impl IsolationMap {
    /// The circuit for these credentials, creating one on first sight.
    fn token_for(&self, credentials: (String, String)) -> IsolationToken {
        let mut entries = self.entries.lock();

        if entries.len() >= MAX_ISOLATION_ENTRIES && !entries.contains_key(&credentials) {
            debug!("clearing the SOCKS isolation map at capacity");
            entries.clear();
        }

        *entries.entry(credentials).or_default()
    }
}

/// Whether binding here would expose an open proxy to the network.
fn bind_is_allowed(addr: &SocketAddr, allow_non_loopback: bool) -> bool {
    addr.ip().is_loopback() || allow_non_loopback
}

/// A SOCKS5 proxy fronting a Tor client.
pub struct SocksProxy {
    tor: Arc<ArtiClient<PreferredRuntime>>,
    config: SocksConfig,
    isolation: IsolationMap,
}

impl SocksProxy {
    /// Build a proxy over an existing Tor client.
    pub fn new(tor: Arc<ArtiClient<PreferredRuntime>>, config: SocksConfig) -> Self {
        Self {
            tor,
            config,
            isolation: IsolationMap::default(),
        }
    }

    /// Build a proxy over a [`TorClient`](crate::TorClient)'s Tor instance.
    pub fn from_client(client: &crate::TorClient, config: SocksConfig) -> Self {
        // `isolated_client` shares the bootstrapped instance — one directory
        // download, one guard set — while keeping proxied traffic on circuits
        // separate from the owning client's own requests.
        Self::new(client.arti().isolated_client(), config)
    }

    /// Serve until the future is dropped or the listener fails.
    pub async fn run(self) -> Result<()> {
        let addr = self.config.bind_addr;

        if !bind_is_allowed(&addr, self.config.allow_non_loopback_bind) {
            return Err(Error::config(format!(
                "refusing to bind a SOCKS proxy to {addr}, which is reachable from the network; \
                 bind to 127.0.0.1 or set allow_non_loopback_bind if you really mean it"
            )));
        }

        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| Error::config(format!("could not bind {addr}: {e}")))?;

        info!(%addr, "SOCKS5 proxy listening");

        let permits = Arc::new(tokio::sync::Semaphore::new(self.config.max_connections));
        let this = Arc::new(self);

        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    warn!(error = %e, "accept failed");
                    continue;
                }
            };

            let Ok(permit) = Arc::clone(&permits).acquire_owned().await else {
                break;
            };

            let this = Arc::clone(&this);
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = this.serve_one(stream).await {
                    debug!(%peer, error = %e, "SOCKS connection ended");
                }
            });
        }

        Ok(())
    }

    async fn serve_one(&self, mut client: TcpStream) -> Result<()> {
        let credentials = self.negotiate_auth(&mut client).await?;
        let (host, port) = self.read_request(&mut client).await?;

        let mut prefs = StreamPrefs::new();
        if let Some(token) = self.isolation_for(credentials) {
            prefs.set_isolation(token.inner());
        }

        let tor_stream = match self
            .tor
            .connect_with_prefs((host.as_str(), port), &prefs)
            .await
        {
            Ok(stream) => stream,
            Err(e) => {
                reply(&mut client, wire::REPLY_HOST_UNREACHABLE).await?;
                return Err(Error::connect(&host, port, e));
            }
        };

        reply(&mut client, wire::REPLY_SUCCESS).await?;

        // `copy_bidirectional` propagates each half-close independently. The
        // previous implementation raced the two directions with `select!` and
        // dropped whatever was still in flight on the other one.
        let mut tor_stream = tor_stream;
        match tokio::io::copy_bidirectional(&mut client, &mut tor_stream).await {
            Ok((up, down)) => debug!(up, down, "relay finished"),
            Err(e) => debug!(error = %e, "relay ended"),
        }

        Ok(())
    }

    /// Negotiate authentication, returning any credentials offered.
    async fn negotiate_auth(&self, client: &mut TcpStream) -> Result<Option<(String, String)>> {
        let mut head = [0u8; 2];
        client.read_exact(&mut head).await?;

        if head[0] != wire::VERSION {
            return Err(Error::invalid_request(format!(
                "not a SOCKS5 greeting (version byte {})",
                head[0]
            )));
        }

        let mut methods = vec![0u8; head[1] as usize];
        client.read_exact(&mut methods).await?;

        // Prefer username/password when the client offers it and isolation is
        // enabled, since the credentials are what select the circuit.
        let chosen = if self.config.isolate_socks_auth && methods.contains(&wire::AUTH_USERPASS) {
            wire::AUTH_USERPASS
        } else if methods.contains(&wire::AUTH_NONE) {
            wire::AUTH_NONE
        } else {
            client
                .write_all(&[wire::VERSION, wire::AUTH_UNACCEPTABLE])
                .await?;
            return Err(Error::invalid_request(
                "client offered no authentication method this proxy supports",
            ));
        };

        client.write_all(&[wire::VERSION, chosen]).await?;

        if chosen != wire::AUTH_USERPASS {
            return Ok(None);
        }

        // RFC 1929 username/password sub-negotiation.
        let mut version = [0u8; 1];
        client.read_exact(&mut version).await?;
        if version[0] != 0x01 {
            return Err(Error::invalid_request(
                "unsupported SOCKS username/password sub-negotiation version",
            ));
        }

        let username = read_prefixed_string(client).await?;
        let password = read_prefixed_string(client).await?;

        // Always succeed: these are an isolation label, not a credential to
        // verify. The proxy is loopback-only, so there is nothing to guard.
        client.write_all(&[0x01, 0x00]).await?;

        Ok(Some((username, password)))
    }

    async fn read_request(&self, client: &mut TcpStream) -> Result<(String, u16)> {
        let mut head = [0u8; 4];
        client.read_exact(&mut head).await?;

        if head[0] != wire::VERSION {
            return Err(Error::invalid_request("not a SOCKS5 request"));
        }

        if head[1] != wire::CMD_CONNECT {
            reply(client, wire::REPLY_CMD_NOT_SUPPORTED).await?;
            return Err(Error::invalid_request(
                "only the CONNECT command is supported; BIND and UDP ASSOCIATE \
                 have no meaning over Tor",
            ));
        }

        let host = match head[3] {
            wire::ATYP_DOMAIN => {
                let mut len = [0u8; 1];
                client.read_exact(&mut len).await?;
                let mut name = vec![0u8; len[0] as usize];
                client.read_exact(&mut name).await?;
                String::from_utf8(name)
                    .map_err(|_| Error::invalid_request("domain name is not valid UTF-8"))?
            }
            wire::ATYP_IPV4 => {
                let mut octets = [0u8; 4];
                client.read_exact(&mut octets).await?;
                IpAddr::from(octets).to_string()
            }
            wire::ATYP_IPV6 => {
                let mut octets = [0u8; 16];
                client.read_exact(&mut octets).await?;
                IpAddr::from(octets).to_string()
            }
            other => {
                reply(client, wire::REPLY_ATYP_NOT_SUPPORTED).await?;
                return Err(Error::invalid_request(format!(
                    "unsupported SOCKS address type {other}"
                )));
            }
        };

        let mut port = [0u8; 2];
        client.read_exact(&mut port).await?;
        let port = u16::from_be_bytes(port);

        if head[3] != wire::ATYP_DOMAIN && !self.config.allow_ip_literals {
            reply(client, wire::REPLY_NOT_ALLOWED).await?;
            return Err(Error::invalid_request(
                "client sent an IP address rather than a hostname, which means it \
                 resolved the name locally and leaked a DNS query outside Tor; \
                 use socks5h:// (curl: --socks5-hostname)",
            ));
        }

        Ok((host, port))
    }

    /// The circuit to use for a connection with these credentials.
    fn isolation_for(&self, credentials: Option<(String, String)>) -> Option<IsolationToken> {
        if !self.config.isolate_socks_auth {
            return None;
        }
        Some(self.isolation.token_for(credentials?))
    }
}

async fn read_prefixed_string(client: &mut TcpStream) -> Result<String> {
    let mut len = [0u8; 1];
    client.read_exact(&mut len).await?;
    let mut buf = vec![0u8; len[0] as usize];
    client.read_exact(&mut buf).await?;
    String::from_utf8(buf)
        .map_err(|_| Error::invalid_request("SOCKS credentials are not valid UTF-8"))
}

/// Send a SOCKS5 reply with an all-zero bound address.
async fn reply(client: &mut TcpStream, code: u8) -> Result<()> {
    let response = [
        wire::VERSION,
        code,
        0x00,
        wire::ATYP_IPV4,
        0,
        0,
        0,
        0, // bound address
        0,
        0, // bound port
    ];
    client.write_all(&response).await?;
    Ok(())
}

// Keeps the constant referenced even when no code path currently sends it.
const _: u8 = wire::REPLY_GENERAL_FAILURE;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_loopback_only() {
        let config = SocksConfig::default();
        assert!(config.bind_addr.ip().is_loopback());
        assert_eq!(config.bind_addr.port(), 9050);
        // An open proxy and a local DNS leak are both off by default.
        assert!(!config.allow_non_loopback_bind);
        assert!(!config.allow_ip_literals);
        assert!(config.isolate_socks_auth);
    }

    #[test]
    fn public_bind_addresses_are_refused_unless_opted_into() {
        let public = SocketAddr::from(([0, 0, 0, 0], 9050));
        let loopback = SocketAddr::from(([127, 0, 0, 1], 9050));

        assert!(
            !bind_is_allowed(&public, false),
            "open proxy must be refused"
        );
        assert!(bind_is_allowed(&public, true), "explicit opt-in must work");
        assert!(bind_is_allowed(&loopback, false));
    }

    #[test]
    fn identical_credentials_share_a_circuit() {
        let map = IsolationMap::default();

        let alice1 = map.token_for(("alice".into(), "x".into()));
        let alice2 = map.token_for(("alice".into(), "x".into()));
        let bob = map.token_for(("bob".into(), "x".into()));

        assert_eq!(alice1, alice2, "same credentials must reuse one circuit");
        assert_ne!(
            alice1, bob,
            "different credentials must not share a circuit"
        );
    }

    #[test]
    fn the_password_is_part_of_the_isolation_key() {
        let map = IsolationMap::default();
        let a = map.token_for(("alice".into(), "one".into()));
        let b = map.token_for(("alice".into(), "two".into()));
        assert_ne!(a, b);
    }

    #[test]
    fn the_isolation_map_stays_bounded() {
        let map = IsolationMap::default();
        for i in 0..(MAX_ISOLATION_ENTRIES * 2) {
            map.token_for((format!("user{i}"), "x".into()));
        }
        assert!(
            map.entries.lock().len() <= MAX_ISOLATION_ENTRIES,
            "an unbounded map is a memory leak reachable by any local client"
        );
    }
}
