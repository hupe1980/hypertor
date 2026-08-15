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
use std::hash::{BuildHasher, RandomState};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use arti_client::{StreamPrefs, TorClient as ArtiClient};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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
    // Tor's SOCKS extensions (socks-extensions.txt). RESOLVE lets a client ask
    // the proxy to look a name up instead of resolving it itself, which is the
    // difference between a DNS query inside Tor and a plaintext one from the
    // user's own address.
    pub const CMD_RESOLVE: u8 = 0xF0;
    pub const CMD_RESOLVE_PTR: u8 = 0xF1;

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
    ///
    /// Use port 0 to let the OS choose one, then read it back with
    /// [`SocksProxy::local_addr`].
    pub bind_addr: SocketAddr,
    /// Maximum simultaneous client connections.
    pub max_connections: usize,
    /// How long a client may take to complete the SOCKS handshake.
    ///
    /// Without this a client that connects and then says nothing holds a
    /// connection slot forever, so any local process could exhaust the proxy
    /// with `max_connections` idle sockets.
    pub handshake_timeout: Duration,
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
            handshake_timeout: Duration::from_secs(10),
            isolate_socks_auth: true,
            allow_ip_literals: false,
            allow_non_loopback_bind: false,
        }
    }
}

/// Maps SOCKS credentials to circuits.
///
/// Extracted so the isolation rules can be tested without bootstrapping Tor.
///
/// The credentials are keyed by a hash rather than stored. They are an
/// isolation label rather than a secret — the proxy authenticates nobody — but
/// people reuse passwords, and a long-lived map of plaintext credentials is a
/// thing worth not having in a process image or a core dump. `RandomState` is
/// SipHash under a key generated at startup, so the map cannot be made to
/// collide by a caller who does not know it, and an accidental collision across
/// the 1024-entry cap is on the order of one in 10^14.
#[derive(Debug, Default)]
struct IsolationMap {
    entries: Mutex<HashMap<u64, IsolationToken>>,
    key: RandomState,
}

/// Cap on remembered credential pairs, so a client cycling credentials cannot
/// grow the map without bound.
const MAX_ISOLATION_ENTRIES: usize = 1024;

/// First and last pause after a recoverable `accept` failure.
const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(10);
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

/// Whether an `accept` failure means the listener will never work again.
///
/// Everything else — a peer that vanished mid-handshake, a momentary descriptor
/// shortage — is transient, and tearing the proxy down for it would be worse
/// than waiting.
fn is_fatal_accept_error(error: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        error.kind(),
        ErrorKind::InvalidInput | ErrorKind::BrokenPipe | ErrorKind::NotConnected
    )
}

impl IsolationMap {
    /// The circuit for these credentials, creating one on first sight.
    fn token_for(&self, credentials: (String, String)) -> IsolationToken {
        let label = self.key.hash_one(credentials);
        let mut entries = self.entries.lock();

        if entries.len() >= MAX_ISOLATION_ENTRIES && !entries.contains_key(&label) {
            debug!("clearing the SOCKS isolation map at capacity");
            entries.clear();
        }

        *entries.entry(label).or_default()
    }
}

/// What a client asked the proxy to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Command {
    /// Open a tunnel — the ordinary SOCKS5 command.
    Connect,
    /// Look up a name at an exit relay (Tor extension `0xF0`).
    Resolve,
    /// Look up a name for an address at an exit relay (Tor extension `0xF1`).
    ResolvePtr,
}

/// A parsed SOCKS5 request.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Request {
    command: Command,
    host: String,
    /// Zero for the lookup commands, which have no port.
    port: u16,
}

/// Whether binding here would expose an open proxy to the network.
fn bind_is_allowed(addr: &SocketAddr, allow_non_loopback: bool) -> bool {
    addr.ip().is_loopback() || allow_non_loopback
}

/// A SOCKS5 proxy fronting a Tor client.
///
/// [`bind`](Self::bind) claims the port and returns immediately, so the actual
/// address is known before any traffic is served — which is what you need for
/// port 0, for tests, and for telling the user where to point their browser.
pub struct SocksProxy {
    tor: Arc<ArtiClient<PreferredRuntime>>,
    config: SocksConfig,
    isolation: IsolationMap,
    listener: TcpListener,
}

impl SocksProxy {
    /// Bind the listening socket.
    ///
    /// Fails rather than binding a publicly reachable address unless
    /// [`allow_non_loopback_bind`](SocksConfig::allow_non_loopback_bind) is set.
    pub async fn bind(tor: Arc<ArtiClient<PreferredRuntime>>, config: SocksConfig) -> Result<Self> {
        let addr = config.bind_addr;

        if !bind_is_allowed(&addr, config.allow_non_loopback_bind) {
            return Err(Error::config(format!(
                "refusing to bind a SOCKS proxy to {addr}, which is reachable from the network; \
                 bind to 127.0.0.1 or set allow_non_loopback_bind if you really mean it"
            )));
        }

        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| Error::config(format!("could not bind {addr}: {e}")))?;

        Ok(Self {
            tor,
            config,
            isolation: IsolationMap::default(),
            listener,
        })
    }

    /// Bind a proxy over a [`TorClient`](crate::TorClient)'s Tor instance.
    pub async fn from_client(client: &crate::TorClient, config: SocksConfig) -> Result<Self> {
        // `isolated_client` shares the bootstrapped instance — one directory
        // download, one guard set — while keeping proxied traffic on circuits
        // separate from the owning client's own requests.
        Self::bind(client.arti().isolated_client(), config).await
    }

    /// The address actually bound, which differs from the configured one when
    /// the port was 0.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// The configuration in use.
    pub fn config(&self) -> &SocksConfig {
        &self.config
    }

    /// Serve until the returned future is dropped or the listener fails
    /// unrecoverably.
    ///
    /// Drop the future — or the task holding it — to stop accepting. In-flight
    /// relays end with their connections.
    pub async fn serve(self) -> Result<()> {
        let addr = self.local_addr()?;
        info!(%addr, "SOCKS5 proxy listening");

        let permits = Arc::new(tokio::sync::Semaphore::new(self.config.max_connections));
        let this = Arc::new(self);
        let mut backoff = Duration::ZERO;

        loop {
            let (stream, peer) = match this.listener.accept().await {
                Ok(pair) => {
                    backoff = Duration::ZERO;
                    pair
                }
                Err(e) if is_fatal_accept_error(&e) => {
                    return Err(Error::config(format!(
                        "the SOCKS listener on {addr} stopped working: {e}"
                    )));
                }
                Err(e) => {
                    // Running out of file descriptors makes `accept` fail
                    // immediately and keep failing. Retrying with no delay turns
                    // that into a busy loop that burns a core and starves the
                    // very tasks whose completion would free a descriptor.
                    backoff = match backoff {
                        Duration::ZERO => ACCEPT_BACKOFF_MIN,
                        current => (current * 2).min(ACCEPT_BACKOFF_MAX),
                    };
                    warn!(error = %e, ?backoff, "accept failed; backing off");
                    tokio::time::sleep(backoff).await;
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
        // The handshake is bounded; the relay that follows is not, because a
        // long-lived tunnel is the whole point of a proxy.
        let deadline = self.config.handshake_timeout;
        let (credentials, request) = tokio::time::timeout(deadline, async {
            let credentials = self.negotiate_auth(&mut client).await?;
            let request = self.read_request(&mut client).await?;
            Ok::<_, Error>((credentials, request))
        })
        .await
        .map_err(|_| Error::timeout("SOCKS handshake", deadline))??;

        let mut prefs = StreamPrefs::new();
        if let Some(token) = self.isolation_for(credentials) {
            prefs.set_isolation(token.inner());
        }

        let Request {
            command,
            host,
            port,
        } = request;

        // The two name-lookup commands answer and close; only CONNECT goes on
        // to relay bytes.
        match command {
            Command::Resolve => return self.serve_resolve(&mut client, &host, &prefs).await,
            Command::ResolvePtr => return self.serve_resolve_ptr(&mut client, &host, &prefs).await,
            Command::Connect => {}
        }

        let tor_stream = match self
            .tor
            .connect_with_prefs((host.as_str(), port), &prefs)
            .await
        {
            Ok(stream) => stream,
            Err(e) => {
                let _ = reply(&mut client, wire::REPLY_HOST_UNREACHABLE).await;
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

    /// Answer a Tor `RESOLVE`: look the name up at an exit relay.
    ///
    /// This is the whole reason the extension exists. A client that cannot ask
    /// the proxy to resolve for it either fails or falls back to the system
    /// resolver, and the fallback emits a plaintext DNS query from the user's
    /// real address for every host they visit — the exact leak the proxy is
    /// there to prevent.
    async fn serve_resolve<S: AsyncWrite + Unpin>(
        &self,
        client: &mut S,
        host: &str,
        prefs: &StreamPrefs,
    ) -> Result<()> {
        let addresses = match self.tor.resolve_with_prefs(host, prefs).await {
            Ok(addresses) => addresses,
            Err(e) => {
                let _ = reply(client, wire::REPLY_HOST_UNREACHABLE).await;
                return Err(Error::connect(host, 0, e));
            }
        };

        let Some(address) = addresses.into_iter().next() else {
            let _ = reply(client, wire::REPLY_HOST_UNREACHABLE).await;
            return Err(Error::invalid_request(
                "the exit relay returned no address for that name",
            ));
        };

        debug!("answered a RESOLVE through Tor");
        reply_with_address(client, address).await
    }

    /// Answer a Tor `RESOLVE_PTR`: reverse-look-up at an exit relay.
    async fn serve_resolve_ptr<S: AsyncWrite + Unpin>(
        &self,
        client: &mut S,
        host: &str,
        prefs: &StreamPrefs,
    ) -> Result<()> {
        let address: IpAddr = host.parse().map_err(|_| {
            Error::invalid_request("RESOLVE_PTR needs an IP address, not a hostname")
        })?;

        let names = match self.tor.resolve_ptr_with_prefs(address, prefs).await {
            Ok(names) => names,
            Err(e) => {
                let _ = reply(client, wire::REPLY_HOST_UNREACHABLE).await;
                return Err(Error::connect(host, 0, e));
            }
        };

        let Some(name) = names.into_iter().next() else {
            let _ = reply(client, wire::REPLY_HOST_UNREACHABLE).await;
            return Err(Error::invalid_request(
                "the exit relay returned no name for that address",
            ));
        };

        debug!("answered a RESOLVE_PTR through Tor");
        reply_with_domain(client, &name).await
    }

    /// Negotiate authentication, returning any credentials offered.
    async fn negotiate_auth<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        client: &mut S,
    ) -> Result<Option<(String, String)>> {
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

    async fn read_request<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        client: &mut S,
    ) -> Result<Request> {
        read_request(&self.config, client).await
    }

    /// The circuit to use for a connection with these credentials.
    fn isolation_for(&self, credentials: Option<(String, String)>) -> Option<IsolationToken> {
        if !self.config.isolate_socks_auth {
            return None;
        }
        Some(self.isolation.token_for(credentials?))
    }
}

/// Parse a SOCKS5 request.
///
/// A free function taking only the configuration: nothing here needs the
/// proxy, and keeping it separate means the whole request grammar — including
/// the DNS-leak guard — is exercised by tests over an in-memory pipe rather
/// than only against a live listener.
async fn read_request<S: AsyncRead + AsyncWrite + Unpin>(
    config: &SocksConfig,
    client: &mut S,
) -> Result<Request> {
    let mut head = [0u8; 4];
    client.read_exact(&mut head).await?;

    if head[0] != wire::VERSION {
        return Err(Error::invalid_request("not a SOCKS5 request"));
    }

    let command = match head[1] {
        wire::CMD_CONNECT => Command::Connect,
        wire::CMD_RESOLVE => Command::Resolve,
        wire::CMD_RESOLVE_PTR => Command::ResolvePtr,
        _ => {
            let _ = reply(client, wire::REPLY_CMD_NOT_SUPPORTED).await;
            return Err(Error::invalid_request(
                "supported commands are CONNECT and Tor's RESOLVE and \
                     RESOLVE_PTR; BIND and UDP ASSOCIATE have no meaning over Tor",
            ));
        }
    };

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
            let _ = reply(client, wire::REPLY_ATYP_NOT_SUPPORTED).await;
            return Err(Error::invalid_request(format!(
                "unsupported SOCKS address type {other}"
            )));
        }
    };

    let mut port = [0u8; 2];
    client.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);

    // The leak guard applies to CONNECT alone. A RESOLVE carries a name by
    // definition, and a RESOLVE_PTR carries an address by definition — both
    // are the client asking Tor to do the lookup, which is the behaviour
    // this check exists to encourage.
    if command == Command::Connect && head[3] != wire::ATYP_DOMAIN && !config.allow_ip_literals {
        reply(client, wire::REPLY_NOT_ALLOWED).await?;
        return Err(Error::invalid_request(
            "client sent an IP address rather than a hostname, which means it \
                 resolved the name locally and leaked a DNS query outside Tor; \
                 use socks5h:// (curl: --socks5-hostname)",
        ));
    }

    if command == Command::ResolvePtr && head[3] == wire::ATYP_DOMAIN {
        reply(client, wire::REPLY_NOT_ALLOWED).await?;
        return Err(Error::invalid_request(
            "RESOLVE_PTR needs an IP address, not a hostname",
        ));
    }

    Ok(Request {
        command,
        host,
        port,
    })
}

async fn read_prefixed_string<S: AsyncRead + Unpin>(client: &mut S) -> Result<String> {
    let mut len = [0u8; 1];
    client.read_exact(&mut len).await?;
    let mut buf = vec![0u8; len[0] as usize];
    client.read_exact(&mut buf).await?;
    String::from_utf8(buf)
        .map_err(|_| Error::invalid_request("SOCKS credentials are not valid UTF-8"))
}

/// Send a SOCKS5 reply with an all-zero bound address.
async fn reply<S: AsyncWrite + Unpin>(client: &mut S, code: u8) -> Result<()> {
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

/// Answer a `RESOLVE`: success, with the address in the bound-address field.
///
/// Tor's socks-extensions.txt specifies exactly this reuse of the reply's
/// address field, which is why no new message type is involved.
async fn reply_with_address<S: AsyncWrite + Unpin>(client: &mut S, address: IpAddr) -> Result<()> {
    let mut response = vec![wire::VERSION, wire::REPLY_SUCCESS, 0x00];
    match address {
        IpAddr::V4(v4) => {
            response.push(wire::ATYP_IPV4);
            response.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            response.push(wire::ATYP_IPV6);
            response.extend_from_slice(&v6.octets());
        }
    }
    response.extend_from_slice(&0u16.to_be_bytes());
    client.write_all(&response).await?;
    Ok(())
}

/// Answer a `RESOLVE_PTR`: success, with the name in the bound-address field.
async fn reply_with_domain<S: AsyncWrite + Unpin>(client: &mut S, name: &str) -> Result<()> {
    let bytes = name.as_bytes();
    let len = u8::try_from(bytes.len())
        .map_err(|_| Error::invalid_request("the resolved name does not fit in a SOCKS reply"))?;

    let mut response = vec![
        wire::VERSION,
        wire::REPLY_SUCCESS,
        0x00,
        wire::ATYP_DOMAIN,
        len,
    ];
    response.extend_from_slice(bytes);
    response.extend_from_slice(&0u16.to_be_bytes());
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
        // A handshake that never completes must not hold a slot forever.
        assert!(!config.handshake_timeout.is_zero());
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
    fn credentials_are_not_retained_in_the_isolation_map() {
        // They are an isolation label rather than a secret, but people reuse
        // passwords and a long-lived map of them is a thing worth not having.
        let map = IsolationMap::default();
        map.token_for(("alice".into(), "hunter2".into()));

        let held = format!("{:?}", map.entries.lock());
        assert!(!held.contains("hunter2"), "the password was kept: {held}");
        assert!(!held.contains("alice"), "the username was kept: {held}");
    }

    // ---- the wire protocol -------------------------------------------------
    //
    // Driven over an in-memory pipe, so request parsing and reply encoding are
    // covered without a listening socket or a Tor circuit.

    /// Parse a request buffer with the given configuration.
    async fn read_request_with(config: &SocksConfig, bytes: &[u8]) -> Result<Request> {
        let (mut client, mut server) = tokio::io::duplex(1024);
        client.write_all(bytes).await.expect("write");
        // Held open across the call: a refusal writes a reply back, and a
        // closed pipe would turn the interesting error into "broken pipe".
        let parsed = read_request(config, &mut server).await;
        drop(client);
        parsed
    }

    #[tokio::test]
    async fn parses_a_connect_to_a_hostname() {
        let mut bytes = vec![
            wire::VERSION,
            wire::CMD_CONNECT,
            0x00,
            wire::ATYP_DOMAIN,
            11,
        ];
        bytes.extend_from_slice(b"example.com");
        bytes.extend_from_slice(&443u16.to_be_bytes());

        let request = read_request_with(&SocksConfig::default(), &bytes)
            .await
            .expect("parses");
        assert_eq!(
            request,
            Request {
                command: Command::Connect,
                host: "example.com".into(),
                port: 443,
            }
        );
    }

    #[tokio::test]
    async fn a_connect_to_an_ip_literal_is_refused_by_default() {
        // An IP literal means the client resolved the name itself, which emits
        // a plaintext DNS query from the user's real address.
        let mut bytes = vec![wire::VERSION, wire::CMD_CONNECT, 0x00, wire::ATYP_IPV4];
        bytes.extend_from_slice(&[93, 184, 216, 34]);
        bytes.extend_from_slice(&443u16.to_be_bytes());

        let err = read_request_with(&SocksConfig::default(), &bytes)
            .await
            .expect_err("must refuse");
        assert!(err.to_string().contains("socks5h"), "unhelpful: {err}");

        let permissive = SocksConfig {
            allow_ip_literals: true,
            ..Default::default()
        };
        assert!(read_request_with(&permissive, &bytes).await.is_ok());
    }

    #[tokio::test]
    async fn a_resolve_carries_a_hostname_and_is_not_treated_as_a_leak() {
        // The leak guard is about CONNECT. A RESOLVE naming a host is the
        // client doing exactly the right thing.
        let mut bytes = vec![
            wire::VERSION,
            wire::CMD_RESOLVE,
            0x00,
            wire::ATYP_DOMAIN,
            11,
        ];
        bytes.extend_from_slice(b"example.com");
        bytes.extend_from_slice(&0u16.to_be_bytes());

        let request = read_request_with(&SocksConfig::default(), &bytes)
            .await
            .expect("parses");
        assert_eq!(request.command, Command::Resolve);
        assert_eq!(request.host, "example.com");
    }

    #[tokio::test]
    async fn a_resolve_ptr_carries_an_address_and_is_not_treated_as_a_leak() {
        let mut bytes = vec![wire::VERSION, wire::CMD_RESOLVE_PTR, 0x00, wire::ATYP_IPV4];
        bytes.extend_from_slice(&[93, 184, 216, 34]);
        bytes.extend_from_slice(&0u16.to_be_bytes());

        let request = read_request_with(&SocksConfig::default(), &bytes)
            .await
            .expect("an address is required here, not a leak");
        assert_eq!(request.command, Command::ResolvePtr);
        assert_eq!(request.host, "93.184.216.34");
    }

    #[tokio::test]
    async fn a_resolve_ptr_naming_a_host_is_rejected() {
        let mut bytes = vec![
            wire::VERSION,
            wire::CMD_RESOLVE_PTR,
            0x00,
            wire::ATYP_DOMAIN,
            11,
        ];
        bytes.extend_from_slice(b"example.com");
        bytes.extend_from_slice(&0u16.to_be_bytes());

        assert!(
            read_request_with(&SocksConfig::default(), &bytes)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn bind_and_udp_associate_are_refused() {
        // Neither has any meaning over Tor.
        for command in [0x02u8, 0x03] {
            let mut bytes = vec![wire::VERSION, command, 0x00, wire::ATYP_DOMAIN, 3];
            bytes.extend_from_slice(b"foo");
            bytes.extend_from_slice(&80u16.to_be_bytes());

            assert!(
                read_request_with(&SocksConfig::default(), &bytes)
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn a_resolve_reply_carries_the_address_in_the_bound_field() {
        // Tor's socks-extensions.txt reuses the reply's address field for the
        // answer, which is why there is no separate message type.
        let (mut client, mut server) = tokio::io::duplex(1024);
        reply_with_address(&mut server, "192.0.2.7".parse().unwrap())
            .await
            .expect("writes");
        drop(server);

        let mut got = Vec::new();
        client.read_to_end(&mut got).await.expect("reads");

        assert_eq!(got[0], wire::VERSION);
        assert_eq!(got[1], wire::REPLY_SUCCESS);
        assert_eq!(got[3], wire::ATYP_IPV4);
        assert_eq!(&got[4..8], &[192, 0, 2, 7]);
        assert_eq!(&got[8..10], &[0, 0], "a lookup answer has no port");
    }

    #[tokio::test]
    async fn a_resolve_ptr_reply_carries_the_name() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        reply_with_domain(&mut server, "example.com")
            .await
            .expect("writes");
        drop(server);

        let mut got = Vec::new();
        client.read_to_end(&mut got).await.expect("reads");

        assert_eq!(got[3], wire::ATYP_DOMAIN);
        assert_eq!(got[4] as usize, "example.com".len());
        assert_eq!(&got[5..5 + 11], b"example.com");
    }

    #[test]
    fn transient_accept_failures_do_not_kill_the_listener() {
        use std::io::{Error as IoError, ErrorKind};

        // Descriptor exhaustion is the common case, and it recovers as soon as
        // an in-flight connection closes.
        for kind in [
            ErrorKind::ConnectionAborted,
            ErrorKind::Interrupted,
            ErrorKind::WouldBlock,
        ] {
            assert!(
                !is_fatal_accept_error(&IoError::from(kind)),
                "{kind:?} must be retried, not fatal"
            );
        }
        assert!(!is_fatal_accept_error(&IoError::other(
            "too many open files"
        )));

        assert!(is_fatal_accept_error(&IoError::from(
            ErrorKind::InvalidInput
        )));
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
