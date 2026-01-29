//! SOCKS5 proxy server implementation.
//!
//! Provides a local SOCKS5 proxy that routes traffic through Tor,
//! allowing applications that support SOCKS5 to transparently use Tor.

use crate::{Config, Error, Result};
use arti_client::{TorClient as ArtiClient, TorClientConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tor_rtcompat::PreferredRuntime;
use tracing::{debug, error, info, warn};

/// SOCKS5 protocol constants
mod socks5 {
    pub const VERSION: u8 = 0x05;
    pub const AUTH_NONE: u8 = 0x00;
    pub const AUTH_NO_ACCEPTABLE: u8 = 0xFF;
    pub const CMD_CONNECT: u8 = 0x01;
    pub const ATYP_IPV4: u8 = 0x01;
    pub const ATYP_DOMAIN: u8 = 0x03;
    pub const ATYP_IPV6: u8 = 0x04;
    pub const REPLY_SUCCESS: u8 = 0x00;
    #[allow(dead_code)]
    pub const REPLY_GENERAL_FAILURE: u8 = 0x01;
    pub const REPLY_CONNECTION_REFUSED: u8 = 0x05;
    pub const REPLY_CMD_NOT_SUPPORTED: u8 = 0x07;
    pub const REPLY_ATYP_NOT_SUPPORTED: u8 = 0x08;
}

/// Configuration for the SOCKS5 proxy server.
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    /// Address to bind the proxy server to.
    pub bind_addr: SocketAddr,
    /// Optional isolation token for stream isolation.
    pub isolation_token: Option<u64>,
    /// Maximum concurrent connections.
    pub max_connections: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        Self {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9050),
            isolation_token: None,
            max_connections: 256,
        }
    }
}

impl ProxyConfig {
    /// Create a new proxy configuration with the given bind address.
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self {
            bind_addr,
            ..Default::default()
        }
    }

    /// Set the isolation token for stream isolation.
    pub fn with_isolation(mut self, token: u64) -> Self {
        self.isolation_token = Some(token);
        self
    }

    /// Set the maximum number of concurrent connections.
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }
}

/// A SOCKS5 proxy server that routes traffic through Tor.
pub struct Socks5Proxy {
    config: ProxyConfig,
    #[allow(dead_code)]
    tor_config: Config,
    shutdown: Arc<Notify>,
}

impl Socks5Proxy {
    /// Create a new SOCKS5 proxy with the given configuration.
    pub fn new(config: ProxyConfig, tor_config: Config) -> Self {
        Self {
            config,
            tor_config,
            shutdown: Arc::new(Notify::new()),
        }
    }

    /// Create a new SOCKS5 proxy with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(ProxyConfig::default(), Config::default())
    }

    /// Get a handle to signal shutdown.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            notify: self.shutdown.clone(),
        }
    }

    /// Start the proxy server.
    ///
    /// This method will block until shutdown is signaled.
    pub async fn run(self) -> Result<()> {
        let listener = TcpListener::bind(self.config.bind_addr)
            .await
            .map_err(|e| {
                Error::io(
                    format!("Failed to bind proxy to {}", self.config.bind_addr),
                    e,
                )
            })?;

        info!(addr = %self.config.bind_addr, "SOCKS5 proxy listening");

        // Bootstrap Tor
        let arti_config = TorClientConfig::default();
        let tor_client = ArtiClient::create_bootstrapped(arti_config)
            .await
            .map_err(|e| Error::bootstrap_with_source("Tor bootstrap failed", e))?;

        let tor_client = Arc::new(tor_client);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.config.max_connections));
        let shutdown = self.shutdown.clone();
        let isolation_token = self.config.isolation_token;

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let permit = match semaphore.clone().try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    warn!(addr = %addr, "Max connections reached, rejecting");
                                    continue;
                                }
                            };

                            let tor_client = tor_client.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(stream, addr, tor_client, isolation_token).await {
                                    debug!(addr = %addr, error = %e, "Connection error");
                                }
                                drop(permit);
                            });
                        }
                        Err(e) => {
                            error!(error = %e, "Accept error");
                        }
                    }
                }
                _ = shutdown.notified() => {
                    info!("Shutting down SOCKS5 proxy");
                    break;
                }
            }
        }

        Ok(())
    }
}

/// Handle to signal proxy shutdown.
#[derive(Clone)]
pub struct ShutdownHandle {
    notify: Arc<Notify>,
}

impl ShutdownHandle {
    /// Signal the proxy to shut down.
    pub fn shutdown(&self) {
        self.notify.notify_one();
    }
}

/// Helper to create protocol errors
fn protocol_err(msg: impl Into<String>) -> Error {
    Error::Protocol(msg.into())
}

/// Helper to create IO errors with context
fn io_err(msg: &str, e: std::io::Error) -> Error {
    Error::io(msg, e)
}

/// Handle a single SOCKS5 connection.
async fn handle_connection(
    mut stream: TcpStream,
    addr: SocketAddr,
    tor_client: Arc<ArtiClient<PreferredRuntime>>,
    _isolation_token: Option<u64>,
) -> Result<()> {
    debug!(addr = %addr, "New connection");

    // Read auth methods
    let mut buf = [0u8; 2];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| io_err("read auth header", e))?;

    if buf[0] != socks5::VERSION {
        return Err(protocol_err(format!("Invalid SOCKS version: {}", buf[0])));
    }

    let nmethods = buf[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream
        .read_exact(&mut methods)
        .await
        .map_err(|e| io_err("read auth methods", e))?;

    // We only support no auth
    let auth_method = if methods.contains(&socks5::AUTH_NONE) {
        socks5::AUTH_NONE
    } else {
        socks5::AUTH_NO_ACCEPTABLE
    };

    // Send auth response
    stream
        .write_all(&[socks5::VERSION, auth_method])
        .await
        .map_err(|e| io_err("write auth response", e))?;

    if auth_method == socks5::AUTH_NO_ACCEPTABLE {
        return Err(protocol_err("No acceptable auth method"));
    }

    // Read request
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| io_err("read request header", e))?;

    if header[0] != socks5::VERSION {
        return Err(protocol_err(format!(
            "Invalid SOCKS version in request: {}",
            header[0]
        )));
    }

    let cmd = header[1];
    let atyp = header[3];

    if cmd != socks5::CMD_CONNECT {
        send_reply(&mut stream, socks5::REPLY_CMD_NOT_SUPPORTED).await?;
        return Err(protocol_err(format!("Unsupported command: {}", cmd)));
    }

    // Parse destination address
    let (host, port) = match atyp {
        socks5::ATYP_IPV4 => {
            let mut addr_buf = [0u8; 4];
            stream
                .read_exact(&mut addr_buf)
                .await
                .map_err(|e| io_err("read IPv4 addr", e))?;
            let ip = std::net::Ipv4Addr::from(addr_buf);
            let mut port_buf = [0u8; 2];
            stream
                .read_exact(&mut port_buf)
                .await
                .map_err(|e| io_err("read port", e))?;
            let port = u16::from_be_bytes(port_buf);
            (ip.to_string(), port)
        }
        socks5::ATYP_IPV6 => {
            let mut addr_buf = [0u8; 16];
            stream
                .read_exact(&mut addr_buf)
                .await
                .map_err(|e| io_err("read IPv6 addr", e))?;
            let ip = std::net::Ipv6Addr::from(addr_buf);
            let mut port_buf = [0u8; 2];
            stream
                .read_exact(&mut port_buf)
                .await
                .map_err(|e| io_err("read port", e))?;
            let port = u16::from_be_bytes(port_buf);
            (ip.to_string(), port)
        }
        socks5::ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .map_err(|e| io_err("read domain length", e))?;
            let mut domain = vec![0u8; len[0] as usize];
            stream
                .read_exact(&mut domain)
                .await
                .map_err(|e| io_err("read domain", e))?;
            let host = String::from_utf8(domain)
                .map_err(|e| protocol_err(format!("Invalid domain encoding: {}", e)))?;
            let mut port_buf = [0u8; 2];
            stream
                .read_exact(&mut port_buf)
                .await
                .map_err(|e| io_err("read port", e))?;
            let port = u16::from_be_bytes(port_buf);
            (host, port)
        }
        _ => {
            send_reply(&mut stream, socks5::REPLY_ATYP_NOT_SUPPORTED).await?;
            return Err(protocol_err(format!("Unsupported address type: {}", atyp)));
        }
    };

    debug!(host = %host, port = port, "Connecting through Tor");

    // Connect through Tor
    let tor_stream = match tor_client.connect((host.as_str(), port)).await {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "Tor connection failed");
            send_reply(&mut stream, socks5::REPLY_CONNECTION_REFUSED).await?;
            return Err(Error::connection(&host, port, e));
        }
    };

    // Send success reply
    send_reply(&mut stream, socks5::REPLY_SUCCESS).await?;

    debug!("Starting bidirectional copy");

    // Bidirectional copy
    let (mut client_read, mut client_write) = stream.into_split();
    let (mut tor_read, mut tor_write) = tor_stream.split();

    let client_to_tor = async {
        let mut buf = [0u8; 8192];
        loop {
            let n = client_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            tor_write.write_all(&buf[..n]).await?;
        }
        tor_write.flush().await?;
        Ok::<_, std::io::Error>(())
    };

    let tor_to_client = async {
        let mut buf = [0u8; 8192];
        loop {
            let n = tor_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            client_write.write_all(&buf[..n]).await?;
        }
        client_write.flush().await?;
        Ok::<_, std::io::Error>(())
    };

    tokio::select! {
        r = client_to_tor => {
            if let Err(e) = r {
                debug!(error = %e, "Client to Tor copy ended");
            }
        }
        r = tor_to_client => {
            if let Err(e) = r {
                debug!(error = %e, "Tor to client copy ended");
            }
        }
    }

    Ok(())
}

/// Send a SOCKS5 reply.
async fn send_reply(stream: &mut TcpStream, reply: u8) -> Result<()> {
    // Reply format: VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
    let response = [
        socks5::VERSION,
        reply,
        0x00, // Reserved
        socks5::ATYP_IPV4,
        0,
        0,
        0,
        0, // Bound address (0.0.0.0)
        0,
        0, // Bound port (0)
    ];

    stream
        .write_all(&response)
        .await
        .map_err(|e| io_err("write reply", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_proxy_config_default() {
        let config = ProxyConfig::default();
        assert_eq!(config.bind_addr.port(), 9050);
        assert_eq!(config.max_connections, 256);
        assert!(config.isolation_token.is_none());
    }

    #[test]
    fn test_proxy_config_builder() {
        let config = ProxyConfig::new("127.0.0.1:1080".parse().unwrap())
            .with_isolation(42)
            .with_max_connections(100);

        assert_eq!(config.bind_addr.port(), 1080);
        assert_eq!(config.isolation_token, Some(42));
        assert_eq!(config.max_connections, 100);
    }
}
