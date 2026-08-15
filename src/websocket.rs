//! WebSocket over Tor.
//!
//! A thin wrapper joining arti's streams to `tokio-tungstenite`. The framing,
//! masking, ping/pong and close handshake are all tungstenite's; hypertor only
//! supplies the transport.
//!
//! ```rust,no_run
//! use hypertor::{TorClient, TorWebSocket};
//!
//! # async fn demo() -> hypertor::Result<()> {
//! let client = TorClient::new().await?;
//! let mut ws = TorWebSocket::connect(&client, "ws://chat.onion/socket").await?;
//!
//! ws.send_text("hello").await?;
//! while let Some(message) = ws.recv().await? {
//!     println!("{message:?}");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Reading and writing at the same time
//!
//! A chat client has to send while it is waiting to receive, and `&mut self` on
//! both halves makes that impossible. [`TorWebSocket::split`] hands back an
//! independent sender and receiver that can be moved into separate tasks.

use arti_client::StreamPrefs;
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use http::{HeaderName, HeaderValue};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::client::TorClient;
use crate::error::{Error, Result};
use crate::isolation::IsolationToken;
use crate::stream::TorStream;

/// Largest message hypertor accepts by default, in bytes.
///
/// tungstenite's own default is 64 MiB. Over Tor that is an implausible amount
/// of data to want in one frame and a very plausible amount for a hostile peer
/// to send, so hypertor is stricter. Raise it deliberately with
/// [`TorWebSocketBuilder::max_message_size`] if your protocol needs to.
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 8 * 1024 * 1024;

/// Largest single frame accepted by default, in bytes.
pub const DEFAULT_MAX_FRAME_SIZE: usize = 2 * 1024 * 1024;

/// Why a peer closed the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Close {
    /// The RFC 6455 close code. `1000` is a normal closure.
    pub code: u16,
    /// The human-readable reason, which is often empty.
    pub reason: String,
}

/// A message received from or sent to a WebSocket peer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Message {
    /// A UTF-8 text message.
    Text(String),
    /// A binary message.
    Binary(Vec<u8>),
    /// The peer closed the connection.
    ///
    /// `None` means it closed without sending a code at all, which RFC 6455
    /// permits and which is not the same as a normal closure.
    Close(Option<Close>),
}

impl Message {
    /// Convert into a tungstenite frame.
    fn into_frame(self) -> WsMessage {
        use tokio_tungstenite::tungstenite::protocol::CloseFrame;
        use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

        match self {
            Message::Text(text) => WsMessage::Text(text.into()),
            Message::Binary(data) => WsMessage::Binary(data.into()),
            Message::Close(close) => WsMessage::Close(close.map(|close| CloseFrame {
                code: CloseCode::from(close.code),
                reason: close.reason.into(),
            })),
        }
    }

    /// Convert a tungstenite frame, or `None` for one the caller never sees.
    fn from_frame(frame: WsMessage) -> Option<Self> {
        match frame {
            WsMessage::Text(text) => Some(Message::Text(text.to_string())),
            WsMessage::Binary(data) => Some(Message::Binary(data.into())),
            WsMessage::Close(frame) => Some(Message::Close(frame.map(|f| Close {
                code: f.code.into(),
                reason: f.reason.to_string(),
            }))),
            // Ping/Pong are answered by tungstenite; Frame is not produced by a
            // reading stream.
            WsMessage::Ping(_) | WsMessage::Pong(_) | WsMessage::Frame(_) => None,
        }
    }
}

/// A WebSocket connection carried over Tor.
pub struct TorWebSocket {
    inner: WebSocketStream<TorStream>,
}

impl TorWebSocket {
    /// Open a WebSocket connection over Tor with the default settings.
    ///
    /// Accepts `ws://` and `wss://`. For `.onion` targets `ws://` is already
    /// end-to-end encrypted by Tor itself, so `wss://` adds a second layer that
    /// is usually unnecessary.
    ///
    /// Circuit isolation follows the client's
    /// [`IsolationLevel`](crate::IsolationLevel), exactly as an HTTP request
    /// would. Use [`builder`](Self::builder) to pin a specific circuit, add
    /// headers, or change the size limits.
    pub async fn connect(client: &TorClient, url: &str) -> Result<Self> {
        Self::builder(client, url).connect().await
    }

    /// Start configuring a connection.
    pub fn builder<'a>(client: &'a TorClient, url: &str) -> TorWebSocketBuilder<'a> {
        TorWebSocketBuilder {
            client,
            url: url.to_owned(),
            isolation: None,
            max_message_size: Some(DEFAULT_MAX_MESSAGE_SIZE),
            max_frame_size: Some(DEFAULT_MAX_FRAME_SIZE),
            headers: Vec::new(),
            error: None,
        }
    }

    /// Send a text message.
    pub async fn send_text(&mut self, text: impl Into<String>) -> Result<()> {
        self.send(Message::Text(text.into())).await
    }

    /// Send a binary message.
    pub async fn send_binary(&mut self, data: impl Into<Vec<u8>>) -> Result<()> {
        self.send(Message::Binary(data.into())).await
    }

    /// Send a message.
    pub async fn send(&mut self, message: Message) -> Result<()> {
        self.inner
            .send(message.into_frame())
            .await
            .map_err(send_failed)
    }

    /// Receive the next message.
    ///
    /// Returns `Ok(None)` once the connection has closed. Ping and pong frames
    /// are answered by tungstenite and are not surfaced.
    pub async fn recv(&mut self) -> Result<Option<Message>> {
        recv_from(&mut self.inner).await
    }

    /// Split into halves that can be used from separate tasks.
    ///
    /// Sending and receiving both need `&mut`, so a single value cannot do both
    /// concurrently — which is exactly what any interactive protocol needs. The
    /// two halves share one connection; dropping either closes it.
    ///
    /// ```rust,no_run
    /// # async fn demo(client: &hypertor::TorClient) -> hypertor::Result<()> {
    /// let ws = hypertor::TorWebSocket::connect(client, "ws://chat.onion/s").await?;
    /// let (mut tx, mut rx) = ws.split();
    ///
    /// tokio::spawn(async move {
    ///     while let Ok(Some(message)) = rx.recv().await {
    ///         println!("{message:?}");
    ///     }
    /// });
    ///
    /// tx.send_text("hello").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn split(self) -> (Sender, Receiver) {
        let (sink, stream) = self.inner.split();
        (Sender { inner: sink }, Receiver { inner: stream })
    }

    /// Close the connection cleanly.
    pub async fn close(mut self) -> Result<()> {
        self.inner
            .close(None)
            .await
            .map_err(|e| Error::http_source("could not close the WebSocket", e))
    }
}

impl std::fmt::Debug for TorWebSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TorWebSocket").finish_non_exhaustive()
    }
}

/// The sending half of a split [`TorWebSocket`].
pub struct Sender {
    inner: SplitSink<WebSocketStream<TorStream>, WsMessage>,
}

impl Sender {
    /// Send a text message.
    pub async fn send_text(&mut self, text: impl Into<String>) -> Result<()> {
        self.send(Message::Text(text.into())).await
    }

    /// Send a binary message.
    pub async fn send_binary(&mut self, data: impl Into<Vec<u8>>) -> Result<()> {
        self.send(Message::Binary(data.into())).await
    }

    /// Send a message.
    pub async fn send(&mut self, message: Message) -> Result<()> {
        self.inner
            .send(message.into_frame())
            .await
            .map_err(send_failed)
    }

    /// Close the connection cleanly.
    pub async fn close(&mut self) -> Result<()> {
        SinkExt::close(&mut self.inner)
            .await
            .map_err(|e| Error::http_source("could not close the WebSocket", e))
    }
}

impl std::fmt::Debug for Sender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sender").finish_non_exhaustive()
    }
}

/// The receiving half of a split [`TorWebSocket`].
pub struct Receiver {
    inner: SplitStream<WebSocketStream<TorStream>>,
}

impl Receiver {
    /// Receive the next message, or `None` once the connection has closed.
    pub async fn recv(&mut self) -> Result<Option<Message>> {
        recv_from(&mut self.inner).await
    }
}

impl std::fmt::Debug for Receiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Receiver").finish_non_exhaustive()
    }
}

/// Pull frames until one is worth handing to the caller.
async fn recv_from<S>(stream: &mut S) -> Result<Option<Message>>
where
    S: futures::Stream<
            Item = std::result::Result<WsMessage, tokio_tungstenite::tungstenite::Error>,
        > + Unpin,
{
    while let Some(frame) = stream.next().await {
        let frame = frame.map_err(|e| Error::http_source("WebSocket receive failed", e))?;
        if let Some(message) = Message::from_frame(frame) {
            return Ok(Some(message));
        }
    }
    Ok(None)
}

fn send_failed(error: tokio_tungstenite::tungstenite::Error) -> Error {
    Error::http_source("could not send a WebSocket message", error)
}

// ===========================================================================
// Builder
// ===========================================================================

/// Configures a [`TorWebSocket`] before connecting.
pub struct TorWebSocketBuilder<'a> {
    client: &'a TorClient,
    url: String,
    isolation: Option<IsolationToken>,
    max_message_size: Option<usize>,
    max_frame_size: Option<usize>,
    headers: Vec<(HeaderName, HeaderValue)>,
    /// Deferred error from an infallible-looking setter.
    error: Option<Error>,
}

impl TorWebSocketBuilder<'_> {
    /// Pin this connection to a specific circuit.
    ///
    /// Overrides the client-wide [`IsolationLevel`](crate::IsolationLevel), so a
    /// socket can share a circuit with the HTTP requests it belongs with — or be
    /// kept away from all of them.
    pub fn isolation(mut self, token: IsolationToken) -> Self {
        self.isolation = Some(token);
        self
    }

    /// Largest message to accept, or `None` for no limit.
    ///
    /// Removing the limit means a hostile peer decides how much memory your
    /// process uses.
    pub fn max_message_size(mut self, bytes: Option<usize>) -> Self {
        self.max_message_size = bytes;
        self
    }

    /// Largest single frame to accept, or `None` for no limit.
    pub fn max_frame_size(mut self, bytes: Option<usize>) -> Self {
        self.max_frame_size = bytes;
        self
    }

    /// Add a header to the opening handshake.
    ///
    /// This is how an `Authorization` header or a cookie reaches a WebSocket
    /// endpoint, since the handshake is the only HTTP request involved.
    pub fn header<K, V>(mut self, name: K, value: V) -> Self
    where
        K: TryInto<HeaderName>,
        V: TryInto<HeaderValue>,
    {
        match (name.try_into(), value.try_into()) {
            (Ok(name), Ok(value)) => self.headers.push((name, value)),
            _ => {
                if self.error.is_none() {
                    self.error = Some(Error::invalid_request(
                        "WebSocket header name or value is not valid in HTTP",
                    ));
                }
            }
        }
        self
    }

    /// Request one or more subprotocols via `Sec-WebSocket-Protocol`.
    pub fn subprotocols<I, S>(self, protocols: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let joined = protocols
            .into_iter()
            .map(|p| p.as_ref().to_owned())
            .collect::<Vec<_>>()
            .join(", ");
        self.header("sec-websocket-protocol", joined)
    }

    /// Open the connection.
    pub async fn connect(self) -> Result<TorWebSocket> {
        if let Some(error) = self.error {
            return Err(error);
        }

        let uri: http::Uri = self
            .url
            .parse()
            .map_err(|e| Error::invalid_url(format!("{:?}: {e}", self.url)))?;

        let tls = match uri.scheme_str() {
            Some("ws") => false,
            Some("wss") => true,
            other => {
                return Err(Error::invalid_url(format!(
                    "unsupported scheme {other:?}; expected ws:// or wss://"
                )));
            }
        };

        let host = uri
            .host()
            .ok_or_else(|| Error::invalid_url("WebSocket URL has no host"))?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });

        let isolation = self.client.isolation_for(&uri, self.isolation);
        let mut prefs = StreamPrefs::new();
        if let Some(token) = isolation.token() {
            prefs.set_isolation(token.inner());
        }

        let connect_timeout = self.client.config().connect_timeout;

        let data_stream = tokio::time::timeout(
            connect_timeout,
            self.client
                .arti()
                .connect_with_prefs((host.as_str(), port), &prefs),
        )
        .await
        .map_err(|_| Error::timeout("Tor connect", connect_timeout))?
        .map_err(|e| Error::connect(&host, port, e))?;

        let stream = if tls {
            // The connector for this socket's isolation group: the certificate
            // configuration is shared (parsing the trust store per socket would
            // be far too expensive) while the TLS session store is not, so a
            // socket cannot be linked to traffic it was isolated from.
            let connector = self.client.tls_for(isolation).ok_or_else(|| {
                Error::tls("wss:// requires a TLS backend; enable the `rustls` feature")
            })?;

            tokio::time::timeout(connect_timeout, connector.connect(data_stream, &host))
                .await
                .map_err(|_| Error::timeout("TLS handshake", connect_timeout))??
        } else {
            TorStream::plain(data_stream)
        };

        let mut request = self
            .url
            .as_str()
            .into_client_request()
            .map_err(|e| Error::invalid_url(format!("{:?}: {e}", self.url)))?;
        for (name, value) in self.headers {
            request.headers_mut().insert(name, value);
        }

        let config = WebSocketConfig::default()
            .max_message_size(self.max_message_size)
            .max_frame_size(self.max_frame_size);

        let (inner, _response) = tokio::time::timeout(
            connect_timeout,
            tokio_tungstenite::client_async_with_config(request, stream, Some(config)),
        )
        .await
        .map_err(|_| Error::timeout("WebSocket handshake", connect_timeout))?
        .map_err(|e| Error::http_source("WebSocket handshake failed", e))?;

        Ok(TorWebSocket { inner })
    }
}

impl std::fmt::Debug for TorWebSocketBuilder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TorWebSocketBuilder")
            .field("url", &self.url)
            .field("max_message_size", &self.max_message_size)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_compare_by_value() {
        assert_eq!(Message::Text("hi".into()), Message::Text("hi".into()));
        assert_ne!(Message::Text("hi".into()), Message::Binary(b"hi".to_vec()));
    }

    #[test]
    fn close_frames_keep_their_code() {
        // The code is how a caller tells "the peer is going away" apart from
        // "the peer rejected what you sent", and the old API discarded it.
        use tokio_tungstenite::tungstenite::protocol::CloseFrame;
        use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

        let frame = WsMessage::Close(Some(CloseFrame {
            code: CloseCode::Policy,
            reason: "no".into(),
        }));

        assert_eq!(
            Message::from_frame(frame),
            Some(Message::Close(Some(Close {
                code: 1008,
                reason: "no".to_string(),
            })))
        );
    }

    #[test]
    fn a_close_without_a_code_stays_distinguishable_from_a_normal_one() {
        assert_eq!(
            Message::from_frame(WsMessage::Close(None)),
            Some(Message::Close(None))
        );
    }

    #[test]
    fn control_frames_are_not_surfaced_to_the_caller() {
        assert_eq!(Message::from_frame(WsMessage::Ping(vec![].into())), None);
        assert_eq!(Message::from_frame(WsMessage::Pong(vec![].into())), None);
    }

    #[test]
    fn messages_round_trip_through_the_wire_form() {
        for message in [
            Message::Text("hello".into()),
            Message::Binary(vec![1, 2, 3]),
            Message::Close(Some(Close {
                code: 1000,
                reason: "bye".into(),
            })),
        ] {
            let round_tripped = Message::from_frame(message.clone().into_frame());
            assert_eq!(round_tripped, Some(message));
        }
    }

    #[test]
    fn the_default_message_limit_is_stricter_than_tungstenites() {
        // 64 MiB in one message over a Tor circuit is a hostile peer, not a
        // legitimate protocol.
        let tungstenite_default = WebSocketConfig::default().max_message_size;
        assert!(
            Some(DEFAULT_MAX_MESSAGE_SIZE) < tungstenite_default,
            "hypertor must not inherit a 64 MiB default"
        );
    }
}
