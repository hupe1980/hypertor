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

use arti_client::StreamPrefs;
use futures::{SinkExt, StreamExt};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use crate::client::TorClient;
use crate::error::{Error, Result};
use crate::isolation::IsolationToken;
use crate::stream::TorStream;

/// A message received from or sent to a WebSocket peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// A UTF-8 text message.
    Text(String),
    /// A binary message.
    Binary(Vec<u8>),
    /// The peer closed the connection, optionally with a reason.
    Close(Option<String>),
}

/// A WebSocket connection carried over Tor.
pub struct TorWebSocket {
    inner: WebSocketStream<TorStream>,
}

impl TorWebSocket {
    /// Open a WebSocket connection over Tor.
    ///
    /// Accepts `ws://` and `wss://`. For `.onion` targets `ws://` is already
    /// end-to-end encrypted by Tor itself, so `wss://` adds a second layer that
    /// is usually unnecessary.
    pub async fn connect(client: &TorClient, url: &str) -> Result<Self> {
        Self::connect_with_isolation(client, url, None).await
    }

    /// Open a WebSocket connection on a specific circuit.
    pub async fn connect_with_isolation(
        client: &TorClient,
        url: &str,
        isolation: Option<IsolationToken>,
    ) -> Result<Self> {
        let uri: http::Uri = url
            .parse()
            .map_err(|e| Error::invalid_url(format!("{url:?}: {e}")))?;

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
            .to_owned();
        let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });

        let mut prefs = StreamPrefs::new();
        if let Some(token) = isolation {
            prefs.set_isolation(token.inner());
        }

        let data_stream = client
            .arti()
            .connect_with_prefs((host.as_str(), port), &prefs)
            .await
            .map_err(|e| Error::connect(&host, port, e))?;

        let stream = if tls {
            let connector = crate::tls::TlsConnector::new(&client.config().tls)?;
            connector.connect(data_stream, &host).await?
        } else {
            TorStream::plain(data_stream)
        };

        let request = url
            .into_client_request()
            .map_err(|e| Error::invalid_url(format!("{url:?}: {e}")))?;

        let (inner, _response) = tokio_tungstenite::client_async(request, stream)
            .await
            .map_err(|e| Error::http_source("WebSocket handshake failed", e))?;

        Ok(Self { inner })
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
        let frame = match message {
            Message::Text(text) => WsMessage::Text(text.into()),
            Message::Binary(data) => WsMessage::Binary(data.into()),
            Message::Close(reason) => WsMessage::Close(reason.map(|r| {
                tokio_tungstenite::tungstenite::protocol::CloseFrame {
                    code:
                        tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal,
                    reason: r.into(),
                }
            })),
        };

        self.inner
            .send(frame)
            .await
            .map_err(|e| Error::http_source("could not send a WebSocket message", e))
    }

    /// Receive the next message.
    ///
    /// Returns `Ok(None)` once the connection has closed. Ping and pong frames
    /// are answered by tungstenite and are not surfaced.
    pub async fn recv(&mut self) -> Result<Option<Message>> {
        while let Some(frame) = self.inner.next().await {
            let frame = frame.map_err(|e| Error::http_source("WebSocket receive failed", e))?;

            match frame {
                WsMessage::Text(text) => return Ok(Some(Message::Text(text.to_string()))),
                WsMessage::Binary(data) => return Ok(Some(Message::Binary(data.into()))),
                WsMessage::Close(frame) => {
                    return Ok(Some(Message::Close(frame.map(|f| f.reason.to_string()))));
                }
                // Ping/Pong are handled by tungstenite; Frame is not produced
                // by a reading stream.
                WsMessage::Ping(_) | WsMessage::Pong(_) | WsMessage::Frame(_) => continue,
            }
        }

        Ok(None)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_compare_by_value() {
        assert_eq!(Message::Text("hi".into()), Message::Text("hi".into()));
        assert_ne!(Message::Text("hi".into()), Message::Binary(b"hi".to_vec()));
    }
}
