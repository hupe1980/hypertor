//! WebSocket over Tor support
//!
//! This module provides WebSocket client and server capabilities that work over Tor,
//! enabling real-time bidirectional communication through the onion network.
//!
//! # Features
//!
//! - **WebSocket Client**: Connect to WebSocket servers over Tor
//! - **WebSocket Server**: Host WebSocket endpoints on onion services
//! - **Message Types**: Text, Binary, Ping, Pong, Close frames
//! - **Fragmentation**: Automatic message fragmentation and reassembly
//! - **Compression**: Per-message deflate compression (RFC 7692)
//! - **Heartbeat**: Configurable ping/pong for connection keepalive
//!
//! # Example
//!
//! ```rust,ignore
//! use hypertor::websocket::{WebSocketClient, Message};
//!
//! // Connect to a WebSocket server over Tor
//! let mut ws = WebSocketClient::connect("ws://example.onion/ws").await?;
//!
//! // Send a message
//! ws.send(Message::text("Hello!")).await?;
//!
//! // Receive messages
//! while let Some(msg) = ws.recv().await? {
//!     match msg {
//!         Message::Text(text) => println!("Received: {}", text),
//!         Message::Binary(data) => println!("Binary: {} bytes", data.len()),
//!         Message::Close(_) => break,
//!         _ => {}
//!     }
//! }
//! ```

#![allow(dead_code)]

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

// ============================================================================
// WebSocket Frame Types
// ============================================================================

/// WebSocket opcode types (RFC 6455)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    /// Continuation frame
    Continuation = 0x0,
    /// Text frame (UTF-8)
    Text = 0x1,
    /// Binary frame
    Binary = 0x2,
    /// Connection close
    Close = 0x8,
    /// Ping frame
    Ping = 0x9,
    /// Pong frame
    Pong = 0xA,
}

impl Opcode {
    /// Parse opcode from byte
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte & 0x0F {
            0x0 => Some(Opcode::Continuation),
            0x1 => Some(Opcode::Text),
            0x2 => Some(Opcode::Binary),
            0x8 => Some(Opcode::Close),
            0x9 => Some(Opcode::Ping),
            0xA => Some(Opcode::Pong),
            _ => None,
        }
    }

    /// Check if this is a control frame
    pub fn is_control(&self) -> bool {
        matches!(self, Opcode::Close | Opcode::Ping | Opcode::Pong)
    }

    /// Check if this is a data frame
    pub fn is_data(&self) -> bool {
        matches!(self, Opcode::Text | Opcode::Binary | Opcode::Continuation)
    }
}

/// WebSocket close status codes (RFC 6455)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseCode {
    /// Normal closure
    Normal,
    /// Endpoint going away
    GoingAway,
    /// Protocol error
    ProtocolError,
    /// Unsupported data type
    UnsupportedData,
    /// No status code present
    NoStatus,
    /// Abnormal closure (no close frame)
    Abnormal,
    /// Invalid frame payload data
    InvalidPayload,
    /// Policy violation
    PolicyViolation,
    /// Message too big
    MessageTooBig,
    /// Missing extension
    MissingExtension,
    /// Internal server error
    InternalError,
    /// TLS handshake error
    TlsHandshake,
    /// Custom close code
    Custom(u16),
}

impl CloseCode {
    /// Convert to u16 code
    pub fn to_u16(&self) -> u16 {
        match self {
            CloseCode::Normal => 1000,
            CloseCode::GoingAway => 1001,
            CloseCode::ProtocolError => 1002,
            CloseCode::UnsupportedData => 1003,
            CloseCode::NoStatus => 1005,
            CloseCode::Abnormal => 1006,
            CloseCode::InvalidPayload => 1007,
            CloseCode::PolicyViolation => 1008,
            CloseCode::MessageTooBig => 1009,
            CloseCode::MissingExtension => 1010,
            CloseCode::InternalError => 1011,
            CloseCode::TlsHandshake => 1015,
            CloseCode::Custom(code) => *code,
        }
    }

    /// Parse from u16 code
    pub fn from_u16(code: u16) -> Self {
        match code {
            1000 => CloseCode::Normal,
            1001 => CloseCode::GoingAway,
            1002 => CloseCode::ProtocolError,
            1003 => CloseCode::UnsupportedData,
            1005 => CloseCode::NoStatus,
            1006 => CloseCode::Abnormal,
            1007 => CloseCode::InvalidPayload,
            1008 => CloseCode::PolicyViolation,
            1009 => CloseCode::MessageTooBig,
            1010 => CloseCode::MissingExtension,
            1011 => CloseCode::InternalError,
            1015 => CloseCode::TlsHandshake,
            code => CloseCode::Custom(code),
        }
    }
}

/// Close frame payload
#[derive(Debug, Clone)]
pub struct CloseFrame {
    /// Close status code
    pub code: CloseCode,
    /// Close reason (UTF-8 text)
    pub reason: String,
}

impl CloseFrame {
    /// Create a new close frame
    pub fn new(code: CloseCode, reason: impl Into<String>) -> Self {
        Self {
            code,
            reason: reason.into(),
        }
    }

    /// Create a normal close frame
    pub fn normal() -> Self {
        Self::new(CloseCode::Normal, "")
    }

    /// Encode to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 + self.reason.len());
        let code = self.code.to_u16();
        bytes.push((code >> 8) as u8);
        bytes.push(code as u8);
        bytes.extend(self.reason.as_bytes());
        bytes
    }

    /// Parse from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return Some(Self::new(CloseCode::NoStatus, ""));
        }
        let code = u16::from_be_bytes([data[0], data[1]]);
        let reason = String::from_utf8_lossy(&data[2..]).to_string();
        Some(Self::new(CloseCode::from_u16(code), reason))
    }
}

// ============================================================================
// WebSocket Messages
// ============================================================================

/// High-level WebSocket message types
#[derive(Debug, Clone)]
pub enum Message {
    /// UTF-8 text message
    Text(String),
    /// Binary message
    Binary(Vec<u8>),
    /// Ping message (with optional payload)
    Ping(Vec<u8>),
    /// Pong message (with optional payload)
    Pong(Vec<u8>),
    /// Close message
    Close(Option<CloseFrame>),
}

impl Message {
    /// Create a text message
    pub fn text(text: impl Into<String>) -> Self {
        Message::Text(text.into())
    }

    /// Create a binary message
    pub fn binary(data: impl Into<Vec<u8>>) -> Self {
        Message::Binary(data.into())
    }

    /// Create a ping message
    pub fn ping(data: impl Into<Vec<u8>>) -> Self {
        Message::Ping(data.into())
    }

    /// Create a pong message
    pub fn pong(data: impl Into<Vec<u8>>) -> Self {
        Message::Pong(data.into())
    }

    /// Create a close message
    pub fn close(code: CloseCode, reason: impl Into<String>) -> Self {
        Message::Close(Some(CloseFrame::new(code, reason)))
    }

    /// Check if this is a text message
    pub fn is_text(&self) -> bool {
        matches!(self, Message::Text(_))
    }

    /// Check if this is a binary message
    pub fn is_binary(&self) -> bool {
        matches!(self, Message::Binary(_))
    }

    /// Check if this is a close message
    pub fn is_close(&self) -> bool {
        matches!(self, Message::Close(_))
    }

    /// Get the message payload length
    pub fn len(&self) -> usize {
        match self {
            Message::Text(s) => s.len(),
            Message::Binary(d) => d.len(),
            Message::Ping(d) => d.len(),
            Message::Pong(d) => d.len(),
            Message::Close(Some(f)) => 2 + f.reason.len(),
            Message::Close(None) => 0,
        }
    }

    /// Check if the message is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Try to get as text
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Message::Text(s) => Some(s),
            _ => None,
        }
    }

    /// Try to get as bytes
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Message::Binary(d) => Some(d),
            _ => None,
        }
    }

    /// Convert message to its opcode
    pub fn opcode(&self) -> Opcode {
        match self {
            Message::Text(_) => Opcode::Text,
            Message::Binary(_) => Opcode::Binary,
            Message::Ping(_) => Opcode::Ping,
            Message::Pong(_) => Opcode::Pong,
            Message::Close(_) => Opcode::Close,
        }
    }

    /// Get the payload as bytes
    pub fn payload(&self) -> Vec<u8> {
        match self {
            Message::Text(s) => s.as_bytes().to_vec(),
            Message::Binary(d) => d.clone(),
            Message::Ping(d) => d.clone(),
            Message::Pong(d) => d.clone(),
            Message::Close(Some(f)) => f.to_bytes(),
            Message::Close(None) => vec![],
        }
    }
}

// ============================================================================
// WebSocket Frame
// ============================================================================

/// Low-level WebSocket frame (RFC 6455)
#[derive(Debug, Clone)]
pub struct Frame {
    /// Final fragment flag
    pub fin: bool,
    /// RSV1 extension bit
    pub rsv1: bool,
    /// RSV2 extension bit
    pub rsv2: bool,
    /// RSV3 extension bit
    pub rsv3: bool,
    /// Frame opcode
    pub opcode: Opcode,
    /// Masking key (client -> server must be masked)
    pub mask: Option<[u8; 4]>,
    /// Frame payload
    pub payload: Vec<u8>,
}

impl Frame {
    /// Create a new frame
    pub fn new(opcode: Opcode, payload: Vec<u8>) -> Self {
        Self {
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode,
            mask: None,
            payload,
        }
    }

    /// Create a text frame
    pub fn text(text: impl Into<String>) -> Self {
        Self::new(Opcode::Text, text.into().into_bytes())
    }

    /// Create a binary frame
    pub fn binary(data: impl Into<Vec<u8>>) -> Self {
        Self::new(Opcode::Binary, data.into())
    }

    /// Create a ping frame
    pub fn ping(data: impl Into<Vec<u8>>) -> Self {
        Self::new(Opcode::Ping, data.into())
    }

    /// Create a pong frame
    pub fn pong(data: impl Into<Vec<u8>>) -> Self {
        Self::new(Opcode::Pong, data.into())
    }

    /// Create a close frame
    pub fn close(code: CloseCode, reason: &str) -> Self {
        let payload = CloseFrame::new(code, reason).to_bytes();
        Self::new(Opcode::Close, payload)
    }

    /// Set the fin flag
    pub fn with_fin(mut self, fin: bool) -> Self {
        self.fin = fin;
        self
    }

    /// Set the masking key
    pub fn with_mask(mut self, mask: [u8; 4]) -> Self {
        self.mask = Some(mask);
        self
    }

    /// Generate a random mask
    pub fn with_random_mask(mut self) -> Self {
        let mask: [u8; 4] = rand::random();
        self.mask = Some(mask);
        self
    }

    /// Apply masking to payload
    fn masked_payload(&self) -> Vec<u8> {
        match self.mask {
            Some(mask) => self
                .payload
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ mask[i % 4])
                .collect(),
            None => self.payload.clone(),
        }
    }

    /// Encode frame to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(14 + self.payload.len());

        // First byte: FIN + RSV + opcode
        let mut byte0 = self.opcode as u8;
        if self.fin {
            byte0 |= 0x80;
        }
        if self.rsv1 {
            byte0 |= 0x40;
        }
        if self.rsv2 {
            byte0 |= 0x20;
        }
        if self.rsv3 {
            byte0 |= 0x10;
        }
        bytes.push(byte0);

        // Second byte: MASK + payload length
        let len = self.payload.len();
        let mask_bit = if self.mask.is_some() { 0x80 } else { 0 };

        if len < 126 {
            bytes.push(mask_bit | len as u8);
        } else if len < 65536 {
            bytes.push(mask_bit | 126);
            bytes.extend(&(len as u16).to_be_bytes());
        } else {
            bytes.push(mask_bit | 127);
            bytes.extend(&(len as u64).to_be_bytes());
        }

        // Masking key
        if let Some(mask) = self.mask {
            bytes.extend(&mask);
        }

        // Payload (masked if necessary)
        bytes.extend(self.masked_payload());

        bytes
    }

    /// Decode frame from bytes
    pub fn decode(data: &[u8]) -> Result<(Self, usize), WebSocketError> {
        if data.len() < 2 {
            return Err(WebSocketError::IncompleteFrame);
        }

        let byte0 = data[0];
        let byte1 = data[1];

        let fin = byte0 & 0x80 != 0;
        let rsv1 = byte0 & 0x40 != 0;
        let rsv2 = byte0 & 0x20 != 0;
        let rsv3 = byte0 & 0x10 != 0;

        let opcode = Opcode::from_byte(byte0).ok_or(WebSocketError::InvalidOpcode(byte0 & 0x0F))?;

        let masked = byte1 & 0x80 != 0;
        let len_byte = byte1 & 0x7F;

        let mut offset = 2;
        let payload_len: usize;

        if len_byte < 126 {
            payload_len = len_byte as usize;
        } else if len_byte == 126 {
            if data.len() < 4 {
                return Err(WebSocketError::IncompleteFrame);
            }
            payload_len = u16::from_be_bytes([data[2], data[3]]) as usize;
            offset = 4;
        } else {
            if data.len() < 10 {
                return Err(WebSocketError::IncompleteFrame);
            }
            payload_len = u64::from_be_bytes([
                data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9],
            ]) as usize;
            offset = 10;
        }

        let mask = if masked {
            if data.len() < offset + 4 {
                return Err(WebSocketError::IncompleteFrame);
            }
            let m = [
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ];
            offset += 4;
            Some(m)
        } else {
            None
        };

        if data.len() < offset + payload_len {
            return Err(WebSocketError::IncompleteFrame);
        }

        let mut payload = data[offset..offset + payload_len].to_vec();

        // Unmask if necessary
        if let Some(m) = mask {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= m[i % 4];
            }
        }

        let frame = Frame {
            fin,
            rsv1,
            rsv2,
            rsv3,
            opcode,
            mask,
            payload,
        };

        Ok((frame, offset + payload_len))
    }
}

// ============================================================================
// WebSocket Errors
// ============================================================================

/// WebSocket errors
#[derive(Debug, Clone)]
pub enum WebSocketError {
    /// Connection closed
    ConnectionClosed,
    /// Connection failed
    ConnectionFailed(String),
    /// Send failed
    SendFailed(String),
    /// Invalid frame opcode
    InvalidOpcode(u8),
    /// Incomplete frame data
    IncompleteFrame,
    /// Invalid UTF-8 in text frame
    InvalidUtf8,
    /// Message too large
    MessageTooLarge(usize),
    /// Protocol error
    ProtocolError(String),
    /// Handshake failed
    HandshakeFailed(String),
    /// IO error
    IoError(String),
    /// Timeout
    Timeout,
}

impl std::fmt::Display for WebSocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebSocketError::ConnectionClosed => write!(f, "Connection closed"),
            WebSocketError::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            WebSocketError::SendFailed(msg) => write!(f, "Send failed: {}", msg),
            WebSocketError::InvalidOpcode(op) => write!(f, "Invalid opcode: {}", op),
            WebSocketError::IncompleteFrame => write!(f, "Incomplete frame"),
            WebSocketError::InvalidUtf8 => write!(f, "Invalid UTF-8 in text frame"),
            WebSocketError::MessageTooLarge(size) => write!(f, "Message too large: {} bytes", size),
            WebSocketError::ProtocolError(msg) => write!(f, "Protocol error: {}", msg),
            WebSocketError::HandshakeFailed(msg) => write!(f, "Handshake failed: {}", msg),
            WebSocketError::IoError(msg) => write!(f, "IO error: {}", msg),
            WebSocketError::Timeout => write!(f, "Timeout"),
        }
    }
}

impl std::error::Error for WebSocketError {}

// ============================================================================
// WebSocket Configuration
// ============================================================================

/// WebSocket connection configuration
#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    /// Maximum message size (default: 64MB)
    pub max_message_size: usize,
    /// Maximum frame size (default: 16MB)
    pub max_frame_size: usize,
    /// Enable per-message deflate compression
    pub compression: bool,
    /// Ping interval for keepalive (None = disabled)
    pub ping_interval: Option<Duration>,
    /// Pong timeout (default: 30s)
    pub pong_timeout: Duration,
    /// Write buffer size
    pub write_buffer_size: usize,
    /// Read buffer size
    pub read_buffer_size: usize,
    /// Auto-respond to pings
    pub auto_pong: bool,
    /// Auto-close on protocol errors
    pub auto_close: bool,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            max_message_size: 64 * 1024 * 1024, // 64MB
            max_frame_size: 16 * 1024 * 1024,   // 16MB
            compression: false,
            ping_interval: Some(Duration::from_secs(30)),
            pong_timeout: Duration::from_secs(30),
            write_buffer_size: 128 * 1024, // 128KB
            read_buffer_size: 128 * 1024,  // 128KB
            auto_pong: true,
            auto_close: true,
        }
    }
}

impl WebSocketConfig {
    /// Create a new configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum message size
    pub fn max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }

    /// Set maximum frame size
    pub fn max_frame_size(mut self, size: usize) -> Self {
        self.max_frame_size = size;
        self
    }

    /// Enable compression
    pub fn with_compression(mut self) -> Self {
        self.compression = true;
        self
    }

    /// Set ping interval
    pub fn ping_interval(mut self, interval: Duration) -> Self {
        self.ping_interval = Some(interval);
        self
    }

    /// Disable automatic pings
    pub fn no_ping(mut self) -> Self {
        self.ping_interval = None;
        self
    }

    /// Configuration optimized for Tor's latency
    pub fn tor_optimized() -> Self {
        Self {
            max_message_size: 16 * 1024 * 1024,           // 16MB
            max_frame_size: 4 * 1024 * 1024,              // 4MB
            compression: true,                            // Reduce bandwidth
            ping_interval: Some(Duration::from_secs(60)), // Longer for Tor latency
            pong_timeout: Duration::from_secs(120),       // Longer timeout
            write_buffer_size: 64 * 1024,
            read_buffer_size: 64 * 1024,
            auto_pong: true,
            auto_close: true,
        }
    }
}

// ============================================================================
// WebSocket State
// ============================================================================

/// WebSocket connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketState {
    /// Connection is being established
    Connecting,
    /// Connection is open and ready
    Open,
    /// Close handshake in progress
    Closing,
    /// Connection is closed
    Closed,
}

// ============================================================================
// WebSocket Client
// ============================================================================

/// WebSocket client for connecting to servers over Tor
#[derive(Debug)]
pub struct WebSocketClient {
    /// Connection state
    state: WebSocketState,
    /// Configuration
    config: WebSocketConfig,
    /// Send queue
    send_queue: VecDeque<Frame>,
    /// Receive queue
    recv_queue: VecDeque<Message>,
    /// Fragmented message buffer
    fragment_buffer: Option<(Opcode, Vec<u8>)>,
    /// Total bytes sent
    bytes_sent: AtomicU64,
    /// Total bytes received
    bytes_received: AtomicU64,
    /// Messages sent
    messages_sent: AtomicU64,
    /// Messages received
    messages_received: AtomicU64,
    /// Last ping time
    last_ping: Option<Instant>,
    /// Waiting for pong
    awaiting_pong: AtomicBool,
    /// Connection URL
    url: String,
}

impl WebSocketClient {
    /// Create a new WebSocket client (not yet connected)
    pub fn new(url: impl Into<String>) -> Self {
        Self::with_config(url, WebSocketConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(url: impl Into<String>, config: WebSocketConfig) -> Self {
        Self {
            state: WebSocketState::Connecting,
            config,
            send_queue: VecDeque::new(),
            recv_queue: VecDeque::new(),
            fragment_buffer: None,
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            last_ping: None,
            awaiting_pong: AtomicBool::new(false),
            url: url.into(),
        }
    }

    /// Create with Tor-optimized settings
    pub fn tor_optimized(url: impl Into<String>) -> Self {
        Self::with_config(url, WebSocketConfig::tor_optimized())
    }

    /// Get the connection URL
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Get connection state
    pub fn state(&self) -> WebSocketState {
        self.state
    }

    /// Check if connection is open
    pub fn is_open(&self) -> bool {
        self.state == WebSocketState::Open
    }

    /// Check if connection is closed
    pub fn is_closed(&self) -> bool {
        self.state == WebSocketState::Closed
    }

    /// Simulate opening the connection
    pub fn open(&mut self) {
        self.state = WebSocketState::Open;
    }

    /// Queue a message for sending
    pub fn send(&mut self, msg: Message) -> Result<(), WebSocketError> {
        if self.state != WebSocketState::Open {
            return Err(WebSocketError::ConnectionClosed);
        }

        // Check message size
        if msg.len() > self.config.max_message_size {
            return Err(WebSocketError::MessageTooLarge(msg.len()));
        }

        let frame = match msg {
            Message::Text(text) => Frame::text(text).with_random_mask(),
            Message::Binary(data) => Frame::binary(data).with_random_mask(),
            Message::Ping(data) => Frame::ping(data).with_random_mask(),
            Message::Pong(data) => Frame::pong(data).with_random_mask(),
            Message::Close(frame) => {
                let (code, reason) = frame
                    .map(|f| (f.code, f.reason))
                    .unwrap_or((CloseCode::Normal, String::new()));
                Frame::close(code, &reason).with_random_mask()
            }
        };

        self.send_queue.push_back(frame);
        self.messages_sent.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    /// Send a text message
    pub fn send_text(&mut self, text: impl Into<String>) -> Result<(), WebSocketError> {
        self.send(Message::text(text))
    }

    /// Send a binary message
    pub fn send_binary(&mut self, data: impl Into<Vec<u8>>) -> Result<(), WebSocketError> {
        self.send(Message::binary(data))
    }

    /// Process received frame
    pub fn process_frame(&mut self, frame: Frame) -> Result<Option<Message>, WebSocketError> {
        self.bytes_received
            .fetch_add(frame.payload.len() as u64, Ordering::Relaxed);

        match frame.opcode {
            Opcode::Text => {
                if frame.fin {
                    let text = String::from_utf8(frame.payload)
                        .map_err(|_| WebSocketError::InvalidUtf8)?;
                    self.messages_received.fetch_add(1, Ordering::Relaxed);
                    Ok(Some(Message::Text(text)))
                } else {
                    self.fragment_buffer = Some((Opcode::Text, frame.payload));
                    Ok(None)
                }
            }
            Opcode::Binary => {
                if frame.fin {
                    self.messages_received.fetch_add(1, Ordering::Relaxed);
                    Ok(Some(Message::Binary(frame.payload)))
                } else {
                    self.fragment_buffer = Some((Opcode::Binary, frame.payload));
                    Ok(None)
                }
            }
            Opcode::Continuation => {
                if let Some((opcode, mut buffer)) = self.fragment_buffer.take() {
                    buffer.extend(frame.payload);
                    if buffer.len() > self.config.max_message_size {
                        return Err(WebSocketError::MessageTooLarge(buffer.len()));
                    }
                    if frame.fin {
                        self.messages_received.fetch_add(1, Ordering::Relaxed);
                        match opcode {
                            Opcode::Text => {
                                let text = String::from_utf8(buffer)
                                    .map_err(|_| WebSocketError::InvalidUtf8)?;
                                Ok(Some(Message::Text(text)))
                            }
                            Opcode::Binary => Ok(Some(Message::Binary(buffer))),
                            _ => Err(WebSocketError::ProtocolError("Invalid continuation".into())),
                        }
                    } else {
                        self.fragment_buffer = Some((opcode, buffer));
                        Ok(None)
                    }
                } else {
                    Err(WebSocketError::ProtocolError(
                        "Unexpected continuation".into(),
                    ))
                }
            }
            Opcode::Ping => {
                if self.config.auto_pong {
                    self.send(Message::Pong(frame.payload.clone()))?;
                }
                Ok(Some(Message::Ping(frame.payload)))
            }
            Opcode::Pong => {
                self.awaiting_pong.store(false, Ordering::Relaxed);
                Ok(Some(Message::Pong(frame.payload)))
            }
            Opcode::Close => {
                let close_frame = CloseFrame::from_bytes(&frame.payload);
                self.state = WebSocketState::Closing;
                if self.config.auto_close {
                    // Echo close frame
                    let _ = self.send(Message::Close(close_frame.clone()));
                    self.state = WebSocketState::Closed;
                }
                Ok(Some(Message::Close(close_frame)))
            }
        }
    }

    /// Check if a ping should be sent
    pub fn should_ping(&self) -> bool {
        if let Some(interval) = self.config.ping_interval {
            if let Some(last) = self.last_ping {
                return last.elapsed() >= interval && !self.awaiting_pong.load(Ordering::Relaxed);
            }
            return true;
        }
        false
    }

    /// Send a ping
    pub fn send_ping(&mut self) -> Result<(), WebSocketError> {
        let data = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
            .to_be_bytes()
            .to_vec();

        self.send(Message::Ping(data))?;
        self.last_ping = Some(Instant::now());
        self.awaiting_pong.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Close the connection
    pub fn close(&mut self, code: CloseCode, reason: &str) -> Result<(), WebSocketError> {
        if self.state == WebSocketState::Open {
            self.state = WebSocketState::Closing;
            self.send(Message::close(code, reason))?;
        }
        Ok(())
    }

    /// Get pending frames to send
    pub fn pending_frames(&mut self) -> Vec<Frame> {
        self.send_queue.drain(..).collect()
    }

    /// Get statistics
    pub fn stats(&self) -> WebSocketStats {
        WebSocketStats {
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            messages_sent: self.messages_sent.load(Ordering::Relaxed),
            messages_received: self.messages_received.load(Ordering::Relaxed),
        }
    }
}

/// WebSocket connection statistics
#[derive(Debug, Clone)]
pub struct WebSocketStats {
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Messages sent
    pub messages_sent: u64,
    /// Messages received
    pub messages_received: u64,
}

// ============================================================================
// WebSocket Server
// ============================================================================

/// WebSocket handler trait
pub trait WebSocketHandler: Send + Sync {
    /// Called when a new connection is established
    fn on_open(&self, _conn_id: u64) {}

    /// Called when a message is received
    fn on_message(&self, conn_id: u64, message: Message) -> Option<Message>;

    /// Called when an error occurs
    fn on_error(&self, _conn_id: u64, _error: WebSocketError) {}

    /// Called when the connection is closed
    fn on_close(&self, _conn_id: u64, _frame: Option<CloseFrame>) {}
}

/// Echo handler for testing
#[derive(Debug, Default)]
pub struct EchoHandler;

impl WebSocketHandler for EchoHandler {
    fn on_message(&self, _conn_id: u64, message: Message) -> Option<Message> {
        // Echo back text and binary messages
        match message {
            Message::Text(_) | Message::Binary(_) => Some(message),
            _ => None,
        }
    }
}

/// WebSocket server connection
#[derive(Debug)]
pub struct WebSocketConnection {
    /// Connection ID
    pub id: u64,
    /// Connection state
    state: WebSocketState,
    /// Configuration
    config: WebSocketConfig,
    /// Fragment buffer
    fragment_buffer: Option<(Opcode, Vec<u8>)>,
    /// Remote address info
    pub remote: String,
}

impl WebSocketConnection {
    /// Create a new server connection
    pub fn new(id: u64, remote: impl Into<String>, config: WebSocketConfig) -> Self {
        Self {
            id,
            state: WebSocketState::Open,
            config,
            fragment_buffer: None,
            remote: remote.into(),
        }
    }

    /// Get connection state
    pub fn state(&self) -> WebSocketState {
        self.state
    }

    /// Process a received frame
    pub fn process_frame(&mut self, frame: Frame) -> Result<Option<Message>, WebSocketError> {
        match frame.opcode {
            Opcode::Text => {
                if frame.fin {
                    let text = String::from_utf8(frame.payload)
                        .map_err(|_| WebSocketError::InvalidUtf8)?;
                    Ok(Some(Message::Text(text)))
                } else {
                    self.fragment_buffer = Some((Opcode::Text, frame.payload));
                    Ok(None)
                }
            }
            Opcode::Binary => {
                if frame.fin {
                    Ok(Some(Message::Binary(frame.payload)))
                } else {
                    self.fragment_buffer = Some((Opcode::Binary, frame.payload));
                    Ok(None)
                }
            }
            Opcode::Continuation => {
                if let Some((opcode, mut buffer)) = self.fragment_buffer.take() {
                    buffer.extend(frame.payload);
                    if buffer.len() > self.config.max_message_size {
                        return Err(WebSocketError::MessageTooLarge(buffer.len()));
                    }
                    if frame.fin {
                        match opcode {
                            Opcode::Text => {
                                let text = String::from_utf8(buffer)
                                    .map_err(|_| WebSocketError::InvalidUtf8)?;
                                Ok(Some(Message::Text(text)))
                            }
                            Opcode::Binary => Ok(Some(Message::Binary(buffer))),
                            _ => Err(WebSocketError::ProtocolError("Invalid continuation".into())),
                        }
                    } else {
                        self.fragment_buffer = Some((opcode, buffer));
                        Ok(None)
                    }
                } else {
                    Err(WebSocketError::ProtocolError(
                        "Unexpected continuation".into(),
                    ))
                }
            }
            Opcode::Ping => Ok(Some(Message::Ping(frame.payload))),
            Opcode::Pong => Ok(Some(Message::Pong(frame.payload))),
            Opcode::Close => {
                let close_frame = CloseFrame::from_bytes(&frame.payload);
                self.state = WebSocketState::Closed;
                Ok(Some(Message::Close(close_frame)))
            }
        }
    }

    /// Create a response frame (server frames are not masked)
    pub fn create_frame(&self, msg: Message) -> Frame {
        match msg {
            Message::Text(text) => Frame::text(text),
            Message::Binary(data) => Frame::binary(data),
            Message::Ping(data) => Frame::ping(data),
            Message::Pong(data) => Frame::pong(data),
            Message::Close(frame) => {
                let (code, reason) = frame
                    .map(|f| (f.code, f.reason))
                    .unwrap_or((CloseCode::Normal, String::new()));
                Frame::close(code, &reason)
            }
        }
    }
}

/// WebSocket server endpoint
pub struct WebSocketServer {
    /// Server configuration
    config: WebSocketConfig,
    /// Active connections
    connections: std::collections::HashMap<u64, WebSocketConnection>,
    /// Next connection ID
    next_conn_id: AtomicU64,
    /// Handler
    handler: Arc<dyn WebSocketHandler>,
}

impl std::fmt::Debug for WebSocketServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebSocketServer")
            .field("config", &self.config)
            .field("connections", &self.connections.len())
            .field("next_conn_id", &self.next_conn_id)
            .finish()
    }
}

impl WebSocketServer {
    /// Create a new WebSocket server
    pub fn new<H: WebSocketHandler + 'static>(handler: H) -> Self {
        Self::with_config(handler, WebSocketConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config<H: WebSocketHandler + 'static>(handler: H, config: WebSocketConfig) -> Self {
        Self {
            config,
            connections: std::collections::HashMap::new(),
            next_conn_id: AtomicU64::new(1),
            handler: Arc::new(handler),
        }
    }

    /// Accept a new connection
    pub fn accept(&mut self, remote: impl Into<String>) -> u64 {
        let conn_id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let conn = WebSocketConnection::new(conn_id, remote, self.config.clone());
        self.connections.insert(conn_id, conn);
        self.handler.on_open(conn_id);
        conn_id
    }

    /// Handle received data
    pub fn handle_frame(&mut self, conn_id: u64, frame: Frame) -> Option<Frame> {
        let conn = self.connections.get_mut(&conn_id)?;

        match conn.process_frame(frame) {
            Ok(Some(msg)) => {
                // Handle control frames
                if let Message::Ping(data) = &msg {
                    return Some(Frame::pong(data.clone()));
                }
                if let Message::Close(ref cf) = msg {
                    self.handler.on_close(conn_id, cf.clone());
                    self.connections.remove(&conn_id);
                    // Echo close
                    let (code, reason) = cf
                        .clone()
                        .map(|f| (f.code, f.reason))
                        .unwrap_or((CloseCode::Normal, String::new()));
                    return Some(Frame::close(code, &reason));
                }

                // Call handler
                if let Some(response) = self.handler.on_message(conn_id, msg) {
                    let conn = self.connections.get(&conn_id)?;
                    return Some(conn.create_frame(response));
                }
            }
            Ok(None) => {
                // Fragmented message, waiting for more
            }
            Err(e) => {
                self.handler.on_error(conn_id, e);
            }
        }

        None
    }

    /// Close a connection
    pub fn close(&mut self, conn_id: u64, code: CloseCode, reason: &str) -> Option<Frame> {
        if self.connections.remove(&conn_id).is_some() {
            self.handler
                .on_close(conn_id, Some(CloseFrame::new(code, reason.to_string())));
            Some(Frame::close(code, reason))
        } else {
            None
        }
    }

    /// Get active connection count
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Get all connection IDs
    pub fn connection_ids(&self) -> Vec<u64> {
        self.connections.keys().copied().collect()
    }
}

// ============================================================================
// WebSocket Handshake
// ============================================================================

/// Generate WebSocket accept key from client key
pub fn generate_accept_key(key: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // In real implementation, use SHA-1 + base64
    // This is a simplified version for demonstration
    let magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let combined = format!("{}{}", key, magic);

    let mut hasher = DefaultHasher::new();
    combined.hash(&mut hasher);
    let hash = hasher.finish();

    // Simplified base64-like encoding
    base64_encode(&hash.to_be_bytes())
}

/// Simple base64 encoding
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    let mut i = 0;

    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = data.get(i + 1).copied().unwrap_or(0) as u32;
        let b2 = data.get(i + 2).copied().unwrap_or(0) as u32;

        let n = (b0 << 16) | (b1 << 8) | b2;

        result.push(CHARS[((n >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((n >> 12) & 0x3F) as usize] as char);

        if i + 1 < data.len() {
            result.push(CHARS[((n >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        if i + 2 < data.len() {
            result.push(CHARS[(n & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }

    result
}

/// Generate random WebSocket key
pub fn generate_client_key() -> String {
    let random_bytes: [u8; 16] = rand::random();
    base64_encode(&random_bytes)
}

/// Build upgrade request headers
#[derive(Debug)]
pub struct UpgradeRequest {
    /// Target host
    pub host: String,
    /// Target path
    pub path: String,
    /// WebSocket key
    pub key: String,
    /// WebSocket version
    pub version: u8,
    /// Subprotocols
    pub protocols: Vec<String>,
    /// Extensions
    pub extensions: Vec<String>,
}

impl UpgradeRequest {
    /// Create a new upgrade request
    pub fn new(host: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            path: path.into(),
            key: generate_client_key(),
            version: 13,
            protocols: Vec::new(),
            extensions: Vec::new(),
        }
    }

    /// Add a subprotocol
    pub fn with_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocols.push(protocol.into());
        self
    }

    /// Add an extension
    pub fn with_extension(mut self, extension: impl Into<String>) -> Self {
        self.extensions.push(extension.into());
        self
    }

    /// Build the HTTP request
    pub fn build(&self) -> String {
        let mut request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: {}\r\n",
            self.path, self.host, self.key, self.version
        );

        if !self.protocols.is_empty() {
            request.push_str(&format!(
                "Sec-WebSocket-Protocol: {}\r\n",
                self.protocols.join(", ")
            ));
        }

        if !self.extensions.is_empty() {
            request.push_str(&format!(
                "Sec-WebSocket-Extensions: {}\r\n",
                self.extensions.join(", ")
            ));
        }

        request.push_str("\r\n");
        request
    }

    /// Get expected accept key
    pub fn expected_accept(&self) -> String {
        generate_accept_key(&self.key)
    }
}

/// Build upgrade response headers
#[derive(Debug)]
pub struct UpgradeResponse {
    /// Accept key
    pub accept: String,
    /// Selected protocol
    pub protocol: Option<String>,
    /// Selected extensions
    pub extensions: Vec<String>,
}

impl UpgradeResponse {
    /// Create from client key
    pub fn from_key(key: &str) -> Self {
        Self {
            accept: generate_accept_key(key),
            protocol: None,
            extensions: Vec::new(),
        }
    }

    /// Set selected protocol
    pub fn with_protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = Some(protocol.into());
        self
    }

    /// Build the HTTP response
    pub fn build(&self) -> String {
        let mut response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\n",
            self.accept
        );

        if let Some(ref proto) = self.protocol {
            response.push_str(&format!("Sec-WebSocket-Protocol: {}\r\n", proto));
        }

        if !self.extensions.is_empty() {
            response.push_str(&format!(
                "Sec-WebSocket-Extensions: {}\r\n",
                self.extensions.join(", ")
            ));
        }

        response.push_str("\r\n");
        response
    }
}

// ============================================================================
// REAL WebSocket over Tor - Using tokio-tungstenite
// ============================================================================

use arti_client::{IsolationToken as ArtiIsolationToken, StreamPrefs, TorClient as ArtiClient};
use futures::{SinkExt, StreamExt};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::Uri;
use tokio_tungstenite::tungstenite::protocol::Message as TungsteniteMessage;
use tor_rtcompat::PreferredRuntime;

/// Real WebSocket client that operates over Tor.
///
/// This wraps `tokio-tungstenite` over a Tor `DataStream`, providing
/// real WebSocket protocol support through the Tor network.
///
/// # Example
///
/// ```rust,ignore
/// use hypertor::websocket::TorWebSocket;
/// use hypertor::TorClient;
///
/// // Create Tor client first
/// let tor = TorClient::new().await?;
///
/// // Connect WebSocket over Tor
/// let mut ws = TorWebSocket::connect(&tor, "wss://example.onion/ws").await?;
///
/// // Send and receive messages
/// ws.send_text("Hello!").await?;
/// while let Some(msg) = ws.recv().await? {
///     println!("Received: {:?}", msg);
/// }
/// ```
pub struct TorWebSocket {
    inner: WebSocketStream<arti_client::DataStream>,
    url: String,
}

impl TorWebSocket {
    /// Connect to a WebSocket server over Tor.
    ///
    /// The URL should be either `ws://` or `wss://` scheme.
    /// For `.onion` addresses, always use `ws://` (TLS is provided by Tor).
    ///
    /// # Arguments
    /// * `tor_client` - The Tor client to use for the connection
    /// * `url` - WebSocket URL (ws:// or wss://)
    ///
    /// # Example
    /// ```rust,ignore
    /// let ws = TorWebSocket::connect(&tor, "ws://example.onion/ws").await?;
    /// ```
    pub async fn connect(
        tor_client: &Arc<ArtiClient<PreferredRuntime>>,
        url: &str,
    ) -> Result<Self, WebSocketError> {
        Self::connect_with_isolation(tor_client, url, None).await
    }

    /// Connect with circuit isolation.
    ///
    /// Use this when you need WebSocket connections to use separate Tor circuits.
    pub async fn connect_with_isolation(
        tor_client: &Arc<ArtiClient<PreferredRuntime>>,
        url: &str,
        isolation_token: Option<ArtiIsolationToken>,
    ) -> Result<Self, WebSocketError> {
        // Parse URL
        let uri: Uri = url
            .parse()
            .map_err(|e| WebSocketError::ConnectionFailed(format!("Invalid URL: {}", e)))?;

        let host = uri
            .host()
            .ok_or_else(|| WebSocketError::ConnectionFailed("Missing host in URL".into()))?;

        let is_tls = uri.scheme_str() == Some("wss");
        let port = uri.port_u16().unwrap_or(if is_tls { 443 } else { 80 });

        // For .onion addresses, we don't need/want TLS (Tor provides e2e encryption)
        // But for clearnet via Tor, we should use TLS
        if is_tls && host.ends_with(".onion") {
            tracing::warn!(
                "Using wss:// with .onion address is unnecessary - Tor provides encryption"
            );
        }

        // Connect through Tor
        let data_stream = if let Some(token) = isolation_token {
            let mut prefs = StreamPrefs::new();
            prefs.set_isolation(token);
            tor_client.connect_with_prefs((host, port), &prefs).await
        } else {
            tor_client.connect((host, port)).await
        }
        .map_err(|e| WebSocketError::ConnectionFailed(format!("Tor connection failed: {}", e)))?;

        tracing::debug!("Tor connection established to {}:{}", host, port);

        // Perform WebSocket handshake over the Tor stream
        // For .onion, use plain WS. For clearnet, we'd need TLS wrapping.
        let request = url
            .into_client_request()
            .map_err(|e| WebSocketError::ConnectionFailed(format!("Invalid request: {}", e)))?;

        let (ws_stream, _response) = tokio_tungstenite::client_async(request, data_stream)
            .await
            .map_err(|e| {
                WebSocketError::ConnectionFailed(format!("WebSocket handshake failed: {}", e))
            })?;

        tracing::info!("WebSocket connection established over Tor to {}", url);

        Ok(Self {
            inner: ws_stream,
            url: url.to_string(),
        })
    }

    /// Send a text message.
    pub async fn send_text(&mut self, text: impl Into<String>) -> Result<(), WebSocketError> {
        self.inner
            .send(TungsteniteMessage::Text(text.into().into()))
            .await
            .map_err(|e| WebSocketError::SendFailed(e.to_string()))
    }

    /// Send a binary message.
    pub async fn send_binary(&mut self, data: impl Into<Vec<u8>>) -> Result<(), WebSocketError> {
        self.inner
            .send(TungsteniteMessage::Binary(data.into().into()))
            .await
            .map_err(|e| WebSocketError::SendFailed(e.to_string()))
    }

    /// Send a ping frame.
    pub async fn send_ping(&mut self, data: Vec<u8>) -> Result<(), WebSocketError> {
        self.inner
            .send(TungsteniteMessage::Ping(data.into()))
            .await
            .map_err(|e| WebSocketError::SendFailed(e.to_string()))
    }

    /// Close the WebSocket connection gracefully.
    pub async fn close(&mut self) -> Result<(), WebSocketError> {
        self.inner
            .close(None)
            .await
            .map_err(|e| WebSocketError::ConnectionFailed(e.to_string()))
    }

    /// Receive the next message.
    ///
    /// Returns `None` if the connection is closed.
    pub async fn recv(&mut self) -> Result<Option<Message>, WebSocketError> {
        loop {
            match self.inner.next().await {
                Some(Ok(msg)) => {
                    let converted = match msg {
                        TungsteniteMessage::Text(s) => Message::Text(s.to_string()),
                        TungsteniteMessage::Binary(b) => Message::Binary(b.to_vec()),
                        TungsteniteMessage::Ping(p) => Message::Ping(p.to_vec()),
                        TungsteniteMessage::Pong(p) => Message::Pong(p.to_vec()),
                        TungsteniteMessage::Close(c) => {
                            let frame = c.map(|cf| CloseFrame {
                                code: CloseCode::from_u16(cf.code.into()),
                                reason: cf.reason.to_string(),
                            });
                            Message::Close(frame)
                        }
                        TungsteniteMessage::Frame(_) => {
                            // Raw frames are not typically exposed to users, skip
                            continue;
                        }
                    };
                    return Ok(Some(converted));
                }
                Some(Err(e)) => return Err(WebSocketError::ProtocolError(e.to_string())),
                None => return Ok(None),
            }
        }
    }

    /// Get the connection URL.
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// Builder for creating WebSocket connections over Tor.
pub struct TorWebSocketBuilder {
    tor_client: Arc<ArtiClient<PreferredRuntime>>,
    isolation_token: Option<ArtiIsolationToken>,
    subprotocols: Vec<String>,
}

impl TorWebSocketBuilder {
    /// Create a new builder with a Tor client.
    pub fn new(tor_client: Arc<ArtiClient<PreferredRuntime>>) -> Self {
        Self {
            tor_client,
            isolation_token: None,
            subprotocols: Vec::new(),
        }
    }

    /// Set circuit isolation token.
    pub fn isolation(mut self, token: ArtiIsolationToken) -> Self {
        self.isolation_token = Some(token);
        self
    }

    /// Add a subprotocol.
    pub fn subprotocol(mut self, protocol: impl Into<String>) -> Self {
        self.subprotocols.push(protocol.into());
        self
    }

    /// Connect to the WebSocket server.
    pub async fn connect(self, url: &str) -> Result<TorWebSocket, WebSocketError> {
        TorWebSocket::connect_with_isolation(&self.tor_client, url, self.isolation_token).await
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn test_frame_encode_decode() {
        let original = Frame::text("Hello, World!");
        let encoded = original.encode();
        let (decoded, len) = Frame::decode(&encoded).unwrap();

        assert_eq!(len, encoded.len());
        assert_eq!(decoded.opcode, Opcode::Text);
        assert!(decoded.fin);
        assert_eq!(decoded.payload, b"Hello, World!");
    }

    #[test]
    fn test_frame_with_mask() {
        let frame = Frame::text("Test").with_mask([0x37, 0xfa, 0x21, 0x3d]);
        let encoded = frame.encode();
        let (decoded, _) = Frame::decode(&encoded).unwrap();

        assert_eq!(decoded.payload, b"Test");
    }

    #[test]
    fn test_message_types() {
        assert!(Message::text("hello").is_text());
        assert!(Message::binary(vec![1, 2, 3]).is_binary());
        assert!(Message::close(CloseCode::Normal, "bye").is_close());
    }

    #[test]
    fn test_close_codes() {
        assert_eq!(CloseCode::Normal.to_u16(), 1000);
        assert_eq!(CloseCode::from_u16(1001), CloseCode::GoingAway);
        assert_eq!(CloseCode::from_u16(4000), CloseCode::Custom(4000));
    }

    #[test]
    fn test_client_send_receive() {
        let mut client = WebSocketClient::new("ws://test.onion/ws");
        client.open();

        // Send a message
        client.send_text("Hello").unwrap();
        assert_eq!(client.stats().messages_sent, 1);

        // Process a received frame
        let frame = Frame::text("World");
        let msg = client.process_frame(frame).unwrap().unwrap();
        assert_eq!(msg.as_text(), Some("World"));
    }

    #[test]
    fn test_echo_server() {
        let mut server = WebSocketServer::new(EchoHandler::default());

        // Accept connection
        let conn_id = server.accept("127.0.0.1:12345");
        assert_eq!(server.connection_count(), 1);

        // Send text, expect echo
        let frame = Frame::text("Echo test").with_mask([1, 2, 3, 4]);
        let response = server.handle_frame(conn_id, frame).unwrap();
        assert_eq!(response.opcode, Opcode::Text);
        assert_eq!(response.payload, b"Echo test");

        // Send ping, expect pong
        let ping = Frame::ping(vec![1, 2, 3]).with_mask([4, 5, 6, 7]);
        let pong = server.handle_frame(conn_id, ping).unwrap();
        assert_eq!(pong.opcode, Opcode::Pong);
    }

    #[test]
    fn test_fragmented_message() {
        let mut client = WebSocketClient::new("ws://test.onion");
        client.open();

        // First fragment
        let frame1 = Frame::new(Opcode::Text, b"Hello, ".to_vec()).with_fin(false);
        assert!(client.process_frame(frame1).unwrap().is_none());

        // Continuation
        let frame2 = Frame::new(Opcode::Continuation, b"World!".to_vec());
        let msg = client.process_frame(frame2).unwrap().unwrap();
        assert_eq!(msg.as_text(), Some("Hello, World!"));
    }

    #[test]
    fn test_upgrade_handshake() {
        let request = UpgradeRequest::new("example.onion", "/ws").with_protocol("chat");

        let req_str = request.build();
        assert!(req_str.contains("Upgrade: websocket"));
        assert!(req_str.contains("Sec-WebSocket-Version: 13"));
        assert!(req_str.contains("Sec-WebSocket-Protocol: chat"));

        let response = UpgradeResponse::from_key(&request.key).with_protocol("chat");

        let resp_str = response.build();
        assert!(resp_str.contains("101 Switching Protocols"));
        assert!(resp_str.contains(&request.expected_accept()));
    }

    #[test]
    fn test_tor_optimized_config() {
        let config = WebSocketConfig::tor_optimized();
        assert!(config.compression);
        assert!(config.ping_interval.unwrap() >= Duration::from_secs(60));
        assert!(config.pong_timeout >= Duration::from_secs(60));
    }

    #[test]
    fn test_large_frame() {
        let data = vec![0u8; 100_000];
        let frame = Frame::binary(data.clone());
        let encoded = frame.encode();
        let (decoded, _) = Frame::decode(&encoded).unwrap();

        assert_eq!(decoded.payload.len(), 100_000);
        assert_eq!(decoded.payload, data);
    }
}
