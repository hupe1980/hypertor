//! HTTP/2 Protocol Support
//!
//! This module provides HTTP/2 multiplexing over Tor connections,
//! enabling efficient concurrent requests over a single connection.
//!
//! # Features
//!
//! - **Multiplexing**: Multiple streams over one connection
//! - **Flow Control**: Per-stream and connection-level flow control
//! - **Server Push**: Support for server-initiated streams
//! - **Header Compression**: HPACK compression
//! - **Priority**: Stream prioritization
//!
//! # Example
//!
//! ```rust,ignore
//! use hypertor::http2::{Http2Client, Http2Config};
//!
//! let client = Http2Client::new(Http2Config::default());
//! let stream = client.request("GET", "https://example.onion/api").await?;
//! let response = stream.recv_response().await?;
//! ```

#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use parking_lot::RwLock;

// ============================================================================
// Constants (RFC 7540)
// ============================================================================

/// HTTP/2 connection preface
pub const CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Default initial window size (64KB)
pub const DEFAULT_INITIAL_WINDOW_SIZE: u32 = 65535;

/// Default max frame size (16KB)
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16384;

/// Maximum frame size allowed (16MB)
pub const MAX_FRAME_SIZE_LIMIT: u32 = 16777215;

/// Default header table size (4KB)
pub const DEFAULT_HEADER_TABLE_SIZE: u32 = 4096;

/// Default max concurrent streams
pub const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 100;

/// Default max header list size
pub const DEFAULT_MAX_HEADER_LIST_SIZE: u32 = 8192;

// ============================================================================
// Frame Types (RFC 7540 Section 6)
// ============================================================================

/// HTTP/2 frame types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    /// DATA frame
    Data = 0x0,
    /// HEADERS frame
    Headers = 0x1,
    /// PRIORITY frame
    Priority = 0x2,
    /// RST_STREAM frame
    RstStream = 0x3,
    /// SETTINGS frame
    Settings = 0x4,
    /// PUSH_PROMISE frame
    PushPromise = 0x5,
    /// PING frame
    Ping = 0x6,
    /// GOAWAY frame
    GoAway = 0x7,
    /// WINDOW_UPDATE frame
    WindowUpdate = 0x8,
    /// CONTINUATION frame
    Continuation = 0x9,
}

impl FrameType {
    /// Parse from byte
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x0 => Some(Self::Data),
            0x1 => Some(Self::Headers),
            0x2 => Some(Self::Priority),
            0x3 => Some(Self::RstStream),
            0x4 => Some(Self::Settings),
            0x5 => Some(Self::PushPromise),
            0x6 => Some(Self::Ping),
            0x7 => Some(Self::GoAway),
            0x8 => Some(Self::WindowUpdate),
            0x9 => Some(Self::Continuation),
            _ => None,
        }
    }
}

// ============================================================================
// Frame Flags
// ============================================================================

/// Frame flags
#[derive(Debug, Clone, Copy, Default)]
pub struct FrameFlags(u8);

impl FrameFlags {
    /// No flags
    pub const NONE: Self = Self(0);
    /// END_STREAM flag (DATA, HEADERS)
    pub const END_STREAM: Self = Self(0x1);
    /// ACK flag (SETTINGS, PING)
    pub const ACK: Self = Self(0x1);
    /// END_HEADERS flag (HEADERS, PUSH_PROMISE, CONTINUATION)
    pub const END_HEADERS: Self = Self(0x4);
    /// PADDED flag (DATA, HEADERS, PUSH_PROMISE)
    pub const PADDED: Self = Self(0x8);
    /// PRIORITY flag (HEADERS)
    pub const PRIORITY: Self = Self(0x20);

    /// Check if flag is set
    pub fn contains(&self, flag: Self) -> bool {
        (self.0 & flag.0) != 0
    }

    /// Set a flag
    pub fn set(&mut self, flag: Self) {
        self.0 |= flag.0;
    }

    /// Get raw value
    pub fn bits(&self) -> u8 {
        self.0
    }

    /// Create from raw bits
    pub fn from_bits(bits: u8) -> Self {
        Self(bits)
    }
}

// ============================================================================
// Error Codes (RFC 7540 Section 7)
// ============================================================================

/// HTTP/2 error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    /// No error
    NoError = 0x0,
    /// Protocol error
    ProtocolError = 0x1,
    /// Internal error
    InternalError = 0x2,
    /// Flow control error
    FlowControlError = 0x3,
    /// Settings timeout
    SettingsTimeout = 0x4,
    /// Stream closed
    StreamClosed = 0x5,
    /// Frame size error
    FrameSizeError = 0x6,
    /// Refused stream
    RefusedStream = 0x7,
    /// Cancel
    Cancel = 0x8,
    /// Compression error
    CompressionError = 0x9,
    /// Connect error
    ConnectError = 0xa,
    /// Enhance your calm
    EnhanceYourCalm = 0xb,
    /// Inadequate security
    InadequateSecurity = 0xc,
    /// HTTP/1.1 required
    Http11Required = 0xd,
}

impl ErrorCode {
    /// Parse from u32
    pub fn from_u32(v: u32) -> Self {
        match v {
            0x0 => Self::NoError,
            0x1 => Self::ProtocolError,
            0x2 => Self::InternalError,
            0x3 => Self::FlowControlError,
            0x4 => Self::SettingsTimeout,
            0x5 => Self::StreamClosed,
            0x6 => Self::FrameSizeError,
            0x7 => Self::RefusedStream,
            0x8 => Self::Cancel,
            0x9 => Self::CompressionError,
            0xa => Self::ConnectError,
            0xb => Self::EnhanceYourCalm,
            0xc => Self::InadequateSecurity,
            0xd => Self::Http11Required,
            _ => Self::InternalError,
        }
    }
}

// ============================================================================
// Settings (RFC 7540 Section 6.5.2)
// ============================================================================

/// Settings parameter identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SettingId {
    /// Header table size
    HeaderTableSize = 0x1,
    /// Enable push
    EnablePush = 0x2,
    /// Max concurrent streams
    MaxConcurrentStreams = 0x3,
    /// Initial window size
    InitialWindowSize = 0x4,
    /// Max frame size
    MaxFrameSize = 0x5,
    /// Max header list size
    MaxHeaderListSize = 0x6,
}

/// Connection settings
#[derive(Debug, Clone)]
pub struct Settings {
    /// Header table size for HPACK
    pub header_table_size: u32,
    /// Enable server push
    pub enable_push: bool,
    /// Max concurrent streams
    pub max_concurrent_streams: u32,
    /// Initial window size for flow control
    pub initial_window_size: u32,
    /// Max frame size
    pub max_frame_size: u32,
    /// Max header list size
    pub max_header_list_size: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            header_table_size: DEFAULT_HEADER_TABLE_SIZE,
            enable_push: true,
            max_concurrent_streams: DEFAULT_MAX_CONCURRENT_STREAMS,
            initial_window_size: DEFAULT_INITIAL_WINDOW_SIZE,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            max_header_list_size: DEFAULT_MAX_HEADER_LIST_SIZE,
        }
    }
}

impl Settings {
    /// Create Tor-optimized settings (higher latency tolerance)
    pub fn tor_optimized() -> Self {
        Self {
            header_table_size: DEFAULT_HEADER_TABLE_SIZE,
            enable_push: false,           // Disable push over Tor
            max_concurrent_streams: 50,   // Lower for Tor
            initial_window_size: 1048576, // 1MB - larger for high latency
            max_frame_size: 65536,        // 64KB frames
            max_header_list_size: 16384,  // 16KB headers
        }
    }

    /// Serialize to frame payload
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(36);

        // Each setting is 6 bytes: 2 byte ID + 4 byte value
        buf.extend_from_slice(&(SettingId::HeaderTableSize as u16).to_be_bytes());
        buf.extend_from_slice(&self.header_table_size.to_be_bytes());

        buf.extend_from_slice(&(SettingId::EnablePush as u16).to_be_bytes());
        buf.extend_from_slice(&(if self.enable_push { 1u32 } else { 0u32 }).to_be_bytes());

        buf.extend_from_slice(&(SettingId::MaxConcurrentStreams as u16).to_be_bytes());
        buf.extend_from_slice(&self.max_concurrent_streams.to_be_bytes());

        buf.extend_from_slice(&(SettingId::InitialWindowSize as u16).to_be_bytes());
        buf.extend_from_slice(&self.initial_window_size.to_be_bytes());

        buf.extend_from_slice(&(SettingId::MaxFrameSize as u16).to_be_bytes());
        buf.extend_from_slice(&self.max_frame_size.to_be_bytes());

        buf.extend_from_slice(&(SettingId::MaxHeaderListSize as u16).to_be_bytes());
        buf.extend_from_slice(&self.max_header_list_size.to_be_bytes());

        buf
    }

    /// Parse from frame payload
    pub fn decode(data: &[u8]) -> Result<Self, Http2Error> {
        let mut settings = Self::default();

        if data.len() % 6 != 0 {
            return Err(Http2Error::FrameSize);
        }

        for chunk in data.chunks(6) {
            let id = u16::from_be_bytes([chunk[0], chunk[1]]);
            let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);

            match id {
                0x1 => settings.header_table_size = value,
                0x2 => settings.enable_push = value != 0,
                0x3 => settings.max_concurrent_streams = value,
                0x4 => {
                    if value > 2147483647 {
                        return Err(Http2Error::FlowControl);
                    }
                    settings.initial_window_size = value;
                }
                0x5 => {
                    if !(DEFAULT_MAX_FRAME_SIZE..=MAX_FRAME_SIZE_LIMIT).contains(&value) {
                        return Err(Http2Error::Protocol("Invalid max frame size".into()));
                    }
                    settings.max_frame_size = value;
                }
                0x6 => settings.max_header_list_size = value,
                _ => {} // Ignore unknown settings
            }
        }

        Ok(settings)
    }
}

// ============================================================================
// Frame
// ============================================================================

/// HTTP/2 frame header (9 bytes)
#[derive(Debug, Clone)]
pub struct FrameHeader {
    /// Payload length (24 bits)
    pub length: u32,
    /// Frame type
    pub frame_type: FrameType,
    /// Flags
    pub flags: FrameFlags,
    /// Stream identifier (31 bits)
    pub stream_id: u32,
}

impl FrameHeader {
    /// Create a new frame header
    pub fn new(frame_type: FrameType, flags: FrameFlags, stream_id: u32) -> Self {
        Self {
            length: 0,
            frame_type,
            flags,
            stream_id,
        }
    }

    /// Encode to bytes
    pub fn encode(&self) -> [u8; 9] {
        let mut buf = [0u8; 9];
        // Length (24 bits, big endian)
        buf[0] = ((self.length >> 16) & 0xFF) as u8;
        buf[1] = ((self.length >> 8) & 0xFF) as u8;
        buf[2] = (self.length & 0xFF) as u8;
        // Type
        buf[3] = self.frame_type as u8;
        // Flags
        buf[4] = self.flags.bits();
        // Stream ID (31 bits, R bit must be 0)
        let sid = self.stream_id & 0x7FFFFFFF;
        buf[5] = ((sid >> 24) & 0xFF) as u8;
        buf[6] = ((sid >> 16) & 0xFF) as u8;
        buf[7] = ((sid >> 8) & 0xFF) as u8;
        buf[8] = (sid & 0xFF) as u8;
        buf
    }

    /// Decode from bytes
    pub fn decode(data: &[u8; 9]) -> Result<Self, Http2Error> {
        let length = ((data[0] as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32);
        let frame_type = FrameType::from_byte(data[3])
            .ok_or_else(|| Http2Error::Protocol("Unknown frame type".into()))?;
        let flags = FrameFlags::from_bits(data[4]);
        let stream_id = ((data[5] as u32) << 24)
            | ((data[6] as u32) << 16)
            | ((data[7] as u32) << 8)
            | (data[8] as u32);
        let stream_id = stream_id & 0x7FFFFFFF; // Clear R bit

        Ok(Self {
            length,
            frame_type,
            flags,
            stream_id,
        })
    }
}

/// Complete HTTP/2 frame
#[derive(Debug, Clone)]
pub struct Frame {
    /// Frame header
    pub header: FrameHeader,
    /// Frame payload
    pub payload: Vec<u8>,
}

impl Frame {
    /// Create a new frame
    pub fn new(frame_type: FrameType, flags: FrameFlags, stream_id: u32, payload: Vec<u8>) -> Self {
        let mut header = FrameHeader::new(frame_type, flags, stream_id);
        header.length = payload.len() as u32;
        Self { header, payload }
    }

    /// Create a DATA frame
    pub fn data(stream_id: u32, data: Vec<u8>, end_stream: bool) -> Self {
        let flags = if end_stream {
            FrameFlags::END_STREAM
        } else {
            FrameFlags::NONE
        };
        Self::new(FrameType::Data, flags, stream_id, data)
    }

    /// Create a HEADERS frame
    pub fn headers(stream_id: u32, headers: Vec<u8>, end_stream: bool, end_headers: bool) -> Self {
        let mut flags = FrameFlags::NONE;
        if end_stream {
            flags.set(FrameFlags::END_STREAM);
        }
        if end_headers {
            flags.set(FrameFlags::END_HEADERS);
        }
        Self::new(FrameType::Headers, flags, stream_id, headers)
    }

    /// Create a SETTINGS frame
    pub fn settings(settings: &Settings) -> Self {
        Self::new(FrameType::Settings, FrameFlags::NONE, 0, settings.encode())
    }

    /// Create a SETTINGS ACK frame
    pub fn settings_ack() -> Self {
        Self::new(FrameType::Settings, FrameFlags::ACK, 0, vec![])
    }

    /// Create a PING frame
    pub fn ping(data: [u8; 8]) -> Self {
        Self::new(FrameType::Ping, FrameFlags::NONE, 0, data.to_vec())
    }

    /// Create a PING ACK frame
    pub fn ping_ack(data: [u8; 8]) -> Self {
        Self::new(FrameType::Ping, FrameFlags::ACK, 0, data.to_vec())
    }

    /// Create a GOAWAY frame
    pub fn goaway(last_stream_id: u32, error_code: ErrorCode, debug_data: Vec<u8>) -> Self {
        let mut payload = Vec::with_capacity(8 + debug_data.len());
        payload.extend_from_slice(&last_stream_id.to_be_bytes());
        payload.extend_from_slice(&(error_code as u32).to_be_bytes());
        payload.extend(debug_data);
        Self::new(FrameType::GoAway, FrameFlags::NONE, 0, payload)
    }

    /// Create a WINDOW_UPDATE frame
    pub fn window_update(stream_id: u32, increment: u32) -> Self {
        let increment = increment & 0x7FFFFFFF; // Clear reserved bit
        Self::new(
            FrameType::WindowUpdate,
            FrameFlags::NONE,
            stream_id,
            increment.to_be_bytes().to_vec(),
        )
    }

    /// Create an RST_STREAM frame
    pub fn rst_stream(stream_id: u32, error_code: ErrorCode) -> Self {
        Self::new(
            FrameType::RstStream,
            FrameFlags::NONE,
            stream_id,
            (error_code as u32).to_be_bytes().to_vec(),
        )
    }

    /// Encode the entire frame
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(9 + self.payload.len());
        buf.extend_from_slice(&self.header.encode());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Decode a frame from buffer
    pub fn decode(data: &[u8]) -> Result<(Self, usize), Http2Error> {
        if data.len() < 9 {
            return Err(Http2Error::Incomplete);
        }

        let header_bytes: &[u8; 9] = data[..9].try_into().map_err(|_| Http2Error::Incomplete)?;
        let header = FrameHeader::decode(header_bytes)?;
        let total_len = 9 + header.length as usize;

        if data.len() < total_len {
            return Err(Http2Error::Incomplete);
        }

        let payload = data[9..total_len].to_vec();
        Ok((Self { header, payload }, total_len))
    }
}

// ============================================================================
// Stream State
// ============================================================================

/// Stream states (RFC 7540 Section 5.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Idle - initial state
    Idle,
    /// Reserved (local) - push promise sent
    ReservedLocal,
    /// Reserved (remote) - push promise received
    ReservedRemote,
    /// Open - active stream
    Open,
    /// Half-closed (local) - sent END_STREAM
    HalfClosedLocal,
    /// Half-closed (remote) - received END_STREAM
    HalfClosedRemote,
    /// Closed
    Closed,
}

/// HTTP/2 stream
#[derive(Debug)]
pub struct Stream {
    /// Stream ID
    pub id: u32,
    /// Current state
    pub state: StreamState,
    /// Send window size
    pub send_window: i32,
    /// Receive window size
    pub recv_window: i32,
    /// Priority weight (1-256)
    pub weight: u8,
    /// Stream dependency
    pub dependency: u32,
    /// Exclusive dependency
    pub exclusive: bool,
    /// Received headers
    pub headers: Vec<(String, String)>,
    /// Received data
    pub data: Vec<u8>,
    /// Created time
    pub created: Instant,
}

impl Stream {
    /// Create a new stream
    pub fn new(id: u32, initial_window: u32) -> Self {
        Self {
            id,
            state: StreamState::Idle,
            send_window: initial_window as i32,
            recv_window: initial_window as i32,
            weight: 16, // Default weight
            dependency: 0,
            exclusive: false,
            headers: Vec::new(),
            data: Vec::new(),
            created: Instant::now(),
        }
    }

    /// Check if stream can send data
    pub fn can_send(&self) -> bool {
        matches!(
            self.state,
            StreamState::Open | StreamState::HalfClosedRemote
        )
    }

    /// Check if stream can receive data
    pub fn can_recv(&self) -> bool {
        matches!(self.state, StreamState::Open | StreamState::HalfClosedLocal)
    }

    /// Check if stream is closed
    pub fn is_closed(&self) -> bool {
        self.state == StreamState::Closed
    }

    /// Transition state on sending END_STREAM
    pub fn send_end_stream(&mut self) {
        self.state = match self.state {
            StreamState::Open => StreamState::HalfClosedLocal,
            StreamState::HalfClosedRemote => StreamState::Closed,
            _ => self.state,
        };
    }

    /// Transition state on receiving END_STREAM
    pub fn recv_end_stream(&mut self) {
        self.state = match self.state {
            StreamState::Open => StreamState::HalfClosedRemote,
            StreamState::HalfClosedLocal => StreamState::Closed,
            _ => self.state,
        };
    }

    /// Close the stream
    pub fn close(&mut self) {
        self.state = StreamState::Closed;
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// HTTP/2 errors
#[derive(Debug)]
pub enum Http2Error {
    /// Connection closed
    Closed,
    /// Need more data
    Incomplete,
    /// Protocol error
    Protocol(String),
    /// Flow control error
    FlowControl,
    /// Frame size error
    FrameSize,
    /// Stream error
    Stream(u32, ErrorCode),
    /// Connection error
    Connection(ErrorCode),
    /// IO error
    Io(String),
    /// Timeout
    Timeout,
}

impl std::fmt::Display for Http2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "Connection closed"),
            Self::Incomplete => write!(f, "Incomplete frame"),
            Self::Protocol(msg) => write!(f, "Protocol error: {}", msg),
            Self::FlowControl => write!(f, "Flow control error"),
            Self::FrameSize => write!(f, "Frame size error"),
            Self::Stream(id, code) => write!(f, "Stream {} error: {:?}", id, code),
            Self::Connection(code) => write!(f, "Connection error: {:?}", code),
            Self::Io(msg) => write!(f, "IO error: {}", msg),
            Self::Timeout => write!(f, "Timeout"),
        }
    }
}

impl std::error::Error for Http2Error {}

// ============================================================================
// HPACK (Header Compression)
// ============================================================================

/// Static table entries (RFC 7541 Appendix A)
const STATIC_TABLE: &[(&str, &str)] = &[
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// HPACK encoder/decoder
#[derive(Debug)]
pub struct Hpack {
    /// Dynamic table
    dynamic_table: VecDeque<(String, String)>,
    /// Dynamic table size
    table_size: usize,
    /// Max table size
    max_table_size: usize,
}

impl Hpack {
    /// Create a new HPACK context
    pub fn new(max_table_size: usize) -> Self {
        Self {
            dynamic_table: VecDeque::new(),
            table_size: 0,
            max_table_size,
        }
    }

    /// Get entry by index (1-based)
    fn get_entry(&self, index: usize) -> Option<(&str, &str)> {
        if index == 0 {
            return None;
        }

        if index <= STATIC_TABLE.len() {
            let (name, value) = STATIC_TABLE[index - 1];
            return Some((name, value));
        }

        let dyn_index = index - STATIC_TABLE.len() - 1;
        self.dynamic_table
            .get(dyn_index)
            .map(|(n, v)| (n.as_str(), v.as_str()))
    }

    /// Add entry to dynamic table
    fn add_entry(&mut self, name: String, value: String) {
        let entry_size = name.len() + value.len() + 32; // 32 byte overhead per entry

        // Evict entries if needed
        while self.table_size + entry_size > self.max_table_size && !self.dynamic_table.is_empty() {
            if let Some((n, v)) = self.dynamic_table.pop_back() {
                self.table_size -= n.len() + v.len() + 32;
            }
        }

        if entry_size <= self.max_table_size {
            self.dynamic_table.push_front((name, value));
            self.table_size += entry_size;
        }
    }

    /// Decode integer (RFC 7541 Section 5.1)
    fn decode_integer(&self, data: &[u8], prefix_bits: u8) -> Option<(u64, usize)> {
        if data.is_empty() {
            return None;
        }

        let prefix_mask = (1u8 << prefix_bits) - 1;
        let mut value = (data[0] & prefix_mask) as u64;

        if value < prefix_mask as u64 {
            return Some((value, 1));
        }

        let mut m = 0u64;
        let mut i = 1;

        while i < data.len() {
            let b = data[i] as u64;
            value += (b & 0x7F) << m;
            m += 7;
            i += 1;

            if b & 0x80 == 0 {
                return Some((value, i));
            }
        }

        None
    }

    /// Decode string (RFC 7541 Section 5.2)
    fn decode_string(&self, data: &[u8]) -> Option<(String, usize)> {
        if data.is_empty() {
            return None;
        }

        let huffman = data[0] & 0x80 != 0;
        let (length, consumed) = self.decode_integer(data, 7)?;
        let length = length as usize;

        if data.len() < consumed + length {
            return None;
        }

        let bytes = &data[consumed..consumed + length];
        let string = if huffman {
            // Simplified: just return raw for now
            // Full implementation would decode Huffman
            String::from_utf8_lossy(bytes).to_string()
        } else {
            String::from_utf8_lossy(bytes).to_string()
        };

        Some((string, consumed + length))
    }

    /// Decode headers from HPACK format
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<(String, String)>, Http2Error> {
        let mut headers = Vec::new();
        let mut pos = 0;

        while pos < data.len() {
            let b = data[pos];

            if b & 0x80 != 0 {
                // Indexed Header Field
                let (index, consumed) = self
                    .decode_integer(&data[pos..], 7)
                    .ok_or_else(|| Http2Error::Protocol("Invalid integer".into()))?;
                pos += consumed;

                let (name, value) = self
                    .get_entry(index as usize)
                    .ok_or_else(|| Http2Error::Protocol("Invalid index".into()))?;
                headers.push((name.to_string(), value.to_string()));
            } else if b & 0x40 != 0 {
                // Literal Header Field with Incremental Indexing
                let (index, consumed) = self
                    .decode_integer(&data[pos..], 6)
                    .ok_or_else(|| Http2Error::Protocol("Invalid integer".into()))?;
                pos += consumed;

                let name = if index > 0 {
                    let (name, _) = self
                        .get_entry(index as usize)
                        .ok_or_else(|| Http2Error::Protocol("Invalid index".into()))?;
                    name.to_string()
                } else {
                    let (name, consumed) = self
                        .decode_string(&data[pos..])
                        .ok_or_else(|| Http2Error::Protocol("Invalid string".into()))?;
                    pos += consumed;
                    name
                };

                let (value, consumed) = self
                    .decode_string(&data[pos..])
                    .ok_or_else(|| Http2Error::Protocol("Invalid string".into()))?;
                pos += consumed;

                self.add_entry(name.clone(), value.clone());
                headers.push((name, value));
            } else if b & 0xF0 == 0 {
                // Literal Header Field without Indexing
                let (index, consumed) = self
                    .decode_integer(&data[pos..], 4)
                    .ok_or_else(|| Http2Error::Protocol("Invalid integer".into()))?;
                pos += consumed;

                let name = if index > 0 {
                    let (name, _) = self
                        .get_entry(index as usize)
                        .ok_or_else(|| Http2Error::Protocol("Invalid index".into()))?;
                    name.to_string()
                } else {
                    let (name, consumed) = self
                        .decode_string(&data[pos..])
                        .ok_or_else(|| Http2Error::Protocol("Invalid string".into()))?;
                    pos += consumed;
                    name
                };

                let (value, consumed) = self
                    .decode_string(&data[pos..])
                    .ok_or_else(|| Http2Error::Protocol("Invalid string".into()))?;
                pos += consumed;

                headers.push((name, value));
            } else if b & 0xF0 == 0x10 {
                // Literal Header Field Never Indexed
                // Same as without indexing
                let (index, consumed) = self
                    .decode_integer(&data[pos..], 4)
                    .ok_or_else(|| Http2Error::Protocol("Invalid integer".into()))?;
                pos += consumed;

                let name = if index > 0 {
                    let (name, _) = self
                        .get_entry(index as usize)
                        .ok_or_else(|| Http2Error::Protocol("Invalid index".into()))?;
                    name.to_string()
                } else {
                    let (name, consumed) = self
                        .decode_string(&data[pos..])
                        .ok_or_else(|| Http2Error::Protocol("Invalid string".into()))?;
                    pos += consumed;
                    name
                };

                let (value, consumed) = self
                    .decode_string(&data[pos..])
                    .ok_or_else(|| Http2Error::Protocol("Invalid string".into()))?;
                pos += consumed;

                headers.push((name, value));
            } else if b & 0xE0 == 0x20 {
                // Dynamic Table Size Update
                let (size, consumed) = self
                    .decode_integer(&data[pos..], 5)
                    .ok_or_else(|| Http2Error::Protocol("Invalid integer".into()))?;
                pos += consumed;
                self.max_table_size = size as usize;

                // Evict if needed
                while self.table_size > self.max_table_size {
                    if let Some((n, v)) = self.dynamic_table.pop_back() {
                        self.table_size -= n.len() + v.len() + 32;
                    } else {
                        break;
                    }
                }
            } else {
                return Err(Http2Error::Protocol("Unknown header encoding".into()));
            }
        }

        Ok(headers)
    }

    /// Encode integer
    fn encode_integer(&self, value: u64, prefix_bits: u8) -> Vec<u8> {
        let prefix_mask = (1u64 << prefix_bits) - 1;

        if value < prefix_mask {
            return vec![value as u8];
        }

        let mut result = vec![prefix_mask as u8];
        let mut remaining = value - prefix_mask;

        while remaining >= 128 {
            result.push(((remaining % 128) as u8) | 0x80);
            remaining /= 128;
        }
        result.push(remaining as u8);

        result
    }

    /// Encode string (no Huffman for simplicity)
    fn encode_string(&self, s: &str) -> Vec<u8> {
        let mut result = self.encode_integer(s.len() as u64, 7);
        result.extend_from_slice(s.as_bytes());
        result
    }

    /// Encode headers to HPACK format (simplified)
    pub fn encode(&mut self, headers: &[(String, String)]) -> Vec<u8> {
        let mut result = Vec::new();

        for (name, value) in headers {
            // Find in static table first
            let mut found_index = None;
            for (i, (n, v)) in STATIC_TABLE.iter().enumerate() {
                if *n == name && (*v == value || v.is_empty()) {
                    found_index = Some(i + 1);
                    if *v == value {
                        break; // Exact match
                    }
                }
            }

            if let Some(index) = found_index {
                if STATIC_TABLE[index - 1].1 == value {
                    // Indexed representation
                    let encoded = self.encode_integer(index as u64, 7);
                    result.push(encoded[0] | 0x80);
                    result.extend_from_slice(&encoded[1..]);
                } else {
                    // Literal with indexing, indexed name
                    let mut encoded = self.encode_integer(index as u64, 6);
                    encoded[0] |= 0x40;
                    result.extend(encoded);
                    result.extend(self.encode_string(value));
                    self.add_entry(name.clone(), value.clone());
                }
            } else {
                // Literal with indexing, new name
                result.push(0x40);
                result.extend(self.encode_string(name));
                result.extend(self.encode_string(value));
                self.add_entry(name.clone(), value.clone());
            }
        }

        result
    }
}

impl Default for Hpack {
    fn default() -> Self {
        Self::new(DEFAULT_HEADER_TABLE_SIZE as usize)
    }
}

// ============================================================================
// HTTP/2 Connection
// ============================================================================

/// HTTP/2 connection configuration
#[derive(Debug, Clone)]
pub struct Http2Config {
    /// Local settings
    pub settings: Settings,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Idle timeout
    pub idle_timeout: Duration,
    /// Enable server push
    pub enable_push: bool,
    /// Validate peer settings
    pub validate_settings: bool,
}

impl Default for Http2Config {
    fn default() -> Self {
        Self {
            settings: Settings::default(),
            connection_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
            enable_push: true,
            validate_settings: true,
        }
    }
}

impl Http2Config {
    /// Create Tor-optimized config
    pub fn tor_optimized() -> Self {
        Self {
            settings: Settings::tor_optimized(),
            connection_timeout: Duration::from_secs(60), // Longer for Tor
            idle_timeout: Duration::from_secs(600),
            enable_push: false,
            validate_settings: true,
        }
    }
}

/// HTTP/2 connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Waiting for preface
    WaitingPreface,
    /// Active connection
    Active,
    /// Graceful shutdown initiated
    GoingAway,
    /// Connection closed
    Closed,
}

/// HTTP/2 connection
pub struct Http2Connection {
    /// Configuration
    config: Http2Config,
    /// Connection state
    state: ConnectionState,
    /// Local settings
    local_settings: Settings,
    /// Remote settings
    remote_settings: Settings,
    /// HPACK encoder
    encoder: Hpack,
    /// HPACK decoder
    decoder: Hpack,
    /// Active streams
    streams: HashMap<u32, Stream>,
    /// Next stream ID (client: odd, server: even)
    next_stream_id: AtomicU32,
    /// Connection-level send window
    send_window: i32,
    /// Connection-level receive window
    recv_window: i32,
    /// Last stream ID
    last_stream_id: u32,
    /// Is client
    is_client: bool,
    /// Pending frames to send
    outgoing: VecDeque<Frame>,
    /// Statistics
    stats: Arc<RwLock<Http2Stats>>,
}

impl Http2Connection {
    /// Create a new client connection
    pub fn client(config: Http2Config) -> Self {
        Self::new(config, true)
    }

    /// Create a new server connection
    pub fn server(config: Http2Config) -> Self {
        Self::new(config, false)
    }

    fn new(config: Http2Config, is_client: bool) -> Self {
        let initial_window = config.settings.initial_window_size as i32;
        let header_table_size = config.settings.header_table_size as usize;

        Self {
            local_settings: config.settings.clone(),
            remote_settings: Settings::default(),
            config,
            state: ConnectionState::WaitingPreface,
            encoder: Hpack::new(header_table_size),
            decoder: Hpack::new(header_table_size),
            streams: HashMap::new(),
            next_stream_id: AtomicU32::new(if is_client { 1 } else { 2 }),
            send_window: initial_window,
            recv_window: initial_window,
            last_stream_id: 0,
            is_client,
            outgoing: VecDeque::new(),
            stats: Arc::new(RwLock::new(Http2Stats::default())),
        }
    }

    /// Get connection state
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Check if connection is active
    pub fn is_active(&self) -> bool {
        self.state == ConnectionState::Active
    }

    /// Get statistics
    pub fn stats(&self) -> Http2Stats {
        self.stats.read().clone()
    }

    /// Initialize connection (send preface + settings)
    pub fn initialize(&mut self) -> Vec<Frame> {
        self.state = ConnectionState::Active;
        vec![Frame::settings(&self.local_settings)]
    }

    /// Get connection preface for clients
    pub fn get_preface(&self) -> &'static [u8] {
        CONNECTION_PREFACE
    }

    /// Create a new stream
    pub fn create_stream(&mut self) -> Result<u32, Http2Error> {
        if self.state != ConnectionState::Active {
            return Err(Http2Error::Closed);
        }

        let active_streams = self.streams.values().filter(|s| !s.is_closed()).count();
        if active_streams >= self.remote_settings.max_concurrent_streams as usize {
            return Err(Http2Error::Stream(0, ErrorCode::RefusedStream));
        }

        let stream_id = self.next_stream_id.fetch_add(2, Ordering::SeqCst);
        let stream = Stream::new(stream_id, self.remote_settings.initial_window_size);
        self.streams.insert(stream_id, stream);

        self.stats.write().streams_created += 1;
        Ok(stream_id)
    }

    /// Send headers on a stream
    pub fn send_headers(
        &mut self,
        stream_id: u32,
        headers: Vec<(String, String)>,
        end_stream: bool,
    ) -> Result<Vec<Frame>, Http2Error> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(Http2Error::Stream(stream_id, ErrorCode::StreamClosed))?;

        // Transition stream state
        if stream.state == StreamState::Idle {
            stream.state = StreamState::Open;
        }
        if end_stream {
            stream.send_end_stream();
        }

        // Encode headers
        let encoded = self.encoder.encode(&headers);

        // Split into frames if needed
        let max_size = self.remote_settings.max_frame_size as usize;
        let mut frames = Vec::new();

        if encoded.len() <= max_size {
            frames.push(Frame::headers(stream_id, encoded, end_stream, true));
        } else {
            // First HEADERS frame
            frames.push(Frame::headers(
                stream_id,
                encoded[..max_size].to_vec(),
                end_stream,
                false,
            ));

            // CONTINUATION frames
            let mut pos = max_size;
            while pos < encoded.len() {
                let end = (pos + max_size).min(encoded.len());
                let is_last = end == encoded.len();
                let mut flags = FrameFlags::NONE;
                if is_last {
                    flags.set(FrameFlags::END_HEADERS);
                }
                frames.push(Frame::new(
                    FrameType::Continuation,
                    flags,
                    stream_id,
                    encoded[pos..end].to_vec(),
                ));
                pos = end;
            }
        }

        self.stats.write().frames_sent += frames.len() as u64;
        Ok(frames)
    }

    /// Send data on a stream
    pub fn send_data(
        &mut self,
        stream_id: u32,
        data: Vec<u8>,
        end_stream: bool,
    ) -> Result<Vec<Frame>, Http2Error> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(Http2Error::Stream(stream_id, ErrorCode::StreamClosed))?;

        if !stream.can_send() {
            return Err(Http2Error::Stream(stream_id, ErrorCode::StreamClosed));
        }

        // Check flow control
        let available = stream.send_window.min(self.send_window) as usize;
        if available == 0 {
            return Err(Http2Error::FlowControl);
        }

        // Split into frames respecting flow control
        let max_size = self.remote_settings.max_frame_size as usize;
        let mut frames = Vec::new();
        let mut pos = 0;

        while pos < data.len() {
            let chunk_size = (data.len() - pos).min(max_size).min(available);
            let is_last = pos + chunk_size >= data.len();

            frames.push(Frame::data(
                stream_id,
                data[pos..pos + chunk_size].to_vec(),
                end_stream && is_last,
            ));

            // Update windows
            stream.send_window -= chunk_size as i32;
            self.send_window -= chunk_size as i32;

            pos += chunk_size;
        }

        if end_stream {
            stream.send_end_stream();
        }

        self.stats.write().frames_sent += frames.len() as u64;
        self.stats.write().bytes_sent += data.len() as u64;
        Ok(frames)
    }

    /// Process received frame
    pub fn process_frame(&mut self, frame: Frame) -> Result<Option<StreamEvent>, Http2Error> {
        self.stats.write().frames_received += 1;

        match frame.header.frame_type {
            FrameType::Data => self.process_data(frame),
            FrameType::Headers => self.process_headers(frame),
            FrameType::Priority => self.process_priority(frame),
            FrameType::RstStream => self.process_rst_stream(frame),
            FrameType::Settings => self.process_settings(frame),
            FrameType::PushPromise => self.process_push_promise(frame),
            FrameType::Ping => self.process_ping(frame),
            FrameType::GoAway => self.process_goaway(frame),
            FrameType::WindowUpdate => self.process_window_update(frame),
            FrameType::Continuation => self.process_continuation(frame),
        }
    }

    fn process_data(&mut self, frame: Frame) -> Result<Option<StreamEvent>, Http2Error> {
        let stream_id = frame.header.stream_id;
        if stream_id == 0 {
            return Err(Http2Error::Protocol("DATA on stream 0".into()));
        }

        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(Http2Error::Stream(stream_id, ErrorCode::StreamClosed))?;

        if !stream.can_recv() {
            return Err(Http2Error::Stream(stream_id, ErrorCode::StreamClosed));
        }

        // Update flow control
        let data_len = frame.payload.len() as i32;
        stream.recv_window -= data_len;
        self.recv_window -= data_len;

        // Store data
        stream.data.extend(frame.payload);

        let end_stream = frame.header.flags.contains(FrameFlags::END_STREAM);
        if end_stream {
            stream.recv_end_stream();
        }

        self.stats.write().bytes_received += data_len as u64;

        Ok(Some(StreamEvent::Data {
            stream_id,
            end_stream,
        }))
    }

    fn process_headers(&mut self, frame: Frame) -> Result<Option<StreamEvent>, Http2Error> {
        let stream_id = frame.header.stream_id;
        if stream_id == 0 {
            return Err(Http2Error::Protocol("HEADERS on stream 0".into()));
        }

        // Get or create stream
        let stream = self.streams.entry(stream_id).or_insert_with(|| {
            self.stats.write().streams_created += 1;
            Stream::new(stream_id, self.local_settings.initial_window_size)
        });

        // Open the stream
        if stream.state == StreamState::Idle {
            stream.state = StreamState::Open;
        }

        // Decode headers
        let headers = self.decoder.decode(&frame.payload)?;
        stream.headers = headers;

        let end_stream = frame.header.flags.contains(FrameFlags::END_STREAM);
        if end_stream {
            stream.recv_end_stream();
        }

        Ok(Some(StreamEvent::Headers {
            stream_id,
            end_stream,
        }))
    }

    fn process_priority(&mut self, frame: Frame) -> Result<Option<StreamEvent>, Http2Error> {
        let stream_id = frame.header.stream_id;
        if frame.payload.len() != 5 {
            return Err(Http2Error::FrameSize);
        }

        let dependency = u32::from_be_bytes([
            frame.payload[0] & 0x7F,
            frame.payload[1],
            frame.payload[2],
            frame.payload[3],
        ]);
        let exclusive = frame.payload[0] & 0x80 != 0;
        let weight = frame.payload[4] + 1;

        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.dependency = dependency;
            stream.exclusive = exclusive;
            stream.weight = weight;
        }

        Ok(None)
    }

    fn process_rst_stream(&mut self, frame: Frame) -> Result<Option<StreamEvent>, Http2Error> {
        let stream_id = frame.header.stream_id;
        if stream_id == 0 {
            return Err(Http2Error::Protocol("RST_STREAM on stream 0".into()));
        }

        if frame.payload.len() != 4 {
            return Err(Http2Error::FrameSize);
        }

        let error_code = ErrorCode::from_u32(u32::from_be_bytes([
            frame.payload[0],
            frame.payload[1],
            frame.payload[2],
            frame.payload[3],
        ]));

        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.close();
        }

        Ok(Some(StreamEvent::Reset {
            stream_id,
            error_code,
        }))
    }

    fn process_settings(&mut self, frame: Frame) -> Result<Option<StreamEvent>, Http2Error> {
        if frame.header.stream_id != 0 {
            return Err(Http2Error::Protocol("SETTINGS on non-zero stream".into()));
        }

        if frame.header.flags.contains(FrameFlags::ACK) {
            // Settings acknowledged
            return Ok(Some(StreamEvent::SettingsAck));
        }

        // Parse and apply settings
        self.remote_settings = Settings::decode(&frame.payload)?;

        // Update HPACK encoder table size
        self.encoder = Hpack::new(self.remote_settings.header_table_size as usize);

        // Queue settings ACK
        self.outgoing.push_back(Frame::settings_ack());

        Ok(Some(StreamEvent::Settings))
    }

    fn process_push_promise(&mut self, frame: Frame) -> Result<Option<StreamEvent>, Http2Error> {
        if !self.config.enable_push {
            // Treat as connection error
            return Err(Http2Error::Protocol("Server push disabled".into()));
        }

        let stream_id = frame.header.stream_id;
        if stream_id == 0 {
            return Err(Http2Error::Protocol("PUSH_PROMISE on stream 0".into()));
        }

        if frame.payload.len() < 4 {
            return Err(Http2Error::FrameSize);
        }

        let promised_id = u32::from_be_bytes([
            frame.payload[0] & 0x7F,
            frame.payload[1],
            frame.payload[2],
            frame.payload[3],
        ]);

        let headers = self.decoder.decode(&frame.payload[4..])?;

        // Create reserved stream
        let mut stream = Stream::new(promised_id, self.local_settings.initial_window_size);
        stream.state = StreamState::ReservedRemote;
        stream.headers = headers;
        self.streams.insert(promised_id, stream);

        Ok(Some(StreamEvent::PushPromise {
            stream_id,
            promised_id,
        }))
    }

    fn process_ping(&mut self, frame: Frame) -> Result<Option<StreamEvent>, Http2Error> {
        if frame.header.stream_id != 0 {
            return Err(Http2Error::Protocol("PING on non-zero stream".into()));
        }

        if frame.payload.len() != 8 {
            return Err(Http2Error::FrameSize);
        }

        if frame.header.flags.contains(FrameFlags::ACK) {
            // Ping response received
            return Ok(Some(StreamEvent::PingAck));
        }

        // Send PING ACK
        let mut data = [0u8; 8];
        data.copy_from_slice(&frame.payload);
        self.outgoing.push_back(Frame::ping_ack(data));

        Ok(Some(StreamEvent::Ping))
    }

    fn process_goaway(&mut self, frame: Frame) -> Result<Option<StreamEvent>, Http2Error> {
        if frame.header.stream_id != 0 {
            return Err(Http2Error::Protocol("GOAWAY on non-zero stream".into()));
        }

        if frame.payload.len() < 8 {
            return Err(Http2Error::FrameSize);
        }

        let last_stream_id = u32::from_be_bytes([
            frame.payload[0] & 0x7F,
            frame.payload[1],
            frame.payload[2],
            frame.payload[3],
        ]);
        let error_code = ErrorCode::from_u32(u32::from_be_bytes([
            frame.payload[4],
            frame.payload[5],
            frame.payload[6],
            frame.payload[7],
        ]));

        self.last_stream_id = last_stream_id;
        self.state = ConnectionState::GoingAway;

        Ok(Some(StreamEvent::GoAway {
            last_stream_id,
            error_code,
        }))
    }

    fn process_window_update(&mut self, frame: Frame) -> Result<Option<StreamEvent>, Http2Error> {
        if frame.payload.len() != 4 {
            return Err(Http2Error::FrameSize);
        }

        let increment = u32::from_be_bytes([
            frame.payload[0] & 0x7F,
            frame.payload[1],
            frame.payload[2],
            frame.payload[3],
        ]);

        if increment == 0 {
            return Err(Http2Error::Protocol("Zero window update".into()));
        }

        let stream_id = frame.header.stream_id;
        if stream_id == 0 {
            // Connection-level
            self.send_window += increment as i32;
        } else {
            // Stream-level
            if let Some(stream) = self.streams.get_mut(&stream_id) {
                stream.send_window += increment as i32;
            }
        }

        Ok(Some(StreamEvent::WindowUpdate {
            stream_id,
            increment,
        }))
    }

    fn process_continuation(&mut self, _frame: Frame) -> Result<Option<StreamEvent>, Http2Error> {
        // In a real implementation, we'd reassemble header blocks
        // For now, just acknowledge
        Ok(None)
    }

    /// Get pending outgoing frames
    pub fn take_outgoing(&mut self) -> Vec<Frame> {
        self.outgoing.drain(..).collect()
    }

    /// Get stream by ID
    pub fn get_stream(&self, stream_id: u32) -> Option<&Stream> {
        self.streams.get(&stream_id)
    }

    /// Get stream data
    pub fn get_stream_data(&mut self, stream_id: u32) -> Option<Vec<u8>> {
        self.streams
            .get_mut(&stream_id)
            .map(|s| std::mem::take(&mut s.data))
    }

    /// Get stream headers
    pub fn get_stream_headers(&self, stream_id: u32) -> Option<&[(String, String)]> {
        self.streams.get(&stream_id).map(|s| s.headers.as_slice())
    }

    /// Initiate graceful shutdown
    pub fn goaway(&mut self, error_code: ErrorCode) -> Frame {
        self.state = ConnectionState::GoingAway;
        Frame::goaway(self.last_stream_id, error_code, vec![])
    }

    /// Send window update
    pub fn send_window_update(&mut self, stream_id: u32, increment: u32) -> Frame {
        if stream_id == 0 {
            self.recv_window += increment as i32;
        } else if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.recv_window += increment as i32;
        }
        Frame::window_update(stream_id, increment)
    }
}

impl std::fmt::Debug for Http2Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http2Connection")
            .field("state", &self.state)
            .field("is_client", &self.is_client)
            .field("streams", &self.streams.len())
            .field("send_window", &self.send_window)
            .field("recv_window", &self.recv_window)
            .finish()
    }
}

// ============================================================================
// Events
// ============================================================================

/// Stream events
#[derive(Debug, Clone)]
pub enum StreamEvent {
    /// Headers received
    Headers {
        /// Stream ID
        stream_id: u32,
        /// End of stream
        end_stream: bool,
    },
    /// Data received
    Data {
        /// Stream ID
        stream_id: u32,
        /// End of stream
        end_stream: bool,
    },
    /// Stream reset
    Reset {
        /// Stream ID
        stream_id: u32,
        /// Error code
        error_code: ErrorCode,
    },
    /// Push promise received
    PushPromise {
        /// Originating stream
        stream_id: u32,
        /// Promised stream ID
        promised_id: u32,
    },
    /// GOAWAY received
    GoAway {
        /// Last stream ID
        last_stream_id: u32,
        /// Error code
        error_code: ErrorCode,
    },
    /// Window update
    WindowUpdate {
        /// Stream ID (0 for connection)
        stream_id: u32,
        /// Increment
        increment: u32,
    },
    /// Settings received
    Settings,
    /// Settings acknowledged
    SettingsAck,
    /// Ping received
    Ping,
    /// Ping acknowledged
    PingAck,
}

// ============================================================================
// Statistics
// ============================================================================

/// HTTP/2 connection statistics
#[derive(Debug, Clone, Default)]
pub struct Http2Stats {
    /// Frames sent
    pub frames_sent: u64,
    /// Frames received
    pub frames_received: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Streams created
    pub streams_created: u64,
    /// Streams completed
    pub streams_completed: u64,
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
        let frame = Frame::data(1, vec![1, 2, 3, 4], false);
        let encoded = frame.encode();

        let (decoded, len) = Frame::decode(&encoded).unwrap();
        assert_eq!(len, encoded.len());
        assert_eq!(decoded.header.stream_id, 1);
        assert_eq!(decoded.payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_frame_header() {
        let header = FrameHeader::new(FrameType::Headers, FrameFlags::END_STREAM, 3);
        let encoded = header.encode();
        let decoded = FrameHeader::decode(&encoded).unwrap();

        assert_eq!(decoded.frame_type, FrameType::Headers);
        assert!(decoded.flags.contains(FrameFlags::END_STREAM));
        assert_eq!(decoded.stream_id, 3);
    }

    #[test]
    fn test_settings_encode_decode() {
        let settings = Settings::tor_optimized();
        let encoded = settings.encode();
        let decoded = Settings::decode(&encoded).unwrap();

        assert_eq!(decoded.max_concurrent_streams, 50);
        assert!(!decoded.enable_push);
    }

    #[test]
    fn test_hpack_encode_decode() {
        let mut encoder = Hpack::new(4096);
        let mut decoder = Hpack::new(4096);

        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":path".to_string(), "/api/test".to_string()),
            ("custom-header".to_string(), "custom-value".to_string()),
        ];

        let encoded = encoder.encode(&headers);
        let decoded = decoder.decode(&encoded).unwrap();

        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0].0, ":method");
        assert_eq!(decoded[0].1, "GET");
    }

    #[test]
    fn test_connection_create_stream() {
        let mut conn = Http2Connection::client(Http2Config::default());
        let _frames = conn.initialize();

        let stream_id = conn.create_stream().unwrap();
        assert_eq!(stream_id, 1); // Client streams are odd

        let stream_id2 = conn.create_stream().unwrap();
        assert_eq!(stream_id2, 3);
    }

    #[test]
    fn test_stream_states() {
        let mut stream = Stream::new(1, 65535);
        assert_eq!(stream.state, StreamState::Idle);

        stream.state = StreamState::Open;
        assert!(stream.can_send());
        assert!(stream.can_recv());

        stream.send_end_stream();
        assert_eq!(stream.state, StreamState::HalfClosedLocal);
        assert!(!stream.can_send());
        assert!(stream.can_recv());
    }

    #[test]
    fn test_goaway_frame() {
        let frame = Frame::goaway(5, ErrorCode::NoError, b"test".to_vec());
        assert_eq!(frame.header.frame_type, FrameType::GoAway);
        assert_eq!(frame.header.stream_id, 0);
    }

    #[test]
    fn test_window_update() {
        let mut conn = Http2Connection::client(Http2Config::default());
        let _frames = conn.initialize();

        let initial_window = conn.send_window;

        // Process incoming window update
        let frame = Frame::window_update(0, 1000);
        conn.process_frame(frame).unwrap();

        assert_eq!(conn.send_window, initial_window + 1000);
    }

    #[test]
    fn test_ping_pong() {
        let mut conn = Http2Connection::client(Http2Config::default());
        let _frames = conn.initialize();

        let ping = Frame::ping([1, 2, 3, 4, 5, 6, 7, 8]);
        let event = conn.process_frame(ping).unwrap();

        assert!(matches!(event, Some(StreamEvent::Ping)));

        // Should have queued a PING ACK
        let outgoing = conn.take_outgoing();
        assert_eq!(outgoing.len(), 1);
        assert_eq!(outgoing[0].header.frame_type, FrameType::Ping);
        assert!(outgoing[0].header.flags.contains(FrameFlags::ACK));
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(ErrorCode::from_u32(0), ErrorCode::NoError);
        assert_eq!(ErrorCode::from_u32(1), ErrorCode::ProtocolError);
        assert_eq!(ErrorCode::from_u32(0xb), ErrorCode::EnhanceYourCalm);
    }
}
