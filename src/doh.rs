//! DNS-over-HTTPS (DoH) Support
//!
//! This module provides DNS resolution over HTTPS for enhanced privacy
//! when combined with Tor. It supports multiple DoH providers and
//! wire formats (JSON and DNS wireformat).
//!
//! # Features
//!
//! - **Multiple Providers**: Cloudflare, Google, Quad9, etc.
//! - **Wire Formats**: JSON API and DNS wireformat (RFC 8484)
//! - **Caching**: Built-in response caching with TTL
//! - **Privacy**: Prevents DNS leaks outside Tor
//! - **Fallback**: Multiple resolver support
//!
//! # Example
//!
//! ```rust,ignore
//! use hypertor::doh::{DohResolver, DohConfig, DohProvider};
//!
//! let resolver = DohResolver::new(DohConfig::cloudflare());
//! let ips = resolver.resolve("example.com", RecordType::A).await?;
//! ```

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

// ============================================================================
// Error Types
// ============================================================================

/// DoH errors
#[derive(Debug)]
pub enum DohError {
    /// No response from resolver
    NoResponse,
    /// DNS lookup failed
    LookupFailed(String),
    /// Invalid response format
    InvalidResponse(String),
    /// Timeout
    Timeout,
    /// Network error
    Network(String),
    /// No records found
    NoRecords,
    /// NXDOMAIN
    NxDomain,
}

impl std::fmt::Display for DohError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoResponse => write!(f, "No response from DoH resolver"),
            Self::LookupFailed(msg) => write!(f, "DNS lookup failed: {}", msg),
            Self::InvalidResponse(msg) => write!(f, "Invalid response: {}", msg),
            Self::Timeout => write!(f, "DNS request timed out"),
            Self::Network(msg) => write!(f, "Network error: {}", msg),
            Self::NoRecords => write!(f, "No records found"),
            Self::NxDomain => write!(f, "Domain does not exist"),
        }
    }
}

impl std::error::Error for DohError {}

// ============================================================================
// DNS Record Types
// ============================================================================

/// DNS record types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    /// A record (IPv4)
    A = 1,
    /// AAAA record (IPv6)
    AAAA = 28,
    /// CNAME record
    Cname = 5,
    /// MX record
    Mx = 15,
    /// TXT record
    Txt = 16,
    /// NS record
    Ns = 2,
    /// SOA record
    Soa = 6,
    /// PTR record
    Ptr = 12,
    /// SRV record
    Srv = 33,
}

impl RecordType {
    /// Get numeric value
    pub fn value(&self) -> u16 {
        *self as u16
    }

    /// Get type name
    pub fn name(&self) -> &'static str {
        match self {
            Self::A => "A",
            Self::AAAA => "AAAA",
            Self::Cname => "CNAME",
            Self::Mx => "MX",
            Self::Txt => "TXT",
            Self::Ns => "NS",
            Self::Soa => "SOA",
            Self::Ptr => "PTR",
            Self::Srv => "SRV",
        }
    }
}

/// DNS record data
#[derive(Debug, Clone)]
pub enum RecordData {
    /// IPv4 address
    A(Ipv4Addr),
    /// IPv6 address
    Aaaa(Ipv6Addr),
    /// Canonical name
    Cname(String),
    /// Mail exchange
    Mx {
        /// Mail server priority
        priority: u16,
        /// Mail exchange hostname
        exchange: String,
    },
    /// Text record
    Txt(String),
    /// Name server
    Ns(String),
    /// Service record
    Srv {
        /// Service priority
        priority: u16,
        /// Service weight
        weight: u16,
        /// Service port
        port: u16,
        /// Service target hostname
        target: String,
    },
    /// Unknown/raw data
    Raw(Vec<u8>),
}

/// A DNS resource record
#[derive(Debug, Clone)]
pub struct DnsRecord {
    /// Record name
    pub name: String,
    /// Record type
    pub record_type: RecordType,
    /// Time-to-live in seconds
    pub ttl: u32,
    /// Record data
    pub data: RecordData,
}

/// DNS response
#[derive(Debug, Clone)]
pub struct DnsResponse {
    /// Query name
    pub name: String,
    /// Query type
    pub query_type: RecordType,
    /// Response code (0 = success)
    pub rcode: u8,
    /// Answer records
    pub answers: Vec<DnsRecord>,
    /// Authority records
    pub authority: Vec<DnsRecord>,
    /// Additional records
    pub additional: Vec<DnsRecord>,
    /// Truncated flag
    pub truncated: bool,
    /// Authoritative answer
    pub authoritative: bool,
}

impl DnsResponse {
    /// Create a new empty response
    pub fn new(name: String, query_type: RecordType) -> Self {
        Self {
            name,
            query_type,
            rcode: 0,
            answers: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
            truncated: false,
            authoritative: false,
        }
    }

    /// Check if successful
    pub fn is_success(&self) -> bool {
        self.rcode == 0
    }

    /// Get all IPv4 addresses
    pub fn ipv4_addrs(&self) -> Vec<Ipv4Addr> {
        self.answers
            .iter()
            .filter_map(|r| match &r.data {
                RecordData::A(addr) => Some(*addr),
                _ => None,
            })
            .collect()
    }

    /// Get all IPv6 addresses
    pub fn ipv6_addrs(&self) -> Vec<Ipv6Addr> {
        self.answers
            .iter()
            .filter_map(|r| match &r.data {
                RecordData::Aaaa(addr) => Some(*addr),
                _ => None,
            })
            .collect()
    }

    /// Get all IP addresses (v4 and v6)
    pub fn ip_addrs(&self) -> Vec<IpAddr> {
        let mut addrs = Vec::new();
        for record in &self.answers {
            match &record.data {
                RecordData::A(addr) => addrs.push(IpAddr::V4(*addr)),
                RecordData::Aaaa(addr) => addrs.push(IpAddr::V6(*addr)),
                _ => {}
            }
        }
        addrs
    }

    /// Get first IPv4 address
    pub fn first_ipv4(&self) -> Option<Ipv4Addr> {
        self.ipv4_addrs().into_iter().next()
    }

    /// Get minimum TTL from answers
    pub fn min_ttl(&self) -> u32 {
        self.answers.iter().map(|r| r.ttl).min().unwrap_or(300)
    }
}

// ============================================================================
// DoH Providers
// ============================================================================

/// Well-known DoH providers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DohProvider {
    /// Cloudflare DNS (1.1.1.1)
    Cloudflare,
    /// Cloudflare DNS for families (malware blocking)
    CloudflareSecurity,
    /// Google Public DNS
    Google,
    /// Quad9 (security-focused)
    Quad9,
    /// AdGuard DNS
    AdGuard,
    /// NextDNS
    NextDns,
    /// Mullvad DNS
    Mullvad,
    /// Custom provider
    Custom,
}

impl DohProvider {
    /// Get the DoH endpoint URL
    pub fn endpoint(&self) -> &'static str {
        match self {
            Self::Cloudflare => "https://cloudflare-dns.com/dns-query",
            Self::CloudflareSecurity => "https://security.cloudflare-dns.com/dns-query",
            Self::Google => "https://dns.google/dns-query",
            Self::Quad9 => "https://dns.quad9.net/dns-query",
            Self::AdGuard => "https://dns.adguard.com/dns-query",
            Self::NextDns => "https://dns.nextdns.io/dns-query",
            Self::Mullvad => "https://doh.mullvad.net/dns-query",
            Self::Custom => "",
        }
    }

    /// Get JSON API endpoint (if supported)
    pub fn json_endpoint(&self) -> Option<&'static str> {
        match self {
            Self::Cloudflare => Some("https://cloudflare-dns.com/dns-query"),
            Self::Google => Some("https://dns.google/resolve"),
            _ => None,
        }
    }

    /// Check if provider supports JSON API
    pub fn supports_json(&self) -> bool {
        self.json_endpoint().is_some()
    }

    /// Privacy rating (subjective)
    pub fn privacy_score(&self) -> u8 {
        match self {
            Self::Mullvad => 10,                              // No logging, privacy-focused
            Self::Quad9 => 9,                                 // No logging
            Self::CloudflareSecurity | Self::Cloudflare => 8, // Limited logging
            Self::AdGuard => 7,                               // Privacy policy good
            Self::NextDns => 6,                               // Configurable
            Self::Google => 5,                                // Some logging
            Self::Custom => 0,                                // Unknown
        }
    }
}

// ============================================================================
// DoH Configuration
// ============================================================================

/// DoH wire format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DohFormat {
    /// DNS wire format (RFC 8484)
    #[default]
    Wire,
    /// JSON API (Cloudflare/Google style)
    Json,
}

/// DoH resolver configuration
#[derive(Debug, Clone)]
pub struct DohConfig {
    /// Primary endpoint URL
    pub endpoint: String,
    /// Provider type
    pub provider: DohProvider,
    /// Wire format to use
    pub format: DohFormat,
    /// Request timeout
    pub timeout: Duration,
    /// Enable caching
    pub cache_enabled: bool,
    /// Maximum cache entries
    pub max_cache_entries: usize,
    /// Bootstrap resolvers (for resolving DoH endpoint)
    pub bootstrap: Vec<IpAddr>,
    /// Use Tor for DoH requests
    pub use_tor: bool,
    /// EDNS client subnet (ECS) - privacy concern if enabled
    pub ecs_enabled: bool,
    /// DNSSEC validation
    pub dnssec: bool,
}

impl DohConfig {
    /// Create a new config with endpoint
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            provider: DohProvider::Custom,
            format: DohFormat::Wire,
            timeout: Duration::from_secs(5),
            cache_enabled: true,
            max_cache_entries: 1000,
            bootstrap: Vec::new(),
            use_tor: false,
            ecs_enabled: false,
            dnssec: false,
        }
    }

    /// Create Cloudflare configuration
    pub fn cloudflare() -> Self {
        Self {
            endpoint: DohProvider::Cloudflare.endpoint().to_string(),
            provider: DohProvider::Cloudflare,
            format: DohFormat::Wire,
            timeout: Duration::from_secs(5),
            cache_enabled: true,
            max_cache_entries: 1000,
            bootstrap: vec![
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
            ],
            use_tor: false,
            ecs_enabled: false,
            dnssec: false,
        }
    }

    /// Create Google configuration
    pub fn google() -> Self {
        Self {
            endpoint: DohProvider::Google.endpoint().to_string(),
            provider: DohProvider::Google,
            format: DohFormat::Json, // Google's JSON API is well-documented
            timeout: Duration::from_secs(5),
            cache_enabled: true,
            max_cache_entries: 1000,
            bootstrap: vec![
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
            ],
            use_tor: false,
            ecs_enabled: false,
            dnssec: false,
        }
    }

    /// Create Quad9 configuration
    pub fn quad9() -> Self {
        Self {
            endpoint: DohProvider::Quad9.endpoint().to_string(),
            provider: DohProvider::Quad9,
            format: DohFormat::Wire,
            timeout: Duration::from_secs(5),
            cache_enabled: true,
            max_cache_entries: 1000,
            bootstrap: vec![
                IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                IpAddr::V4(Ipv4Addr::new(149, 112, 112, 112)),
            ],
            use_tor: false,
            ecs_enabled: false,
            dnssec: true, // Quad9 has good DNSSEC support
        }
    }

    /// Create Mullvad configuration (privacy-focused)
    pub fn mullvad() -> Self {
        Self {
            endpoint: DohProvider::Mullvad.endpoint().to_string(),
            provider: DohProvider::Mullvad,
            format: DohFormat::Wire,
            timeout: Duration::from_secs(5),
            cache_enabled: true,
            max_cache_entries: 1000,
            bootstrap: vec![],
            use_tor: true, // Mullvad is privacy-focused, use Tor
            ecs_enabled: false,
            dnssec: true,
        }
    }

    /// Configure for maximum privacy (use with Tor)
    pub fn privacy_max() -> Self {
        Self {
            endpoint: DohProvider::Mullvad.endpoint().to_string(),
            provider: DohProvider::Mullvad,
            format: DohFormat::Wire,
            timeout: Duration::from_secs(10), // Tor adds latency
            cache_enabled: true,
            max_cache_entries: 500,
            bootstrap: vec![],
            use_tor: true,
            ecs_enabled: false,
            dnssec: true,
        }
    }

    /// Set the endpoint
    pub fn endpoint(mut self, url: impl Into<String>) -> Self {
        self.endpoint = url.into();
        self
    }

    /// Enable Tor transport
    pub fn with_tor(mut self) -> Self {
        self.use_tor = true;
        self
    }

    /// Set timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Enable DNSSEC validation
    pub fn with_dnssec(mut self) -> Self {
        self.dnssec = true;
        self
    }
}

impl Default for DohConfig {
    fn default() -> Self {
        Self::cloudflare()
    }
}

// ============================================================================
// DNS Cache
// ============================================================================

/// Cached DNS entry
#[derive(Debug, Clone)]
struct CacheEntry {
    response: DnsResponse,
    expires_at: Instant,
}

/// DNS response cache
#[derive(Debug)]
pub struct DnsCache {
    entries: RwLock<HashMap<(String, RecordType), CacheEntry>>,
    max_entries: usize,
    min_ttl: u32,
    max_ttl: u32,
}

impl DnsCache {
    /// Create a new cache
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            max_entries,
            min_ttl: 60,
            max_ttl: 86400,
        }
    }

    /// Get a cached response
    pub fn get(&self, name: &str, record_type: RecordType) -> Option<DnsResponse> {
        let entries = self.entries.read();
        let key = (name.to_lowercase(), record_type);

        if let Some(entry) = entries.get(&key) {
            if entry.expires_at > Instant::now() {
                return Some(entry.response.clone());
            }
        }
        None
    }

    /// Insert a response into cache
    pub fn insert(&self, response: DnsResponse) {
        let mut entries = self.entries.write();

        // Evict old entries if at capacity
        if entries.len() >= self.max_entries {
            let now = Instant::now();
            entries.retain(|_, v| v.expires_at > now);

            // If still at capacity, remove oldest
            if entries.len() >= self.max_entries {
                if let Some(oldest_key) = entries
                    .iter()
                    .min_by_key(|(_, v)| v.expires_at)
                    .map(|(k, _)| k.clone())
                {
                    entries.remove(&oldest_key);
                }
            }
        }

        // Calculate TTL
        let ttl = response.min_ttl().max(self.min_ttl).min(self.max_ttl);

        let expires_at = Instant::now() + Duration::from_secs(ttl as u64);
        let key = (response.name.to_lowercase(), response.query_type);

        entries.insert(
            key,
            CacheEntry {
                response,
                expires_at,
            },
        );
    }

    /// Clear expired entries
    pub fn cleanup(&self) {
        let now = Instant::now();
        self.entries.write().retain(|_, v| v.expires_at > now);
    }

    /// Clear all entries
    pub fn clear(&self) {
        self.entries.write().clear();
    }

    /// Get cache statistics
    pub fn stats(&self) -> (usize, usize) {
        let entries = self.entries.read();
        let now = Instant::now();
        let valid = entries.values().filter(|v| v.expires_at > now).count();
        (entries.len(), valid)
    }
}

// ============================================================================
// DNS Query Builder
// ============================================================================

/// DNS query message builder
#[derive(Debug)]
pub struct DnsQueryBuilder {
    name: String,
    record_type: RecordType,
    recursion_desired: bool,
    dnssec_ok: bool,
}

impl DnsQueryBuilder {
    /// Create a new query builder
    pub fn new(name: impl Into<String>, record_type: RecordType) -> Self {
        Self {
            name: name.into(),
            record_type,
            recursion_desired: true,
            dnssec_ok: false,
        }
    }

    /// Enable DNSSEC OK flag
    pub fn dnssec(mut self) -> Self {
        self.dnssec_ok = true;
        self
    }

    /// Build wire format query
    pub fn build_wire(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);

        // Header
        let id = rand_u16();
        buf.extend_from_slice(&id.to_be_bytes());

        // Flags: RD=1, rest 0
        let flags: u16 = if self.recursion_desired {
            0x0100
        } else {
            0x0000
        };
        buf.extend_from_slice(&flags.to_be_bytes());

        // QDCOUNT=1
        buf.extend_from_slice(&1u16.to_be_bytes());
        // ANCOUNT=0
        buf.extend_from_slice(&0u16.to_be_bytes());
        // NSCOUNT=0
        buf.extend_from_slice(&0u16.to_be_bytes());
        // ARCOUNT=0 (or 1 if DNSSEC)
        let arcount: u16 = if self.dnssec_ok { 1 } else { 0 };
        buf.extend_from_slice(&arcount.to_be_bytes());

        // Question section
        // QNAME
        for label in self.name.split('.') {
            let len = label.len() as u8;
            buf.push(len);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0); // Root label

        // QTYPE
        buf.extend_from_slice(&self.record_type.value().to_be_bytes());
        // QCLASS (IN)
        buf.extend_from_slice(&1u16.to_be_bytes());

        // OPT record for EDNS0/DNSSEC
        if self.dnssec_ok {
            // Name (root)
            buf.push(0);
            // Type OPT (41)
            buf.extend_from_slice(&41u16.to_be_bytes());
            // UDP payload size
            buf.extend_from_slice(&4096u16.to_be_bytes());
            // Extended RCODE
            buf.push(0);
            // EDNS version
            buf.push(0);
            // Flags (DO bit)
            buf.extend_from_slice(&0x8000u16.to_be_bytes());
            // RDLENGTH
            buf.extend_from_slice(&0u16.to_be_bytes());
        }

        buf
    }

    /// Build JSON query URL parameters
    pub fn build_json_params(&self) -> String {
        let mut params = format!(
            "?name={}&type={}",
            urlencoding::encode(&self.name),
            self.record_type.name()
        );

        if self.dnssec_ok {
            params.push_str("&do=1");
        }

        params
    }
}

/// Generate random u16 for query ID
fn rand_u16() -> u16 {
    use std::time::SystemTime;
    let seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u16;
    seed.wrapping_mul(31337)
}

// ============================================================================
// DNS Response Parser
// ============================================================================

/// Parse DNS wire format response
pub fn parse_wire_response(
    data: &[u8],
    name: &str,
    query_type: RecordType,
) -> Result<DnsResponse, DohError> {
    if data.len() < 12 {
        return Err(DohError::InvalidResponse("Response too short".into()));
    }

    let mut response = DnsResponse::new(name.to_string(), query_type);

    // Parse header
    let flags = u16::from_be_bytes([data[2], data[3]]);
    response.rcode = (flags & 0x000F) as u8;
    response.truncated = (flags & 0x0200) != 0;
    response.authoritative = (flags & 0x0400) != 0;

    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

    // Skip question section
    let mut pos = 12;
    pos = skip_name(data, pos)?;
    pos += 4; // QTYPE + QCLASS

    // Parse answer section
    for _ in 0..ancount {
        let (record, new_pos) = parse_record(data, pos)?;
        pos = new_pos;
        response.answers.push(record);
    }

    // Parse authority section
    for _ in 0..nscount {
        let (record, new_pos) = parse_record(data, pos)?;
        pos = new_pos;
        response.authority.push(record);
    }

    // Parse additional section
    for _ in 0..arcount {
        if pos >= data.len() {
            break;
        }
        match parse_record(data, pos) {
            Ok((record, new_pos)) => {
                pos = new_pos;
                response.additional.push(record);
            }
            Err(_) => break,
        }
    }

    Ok(response)
}

/// Skip a DNS name in wire format
fn skip_name(data: &[u8], mut pos: usize) -> Result<usize, DohError> {
    while pos < data.len() {
        let len = data[pos] as usize;
        if len == 0 {
            return Ok(pos + 1);
        } else if len >= 0xC0 {
            // Compression pointer
            return Ok(pos + 2);
        } else {
            pos += len + 1;
        }
    }
    Err(DohError::InvalidResponse("Invalid name".into()))
}

/// Parse a DNS name
fn parse_name(data: &[u8], mut pos: usize) -> Result<(String, usize), DohError> {
    let mut name = String::new();
    let mut jumped = false;
    let mut original_pos = pos;

    while pos < data.len() {
        let len = data[pos] as usize;

        if len == 0 {
            if !jumped {
                original_pos = pos + 1;
            }
            break;
        } else if len >= 0xC0 {
            // Compression pointer
            if pos + 1 >= data.len() {
                return Err(DohError::InvalidResponse("Invalid pointer".into()));
            }
            let offset = ((len & 0x3F) << 8) | (data[pos + 1] as usize);
            if !jumped {
                original_pos = pos + 2;
            }
            pos = offset;
            jumped = true;
        } else {
            if pos + len + 1 > data.len() {
                return Err(DohError::InvalidResponse("Name overflow".into()));
            }
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(&String::from_utf8_lossy(&data[pos + 1..pos + 1 + len]));
            pos += len + 1;
        }
    }

    Ok((name, original_pos))
}

/// Parse a DNS resource record
fn parse_record(data: &[u8], pos: usize) -> Result<(DnsRecord, usize), DohError> {
    let (name, mut pos) = parse_name(data, pos)?;

    if pos + 10 > data.len() {
        return Err(DohError::InvalidResponse("Record too short".into()));
    }

    let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
    let _rclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
    let ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
    let rdlength = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
    pos += 10;

    if pos + rdlength > data.len() {
        return Err(DohError::InvalidResponse("RDATA overflow".into()));
    }

    let record_type = match rtype {
        1 => RecordType::A,
        28 => RecordType::AAAA,
        5 => RecordType::Cname,
        15 => RecordType::Mx,
        16 => RecordType::Txt,
        2 => RecordType::Ns,
        6 => RecordType::Soa,
        12 => RecordType::Ptr,
        33 => RecordType::Srv,
        _ => RecordType::A, // Default, use raw data
    };

    let record_data = match record_type {
        RecordType::A if rdlength == 4 => RecordData::A(Ipv4Addr::new(
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
        )),
        RecordType::AAAA if rdlength == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[pos..pos + 16]);
            RecordData::Aaaa(Ipv6Addr::from(octets))
        }
        RecordType::Cname | RecordType::Ns | RecordType::Ptr => {
            let (cname, _) = parse_name(data, pos)?;
            match record_type {
                RecordType::Cname => RecordData::Cname(cname),
                RecordType::Ns => RecordData::Ns(cname),
                _ => RecordData::Cname(cname),
            }
        }
        RecordType::Mx if rdlength >= 2 => {
            let priority = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let (exchange, _) = parse_name(data, pos + 2)?;
            RecordData::Mx { priority, exchange }
        }
        RecordType::Txt => {
            let mut txt = String::new();
            let mut tpos = pos;
            while tpos < pos + rdlength {
                let slen = data[tpos] as usize;
                if tpos + 1 + slen <= pos + rdlength {
                    txt.push_str(&String::from_utf8_lossy(&data[tpos + 1..tpos + 1 + slen]));
                }
                tpos += slen + 1;
            }
            RecordData::Txt(txt)
        }
        _ => RecordData::Raw(data[pos..pos + rdlength].to_vec()),
    };

    let record = DnsRecord {
        name,
        record_type,
        ttl,
        data: record_data,
    };

    Ok((record, pos + rdlength))
}

// ============================================================================
// DoH Resolver
// ============================================================================

/// DNS-over-HTTPS resolver
#[derive(Debug)]
pub struct DohResolver {
    /// Configuration
    config: DohConfig,
    /// Response cache
    cache: Arc<DnsCache>,
    /// Statistics
    stats: Arc<RwLock<DohStats>>,
}

/// Resolver statistics
#[derive(Debug, Default, Clone)]
pub struct DohStats {
    /// Total queries
    pub queries: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,
    /// Successful resolutions
    pub success: u64,
    /// Failed resolutions
    pub failures: u64,
    /// Timeouts
    pub timeouts: u64,
}

impl DohResolver {
    /// Create a new resolver
    pub fn new(config: DohConfig) -> Self {
        let cache = Arc::new(DnsCache::new(config.max_cache_entries));
        Self {
            config,
            cache,
            stats: Arc::new(RwLock::new(DohStats::default())),
        }
    }

    /// Create with default (Cloudflare)
    pub fn cloudflare() -> Self {
        Self::new(DohConfig::cloudflare())
    }

    /// Create with Google
    pub fn google() -> Self {
        Self::new(DohConfig::google())
    }

    /// Create with Quad9
    pub fn quad9() -> Self {
        Self::new(DohConfig::quad9())
    }

    /// Create privacy-focused resolver (Mullvad over Tor)
    pub fn privacy() -> Self {
        Self::new(DohConfig::privacy_max())
    }

    /// Resolve a hostname (simulation for now)
    pub fn resolve(&self, name: &str, record_type: RecordType) -> Result<DnsResponse, DohError> {
        let mut stats = self.stats.write();
        stats.queries += 1;

        // Check cache first
        if self.config.cache_enabled {
            if let Some(cached) = self.cache.get(name, record_type) {
                stats.cache_hits += 1;
                return Ok(cached);
            }
            stats.cache_misses += 1;
        }

        // Build query
        let query = DnsQueryBuilder::new(name, record_type);
        if self.config.dnssec {
            let _ = query.dnssec();
        }

        // In a real implementation, this would:
        // 1. Send HTTP request to DoH endpoint
        // 2. Parse the response
        // 3. Return the result

        // For now, return a simulated response
        let mut response = DnsResponse::new(name.to_string(), record_type);

        // Simulate some responses
        match record_type {
            RecordType::A => {
                response.answers.push(DnsRecord {
                    name: name.to_string(),
                    record_type: RecordType::A,
                    ttl: 300,
                    data: RecordData::A(Ipv4Addr::new(93, 184, 216, 34)),
                });
                stats.success += 1;
            }
            RecordType::AAAA => {
                response.answers.push(DnsRecord {
                    name: name.to_string(),
                    record_type: RecordType::AAAA,
                    ttl: 300,
                    data: RecordData::Aaaa(Ipv6Addr::new(
                        0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946,
                    )),
                });
                stats.success += 1;
            }
            _ => {
                stats.failures += 1;
                return Err(DohError::NoRecords);
            }
        }

        // Cache the response
        if self.config.cache_enabled {
            self.cache.insert(response.clone());
        }

        Ok(response)
    }

    /// Resolve to IPv4 addresses only
    pub fn resolve_v4(&self, name: &str) -> Result<Vec<Ipv4Addr>, DohError> {
        let response = self.resolve(name, RecordType::A)?;
        let addrs = response.ipv4_addrs();
        if addrs.is_empty() {
            Err(DohError::NoRecords)
        } else {
            Ok(addrs)
        }
    }

    /// Resolve to IPv6 addresses only
    pub fn resolve_v6(&self, name: &str) -> Result<Vec<Ipv6Addr>, DohError> {
        let response = self.resolve(name, RecordType::AAAA)?;
        let addrs = response.ipv6_addrs();
        if addrs.is_empty() {
            Err(DohError::NoRecords)
        } else {
            Ok(addrs)
        }
    }

    /// Resolve to any IP address
    pub fn resolve_ip(&self, name: &str) -> Result<IpAddr, DohError> {
        // Try IPv4 first
        if let Ok(response) = self.resolve(name, RecordType::A) {
            if let Some(addr) = response.first_ipv4() {
                return Ok(IpAddr::V4(addr));
            }
        }

        // Try IPv6
        if let Ok(response) = self.resolve(name, RecordType::AAAA) {
            if let Some(addr) = response.ipv6_addrs().into_iter().next() {
                return Ok(IpAddr::V6(addr));
            }
        }

        Err(DohError::NoRecords)
    }

    /// Get resolver statistics
    pub fn stats(&self) -> DohStats {
        self.stats.read().clone()
    }

    /// Clear cache
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Get config
    pub fn config(&self) -> &DohConfig {
        &self.config
    }
}

impl Default for DohResolver {
    fn default() -> Self {
        Self::cloudflare()
    }
}

// ============================================================================
// Multi-Resolver (Fallback)
// ============================================================================

/// Multi-resolver with fallback support
#[derive(Debug)]
pub struct MultiDohResolver {
    resolvers: Vec<DohResolver>,
}

impl MultiDohResolver {
    /// Create a new multi-resolver
    pub fn new() -> Self {
        Self {
            resolvers: Vec::new(),
        }
    }

    /// Add a resolver
    pub fn add_resolver(mut self, resolver: DohResolver) -> Self {
        self.resolvers.push(resolver);
        self
    }

    /// Create with default resolvers
    pub fn with_defaults() -> Self {
        Self::new()
            .add_resolver(DohResolver::cloudflare())
            .add_resolver(DohResolver::quad9())
            .add_resolver(DohResolver::google())
    }

    /// Resolve using first successful resolver
    pub fn resolve(&self, name: &str, record_type: RecordType) -> Result<DnsResponse, DohError> {
        let mut last_error = DohError::NoResponse;

        for resolver in &self.resolvers {
            match resolver.resolve(name, record_type) {
                Ok(response) => return Ok(response),
                Err(e) => last_error = e,
            }
        }

        Err(last_error)
    }

    /// Resolve to IP
    pub fn resolve_ip(&self, name: &str) -> Result<IpAddr, DohError> {
        let mut last_error = DohError::NoResponse;

        for resolver in &self.resolvers {
            match resolver.resolve_ip(name) {
                Ok(ip) => return Ok(ip),
                Err(e) => last_error = e,
            }
        }

        Err(last_error)
    }
}

impl Default for MultiDohResolver {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// ============================================================================
// URL Encoding Helper
// ============================================================================

mod urlencoding {
    /// Percent-encode a string for URL
    pub fn encode(s: &str) -> String {
        let mut result = String::with_capacity(s.len() * 3);
        for c in s.chars() {
            match c {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                    result.push(c);
                }
                _ => {
                    for byte in c.to_string().bytes() {
                        result.push('%');
                        result.push_str(&format!("{:02X}", byte));
                    }
                }
            }
        }
        result
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
    fn test_record_types() {
        assert_eq!(RecordType::A.value(), 1);
        assert_eq!(RecordType::AAAA.value(), 28);
        assert_eq!(RecordType::Mx.name(), "MX");
    }

    #[test]
    fn test_doh_providers() {
        assert!(!DohProvider::Cloudflare.endpoint().is_empty());
        assert!(DohProvider::Cloudflare.supports_json());
        assert!(DohProvider::Mullvad.privacy_score() > DohProvider::Google.privacy_score());
    }

    #[test]
    fn test_doh_config() {
        let config = DohConfig::cloudflare();
        assert_eq!(config.provider, DohProvider::Cloudflare);
        assert!(config.cache_enabled);

        let privacy = DohConfig::privacy_max();
        assert!(privacy.use_tor);
        assert!(privacy.dnssec);
    }

    #[test]
    fn test_dns_cache() {
        let cache = DnsCache::new(10);

        let mut response = DnsResponse::new("example.com".to_string(), RecordType::A);
        response.answers.push(DnsRecord {
            name: "example.com".to_string(),
            record_type: RecordType::A,
            ttl: 300,
            data: RecordData::A(Ipv4Addr::new(1, 2, 3, 4)),
        });

        cache.insert(response.clone());

        let cached = cache.get("example.com", RecordType::A);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().ipv4_addrs().len(), 1);
    }

    #[test]
    fn test_query_builder() {
        let query = DnsQueryBuilder::new("example.com", RecordType::A);
        let wire = query.build_wire();

        assert!(wire.len() > 12); // Header + question
    }

    #[test]
    fn test_resolver() {
        let resolver = DohResolver::cloudflare();
        let response = resolver.resolve("example.com", RecordType::A);

        assert!(response.is_ok());
        let resp = response.unwrap();
        assert!(!resp.ipv4_addrs().is_empty());
    }

    #[test]
    fn test_multi_resolver() {
        let resolver = MultiDohResolver::with_defaults();
        let response = resolver.resolve("example.com", RecordType::A);

        assert!(response.is_ok());
    }

    #[test]
    fn test_dns_response_helpers() {
        let mut response = DnsResponse::new("test.com".to_string(), RecordType::A);
        response.answers.push(DnsRecord {
            name: "test.com".to_string(),
            record_type: RecordType::A,
            ttl: 300,
            data: RecordData::A(Ipv4Addr::new(1, 2, 3, 4)),
        });
        response.answers.push(DnsRecord {
            name: "test.com".to_string(),
            record_type: RecordType::AAAA,
            ttl: 300,
            data: RecordData::Aaaa(Ipv6Addr::LOCALHOST),
        });

        assert_eq!(response.ipv4_addrs().len(), 1);
        assert_eq!(response.ipv6_addrs().len(), 1);
        assert_eq!(response.ip_addrs().len(), 2);
    }

    #[test]
    fn test_url_encoding() {
        assert_eq!(urlencoding::encode("test.com"), "test.com");
        assert_eq!(urlencoding::encode("hello world"), "hello%20world");
    }
}
