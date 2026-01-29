//! Cookie jar for session management.
//!
//! Provides automatic cookie handling with security-conscious defaults.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// A cookie with metadata.
#[derive(Debug, Clone)]
pub struct Cookie {
    /// Cookie name
    pub name: String,
    /// Cookie value
    pub value: String,
    /// Domain the cookie is valid for
    pub domain: String,
    /// Path the cookie is valid for
    pub path: String,
    /// Expiration time (None = session cookie)
    pub expires: Option<SystemTime>,
    /// HttpOnly flag (not accessible via JavaScript)
    pub http_only: bool,
    /// Secure flag (only sent over HTTPS)
    pub secure: bool,
    /// SameSite attribute
    pub same_site: SameSite,
}

/// SameSite cookie attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SameSite {
    /// Cookie sent with all requests
    None,
    /// Cookie sent with same-site and top-level navigation
    Lax,
    /// Cookie only sent with same-site requests
    #[default]
    Strict,
}

impl Cookie {
    /// Parse a Set-Cookie header value.
    pub fn parse(header: &str, request_domain: &str) -> Option<Self> {
        let mut parts = header.split(';');
        let name_value = parts.next()?;
        let (name, value) = name_value.split_once('=')?;

        let mut cookie = Cookie {
            name: name.trim().to_string(),
            value: value.trim().to_string(),
            domain: request_domain.to_string(),
            path: "/".to_string(),
            expires: None,
            http_only: false,
            secure: false,
            same_site: SameSite::default(),
        };

        for part in parts {
            let part = part.trim();
            if let Some((attr, val)) = part.split_once('=') {
                match attr.to_lowercase().as_str() {
                    "domain" => cookie.domain = val.trim_start_matches('.').to_string(),
                    "path" => cookie.path = val.to_string(),
                    "max-age" => {
                        if let Ok(seconds) = val.parse::<u64>() {
                            cookie.expires = Some(SystemTime::now() + Duration::from_secs(seconds));
                        }
                    }
                    "samesite" => {
                        cookie.same_site = match val.to_lowercase().as_str() {
                            "none" => SameSite::None,
                            "lax" => SameSite::Lax,
                            _ => SameSite::Strict,
                        };
                    }
                    _ => {}
                }
            } else {
                match part.to_lowercase().as_str() {
                    "httponly" => cookie.http_only = true,
                    "secure" => cookie.secure = true,
                    _ => {}
                }
            }
        }

        Some(cookie)
    }

    /// Check if the cookie is expired.
    pub fn is_expired(&self) -> bool {
        self.expires
            .map(|exp| SystemTime::now() > exp)
            .unwrap_or(false)
    }

    /// Check if the cookie matches the given domain.
    pub fn matches_domain(&self, domain: &str) -> bool {
        domain == self.domain || domain.ends_with(&format!(".{}", self.domain))
    }

    /// Check if the cookie matches the given path.
    pub fn matches_path(&self, path: &str) -> bool {
        path.starts_with(&self.path)
    }
}

/// Thread-safe cookie jar.
#[derive(Debug, Clone, Default)]
pub struct CookieJar {
    cookies: Arc<RwLock<HashMap<String, Cookie>>>,
}

impl CookieJar {
    /// Create a new empty cookie jar.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a cookie to the jar.
    pub fn add(&self, cookie: Cookie) {
        let key = format!("{}:{}:{}", cookie.domain, cookie.path, cookie.name);
        self.cookies.write().insert(key, cookie);
    }

    /// Parse and add a Set-Cookie header with explicit domain.
    pub fn add_header_with_domain(&self, header: &str, domain: &str) {
        if let Some(cookie) = Cookie::parse(header, domain) {
            self.add(cookie);
        }
    }

    /// Get cookies for a request to the given URL.
    pub fn cookies_for(&self, domain: &str, path: &str, secure: bool) -> Vec<Cookie> {
        let cookies = self.cookies.read();
        cookies
            .values()
            .filter(|c| {
                !c.is_expired()
                    && c.matches_domain(domain)
                    && c.matches_path(path)
                    && (!c.secure || secure)
            })
            .cloned()
            .collect()
    }

    /// Get the Cookie header value for a request.
    pub fn cookie_header(&self, domain: &str, path: &str, secure: bool) -> Option<String> {
        let cookies = self.cookies_for(domain, path, secure);
        if cookies.is_empty() {
            None
        } else {
            Some(
                cookies
                    .iter()
                    .map(|c| format!("{}={}", c.name, c.value))
                    .collect::<Vec<_>>()
                    .join("; "),
            )
        }
    }

    /// Get the Cookie header value for a request URI.
    pub fn get_cookie_header(&self, uri: &http::Uri) -> Option<String> {
        let domain = uri.host()?;
        let path = uri.path();
        let secure = uri.scheme_str() == Some("https");
        self.cookie_header(domain, path, secure)
    }

    /// Add a cookie from a Set-Cookie header for the given URI.
    pub fn add_from_header(&self, header: &str, uri: &http::Uri) {
        if let Some(domain) = uri.host() {
            if let Some(cookie) = Cookie::parse(header, domain) {
                self.add(cookie);
            }
        }
    }

    /// Remove all cookies.
    pub fn clear(&self) {
        self.cookies.write().clear();
    }

    /// Remove expired cookies.
    pub fn cleanup(&self) {
        self.cookies.write().retain(|_, c| !c.is_expired());
    }

    /// Get the number of cookies in the jar.
    pub fn len(&self) -> usize {
        self.cookies.read().len()
    }

    /// Check if the jar is empty.
    pub fn is_empty(&self) -> bool {
        self.cookies.read().is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_cookie_parse() {
        let cookie =
            Cookie::parse("session=abc123; HttpOnly; Secure; Path=/app", "example.com").unwrap();
        assert_eq!(cookie.name, "session");
        assert_eq!(cookie.value, "abc123");
        assert!(cookie.http_only);
        assert!(cookie.secure);
        assert_eq!(cookie.path, "/app");
    }

    #[test]
    fn test_cookie_jar() {
        let jar = CookieJar::new();

        jar.add_header_with_domain("session=xyz; Path=/", "example.com");
        jar.add_header_with_domain("user=alice; Path=/app", "example.com");

        assert_eq!(jar.len(), 2);

        let header = jar.cookie_header("example.com", "/app/page", false);
        assert!(header.is_some());
        let header = header.unwrap();
        assert!(header.contains("session=xyz"));
        assert!(header.contains("user=alice"));
    }

    #[test]
    fn test_cookie_domain_matching() {
        let cookie = Cookie {
            name: "test".to_string(),
            value: "value".to_string(),
            domain: "example.com".to_string(),
            path: "/".to_string(),
            expires: None,
            http_only: false,
            secure: false,
            same_site: SameSite::Strict,
        };

        assert!(cookie.matches_domain("example.com"));
        assert!(cookie.matches_domain("sub.example.com"));
        assert!(!cookie.matches_domain("other.com"));
    }
}
