//! Redirect handling
//!
//! Safe redirect following with security checks.

use std::collections::HashSet;

use http::{StatusCode, Uri, header};
use tracing::debug;

use crate::error::{Error, Result};
use crate::response::Response;

/// Redirect policy for HTTP requests
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RedirectPolicy {
    /// Never follow redirects (safest)
    #[default]
    Never,
    /// Follow up to N redirects with security checks
    Limited(u32),
    /// Follow any number of redirects (dangerous)
    All,
}

impl RedirectPolicy {
    /// Follow up to 10 redirects (standard browser behavior)
    #[must_use]
    pub fn standard() -> Self {
        Self::Limited(10)
    }

    /// Check if redirects should be followed
    #[must_use]
    pub fn should_follow(&self) -> bool {
        !matches!(self, Self::Never)
    }

    /// Get the maximum number of redirects
    #[must_use]
    pub fn max_redirects(&self) -> Option<u32> {
        match self {
            Self::Never => Some(0),
            Self::Limited(n) => Some(*n),
            Self::All => None,
        }
    }
}

/// Result of checking if a redirect should be followed
#[derive(Debug)]
pub enum RedirectAction {
    /// Follow the redirect to this URI
    Follow(Uri),
    /// Stop following redirects
    Stop,
}

/// Security checks for redirects
#[derive(Debug, Clone)]
pub struct RedirectGuard {
    /// Maximum number of redirects
    max_redirects: u32,
    /// Current redirect count
    count: u32,
    /// Track visited URIs to prevent loops
    visited: HashSet<String>,
    /// Allow HTTP -> HTTPS upgrades only
    allow_https_downgrade: bool,
    /// Allow redirects to different hosts
    allow_cross_origin: bool,
}

impl Default for RedirectGuard {
    fn default() -> Self {
        Self {
            max_redirects: 10,
            count: 0,
            visited: HashSet::new(),
            allow_https_downgrade: false,
            allow_cross_origin: true,
        }
    }
}

impl RedirectGuard {
    /// Create a new redirect guard
    #[must_use]
    pub fn new(max_redirects: u32) -> Self {
        Self {
            max_redirects,
            ..Default::default()
        }
    }

    /// Disallow HTTPS -> HTTP downgrades
    #[must_use]
    pub fn forbid_https_downgrade(mut self) -> Self {
        self.allow_https_downgrade = false;
        self
    }

    /// Disallow cross-origin redirects
    #[must_use]
    pub fn forbid_cross_origin(mut self) -> Self {
        self.allow_cross_origin = false;
        self
    }

    /// Check if a redirect should be followed
    pub fn check_redirect(
        &mut self,
        response: &Response,
        current_uri: &Uri,
    ) -> Result<RedirectAction> {
        // Only follow redirect status codes
        if !response.is_redirect() {
            return Ok(RedirectAction::Stop);
        }

        // Check redirect limit
        if self.count >= self.max_redirects {
            return Err(Error::TooManyRedirects {
                count: self.count,
                limit: self.max_redirects,
            });
        }

        // Get Location header
        let location = response
            .header(header::LOCATION.as_str())
            .ok_or_else(|| Error::http("redirect response missing Location header"))?;

        // Parse the redirect target
        let target_uri = resolve_redirect_uri(current_uri, location)?;

        // Check for redirect loops
        let target_str = target_uri.to_string();
        if self.visited.contains(&target_str) {
            return Err(Error::http(format!(
                "redirect loop detected: {} already visited",
                target_str
            )));
        }

        // Security: Check for HTTPS downgrade
        if !self.allow_https_downgrade
            && current_uri.scheme_str() == Some("https")
            && target_uri.scheme_str() == Some("http")
        {
            return Err(Error::http(format!(
                "refusing HTTPS to HTTP downgrade: {} -> {}",
                current_uri, target_uri
            )));
        }

        // Security: Check for cross-origin redirects
        if !self.allow_cross_origin {
            let current_host = current_uri.host();
            let target_host = target_uri.host();
            if current_host != target_host {
                return Err(Error::http(format!(
                    "refusing cross-origin redirect: {} -> {}",
                    current_host.unwrap_or("unknown"),
                    target_host.unwrap_or("unknown")
                )));
            }
        }

        // Track this redirect
        self.visited.insert(target_str);
        self.count += 1;

        debug!(
            "Following redirect {}/{}: {} -> {}",
            self.count, self.max_redirects, current_uri, target_uri
        );

        Ok(RedirectAction::Follow(target_uri))
    }

    /// Get the number of redirects followed
    #[must_use]
    pub fn redirect_count(&self) -> u32 {
        self.count
    }
}

/// Resolve a redirect URI relative to the current URI
fn resolve_redirect_uri(current: &Uri, location: &str) -> Result<Uri> {
    // Try parsing as absolute URI first
    if let Ok(uri) = location.parse::<Uri>() {
        if uri.scheme().is_some() && uri.host().is_some() {
            return Ok(uri);
        }
    }

    // Parse as relative URI
    if location.starts_with("//") {
        // Protocol-relative URL
        let scheme = current.scheme_str().unwrap_or("https");
        let full_url = format!("{}:{}", scheme, location);
        return full_url
            .parse()
            .map_err(|_| Error::invalid_url(&full_url, "invalid redirect URL"));
    }

    if location.starts_with('/') {
        // Absolute path
        let scheme = current.scheme_str().unwrap_or("https");
        let authority = current.authority().map(|a| a.as_str()).unwrap_or("");
        let full_url = format!("{}://{}{}", scheme, authority, location);
        return full_url
            .parse()
            .map_err(|_| Error::invalid_url(&full_url, "invalid redirect URL"));
    }

    // Relative path - combine with current path
    let scheme = current.scheme_str().unwrap_or("https");
    let authority = current.authority().map(|a| a.as_str()).unwrap_or("");
    let current_path = current.path();
    let base_path = current_path.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
    let full_url = format!("{}://{}{}/{}", scheme, authority, base_path, location);
    full_url
        .parse()
        .map_err(|_| Error::invalid_url(&full_url, "invalid redirect URL"))
}

/// Determine if headers should be removed on cross-origin redirect
#[must_use]
pub fn should_remove_auth_on_redirect(from: &Uri, to: &Uri) -> bool {
    // Remove Authorization header on cross-origin redirects
    from.host() != to.host()
}

/// Determine if the request method should change for this redirect
#[must_use]
pub fn redirect_method_for_status(
    status: StatusCode,
    original_method: &http::Method,
) -> http::Method {
    use http::Method;

    match status.as_u16() {
        // 301/302: Historically browsers changed POST to GET
        301 | 302 => {
            if *original_method == Method::POST {
                Method::GET
            } else {
                original_method.clone()
            }
        }
        // 303: Always change to GET (except HEAD)
        303 => {
            if *original_method == Method::HEAD {
                Method::HEAD
            } else {
                Method::GET
            }
        }
        // 307/308: Preserve method
        307 | 308 => original_method.clone(),
        // Unknown redirect status
        _ => original_method.clone(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_redirect_policy() {
        assert!(!RedirectPolicy::Never.should_follow());
        assert!(RedirectPolicy::Limited(5).should_follow());
        assert!(RedirectPolicy::All.should_follow());
        assert_eq!(RedirectPolicy::standard().max_redirects(), Some(10));
    }

    #[test]
    fn test_resolve_absolute_redirect() {
        let current: Uri = "https://example.com/page".parse().unwrap();
        let target = resolve_redirect_uri(&current, "https://other.com/new").unwrap();
        assert_eq!(target.to_string(), "https://other.com/new");
    }

    #[test]
    fn test_resolve_relative_redirect() {
        let current: Uri = "https://example.com/foo/bar".parse().unwrap();
        let target = resolve_redirect_uri(&current, "/baz").unwrap();
        assert_eq!(target.to_string(), "https://example.com/baz");
    }

    #[test]
    fn test_redirect_method_change() {
        use http::Method;

        // POST -> GET on 303
        assert_eq!(
            redirect_method_for_status(StatusCode::SEE_OTHER, &Method::POST),
            Method::GET
        );

        // POST preserved on 307
        assert_eq!(
            redirect_method_for_status(StatusCode::TEMPORARY_REDIRECT, &Method::POST),
            Method::POST
        );
    }
}
