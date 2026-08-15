//! Redirect handling.
//!
//! # Why redirects need care over Tor
//!
//! A redirect is the server choosing your next request. Followed naively it can
//! move you from an onion service to a clearnet host — taking your traffic out
//! through an exit relay that can read and modify it — or replay your
//! `Authorization` header to a host you never chose to trust.
//!
//! hypertor therefore defaults to [`RedirectPolicy::limited`], which follows
//! redirects but strips credentials whenever the origin changes, and refuses to
//! downgrade from an onion service to clearnet.

use http::header::{AUTHORIZATION, COOKIE, PROXY_AUTHORIZATION};
use http::{HeaderMap, Uri};

/// How the client reacts to a 3xx response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectPolicy {
    limit: usize,
    allow_onion_to_clearnet: bool,
}

impl Default for RedirectPolicy {
    fn default() -> Self {
        Self::limited(10)
    }
}

impl RedirectPolicy {
    /// Follow up to `limit` redirects.
    pub fn limited(limit: usize) -> Self {
        Self {
            limit,
            allow_onion_to_clearnet: false,
        }
    }

    /// Never follow redirects; return the 3xx response as-is.
    pub fn none() -> Self {
        Self {
            limit: 0,
            allow_onion_to_clearnet: false,
        }
    }

    /// Permit a redirect from a `.onion` origin out to a clearnet host.
    ///
    /// # Warning
    ///
    /// Traffic to an onion service never leaves the Tor network and is
    /// authenticated by the address itself. Following a redirect to clearnet
    /// sends the follow-up request through an exit relay — an untrusted party
    /// that sees the destination and, without TLS, the content. Only enable
    /// this if you specifically expect such redirects.
    pub fn allow_onion_to_clearnet(mut self, allow: bool) -> Self {
        self.allow_onion_to_clearnet = allow;
        self
    }

    /// Whether any redirect will be followed.
    pub fn is_enabled(&self) -> bool {
        self.limit > 0
    }

    /// The configured maximum.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Decide what to do with a redirect from `from` to `to`.
    pub fn evaluate(&self, from: &Uri, to: &Uri) -> RedirectAction {
        if self.limit == 0 {
            return RedirectAction::Stop;
        }

        if is_onion(from) && !is_onion(to) && !self.allow_onion_to_clearnet {
            return RedirectAction::Refuse(
                "refusing to follow a redirect from an onion service to a clearnet host; \
                 enable RedirectPolicy::allow_onion_to_clearnet if this is expected",
            );
        }

        if same_origin(from, to) {
            RedirectAction::Follow
        } else {
            RedirectAction::FollowStripped
        }
    }
}

/// The outcome of evaluating one redirect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectAction {
    /// Follow, keeping all headers.
    Follow,
    /// Follow, but drop credentials because the origin changed.
    FollowStripped,
    /// Do not follow; return the 3xx response to the caller.
    Stop,
    /// Do not follow; fail with this explanation.
    Refuse(&'static str),
}

/// Whether a URI names an onion service.
pub(crate) fn is_onion(uri: &Uri) -> bool {
    uri.host().is_some_and(|h| {
        h.rsplit('.')
            .next()
            .is_some_and(|tld| tld.eq_ignore_ascii_case("onion"))
    })
}

/// Whether two URIs share a scheme, host and effective port.
fn same_origin(a: &Uri, b: &Uri) -> bool {
    fn port(uri: &Uri) -> Option<u16> {
        uri.port_u16().or(match uri.scheme_str() {
            Some("http") => Some(80),
            Some("https") => Some(443),
            _ => None,
        })
    }

    a.scheme_str() == b.scheme_str()
        && a.host().map(str::to_ascii_lowercase) == b.host().map(str::to_ascii_lowercase)
        && port(a) == port(b)
}

/// Remove headers that must not cross an origin boundary.
pub(crate) fn strip_sensitive_headers(headers: &mut HeaderMap) {
    headers.remove(AUTHORIZATION);
    headers.remove(PROXY_AUTHORIZATION);
    headers.remove(COOKIE);
}

/// Resolve a `Location` value against the URI it was returned from.
///
/// Handles absolute URLs, absolute paths and relative paths.
pub(crate) fn resolve(base: &Uri, location: &str) -> Option<Uri> {
    let location = location.trim();
    if location.is_empty() {
        return None;
    }

    // Absolute URL.
    if let Ok(uri) = location.parse::<Uri>()
        && uri.scheme().is_some()
    {
        return Some(uri);
    }

    let parts = base.clone().into_parts();
    let scheme = parts.scheme?;
    let authority = parts.authority?;

    let path_and_query = if let Some(stripped) = location.strip_prefix("//") {
        // Protocol-relative: //host/path
        return format!("{}://{}", scheme.as_str(), stripped).parse().ok();
    } else if location.starts_with('/') {
        location.to_string()
    } else {
        // Relative to the base's directory.
        let base_path = base.path();
        let dir = match base_path.rfind('/') {
            Some(i) => &base_path[..=i],
            None => "/",
        };
        format!("{dir}{location}")
    };

    format!(
        "{}://{}{}",
        scheme.as_str(),
        authority.as_str(),
        path_and_query
    )
    .parse()
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(s: &str) -> Uri {
        s.parse().expect("test URI parses")
    }

    #[test]
    fn same_origin_redirects_keep_headers() {
        let policy = RedirectPolicy::default();
        assert_eq!(
            policy.evaluate(&uri("http://a.onion/one"), &uri("http://a.onion/two")),
            RedirectAction::Follow
        );
    }

    #[test]
    fn cross_origin_redirects_drop_credentials() {
        let policy = RedirectPolicy::default();
        for (from, to) in [
            ("http://a.onion/", "http://b.onion/"),
            ("https://example.com/", "https://other.example.com/"),
            ("http://example.com/", "https://example.com/"),
            ("http://example.com/", "http://example.com:8080/"),
        ] {
            assert_eq!(
                policy.evaluate(&uri(from), &uri(to)),
                RedirectAction::FollowStripped,
                "{from} -> {to}"
            );
        }
    }

    #[test]
    fn default_port_is_not_a_different_origin() {
        let policy = RedirectPolicy::default();
        assert_eq!(
            policy.evaluate(&uri("http://a.onion/x"), &uri("http://a.onion:80/y")),
            RedirectAction::Follow
        );
    }

    #[test]
    fn onion_to_clearnet_is_refused_by_default() {
        let policy = RedirectPolicy::default();
        assert!(matches!(
            policy.evaluate(&uri("http://a.onion/"), &uri("https://tracker.example/")),
            RedirectAction::Refuse(_)
        ));
    }

    #[test]
    fn onion_to_clearnet_can_be_opted_into() {
        let policy = RedirectPolicy::default().allow_onion_to_clearnet(true);
        assert_eq!(
            policy.evaluate(&uri("http://a.onion/"), &uri("https://example.com/")),
            RedirectAction::FollowStripped
        );
    }

    #[test]
    fn clearnet_to_onion_is_always_allowed() {
        // Moving *into* the Tor network is a security upgrade, not a downgrade.
        let policy = RedirectPolicy::default();
        assert_eq!(
            policy.evaluate(&uri("https://example.com/"), &uri("http://a.onion/")),
            RedirectAction::FollowStripped
        );
    }

    #[test]
    fn disabled_policy_stops() {
        assert_eq!(
            RedirectPolicy::none().evaluate(&uri("http://a.onion/"), &uri("http://a.onion/x")),
            RedirectAction::Stop
        );
        assert!(!RedirectPolicy::none().is_enabled());
    }

    #[test]
    fn strips_every_credential_header() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer secret".parse().unwrap());
        headers.insert(COOKIE, "session=abc".parse().unwrap());
        headers.insert(PROXY_AUTHORIZATION, "Basic xyz".parse().unwrap());
        headers.insert("x-custom", "kept".parse().unwrap());

        strip_sensitive_headers(&mut headers);

        assert!(headers.get(AUTHORIZATION).is_none());
        assert!(headers.get(COOKIE).is_none());
        assert!(headers.get(PROXY_AUTHORIZATION).is_none());
        assert!(headers.get("x-custom").is_some());
    }

    #[test]
    fn resolves_absolute_locations() {
        let base = uri("http://a.onion/dir/page");
        assert_eq!(
            resolve(&base, "https://b.onion/x").unwrap(),
            uri("https://b.onion/x")
        );
    }

    #[test]
    fn resolves_absolute_paths() {
        let base = uri("http://a.onion/dir/page?q=1");
        assert_eq!(
            resolve(&base, "/other").unwrap(),
            uri("http://a.onion/other")
        );
    }

    #[test]
    fn resolves_relative_paths_against_the_directory() {
        let base = uri("http://a.onion/dir/page");
        assert_eq!(
            resolve(&base, "sibling").unwrap(),
            uri("http://a.onion/dir/sibling")
        );
    }

    #[test]
    fn resolves_protocol_relative_locations() {
        let base = uri("https://a.example/dir/page");
        assert_eq!(
            resolve(&base, "//b.example/x").unwrap(),
            uri("https://b.example/x")
        );
    }

    #[test]
    fn empty_location_is_not_a_redirect() {
        assert!(resolve(&uri("http://a.onion/"), "   ").is_none());
    }
}
