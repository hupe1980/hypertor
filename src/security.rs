//! Security configuration presets for Tor client and onion services.
//!
//! This module provides **configuration presets** that wire to real arti APIs.
//! All actual security is implemented by arti - we just provide convenient presets.
//!
//! # What's REAL (handled by arti)
//!
//! | Feature | arti API | Module |
//! |---------|----------|--------|
//! | PoW DoS Protection | `OnionServiceConfigBuilder::enable_pow()` | `onion_service.rs` |
//! | Rate Limiting | `OnionServiceConfigBuilder::rate_limit_at_intro()` | `onion_service.rs` |
//! | Stream Limits | `OnionServiceConfigBuilder::max_concurrent_streams_per_circuit()` | `onion_service.rs` |
//! | Client Authorization | `RestrictedDiscoveryConfigBuilder` | `onion_service.rs` |
//! | Vanguards | `VanguardConfigBuilder::mode()` | `client.rs` |
//! | Bridges | `TorClientConfigBuilder::bridges()` | `client.rs` |
//! | Circuit Isolation | `StreamPrefs::set_isolation()` | `client.rs` |
//!
//! # What's NOT Here
//!
//! We **intentionally removed** fake/scaffolding implementations:
//! - ~~PowSolver/PowVerifier~~ → Use `OnionServiceConfig::with_pow()` (real arti API)
//! - ~~WfDefense~~ → Application-layer padding doesn't protect against traffic analysis
//!
//! **Fake security is worse than no security.**
//!
//! ## References
//!
//! - [Tor PoW Defense](https://blog.torproject.org/introducing-proof-of-work-defense-for-onion-services/)
//! - [Vanguards Specification](https://spec.torproject.org/vanguards-spec/index.html)
//! - [Restricted Discovery](https://spec.torproject.org/rend-spec/protocol-overview.html#CLIENT-AUTH)

use tor_guardmgr::VanguardMode;

use crate::onion_service::OnionServiceConfig;

// ============================================================================
// Security Level Presets
// ============================================================================

/// Security level presets for quick configuration.
///
/// These map to real arti configurations:
/// - `Standard` - Default Tor settings
/// - `Enhanced` - PoW + rate limiting + vanguards-lite
/// - `Maximum` - All protections enabled
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecurityLevel {
    /// Standard security (default Tor behavior).
    /// - No PoW
    /// - No vanguards
    /// - Default stream limits
    Standard,

    /// Enhanced security (recommended for most services).
    /// - PoW DoS protection enabled
    /// - Rate limiting at intro points
    /// - Vanguards-lite mode
    #[default]
    Enhanced,

    /// Maximum security (for high-value targets).
    /// - PoW enabled
    /// - Aggressive rate limiting
    /// - Full vanguards
    /// - Low stream limits
    Maximum,
}

impl SecurityLevel {
    /// Get the corresponding VanguardMode for this security level.
    pub fn vanguard_mode(&self) -> VanguardMode {
        match self {
            SecurityLevel::Standard => VanguardMode::Lite,
            SecurityLevel::Enhanced => VanguardMode::Lite,
            SecurityLevel::Maximum => VanguardMode::Full,
        }
    }

    /// Get the corresponding OnionServiceConfig for this security level.
    pub fn onion_service_config(&self, nickname: impl Into<String>) -> OnionServiceConfig {
        match self {
            SecurityLevel::Standard => OnionServiceConfig::new(nickname),

            SecurityLevel::Enhanced => OnionServiceConfig::new(nickname)
                .with_pow()
                .rate_limit_at_intro(50.0, 100)
                .max_streams_per_circuit(500),

            SecurityLevel::Maximum => OnionServiceConfig::new(nickname)
                .with_pow()
                .rate_limit_at_intro(10.0, 20)
                .max_streams_per_circuit(100)
                .num_intro_points(5),
        }
    }

    /// Whether this level enables PoW protection.
    pub fn pow_enabled(&self) -> bool {
        !matches!(self, SecurityLevel::Standard)
    }

    /// Whether this level uses full vanguards.
    pub fn full_vanguards(&self) -> bool {
        matches!(self, SecurityLevel::Maximum)
    }
}

// ============================================================================
// Client Security Config
// ============================================================================

/// Client-side security configuration.
///
/// Use this to configure TorClient with appropriate security settings.
#[derive(Debug, Clone)]
pub struct ClientSecurityConfig {
    /// Security level preset.
    pub level: SecurityLevel,
    /// Vanguard mode (derived from level, or override).
    pub vanguard_mode: VanguardMode,
    /// Enable strict stream isolation.
    pub strict_isolation: bool,
}

impl Default for ClientSecurityConfig {
    fn default() -> Self {
        Self::enhanced()
    }
}

impl ClientSecurityConfig {
    /// Standard client security (default Tor).
    pub fn standard() -> Self {
        Self {
            level: SecurityLevel::Standard,
            vanguard_mode: VanguardMode::Lite,
            strict_isolation: false,
        }
    }

    /// Enhanced client security (recommended).
    pub fn enhanced() -> Self {
        Self {
            level: SecurityLevel::Enhanced,
            vanguard_mode: VanguardMode::Lite,
            strict_isolation: true,
        }
    }

    /// Maximum client security.
    pub fn maximum() -> Self {
        Self {
            level: SecurityLevel::Maximum,
            vanguard_mode: VanguardMode::Full,
            strict_isolation: true,
        }
    }
}

// ============================================================================
// Service Security Config
// ============================================================================

/// Server-side (onion service) security configuration.
///
/// This generates an `OnionServiceConfig` with appropriate hardening.
#[derive(Debug, Clone)]
pub struct ServiceSecurityConfig {
    /// Security level preset.
    pub level: SecurityLevel,
    /// Enable PoW DoS protection.
    pub enable_pow: bool,
    /// Rate limit at intro points (requests/sec, burst).
    pub rate_limit: Option<(f64, u32)>,
    /// Max streams per circuit.
    pub max_streams: u32,
    /// Number of introduction points.
    pub num_intro_points: u8,
}

impl Default for ServiceSecurityConfig {
    fn default() -> Self {
        Self::enhanced()
    }
}

impl ServiceSecurityConfig {
    /// Standard service security.
    pub fn standard() -> Self {
        Self {
            level: SecurityLevel::Standard,
            enable_pow: false,
            rate_limit: None,
            max_streams: 65535,
            num_intro_points: 3,
        }
    }

    /// Enhanced service security (recommended).
    pub fn enhanced() -> Self {
        Self {
            level: SecurityLevel::Enhanced,
            enable_pow: true,
            rate_limit: Some((50.0, 100)),
            max_streams: 500,
            num_intro_points: 3,
        }
    }

    /// Maximum service security.
    pub fn maximum() -> Self {
        Self {
            level: SecurityLevel::Maximum,
            enable_pow: true,
            rate_limit: Some((10.0, 20)),
            max_streams: 100,
            num_intro_points: 5,
        }
    }

    /// Convert to OnionServiceConfig with these security settings.
    pub fn to_onion_config(&self, nickname: impl Into<String>) -> OnionServiceConfig {
        let mut config = OnionServiceConfig::new(nickname);

        if self.enable_pow {
            config = config.with_pow();
        }

        if let Some((rate, burst)) = self.rate_limit {
            config = config.rate_limit_at_intro(rate, burst);
        }

        config
            .max_streams_per_circuit(self.max_streams)
            .num_intro_points(self.num_intro_points)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_levels() {
        // Standard - minimal protection
        let standard = SecurityLevel::Standard;
        assert!(!standard.pow_enabled());
        assert!(!standard.full_vanguards());
        assert_eq!(standard.vanguard_mode(), VanguardMode::Lite);

        // Enhanced - recommended
        let enhanced = SecurityLevel::Enhanced;
        assert!(enhanced.pow_enabled());
        assert!(!enhanced.full_vanguards());

        // Maximum - all protections
        let maximum = SecurityLevel::Maximum;
        assert!(maximum.pow_enabled());
        assert!(maximum.full_vanguards());
        assert_eq!(maximum.vanguard_mode(), VanguardMode::Full);
    }

    #[test]
    fn test_client_security_configs() {
        let standard = ClientSecurityConfig::standard();
        assert!(!standard.strict_isolation);

        let enhanced = ClientSecurityConfig::enhanced();
        assert!(enhanced.strict_isolation);

        let maximum = ClientSecurityConfig::maximum();
        assert_eq!(maximum.vanguard_mode, VanguardMode::Full);
    }

    #[test]
    fn test_service_security_configs() {
        let standard = ServiceSecurityConfig::standard();
        assert!(!standard.enable_pow);
        assert!(standard.rate_limit.is_none());

        let enhanced = ServiceSecurityConfig::enhanced();
        assert!(enhanced.enable_pow);
        assert!(enhanced.rate_limit.is_some());

        let maximum = ServiceSecurityConfig::maximum();
        assert_eq!(maximum.num_intro_points, 5);
        assert_eq!(maximum.max_streams, 100);
    }

    #[test]
    fn test_service_to_onion_config() {
        let security = ServiceSecurityConfig::maximum();
        let config = security.to_onion_config("test-service");

        assert!(config.enable_pow);
        assert_eq!(config.max_streams_per_circuit, 100);
        assert_eq!(config.num_intro_points, 5);
        assert_eq!(config.rate_limit_at_intro, Some((10.0, 20)));
    }

    #[test]
    fn test_level_to_onion_config() {
        let config = SecurityLevel::Maximum.onion_service_config("secure-svc");
        assert!(config.enable_pow);
        assert_eq!(config.num_intro_points, 5);
    }
}
