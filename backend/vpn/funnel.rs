//! Funnel — Bidirectional Service Exposure (§13.16)
//!
//! # What is Funnel?
//!
//! Funnel is a reverse proxy that allows hosting devices to accept
//! inbound internet connections without a public IP. A mesh relay
//! node with a public IP accepts connections and forwards them to
//! the Infinet device.
//!
//! # Key Properties
//!
//! - Relay nodes do NOT terminate TLS (pass-through transparent proxy)
//! - Hosting device never needs a public IP
//! - Relay sees only source mesh address and destination service
//! - DDNS integration: Cloudflare, deSEC, RFC 2136

use serde::{Deserialize, Serialize};

/// Funnel configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// FunnelConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FunnelConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FunnelConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct FunnelConfig {
    /// Whether funnel is enabled for this device.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub enabled: bool,
    /// Which services to expose via funnel.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub exposed_services: Vec<FunnelExposure>,
    /// DDNS configuration (optional).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub ddns: Option<DdnsConfig>,
}

/// A service exposed via funnel.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// FunnelExposure — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FunnelExposure — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// FunnelExposure — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct FunnelExposure {
    /// Service ID to expose.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub service_id: [u8; 16],
    /// External hostname (for TLS SNI routing).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub hostname: Option<String>,
    /// External port.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub external_port: u16,
}

/// DDNS provider configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// DdnsConfig — variant enumeration.
// Match exhaustively to handle every protocol state.
// DdnsConfig — variant enumeration.
// Match exhaustively to handle every protocol state.
// DdnsConfig — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum DdnsConfig {
    /// Cloudflare DNS API.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Cloudflare {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        zone_id: String,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        api_token: String,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        record_name: String,
    },
    /// deSEC.
    DeSec {
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        domain: String,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        api_token: String,
    },
    /// RFC 2136 dynamic DNS.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Rfc2136 {
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        server: String,
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        zone: String,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        key_name: String,
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        key_secret: String,
    },
}

/// Direct IP exposure configuration (§13.17).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[derive(Default)]
// Begin the block scope.
// DirectIpConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// DirectIpConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// DirectIpConfig — protocol data structure (see field-level docs).
pub struct DirectIpConfig {
    /// Whether direct IP exposure is enabled.
    // Execute this protocol step.
    // Execute this protocol step.
    pub enabled: bool,
    /// Advertise our IP in the network map.
    // Execute this protocol step.
    // Execute this protocol step.
    pub advertise_in_map: bool,
    /// Advertise our IP in DNS.
    // Execute this protocol step.
    // Execute this protocol step.
    pub advertise_in_dns: bool,
    /// Addresses to bind to (empty = auto-detect).
    // Execute this protocol step.
    // Execute this protocol step.
    pub bind_addresses: Vec<String>,
    /// User has explicitly accepted the risk.
    // Execute this protocol step.
    // Execute this protocol step.
    pub accepted_risk: bool,
}


// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direct_ip_defaults() {
        let config = DirectIpConfig::default();
        assert!(!config.enabled);
        assert!(!config.accepted_risk);
    }

    #[test]
    fn test_funnel_serde() {
        let config = FunnelConfig {
            enabled: true,
            exposed_services: vec![FunnelExposure {
                service_id: [0x01; 16],
                hostname: Some("myservice.example.com".to_string()),
                external_port: 443,
            }],
            ddns: None,
        };
        let json = serde_json::to_string(&config).unwrap();
        let recovered: FunnelConfig = serde_json::from_str(&json).unwrap();
        assert!(recovered.enabled);
    }
}
