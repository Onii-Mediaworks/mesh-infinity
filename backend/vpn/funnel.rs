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
pub struct FunnelConfig {
    /// Whether funnel is enabled for this device.
    pub enabled: bool,
    /// Which services to expose via funnel.
    pub exposed_services: Vec<FunnelExposure>,
    /// DDNS configuration (optional).
    pub ddns: Option<DdnsConfig>,
}

/// A service exposed via funnel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FunnelExposure {
    /// Service ID to expose.
    pub service_id: [u8; 16],
    /// External hostname (for TLS SNI routing).
    pub hostname: Option<String>,
    /// External port.
    pub external_port: u16,
}

/// DDNS provider configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DdnsConfig {
    /// Cloudflare DNS API.
    Cloudflare {
        zone_id: String,
        api_token: String,
        record_name: String,
    },
    /// deSEC.
    DeSec {
        domain: String,
        api_token: String,
    },
    /// RFC 2136 dynamic DNS.
    Rfc2136 {
        server: String,
        zone: String,
        key_name: String,
        key_secret: String,
    },
}

/// Direct IP exposure configuration (§13.17).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[derive(Default)]
pub struct DirectIpConfig {
    /// Whether direct IP exposure is enabled.
    pub enabled: bool,
    /// Advertise our IP in the network map.
    pub advertise_in_map: bool,
    /// Advertise our IP in DNS.
    pub advertise_in_dns: bool,
    /// Addresses to bind to (empty = auto-detect).
    pub bind_addresses: Vec<String>,
    /// User has explicitly accepted the risk.
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
