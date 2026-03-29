//! LoSec Mode — Low-Security, High-Bandwidth Transport (§6.9)
//!
//! # What is LoSec Mode?
//!
//! LoSec is an opt-in mode that trades anonymity for bandwidth and
//! latency. Instead of routing through the full mesh with 4-layer
//! encryption, LoSec uses shorter paths (1-2 relay hops) with only
//! WireGuard encryption.
//!
//! # Three Connection Modes (§6.9)
//!
//! The spec defines three distinct connection modes:
//!
//! 1. **Standard mesh (default):** Full inner tunnel, multi-hop,
//!    maximum anonymity, outer cover traffic always present.
//!
//! 2. **LoSec (1-2 hops):** Still uses mesh routing layer, but
//!    with a shorter path. Relies on ambient mesh traffic for cover.
//!    Shows an amber indicator in the UI.
//!
//! 3. **Direct (0 hops):** Bypasses mesh routing entirely. IP address
//!    visible to the peer. Shows a persistent red banner and requires
//!    a full-screen terror warning before establishing.
//!
//! # When is LoSec Available?
//!
//! LoSec requires three conditions (§6.9.6):
//! 1. Host-side `allow_losec` toggle enabled
//! 2. Initiator explicitly requests it
//! 3. Remote peer explicitly accepts (default: deny)
//!
//! # Ambient Traffic Threshold (§6.7)
//!
//! LoSec and fast routing are only available when ambient traffic
//! is sufficient to make a shorter path statistically indistinguishable.
//! Below threshold, LoSec is ABSENT from the UI — not disabled, absent.
//! The threshold is an implementation constant not reducible by the user.
//!
//! # Direct Mode Paths (§6.9.5)
//!
//! Two paths to direct mode:
//!
//! - **Path A (Proximity):** BLE, WiFi Direct, NFC, etc. Automatic,
//!   no confirmation needed, no ambient threshold, no red banner.
//!   Physical proximity is its own security guarantee.
//!
//! - **Path B (Network):** Requires Level 1+ trust (WoT depth 1,
//!   optionally 2) AND sufficient ambient noise. Full-screen modal
//!   before establishing.
//!
//! # Hardening Measures (§6.9.2)
//!
//! All five hardening measures apply to ALL LoSec sessions:
//! 1. Relay node rotation per session (or on timer)
//! 2. Traffic shaping to fixed bandwidth tiers
//! 3. Mandatory cover traffic injection
//! 4. Time-bounded sessions with auto re-establishment
//! 5. Ambient threshold enforcement

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::network::transport_hint::TransportType;
use crate::trust::levels::TrustLevel;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum number of active outer tunnels required for LoSec
/// to be available. Below this, there isn't enough ambient traffic
/// to hide a shorter path.
///
/// This is an implementation constant, NOT user-configurable.
pub const LOSEC_MIN_ACTIVE_TUNNELS: usize = 5;

/// Minimum traffic volume (bytes/sec) across outer tunnels for
/// LoSec to be available. Ensures sufficient ambient noise.
pub const LOSEC_MIN_TRAFFIC_VOLUME: u64 = 10_000;

/// Maximum LoSec session duration before mandatory re-establishment
/// (seconds). Limits the window for traffic analysis.
pub const LOSEC_MAX_SESSION_SECS: u64 = 3600;

/// Default LoSec session duration (seconds).
pub const LOSEC_DEFAULT_SESSION_SECS: u64 = 1800;

/// Minimum trust level for network-transport direct mode.
/// The remote peer must be at least this level.
pub const DIRECT_MODE_MIN_TRUST: TrustLevel = TrustLevel::Public;

// ---------------------------------------------------------------------------
// Connection Mode
// ---------------------------------------------------------------------------

/// The three connection security modes (§6.9).
///
/// Each provides a different tradeoff between privacy and performance.
/// The UI indicates the current mode with a colored indicator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionMode {
    /// Full mesh routing with 4-layer encryption.
    /// Maximum anonymity. No indicator (default).
    Standard,

    /// Low-security mode: 1-2 relay hops, WireGuard only.
    /// Amber indicator in UI.
    LoSec,

    /// Direct peer-to-peer: 0 hops, IP visible.
    /// Persistent red banner.
    Direct,
}

impl ConnectionMode {
    /// Number of relay hops for this mode.
    ///
    /// Standard: variable (determined by routing).
    /// LoSec: 1-2 (fixed for predictable latency).
    /// Direct: 0.
    pub fn hop_count_range(self) -> (u8, u8) {
        match self {
            Self::Standard => (1, 255), // Variable, routing decides.
            Self::LoSec => (1, 2),      // Fixed 1-2 hops.
            Self::Direct => (0, 0),     // No relay.
        }
    }

    /// Whether this mode requires the full-screen terror warning.
    ///
    /// Only Direct mode on network transports requires the warning.
    /// Proximity direct (BLE, NFC, etc.) is exempt.
    pub fn requires_terror_warning(self) -> bool {
        self == Self::Direct
    }

    /// UI indicator color name for this mode.
    pub fn indicator_color(self) -> &'static str {
        match self {
            Self::Standard => "none", // No indicator.
            Self::LoSec => "amber",
            Self::Direct => "red",
        }
    }
}

// ---------------------------------------------------------------------------
// LoSec Configuration (§6.9.6)
// ---------------------------------------------------------------------------

/// Per-service LoSec configuration.
///
/// Controls whether this node will accept LoSec connections.
/// Both flags default to false (deny-by-default policy).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[derive(Default)]
pub struct ServiceLoSecConfig {
    /// Whether to accept LoSec (1-2 hop) connections.
    /// Default: false.
    pub allow_losec: bool,

    /// Whether to accept direct (0 hop) connections.
    /// Default: false.
    /// Even when enabled, direct mode requires additional
    /// conditions (trust level, ambient noise for network transport,
    /// or proximity transport).
    pub allow_direct: bool,
}


// ---------------------------------------------------------------------------
// LoSec Request / Negotiation
// ---------------------------------------------------------------------------

/// A request to establish a LoSec or direct connection (§6.9.6).
///
/// The initiator sends this to the remote peer. The remote peer
/// checks its ServiceLoSecConfig and either accepts or denies.
/// Three conditions must all be true for establishment:
/// 1. Host-side allow_losec/allow_direct enabled
/// 2. Initiator sends this request
/// 3. Remote peer accepts
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoSecRequest {
    /// Unique session identifier.
    pub session_id: [u8; 32],

    /// Requested connection mode.
    pub mode: ConnectionMode,

    /// Requested hop count (for LoSec mode).
    /// 1 or 2. Ignored for Direct mode.
    pub hop_count: u8,

    /// Human-readable reason for requesting LoSec.
    /// Displayed in the remote peer's approval dialog.
    /// Examples: "video call", "large file transfer".
    pub reason: String,
}

/// Response to a LoSec request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoSecResponse {
    /// The session ID from the request.
    pub session_id: [u8; 32],

    /// Whether the request was accepted.
    pub accepted: bool,

    /// If rejected, a reason (optional).
    pub rejection_reason: Option<String>,
}

// ---------------------------------------------------------------------------
// LoSec Wire Protocol (§6.9.6)
// ---------------------------------------------------------------------------

/// Domain separator for LoSec request signatures (§6.9.6).
const DOMAIN_LOSEC_REQ: &[u8] = b"meshinfinity-losec-req-v1\x00";
/// Domain separator for LoSec response signatures (§6.9.6).
const DOMAIN_LOSEC_RSP: &[u8] = b"meshinfinity-losec-rsp-v1\x00";

/// LoSec negotiation error.
#[derive(Debug, PartialEq, Eq)]
pub enum LoSecError {
    /// Peer's host-side allow_losec/allow_direct is disabled.
    PolicyDenied,
    /// Requested mode is not compatible with the available ambient traffic.
    InsufficientAmbient,
    /// Invalid signature on request or response.
    SignatureInvalid,
    /// Invalid hop count for LoSec mode (must be 1 or 2).
    InvalidHopCount,
    /// Requested mode is `Direct` but only LoSec is allowed.
    DirectNotAllowed,
}

/// Build the canonical signing payload for a `LoSecRequest`.
///
/// Format: DOMAIN || session_id (32) || mode (1) || hop_count (1) || reason_len (4) || reason_utf8
fn losec_request_payload(req: &LoSecRequest) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(DOMAIN_LOSEC_REQ);
    buf.extend_from_slice(&req.session_id);
    buf.push(match req.mode {
        ConnectionMode::Standard => 0,
        ConnectionMode::LoSec => 1,
        ConnectionMode::Direct => 2,
    });
    buf.push(req.hop_count);
    let reason_bytes = req.reason.as_bytes();
    buf.extend_from_slice(&(reason_bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(reason_bytes);
    buf
}

/// Build the canonical signing payload for a `LoSecResponse`.
///
/// Format: DOMAIN || session_id (32) || accepted (1) || reason_len (4) || reason_utf8
fn losec_response_payload(rsp: &LoSecResponse) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(DOMAIN_LOSEC_RSP);
    buf.extend_from_slice(&rsp.session_id);
    buf.push(if rsp.accepted { 1 } else { 0 });
    let reason = rsp.rejection_reason.as_deref().unwrap_or("").as_bytes();
    buf.extend_from_slice(&(reason.len() as u32).to_be_bytes());
    buf.extend_from_slice(reason);
    buf
}

/// A signed LoSec request — the on-wire form sent by the initiator.
///
/// The initiator signs the request with its mask key. The responder verifies
/// before checking its ServiceLoSecConfig.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedLoSecRequest {
    pub request: LoSecRequest,
    /// Ed25519 signature by the initiator's mask key.
    /// Covers `losec_request_payload(request)`.
    pub signature: Vec<u8>,
    /// Initiator's Ed25519 public key (for verification).
    pub initiator_ed25519_pub: [u8; 32],
}

/// A signed LoSec response — the on-wire form sent by the responder.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedLoSecResponse {
    pub response: LoSecResponse,
    /// Ed25519 signature by the responder's mask key.
    pub signature: Vec<u8>,
    /// Responder's Ed25519 public key.
    pub responder_ed25519_pub: [u8; 32],
}

impl SignedLoSecRequest {
    /// Create and sign a new LoSec request.
    pub fn new(
        session_id: [u8; 32],
        mode: ConnectionMode,
        hop_count: u8,
        reason: impl Into<String>,
        signing_key: &SigningKey,
    ) -> Result<Self, LoSecError> {
        if mode == ConnectionMode::LoSec && !(1..=2).contains(&hop_count) {
            return Err(LoSecError::InvalidHopCount);
        }
        let request = LoSecRequest { session_id, mode, hop_count, reason: reason.into() };
        let payload = losec_request_payload(&request);
        let sig: Signature = signing_key.sign(&payload);
        Ok(Self {
            request,
            signature: sig.to_bytes().to_vec(),
            initiator_ed25519_pub: signing_key.verifying_key().to_bytes(),
        })
    }

    /// Verify the signature on this signed request.
    pub fn verify(&self) -> Result<(), LoSecError> {
        let vk = VerifyingKey::from_bytes(&self.initiator_ed25519_pub)
            .map_err(|_| LoSecError::SignatureInvalid)?;
        if self.signature.len() != 64 {
            return Err(LoSecError::SignatureInvalid);
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&self.signature);
        let sig = Signature::from_bytes(&sig_bytes);
        let payload = losec_request_payload(&self.request);
        vk.verify(&payload, &sig).map_err(|_| LoSecError::SignatureInvalid)
    }
}

impl SignedLoSecResponse {
    /// Create and sign a LoSec response.
    pub fn accept(session_id: [u8; 32], signing_key: &SigningKey) -> Self {
        let response = LoSecResponse { session_id, accepted: true, rejection_reason: None };
        let payload = losec_response_payload(&response);
        let sig: Signature = signing_key.sign(&payload);
        Self {
            response,
            signature: sig.to_bytes().to_vec(),
            responder_ed25519_pub: signing_key.verifying_key().to_bytes(),
        }
    }

    /// Create and sign a rejection response.
    pub fn reject(session_id: [u8; 32], reason: &str, signing_key: &SigningKey) -> Self {
        let response = LoSecResponse {
            session_id,
            accepted: false,
            rejection_reason: Some(reason.to_string()),
        };
        let payload = losec_response_payload(&response);
        let sig: Signature = signing_key.sign(&payload);
        Self {
            response,
            signature: sig.to_bytes().to_vec(),
            responder_ed25519_pub: signing_key.verifying_key().to_bytes(),
        }
    }

    /// Verify the signature on this signed response.
    pub fn verify(&self) -> Result<(), LoSecError> {
        let vk = VerifyingKey::from_bytes(&self.responder_ed25519_pub)
            .map_err(|_| LoSecError::SignatureInvalid)?;
        if self.signature.len() != 64 {
            return Err(LoSecError::SignatureInvalid);
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&self.signature);
        let sig = Signature::from_bytes(&sig_bytes);
        let payload = losec_response_payload(&self.response);
        vk.verify(&payload, &sig).map_err(|_| LoSecError::SignatureInvalid)
    }
}

/// Process an incoming LoSec request as the responder.
///
/// Checks:
/// 1. Valid signature from initiator
/// 2. Requested mode is allowed by our ServiceLoSecConfig
/// 3. Ambient traffic sufficient (if not a proximity transport)
/// 4. Hop count is valid for LoSec mode
///
/// Returns a signed response to send back.
pub fn handle_losec_request(
    signed: &SignedLoSecRequest,
    config: &ServiceLoSecConfig,
    ambient_ok: bool,
    responder_signing_key: &SigningKey,
) -> SignedLoSecResponse {
    // 1. Verify signature.
    if signed.verify().is_err() {
        return SignedLoSecResponse::reject(signed.request.session_id, "invalid signature", responder_signing_key);
    }

    let req = &signed.request;

    // 2. Check hop count.
    if req.mode == ConnectionMode::LoSec && !(1..=2).contains(&req.hop_count) {
        return SignedLoSecResponse::reject(req.session_id, "invalid hop count", responder_signing_key);
    }

    // 3. Check policy.
    match req.mode {
        ConnectionMode::LoSec => {
            if !config.allow_losec {
                return SignedLoSecResponse::reject(req.session_id, "losec not allowed", responder_signing_key);
            }
            // LoSec requires ambient traffic.
            if !ambient_ok {
                return SignedLoSecResponse::reject(req.session_id, "insufficient ambient traffic", responder_signing_key);
            }
        }
        ConnectionMode::Direct => {
            if !config.allow_direct {
                return SignedLoSecResponse::reject(req.session_id, "direct mode not allowed", responder_signing_key);
            }
        }
        ConnectionMode::Standard => {
            // Standard mode doesn't need negotiation (no-op accept).
        }
    }

    SignedLoSecResponse::accept(req.session_id, responder_signing_key)
}

// ---------------------------------------------------------------------------
// Security Properties Table (§6.9.1)
// ---------------------------------------------------------------------------

/// Security properties for each connection mode.
///
/// These are informational — used by the UI to display the
/// security tradeoffs of the current connection mode.
#[derive(Clone, Debug)]
pub struct SecurityProperties {
    /// Encryption level description.
    pub confidentiality: &'static str,
    /// Sender anonymity level.
    pub sender_anonymity: &'static str,
    /// Traffic analysis resistance level.
    pub traffic_analysis_resistance: &'static str,
    /// Relationship hiding level.
    pub relationship_hiding: &'static str,
    /// Bandwidth characteristic.
    pub bandwidth: &'static str,
    /// Typical latency.
    pub latency: &'static str,
}

/// Get the security properties for a connection mode (§6.9.1).
///
/// Used by the UI to display what the user is giving up (or gaining)
/// when switching modes.
pub fn security_properties(mode: ConnectionMode) -> SecurityProperties {
    match mode {
        ConnectionMode::Standard => SecurityProperties {
            confidentiality: "4-layer onion",
            sender_anonymity: "Strong",
            traffic_analysis_resistance: "Strong",
            relationship_hiding: "Strong",
            bandwidth: "Low",
            latency: "<100ms",
        },
        ConnectionMode::LoSec => SecurityProperties {
            confidentiality: "WireGuard",
            sender_anonymity: "Weak",
            traffic_analysis_resistance: "Weak",
            relationship_hiding: "Weak",
            bandwidth: "High",
            latency: "<50ms",
        },
        ConnectionMode::Direct => SecurityProperties {
            confidentiality: "WireGuard",
            sender_anonymity: "None",
            traffic_analysis_resistance: "None",
            relationship_hiding: "None",
            bandwidth: "Maximum",
            latency: "Minimum",
        },
    }
}

// ---------------------------------------------------------------------------
// Ambient Traffic Monitor
// ---------------------------------------------------------------------------

/// Monitors ambient traffic levels to determine LoSec availability.
///
/// LoSec is only available when there's enough ambient traffic
/// to make a shorter path statistically indistinguishable from
/// normal mesh traffic. This is measured by:
///
/// 1. Number of active outer tunnels (must be ≥ LOSEC_MIN_ACTIVE_TUNNELS)
/// 2. Traffic volume across tunnels (must be ≥ LOSEC_MIN_TRAFFIC_VOLUME)
///
/// If either condition is not met, LoSec is ABSENT from the UI.
pub struct AmbientTrafficMonitor {
    /// Number of currently active outer tunnels.
    active_tunnels: usize,

    /// Current traffic volume across all tunnels (bytes/sec, EMA).
    traffic_volume: u64,

    /// Traffic variance (standard deviation of volume measurements).
    /// Higher variance means less predictable traffic, which is
    /// better for hiding LoSec paths.
    traffic_variance: f64,
}

impl AmbientTrafficMonitor {
    /// Create a new ambient traffic monitor.
    pub fn new() -> Self {
        Self {
            active_tunnels: 0,
            traffic_volume: 0,
            traffic_variance: 0.0,
        }
    }

    /// Update the monitor with current traffic observations.
    ///
    /// Called periodically (e.g., every 5 seconds) with the latest
    /// tunnel count and measured traffic volume.
    pub fn update(&mut self, active_tunnels: usize, volume_bytes_per_sec: u64) {
        self.active_tunnels = active_tunnels;

        // Simple EMA for volume (alpha = 0.1).
        let alpha = 0.1;
        self.traffic_volume = (alpha * volume_bytes_per_sec as f64
            + (1.0 - alpha) * self.traffic_volume as f64)
            as u64;

        // Update variance using Welford's online algorithm (simplified).
        let diff = (volume_bytes_per_sec as f64) - (self.traffic_volume as f64);
        self.traffic_variance =
            (1.0 - alpha) * self.traffic_variance + alpha * diff * diff;
    }

    /// Whether LoSec is currently available based on ambient traffic.
    ///
    /// Both conditions must be met:
    /// 1. Enough active tunnels for traffic mixing
    /// 2. Enough traffic volume to hide LoSec paths
    ///
    /// If this returns false, LoSec should be ABSENT from the UI.
    pub fn losec_available(&self) -> bool {
        self.active_tunnels >= LOSEC_MIN_ACTIVE_TUNNELS
            && self.traffic_volume >= LOSEC_MIN_TRAFFIC_VOLUME
    }

    /// Current traffic volume (EMA).
    pub fn volume(&self) -> u64 {
        self.traffic_volume
    }

    /// Current tunnel count.
    pub fn tunnel_count(&self) -> usize {
        self.active_tunnels
    }
}

impl Default for AmbientTrafficMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Direct Mode Eligibility (§6.9.5)
// ---------------------------------------------------------------------------

/// Check if direct mode is available for a given transport and trust level.
///
/// Two paths to direct mode:
///
/// - **Path A (Proximity transports):** Always available. No trust
///   requirement, no ambient threshold, no confirmation dialog.
///   Physical proximity IS the security guarantee.
///
/// - **Path B (Network transports):** Requires trust (WoT depth 1+)
///   AND ambient noise. Full-screen modal confirmation required.
pub fn direct_mode_eligible(
    transport: &TransportType,
    peer_trust: TrustLevel,
    ambient_ok: bool,
) -> DirectModeEligibility {
    // Path A: proximity transports are always eligible.
    if transport.is_proximity() {
        return DirectModeEligibility::Eligible {
            needs_confirmation: false,
        };
    }

    // Path B: network transports need trust + ambient noise.
    if peer_trust >= DIRECT_MODE_MIN_TRUST && ambient_ok {
        return DirectModeEligibility::Eligible {
            needs_confirmation: true, // Full-screen terror warning.
        };
    }

    // Not eligible.
    if peer_trust < DIRECT_MODE_MIN_TRUST {
        DirectModeEligibility::IneligibleTrust
    } else {
        DirectModeEligibility::IneligibleAmbient
    }
}

/// Result of checking direct mode eligibility.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectModeEligibility {
    /// Direct mode is available.
    /// `needs_confirmation`: whether the full-screen terror warning
    /// is required (always true for network transports, false for proximity).
    Eligible { needs_confirmation: bool },

    /// Not eligible: trust level too low.
    IneligibleTrust,

    /// Not eligible: ambient traffic insufficient.
    IneligibleAmbient,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_losec_request_sign_verify() {
        use ed25519_dalek::SigningKey;
        let key = SigningKey::from_bytes(&[0x11u8; 32]);
        let session_id = [0x22u8; 32];

        let signed = SignedLoSecRequest::new(session_id, ConnectionMode::LoSec, 1, "video call", &key).unwrap();
        assert!(signed.verify().is_ok());

        // Tamper with hop count → verify fails.
        let mut tampered = signed.clone();
        tampered.request.hop_count = 3;
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn test_losec_response_sign_verify() {
        use ed25519_dalek::SigningKey;
        let key = SigningKey::from_bytes(&[0x33u8; 32]);
        let session_id = [0x44u8; 32];

        let rsp = SignedLoSecResponse::accept(session_id, &key);
        assert!(rsp.verify().is_ok());
        assert!(rsp.response.accepted);

        let rej = SignedLoSecResponse::reject(session_id, "not allowed", &key);
        assert!(rej.verify().is_ok());
        assert!(!rej.response.accepted);
    }

    #[test]
    fn test_handle_losec_request_accepted() {
        use ed25519_dalek::SigningKey;
        let initiator_key = SigningKey::from_bytes(&[0x55u8; 32]);
        let responder_key = SigningKey::from_bytes(&[0x66u8; 32]);
        let config = ServiceLoSecConfig { allow_losec: true, allow_direct: false };

        let signed = SignedLoSecRequest::new(
            [0x77u8; 32], ConnectionMode::LoSec, 1, "file transfer", &initiator_key,
        ).unwrap();

        let resp = handle_losec_request(&signed, &config, true, &responder_key);
        assert!(resp.response.accepted);
        assert!(resp.verify().is_ok());
    }

    #[test]
    fn test_handle_losec_request_denied_policy() {
        use ed25519_dalek::SigningKey;
        let initiator_key = SigningKey::from_bytes(&[0x55u8; 32]);
        let responder_key = SigningKey::from_bytes(&[0x66u8; 32]);
        let config = ServiceLoSecConfig { allow_losec: false, allow_direct: false };

        let signed = SignedLoSecRequest::new(
            [0x77u8; 32], ConnectionMode::LoSec, 1, "file transfer", &initiator_key,
        ).unwrap();

        let resp = handle_losec_request(&signed, &config, true, &responder_key);
        assert!(!resp.response.accepted);
        assert_eq!(resp.response.rejection_reason.as_deref(), Some("losec not allowed"));
    }

    #[test]
    fn test_handle_losec_request_denied_ambient() {
        use ed25519_dalek::SigningKey;
        let initiator_key = SigningKey::from_bytes(&[0x55u8; 32]);
        let responder_key = SigningKey::from_bytes(&[0x66u8; 32]);
        let config = ServiceLoSecConfig { allow_losec: true, allow_direct: false };

        let signed = SignedLoSecRequest::new(
            [0x77u8; 32], ConnectionMode::LoSec, 2, "file transfer", &initiator_key,
        ).unwrap();

        let resp = handle_losec_request(&signed, &config, false /* ambient insufficient */, &responder_key);
        assert!(!resp.response.accepted);
    }

    #[test]
    fn test_invalid_hop_count() {
        use ed25519_dalek::SigningKey;
        let key = SigningKey::from_bytes(&[0xAAu8; 32]);
        let result = SignedLoSecRequest::new([0u8; 32], ConnectionMode::LoSec, 3, "test", &key);
        assert_eq!(result.unwrap_err(), LoSecError::InvalidHopCount);
    }

    #[test]
    fn test_connection_mode_hops() {
        assert_eq!(ConnectionMode::Standard.hop_count_range(), (1, 255));
        assert_eq!(ConnectionMode::LoSec.hop_count_range(), (1, 2));
        assert_eq!(ConnectionMode::Direct.hop_count_range(), (0, 0));
    }

    #[test]
    fn test_terror_warning() {
        assert!(!ConnectionMode::Standard.requires_terror_warning());
        assert!(!ConnectionMode::LoSec.requires_terror_warning());
        assert!(ConnectionMode::Direct.requires_terror_warning());
    }

    #[test]
    fn test_losec_config_defaults() {
        let config = ServiceLoSecConfig::default();
        assert!(!config.allow_losec);
        assert!(!config.allow_direct);
    }

    #[test]
    fn test_security_properties() {
        let standard = security_properties(ConnectionMode::Standard);
        assert_eq!(standard.sender_anonymity, "Strong");

        let losec = security_properties(ConnectionMode::LoSec);
        assert_eq!(losec.sender_anonymity, "Weak");

        let direct = security_properties(ConnectionMode::Direct);
        assert_eq!(direct.sender_anonymity, "None");
    }

    #[test]
    fn test_ambient_monitor_threshold() {
        let mut monitor = AmbientTrafficMonitor::new();

        // Initially: not enough traffic.
        assert!(!monitor.losec_available());

        // Update with sufficient traffic.
        // Need multiple updates because EMA converges slowly.
        for _ in 0..50 {
            monitor.update(10, 50_000);
        }

        assert!(monitor.losec_available());
        assert!(monitor.tunnel_count() >= LOSEC_MIN_ACTIVE_TUNNELS);
    }

    #[test]
    fn test_ambient_monitor_insufficient_tunnels() {
        let mut monitor = AmbientTrafficMonitor::new();

        // High traffic but too few tunnels.
        for _ in 0..50 {
            monitor.update(2, 100_000);
        }

        assert!(!monitor.losec_available());
    }

    #[test]
    fn test_direct_mode_proximity() {
        // BLE is a proximity transport — always eligible, no confirmation.
        let result = direct_mode_eligible(
            &TransportType::BLE,
            TrustLevel::Unknown, // Trust doesn't matter for proximity.
            false,               // Ambient doesn't matter for proximity.
        );

        assert_eq!(
            result,
            DirectModeEligibility::Eligible {
                needs_confirmation: false,
            }
        );
    }

    #[test]
    fn test_direct_mode_network_trusted() {
        // Network transport with sufficient trust and ambient noise.
        let result = direct_mode_eligible(
            &TransportType::Clearnet,
            TrustLevel::Trusted,
            true, // Ambient OK.
        );

        assert_eq!(
            result,
            DirectModeEligibility::Eligible {
                needs_confirmation: true, // Terror warning required.
            }
        );
    }

    #[test]
    fn test_direct_mode_network_untrusted() {
        // Network transport without trust.
        let result = direct_mode_eligible(
            &TransportType::Clearnet,
            TrustLevel::Unknown,
            true,
        );

        assert_eq!(result, DirectModeEligibility::IneligibleTrust);
    }

    #[test]
    fn test_direct_mode_no_ambient() {
        // Network transport with trust but insufficient ambient.
        let result = direct_mode_eligible(
            &TransportType::Clearnet,
            TrustLevel::Trusted,
            false,
        );

        assert_eq!(result, DirectModeEligibility::IneligibleAmbient);
    }
}
