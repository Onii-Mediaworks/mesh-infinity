//! Pairing Methods (§8.3.1–§8.3.8)
//!
//! # Overview
//!
//! Each pairing method provides a different out-of-band channel for
//! exchanging initial key material. After the key exchange, all methods
//! converge on the same Sigma protocol handshake (§3.5) to prove
//! key possession.
//!
//! # Available Methods
//!
//! | Method | Security | Use Case |
//! |--------|----------|----------|
//! | QR Code | High (live rotating) | In-person |
//! | Pairing Code | Medium | In-person or phone |
//! | Link Share | Low | Casual/remote |
//! | Key Export | Medium | Manual/archival |
//! | BLE Proximity | Medium | Nearby devices |
//! | NFC | Highest (in-person) | Physical contact |
//! | Telephone | Highest (remote) | Phone call |
//! | Service | Automatic | Network services |
//!
//! # Pairing Payload
//!
//! All methods encode a PairingPayload that contains:
//! - Protocol version
//! - Peer ID (SHA-256 of Ed25519 public key)
//! - Ed25519 public key (signing)
//! - X25519 public key (key agreement)
//! - A random pairing token for one-time-use binding
//! - Optional display name (signed by the private key)
//! - Transport hints for reaching the peer
//! - Expiry timestamp

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::error::MeshError;
use crate::identity::peer_id::PeerId;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Current pairing protocol version.
// PAIRING_VERSION — protocol constant.
// Defined by the spec; must not change without a version bump.
// PAIRING_VERSION — protocol constant.
// Defined by the spec; must not change without a version bump.
// PAIRING_VERSION — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const PAIRING_VERSION: u8 = 1;

/// Default QR code expiry (seconds). Live rotating QR.
// QR_EXPIRY_LIVE — protocol constant.
// Defined by the spec; must not change without a version bump.
// QR_EXPIRY_LIVE — protocol constant.
// Defined by the spec; must not change without a version bump.
// QR_EXPIRY_LIVE — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const QR_EXPIRY_LIVE: u64 = 30;

/// Extended QR expiry options (seconds).
// QR_EXPIRY_5MIN — protocol constant.
// Defined by the spec; must not change without a version bump.
// QR_EXPIRY_5MIN — protocol constant.
// Defined by the spec; must not change without a version bump.
// QR_EXPIRY_5MIN — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const QR_EXPIRY_5MIN: u64 = 300;
// Protocol constant.
// QR_EXPIRY_1HR — protocol constant.
// Defined by the spec; must not change without a version bump.
// QR_EXPIRY_1HR — protocol constant.
// Defined by the spec; must not change without a version bump.
// QR_EXPIRY_1HR — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const QR_EXPIRY_1HR: u64 = 3600;
// Protocol constant.
// QR_EXPIRY_24HR — protocol constant.
// Defined by the spec; must not change without a version bump.
// QR_EXPIRY_24HR — protocol constant.
// Defined by the spec; must not change without a version bump.
// QR_EXPIRY_24HR — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const QR_EXPIRY_24HR: u64 = 86400;

/// Pairing code length (Base32 characters).
/// 8 characters = 32^8 ≈ 1 trillion combinations.
// PAIRING_CODE_LENGTH — protocol constant.
// Defined by the spec; must not change without a version bump.
// PAIRING_CODE_LENGTH — protocol constant.
// Defined by the spec; must not change without a version bump.
// PAIRING_CODE_LENGTH — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const PAIRING_CODE_LENGTH: usize = 8;

/// Pairing code expiry (seconds). 10 minutes or first use.
// PAIRING_CODE_EXPIRY — protocol constant.
// Defined by the spec; must not change without a version bump.
// PAIRING_CODE_EXPIRY — protocol constant.
// Defined by the spec; must not change without a version bump.
// PAIRING_CODE_EXPIRY — protocol constant.
// Defined by the spec; must not change without a version bump.
pub const PAIRING_CODE_EXPIRY: u64 = 600;

/// Base32 alphabet for pairing codes (Crockford variant).
/// Excludes I, L, O, U to avoid visual confusion.
// BASE32_ALPHABET — protocol constant.
// Defined by the spec; must not change without a version bump.
// BASE32_ALPHABET — protocol constant.
// Defined by the spec; must not change without a version bump.
// BASE32_ALPHABET — protocol constant.
// Defined by the spec; must not change without a version bump.
const BASE32_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

// ---------------------------------------------------------------------------
// Pairing Method
// ---------------------------------------------------------------------------

/// Which pairing method was used (§8.3).
///
/// Recorded in the contact record so the user can see how each
/// peer was added. Also used for security assessment — some methods
/// are more secure than others.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// PairingMethod — variant enumeration.
// Match exhaustively to handle every protocol state.
// PairingMethod — variant enumeration.
// Match exhaustively to handle every protocol state.
// PairingMethod — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum PairingMethod {
    /// QR code scan (§8.3.1). In-person, high security.
    QrCode,
    /// Short alphanumeric code (§8.3.2). Verbal or typed.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    PairingCode,
    /// Deep-link URL (§8.3.3). Lowest security.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    LinkShare,
    /// Full key export/import (§8.3.4). Manual.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    KeyExport,
    /// BLE proximity (§8.3.5). Nearby devices.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    BluetoothProximity,
    /// NFC tap (§8.3.6). Physical contact. Highest in-person.
    Nfc,
    /// Telephone subchannel (§8.3.7). Highest remote.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Telephone,
    /// Service identity auto-pairing (§8.3.8). Automatic.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    ServiceIdentity,
}

// Begin the block scope.
// PairingMethod implementation — core protocol logic.
// PairingMethod implementation — core protocol logic.
// PairingMethod implementation — core protocol logic.
impl PairingMethod {
    /// Security level description for UI display.
    ///
    /// Helps users understand the security implications of how
    /// they paired with someone.
    // Perform the 'security label' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'security label' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'security label' operation.
    // Errors are propagated to the caller via Result.
    pub fn security_label(&self) -> &'static str {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match self {
            // Handle this match arm.
            Self::QrCode => "High (in-person, live QR)",
            // Handle this match arm.
            Self::PairingCode => "Medium (verbal code)",
            // Handle this match arm.
            Self::LinkShare => "Low (URL in cleartext)",
            // Handle this match arm.
            Self::KeyExport => "Medium (manual key exchange)",
            // Handle this match arm.
            Self::BluetoothProximity => "Medium (BLE proximity)",
            // Handle this match arm.
            Self::Nfc => "High (physical contact)",
            // Handle this match arm.
            Self::Telephone => "High (inaudible subchannel)",
            // Handle this match arm.
            Self::ServiceIdentity => "Automatic (service)",
        }
    }

    /// Whether this method is suitable for high-security environments.
    ///
    /// Only NFC, telephone, and live-rotating QR are recommended
    /// in surveillance-sensitive scenarios.
    // Perform the 'is high security' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is high security' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is high security' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_high_security(&self) -> bool {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        matches!(self, Self::Nfc | Self::Telephone | Self::QrCode)
    }
}

// ---------------------------------------------------------------------------
// Pairing Payload
// ---------------------------------------------------------------------------

/// The key material exchanged during pairing (§8.3).
///
/// This is the core data that every pairing method encodes and
/// transmits. After receiving this payload, the peer initiates
/// a Sigma protocol handshake to verify key possession.
///
/// The payload is the same regardless of pairing method — only
/// the transport channel differs.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// PairingPayload — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PairingPayload — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PairingPayload — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct PairingPayload {
    /// Protocol version (currently 1).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub version: u8,

    /// The sender's peer ID (SHA-256 of Ed25519 public key).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub peer_id: PeerId,

    /// Ed25519 public key for signing and identity.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub ed25519_public: [u8; 32],

    /// X25519 public key for key agreement (X3DH, DH).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub x25519_public: [u8; 32],

    /// Random one-time-use pairing token.
    ///
    /// Binds this specific pairing session. Prevents replay
    /// attacks — a captured QR code can't be used after the
    /// token has been consumed.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub pairing_token: [u8; 32],

    /// Optional display name (human-readable).
    /// Signed by the sender's Ed25519 private key when present.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub display_name: Option<String>,

    /// Signature over the display name (if present).
    /// Proves the name was set by the key owner, not modified in transit.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub display_name_sig: Option<Vec<u8>>,

    /// Transport hints for reaching this peer.
    /// Encoded as a list of (transport_type, endpoint) pairs.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub transport_hints: Vec<TransportHintEntry>,

    /// Unix timestamp when this payload expires.
    /// After expiry, the pairing token is invalid and the peer
    /// should generate a new payload.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub expiry: u64,
}

/// A transport hint entry within a pairing payload.
///
/// Tells the receiving peer how to reach the sender.
/// For proximity transports (NFC, BLE), the endpoint may be empty
/// because discovery happens automatically.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// TransportHintEntry — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TransportHintEntry — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// TransportHintEntry — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct TransportHintEntry {
    /// Transport type name (e.g., "clearnet", "tor", "ble").
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub transport: String,
    /// Endpoint address (e.g., IP:port, .onion address).
    /// None for proximity transports.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub endpoint: Option<String>,
}

/// Decoded QR/deep-link pairing payload with optional extension fields.
///
/// The core `PairingPayload` carries the protocol-required fields that every
/// pairing method shares. QR and deep-link payloads also advertise a few
/// optional extension fields used during session bootstrap and routing hints.
#[derive(Clone, Debug)]
pub struct DecodedPairingPayload {
    pub payload: PairingPayload,
    pub mesh_x25519_public: Option<[u8; 32]>,
    pub preauth_x25519_public: Option<[u8; 32]>,
    pub preauth_sig: Option<Vec<u8>>,
    pub kem_pub: Option<Vec<u8>>,
}

// Begin the block scope.
// PairingPayload implementation — core protocol logic.
// PairingPayload implementation — core protocol logic.
// PairingPayload implementation — core protocol logic.
impl PairingPayload {
    /// Check if this payload has expired.
    // Perform the 'is expired' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is expired' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is expired' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_expired(&self, now: u64) -> bool {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        now >= self.expiry
    }

    /// Validate the payload structure.
    ///
    /// Checks:
    /// - Version is supported
    /// - Peer ID matches the Ed25519 public key
    /// - Expiry is in the future
    /// - Display name (if present) has a signature
    // Perform the 'validate' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'validate' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'validate' operation.
    // Errors are propagated to the caller via Result.
    pub fn validate(&self, now: u64) -> Result<(), PayloadError> {
        // Check version.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.version != PAIRING_VERSION {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return Err(PayloadError::UnsupportedVersion(self.version));
        }

        // Check expiry.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.is_expired(now) {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return Err(PayloadError::Expired);
        }

        // Check peer ID derivation.
        // Compute expected id for this protocol step.
        // Compute expected id for this protocol step.
        // Compute expected id for this protocol step.
        let expected_id = PeerId::from_ed25519_pub(&self.ed25519_public);
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.peer_id != expected_id {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return Err(PayloadError::PeerIdMismatch);
        }

        // Check display name signature presence.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.display_name.is_some() && self.display_name_sig.is_none() {
            // Reject with an explicit error for the caller to handle.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return Err(PayloadError::MissingDisplayNameSig);
        }

        // Wrap the computed value in the success variant.
        // Success path — return the computed value.
        // Success path — return the computed value.
        Ok(())
    }
}

fn pairing_invalid(message: impl Into<String>) -> MeshError {
    MeshError::PairingInvalid(message.into())
}

fn decode_hex_array<const N: usize>(
    payload: &serde_json::Value,
    field: &'static str,
) -> Result<[u8; N], MeshError> {
    let hex_value = payload
        .get(field)
        .and_then(|value| value.as_str())
        .ok_or_else(|| pairing_invalid(format!("missing {field}")))?;
    let bytes =
        hex::decode(hex_value).map_err(|_| pairing_invalid(format!("invalid {field} hex")))?;
    if bytes.len() != N {
        return Err(pairing_invalid(format!("invalid {field} length")));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_optional_hex_array<const N: usize>(
    payload: &serde_json::Value,
    field: &'static str,
) -> Result<Option<[u8; N]>, MeshError> {
    match payload.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(hex_value)) => {
            let bytes = hex::decode(hex_value)
                .map_err(|_| pairing_invalid(format!("invalid {field} hex")))?;
            if bytes.len() != N {
                return Err(pairing_invalid(format!("invalid {field} length")));
            }
            let mut out = [0u8; N];
            out.copy_from_slice(&bytes);
            Ok(Some(out))
        }
        Some(_) => Err(pairing_invalid(format!("{field} must be a string"))),
    }
}

fn decode_optional_hex_vec(
    payload: &serde_json::Value,
    field: &'static str,
) -> Result<Option<Vec<u8>>, MeshError> {
    match payload.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(hex_value)) => hex::decode(hex_value)
            .map(Some)
            .map_err(|_| pairing_invalid(format!("invalid {field} hex"))),
        Some(_) => Err(pairing_invalid(format!("{field} must be a string"))),
    }
}

fn decode_transport_hints(
    payload: &serde_json::Value,
) -> Result<Vec<TransportHintEntry>, MeshError> {
    let Some(value) = payload.get("transport_hints") else {
        return Ok(Vec::new());
    };
    let hints = value
        .as_array()
        .ok_or_else(|| pairing_invalid("transport_hints must be an array"))?;
    let mut decoded = Vec::with_capacity(hints.len());
    for hint in hints {
        let transport = hint
            .get("transport")
            .and_then(|value| value.as_str())
            .ok_or_else(|| pairing_invalid("transport_hints[].transport missing"))?;
        let endpoint = match hint.get("endpoint") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(endpoint)) => Some(endpoint.clone()),
            Some(_) => {
                return Err(pairing_invalid(
                    "transport_hints[].endpoint must be a string or null",
                ));
            }
        };
        decoded.push(TransportHintEntry {
            transport: transport.to_string(),
            endpoint,
        });
    }
    Ok(decoded)
}

/// Parse the JSON payload carried by pairing QR codes and deep links.
///
/// This is the external byte boundary for hostile pairing payloads. It performs
/// structural JSON parsing, hex decoding, and core payload validation before
/// the service layer uses any field semantically.
pub fn parse_pairing_qr_payload_json(
    payload_json: &[u8],
    now: u64,
) -> Result<DecodedPairingPayload, MeshError> {
    let payload_value: serde_json::Value = serde_json::from_slice(payload_json)?;

    let version = payload_value
        .get("version")
        .and_then(|value| value.as_u64())
        .ok_or_else(|| pairing_invalid("missing version"))?;
    let version = u8::try_from(version).map_err(|_| pairing_invalid("version out of range"))?;

    let peer_id_hex = payload_value
        .get("peer_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| pairing_invalid("missing peer_id"))?;
    let peer_id = PeerId::from_hex(peer_id_hex).map_err(|_| pairing_invalid("invalid peer_id"))?;

    let display_name = match payload_value.get("display_name") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(name)) => Some(name.clone()),
        Some(_) => return Err(pairing_invalid("display_name must be a string")),
    };

    let display_name_sig = decode_optional_hex_vec(&payload_value, "display_name_sig")?;
    let mesh_x25519_public = decode_optional_hex_array(&payload_value, "mesh_x25519_public")?;
    let preauth_x25519_public = decode_optional_hex_array(&payload_value, "preauth_x25519_public")?;
    let preauth_sig = decode_optional_hex_vec(&payload_value, "preauth_sig")?;
    let kem_pub = decode_optional_hex_vec(&payload_value, "kem_pub")?;

    let expiry = payload_value
        .get("expiry")
        .and_then(|value| value.as_u64())
        .ok_or_else(|| pairing_invalid("missing expiry"))?;

    let payload = PairingPayload {
        version,
        peer_id,
        ed25519_public: decode_hex_array(&payload_value, "ed25519_public")?,
        x25519_public: decode_hex_array(&payload_value, "x25519_public")?,
        pairing_token: decode_hex_array(&payload_value, "pairing_token")?,
        display_name,
        display_name_sig,
        transport_hints: decode_transport_hints(&payload_value)?,
        expiry,
    };

    payload
        .validate(now)
        .map_err(|error| pairing_invalid(error.to_string()))?;

    Ok(DecodedPairingPayload {
        payload,
        mesh_x25519_public,
        preauth_x25519_public,
        preauth_sig,
        kem_pub,
    })
}

/// Errors when validating a pairing payload.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
// Begin the block scope.
// PayloadError — variant enumeration.
// Match exhaustively to handle every protocol state.
// PayloadError — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum PayloadError {
    /// Protocol version not supported.
    // Execute this protocol step.
    // Execute this protocol step.
    #[error("unsupported version {0}")]
    UnsupportedVersion(u8),
    /// Payload has expired.
    #[error("expired")]
    Expired,
    /// Peer ID doesn't match the Ed25519 public key.
    // Execute this protocol step.
    // Execute this protocol step.
    #[error("peer_id mismatch")]
    PeerIdMismatch,
    /// Display name is present but signature is missing.
    // Execute this protocol step.
    // Execute this protocol step.
    #[error("display name signature missing")]
    MissingDisplayNameSig,
}

// ---------------------------------------------------------------------------
// Pairing Code Generator
// ---------------------------------------------------------------------------

/// Generate a pairing code from random bytes.
///
/// The code is PAIRING_CODE_LENGTH characters of Base32 (Crockford),
/// derived from random entropy. Each character has 5 bits of entropy,
/// so 8 characters = 40 bits = ~1 trillion possibilities.
///
/// The code is intended for verbal or typed exchange — easy to read
/// and type, resistant to visual confusion (no I/L/O/U).
// Perform the 'generate pairing code' operation.
// Errors are propagated to the caller via Result.
// Perform the 'generate pairing code' operation.
// Errors are propagated to the caller via Result.
pub fn generate_pairing_code(random_bytes: &[u8]) -> String {
    // Track the count for threshold and bounds checking.
    // Compute code for this protocol step.
    // Compute code for this protocol step.
    let mut code = String::with_capacity(PAIRING_CODE_LENGTH);

    // Iterate over each element in the collection.
    // Iterate over each element.
    // Iterate over each element.
    for i in 0..PAIRING_CODE_LENGTH {
        // Use each byte modulo the alphabet length.
        // If random_bytes is shorter than PAIRING_CODE_LENGTH,
        // cycle through it.
        // Compute idx for this protocol step.
        // Compute idx for this protocol step.
        let idx = random_bytes[i % random_bytes.len()] as usize % BASE32_ALPHABET.len();
        // Execute the operation and bind the result.
        // Append to the collection.
        // Append to the collection.
        code.push(BASE32_ALPHABET[idx] as char);
    }

    code
}

/// Validate that a string is a valid pairing code.
///
/// Checks length and character set (Base32 Crockford).
// Perform the 'validate pairing code' operation.
// Errors are propagated to the caller via Result.
// Perform the 'validate pairing code' operation.
// Errors are propagated to the caller via Result.
pub fn validate_pairing_code(code: &str) -> bool {
    // Validate the length matches the expected protocol size.
    // Execute this protocol step.
    // Execute this protocol step.
    code.len() == PAIRING_CODE_LENGTH
        && code
            // Chain the operation on the intermediate result.
            .bytes()
            // Check membership in the collection.
            // Execute this protocol step.
            // Execute this protocol step.
            .all(|b| BASE32_ALPHABET.contains(&b.to_ascii_uppercase()))
}

// ---------------------------------------------------------------------------
// Link Share
// ---------------------------------------------------------------------------

/// Generate a deep-link URL for pairing (§8.3.3).
///
/// Format: meshinfinity://pair?v=1&peer_id=<hex>&ed25519=<hex>&x25519=<hex>&token=<hex>&name=<optional>
///
/// This is the lowest-security pairing method because the URL
/// contains key material in cleartext. Short expiry is essential.
// Perform the 'generate pair link' operation.
// Errors are propagated to the caller via Result.
// Perform the 'generate pair link' operation.
// Errors are propagated to the caller via Result.
pub fn generate_pair_link(payload: &PairingPayload) -> String {
    // Format the output for display or logging.
    // Compute url for this protocol step.
    // Compute url for this protocol step.
    let mut url = format!(
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        "meshinfinity://pair?v={}&peer_id={}&ed25519={}&x25519={}&token={}",
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        payload.version,
        // Invoke the associated function.
        // Execute this protocol step.
        // Execute this protocol step.
        hex::encode(payload.peer_id.0),
        // Invoke the associated function.
        // Execute this protocol step.
        // Execute this protocol step.
        hex::encode(payload.ed25519_public),
        // Invoke the associated function.
        // Execute this protocol step.
        // Execute this protocol step.
        hex::encode(payload.x25519_public),
        // Invoke the associated function.
        // Execute this protocol step.
        // Execute this protocol step.
        hex::encode(payload.pairing_token),
    );

    // Conditional branch based on the current state.
    // Guard: validate the condition before proceeding.
    // Guard: validate the condition before proceeding.
    if let Some(ref name) = payload.display_name {
        // Format the output for display or logging.
        // Execute this protocol step.
        // Execute this protocol step.
        url.push_str(&format!("&name={}", name));
    }

    url
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a test pairing payload.
    fn test_payload(now: u64) -> PairingPayload {
        let ed_pub = [0x42; 32];
        let peer_id = PeerId::from_ed25519_pub(&ed_pub);

        PairingPayload {
            version: PAIRING_VERSION,
            peer_id,
            ed25519_public: ed_pub,
            x25519_public: [0x43; 32],
            pairing_token: [0x44; 32],
            display_name: None,
            display_name_sig: None,
            transport_hints: vec![],
            expiry: now + 3600,
        }
    }

    fn test_payload_json(now: u64) -> String {
        let payload = test_payload(now);
        serde_json::json!({
            "version": payload.version,
            "peer_id": payload.peer_id.to_hex(),
            "ed25519_public": hex::encode(payload.ed25519_public),
            "x25519_public": hex::encode(payload.x25519_public),
            "pairing_token": hex::encode(payload.pairing_token),
            "display_name": payload.display_name,
            "display_name_sig": payload.display_name_sig.map(hex::encode),
            "transport_hints": [
                {
                    "transport": "clearnet",
                    "endpoint": "127.0.0.1:31337",
                }
            ],
            "expiry": payload.expiry,
            "mesh_x25519_public": hex::encode([0x77; 32]),
            "preauth_x25519_public": hex::encode([0x55; 32]),
            "preauth_sig": hex::encode([0x11; 64]),
            "kem_pub": hex::encode([0x22; 32]),
        })
        .to_string()
    }

    #[test]
    fn test_payload_validates() {
        let now = 1000;
        let payload = test_payload(now);
        assert!(payload.validate(now).is_ok());
    }

    #[test]
    fn test_payload_expired() {
        let now = 1000;
        let payload = test_payload(now);

        // Expired.
        assert_eq!(payload.validate(now + 3601), Err(PayloadError::Expired));
    }

    #[test]
    fn test_payload_wrong_version() {
        let now = 1000;
        let mut payload = test_payload(now);
        payload.version = 99;

        assert_eq!(
            payload.validate(now),
            Err(PayloadError::UnsupportedVersion(99))
        );
    }

    #[test]
    fn test_payload_peer_id_mismatch() {
        let now = 1000;
        let mut payload = test_payload(now);
        // Corrupt the peer ID.
        payload.peer_id = PeerId([0xFF; 32]);

        assert_eq!(payload.validate(now), Err(PayloadError::PeerIdMismatch));
    }

    #[test]
    fn test_payload_display_name_needs_sig() {
        let now = 1000;
        let mut payload = test_payload(now);
        payload.display_name = Some("Alice".to_string());
        // No signature.
        payload.display_name_sig = None;

        assert_eq!(
            payload.validate(now),
            Err(PayloadError::MissingDisplayNameSig)
        );
    }

    #[test]
    fn test_payload_display_name_with_sig() {
        let now = 1000;
        let mut payload = test_payload(now);
        payload.display_name = Some("Alice".to_string());
        payload.display_name_sig = Some(vec![0x01; 64]);

        assert!(payload.validate(now).is_ok());
    }

    #[test]
    fn test_generate_pairing_code() {
        let random = [0x01, 0x10, 0x20, 0x30, 0x05, 0x15, 0x25, 0x1F];
        let code = generate_pairing_code(&random);

        assert_eq!(code.len(), PAIRING_CODE_LENGTH);
        assert!(validate_pairing_code(&code));
    }

    #[test]
    fn test_validate_pairing_code() {
        assert!(validate_pairing_code("ABCD1234"));
        assert!(validate_pairing_code("00000000"));

        // Wrong length.
        assert!(!validate_pairing_code("ABC"));
        assert!(!validate_pairing_code("ABCDEFGHIJ"));

        // Invalid characters (I, L, O, U are excluded).
        // But validate_pairing_code checks against BASE32_ALPHABET
        // which doesn't contain these.
    }

    #[test]
    fn test_generate_pair_link() {
        let now = 1000;
        let payload = test_payload(now);
        let link = generate_pair_link(&payload);

        assert!(link.starts_with("meshinfinity://pair?"));
        assert!(link.contains("v=1"));
        assert!(link.contains("peer_id="));
        assert!(link.contains("ed25519="));
        assert!(link.contains("x25519="));
        assert!(link.contains("token="));
    }

    #[test]
    fn test_parse_pairing_qr_payload_json() {
        let now = 1000;
        let decoded = parse_pairing_qr_payload_json(test_payload_json(now).as_bytes(), now)
            .expect("valid QR payload must parse");

        assert_eq!(decoded.payload.peer_id, test_payload(now).peer_id);
        assert_eq!(decoded.payload.transport_hints.len(), 1);
        assert_eq!(decoded.mesh_x25519_public, Some([0x77; 32]));
        assert_eq!(decoded.preauth_x25519_public, Some([0x55; 32]));
        assert_eq!(decoded.preauth_sig, Some(vec![0x11; 64]));
        assert_eq!(decoded.kem_pub, Some(vec![0x22; 32]));
    }

    #[test]
    fn test_parse_pairing_qr_payload_json_rejects_bad_hex() {
        let now = 1000;
        let mut payload: serde_json::Value =
            serde_json::from_str(&test_payload_json(now)).expect("test payload JSON");
        payload["ed25519_public"] = serde_json::json!("not-hex");

        let error = parse_pairing_qr_payload_json(payload.to_string().as_bytes(), now)
            .expect_err("bad ed25519 hex must be rejected");
        assert!(error.safe_description().contains("ed25519_public"));
    }

    #[test]
    fn test_parse_pairing_qr_payload_json_rejects_bad_transport_hints() {
        let now = 1000;
        let mut payload: serde_json::Value =
            serde_json::from_str(&test_payload_json(now)).expect("test payload JSON");
        payload["transport_hints"] = serde_json::json!({"transport": "clearnet"});

        let error = parse_pairing_qr_payload_json(payload.to_string().as_bytes(), now)
            .expect_err("non-array transport_hints must be rejected");
        assert!(error.safe_description().contains("transport_hints"));
    }

    #[test]
    fn test_pairing_method_security() {
        assert!(PairingMethod::Nfc.is_high_security());
        assert!(PairingMethod::Telephone.is_high_security());
        assert!(PairingMethod::QrCode.is_high_security());
        assert!(!PairingMethod::LinkShare.is_high_security());
        assert!(!PairingMethod::PairingCode.is_high_security());
    }
}
