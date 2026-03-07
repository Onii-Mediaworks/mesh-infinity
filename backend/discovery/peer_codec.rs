//! Shared peer-id encoding helpers for discovery protocols.
//!
//! Keeps hex serialization logic in one place for mDNS TXT fields, jumpstart
//! payloads, and any future discovery transports.

use crate::core::error::{MeshInfinityError, Result};
use crate::core::PeerId;

/// Convert [`PeerId`] bytes to lowercase hex string.
pub fn peer_id_to_hex(peer_id: &PeerId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(peer_id.len() * 2);
    for &byte in peer_id {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

/// Parse lowercase/uppercase hex string into [`PeerId`].
pub fn hex_to_peer_id(hex: &str) -> Result<PeerId> {
    if hex.len() != 64 {
        return Err(MeshInfinityError::InvalidInput(format!(
            "Invalid peer ID length: expected 64 hex chars, got {}",
            hex.len()
        )));
    }

    let mut peer_id = [0u8; 32];
    for (i, slot) in peer_id.iter_mut().enumerate() {
        let idx = i * 2;
        let byte = u8::from_str_radix(&hex[idx..idx + 2], 16)
            .map_err(|e| MeshInfinityError::InvalidInput(format!("Invalid hex: {}", e)))?;
        *slot = byte;
    }

    Ok(peer_id)
}
