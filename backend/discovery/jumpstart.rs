//! Jumpstart payload format for peer-map distribution.
//!
//! Jumpstart codes are compact JSON blobs carrying a small peer set to bootstrap
//! discovery in disconnected or cold-start scenarios.

use serde::{Deserialize, Serialize};

use crate::core::error::{MeshInfinityError, Result};
use crate::core::PeerInfo;

/// Portable jumpstart payload for sharing peer map snapshots out-of-band.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JumpstartPayload {
    /// Payload schema version for forward compatibility.
    pub version: u8,
    /// Included peer records.
    pub peers: Vec<PeerInfo>,
}

impl JumpstartPayload {
    /// Build payload from peer list using current schema version.
    pub fn new(peers: Vec<PeerInfo>) -> Self {
        Self { version: 1, peers }
    }

    /// Serialize payload into JSON string.
    pub fn encode_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| {
            MeshInfinityError::SerializationError(format!("jumpstart encode failed: {e}"))
        })
    }

    /// Deserialize payload from JSON string.
    pub fn decode_json(value: &str) -> Result<Self> {
        let payload: JumpstartPayload = serde_json::from_str(value).map_err(|e| {
            MeshInfinityError::SerializationError(format!("jumpstart decode failed: {e}"))
        })?;
        if payload.version != 1 {
            return Err(MeshInfinityError::InvalidInput(format!(
                "unsupported jumpstart payload version {}",
                payload.version
            )));
        }
        Ok(payload)
    }
}
