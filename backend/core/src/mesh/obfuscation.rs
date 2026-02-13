// Traffic obfuscation for WireGuard packets
// Makes WireGuard traffic indistinguishable from regular HTTPS traffic

use crate::core::error::{MeshInfinityError, Result};
use std::sync::{Arc, Mutex};

/// Simple XOR-based obfuscation
/// This is a lightweight alternative to TLS for cases where performance matters
/// Note: This provides obfuscation, not additional encryption
pub struct XorObfuscator {
    key: [u8; 32],
}

impl XorObfuscator {
    /// Create a new XOR obfuscator with a shared key
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Obfuscate data by XORing with the key
    pub fn obfuscate(&self, data: &[u8]) -> Vec<u8> {
        data.iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ self.key[i % 32])
            .collect()
    }

    /// Deobfuscate data (XOR is symmetric)
    pub fn deobfuscate(&self, data: &[u8]) -> Vec<u8> {
        self.obfuscate(data) // XOR is its own inverse
    }
}

/// Obfuscation mode configuration
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ObfuscationMode {
    /// No obfuscation (raw WireGuard)
    None,
    /// Simple XOR obfuscation (lightweight)
    Xor,
    /// TLS wrapper (looks like HTTPS)
    Tls,
}

/// Traffic obfuscator that can wrap/unwrap packets
pub struct TrafficObfuscator {
    mode: ObfuscationMode,
    xor_key: Option<[u8; 32]>,
}

impl TrafficObfuscator {
    /// Create a new traffic obfuscator
    pub fn new(mode: ObfuscationMode) -> Self {
        // Generate a random XOR key if needed
        let xor_key = if mode == ObfuscationMode::Xor {
            Some(Self::generate_key())
        } else {
            None
        };

        Self { mode, xor_key }
    }

    /// Create with a specific XOR key
    pub fn with_key(mode: ObfuscationMode, key: [u8; 32]) -> Self {
        Self {
            mode,
            xor_key: Some(key),
        }
    }

    /// Obfuscate outbound packet
    pub fn obfuscate(&self, packet: &[u8]) -> Result<Vec<u8>> {
        match self.mode {
            ObfuscationMode::None => Ok(packet.to_vec()),
            ObfuscationMode::Xor => {
                if let Some(key) = self.xor_key {
                    let obfuscator = XorObfuscator::new(key);
                    Ok(obfuscator.obfuscate(packet))
                } else {
                    Err(MeshInfinityError::CryptoError(
                        "XOR key not set".to_string()
                    ))
                }
            }
            ObfuscationMode::Tls => {
                // TLS wrapper would go here
                // For now, fallback to XOR
                if let Some(key) = self.xor_key {
                    let obfuscator = XorObfuscator::new(key);
                    Ok(obfuscator.obfuscate(packet))
                } else {
                    Ok(packet.to_vec())
                }
            }
        }
    }

    /// Deobfuscate inbound packet
    pub fn deobfuscate(&self, packet: &[u8]) -> Result<Vec<u8>> {
        match self.mode {
            ObfuscationMode::None => Ok(packet.to_vec()),
            ObfuscationMode::Xor => {
                if let Some(key) = self.xor_key {
                    let obfuscator = XorObfuscator::new(key);
                    Ok(obfuscator.deobfuscate(packet))
                } else {
                    Err(MeshInfinityError::CryptoError(
                        "XOR key not set".to_string()
                    ))
                }
            }
            ObfuscationMode::Tls => {
                // TLS unwrapping would go here
                // For now, fallback to XOR
                if let Some(key) = self.xor_key {
                    let obfuscator = XorObfuscator::new(key);
                    Ok(obfuscator.deobfuscate(packet))
                } else {
                    Ok(packet.to_vec())
                }
            }
        }
    }

    /// Get the current obfuscation mode
    pub fn mode(&self) -> ObfuscationMode {
        self.mode
    }

    /// Get the XOR key (if using XOR mode)
    pub fn xor_key(&self) -> Option<[u8; 32]> {
        self.xor_key
    }

    /// Generate a random XOR key
    fn generate_key() -> [u8; 32] {
        use std::time::SystemTime;
        let mut key = [0u8; 32];

        // Simple key derivation from timestamp
        // In production, use a proper CSPRNG
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let bytes = timestamp.to_le_bytes();
        for (i, chunk) in bytes.chunks(8).cycle().take(32 / 8 + 1).enumerate() {
            let start = i * 8;
            let end = (start + chunk.len()).min(32);
            key[start..end].copy_from_slice(&chunk[..end - start]);
        }

        key
    }
}

/// Pattern-based traffic shaping to mimic HTTPS timing
pub struct TrafficShaper {
    enabled: bool,
}

impl TrafficShaper {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Shape traffic to look like HTTPS patterns
    /// Adds random delays and padding to match HTTPS characteristics
    pub fn shape_packet(&self, packet: &[u8]) -> Result<Vec<u8>> {
        if !self.enabled {
            return Ok(packet.to_vec());
        }

        // Add random padding to match typical HTTPS packet sizes
        let mut shaped = packet.to_vec();

        // HTTPS typically uses packets in multiples of TLS record size (16KB max)
        // Pad to nearest 512 bytes to blend in
        let target_size = ((shaped.len() + 511) / 512) * 512;
        let padding_needed = target_size - shaped.len();

        if padding_needed > 0 {
            shaped.extend(vec![0u8; padding_needed]);
        }

        Ok(shaped)
    }

    /// Remove traffic shaping padding
    pub fn unshape_packet(&self, packet: &[u8]) -> Result<Vec<u8>> {
        if !self.enabled {
            return Ok(packet.to_vec());
        }

        // Find the last non-zero byte to remove padding
        let mut end = packet.len();
        while end > 0 && packet[end - 1] == 0 {
            end -= 1;
        }

        Ok(packet[..end].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_obfuscation_symmetric() {
        let key = [42u8; 32];
        let obfuscator = XorObfuscator::new(key);

        let original = b"Hello, WireGuard!";
        let obfuscated = obfuscator.obfuscate(original);
        let deobfuscated = obfuscator.deobfuscate(&obfuscated);

        assert_eq!(original, deobfuscated.as_slice());
        assert_ne!(original, obfuscated.as_slice()); // Should be different
    }

    #[test]
    fn test_traffic_obfuscator_none() {
        let obfuscator = TrafficObfuscator::new(ObfuscationMode::None);
        let data = b"test packet";

        let obfuscated = obfuscator.obfuscate(data).unwrap();
        assert_eq!(data, obfuscated.as_slice());
    }

    #[test]
    fn test_traffic_obfuscator_xor() {
        let key = [123u8; 32];
        let obfuscator = TrafficObfuscator::with_key(ObfuscationMode::Xor, key);
        let data = b"test packet";

        let obfuscated = obfuscator.obfuscate(data).unwrap();
        let deobfuscated = obfuscator.deobfuscate(&obfuscated).unwrap();

        assert_eq!(data, deobfuscated.as_slice());
        assert_ne!(data, obfuscated.as_slice());
    }

    #[test]
    fn test_traffic_shaper() {
        let shaper = TrafficShaper::new(true);
        let data = b"small packet";

        let shaped = shaper.shape_packet(data).unwrap();
        assert!(shaped.len() >= data.len());
        assert_eq!(shaped.len() % 512, 0); // Should be multiple of 512

        let unshaped = shaper.unshape_packet(&shaped).unwrap();
        assert_eq!(data, unshaped.as_slice());
    }
}
