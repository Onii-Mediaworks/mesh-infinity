//! Service Health Monitoring (§12.8)
//!
//! Services send periodic health pings (every 60 seconds).
//! Records are stale after 5 minutes without refresh.
//! Mirror announcements allow distributed service availability.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Health ping interval (seconds).
pub const HEALTH_PING_INTERVAL_SECS: u64 = 60;

/// Health record staleness threshold (seconds).
pub const HEALTH_STALE_SECS: u64 = 300;

// ---------------------------------------------------------------------------
// Service Mirror Announcement
// ---------------------------------------------------------------------------

/// Announcement that a mirror is available for a service.
///
/// Mirrors provide distributed service availability.
/// Clients prefer mirrors with higher capacity scores.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceMirrorAnnouncement {
    /// Which service this mirror serves.
    pub service_id: [u8; 16],
    /// Version of the service record this mirror tracks.
    pub record_version: u64,
    /// Mirror's device address.
    pub mirror_addr: [u8; 32],
    /// Mirror's port (if different from service default).
    pub mirror_port: Option<u32>,
    /// Relative capacity hint (0-100). 0 = backend down.
    pub capacity: u8,
    /// Last alive timestamp.
    pub last_alive: u64,
    /// Ed25519 signature.
    pub sig: Vec<u8>,
}

impl ServiceMirrorAnnouncement {
    /// Whether this mirror is considered healthy.
    pub fn is_healthy(&self, now: u64) -> bool {
        self.capacity > 0
            && now.saturating_sub(self.last_alive) <= HEALTH_STALE_SECS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mirror_health() {
        let mirror = ServiceMirrorAnnouncement {
            service_id: [0x01; 16],
            record_version: 1,
            mirror_addr: [0x02; 32],
            mirror_port: None,
            capacity: 80,
            last_alive: 1000,
            sig: vec![0x42; 64],
        };

        assert!(mirror.is_healthy(1000));
        assert!(mirror.is_healthy(1000 + HEALTH_STALE_SECS));
        assert!(!mirror.is_healthy(1000 + HEALTH_STALE_SECS + 1));
    }

    #[test]
    fn test_mirror_zero_capacity() {
        let mirror = ServiceMirrorAnnouncement {
            service_id: [0x01; 16],
            record_version: 1,
            mirror_addr: [0x02; 32],
            mirror_port: None,
            capacity: 0, // Backend down.
            last_alive: 1000,
            sig: vec![0x42; 64],
        };

        assert!(!mirror.is_healthy(1000));
    }
}
