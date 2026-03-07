//! Sliding-window bandwidth limiter for exit-node routing decisions.
//!
//! Tracks recent byte reservations over a short window and rejects new traffic
//! reservations when the configured kbps limit would be exceeded.

use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::core::error::{MeshInfinityError, Result};

#[derive(Clone)]
struct BandwidthSample {
    timestamp: Instant,
    bytes: u64,
}

pub struct BandwidthManager {
    limit_kbps: Arc<RwLock<u32>>,
    current_usage_bytes: Arc<RwLock<u64>>,
    samples: Arc<RwLock<VecDeque<BandwidthSample>>>,
    window_duration: Duration,
}

impl BandwidthManager {
    /// Create limiter with an initial kilobits-per-second cap.
    pub fn new(limit_kbps: u32) -> Self {
        Self {
            limit_kbps: Arc::new(RwLock::new(limit_kbps)),
            current_usage_bytes: Arc::new(RwLock::new(0)),
            samples: Arc::new(RwLock::new(VecDeque::new())),
            window_duration: Duration::from_secs(1), // 1 second window for rate limiting
        }
    }

    /// Update runtime bandwidth cap in kbps.
    pub fn set_limit(&mut self, limit_kbps: u32) {
        if let Ok(mut limit) = self.limit_kbps.write() {
            *limit = limit_kbps;
        }
    }

    /// Reserve `amount_bytes` within the active window or return limit error.
    ///
    /// Callers should invoke this before forwarding payload through an exit
    /// gateway to enforce configured throughput policy.
    pub fn reserve(&self, amount_bytes: u64) -> Result<()> {
        // Clean old samples outside the window
        self.cleanup_old_samples()?;

        // Calculate current usage in the window
        let current_rate_kbps = self.calculate_current_rate()?;

        // Get the limit
        let limit = self
            .limit_kbps
            .read()
            .map_err(|e| MeshInfinityError::LockError(format!("Limit lock poisoned: {}", e)))?;

        // Check if we have bandwidth available
        let amount_kbps = (amount_bytes * 8) / 1024; // Convert bytes to kilobits

        if current_rate_kbps + amount_kbps > (*limit as u64) {
            return Err(MeshInfinityError::ResourceUnavailable);
        }

        // Reserve the bandwidth
        let mut samples = self
            .samples
            .write()
            .map_err(|e| MeshInfinityError::LockError(format!("Samples lock poisoned: {}", e)))?;

        samples.push_back(BandwidthSample {
            timestamp: Instant::now(),
            bytes: amount_bytes,
        });

        let mut usage = self
            .current_usage_bytes
            .write()
            .map_err(|e| MeshInfinityError::LockError(format!("Usage lock poisoned: {}", e)))?;
        *usage += amount_bytes;

        Ok(())
    }

    /// Return currently accounted usage (kbps) in the active sliding window.
    pub fn get_current_usage_kbps(&self) -> Result<u64> {
        self.cleanup_old_samples()?;
        self.calculate_current_rate()
    }

    /// Return configured kbps limit.
    pub fn get_limit(&self) -> Result<u32> {
        let limit = self
            .limit_kbps
            .read()
            .map_err(|e| MeshInfinityError::LockError(format!("Limit lock poisoned: {}", e)))?;
        Ok(*limit)
    }

    /// Remove expired samples and decrement tracked usage accordingly.
    fn cleanup_old_samples(&self) -> Result<()> {
        let mut samples = self
            .samples
            .write()
            .map_err(|e| MeshInfinityError::LockError(format!("Samples lock poisoned: {}", e)))?;

        let now = Instant::now();
        while let Some(sample) = samples.front() {
            if now.duration_since(sample.timestamp) > self.window_duration {
                if let Some(old) = samples.pop_front() {
                    let mut usage = self.current_usage_bytes.write().map_err(|e| {
                        MeshInfinityError::LockError(format!("Usage lock poisoned: {}", e))
                    })?;
                    *usage = usage.saturating_sub(old.bytes);
                }
            } else {
                break;
            }
        }
        Ok(())
    }

    /// Compute aggregate kbps from currently retained samples.
    fn calculate_current_rate(&self) -> Result<u64> {
        let samples = self
            .samples
            .read()
            .map_err(|e| MeshInfinityError::LockError(format!("Samples lock poisoned: {}", e)))?;

        if samples.is_empty() {
            return Ok(0);
        }

        let total_bytes: u64 = samples.iter().map(|s| s.bytes).sum();
        // Convert bytes per second to kilobits per second
        let kbps = (total_bytes * 8) / 1024;
        Ok(kbps)
    }
}
