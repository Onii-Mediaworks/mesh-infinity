use crate::core::error::Result;

pub struct BandwidthManager {
    limit_kbps: u32,
}

impl BandwidthManager {
    pub fn new(limit_kbps: u32) -> Self {
        Self { limit_kbps }
    }

    pub fn set_limit(&mut self, limit_kbps: u32) {
        self.limit_kbps = limit_kbps;
    }

    pub fn reserve(&self, _amount_kbps: u32) -> Result<()> {
        Ok(())
    }
}
