use std::net::IpAddr;

use crate::core::error::Result;

pub struct TrafficRouter;

impl TrafficRouter {
    pub fn new() -> Self {
        Self
    }

    pub fn route(&self, _destination: IpAddr, _payload: &[u8]) -> Result<()> {
        Ok(())
    }
}
