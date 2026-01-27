use std::net::SocketAddr;

use crate::error::Result;

pub struct NatTraversal;

impl NatTraversal {
    pub fn new() -> Self {
        Self
    }

    pub fn punch_hole(&self, _remote: SocketAddr) -> Result<()> {
        Ok(())
    }
}
