use crate::core::error::Result;

pub struct PolicyEngine;

impl PolicyEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn evaluate(&self, _policy: &str, _context: &str) -> Result<bool> {
        Ok(true)
    }
}
