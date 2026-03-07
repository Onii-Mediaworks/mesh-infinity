//! Protocol-handler abstraction for application gateway payload dispatch.
//!
//! Defines a trait implemented by app-specific protocol processors and a small
//! registry used to find a matching handler by protocol key.

use crate::core::error::Result;

pub trait ProtocolHandler: Send + Sync {
    /// Return protocol identifier used for dispatch matching.
    fn protocol(&self) -> &'static str;
    /// Process payload bytes and return transformed/response bytes.
    fn handle(&self, payload: &[u8]) -> Result<Vec<u8>>;
}

pub struct ProtocolRegistry {
    handlers: Vec<Box<dyn ProtocolHandler>>,
}

impl Default for ProtocolRegistry {
    /// Create an empty protocol registry.
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolRegistry {
    /// Construct an empty registry with no protocol handlers installed.
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    /// Register a handler implementation for protocol dispatch.
    pub fn register(&mut self, handler: Box<dyn ProtocolHandler>) {
        self.handlers.push(handler);
    }

    /// Dispatch payload to the first handler whose protocol key matches.
    ///
    /// Returns `Ok(None)` when no handler exists for the requested protocol.
    pub fn handle(&self, protocol: &str, payload: &[u8]) -> Result<Option<Vec<u8>>> {
        for handler in &self.handlers {
            if handler.protocol() == protocol {
                return handler.handle(payload).map(Some);
            }
        }
        Ok(None)
    }
}
