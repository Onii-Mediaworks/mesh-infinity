//! Registry of application ids to protocol-handler keys.
//!
//! This map lets the gateway resolve incoming app-targeted payloads to the
//! handler name/protocol implementation responsible for processing them.

use std::collections::HashMap;

use crate::core::error::Result;

pub struct AppRegistry {
    apps: HashMap<String, String>,
}

impl Default for AppRegistry {
    /// Create an empty application registry.
    fn default() -> Self {
        Self::new()
    }
}

impl AppRegistry {
    /// Construct a new empty registry.
    pub fn new() -> Self {
        Self {
            apps: HashMap::new(),
        }
    }

    /// Register or replace handler mapping for `app_id`.
    pub fn register(&mut self, app_id: &str, handler: &str) -> Result<()> {
        self.apps.insert(app_id.to_string(), handler.to_string());
        Ok(())
    }

    /// Resolve handler key for a given application id.
    pub fn handler_for(&self, app_id: &str) -> Option<&String> {
        self.apps.get(app_id)
    }
}
