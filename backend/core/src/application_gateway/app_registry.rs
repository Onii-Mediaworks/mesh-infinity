use std::collections::HashMap;

use crate::error::Result;

pub struct AppRegistry {
    apps: HashMap<String, String>,
}

impl AppRegistry {
    pub fn new() -> Self {
        Self {
            apps: HashMap::new(),
        }
    }

    pub fn register(&mut self, app_id: &str, handler: &str) -> Result<()> {
        self.apps.insert(app_id.to_string(), handler.to_string());
        Ok(())
    }

    pub fn handler_for(&self, app_id: &str) -> Option<&String> {
        self.apps.get(app_id)
    }
}
