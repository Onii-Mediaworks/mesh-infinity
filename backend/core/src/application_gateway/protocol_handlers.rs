use crate::error::Result;

pub trait ProtocolHandler: Send + Sync {
    fn protocol(&self) -> &'static str;
    fn handle(&self, payload: &[u8]) -> Result<Vec<u8>>;
}

pub struct ProtocolRegistry {
    handlers: Vec<Box<dyn ProtocolHandler>>,
}

impl ProtocolRegistry {
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    pub fn register(&mut self, handler: Box<dyn ProtocolHandler>) {
        self.handlers.push(handler);
    }

    pub fn handle(&self, protocol: &str, payload: &[u8]) -> Result<Option<Vec<u8>>> {
        for handler in &self.handlers {
            if handler.protocol() == protocol {
                return handler.handle(payload).map(Some);
            }
        }
        Ok(None)
    }
}
