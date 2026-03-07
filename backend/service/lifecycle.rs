//! Service lifecycle and runtime mode transitions.
//!
//! This module owns worker-thread lifecycle and mode-driven start/stop behavior.

use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

use crate::core::error::Result;

use super::{MeshInfinityService, NodeMode};

impl MeshInfinityService {
    /// Start service runtime workers and transition to running state.
    pub fn start(&self) -> Result<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        let mut worker_slot = self.routing_worker.lock().unwrap();
        if worker_slot.is_some() {
            return Ok(());
        }

        let running = std::sync::Arc::clone(&self.running);
        let router = std::sync::Arc::clone(&self.message_router);
        *worker_slot = Some(thread::spawn(move || {
            while running.load(Ordering::Relaxed) {
                let _ = router.process_queue();
                thread::sleep(Duration::from_millis(50));
            }
        }));

        Ok(())
    }

    /// Stop service runtime workers and transition to stopped state.
    pub fn stop(&self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        if let Some(handle) = self.routing_worker.lock().unwrap().take() {
            let _ = handle.join();
        }
        Ok(())
    }

    /// Report whether the service is currently marked as running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Set node runtime mode and reconcile worker lifecycle.
    pub fn set_node_mode(&self, mode: NodeMode) {
        self.state.write().unwrap().settings.node_mode = mode;
        match mode {
            NodeMode::Client => {
                let _ = self.stop();
            }
            NodeMode::Server | NodeMode::Dual => {
                let _ = self.start();
            }
        }
    }
}
