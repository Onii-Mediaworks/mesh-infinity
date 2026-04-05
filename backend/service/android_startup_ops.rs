//! Android startup and unlock state intake.
//!
//! The Android platform layer reports boot and user-unlock milestones here so
//! the backend can reason about startup semantics using platform-owned state
//! instead of inferring everything from app launch timing.

use crate::service::runtime::{AndroidStartupState, MeshRuntime};

impl MeshRuntime {
    /// Return the backend-owned Android startup snapshot as JSON.
    pub fn get_android_startup_state_json(&self) -> String {
        let state = self
            .android_startup_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        serde_json::to_string(&state).unwrap_or_else(|_| "{}".to_string())
    }

    /// Replace the backend-owned Android startup snapshot.
    pub fn update_android_startup_state(&self, state_json: &str) -> Result<(), String> {
        let state: AndroidStartupState = serde_json::from_str(state_json)
            .map_err(|e| format!("invalid android startup state: {e}"))?;
        *self
            .android_startup_state
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = state.clone();
        self.reconcile_layer1_runtime()?;
        self.refresh_layer1_participation_state();
        self.push_event(
            "AndroidStartupUpdated",
            serde_json::to_value(&state).unwrap_or_else(|_| serde_json::json!({})),
        );
        Ok(())
    }
}
