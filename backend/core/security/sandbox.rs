//! Runtime sandbox-policy model and enforcement shim.
//!
//! Defines policy structures for permissions/resource constraints and exposes a
//! lightweight activation/check flow used by security-sensitive components.

use crate::core::error::{MeshInfinityError, Result};
use std::collections::HashSet;

#[derive(Clone, Debug)]
pub enum SandboxPermission {
    NetworkAccess,
    FileRead,
    FileWrite,
    ProcessSpawn,
    SystemCall(String),
}

pub struct SandboxPolicy {
    pub name: String,
    pub allowed_permissions: HashSet<String>,
    pub denied_permissions: HashSet<String>,
    pub max_memory_mb: Option<u64>,
    pub max_cpu_percent: Option<u8>,
}

impl SandboxPolicy {
    /// Create a named sandbox policy with no permissions granted.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            allowed_permissions: HashSet::new(),
            denied_permissions: HashSet::new(),
            max_memory_mb: None,
            max_cpu_percent: None,
        }
    }

    /// Add permission string to explicit allow-list.
    pub fn allow_permission(&mut self, permission: &str) {
        self.allowed_permissions.insert(permission.to_string());
    }

    /// Add permission string to explicit deny-list.
    pub fn deny_permission(&mut self, permission: &str) {
        self.denied_permissions.insert(permission.to_string());
    }

    /// Set optional memory limit in megabytes.
    pub fn set_memory_limit(&mut self, mb: u64) {
        self.max_memory_mb = Some(mb);
    }

    /// Set optional CPU cap as percentage (clamped to 100).
    pub fn set_cpu_limit(&mut self, percent: u8) {
        self.max_cpu_percent = Some(percent.min(100));
    }
}

pub struct Sandbox {
    policy: SandboxPolicy,
    active: bool,
}

impl Sandbox {
    /// Create sandbox with a fresh named policy.
    pub fn new(policy_name: &str) -> Self {
        Self {
            policy: SandboxPolicy::new(policy_name),
            active: false,
        }
    }

    /// Create sandbox from preconfigured policy.
    pub fn with_policy(policy: SandboxPolicy) -> Self {
        Self {
            policy,
            active: false,
        }
    }

    /// Validate policy and activate sandbox enforcement state.
    ///
    /// Platform-specific hardening hooks are intentionally deferred; this method
    /// currently enforces policy sanity checks and activation semantics.
    pub fn apply(&mut self) -> Result<()> {
        // Validate policy before applying
        if self.policy.name.is_empty() {
            return Err(MeshInfinityError::SecurityError(
                "Sandbox policy name cannot be empty".to_string(),
            ));
        }

        // In a full implementation, this would:
        // 1. Set up seccomp filters on Linux
        // 2. Use App Sandbox on macOS
        // 3. Use process restrictions on Windows
        // 4. Apply resource limits (memory, CPU)
        // 5. Restrict filesystem access

        // For now, we just validate the policy is reasonable
        if let Some(mem) = self.policy.max_memory_mb {
            if mem == 0 {
                return Err(MeshInfinityError::SecurityError(
                    "Memory limit must be greater than 0".to_string(),
                ));
            }
        }

        if let Some(cpu) = self.policy.max_cpu_percent {
            if cpu == 0 {
                return Err(MeshInfinityError::SecurityError(
                    "CPU limit must be greater than 0".to_string(),
                ));
            }
        }

        self.active = true;
        Ok(())
    }

    /// Check whether permission is allowed under active policy.
    ///
    /// Deny-list takes precedence; inactive sandbox denies all by default.
    pub fn check_permission(&self, permission: &str) -> bool {
        if !self.active {
            // If sandbox isn't active, deny by default
            return false;
        }

        // Explicitly denied permissions take precedence
        if self.policy.denied_permissions.contains(permission) {
            return false;
        }

        // Check if allowed
        self.policy.allowed_permissions.contains(permission)
    }

    /// Return whether sandbox has been successfully activated.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Disable sandbox enforcement state.
    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies allow/deny behavior for active sandbox permissions.
    #[test]
    fn test_sandbox_permissions() {
        let mut policy = SandboxPolicy::new("test");
        policy.allow_permission("network");
        policy.deny_permission("file_write");

        let mut sandbox = Sandbox::with_policy(policy);
        sandbox.apply().unwrap();

        assert!(sandbox.check_permission("network"));
        assert!(!sandbox.check_permission("file_write"));
        assert!(!sandbox.check_permission("unknown"));
    }

    /// Verifies non-zero resource limits are accepted.
    #[test]
    fn test_resource_limits() {
        let mut policy = SandboxPolicy::new("limited");
        policy.set_memory_limit(512);
        policy.set_cpu_limit(50);

        let mut sandbox = Sandbox::with_policy(policy);
        assert!(sandbox.apply().is_ok());
    }
}
