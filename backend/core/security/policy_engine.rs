//! Declarative policy-evaluation engine.
//!
//! Supports named policies with ordered rules and a default action. Policies
//! evaluate against runtime context (trust level, operation/resource, attrs).

use crate::core::core::TrustLevel;
use crate::core::error::{MeshInfinityError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    pub peer_trust_level: Option<TrustLevel>,
    pub operation: String,
    pub resource: String,
    pub attributes: HashMap<String, String>,
}

impl PolicyContext {
    /// Parse policy context from JSON representation.
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| {
            MeshInfinityError::InvalidInput(format!("Failed to parse policy context: {}", e))
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    pub rules: Vec<PolicyRule>,
    pub default_action: PolicyAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub conditions: Vec<PolicyCondition>,
    pub action: PolicyAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyCondition {
    TrustLevelAtLeast(TrustLevel),
    TrustLevelExactly(TrustLevel),
    OperationEquals(String),
    ResourceMatches(String),
    AttributeEquals { key: String, value: String },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyAction {
    Allow,
    Deny,
}

pub struct PolicyEngine {
    policies: HashMap<String, Policy>,
}

impl PolicyEngine {
    /// Create empty policy engine with no registered policies.
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
        }
    }

    /// Insert or replace a named policy.
    pub fn add_policy(&mut self, policy: Policy) {
        self.policies.insert(policy.name.clone(), policy);
    }

    /// Evaluate `policy_name` against a JSON context and return allow/deny.
    pub fn evaluate(&self, policy_name: &str, context_json: &str) -> Result<bool> {
        let context = PolicyContext::from_json(context_json)?;

        let policy = self.policies.get(policy_name).ok_or_else(|| {
            MeshInfinityError::InvalidInput(format!("Policy '{}' not found", policy_name))
        })?;

        // Evaluate each rule in order
        for rule in &policy.rules {
            if self.evaluate_rule(rule, &context) {
                return Ok(rule.action == PolicyAction::Allow);
            }
        }

        // No rule matched, use default action
        Ok(policy.default_action == PolicyAction::Allow)
    }

    /// Return `true` when all rule conditions match current context.
    fn evaluate_rule(&self, rule: &PolicyRule, context: &PolicyContext) -> bool {
        // All conditions must be true for the rule to match
        rule.conditions
            .iter()
            .all(|condition| self.evaluate_condition(condition, context))
    }

    /// Evaluate one condition against context fields.
    fn evaluate_condition(&self, condition: &PolicyCondition, context: &PolicyContext) -> bool {
        match condition {
            PolicyCondition::TrustLevelAtLeast(required_level) => context
                .peer_trust_level
                .is_some_and(|level| level >= *required_level),
            PolicyCondition::TrustLevelExactly(required_level) => {
                context.peer_trust_level == Some(*required_level)
            }
            PolicyCondition::OperationEquals(op) => &context.operation == op,
            PolicyCondition::ResourceMatches(resource) => {
                // Simple wildcard matching: * matches anything
                if resource == "*" {
                    return true;
                }
                // Exact match or prefix match with *
                if resource.ends_with('*') {
                    let prefix = &resource[..resource.len() - 1];
                    context.resource.starts_with(prefix)
                } else {
                    &context.resource == resource
                }
            }
            PolicyCondition::AttributeEquals { key, value } => {
                context.attributes.get(key) == Some(value)
            }
        }
    }
}

impl Default for PolicyEngine {
    /// Create default engine equivalent to [`PolicyEngine::new`].
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trusted peer should satisfy trust-gated read policy.
    #[test]
    fn test_trust_level_policy() {
        let mut engine = PolicyEngine::new();

        let policy = Policy {
            name: "file_access".to_string(),
            rules: vec![PolicyRule {
                conditions: vec![
                    PolicyCondition::TrustLevelAtLeast(TrustLevel::Trusted),
                    PolicyCondition::OperationEquals("read".to_string()),
                ],
                action: PolicyAction::Allow,
            }],
            default_action: PolicyAction::Deny,
        };

        engine.add_policy(policy);

        let context = r#"{
            "peer_trust_level": "Trusted",
            "operation": "read",
            "resource": "file.txt",
            "attributes": {}
        }"#;

        assert!(engine.evaluate("file_access", context).unwrap());
    }

    /// Untrusted peer should be denied by secure default policy.
    #[test]
    fn test_deny_untrusted() {
        let mut engine = PolicyEngine::new();

        let policy = Policy {
            name: "secure_access".to_string(),
            rules: vec![PolicyRule {
                conditions: vec![PolicyCondition::TrustLevelAtLeast(TrustLevel::Trusted)],
                action: PolicyAction::Allow,
            }],
            default_action: PolicyAction::Deny,
        };

        engine.add_policy(policy);

        let context = r#"{
            "peer_trust_level": "Untrusted",
            "operation": "read",
            "resource": "sensitive.dat",
            "attributes": {}
        }"#;

        assert!(!engine.evaluate("secure_access", context).unwrap());
    }
}
