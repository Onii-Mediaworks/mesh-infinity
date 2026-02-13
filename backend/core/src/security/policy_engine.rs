use crate::core::error::{MeshInfinityError, Result};
use crate::core::core::TrustLevel;
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
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
        }
    }

    pub fn add_policy(&mut self, policy: Policy) {
        self.policies.insert(policy.name.clone(), policy);
    }

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

    fn evaluate_rule(&self, rule: &PolicyRule, context: &PolicyContext) -> bool {
        // All conditions must be true for the rule to match
        rule.conditions.iter().all(|condition| {
            self.evaluate_condition(condition, context)
        })
    }

    fn evaluate_condition(&self, condition: &PolicyCondition, context: &PolicyContext) -> bool {
        match condition {
            PolicyCondition::TrustLevelAtLeast(required_level) => {
                context.peer_trust_level.map_or(false, |level| level >= *required_level)
            }
            PolicyCondition::TrustLevelExactly(required_level) => {
                context.peer_trust_level.map_or(false, |level| level == *required_level)
            }
            PolicyCondition::OperationEquals(op) => {
                &context.operation == op
            }
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
                context.attributes.get(key).map_or(false, |v| v == value)
            }
        }
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_level_policy() {
        let mut engine = PolicyEngine::new();

        let policy = Policy {
            name: "file_access".to_string(),
            rules: vec![
                PolicyRule {
                    conditions: vec![
                        PolicyCondition::TrustLevelAtLeast(TrustLevel::Trusted),
                        PolicyCondition::OperationEquals("read".to_string()),
                    ],
                    action: PolicyAction::Allow,
                },
            ],
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

    #[test]
    fn test_deny_untrusted() {
        let mut engine = PolicyEngine::new();

        let policy = Policy {
            name: "secure_access".to_string(),
            rules: vec![
                PolicyRule {
                    conditions: vec![
                        PolicyCondition::TrustLevelAtLeast(TrustLevel::Trusted),
                    ],
                    action: PolicyAction::Allow,
                },
            ],
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
