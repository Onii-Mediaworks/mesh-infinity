use crate::core::error::Result;

pub struct Sandbox {
    policy_name: String,
}

impl Sandbox {
    pub fn new(policy_name: &str) -> Self {
        Self {
            policy_name: policy_name.to_string(),
        }
    }

    pub fn apply(&self) -> Result<()> {
        let _ = &self.policy_name;
        Ok(())
    }
}
