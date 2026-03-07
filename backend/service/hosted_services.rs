//! Hosted-service configuration and access policy operations.
//!
//! This module centralizes hosted-service metadata mutations and policy checks.

use crate::core::core::{PeerId, TransportType};
use crate::core::error::{MeshInfinityError, Result};
use crate::core::TrustLevel as CoreTrustLevel;

use super::{HostedServicePolicy, HostedServiceSummary, MeshInfinityService};

impl MeshInfinityService {
    /// Return all hosted-service summaries.
    pub fn hosted_services(&self) -> Vec<HostedServiceSummary> {
        self.state
            .read()
            .unwrap()
            .hosted_services
            .values()
            .cloned()
            .collect()
    }

    /// Create or update hosted service metadata record.
    pub fn configure_hosted_service(
        &self,
        service_id: &str,
        name: &str,
        path: &str,
        address: &str,
        enabled: bool,
    ) -> Result<()> {
        self.configure_hosted_service_with_policy(
            service_id,
            name,
            path,
            address,
            enabled,
            HostedServicePolicy::default(),
        )
    }

    /// Create or update hosted service metadata record with explicit access policy.
    pub fn configure_hosted_service_with_policy(
        &self,
        service_id: &str,
        name: &str,
        path: &str,
        address: &str,
        enabled: bool,
        policy: HostedServicePolicy,
    ) -> Result<()> {
        let service_id = service_id.trim();
        if service_id.is_empty() {
            return Err(MeshInfinityError::InvalidConfiguration(
                "service id required".to_string(),
            ));
        }
        if !service_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.')
        {
            return Err(MeshInfinityError::InvalidConfiguration(
                "service id contains invalid characters".to_string(),
            ));
        }

        let name = name.trim();
        if name.is_empty() {
            return Err(MeshInfinityError::InvalidConfiguration(
                "service name required".to_string(),
            ));
        }

        let path = path.trim();
        if path.is_empty() || !path.starts_with('/') {
            return Err(MeshInfinityError::InvalidConfiguration(
                "service path must start with '/'".to_string(),
            ));
        }

        let address = address.trim();
        if address.is_empty() || address.chars().any(char::is_whitespace) {
            return Err(MeshInfinityError::InvalidConfiguration(
                "service address required".to_string(),
            ));
        }

        if policy.allowed_transports.is_empty() {
            return Err(MeshInfinityError::InvalidConfiguration(
                "service policy requires at least one transport".to_string(),
            ));
        }

        let mut state = self.state.write().unwrap();
        state.hosted_services.insert(
            service_id.to_string(),
            HostedServiceSummary {
                id: service_id.to_string(),
                name: name.to_string(),
                path: path.to_string(),
                address: address.to_string(),
                enabled,
                min_trust_level: policy.min_trust_level as i32,
                allowed_transports: policy
                    .allowed_transports
                    .into_iter()
                    .map(|transport| format!("{:?}", transport))
                    .collect(),
            },
        );
        Ok(())
    }

    /// Check whether a peer/transport tuple can access a hosted service.
    pub fn hosted_service_access_allowed(
        &self,
        service_id: &str,
        peer_id: &PeerId,
        transport: TransportType,
    ) -> Result<bool> {
        let state = self.state.read().unwrap();
        let Some(service) = state.hosted_services.get(service_id) else {
            return Err(MeshInfinityError::InvalidConfiguration(
                "service not found".to_string(),
            ));
        };

        if !service.enabled {
            return Ok(false);
        }

        let peer_trust = self
            .peers
            .get_trust_level(peer_id)
            .unwrap_or(CoreTrustLevel::Untrusted) as i32;
        if peer_trust < service.min_trust_level {
            return Ok(false);
        }

        let transport_name = format!("{:?}", transport);
        Ok(service
            .allowed_transports
            .iter()
            .any(|allowed| allowed == &transport_name))
    }
}
