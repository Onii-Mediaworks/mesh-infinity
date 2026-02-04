// Simple integration test to verify the basic structure
#[cfg(test)]
mod tests {
    use mesh_infinity::core::{MeshConfig, PeerInfo, TransportType, TrustLevel};
    use mesh_infinity::core::error::Result;

    #[test]
    fn test_basic_configuration() {
        let config = MeshConfig::default();
        assert_eq!(config.wireguard_port, 51820);
        assert_eq!(config.max_peers, 100);
        assert!(config.enable_tor);
    }

    #[test]
    fn test_peer_info_creation() {
        let peer_info = PeerInfo {
            peer_id: [0; 32],
            public_key: [1; 32],
            trust_level: TrustLevel::Trusted,
            available_transports: vec![TransportType::Tor, TransportType::Clearnet],
            last_seen: None,
            endpoint: None,
        };

        assert_eq!(peer_info.trust_level, TrustLevel::Trusted);
        assert_eq!(peer_info.available_transports.len(), 2);
    }

    #[test]
    fn test_error_handling() {
        let error = mesh_infinity::core::error::MeshInfinityError::PeerNotFound("test".to_string());
        match error {
            mesh_infinity::core::error::MeshInfinityError::PeerNotFound(msg) => {
                assert_eq!(msg, "test");
            }
            _ => panic!("Wrong error type"),
        }
    }
}
