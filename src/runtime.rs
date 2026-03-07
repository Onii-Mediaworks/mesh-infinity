use crate::core::MeshConfig;
use crate::{MeshInfinityService, NodeMode, ServiceConfig};

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub ui_enabled: bool,
    pub node_mode: NodeMode,
    pub mesh_config: MeshConfig,
    pub identity_name: Option<String>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            ui_enabled: true,
            node_mode: NodeMode::Client,
            mesh_config: MeshConfig::default(),
            identity_name: None,
        }
    }
}

pub struct MeshInfinityRuntime {
    service: MeshInfinityService,
    ui_enabled: bool,
}

impl MeshInfinityRuntime {
    pub fn new(config: RuntimeConfig) -> Self {
        let initial_mode = Self::normalize_mode(config.ui_enabled, config.node_mode);

        let service = MeshInfinityService::new(ServiceConfig {
            initial_mode,
            mesh_config: config.mesh_config,
            identity_name: config.identity_name,
        });

        Self {
            service,
            ui_enabled: config.ui_enabled,
        }
    }

    pub fn service(&self) -> &MeshInfinityService {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut MeshInfinityService {
        &mut self.service
    }

    pub fn ui_enabled(&self) -> bool {
        self.ui_enabled
    }

    pub fn node_mode(&self) -> NodeMode {
        self.service.settings().node_mode
    }

    pub fn set_node_mode(&mut self, mode: NodeMode) {
        self.service
            .set_node_mode(Self::normalize_mode(self.ui_enabled, mode));
    }

    pub fn start(&self) -> crate::core::error::Result<()> {
        self.service.start()
    }

    pub fn stop(&self) -> crate::core::error::Result<()> {
        self.service.stop()
    }

    pub fn set_ui_enabled(&mut self, enabled: bool) {
        self.ui_enabled = enabled;
        let current = self.service.settings().node_mode;
        let normalized = Self::normalize_mode(enabled, current);
        if normalized != current {
            self.service.set_node_mode(normalized);
        }
    }

    fn normalize_mode(ui_enabled: bool, requested: NodeMode) -> NodeMode {
        if ui_enabled {
            requested
        } else {
            // Headless runtime must keep networking active.
            NodeMode::Server
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headless_runtime_forces_server_mode() {
        let runtime = MeshInfinityRuntime::new(RuntimeConfig {
            ui_enabled: false,
            node_mode: NodeMode::Client,
            ..RuntimeConfig::default()
        });

        assert_eq!(runtime.node_mode(), NodeMode::Server);
        assert!(runtime.service().is_running());
    }

    #[test]
    fn client_mode_stops_and_dual_mode_starts() {
        let mut runtime = MeshInfinityRuntime::new(RuntimeConfig::default());

        assert_eq!(runtime.node_mode(), NodeMode::Client);
        assert!(!runtime.service().is_running());

        runtime.set_node_mode(NodeMode::Dual);
        assert_eq!(runtime.node_mode(), NodeMode::Dual);
        assert!(runtime.service().is_running());

        runtime.set_node_mode(NodeMode::Client);
        assert_eq!(runtime.node_mode(), NodeMode::Client);
        assert!(!runtime.service().is_running());
    }

    #[test]
    fn disabling_ui_reconciles_mode_to_server() {
        let mut runtime = MeshInfinityRuntime::new(RuntimeConfig {
            ui_enabled: true,
            node_mode: NodeMode::Dual,
            ..RuntimeConfig::default()
        });

        assert_eq!(runtime.node_mode(), NodeMode::Dual);
        runtime.set_ui_enabled(false);
        assert_eq!(runtime.node_mode(), NodeMode::Server);
        assert!(runtime.service().is_running());
    }
}
