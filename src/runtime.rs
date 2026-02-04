use crate::{MeshInfinityService, NodeMode, ServiceConfig};
use crate::core::MeshConfig;

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
        let initial_mode = if config.ui_enabled {
            config.node_mode
        } else {
            NodeMode::Server
        };

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
        self.service.set_node_mode(mode);
    }
}
