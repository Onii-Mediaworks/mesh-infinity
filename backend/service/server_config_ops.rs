//! Protocol server configuration operations (§22.54.4–§22.54.9).
//!
//! # What this file does
//!
//! Bridges the typed configuration in `services::server_config` to the
//! runtime: reading the current block as JSON for a screen, accepting a
//! JSON save, validating it against this host, storing it, persisting it
//! to `settings.vault` and announcing the change.  It also answers the
//! two environment questions the screens ask — which shells and account
//! this machine has, and which IPP queues the local spooler reports.
//!
//! # Save semantics (§22.54.4)
//!
//! A save is all-or-nothing: the JSON is parsed and validated in full
//! before anything in the runtime changes, so a rejected payload leaves the
//! running configuration untouched and the UI keeps the user's edits.  A
//! successful save updates the in-memory block (the running server reads
//! it on the next session request, so no restart is needed), persists the
//! bundle to its own vault collection and emits `SettingsUpdated` so other
//! screens refresh.

use std::path::PathBuf;

use crate::services::ipp;
use crate::services::server_config::{
    local_shells, local_user_and_home, local_users, parse_config, ApiGatewayConfig, HostProbe,
    MnfpServerConfig, MnrdpServerConfig, MnspServerConfig, OsHostProbe, PrintServiceConfig,
    ProtocolServerConfig, ServerConfigError,
};

use super::MeshRuntime;

impl MeshRuntime {
    /// The host probe for validation: the real OS, rooted at this runtime's
    /// data directory so the vault folder can never become a share.
    fn host_probe(&self) -> OsHostProbe {
        OsHostProbe {
            data_dir: PathBuf::from(&self.data_dir),
        }
    }

    /// Serialise one block of the stored bundle as JSON.
    fn config_json<T: serde::Serialize>(
        &self,
        pick: impl FnOnce(&ProtocolServerConfig) -> T,
    ) -> String {
        let bundle = self
            .protocol_server_config
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        serde_json::to_string(&pick(&bundle)).unwrap_or_else(|_| "{}".to_string())
    }

    /// Commit a validated block, persist and announce it.
    fn commit_config(&self, apply: impl FnOnce(&mut ProtocolServerConfig)) {
        {
            let mut bundle = self
                .protocol_server_config
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            apply(&mut bundle);
        }
        self.save_protocol_server_config();
        self.emit_settings_updated();
    }

    // -----------------------------------------------------------------------
    // Remote Desktop (§22.54.5)
    // -----------------------------------------------------------------------

    /// Current Remote Desktop settings as JSON.
    pub fn get_mnrdp_config(&self) -> String {
        self.config_json(|b| b.mnrdp.clone())
    }

    /// Replace the Remote Desktop settings from JSON.
    pub fn set_mnrdp_config(&self, json: &str) -> Result<(), ServerConfigError> {
        let cfg: MnrdpServerConfig = parse_config(json)?;
        cfg.validate()?;
        self.commit_config(|b| b.mnrdp = cfg);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Remote Shell (§22.54.6)
    // -----------------------------------------------------------------------

    /// Current Remote Shell settings as JSON.
    pub fn get_mnsp_config(&self) -> String {
        self.config_json(|b| b.mnsp.clone())
    }

    /// Replace the Remote Shell settings from JSON.
    ///
    /// Turning the SSH adapter off also turns off MNFP's "SFTP via SSH",
    /// which depends on it (§22.54.7), so the stored bundle never holds a
    /// combination the validators would refuse.
    pub fn set_mnsp_config(&self, json: &str) -> Result<(), ServerConfigError> {
        let cfg: MnspServerConfig = parse_config(json)?;
        cfg.validate(&self.host_probe())?;
        self.commit_config(|b| {
            if !cfg.ssh_adapter {
                b.mnfp.sftp_via_ssh = false;
            }
            b.mnsp = cfg;
        });
        Ok(())
    }

    // -----------------------------------------------------------------------
    // File Access (§22.54.7)
    // -----------------------------------------------------------------------

    /// Current File Access settings as JSON.
    pub fn get_mnfp_config(&self) -> String {
        self.config_json(|b| b.mnfp.clone())
    }

    /// Replace the File Access settings from JSON.
    pub fn set_mnfp_config(&self, json: &str) -> Result<(), ServerConfigError> {
        let cfg: MnfpServerConfig = parse_config(json)?;
        let ssh_on = self
            .protocol_server_config
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .mnsp
            .ssh_adapter;
        cfg.validate(&self.host_probe(), ssh_on)?;
        self.commit_config(|b| b.mnfp = cfg);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // API Gateway (§22.54.8)
    // -----------------------------------------------------------------------

    /// Current API Gateway settings as JSON.
    pub fn get_api_gateway_config(&self) -> String {
        self.config_json(|b| b.api_gateway.clone())
    }

    /// Replace the API Gateway settings from JSON.
    pub fn set_api_gateway_config(&self, json: &str) -> Result<(), ServerConfigError> {
        let cfg: ApiGatewayConfig = parse_config(json)?;
        cfg.validate(&self.host_probe())?;
        self.commit_config(|b| b.api_gateway = cfg);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Print Services (§22.54.9)
    // -----------------------------------------------------------------------

    /// Current Print Services settings as JSON.
    pub fn get_print_config(&self) -> String {
        self.config_json(|b| b.print.clone())
    }

    /// Replace the Print Services settings from JSON.
    pub fn set_print_config(&self, json: &str) -> Result<(), ServerConfigError> {
        let cfg: PrintServiceConfig = parse_config(json)?;
        cfg.validate(&self.host_probe())?;
        self.commit_config(|b| b.print = cfg);
        Ok(())
    }

    /// Queues the local spooler reports, as a JSON array of
    /// `{name, url, capabilities}`.  Empty when no spooler answers.
    pub fn print_queues(&self) -> String {
        serde_json::to_string(&ipp::discover_local_queues()).unwrap_or_else(|_| "[]".to_string())
    }

    /// Name and capabilities of the queue at `url`, as JSON.
    pub fn print_queue_probe(&self, url: &str) -> Result<String, ipp::IppError> {
        let hostname = self.host_probe().hostname();
        let printer = ipp::probe_queue(url, hostname.as_deref())?;
        Ok(serde_json::to_string(&printer).unwrap_or_else(|_| "{}".to_string()))
    }

    // -----------------------------------------------------------------------
    // Host facts for the screens
    // -----------------------------------------------------------------------

    /// Facts about this machine the configuration screens need:
    ///
    /// ```json
    /// { "platform": "linux", "hostname": "workstation",
    ///   "mnrdp_adapters": { "vnc": true, "nx": true, "ard": false },
    ///   "mnsp": { "default_user": "alice", "home": "/home/alice",
    ///             "users": ["alice", "bob"],
    ///             "shells": ["/bin/bash", "/bin/zsh"] } }
    /// ```
    ///
    /// `hostname` lets the UI apply the same "name on this machine" rule
    /// the backend uses for the API Gateway upstream (§22.54.8).
    ///
    /// Adapter availability follows §20.2.3–§20.2.5: VNC and NX exist on
    /// desktop platforms, Apple Remote Desktop on macOS only.
    pub fn service_host_facts(&self) -> String {
        let platform = std::env::consts::OS;
        let desktop = matches!(platform, "linux" | "macos" | "windows");
        let (default_user, home) = local_user_and_home();
        serde_json::json!({
            "platform": platform,
            "hostname": self.host_probe().hostname(),
            "mnrdp_adapters": {
                "vnc": desktop,
                "nx": desktop,
                "ard": platform == "macos",
            },
            "mnsp": {
                "default_user": default_user,
                "home": home,
                "users": local_users(),
                "shells": local_shells(),
            },
        })
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::server_config::{MNRDP_INPUT_FLOOR, MNRDP_VIEW_FLOOR};

    fn runtime() -> (tempfile::TempDir, MeshRuntime) {
        let dir = tempfile::TempDir::new().unwrap();
        let rt = MeshRuntime::new(dir.path().to_string_lossy().into_owned());
        (dir, rt)
    }

    #[test]
    fn defaults_are_served_before_any_save() {
        let (_dir, rt) = runtime();
        let cfg: MnrdpServerConfig = serde_json::from_str(&rt.get_mnrdp_config()).unwrap();
        assert_eq!(cfg, MnrdpServerConfig::default());
        assert_eq!(cfg.view_floor, MNRDP_VIEW_FLOOR);
        assert_eq!(cfg.input_floor, MNRDP_INPUT_FLOOR);
        let bundle: ProtocolServerConfig = serde_json::from_str(&format!(
            r#"{{"mnrdp":{},"mnsp":{},"mnfp":{},"api_gateway":{},"print":{}}}"#,
            rt.get_mnrdp_config(),
            rt.get_mnsp_config(),
            rt.get_mnfp_config(),
            rt.get_api_gateway_config(),
            rt.get_print_config()
        ))
        .unwrap();
        assert_eq!(bundle, ProtocolServerConfig::default());
    }

    #[test]
    fn valid_save_is_stored_and_readable() {
        let (_dir, rt) = runtime();
        rt.set_mnrdp_config(r#"{"view_floor":6,"input_floor":7,"max_sessions":4}"#)
            .unwrap();
        let cfg: MnrdpServerConfig = serde_json::from_str(&rt.get_mnrdp_config()).unwrap();
        assert_eq!(
            (cfg.view_floor, cfg.input_floor, cfg.max_sessions),
            (6, 7, 4)
        );
    }

    #[test]
    fn rejected_save_leaves_state_untouched() {
        let (_dir, rt) = runtime();
        rt.set_api_gateway_config(r#"{"upstream_url":"http://127.0.0.1:9000"}"#)
            .unwrap();
        let err = rt
            .set_api_gateway_config(r#"{"upstream_url":"http://evil.example"}"#)
            .unwrap_err();
        assert!(
            matches!(err, ServerConfigError::Invalid { ref field, .. } if field == "upstream_url")
        );
        let cfg: ApiGatewayConfig = serde_json::from_str(&rt.get_api_gateway_config()).unwrap();
        assert_eq!(cfg.upstream_url, "http://127.0.0.1:9000");
        // Malformed JSON is a typed error too, never a panic.
        assert!(matches!(
            rt.set_print_config("{"),
            Err(ServerConfigError::Malformed(_))
        ));
    }

    #[test]
    fn sftp_follows_the_ssh_adapter() {
        let (_dir, rt) = runtime();
        // SFTP cannot be turned on before the SSH adapter.
        assert!(rt.set_mnfp_config(r#"{"sftp_via_ssh":true}"#).is_err());
        rt.set_mnsp_config(r#"{"ssh_adapter":true}"#).unwrap();
        rt.set_mnfp_config(r#"{"sftp_via_ssh":true}"#).unwrap();
        // Turning SSH off clears the dependent switch.
        rt.set_mnsp_config(r#"{"ssh_adapter":false}"#).unwrap();
        let cfg: MnfpServerConfig = serde_json::from_str(&rt.get_mnfp_config()).unwrap();
        assert!(!cfg.sftp_via_ssh);
    }

    #[test]
    fn share_root_cannot_be_the_data_dir() {
        let (dir, rt) = runtime();
        let json = serde_json::json!({
            "shares": [{
                "name": "oops",
                "root_path": dir.path().to_string_lossy(),
                "access": "ReadOnly",
                "min_trust_level": 6
            }]
        })
        .to_string();
        let err = rt.set_mnfp_config(&json).unwrap_err();
        assert!(
            matches!(err, ServerConfigError::Invalid { ref field, .. } if field == "shares[0].root_path")
        );
    }

    #[test]
    fn host_facts_have_the_documented_shape() {
        let (_dir, rt) = runtime();
        let facts: serde_json::Value = serde_json::from_str(&rt.service_host_facts()).unwrap();
        assert!(facts["platform"].is_string());
        assert!(facts["mnrdp_adapters"]["vnc"].is_boolean());
        assert!(facts["mnrdp_adapters"]["ard"].is_boolean());
        assert!(facts["mnsp"]["shells"].is_array());
        assert!(facts["mnsp"]["users"].is_array());
        assert!(facts["mnsp"]["default_user"].is_string());
        assert!(facts["hostname"].is_string() || facts["hostname"].is_null());
    }

    #[test]
    fn probe_rejects_remote_url_as_typed_error() {
        let (_dir, rt) = runtime();
        assert_eq!(
            rt.print_queue_probe("ipp://1.1.1.1/x"),
            Err(ipp::IppError::NotLocal)
        );
        assert_eq!(
            rt.print_queue_probe("ipps://127.0.0.1/x"),
            Err(ipp::IppError::TlsUnsupported)
        );
    }
}
