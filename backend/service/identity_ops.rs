//! Identity lifecycle operations for `MeshRuntime`.
//!
//! This module implements the service-layer methods for creating, unlocking,
//! importing, resetting, and querying the node identity.  These methods are
//! called by the thin FFI shim in `backend/ffi/lib.rs`.
//!
//! ## Identity lifecycle
//! 1. `create_identity` — generate fresh key material, persist to disk.
//! 2. `unlock_identity` — load keys from disk (optionally with PIN).
//! 3. `import_identity` — restore contacts/rooms from an encrypted backup.
//! 4. `reset_identity` — non-emergency wipe of all in-memory state.
//! 5. `get_identity_summary` — read-only JSON snapshot for Flutter.
//! 6. `set_public_profile` / `set_private_profile` — update visible profiles.
//!
//! ## Security notes
//! Private key material is **never** included in backups (§3.7).  The vault is
//! re-initialised from the identity master key on every unlock.

use crate::crypto::backup::EncryptedBackup;
use crate::identity::pin::{
    self, KdfParams, PinAttemptState, PinError, PinWrappedKey, SALT_LEN, UNLOCK_RESPONSE_DEADLINE,
};
use crate::identity::self_identity::{
    derive_kem_keypair, encode_wrapped_key_file, read_master_key_record, write_atomic,
    write_identity_files, IdentityError, MasterKeyRecord, SelfIdentity, WrappedMasterKey,
};
use crate::service::runtime::{
    build_settings_json, try_random_fill, Layer1StartupConfig, MeshRuntime, RegisteredDevice,
    SettingsVault,
};
use crate::storage::VaultManager;
use crate::trust::levels::TrustLevel;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{Signature, Signer as _, Verifier as _, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

/// Local mirror of the backup payload structure (§3.7.4).
///
/// Private keys are never included — the spec §3.7 explicitly prohibits it.
/// This mirrors the struct in `ffi/lib.rs` but lives here so that
/// `import_identity` can deserialise backup payloads without reaching into the
/// FFI layer.
#[derive(serde::Serialize, serde::Deserialize)]
struct BackupContents {
    /// Schema version for forward compatibility.
    version: u8,
    /// All paired contacts (public keys + trust levels, no private material).
    contacts: Vec<crate::pairing::contact::ContactRecord>,
    /// All rooms / conversations.
    rooms: Vec<crate::messaging::room::Room>,
    /// Message history per room (key = room_id hex, value = message list).
    /// Populated for Extended backups only; empty for Standard.
    messages: std::collections::HashMap<String, Vec<serde_json::Value>>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct DeviceEnrollmentRequest {
    version: u8,
    request_id: String,
    target_device_id: String,
    device_name: String,
    platform: String,
    target_public_key: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PendingDeviceEnrollment {
    request_id: String,
    target_device_id: String,
    device_name: String,
    platform: String,
    target_secret_key: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct DeviceTransferEnvelope {
    version: u8,
    request_id: String,
    sender_public_key: String,
    nonce: String,
    ciphertext: String,
    registration_sig: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct DeviceTransferPayload {
    version: u8,
    request_id: String,
    target_device_id: String,
    registered_devices: Vec<RegisteredDevice>,
    identity_payload: String,
    master_key: String,
    settings: SettingsVault,
    contacts: Vec<crate::pairing::contact::ContactRecord>,
    rooms: Vec<crate::messaging::room::Room>,
    messages: std::collections::HashMap<String, Vec<serde_json::Value>>,
    masks: Vec<crate::identity::mask::MaskMetadata>,
}

impl MeshRuntime {
    fn mesh_identity_path(&self) -> std::path::PathBuf {
        std::path::Path::new(&self.data_dir).join("mesh_identity.key")
    }

    fn duress_pin_path(&self) -> std::path::PathBuf {
        std::path::Path::new(&self.data_dir).join("pin.dat")
    }

    /// Sealed attempt counter (§3.10): `[0x01][nonce][AEAD(JSON state)]`.
    fn pin_attempt_state_path(&self) -> std::path::PathBuf {
        std::path::Path::new(&self.data_dir).join("pin_attempts.sealed")
    }

    /// Key the attempt counter is sealed under.
    ///
    /// No Rust-side keystore abstraction exists yet, so the key lives next
    /// to `identity.key` with the same filesystem protection (§3.6.3
    /// fallback row). That makes an edited or deleted counter detectable;
    /// it does not stop an adversary who can rewrite every file at once
    /// from replacing key and counter together. The keystore-backed
    /// variant SPEC §3.10 asks for closes that gap once a platform keystore
    /// binding exists.
    fn pin_counter_key_path(&self) -> std::path::PathBuf {
        std::path::Path::new(&self.data_dir).join("pin_counter.key")
    }

    /// Plaintext counter written by builds before the sealed format.
    /// Read once for migration of a legacy (mode 0x01) install, then
    /// removed; never written.
    fn legacy_pin_attempt_json_path(&self) -> std::path::PathBuf {
        std::path::Path::new(&self.data_dir).join("pin_attempts.json")
    }

    fn local_device_id_path(&self) -> std::path::PathBuf {
        std::path::Path::new(&self.data_dir).join("device_id")
    }

    fn pending_device_enrollment_path(&self) -> std::path::PathBuf {
        std::path::Path::new(&self.data_dir).join("device_enrollment_request.json")
    }

    pub(crate) fn layer1_startup_config_path(&self) -> std::path::PathBuf {
        std::path::Path::new(&self.data_dir).join("layer1_startup.json")
    }

    fn has_duress_pin(&self) -> bool {
        self.duress_pin_path().is_file()
    }

    /// Whether `identity.key` is PIN-wrapped (mode 0x01 or 0x02).
    ///
    /// A missing or unparsable key file counts as "no PIN": there is nothing
    /// a PIN could unlock, and the unlock path reports the real error.
    fn has_pin_configured(&self) -> bool {
        read_master_key_record(std::path::Path::new(&self.data_dir))
            .map(|record| record.is_wrapped())
            .unwrap_or(false)
    }

    /// Fill `dest` from the OS RNG, as a typed error instead of a bool so
    /// the PIN paths can propagate an unavailable RNG with `?`.
    fn fill_random(dest: &mut [u8]) -> Result<(), String> {
        if try_random_fill(dest) {
            Ok(())
        } else {
            Err("OS random number generator is unavailable".to_string())
        }
    }

    /// Wall-clock seconds since the Unix epoch, or an error when the clock
    /// is unreadable. The PIN paths never substitute zero for a clock error
    /// (§3.10): a zero timestamp would clear every backoff.
    fn wall_clock_secs() -> Result<u64, String> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| "System clock is unavailable; PIN entry refused".to_string())
    }

    fn current_time_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn generate_device_id() -> Result<String, String> {
        let mut bytes = [0u8; 16];
        if !try_random_fill(&mut bytes) {
            return Err("Failed to generate device identifier".to_string());
        }
        Ok(hex::encode(bytes))
    }

    fn read_or_create_local_device_id(&self) -> Result<String, String> {
        let path = self.local_device_id_path();
        match std::fs::read_to_string(&path) {
            Ok(existing) => {
                let device_id = existing.trim().to_string();
                if device_id.is_empty() {
                    return Err("Local device identifier file is empty".to_string());
                }
                Ok(device_id)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let device_id = Self::generate_device_id()?;
                std::fs::write(&path, &device_id)
                    .map_err(|e| format!("Failed to persist local device identifier: {e}"))?;
                Ok(device_id)
            }
            Err(err) => Err(format!("Failed to read local device identifier: {err}")),
        }
    }

    fn snapshot_settings_vault(&self) -> SettingsVault {
        let flags = self
            .transport_flags
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let notif = self.notifications.lock().unwrap_or_else(|e| e.into_inner());
        let ncfg = &notif.config;
        let push_url = ncfg
            .push_relay
            .as_ref()
            .map(|r| match &r.relay_address {
                crate::notifications::RelayAddress::ClearnetUrl { url } => url.clone(),
                crate::notifications::RelayAddress::UnifiedPush { endpoint } => endpoint.clone(),
                crate::notifications::RelayAddress::MeshService { .. } => String::new(),
            })
            .unwrap_or_default();
        let mc_val =
            serde_json::to_value(&*self.module_config.lock().unwrap_or_else(|e| e.into_inner()))
                .ok();
        SettingsVault {
            node_mode: *self.node_mode.lock().unwrap_or_else(|e| e.into_inner()),
            threat_context: self.threat_context as u8,
            tor: flags.tor,
            clearnet: flags.clearnet,
            clearnet_fallback: flags.clearnet_fallback,
            i2p: flags.i2p,
            bluetooth: flags.bluetooth,
            rf: flags.rf,
            mesh_discovery: flags.mesh_discovery,
            allow_relays: flags.allow_relays,
            clearnet_port: *self.clearnet_port.lock().unwrap_or_else(|e| e.into_inner()),
            notification_tier: ncfg.tier as u8,
            notification_enabled: ncfg.enabled,
            notification_push_url: push_url,
            notification_show_previews: ncfg.rich_content_level as u8 >= 1,
            module_config: mc_val,
            app_connector_config: Some(
                self.app_connector_config
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone(),
            ),
            distress_message_enabled: *self
                .distress_message_enabled
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            liveness_signal_enabled: *self
                .liveness_signal_enabled
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            wrong_pin_wipe_enabled: *self
                .wrong_pin_wipe_enabled
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            wrong_pin_wipe_threshold: *self
                .wrong_pin_wipe_threshold
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            remote_wipe_enabled: *self
                .remote_wipe_enabled
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            active_tier: *self.active_tier.lock().unwrap_or_else(|e| e.into_inner()),
            bandwidth_profile: *self
                .bandwidth_profile
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
            onboarding_complete: *self
                .onboarding_complete
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        }
    }

    pub(crate) fn snapshot_layer1_startup_config(&self) -> Layer1StartupConfig {
        let flags = self
            .transport_flags
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        Layer1StartupConfig {
            node_mode: *self.node_mode.lock().unwrap_or_else(|e| e.into_inner()),
            threat_context: self.threat_context as u8,
            tor: flags.tor,
            clearnet: flags.clearnet,
            i2p: flags.i2p,
            bluetooth: flags.bluetooth,
            rf: flags.rf,
            mesh_discovery: flags.mesh_discovery,
            allow_relays: flags.allow_relays,
            clearnet_port: *self.clearnet_port.lock().unwrap_or_else(|e| e.into_inner()),
        }
    }

    pub(crate) fn save_layer1_startup_config(&self) {
        let path = self.layer1_startup_config_path();
        let config = self.snapshot_layer1_startup_config();
        let Ok(bytes) = serde_json::to_vec(&config) else {
            return;
        };
        if let Err(err) = std::fs::write(path, bytes) {
            eprintln!("[startup] ERROR: failed to persist layer1 startup config: {err}");
        }
    }

    pub fn load_layer1_startup_config(&mut self) {
        let path = self.layer1_startup_config_path();
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return,
            Err(err) => {
                eprintln!("[startup] ERROR: failed to read layer1 startup config: {err}");
                return;
            }
        };
        let config = match serde_json::from_slice::<Layer1StartupConfig>(&bytes) {
            Ok(config) => config,
            Err(err) => {
                eprintln!("[startup] ERROR: failed to decode layer1 startup config: {err}");
                return;
            }
        };

        *self.node_mode.lock().unwrap_or_else(|e| e.into_inner()) = config.node_mode;
        if let Some(threat_context) =
            crate::network::threat_context::ThreatContext::from_u8(config.threat_context)
        {
            self.threat_context = threat_context;
        }
        {
            let mut flags = self
                .transport_flags
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            flags.tor = config.tor;
            flags.clearnet = config.clearnet;
            flags.i2p = config.i2p;
            flags.bluetooth = config.bluetooth;
            flags.rf = config.rf;
            flags.mesh_discovery = config.mesh_discovery;
            flags.allow_relays = config.allow_relays;
        }
        *self.clearnet_port.lock().unwrap_or_else(|e| e.into_inner()) = config.clearnet_port;
        self.sync_store_forward_mode();
    }

    fn ensure_local_device_registered(&self, primary_if_empty: bool) -> Result<(), String> {
        let local_device_id = self.read_or_create_local_device_id()?;
        let mut devices = self
            .registered_devices
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let now = Self::current_time_ms();
        let display_name = self
            .identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .and_then(|identity| identity.display_name.clone())
            .unwrap_or_else(|| current_device_name().to_string());
        let platform = current_platform_id().to_string();
        let should_be_primary = primary_if_empty || devices.is_empty();
        if let Some(existing) = devices
            .iter_mut()
            .find(|device| device.id == local_device_id)
        {
            existing.name = display_name;
            existing.platform = platform;
            existing.last_seen_ms = now;
            if primary_if_empty {
                existing.is_primary = true;
            }
        } else {
            devices.push(RegisteredDevice {
                id: local_device_id,
                name: display_name,
                platform,
                is_primary: should_be_primary,
                added_at_ms: now,
                last_seen_ms: now,
                authorized_by_device_id: None,
            });
        }
        devices.sort_by(|a, b| {
            a.added_at_ms
                .cmp(&b.added_at_ms)
                .then_with(|| a.id.cmp(&b.id))
        });
        drop(devices);
        self.save_registered_devices();
        Ok(())
    }

    fn save_pending_device_enrollment(
        &self,
        pending: &PendingDeviceEnrollment,
    ) -> Result<(), String> {
        let encoded = serde_json::to_vec(pending)
            .map_err(|e| format!("Failed to encode device enrollment request: {e}"))?;
        std::fs::write(self.pending_device_enrollment_path(), encoded)
            .map_err(|e| format!("Failed to persist device enrollment request: {e}"))
    }

    fn load_pending_device_enrollment(&self) -> Result<PendingDeviceEnrollment, String> {
        let bytes = std::fs::read(self.pending_device_enrollment_path())
            .map_err(|e| format!("Failed to read device enrollment request: {e}"))?;
        serde_json::from_slice(&bytes)
            .map_err(|e| format!("Failed to decode device enrollment request: {e}"))
    }

    fn clear_pending_device_enrollment(&self) {
        let _ = std::fs::remove_file(self.pending_device_enrollment_path());
    }

    fn ensure_layer1_transport_started(&self) -> Result<(), String> {
        self.reconcile_layer1_runtime()
    }

    pub fn reconcile_layer1_runtime(&self) -> Result<(), String> {
        let flags = self
            .transport_flags
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let threat_context = self.threat_context;

        if flags.clearnet && threat_context.allows_clearnet() {
            self.start_clearnet_listener()?;
        } else {
            self.stop_clearnet_listener();
        }
        if flags.mesh_discovery && threat_context.allows_mdns() {
            self.mdns_enable();
        } else {
            self.mdns_disable();
        }
        if flags.tor && self.identity_unlocked {
            self.tor_enable()?;
        } else if !flags.tor {
            self.tor_disable();
        }

        self.refresh_layer1_participation_state();
        Ok(())
    }

    pub(crate) fn refresh_layer1_participation_state(&self) {
        let flags = self
            .transport_flags
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let android_proximity = self
            .android_proximity_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let android_startup = self
            .android_startup_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let mut transport_manager = self
            .transport_manager
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let threat_context = self.threat_context;
        let mdns_allowed = threat_context.allows_mdns();
        let clearnet_allowed = threat_context.allows_clearnet();
        let proximity_direct_allowed = threat_context.allows_proximity_direct();
        transport_manager.sync_availability(&[
            (
                crate::network::transport_hint::TransportType::Clearnet,
                flags.clearnet && clearnet_allowed,
            ),
            (
                crate::network::transport_hint::TransportType::Tor,
                flags.tor,
            ),
            (
                crate::network::transport_hint::TransportType::I2P,
                flags.i2p,
            ),
            (
                crate::network::transport_hint::TransportType::BLE,
                flags.bluetooth,
            ),
            (crate::network::transport_hint::TransportType::RF, flags.rf),
            (
                crate::network::transport_hint::TransportType::WiFiDirect,
                flags.mesh_discovery
                    && mdns_allowed
                    && proximity_direct_allowed
                    && android_proximity.wifi_direct_enabled,
            ),
            (
                crate::network::transport_hint::TransportType::NFC,
                proximity_direct_allowed && android_proximity.nfc_enabled,
            ),
        ]);
        let has_active_transport = transport_manager.active_transport_type_count() > 0;
        drop(transport_manager);

        let has_active_conversation = self
            .active_conversation
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some();
        let activity_state = if android_startup.is_android
            && android_startup.boot_completed
            && !android_startup.user_unlocked
        {
            crate::network::security_policy::DeviceActivityState::ScreenOff
        } else if has_active_conversation {
            crate::network::security_policy::DeviceActivityState::ActiveConversation
        } else if self.identity_unlocked {
            crate::network::security_policy::DeviceActivityState::ForegroundIdle
        } else {
            crate::network::security_policy::DeviceActivityState::Backgrounded
        };
        *self
            .layer1_activity_state
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = activity_state;
        *self
            .layer1_cover_traffic
            .lock()
            .unwrap_or_else(|e| e.into_inner()) =
            crate::network::security_policy::cover_traffic_for_state(activity_state);
        *self
            .layer1_participation_started
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = self
            .mesh_identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
            && has_active_transport;
    }

    pub(crate) fn sync_tunnel_gossip_identity(&self) {
        let mesh_pub = self
            .mesh_identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|identity| identity.public_bytes())
            .unwrap_or([0u8; 32]);
        *self.tunnel_gossip.lock().unwrap_or_else(|e| e.into_inner()) =
            crate::routing::tunnel_gossip::TunnelGossipProcessor::new(mesh_pub);
    }

    pub(crate) fn sync_announcement_processor_identity(&self) {
        let our_address = self
            .mesh_identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|identity| crate::routing::table::DeviceAddress(identity.public_bytes()))
            .unwrap_or(crate::routing::table::DeviceAddress([0u8; 32]));
        *self
            .announcement_processor
            .lock()
            .unwrap_or_else(|e| e.into_inner()) =
            crate::routing::announcement::AnnouncementProcessor::new(our_address, 10);
    }

    pub(crate) fn sync_store_forward_mode(&self) {
        let node_mode = *self.node_mode.lock().unwrap_or_else(|e| e.into_inner());
        let storage_cap = if node_mode >= 2 {
            crate::routing::store_forward::DEFAULT_SERVER_STORAGE_CAP
        } else {
            crate::routing::store_forward::DEFAULT_CLIENT_STORAGE_CAP
        };
        self.sf_server
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .set_storage_cap(storage_cap);
    }

    fn load_or_create_mesh_identity(&self) -> Result<(), String> {
        let path = self.mesh_identity_path();
        let identity = match std::fs::read(&path) {
            Ok(bytes) => {
                if bytes.len() != 32 {
                    return Err("mesh identity key has invalid length".to_string());
                }
                let mut secret = [0u8; 32];
                secret.copy_from_slice(&bytes);
                crate::identity::mesh_identity::MeshIdentity::from_secret_bytes(secret)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let identity = crate::identity::mesh_identity::MeshIdentity::generate();
                std::fs::write(&path, identity.secret_bytes())
                    .map_err(|e| format!("failed to persist mesh identity: {e}"))?;
                identity
            }
            Err(err) => return Err(format!("failed to load mesh identity: {err}")),
        };
        *self.mesh_identity.lock().unwrap_or_else(|e| e.into_inner()) = Some(identity);
        self.sync_tunnel_gossip_identity();
        self.sync_announcement_processor_identity();
        self.sync_store_forward_mode();
        Ok(())
    }

    /// Inject 32 raw secret bytes as the in-memory mesh identity, bypassing
    /// the filesystem entirely.
    ///
    /// Called by the Android startup service when the Keystore-backed wrapped
    /// copy of the Layer 1 secret is available.  The Keystore copy takes
    /// precedence over the on-disk `mesh_identity.key` file because it is
    /// hardware-protected — even an attacker with raw filesystem access cannot
    /// recover the plaintext key without the device hardware and a successful
    /// boot attestation.
    ///
    /// This method constructs a `MeshIdentity` from the provided secret, stores
    /// it in the runtime, and propagates the identity to all dependent
    /// subsystems (tunnel gossip, announcement processor, store-forward mode).
    ///
    /// Returns `Ok(())` on success.  Returns `Err` if the byte slice is not
    /// exactly 32 bytes, which would indicate a bug in the Keystore unwrap path.
    pub fn inject_mesh_identity_secret(&self, secret: [u8; 32]) -> Result<(), String> {
        // Reconstruct the full X25519 keypair from the raw entropy.
        // `from_secret_bytes` re-derives the public key deterministically,
        // so no public key needs to be stored in the Keystore blob.
        let identity = crate::identity::mesh_identity::MeshIdentity::from_secret_bytes(secret);

        // Overwrite whatever was in memory (e.g., the file-based key that
        // `initialize_startup_state` may have loaded a moment before).
        *self.mesh_identity.lock().unwrap_or_else(|e| e.into_inner()) = Some(identity);

        // Propagate the new identity to all subsystems that cache the mesh
        // public key.  These calls are no-ops if the subsystem has not been
        // started yet, so they are safe to call at any point in the startup
        // sequence.
        self.sync_tunnel_gossip_identity();
        self.sync_announcement_processor_identity();
        self.sync_store_forward_mode();

        Ok(())
    }

    /// Export the current in-memory mesh identity secret bytes.
    ///
    /// Returns `Some([u8; 32])` if a mesh identity is loaded, `None` if the
    /// identity has not been loaded yet.
    ///
    /// Used by the Android startup service on the very first boot (or after a
    /// Keystore entry deletion) to wrap the freshly generated / file-loaded
    /// secret with the hardware-backed AES key before persisting it.  After
    /// `wrapAndSaveKeypairIfNeeded` completes on the Kotlin side the raw bytes
    /// are zeroed immediately — the secret should never persist in the JVM heap.
    ///
    /// ## Security note
    ///
    /// The returned bytes are the raw WireGuard private key.  The caller is
    /// responsible for zeroing them immediately after use.
    pub fn export_mesh_identity_secret(&self) -> Option<[u8; 32]> {
        self.mesh_identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            // `secret_bytes()` copies from `secret_raw` — the return value is
            // a stack allocation, not a reference into the MeshIdentity.
            .map(|id| id.secret_bytes())
    }

    /// Like `initialize_startup_state` but uses a caller-supplied secret
    /// instead of reading from or writing to disk.
    ///
    /// This is the Android Keystore-first startup path (§3.1.1):
    ///
    /// 1. The Kotlin startup service reads the Keystore-wrapped blob from
    ///    device-protected storage and unwraps it with the hardware AES key.
    /// 2. It calls `mi_layer1_inject_secret` (FFI) → `inject_mesh_identity_secret`
    ///    to put the unwrapped secret into the runtime's `mesh_identity` slot.
    /// 3. It then calls `initialize_startup_state_with_secret` (via the Kotlin
    ///    path that calls `startLayer1` then immediately injects), which:
    ///    - Writes the same bytes to `mesh_identity.key` as a **fallback** only
    ///      if that file does not yet exist.  This ensures the node can still
    ///      boot if the Keystore entry is ever deleted (e.g., after a factory
    ///      reset of the security chip that does not wipe storage).
    ///    - Calls `refresh_layer1_participation_state` and
    ///      `ensure_layer1_transport_started` to bring up WireGuard and cover
    ///      traffic.
    ///    - Auto-unlocks Layer 2 if no PIN is configured (same as the base
    ///      `initialize_startup_state`).
    ///
    /// The file-based key is a **write-once fallback** — we never read it back
    /// inside this function because the Keystore copy is authoritative.
    pub fn initialize_startup_state_with_secret(&mut self, secret: [u8; 32]) {
        // Inject the hardware-backed secret before any subsystem reads the
        // identity.  This overwrites any stale value from a prior file-based
        // load, making the Keystore copy authoritative.
        if let Err(e) = self.inject_mesh_identity_secret(secret) {
            self.set_error(&format!("Mesh identity injection failed: {e}"));
            return;
        }

        // A successfully injected hardware-backed identity supersedes any
        // legacy raw file. Failure to remove it is security-significant and
        // remains visible rather than silently preserving a plaintext copy.
        let path = self.mesh_identity_path();
        if path.exists() {
            if let Err(e) = std::fs::remove_file(&path) {
                self.set_error(&format!(
                    "Failed to remove legacy plaintext mesh identity: {e}"
                ));
                return;
            }
        }

        // Refresh Layer 1 participation flags and start transport subsystems.
        self.refresh_layer1_participation_state();
        if !self.has_identity() {
            // Should never happen — we just injected a valid identity above.
            return;
        }
        if let Err(e) = self.ensure_layer1_transport_started() {
            self.set_error(&format!("Layer 1 transport startup failed: {e}"));
        }

        // Auto-unlock Layer 2 if no PIN has been configured.  This mirrors
        // the behaviour in `initialize_startup_state` so that the Keystore
        // path does not create a divergent startup experience.
        if !self.has_pin_configured() {
            if let Err(e) = self.unlock_identity(None) {
                self.set_error(&format!("Automatic identity unlock failed: {e}"));
            }
        }
    }

    /// Wipe in-memory Layer 2/3 identity key material exactly once (§3.6.4).
    ///
    /// Safe to call concurrently from both the screen-lock path and the
    /// PIN-timeout path.  An `AtomicBool` compare-exchange ensures at most
    /// one thread executes the wipe; the other returns immediately.  The flag
    /// is reset after the wipe completes so a future `unlock_identity` can
    /// re-populate keys.
    ///
    /// Dropping `Option<SelfIdentity>` triggers `Zeroize` on all key fields
    /// (`SigningKey`, `StaticSecret`, `Zeroizing<[u8;32]>`).
    pub fn clear_identity_keys(&self) {
        use std::sync::atomic::Ordering;
        // Only one thread executes the wipe; all others return immediately.
        if self
            .identity_clear_in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        // Dropping the SelfIdentity triggers Zeroize on all key fields.
        *self.identity.lock().unwrap_or_else(|e| e.into_inner()) = None;
        // Also clear the Layer 1 mesh identity.
        *self.mesh_identity.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.sync_tunnel_gossip_identity();
        self.sync_announcement_processor_identity();
        // Reset flag so unlock_identity() can repopulate after re-authentication.
        self.identity_clear_in_progress
            .store(false, Ordering::Release);
    }

    fn clear_mesh_identity_runtime_state(&self) {
        // Delegate to clear_identity_keys() so the AtomicBool guard is respected.
        self.clear_identity_keys();
    }

    // -----------------------------------------------------------------------
    // PIN attempt counter (§3.10)
    // -----------------------------------------------------------------------

    /// Wipe threshold from the in-memory security settings.
    ///
    /// Only meaningful after unlock (the settings vault is encrypted under
    /// the master key); the unlock screen uses the copy stored inside the
    /// sealed counter instead.
    fn current_pin_wipe_threshold(&self) -> Option<u32> {
        let enabled = *self
            .wrong_pin_wipe_enabled
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !enabled {
            return None;
        }
        Some(
            (*self
                .wrong_pin_wipe_threshold
                .lock()
                .unwrap_or_else(|e| e.into_inner())) as u32,
        )
    }

    /// Read the counter-sealing key.
    ///
    /// `Ok(None)` means the file is absent or not exactly 32 bytes — both
    /// are "no usable key" and the caller decides whether that is tampering.
    /// Other I/O failures are reported, not conflated with tampering.
    fn load_counter_key(&self) -> Result<Option<zeroize::Zeroizing<[u8; 32]>>, String> {
        match std::fs::read(self.pin_counter_key_path()) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut key = zeroize::Zeroizing::new([0u8; 32]);
                // Copy into the fixed-size buffer.
                key.copy_from_slice(&bytes);
                Ok(Some(key))
            }
            // Wrong length: unusable, treated like a missing key.
            Ok(_) => Ok(None),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(format!("Failed to read PIN counter key: {err}")),
        }
    }

    /// Generate and persist a fresh counter-sealing key.
    fn create_counter_key(&self) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        // OS-provided cryptographic random number generator.
        Self::fill_random(&mut *key)?;
        write_atomic(&self.pin_counter_key_path(), &*key)
            .map_err(|e| format!("Failed to persist PIN counter key: {e}"))?;
        Ok(key)
    }

    /// Load the sealed attempt counter.
    ///
    /// Returns `Ok(Some(state))` when key and counter are present and the
    /// counter authenticates, `Ok(None)` when either is missing, edited or
    /// otherwise unusable — tampering under §3.10 once a PIN is configured —
    /// and `Err` only for I/O failures that are neither.
    ///
    /// `legacy_record` is true when `identity.key` is still the mode 0x01
    /// layout. Such a file was written before the sealed counter existed,
    /// so a missing counter there is a one-time migration, not tampering:
    /// the plaintext `pin_attempts.json` (if any) is carried over, sealed,
    /// and the plaintext file removed. A mode 0x02 file is only ever written
    /// together with a sealed counter, so the bootstrap never applies to it.
    fn load_pin_attempt_state(
        &self,
        legacy_record: bool,
    ) -> Result<Option<PinAttemptState>, String> {
        let key = self.load_counter_key()?;
        let sealed = match std::fs::read(self.pin_attempt_state_path()) {
            Ok(bytes) => Some(bytes),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => return Err(format!("Failed to read PIN attempt counter: {err}")),
        };
        match (key, sealed) {
            // Normal case: open and authenticate.
            (Some(key), Some(sealed)) => Ok(pin::open_attempt_state(&sealed, &key).ok()),
            // Legacy install with no sealed counter at all: bootstrap once.
            (None, None) if legacy_record => {
                let mut state = std::fs::read(self.legacy_pin_attempt_json_path())
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<PinAttemptState>(&bytes).ok())
                    .unwrap_or_default();
                // The runtime threshold is unknown at the unlock screen;
                // the first post-unlock sync fills it in.
                state.wipe_threshold = state.wipe_threshold.or(self.current_pin_wipe_threshold());
                self.save_pin_attempt_state(&state)?;
                // The plaintext copy must not linger as a reset vector.
                let _ = std::fs::remove_file(self.legacy_pin_attempt_json_path());
                Ok(Some(state))
            }
            // Anything else — one file without the other, or both gone on
            // a current-format install — is tampering.
            _ => Ok(None),
        }
    }

    /// Seal and persist the attempt counter, creating the sealing key on
    /// first use. The write is atomic (tmp + rename) so a crash mid-write
    /// cannot leave a half-written counter that reads as tampering.
    fn save_pin_attempt_state(&self, state: &PinAttemptState) -> Result<(), String> {
        let key = match self.load_counter_key()? {
            Some(key) => key,
            None => self.create_counter_key()?,
        };
        let sealed = pin::seal_attempt_state(state, &key)
            .map_err(|e| format!("Failed to seal PIN attempt counter: {e}"))?;
        write_atomic(&self.pin_attempt_state_path(), &sealed)
            .map_err(|e| format!("Failed to persist PIN attempt counter: {e}"))
    }

    /// Remove every counter file. Used when no PIN is configured (nothing
    /// to count) and after a wipe. A missing file is not an error.
    fn clear_pin_attempt_files(&self) -> Result<(), String> {
        for path in [
            self.pin_attempt_state_path(),
            self.pin_counter_key_path(),
            self.legacy_pin_attempt_json_path(),
        ] {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(format!("Failed to clear PIN attempt state: {err}")),
            }
        }
        Ok(())
    }

    /// Re-seal the counter with the wipe threshold currently in settings.
    ///
    /// Called after unlock and whenever the setting changes, so the copy the
    /// unlock screen reads tracks the user's choice. A counter that is
    /// missing or fails authentication while a PIN is configured is
    /// tampering (§3.10) and wipes, even from a settings screen.
    fn sync_pin_counter_threshold(&self) -> Result<(), String> {
        let record = match read_master_key_record(std::path::Path::new(&self.data_dir)) {
            Ok(MasterKeyRecord::Wrapped(w)) => w,
            // No PIN configured: there is no counter to keep in sync.
            _ => return Ok(()),
        };
        match self.load_pin_attempt_state(record.legacy)? {
            Some(mut state) => {
                state.wipe_threshold = self.current_pin_wipe_threshold();
                self.save_pin_attempt_state(&state)
            }
            None => Err(self.wipe_for_counter_tamper()),
        }
    }

    /// §3.10: "Tampering with or deleting the counter file when PIN is
    /// enabled triggers immediate Self-Disavowed broadcast followed by
    /// identity wipe." `standard_erase` writes the Self-Disavowed marker
    /// first, then destroys every layer (§3.9.1). Returns the message the
    /// caller reports.
    fn wipe_for_counter_tamper(&self) -> String {
        self.diagnostic_log("identity", "pin_counter_tamper_wipe");
        self.wipe_local_identity_files();
        "PIN attempt counter was tampered with. Local data was erased.".to_string()
    }

    /// The `&self` half of a local wipe: on-disk erase, counter files, and
    /// in-memory key material. Callers holding `&mut self` follow up with
    /// `reset_identity_runtime_state`.
    fn wipe_local_identity_files(&self) {
        crate::identity::killswitch::standard_erase(std::path::Path::new(&self.data_dir));
        // The erase sweep already removed the counter files; clearing them
        // again is a no-op that still holds if the sweep was partial.
        let _ = self.clear_pin_attempt_files();
        self.clear_mesh_identity_runtime_state();
    }

    /// Count one failed attempt at wall-clock `now` and persist it.
    ///
    /// Returns `Ok(true)` when the stored wipe threshold was reached and the
    /// identity has been erased (§3.10 "Wipe threshold"). The timestamp is
    /// the caller's verified clock reading; this function never writes a
    /// substitute value.
    fn record_failed_pin_attempt(
        &mut self,
        mut state: PinAttemptState,
        now: u64,
    ) -> Result<bool, String> {
        state.failed_attempts = state.failed_attempts.saturating_add(1);
        state.last_failed_at = now;
        if let Some(threshold) = state.wipe_threshold {
            if state.failed_attempts >= threshold {
                self.diagnostic_log("identity", "pin_wipe_threshold_reached");
                self.wipe_local_identity_files();
                self.reset_identity_runtime_state();
                return Ok(true);
            }
        }
        self.save_pin_attempt_state(&state)?;
        Ok(false)
    }

    // -----------------------------------------------------------------------
    // Duress PIN (§3.9.2)
    // -----------------------------------------------------------------------

    /// Read and decode `pin.dat`, or `None` when absent or unreadable.
    ///
    /// A corrupt duress blob must not block a normal unlock, so decode
    /// failures degrade to "no duress PIN" (logged) rather than erroring.
    fn read_duress_blob(&self) -> Option<PinWrappedKey> {
        let bytes = match std::fs::read(self.duress_pin_path()) {
            Ok(bytes) => bytes,
            Err(err) => {
                if err.kind() != std::io::ErrorKind::NotFound {
                    self.diagnostic_log("identity", "duress_blob_unreadable");
                }
                return None;
            }
        };
        match serde_json::from_slice::<PinWrappedKey>(&bytes) {
            Ok(blob) => Some(blob),
            Err(_) => {
                self.diagnostic_log("identity", "duress_blob_undecodable");
                None
            }
        }
    }

    /// Try the key derived for this attempt against the duress blob.
    ///
    /// Returns the wrapping key, salt and parameters to wrap the replacement
    /// identity under when the duress PIN matched. The blob normally shares
    /// the primary record's salt and parameters, so this is a microsecond
    /// AEAD open with no second derivation. The only exception is a legacy
    /// mode 0x01 record, whose 16-byte salt a blob cannot share: there the
    /// blob is checked under its own salt (one extra derivation, once, until
    /// the successful unlock that migrates the record).
    fn match_duress_blob(
        &self,
        wrapped: &WrappedMasterKey,
        wrapping_key: &zeroize::Zeroizing<[u8; 32]>,
        pin: &[u8],
    ) -> Option<(zeroize::Zeroizing<[u8; 32]>, [u8; SALT_LEN], KdfParams)> {
        let blob = self.read_duress_blob()?;
        let mut blob_salt = [0u8; SALT_LEN];
        // A blob with any other salt length is malformed; `open_wrapped_key`
        // would reject it, so there is nothing to match.
        if blob.salt.len() != SALT_LEN {
            return None;
        }
        // Copy into the fixed-size buffer.
        blob_salt.copy_from_slice(&blob.salt);

        if blob.salt == wrapped.salt && blob.params() == wrapped.params {
            // Shared salt: the single derivation covers this blob.
            return pin::open_wrapped_key(&blob, wrapping_key)
                .ok()
                .map(|_| (wrapping_key.clone(), blob_salt, wrapped.params));
        }
        if wrapped.legacy {
            // Legacy fallback: derive under the blob's own parameters.
            let key = pin::derive_key_from_pin(pin, &blob.salt, blob.params()).ok()?;
            return pin::open_wrapped_key(&blob, &key)
                .ok()
                .map(|_| (key, blob_salt, blob.params()));
        }
        // A current-format record with a blob under a different salt is a
        // stale blob; it can never match and is reported as unconfigured.
        None
    }

    /// Salt and parameters of a usable duress blob, if one exists.
    ///
    /// The 0x01 → 0x02 migration re-wraps `identity.key` under these so the
    /// duress PIN keeps working without the user re-entering it.
    fn duress_blob_salt_params(&self) -> Option<([u8; SALT_LEN], KdfParams)> {
        let blob = self.read_duress_blob()?;
        if blob.salt.len() != SALT_LEN || blob.params().validate().is_err() {
            return None;
        }
        let mut salt = [0u8; SALT_LEN];
        // Copy into the fixed-size buffer.
        salt.copy_from_slice(&blob.salt);
        Some((salt, blob.params()))
    }

    /// Duress unlock (§3.9.2): decide in the foreground, destroy in the
    /// background.
    ///
    /// Foreground (inside the one-second budget): generate the replacement
    /// self, encode its `identity.key` (wrapped under the duress PIN with
    /// the key already derived for this attempt — no second Argon2 pass)
    /// and `identity.dat`, seal a fresh attempt counter, start the 60–120 s
    /// wind-down timer, and clear the old in-memory state. The caller then
    /// activates the returned identity and the UI sees a normal unlock.
    ///
    /// Background thread, in order (§3.9.2 step 4): Self-Disavowed marker
    /// and Layer 2/3 erase (`duress_erase`, which also removes `pin.dat`),
    /// then the new counter files, then the new identity files. If the
    /// process dies before the thread finishes, the device simply has no
    /// Layer 2 identity on next start — consistent with "I reinstalled".
    /// If the thread cannot even be spawned, the same work runs inline:
    /// the erase is never skipped.
    fn begin_duress_rotation(
        &mut self,
        wrapping_key: zeroize::Zeroizing<[u8; 32]>,
        salt: [u8; SALT_LEN],
        params: KdfParams,
    ) -> Result<SelfIdentity, String> {
        self.diagnostic_log("identity", "duress_unlock");
        let data_dir = std::path::PathBuf::from(&self.data_dir);

        // Replacement self under the reset (empty) profile.
        let fresh = SelfIdentity::generate(None);
        let key_bytes = encode_wrapped_key_file(&fresh.master_key, &wrapping_key, &salt, params)
            .map_err(|e| format!("Failed to wrap duress identity: {e}"))?;
        let dat_bytes = fresh
            .encode_dat_file()
            .map_err(|e| format!("Failed to encode duress identity: {e}"))?;
        // The derived key has done its work; drop it before anything else.
        drop(wrapping_key);

        // Fresh counter under a fresh key: the duress PIN is now the
        // legitimate unlock PIN (§3.9.2 step 5) with a clean history.
        let mut counter_key = zeroize::Zeroizing::new([0u8; 32]);
        Self::fill_random(&mut *counter_key)?;
        let sealed_counter = pin::seal_attempt_state(&PinAttemptState::default(), &counter_key)
            .map_err(|e| format!("Failed to seal duress attempt counter: {e}"))?;

        // Start the transition timer now: the old identity's taper begins
        // the moment the new one takes over (§3.9.2 transition masking).
        // A poisoned lock must not turn the erase into a panic across FFI.
        *self
            .duress_wind_down
            .lock()
            .unwrap_or_else(|e| e.into_inner()) =
            Some(crate::identity::killswitch::start_duress_wind_down());

        // Old in-memory self and masks go before the UI sees the new one.
        self.reset_identity_runtime_state();

        // Everything that touches disk runs off the response path.
        let work = move || {
            finish_duress_rotation(
                &data_dir,
                &key_bytes,
                &dat_bytes,
                &counter_key,
                &sealed_counter,
            )
        };
        if let Err(err) = std::thread::Builder::new()
            .name("duress-rotation".to_string())
            .spawn(work.clone())
        {
            // No thread available: never skip the erase, run it here.
            eprintln!(
                "[identity] WARNING: duress rotation thread unavailable ({err}); running inline"
            );
            work();
        }
        Ok(fresh)
    }

    /// Wrap the current master key under a duress PIN and persist `pin.dat`.
    ///
    /// The blob shares the primary record's salt and parameters so the
    /// unlock path can try one derived key against both (§3.10 timing
    /// normalization); that also means it must be set while a current-format
    /// unlock PIN exists, and must differ from it.
    fn persist_duress_pin(&self, pin: &str) -> Result<(), String> {
        if !self.identity_unlocked {
            return Err("Identity must be unlocked before setting a duress PIN".to_string());
        }
        pin::validate_pin(pin.as_bytes()).map_err(|e| e.to_string())?;
        let data_dir = std::path::Path::new(&self.data_dir);
        let wrapped = match read_master_key_record(data_dir) {
            Ok(MasterKeyRecord::Wrapped(w)) => w,
            Ok(MasterKeyRecord::Plain(_)) => {
                return Err("Set an unlock PIN before setting a duress PIN".to_string());
            }
            Err(e) => return Err(format!("Failed to read identity key: {e}")),
        };
        // A legacy record cannot share its salt; unlock migrates it, so this
        // only happens if the record was swapped while unlocked.
        let Some(salt) = wrapped.shared_salt() else {
            return Err(
                "Unlock PIN format is outdated; unlock again before setting a duress PIN"
                    .to_string(),
            );
        };
        // One derivation under the shared salt.
        let wrapping_key = pin::derive_key_from_pin(pin.as_bytes(), &salt, wrapped.params)
            .map_err(|e| format!("Failed to set duress PIN: {e}"))?;
        // Same PIN as the unlock PIN would make the primary blob win every
        // time and the duress blob unreachable.
        if wrapped.open(&wrapping_key).is_ok() {
            return Err("Duress PIN must differ from the current unlock PIN".to_string());
        }
        let identity = self.identity.lock().unwrap_or_else(|e| e.into_inner());
        let Some(identity) = identity.as_ref() else {
            return Err("Identity is not loaded".to_string());
        };
        let blob = pin::wrap_key_under(&identity.master_key, &wrapping_key, &salt, wrapped.params)
            .map_err(|e| format!("Failed to set duress PIN: {e}"))?;
        let encoded =
            serde_json::to_vec(&blob).map_err(|e| format!("Failed to encode duress PIN: {e}"))?;
        write_atomic(&self.duress_pin_path(), &encoded)
            .map_err(|e| format!("Failed to persist duress PIN: {e}"))?;
        Ok(())
    }

    fn clear_duress_pin_file(&self) -> Result<(), String> {
        let path = self.duress_pin_path();
        if !path.exists() {
            return Ok(());
        }
        std::fs::remove_file(path).map_err(|e| format!("Failed to remove duress PIN: {e}"))
    }

    /// Verify a duress PIN against `pin.dat` (settings flows only).
    ///
    /// Derives under the blob's own salt and parameters; the unlock screen
    /// never calls this, it uses `match_duress_blob` with the shared key.
    fn duress_pin_matches(&self, pin: &str) -> Result<bool, String> {
        let Some(wrapped) = self.read_duress_blob() else {
            return Ok(false);
        };
        match pin::unwrap_key_with_pin(&wrapped, pin.as_bytes()) {
            Ok(_) => Ok(true),
            Err(PinError::WrongPin) => Ok(false),
            Err(err) => Err(format!("Failed to verify duress PIN: {err}")),
        }
    }
    fn reset_identity_runtime_state(&mut self) {
        // Wipe key material first through the guarded path, then clear state.
        self.clear_identity_keys();
        self.identity_unlocked = false;
        self.rooms.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.contacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.masks.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.discoverable_gardens
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        *self
            .android_proximity_state
            .lock()
            .unwrap_or_else(|e| e.into_inner()) =
            crate::service::runtime::AndroidProximityState::default();
        *self
            .service_registry
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = crate::services::registry::ServiceStore::new();
        self.registered_devices
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.groups
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.published_files
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.pending_message_requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.gossip.lock().unwrap_or_else(|e| e.into_inner()).map =
            crate::network::map::NetworkMap::default();
        {
            let mut routing_table = self.routing_table.lock().unwrap_or_else(|e| e.into_inner());
            routing_table.public.clear();
            routing_table.groups.clear();
            routing_table.local.clear();
            routing_table.ble_ephemeral.clear();
        }
        *self
            .distress_message_enabled
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = false;
        *self
            .liveness_signal_enabled
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = false;
        *self
            .wrong_pin_wipe_enabled
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = false;
        *self
            .wrong_pin_wipe_threshold
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = 5;
        *self
            .remote_wipe_enabled
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = false;
        *self.active_tier.lock().unwrap_or_else(|e| e.into_inner()) = 0;
        *self
            .bandwidth_profile
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = 1;
        self.vault = None;
    }

    fn activate_identity(&mut self, identity: SelfIdentity) {
        let master_key = *identity.master_key;
        self.vault = Some(VaultManager::new(
            std::path::PathBuf::from(&self.data_dir),
            master_key,
        ));
        self.identity_unlocked = true;
        *self.identity.lock().unwrap_or_else(|e| e.into_inner()) = Some(identity);
        self.load_from_vault();
        self.sync_store_forward_mode();
        self.ensure_default_masks();
        let make_primary = self
            .registered_devices
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty();
        let _ = self.ensure_local_device_registered(make_primary);
    }

    fn emit_identity_settings_updated(&self) {
        let peer_id = self
            .identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|id| id.peer_id().to_hex())
            .unwrap_or_default();
        let ed25519_pub = self
            .identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|id| hex::encode(id.ed25519_pub))
            .unwrap_or_default();
        let flags = self
            .transport_flags
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let node_mode = *self.node_mode.lock().unwrap_or_else(|e| e.into_inner());
        let clearnet_port = *self.clearnet_port.lock().unwrap_or_else(|e| e.into_inner());
        let active_tier = *self.active_tier.lock().unwrap_or_else(|e| e.into_inner());
        let bandwidth_profile = *self
            .bandwidth_profile
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        self.push_event(
            "SettingsUpdated",
            build_settings_json(
                &flags,
                node_mode,
                &self.threat_context,
                &peer_id,
                &ed25519_pub,
                clearnet_port,
                active_tier,
                bandwidth_profile,
                self.build_layer1_status_json(),
            ),
        );
    }

    /// Prepare backend startup state from persisted identity material.
    ///
    /// If an identity exists without a PIN, Layer 2 is auto-unlocked so the
    /// shell can come up without a frontend-driven unlock probe. If an
    /// identity exists at all, Layer 1 transport readiness is established from
    /// the backend side rather than app.dart driving it.
    pub fn initialize_startup_state(&mut self) {
        if let Err(error) = self.load_or_create_mesh_identity() {
            self.set_error(&format!("Mesh identity startup failed: {error}"));
        }
        self.refresh_layer1_participation_state();
        if !self.has_identity() {
            return;
        }
        if let Err(error) = self.ensure_layer1_transport_started() {
            self.set_error(&format!("Layer 1 transport startup failed: {error}"));
        }
        if !self.has_pin_configured() {
            if let Err(error) = self.unlock_identity(None) {
                self.set_error(&format!("Automatic identity unlock failed: {error}"));
            }
        }
    }

    fn ensure_default_masks(&self) {
        let mut masks = self.masks.lock().unwrap_or_else(|e| e.into_inner());
        if !masks.is_empty() {
            return;
        }
        let identity_guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
        let Some(identity) = identity_guard.as_ref() else {
            return;
        };
        let public_mask = crate::identity::mask::Mask::derive_from_self(
            &identity.ed25519_signing,
            &identity.x25519_secret,
            crate::identity::mask::MaskId([0u8; 16]),
            identity
                .display_name
                .clone()
                .unwrap_or_else(|| "Public".to_string()),
            0,
            true,
        );
        masks.push(public_mask.metadata());
        drop(identity_guard);
        drop(masks);
        self.save_masks();
    }

    // -----------------------------------------------------------------------
    // Create
    // -----------------------------------------------------------------------

    /// Generate a new identity with an optional display name.
    ///
    /// Produces fresh Ed25519, X25519, preauth-X25519, and ML-KEM-768 key
    /// pairs.  Persists to `data_dir/identity.dat` (PIN protection can be
    /// added later via a separate call).  Initialises the vault and loads any
    /// existing vault state (first run = empty).
    ///
    /// Returns `Ok(())` on success, `Err(reason)` on failure.
    pub fn create_identity(&mut self, display_name: Option<String>) -> Result<(), String> {
        self.diagnostic_log("identity", "create_started");
        // Generate fresh key material.
        let identity = SelfIdentity::generate(display_name);
        let peer_id = identity.peer_id();
        let ed25519_pub = identity.ed25519_pub;
        let master_key = *identity.master_key;

        // Persist identity to disk (no PIN — PIN set separately via mi_set_pin).
        let data_dir = std::path::Path::new(&self.data_dir);
        identity
            .save_to_disk(data_dir, None)
            .map_err(|e| format!("Failed to persist identity: {e}"))?;
        self.diagnostic_log("identity", "persist_completed");

        // Initialise vault with the identity master key.
        self.activate_identity(identity);
        self.diagnostic_log("identity", "activation_completed");
        self.ensure_layer1_transport_started()?;
        self.diagnostic_log("identity", "network_reconcile_returned");

        // Emit SettingsUpdated so Flutter knows identity is now live.
        let _ = master_key;
        let flags = self
            .transport_flags
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let node_mode = *self.node_mode.lock().unwrap_or_else(|e| e.into_inner());
        let clearnet_port = *self.clearnet_port.lock().unwrap_or_else(|e| e.into_inner());
        let active_tier = *self.active_tier.lock().unwrap_or_else(|e| e.into_inner());
        let bandwidth_profile = *self
            .bandwidth_profile
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        self.push_event(
            "SettingsUpdated",
            build_settings_json(
                &flags,
                node_mode,
                &self.threat_context,
                &peer_id.to_hex(),
                &hex::encode(ed25519_pub),
                clearnet_port,
                active_tier,
                bandwidth_profile,
                self.build_layer1_status_json(),
            ),
        );

        self.diagnostic_log("identity", "create_completed");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Unlock
    // -----------------------------------------------------------------------

    /// Load and decrypt the existing identity from disk.
    ///
    /// Pass `pin = None` if no PIN was set.  On success, restores all vault
    /// state (rooms, contacts, messages, settings, ratchet sessions) and emits
    /// `SettingsUpdated`.
    ///
    /// Returns `Ok(())` on success, `Err(reason)` on failure (wrong PIN, file
    /// missing, or I/O error).
    pub fn unlock_identity(&mut self, pin: Option<String>) -> Result<(), String> {
        let started = std::time::Instant::now();
        // Zeroized on drop so the PIN does not linger on the heap after the
        // derivation (§3.10 "process monitoring mitigation").
        let pin = pin.map(zeroize::Zeroizing::new);
        let is_pin_attempt = pin.is_some();
        let result = self.unlock_identity_inner(pin.as_deref().map(String::as_str));
        // §3.9 / §3.10: every PIN attempt — correct, wrong or duress — returns
        // at the same wall-clock offset. The derivation and decision above
        // take a fraction of the budget; the remainder is slept here, in
        // Rust, so no caller can skip it. A no-PIN auto-unlock at startup is
        // not a guess and is not padded.
        if is_pin_attempt {
            if let Some(remaining) = UNLOCK_RESPONSE_DEADLINE.checked_sub(started.elapsed()) {
                std::thread::sleep(remaining);
            }
        }
        result
    }

    /// The unlock decision, without the response-time padding.
    fn unlock_identity_inner(&mut self, pin: Option<&str>) -> Result<(), String> {
        let data_dir = std::path::PathBuf::from(&self.data_dir);
        let record = match read_master_key_record(&data_dir) {
            Ok(record) => record,
            Err(IdentityError::NotFound(_)) => {
                return Err("No identity found — call mi_create_identity first".to_string());
            }
            Err(other) => return Err(format!("Identity unlock failed: {other}")),
        };
        let identity = match record {
            MasterKeyRecord::Plain(master_key) => {
                // No PIN configured: nothing to count, and stale counter
                // files from a removed PIN must not survive.
                let identity = SelfIdentity::load_dat_file(&data_dir, master_key)
                    .map_err(|e| format!("Identity unlock failed: {e}"))?;
                self.clear_pin_attempt_files()?;
                identity
            }
            MasterKeyRecord::Wrapped(wrapped) => {
                self.unlock_wrapped_identity(&data_dir, &wrapped, pin)?
            }
        };
        self.activate_identity(identity);
        self.ensure_layer1_transport_started()?;
        // Settings are loaded now; push the wipe threshold into the counter
        // so the next locked-screen attempt enforces the user's choice.
        self.sync_pin_counter_threshold()?;
        // Build and sign our self-entry for the gossip network map (§4.5).
        // This lets other nodes learn our addresses and public keys.
        {
            use crate::network::map::NetworkMapEntry;
            use ed25519_dalek::SigningKey;

            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ref id) = *guard {
                let signing_key = SigningKey::from_bytes(&id.ed25519_signing.to_bytes());
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                let public_profile = id.display_name.as_ref().map(|name| {
                    crate::network::map::PublicProfileSummary {
                        display_name: Some(name.clone()),
                        bio: None,
                        avatar_hash: None,
                    }
                });

                let kem_ek = if id.kem_encapsulation_key.is_empty() {
                    None
                } else {
                    Some(id.kem_encapsulation_key.clone())
                };

                // Sign the preauth key with our Ed25519 identity key (§7.0.1).
                let preauth_sig = {
                    use crate::crypto::x3dh::PreauthBundle;
                    let msg = PreauthBundle::signed_message(&id.preauth_x25519_pub);
                    let secret = id.ed25519_signing.to_bytes();
                    Some(crate::crypto::signing::sign(
                        &secret,
                        crate::crypto::x3dh::PREAUTH_SIG_DOMAIN,
                        &msg,
                    ))
                };

                let mut self_entry = NetworkMapEntry {
                    peer_id: id.peer_id(),
                    public_keys: vec![crate::network::map::PublicKeyRecord {
                        ed25519_public: id.ed25519_pub,
                        x25519_public: *id.x25519_pub.as_bytes(),
                        preauth_x25519_public: Some(*id.preauth_x25519_pub.as_bytes()),
                        kem_encapsulation_key: kem_ek,
                        preauth_sig,
                    }],
                    version: crate::network::map::MAP_ENTRY_FORMAT_VERSION,
                    transport_hints: vec![],
                    public_profile,
                    services: vec![],
                    sequence: 1,
                    signature: vec![],
                    prev_hash: None,
                    local_trust: TrustLevel::InnerCircle,
                };
                self_entry.sign(&signing_key);
                drop(guard);

                let mut gossip = self.gossip.lock().unwrap_or_else(|e| e.into_inner());
                let _ = gossip.map.insert(self_entry, now);
            }
        }

        // Emit settings event so Flutter receives the unlocked identity details.
        self.emit_identity_settings_updated();

        Ok(())
    }

    /// One PIN attempt against a wrapped `identity.key` (§3.10).
    ///
    /// Order of operations:
    /// 1. counter present and authentic, else tamper wipe;
    /// 2. clock readable (never substituted), backoff and rollback checks;
    /// 3. exactly one Argon2id derivation under the record's salt/params;
    /// 4. the derived key is tried against the primary record and the
    ///    duress blob — both are microsecond AEAD opens;
    /// 5. correct → load, migrate a legacy record, zero the counter;
    ///    duress → `begin_duress_rotation`; neither → count the failure.
    fn unlock_wrapped_identity(
        &mut self,
        data_dir: &std::path::Path,
        wrapped: &WrappedMasterKey,
        pin: Option<&str>,
    ) -> Result<SelfIdentity, String> {
        let Some(pin) = pin else {
            return Err("PIN required".to_string());
        };
        // A PIN outside 4–16 digits cannot be the configured one; it is not
        // a guess at the secret, so it is refused without being counted.
        if pin::validate_pin(pin.as_bytes()).is_err() {
            return Err("Wrong PIN".to_string());
        }

        // 1. Counter.
        let Some(state) = self.load_pin_attempt_state(wrapped.legacy)? else {
            let message = self.wipe_for_counter_tamper();
            self.reset_identity_runtime_state();
            return Err(message);
        };

        // 2. Clock and backoff. A clock error refuses the attempt outright;
        // zero is never written in its place.
        let now = Self::wall_clock_secs()?;
        match pin::is_attempt_allowed(&state, now) {
            Ok(()) => {}
            Err(PinError::LockedOut) => {
                return Err("PIN entry is temporarily locked. Try again later.".to_string());
            }
            Err(err) => return Err(format!("PIN unlock failed: {err}")),
        }

        // 3. The single derivation.
        let wrapping_key = wrapped
            .derive_wrapping_key(pin.as_bytes())
            .map_err(|e| format!("PIN unlock failed: {e}"))?;

        // 4. Try both records.
        let primary = wrapped.open(&wrapping_key);
        let duress = self.match_duress_blob(wrapped, &wrapping_key, pin.as_bytes());

        // 5. Decide.
        match primary {
            Ok(master_key) => {
                let identity = SelfIdentity::load_dat_file(data_dir, master_key)
                    .map_err(|e| format!("Identity unlock failed: {e}"))?;
                if wrapped.legacy {
                    self.migrate_legacy_wrap(data_dir, &identity, pin)?;
                }
                // The PIN is proven: the counter restarts from zero. The
                // stored threshold is kept until settings are loaded.
                self.save_pin_attempt_state(&PinAttemptState {
                    failed_attempts: 0,
                    last_failed_at: 0,
                    wipe_threshold: state.wipe_threshold,
                })?;
                Ok(identity)
            }
            Err(IdentityError::WrongPin) => match duress {
                Some((key, salt, params)) => self.begin_duress_rotation(key, salt, params),
                None => {
                    if self.record_failed_pin_attempt(state, now)? {
                        return Err(
                            "Too many wrong PIN attempts. Local data was erased.".to_string()
                        );
                    }
                    Err("Wrong PIN".to_string())
                }
            },
            Err(other) => Err(format!("Identity unlock failed: {other}")),
        }
    }

    /// Re-wrap a legacy mode 0x01 `identity.key` as mode 0x02 under the
    /// spec parameters after a successful unlock.
    ///
    /// If a duress blob exists, its salt and parameters are adopted so the
    /// duress PIN keeps working without re-entry; otherwise a fresh salt is
    /// drawn. This is the one place a correct unlock performs a second
    /// derivation, and it happens once per identity.
    fn migrate_legacy_wrap(
        &self,
        data_dir: &std::path::Path,
        identity: &SelfIdentity,
        pin: &str,
    ) -> Result<(), String> {
        self.diagnostic_log("identity", "pin_wrap_migrate_0x01_to_0x02");
        let (salt, params) = match self.duress_blob_salt_params() {
            Some(existing) => existing,
            None => {
                let mut salt = [0u8; SALT_LEN];
                Self::fill_random(&mut salt)?;
                (salt, KdfParams::SPEC)
            }
        };
        let wrapping_key = pin::derive_key_from_pin(pin.as_bytes(), &salt, params)
            .map_err(|e| format!("Failed to upgrade PIN wrap: {e}"))?;
        identity
            .save_wrapped(data_dir, &wrapping_key, &salt, params)
            .map_err(|e| format!("Failed to upgrade PIN wrap: {e}"))
    }
    /// Return backend-owned security configuration for settings screens.
    pub fn get_security_config(&self) -> String {
        serde_json::json!({
            "pinEnabled": self.has_pin_configured(),
            "duressPinConfigured": self.has_duress_pin(),
            "wrongPinWipeEnabled": *self.wrong_pin_wipe_enabled.lock().unwrap_or_else(|e| e.into_inner()),
            "wrongPinWipeThreshold": *self.wrong_pin_wipe_threshold.lock().unwrap_or_else(|e| e.into_inner()),
            "remoteWipeEnabled": *self.remote_wipe_enabled.lock().unwrap_or_else(|e| e.into_inner()),
            "distressMessageEnabled": *self.distress_message_enabled.lock().unwrap_or_else(|e| e.into_inner()),
            "livenessSignalEnabled": *self.liveness_signal_enabled.lock().unwrap_or_else(|e| e.into_inner()),
        })
        .to_string()
    }

    /// Update backend-owned security settings exposed in the settings UI.
    pub fn set_security_config(&self, config_json: &str) -> Result<(), String> {
        let value: serde_json::Value =
            serde_json::from_str(config_json).map_err(|_| "invalid security config json")?;

        if let Some(enabled) = value
            .get("distressMessageEnabled")
            .and_then(|v| v.as_bool())
        {
            *self
                .distress_message_enabled
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = enabled;
        }
        if let Some(enabled) = value.get("livenessSignalEnabled").and_then(|v| v.as_bool()) {
            *self
                .liveness_signal_enabled
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = enabled;
        }
        if let Some(enabled) = value.get("wrongPinWipeEnabled").and_then(|v| v.as_bool()) {
            *self
                .wrong_pin_wipe_enabled
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = enabled;
        }
        if let Some(threshold) = value
            .get("wrongPinWipeThreshold")
            .and_then(|v| v.as_u64())
            .map(|v| v as u8)
        {
            if matches!(threshold, 3 | 5 | 10) {
                *self
                    .wrong_pin_wipe_threshold
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = threshold;
            } else {
                return Err("wrong PIN wipe threshold must be 3, 5, or 10".into());
            }
        }
        if let Some(enabled) = value.get("remoteWipeEnabled").and_then(|v| v.as_bool()) {
            *self
                .remote_wipe_enabled
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = enabled;
        }

        self.save_settings();
        // The unlock screen reads the wipe threshold from the sealed counter
        // (the settings vault is locked then), so mirror the change there.
        self.sync_pin_counter_threshold()?;
        Ok(())
    }

    /// Configure a duress PIN that triggers a fresh-account erase on unlock.
    pub fn set_duress_pin(&self, pin: String) -> Result<(), String> {
        self.persist_duress_pin(&pin)
    }

    /// Replace the current duress PIN after verifying the old duress PIN.
    ///
    /// Requires an unlocked identity first: the verification below runs a
    /// derivation outside the attempt counter, so it must never be reachable
    /// from a locked device as a backoff-free guessing oracle.
    pub fn change_duress_pin(&self, current_pin: String, new_pin: String) -> Result<(), String> {
        if !self.identity_unlocked {
            return Err("Identity must be unlocked before changing the duress PIN".to_string());
        }
        if !self.duress_pin_matches(&current_pin)? {
            return Err("Wrong duress PIN".to_string());
        }
        self.persist_duress_pin(&new_pin)
    }

    /// Remove the configured duress PIN after verifying it.
    ///
    /// Unlocked-only for the same reason as `change_duress_pin`.
    pub fn remove_duress_pin(&self, current_pin: String) -> Result<(), String> {
        if !self.identity_unlocked {
            return Err("Identity must be unlocked before removing the duress PIN".to_string());
        }
        if !self.duress_pin_matches(&current_pin)? {
            return Err("Wrong duress PIN".to_string());
        }
        self.clear_duress_pin_file()
    }

    /// Return persisted masks in UI JSON form.
    pub fn get_masks_json(&self) -> String {
        let masks = self.masks.lock().unwrap_or_else(|e| e.into_inner());
        serde_json::Value::Array(
            masks
                .iter()
                .map(|mask| {
                    serde_json::json!({
                        "id": mask.id.to_hex(),
                        "name": mask.name,
                        "avatarColor": mask.avatar_color,
                        "isPublic": mask.is_public,
                        "isAnonymous": mask.is_anonymous,
                        "peerId": mask.peer_id,
                        "ed25519Pub": mask.ed25519_pub,
                        "x25519Pub": mask.x25519_pub,
                    })
                })
                .collect(),
        )
        .to_string()
    }

    /// Create a new mask from a JSON payload and persist its metadata.
    pub fn create_mask(&self, config_json: &str) -> Result<(), String> {
        if !self.identity_unlocked {
            return Err("identity must be unlocked".into());
        }
        let value: serde_json::Value =
            serde_json::from_str(config_json).map_err(|_| "invalid mask json")?;
        let name = value
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| "mask name is required".to_string())?
            .to_string();
        let avatar_color = value
            .get("avatarColor")
            .and_then(|v| v.as_u64())
            .map(|v| (v as u8) % 8)
            .unwrap_or(0);
        let is_anonymous = value
            .get("isAnonymous")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let identity_guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
        let Some(identity) = identity_guard.as_ref() else {
            return Err("identity not loaded".into());
        };
        let mask = if is_anonymous {
            crate::identity::mask::Mask::generate_anonymous(name, avatar_color)
        } else {
            crate::identity::mask::Mask::derive_from_self(
                &identity.ed25519_signing,
                &identity.x25519_secret,
                crate::identity::mask::MaskId::random(),
                name,
                avatar_color,
                false,
            )
        };
        let metadata = mask.metadata();
        drop(identity_guard);

        let mut masks = self.masks.lock().unwrap_or_else(|e| e.into_inner());
        if masks
            .iter()
            .any(|existing| existing.peer_id == metadata.peer_id)
        {
            return Err("mask already exists".into());
        }
        masks.push(metadata);
        drop(masks);
        self.save_masks();
        Ok(())
    }

    /// Return the current device list for the multi-device settings screen.
    pub fn get_devices_json(&self) -> String {
        let _ = self.ensure_local_device_registered(false);
        let local_device_id = self.read_or_create_local_device_id().ok();
        let peer_id = self
            .identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|identity| identity.peer_id().to_hex())
            .unwrap_or_default();
        let devices = self
            .registered_devices
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let payload: Vec<serde_json::Value> = devices
            .into_iter()
            .map(|device| {
                serde_json::json!({
                    "id": device.id,
                    "name": device.name,
                    "platform": device.platform,
                    "isPrimary": device.is_primary,
                    "isThisDevice": local_device_id.as_deref() == Some(device.id.as_str()),
                    "lastSeenMs": device.last_seen_ms,
                    "peerId": peer_id,
                    "authorizedByDeviceId": device.authorized_by_device_id,
                })
            })
            .collect();
        serde_json::to_string(&payload).unwrap_or_else(|_| "[]".to_string())
    }

    /// Create a new-device enrollment request for this device.
    pub fn create_device_enrollment_request(
        &self,
        device_name: Option<String>,
    ) -> Result<String, String> {
        if self.has_identity() {
            return Err(
                "This device already has an identity. Reset it before linking a different one."
                    .to_string(),
            );
        }
        let target_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let target_public = X25519Public::from(&target_secret);
        let request = DeviceEnrollmentRequest {
            version: 1,
            request_id: Self::generate_device_id()?,
            target_device_id: Self::generate_device_id()?,
            device_name: device_name
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| current_device_name().to_string()),
            platform: current_platform_id().to_string(),
            target_public_key: hex::encode(target_public.as_bytes()),
        };
        self.save_pending_device_enrollment(&PendingDeviceEnrollment {
            request_id: request.request_id.clone(),
            target_device_id: request.target_device_id.clone(),
            device_name: request.device_name.clone(),
            platform: request.platform.clone(),
            target_secret_key: hex::encode(target_secret.to_bytes()),
        })?;
        serde_json::to_string(&request)
            .map_err(|e| format!("Failed to encode device enrollment request: {e}"))
    }

    fn rotate_multi_device_sessions(&self) {
        self.ratchet_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.save_ratchet_sessions();
        self.x3dh_pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.pqxdh_pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        let now = Self::current_time_ms() / 1000;
        let mut groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
        for group in groups.iter_mut() {
            let mut symmetric_key = [0u8; 32];
            let mut sender_chain_key = [0u8; 32];
            let mut sender_signing_key = [0u8; 64];
            if !try_random_fill(&mut symmetric_key)
                || !try_random_fill(&mut sender_chain_key)
                || !try_random_fill(&mut sender_signing_key)
            {
                continue;
            }
            group.symmetric_key = symmetric_key;
            group.sender_key_epoch = group.sender_key_epoch.saturating_add(1);
            group.last_rekey_at = now;
            group.my_sender_chain_key = Some(sender_chain_key);
            group.my_sender_iteration = 0;
            group.my_sender_signing_key = Some(sender_signing_key);
            group.peer_sender_keys.clear();
        }
        drop(groups);
        self.save_groups();
    }

    /// Complete a device-enrollment request on the primary device.
    pub fn complete_device_enrollment(&mut self, request_json: &str) -> Result<String, String> {
        if !self.identity_unlocked {
            return Err("Unlock the identity before linking another device".to_string());
        }
        let request: DeviceEnrollmentRequest = serde_json::from_str(request_json)
            .map_err(|e| format!("Invalid device request: {e}"))?;
        let local_device_id = self.read_or_create_local_device_id()?;
        let devices = self
            .registered_devices
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let Some(primary_device) = devices.iter().find(|device| device.id == local_device_id)
        else {
            return Err("This device is not registered as part of the shared identity".to_string());
        };
        if !primary_device.is_primary {
            return Err("Only the primary device can authorize another device".to_string());
        }
        let target_public_bytes = hex::decode(&request.target_public_key)
            .map_err(|e| format!("Invalid target public key: {e}"))?;
        if target_public_bytes.len() != 32 {
            return Err("Target public key must be 32 bytes".to_string());
        }
        let mut target_public_array = [0u8; 32];
        target_public_array.copy_from_slice(&target_public_bytes);
        let target_public = X25519Public::from(target_public_array);
        let sender_secret = X25519Secret::random_from_rng(rand_core::OsRng);
        let sender_public = X25519Public::from(&sender_secret);
        let shared_secret = sender_secret.diffie_hellman(&target_public);
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut aead_key = [0u8; 32];
        let mut nonce_bytes = [0u8; 12];
        hk.expand(b"meshinfinity-device-enrollment-key-v1", &mut aead_key)
            .map_err(|_| "Failed to derive device enrollment key".to_string())?;
        hk.expand(b"meshinfinity-device-enrollment-nonce-v1", &mut nonce_bytes)
            .map_err(|_| "Failed to derive device enrollment nonce".to_string())?;
        let cipher = ChaCha20Poly1305::new_from_slice(&aead_key)
            .map_err(|_| "Failed to initialize device enrollment cipher".to_string())?;
        let mut updated_devices = devices.clone();
        let now = Self::current_time_ms();
        if let Some(existing) = updated_devices
            .iter_mut()
            .find(|device| device.id == request.target_device_id)
        {
            existing.name = request.device_name.clone();
            existing.platform = request.platform.clone();
            existing.last_seen_ms = now;
            existing.authorized_by_device_id = Some(local_device_id.clone());
        } else {
            updated_devices.push(RegisteredDevice {
                id: request.target_device_id.clone(),
                name: request.device_name.clone(),
                platform: request.platform.clone(),
                is_primary: false,
                added_at_ms: now,
                last_seen_ms: now,
                authorized_by_device_id: Some(local_device_id.clone()),
            });
        }
        updated_devices.sort_by(|a, b| {
            a.added_at_ms
                .cmp(&b.added_at_ms)
                .then_with(|| a.id.cmp(&b.id))
        });
        *self
            .registered_devices
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = updated_devices.clone();
        self.save_registered_devices();
        let (identity_payload, master_key) = {
            let identity = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            let Some(identity) = identity.as_ref() else {
                return Err("Identity is not loaded".to_string());
            };
            (
                hex::encode(identity.serialize_payload()),
                hex::encode(*identity.master_key),
            )
        };
        let payload = DeviceTransferPayload {
            version: 1,
            request_id: request.request_id.clone(),
            target_device_id: request.target_device_id.clone(),
            registered_devices: updated_devices,
            identity_payload,
            master_key,
            settings: self.snapshot_settings_vault(),
            contacts: self
                .contacts
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .all()
                .iter()
                .map(|contact| (*contact).clone())
                .collect(),
            rooms: self.rooms.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            messages: self
                .messages
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            masks: self.masks.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        };
        let plaintext = serde_json::to_vec(&payload)
            .map_err(|e| format!("Failed to encode device transfer payload: {e}"))?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
            .map_err(|_| "Failed to encrypt device transfer payload".to_string())?;
        let signature_message = [
            request.request_id.as_bytes(),
            sender_public.as_bytes(),
            nonce_bytes.as_slice(),
            ciphertext.as_slice(),
        ]
        .concat();
        let registration_sig = self
            .identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .ok_or_else(|| "Identity is not loaded".to_string())?
            .ed25519_signing
            .sign(&signature_message);
        serde_json::to_string(&DeviceTransferEnvelope {
            version: 1,
            request_id: request.request_id,
            sender_public_key: hex::encode(sender_public.as_bytes()),
            nonce: hex::encode(nonce_bytes),
            ciphertext: hex::encode(ciphertext),
            registration_sig: hex::encode(registration_sig.to_bytes()),
        })
        .map_err(|e| format!("Failed to encode device transfer envelope: {e}"))
    }

    /// Remove a registered secondary device and rotate future session state.
    pub fn remove_device(&self, device_id: &str) -> Result<(), String> {
        if self
            .identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_none()
        {
            return Err("Unlock the identity before removing a device".to_string());
        }
        let local_device_id = self.read_or_create_local_device_id()?;
        let mut devices = self
            .registered_devices
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let Some(local_device) = devices.iter().find(|device| device.id == local_device_id) else {
            return Err("This device is not registered as part of the shared identity".to_string());
        };
        if !local_device.is_primary {
            return Err("Only the primary device can remove another device".to_string());
        }
        if device_id == local_device_id {
            return Err("Remove this device by resetting the identity on it".to_string());
        }
        let removed_count_before = devices.len();
        devices.retain(|device| device.id != device_id);
        if devices.len() == removed_count_before {
            return Err("Device not found".to_string());
        }
        drop(devices);
        self.save_registered_devices();
        self.rotate_multi_device_sessions();
        Ok(())
    }

    /// Accept a device-enrollment package on the new device.
    pub fn accept_device_enrollment(&mut self, package_json: &str) -> Result<(), String> {
        if self.has_identity() {
            return Err(
                "This device already has an identity. Reset it before linking a different one."
                    .to_string(),
            );
        }
        let pending = self.load_pending_device_enrollment()?;
        let envelope: DeviceTransferEnvelope = serde_json::from_str(package_json)
            .map_err(|e| format!("Invalid device enrollment package: {e}"))?;
        if envelope.request_id != pending.request_id {
            return Err("Device enrollment package does not match this device request".to_string());
        }
        let target_secret_bytes = hex::decode(&pending.target_secret_key)
            .map_err(|e| format!("Invalid local device secret: {e}"))?;
        if target_secret_bytes.len() != 32 {
            return Err("Local device secret has invalid length".to_string());
        }
        let mut target_secret_array = [0u8; 32];
        target_secret_array.copy_from_slice(&target_secret_bytes);
        let target_secret = X25519Secret::from(target_secret_array);
        let sender_public_bytes = hex::decode(&envelope.sender_public_key)
            .map_err(|e| format!("Invalid sender public key: {e}"))?;
        if sender_public_bytes.len() != 32 {
            return Err("Sender public key must be 32 bytes".to_string());
        }
        let mut sender_public_array = [0u8; 32];
        sender_public_array.copy_from_slice(&sender_public_bytes);
        let sender_public = X25519Public::from(sender_public_array);
        let shared_secret = target_secret.diffie_hellman(&sender_public);
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut aead_key = [0u8; 32];
        let mut nonce_bytes = [0u8; 12];
        hk.expand(b"meshinfinity-device-enrollment-key-v1", &mut aead_key)
            .map_err(|_| "Failed to derive device enrollment key".to_string())?;
        hk.expand(b"meshinfinity-device-enrollment-nonce-v1", &mut nonce_bytes)
            .map_err(|_| "Failed to derive device enrollment nonce".to_string())?;
        let package_nonce =
            hex::decode(&envelope.nonce).map_err(|e| format!("Invalid package nonce: {e}"))?;
        if package_nonce != nonce_bytes {
            return Err("Device enrollment package nonce did not verify".to_string());
        }
        let cipher = ChaCha20Poly1305::new_from_slice(&aead_key)
            .map_err(|_| "Failed to initialize device enrollment cipher".to_string())?;
        let ciphertext = hex::decode(&envelope.ciphertext)
            .map_err(|e| format!("Invalid package ciphertext: {e}"))?;
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
            .map_err(|_| "Failed to decrypt device enrollment package".to_string())?;
        let payload: DeviceTransferPayload = serde_json::from_slice(&plaintext)
            .map_err(|e| format!("Invalid device transfer payload: {e}"))?;
        if payload.request_id != pending.request_id
            || payload.target_device_id != pending.target_device_id
        {
            return Err("Device transfer payload does not match this request".to_string());
        }
        let sig_bytes = hex::decode(&envelope.registration_sig)
            .map_err(|e| format!("Invalid registration signature: {e}"))?;
        if sig_bytes.len() != 64 {
            return Err("Registration signature has invalid length".to_string());
        }
        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_array);
        let identity_payload = hex::decode(&payload.identity_payload)
            .map_err(|e| format!("Invalid identity payload: {e}"))?;
        let master_key_bytes =
            hex::decode(&payload.master_key).map_err(|e| format!("Invalid master key: {e}"))?;
        if master_key_bytes.len() != 32 {
            return Err("Transferred master key has invalid length".to_string());
        }
        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&master_key_bytes);
        let mut identity = SelfIdentity::from_payload(&identity_payload)
            .ok_or_else(|| "Transferred identity payload could not be decoded".to_string())?;
        identity.master_key = zeroize::Zeroizing::new(master_key);
        let (dk, ek) = derive_kem_keypair(&identity.master_key);
        identity.kem_decapsulation_key = dk;
        identity.kem_encapsulation_key = ek;
        let verifying_key = VerifyingKey::from_bytes(&identity.ed25519_pub)
            .map_err(|e| format!("Transferred identity key is invalid: {e}"))?;
        let signature_message = [
            payload.request_id.as_bytes(),
            sender_public.as_bytes(),
            nonce_bytes.as_slice(),
            ciphertext.as_slice(),
        ]
        .concat();
        verifying_key
            .verify(&signature_message, &signature)
            .map_err(|_| "Device registration signature did not verify".to_string())?;

        let data_dir = std::path::PathBuf::from(&self.data_dir);
        identity
            .save_to_disk(&data_dir, None)
            .map_err(|e| format!("Failed to activate transferred identity: {e}"))?;
        self.activate_identity(identity);

        if let Some(vm) = self.vault.as_ref() {
            if let Ok(coll) = vm.collection("settings") {
                let _ = coll.save(&payload.settings);
            }
            if let Ok(coll) = vm.collection("peers") {
                let _ = coll.save(&payload.contacts);
            }
            if let Ok(coll) = vm.collection("rooms") {
                let _ = coll.save(&payload.rooms);
            }
            if let Ok(coll) = vm.collection("messages") {
                let _ = coll.save(&payload.messages);
            }
            if let Ok(coll) = vm.collection("masks") {
                let _ = coll.save(&payload.masks);
            }
            if let Ok(coll) = vm.collection("devices") {
                let _ = coll.save(&payload.registered_devices);
            }
        }
        std::fs::write(self.local_device_id_path(), &payload.target_device_id)
            .map_err(|e| format!("Failed to persist local device id: {e}"))?;
        self.load_from_vault();
        let _ = self.ensure_local_device_registered(false);
        self.emit_identity_settings_updated();
        self.clear_pending_device_enrollment();
        Ok(())
    }

    /// Persist the currently unlocked identity with a PIN-wrapped master key.
    ///
    /// When `identity.key` is already a current-format wrap, the existing
    /// salt and parameters are kept so a duress blob wrapped under them
    /// stays valid; the new PIN is also checked against that blob so the
    /// two can never coincide. Otherwise a fresh salt is drawn and any
    /// stale duress blob is removed. The sealed attempt counter is written
    /// before the key file so a crash in between leaves a consistent state.
    pub fn set_pin(&mut self, pin: String) -> Result<(), String> {
        if !self.identity_unlocked {
            return Err("Identity must be unlocked before setting a PIN".to_string());
        }
        pin::validate_pin(pin.as_bytes()).map_err(|e| e.to_string())?;
        let data_dir = std::path::Path::new(&self.data_dir);

        // Keep the salt of an existing current-format wrap.
        let existing = match read_master_key_record(data_dir) {
            Ok(MasterKeyRecord::Wrapped(w)) if !w.legacy => w.shared_salt().map(|s| (s, w.params)),
            Ok(_) => None,
            Err(IdentityError::NotFound(_)) => None,
            Err(e) => return Err(format!("Failed to read identity key: {e}")),
        };
        let (salt, params, keep_duress) = match existing {
            Some((salt, params)) => (salt, params, true),
            None => {
                let mut salt = [0u8; SALT_LEN];
                Self::fill_random(&mut salt)?;
                (salt, KdfParams::SPEC, false)
            }
        };

        // One derivation under the chosen salt.
        let wrapping_key = pin::derive_key_from_pin(pin.as_bytes(), &salt, params)
            .map_err(|e| format!("Failed to set PIN: {e}"))?;
        if keep_duress {
            // A duress blob under this salt must not open with the new PIN,
            // or the primary record would always win and the duress PIN
            // would silently stop working.
            if let Some(blob) = self.read_duress_blob() {
                if pin::open_wrapped_key(&blob, &wrapping_key).is_ok() {
                    return Err("New PIN must differ from the duress PIN".to_string());
                }
            }
        } else {
            // A blob under any other salt can never match again.
            self.clear_duress_pin_file()?;
        }

        // Counter before key file: an identity that is PIN-wrapped must
        // always have a sealed counter beside it (§3.10).
        self.save_pin_attempt_state(&PinAttemptState {
            failed_attempts: 0,
            last_failed_at: 0,
            wipe_threshold: self.current_pin_wipe_threshold(),
        })?;

        let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
        let identity = guard
            .as_ref()
            .ok_or_else(|| "Identity is not loaded".to_string())?;
        identity
            .save_wrapped(data_dir, &wrapping_key, &salt, params)
            .map_err(|e| format!("Failed to set PIN: {e}"))?;
        drop(guard);
        let flags = self
            .transport_flags
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let node_mode = *self.node_mode.lock().unwrap_or_else(|e| e.into_inner());
        let (peer_id, ed25519_pub) = {
            let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
            let identity = guard
                .as_ref()
                .ok_or_else(|| "Identity is not loaded".to_string())?;
            (
                identity.peer_id().to_hex(),
                hex::encode(identity.ed25519_pub),
            )
        };
        let clearnet_port = *self.clearnet_port.lock().unwrap_or_else(|e| e.into_inner());
        let active_tier = *self.active_tier.lock().unwrap_or_else(|e| e.into_inner());
        let bandwidth_profile = *self
            .bandwidth_profile
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        self.push_event(
            "SettingsUpdated",
            build_settings_json(
                &flags,
                node_mode,
                &self.threat_context,
                &peer_id,
                &ed25519_pub,
                clearnet_port,
                active_tier,
                bandwidth_profile,
                self.build_layer1_status_json(),
            ),
        );
        Ok(())
    }

    /// Change the current PIN after verifying the existing one.
    ///
    /// Unlocked-only: the verification below derives outside the attempt
    /// counter and must not serve a locked device as a guessing oracle.
    pub fn change_pin(&mut self, current_pin: String, new_pin: String) -> Result<(), String> {
        if !self.identity_unlocked {
            return Err("Identity must be unlocked before changing the PIN".to_string());
        }
        let data_dir = std::path::Path::new(&self.data_dir);
        SelfIdentity::load_from_disk(data_dir, Some(&current_pin)).map_err(|e| match e {
            IdentityError::WrongPin => "Wrong PIN".to_string(),
            other => format!("Failed to verify current PIN: {other}"),
        })?;
        self.set_pin(new_pin)
    }

    /// Remove the PIN wrapper after verifying the current PIN.
    pub fn remove_pin(&mut self, current_pin: String) -> Result<(), String> {
        if !self.identity_unlocked {
            return Err("Identity must be unlocked before removing the PIN".to_string());
        }
        let data_dir = std::path::Path::new(&self.data_dir);
        SelfIdentity::load_from_disk(data_dir, Some(&current_pin)).map_err(|e| match e {
            IdentityError::WrongPin => "Wrong PIN".to_string(),
            other => format!("Failed to verify current PIN: {other}"),
        })?;
        let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
        let identity = guard
            .as_ref()
            .ok_or_else(|| "Identity is not loaded".to_string())?;
        identity
            .save_to_disk(data_dir, None)
            .map_err(|e| format!("Failed to remove PIN: {e}"))?;
        drop(guard);
        // Without a PIN there is nothing to count and no unlock screen for
        // a duress PIN to be entered on; both records go with the wrap.
        self.clear_pin_attempt_files()?;
        self.clear_duress_pin_file()?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------------

    /// Serialise the current identity state to a JSON string.
    ///
    /// Returns a locked indicator if the identity is not unlocked, otherwise
    /// includes `peerId`, `ed25519Pub`, and `displayName`.
    pub fn get_identity_summary(&self) -> String {
        if !self.identity_unlocked {
            return r#"{"locked": true}"#.to_string();
        }

        let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(id) => {
                let json = serde_json::json!({
                    "locked":       false,
                    "peerId":       id.peer_id().to_hex(),
                    "ed25519Pub":   hex::encode(id.ed25519_pub),
                    "displayName":  id.display_name,
                });
                json.to_string()
            }
            None => r#"{"locked": false, "status": "active"}"#.to_string(),
        }
    }

    // -----------------------------------------------------------------------
    // Backup restore
    // -----------------------------------------------------------------------

    /// Import social state (contacts + rooms + messages) from an encrypted backup.
    ///
    /// The backup is a base64-encoded `EncryptedBackup` JSON blob — optionally
    /// wrapped in `{"backup_b64": "..."}` as produced by the UI backup screen.
    ///
    /// SPEC §3.7: private key material is **never** included in backups.  The
    /// caller must have an identity loaded (via `create_identity` or
    /// `unlock_identity`) before calling this.  The restore is a full
    /// replacement — existing contacts and rooms are cleared first.
    ///
    /// Returns `Ok(())` on success, `Err(reason)` on decryption or parse
    /// failure.
    pub fn import_identity_backup(
        &mut self,
        backup_b64_or_json: &str,
        passphrase: &str,
    ) -> Result<(), String> {
        // Support both raw base64 and `{"backup_b64":"..."}` JSON wrappers.
        let b64_str: String = if backup_b64_or_json.trim_start().starts_with('{') {
            let v: serde_json::Value = serde_json::from_str(backup_b64_or_json)
                .map_err(|_| "Backup JSON parse failed".to_string())?;
            v.get("backup_b64")
                .and_then(|b| b.as_str())
                .ok_or_else(|| "backup_b64 field missing".to_string())?
                .to_string()
        } else {
            backup_b64_or_json.to_string()
        };

        // Base64-decode the outer envelope.
        use base64::Engine as _;
        let json_bytes = base64::engine::general_purpose::STANDARD
            .decode(&b64_str)
            .map_err(|e| format!("Base64 decode failed: {e}"))?;

        // Deserialise into EncryptedBackup.
        let encrypted: EncryptedBackup = serde_json::from_slice(&json_bytes)
            .map_err(|e| format!("EncryptedBackup parse failed: {e}"))?;

        // Decrypt the backup payload.
        let (payload, _backup_type) =
            crate::crypto::backup::restore_backup(&encrypted, passphrase.as_bytes())
                .map_err(|_| "Backup decryption failed — wrong passphrase?".to_string())?;

        // Deserialise BackupContents.
        let contents: BackupContents = serde_json::from_slice(&payload)
            .map_err(|e| format!("BackupContents parse failed: {e}"))?;

        // Identity must already be loaded.
        if !self.identity_unlocked {
            return Err("Identity not unlocked — unlock before restoring backup".to_string());
        }

        // Full replacement — clear existing social state.
        self.contacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.rooms.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();

        // Restore contacts.
        {
            let mut store = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
            for contact in contents.contacts {
                store.upsert(contact);
            }
        }

        // Restore rooms.
        {
            let mut rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            for room in contents.rooms {
                rooms.push(room);
            }
        }

        // Restore message history (extended backups only).
        if !contents.messages.is_empty() {
            let mut msgs = self.messages.lock().unwrap_or_else(|e| e.into_inner());
            for (room_id, message_list) in contents.messages {
                msgs.insert(room_id, message_list);
            }
        }

        self.push_event("BackupRestored", serde_json::json!({}));
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Reset
    // -----------------------------------------------------------------------

    /// Non-emergency wipe of all in-memory identity and social state.
    ///
    /// Does not remove files from disk — this is a clean in-memory reset to
    /// the pre-unlock state (e.g. for logout flows).  The vault is dropped so
    /// subsequent calls that need vault access will fail until `unlock_identity`
    /// is called again.
    pub fn reset_identity(&mut self) {
        // Wipe key material through the guarded path before clearing other state.
        self.clear_identity_keys();
        self.identity_unlocked = false;
        self.rooms.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.contacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.vault = None;
    }

    // -----------------------------------------------------------------------
    // Profile
    // -----------------------------------------------------------------------

    /// Persist and broadcast the public profile (§9.1).
    ///
    /// Validates `display_name` length, persists to vault under
    /// `"public_profile"`, and emits a `ProfileUpdated` event.
    ///
    /// Returns `Ok(())` on success, `Err(reason)` on validation or persist
    /// failure.
    pub fn set_public_profile(&self, profile_json: &str) -> Result<(), String> {
        let profile: serde_json::Value =
            serde_json::from_str(profile_json).map_err(|_| "Invalid JSON".to_string())?;

        // Validate field lengths per §9.1.
        if let Some(name) = profile.get("display_name").and_then(|v| v.as_str()) {
            if name.len() > crate::identity::profile::MAX_DISPLAY_NAME_LEN {
                return Err("display_name exceeds maximum length".to_string());
            }
        }

        // Persist to vault (encrypted at rest by the vault layer).
        if let Some(vm) = self.vault.as_ref() {
            if let Ok(coll) = vm.collection("public_profile") {
                coll.save(&profile)
                    .map_err(|e| format!("vault write failed: {e}"))?;
            }
        }

        self.push_event(
            "ProfileUpdated",
            serde_json::json!({
                "kind":    "public",
                "profile": profile,
            }),
        );
        Ok(())
    }

    /// Persist the private profile shared only with trusted contacts (§9.2).
    ///
    /// Persists to vault under `"private_profile"` and emits `ProfileUpdated`.
    ///
    /// Returns `Ok(())` on success, `Err(reason)` on persist failure.
    pub fn set_private_profile(&self, profile_json: &str) -> Result<(), String> {
        let profile: serde_json::Value =
            serde_json::from_str(profile_json).map_err(|_| "Invalid JSON".to_string())?;

        // Persist to vault (encrypted at rest by the vault layer).
        if let Some(vm) = self.vault.as_ref() {
            if let Ok(coll) = vm.collection("private_profile") {
                coll.save(&profile)
                    .map_err(|e| format!("vault write failed: {e}"))?;
            }
        }

        self.push_event(
            "ProfileUpdated",
            serde_json::json!({
                "kind":    "private",
                "profile": profile,
            }),
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Pairing payload
    // -----------------------------------------------------------------------

    /// Build the local pairing payload as a JSON string.
    ///
    /// The payload contains our public keys, a freshly generated pairing token
    /// (prevents replay), and transport hints (clearnet / Tor endpoints if the
    /// corresponding services are running).  Callers encode this as a QR code
    /// or deep link for peer scanning.
    ///
    /// Returns `Ok(json)` on success, `Err(reason)` if identity is not unlocked
    /// or random number generation fails.
    pub fn get_pairing_payload(&self) -> Result<String, String> {
        let guard = self.identity.lock().unwrap_or_else(|e| e.into_inner());
        let id = guard
            .as_ref()
            .ok_or_else(|| "identity not unlocked".to_string())?;

        let peer_id_hex = id.peer_id().to_hex();
        let ed25519_hex = hex::encode(id.ed25519_pub);
        let x25519_hex = hex::encode(id.x25519_pub.as_bytes());
        let preauth_x25519_hex = hex::encode(id.preauth_x25519_pub.as_bytes());

        // One-time pairing token (prevents replay attacks).
        let mut token = [0u8; 32];
        if !try_random_fill(&mut token) {
            return Err("random number generation failed".to_string());
        }

        // Transport hints: include clearnet if the listener is running.
        let port = *self.clearnet_port.lock().unwrap_or_else(|e| e.into_inner());
        let mut hints: Vec<serde_json::Value> = Vec::new();
        if self
            .clearnet_listener
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            let ip = crate::service::runtime::local_clearnet_ip()
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "0.0.0.0".to_string());
            hints.push(serde_json::json!({
                "transport": "clearnet",
                "endpoint":  format!("{ip}:{port}"),
            }));
        }

        // Transport hints: include Tor onion address if Tor is enabled.
        {
            let tor_guard = self.tor_transport.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ref t) = *tor_guard {
                hints.push(serde_json::json!({
                    "transport": "tor",
                    "endpoint":  format!("{}:{}", t.onion_address, crate::service::runtime::DEFAULT_HS_PORT),
                }));
            }
        }

        // Sign the display name if present so the recipient can verify it.
        let (display_name, display_name_sig) = if let Some(ref name) = id.display_name {
            let sig = id.ed25519_signing.sign(name.as_bytes());
            (
                serde_json::json!(name),
                serde_json::json!(hex::encode(sig.to_bytes())),
            )
        } else {
            (serde_json::Value::Null, serde_json::Value::Null)
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Remember the token so a `pairing_hello` presenting it is honoured
        // only while this payload is valid (§8.3); a hello without one of our
        // issued tokens never creates a contact.
        let expires_at = now + crate::pairing::methods::QR_EXPIRY_LIVE;
        self.remember_pairing_token(token, expires_at);

        let payload = serde_json::json!({
            "version":              1,
            "peer_id":              peer_id_hex,
            "ed25519_public":       ed25519_hex,
            "x25519_public":        x25519_hex,
            "mesh_x25519_public":   self
                .mesh_identity
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(|identity| hex::encode(identity.public_bytes()))
                .unwrap_or_default(),
            // Preauth X25519 public key (our current SPK — changes weekly).
            "preauth_x25519_public": preauth_x25519_hex,
            "pairing_token":        hex::encode(token),
            "display_name":         display_name,
            "display_name_sig":     display_name_sig,
            "transport_hints":      hints,
            "expiry":               expires_at,
            // ML-KEM-768 encapsulation key (hex) — enables PQXDH (§3.4.1).
            "kem_pub":              hex::encode(&id.kem_encapsulation_key),
        });

        Ok(payload.to_string())
    }

    // -----------------------------------------------------------------------
    // Remote killswitch (§3.9.3)
    // -----------------------------------------------------------------------

    /// Execute a remote killswitch command sent by a peer (§3.9.3).
    ///
    /// The spec requires the requesting peer to hold `TrustLevel::InnerCircle`
    /// (Level 8) before this device executes a wipe.  Any peer below that
    /// threshold is rejected with an error — the wipe does NOT happen.
    ///
    /// ## Security invariant
    ///
    /// The trust check is performed against the locally stored contact record,
    /// not a value supplied by the requester.  An attacker cannot self-elevate
    /// to InnerCircle by crafting the killswitch message.
    ///
    /// ## Acceptance path
    ///
    /// On approval the method calls `standard_erase()` and clears all
    /// in-memory key material, leaving the device in a wiped state
    /// identical to a local killswitch activation.
    pub fn execute_remote_killswitch(&self, requesting_peer_id_hex: &str) -> Result<(), String> {
        use crate::identity::peer_id::PeerId;

        // ----------------------------------------------------------------
        // Parse the requesting peer's ID.
        // ----------------------------------------------------------------
        let pid_bytes: [u8; 32] = hex::decode(requesting_peer_id_hex)
            .ok()
            .filter(|b| b.len() == 32)
            .map(|b| {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            })
            .ok_or_else(|| "Invalid requesting peer ID".to_string())?;
        let pid = PeerId(pid_bytes);

        // ----------------------------------------------------------------
        // Look up the peer's stored trust level.
        // ----------------------------------------------------------------
        let trust = {
            let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
            contacts
                .get(&pid)
                .map(|c| c.trust_level)
                .ok_or_else(|| "Requesting peer is not a known contact".to_string())?
        };

        // ----------------------------------------------------------------
        // Trust gate: reject anything below InnerCircle (Level 8).
        // ----------------------------------------------------------------
        if trust != TrustLevel::InnerCircle {
            return Err(format!(
                "Remote killswitch rejected: peer {} has trust level {:?} (InnerCircle required)",
                requesting_peer_id_hex, trust,
            ));
        }

        // ----------------------------------------------------------------
        // Approved — execute the wipe.
        //
        // Order: (1) erase on-disk material first so no window exists
        // where memory is clear but disk still readable; (2) clear all
        // Mutex-protected in-memory state.  `identity_unlocked` is a
        // plain bool that requires `&mut self`; the caller's next poll
        // cycle will detect the empty identity and treat the session as
        // locked.
        // ----------------------------------------------------------------
        crate::identity::killswitch::standard_erase(std::path::Path::new(&self.data_dir));
        self.clear_identity_keys();
        self.rooms.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.contacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.messages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.masks.lock().unwrap_or_else(|e| e.into_inner()).clear();

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Trust helpers (used by pairing_ops but logically identity-adjacent)
    // -----------------------------------------------------------------------

    /// Check whether an identity file exists on disk (pre-unlock check).
    pub fn has_identity(&self) -> bool {
        std::path::Path::new(&self.data_dir)
            .join("identity.dat")
            .exists()
    }
}

/// Background half of a duress unlock (§3.9.2 step 4), run off the
/// response path by `begin_duress_rotation`.
///
/// Order matters: the Self-Disavowed marker and the Layer 2/3 erase come
/// first (`duress_erase` overwrites `identity.key` before unlinking it and
/// removes `pin.dat`), then the counter files, then the replacement
/// identity. Each step is independent of the thread's survival: a crash at
/// any point leaves either no Layer 2 identity or a complete new one, never
/// the old one. Failures are logged the way the killswitch logs its own —
/// there is no caller left to report to.
fn finish_duress_rotation(
    data_dir: &std::path::Path,
    key_bytes: &[u8],
    dat_bytes: &[u8],
    counter_key: &[u8; 32],
    sealed_counter: &[u8],
) {
    let erase = crate::identity::killswitch::duress_erase(data_dir);
    if !erase.broadcast_sent {
        eprintln!("[identity] WARNING: duress Self-Disavowed marker could not be written");
    }
    if let Err(e) = write_atomic(&data_dir.join("pin_counter.key"), counter_key) {
        eprintln!("[identity] WARNING: duress counter key not written: {e}");
    }
    if let Err(e) = write_atomic(&data_dir.join("pin_attempts.sealed"), sealed_counter) {
        eprintln!("[identity] WARNING: duress attempt counter not written: {e}");
    }
    if let Err(e) = write_identity_files(data_dir, key_bytes, dat_bytes) {
        eprintln!("[identity] WARNING: duress replacement identity not written: {e}");
    }
}

fn current_platform_id() -> &'static str {
    if cfg!(target_os = "android") {
        "android"
    } else if cfg!(target_os = "ios") {
        "ios"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    }
}

fn current_device_name() -> &'static str {
    match current_platform_id() {
        "android" => "Android device",
        "ios" => "iPhone",
        "macos" => "Mac",
        "windows" => "Windows PC",
        "linux" => "Linux device",
        _ => "This device",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::identity::peer_id::PeerId;
    use crate::pairing::contact::ContactRecord;
    use crate::pairing::methods::PairingMethod;
    use crate::service::runtime::MeshRuntime;
    use crate::trust::levels::TrustLevel;

    // ------------------------------------------------------------------
    // T2-G: remote killswitch trust gate (§3.9.3)
    // ------------------------------------------------------------------

    /// Insert a contact at `trust` into `rt`'s contact store; return hex peer ID.
    fn add_contact(rt: &MeshRuntime, trust: TrustLevel) -> String {
        let pid_bytes = [0xABu8; 32];
        let pid = PeerId(pid_bytes);
        let contact = ContactRecord::new(pid, [0u8; 32], [0u8; 32], PairingMethod::QrCode, 0);
        let mut store = rt.contacts.lock().unwrap_or_else(|e| e.into_inner());
        store.upsert({
            let mut c = contact;
            c.set_trust_level(trust);
            c
        });
        hex::encode(pid_bytes)
    }

    /// A peer below InnerCircle must be rejected; wipe must NOT happen.
    #[test]
    fn remote_killswitch_rejected_for_non_inner_circle_peer() {
        let rt = MeshRuntime::new("target/test-remote-ks-reject".to_string());
        let peer_hex = add_contact(&rt, TrustLevel::Ally);
        let result = rt.execute_remote_killswitch(&peer_hex);
        assert!(result.is_err(), "Ally-level peer must be rejected");
        assert!(
            result.unwrap_err().contains("trust level"),
            "error must mention trust level"
        );
    }

    /// An InnerCircle peer must be accepted and the wipe must execute.
    #[test]
    fn remote_killswitch_accepted_for_inner_circle_peer() {
        let rt = MeshRuntime::new("target/test-remote-ks-accept".to_string());
        let peer_hex = add_contact(&rt, TrustLevel::InnerCircle);
        assert!(
            rt.execute_remote_killswitch(&peer_hex).is_ok(),
            "InnerCircle peer must be accepted"
        );
    }

    /// An unknown peer (not in contacts) must be rejected.
    #[test]
    fn remote_killswitch_rejected_for_unknown_peer() {
        let rt = MeshRuntime::new("target/test-remote-ks-unknown".to_string());
        let result = rt.execute_remote_killswitch(&hex::encode([0xFFu8; 32]));
        assert!(result.is_err(), "Unknown peer must be rejected");
    }

    /// An invalid peer ID hex string must be rejected cleanly.
    #[test]
    fn remote_killswitch_rejected_for_invalid_peer_id() {
        let rt = MeshRuntime::new("target/test-remote-ks-invalid".to_string());
        assert!(rt.execute_remote_killswitch("not-valid-hex").is_err());
    }

    // ------------------------------------------------------------------
    // T1-A: clear_identity_keys() atomicity (§3.6.4)
    // ------------------------------------------------------------------

    /// Two threads calling clear_identity_keys() concurrently must both
    /// complete without panicking.  The AtomicBool guard ensures the
    /// clear executes at most once per call pair; after both threads
    /// finish, identity must be None.
    #[test]
    fn clear_identity_keys_concurrent_calls_are_safe() {
        use std::sync::Arc;

        let rt = Arc::new(MeshRuntime::new(
            "target/test-clear-identity-concurrent".to_string(),
        ));

        let rt1 = Arc::clone(&rt);
        let rt2 = Arc::clone(&rt);

        let t1 = std::thread::spawn(move || rt1.clear_identity_keys());
        let t2 = std::thread::spawn(move || rt2.clear_identity_keys());

        t1.join().expect("thread 1 must not panic");
        t2.join().expect("thread 2 must not panic");

        let identity = rt.identity.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            identity.is_none(),
            "identity must be None after concurrent clear_identity_keys"
        );
    }

    // ------------------------------------------------------------------
    // App PIN: sealed counter, backoff, timing, migration (§3.9, §3.10)
    // ------------------------------------------------------------------

    use crate::identity::pin::{self, PinAttemptState, UNLOCK_RESPONSE_DEADLINE};
    use crate::identity::self_identity::{
        encode_legacy_wrapped_key_file, parse_master_key_record, MasterKeyRecord, SelfIdentity,
    };
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    /// Tolerance for the three unlock outcomes' response times. The padding
    /// makes each attempt take `UNLOCK_RESPONSE_DEADLINE`; what remains is
    /// scheduler jitter and, on a machine where one derivation alone exceeds
    /// the deadline, Argon2 run-to-run variance.
    const TIMING_TOLERANCE: Duration = Duration::from_millis(150);

    /// A runtime in a fresh temp dir with no network side effects.
    fn quiet_runtime(dir: &TempDir) -> MeshRuntime {
        let rt = MeshRuntime::new(dir.path().to_string_lossy().into_owned());
        // Keep the Layer 1 reconcile from binding sockets or starting mDNS.
        let mut flags = rt.transport_flags.lock().unwrap_or_else(|e| e.into_inner());
        flags.clearnet = false;
        flags.clearnet_fallback = false;
        flags.mesh_discovery = false;
        drop(flags);
        rt
    }

    /// Create an identity, protect it with `pin` (and optionally a duress
    /// PIN), then lock it so the next call is a real unlock attempt.
    fn locked_pin_runtime(pin: &str, duress: Option<&str>) -> (TempDir, MeshRuntime, [u8; 32]) {
        let dir = TempDir::new().expect("tempdir");
        let mut rt = quiet_runtime(&dir);
        rt.create_identity(Some("Pinned".into())).expect("create");
        let original_pub = rt
            .identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .expect("identity loaded")
            .ed25519_pub;
        rt.set_pin(pin.to_string()).expect("set_pin");
        if let Some(duress) = duress {
            rt.set_duress_pin(duress.to_string()).expect("set duress");
        }
        rt.reset_identity();
        (dir, rt, original_pub)
    }

    /// Current wall-clock seconds for tests that seed the counter.
    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs()
    }

    /// Read the sealing key and open the sealed counter on disk.
    fn read_sealed_counter(dir: &TempDir) -> PinAttemptState {
        let key_bytes = std::fs::read(dir.path().join("pin_counter.key")).expect("counter key");
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        let sealed = std::fs::read(dir.path().join("pin_attempts.sealed")).expect("sealed");
        pin::open_attempt_state(&sealed, &key).expect("counter authenticates")
    }

    /// Overwrite the sealed counter with `state` under the existing key.
    fn write_sealed_counter(dir: &TempDir, state: &PinAttemptState) {
        let key_bytes = std::fs::read(dir.path().join("pin_counter.key")).expect("counter key");
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        let sealed = pin::seal_attempt_state(state, &key).expect("seal");
        std::fs::write(dir.path().join("pin_attempts.sealed"), sealed).expect("write sealed");
    }

    /// Wait for the background duress rotation to finish writing the
    /// replacement identity under `pin`, or fail after a generous bound.
    fn wait_for_duress_rotation(dir: &TempDir, pin: &str) -> SelfIdentity {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let done = !dir.path().join("pin.dat").exists()
                && dir.path().join("pin_attempts.sealed").exists()
                && dir.path().join("pin_counter.key").exists();
            if done {
                if let Ok(identity) = SelfIdentity::load_from_disk(dir.path(), Some(pin)) {
                    return identity;
                }
            }
            assert!(
                Instant::now() < deadline,
                "duress rotation did not persist the replacement identity in time"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Assert that every pair of durations is within the tolerance.
    fn assert_close(label: &str, durations: &[(&str, Duration)]) {
        for (name_a, a) in durations {
            for (name_b, b) in durations {
                let gap = if a > b { *a - *b } else { *b - *a };
                assert!(
                    gap <= TIMING_TOLERANCE,
                    "{label}: {name_a} ({a:?}) and {name_b} ({b:?}) differ by {gap:?}, over {TIMING_TOLERANCE:?}"
                );
            }
        }
    }

    /// §3.10 "Timing normalization": correct, wrong and duress PINs respond
    /// at the same wall-clock offset, each at least the one-second deadline,
    /// and the duress erase happens after the call has returned.
    #[test]
    fn unlock_timing_normalized_across_outcomes() {
        let (dir, mut rt, original_pub) = locked_pin_runtime("1234", Some("9999"));

        let started = Instant::now();
        let wrong = rt.unlock_identity(Some("0000".into()));
        let t_wrong = started.elapsed();
        assert_eq!(wrong.unwrap_err(), "Wrong PIN");
        assert!(!rt.identity_unlocked);

        let started = Instant::now();
        rt.unlock_identity(Some("1234".into()))
            .expect("correct PIN unlocks");
        let t_ok = started.elapsed();
        assert!(rt.identity_unlocked);
        rt.reset_identity();

        let started = Instant::now();
        rt.unlock_identity(Some("9999".into()))
            .expect("duress PIN looks like a normal unlock");
        let t_duress = started.elapsed();
        assert!(
            rt.identity_unlocked,
            "duress unlock presents an unlocked app"
        );

        for (name, t) in [("wrong", t_wrong), ("correct", t_ok), ("duress", t_duress)] {
            assert!(
                t >= UNLOCK_RESPONSE_DEADLINE,
                "{name} returned after {t:?}, before the {UNLOCK_RESPONSE_DEADLINE:?} deadline"
            );
        }
        assert_close(
            "unlock outcomes",
            &[("wrong", t_wrong), ("correct", t_ok), ("duress", t_duress)],
        );

        // The foreground already runs the replacement self ...
        let fresh_pub = rt
            .identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .expect("replacement identity loaded")
            .ed25519_pub;
        assert_ne!(fresh_pub, original_pub, "duress must rotate the self");
        // ... and the background thread persists it under the duress PIN,
        // which is now the legitimate unlock PIN (§3.9.2 step 5).
        let persisted = wait_for_duress_rotation(&dir, "9999");
        assert_eq!(persisted.ed25519_pub, fresh_pub);
        assert!(
            SelfIdentity::load_from_disk(dir.path(), Some("1234")).is_err(),
            "the old PIN must not open the replacement identity"
        );
        assert!(
            dir.path().join("killswitch_broadcast.pending").exists(),
            "Self-Disavowed marker must be written for the old self"
        );
        assert!(rt
            .duress_wind_down
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some());
    }

    /// §3.10: deleting the counter while a PIN is set is tampering — the
    /// identity is wiped behind a Self-Disavowed marker, never reset to
    /// zero failures.
    #[test]
    fn deleted_counter_with_pin_set_wipes_instead_of_resetting() {
        let (dir, mut rt, _) = locked_pin_runtime("1234", None);
        std::fs::remove_file(dir.path().join("pin_attempts.sealed")).expect("delete counter");

        let err = rt.unlock_identity(Some("1234".into())).unwrap_err();
        assert!(err.contains("tampered"), "unexpected error: {err}");
        assert!(!rt.identity_unlocked);
        assert!(!dir.path().join("identity.key").exists());
        assert!(!dir.path().join("identity.dat").exists());
        assert!(dir.path().join("killswitch_broadcast.pending").exists());
        // Nothing is left to guess at; the counter was not quietly recreated.
        assert!(!dir.path().join("pin_attempts.sealed").exists());
        let again = rt.unlock_identity(Some("1234".into())).unwrap_err();
        assert!(again.contains("No identity"), "unexpected error: {again}");
    }

    /// Editing a single byte of the sealed counter is the same tampering.
    #[test]
    fn edited_counter_with_pin_set_wipes() {
        let (dir, mut rt, _) = locked_pin_runtime("1234", None);
        let path = dir.path().join("pin_attempts.sealed");
        let mut bytes = std::fs::read(&path).expect("read counter");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&path, bytes).expect("rewrite counter");

        let err = rt.unlock_identity(Some("1234".into())).unwrap_err();
        assert!(err.contains("tampered"), "unexpected error: {err}");
        assert!(!dir.path().join("identity.dat").exists());
    }

    /// Removing the sealing key (leaving the counter) is tampering too.
    #[test]
    fn deleted_counter_key_with_pin_set_wipes() {
        let (dir, mut rt, _) = locked_pin_runtime("1234", None);
        std::fs::remove_file(dir.path().join("pin_counter.key")).expect("delete key");

        let err = rt.unlock_identity(Some("1234".into())).unwrap_err();
        assert!(err.contains("tampered"), "unexpected error: {err}");
        assert!(!dir.path().join("identity.dat").exists());
    }

    /// A wall clock that reads earlier than the last recorded failure keeps
    /// the lock, even for the correct PIN, and the counter is left as it was.
    #[test]
    fn clock_rollback_keeps_unlock_locked() {
        let (dir, mut rt, _) = locked_pin_runtime("1234", None);
        // Six failures recorded "in the future": what the file looks like
        // after the clock is moved back past them.
        let seeded = PinAttemptState {
            failed_attempts: 6,
            last_failed_at: now_secs() + 100_000,
            wipe_threshold: None,
        };
        write_sealed_counter(&dir, &seeded);

        let err = rt.unlock_identity(Some("1234".into())).unwrap_err();
        assert!(err.contains("locked"), "unexpected error: {err}");
        assert!(!rt.identity_unlocked);
        assert_eq!(
            read_sealed_counter(&dir),
            seeded,
            "counter must not be rewritten"
        );
        assert!(
            dir.path().join("identity.dat").exists(),
            "a lock is not a wipe"
        );
    }

    /// Backoff is enforced from the sealed counter across a lock/unlock
    /// cycle: a sixth failure starts the 30 s delay and the correct PIN is
    /// refused until it passes.
    #[test]
    fn backoff_applies_after_sixth_failure() {
        let (dir, mut rt, _) = locked_pin_runtime("1234", None);
        write_sealed_counter(
            &dir,
            &PinAttemptState {
                failed_attempts: 5,
                last_failed_at: now_secs(),
                wipe_threshold: None,
            },
        );
        assert_eq!(
            rt.unlock_identity(Some("0000".into())).unwrap_err(),
            "Wrong PIN"
        );
        let state = read_sealed_counter(&dir);
        assert_eq!(state.failed_attempts, 6);
        assert!(
            state.last_failed_at > 0,
            "a real timestamp is recorded, never zero"
        );

        let err = rt.unlock_identity(Some("1234".into())).unwrap_err();
        assert!(err.contains("locked"), "unexpected error: {err}");
        assert!(!rt.identity_unlocked);
    }

    /// The wipe threshold stored in the counter is enforced at the locked
    /// screen, where the settings vault is unreadable.
    #[test]
    fn wipe_threshold_enforced_from_sealed_counter() {
        let dir = TempDir::new().expect("tempdir");
        let mut rt = quiet_runtime(&dir);
        rt.create_identity(None).expect("create");
        rt.set_pin("1234".to_string()).expect("set_pin");
        rt.set_security_config(r#"{"wrongPinWipeEnabled": true, "wrongPinWipeThreshold": 3}"#)
            .expect("config");
        assert_eq!(read_sealed_counter(&dir).wipe_threshold, Some(3));
        rt.reset_identity();

        assert_eq!(
            rt.unlock_identity(Some("0000".into())).unwrap_err(),
            "Wrong PIN"
        );
        assert_eq!(
            rt.unlock_identity(Some("0001".into())).unwrap_err(),
            "Wrong PIN"
        );
        let err = rt.unlock_identity(Some("0002".into())).unwrap_err();
        assert!(err.contains("erased"), "unexpected error: {err}");
        assert!(!dir.path().join("identity.dat").exists());
        assert!(dir.path().join("killswitch_broadcast.pending").exists());
    }

    /// A legacy mode 0x01 identity.key (argon2 crate defaults, no counter)
    /// is bootstrapped on its first attempt, unlocks with its PIN, and is
    /// re-wrapped as mode 0x02 under the spec parameters.
    #[test]
    fn legacy_0x01_identity_migrates_to_0x02_on_unlock() {
        let dir = TempDir::new().expect("tempdir");
        let mut rt = quiet_runtime(&dir);
        rt.create_identity(Some("Legacy".into())).expect("create");
        let (master_key, original_pub) = {
            let guard = rt.identity.lock().unwrap_or_else(|e| e.into_inner());
            let id = guard.as_ref().expect("identity");
            (*id.master_key, id.ed25519_pub)
        };
        // What an earlier build left on disk: legacy wrap, plaintext counter.
        let legacy = encode_legacy_wrapped_key_file(&master_key, b"4321").expect("legacy");
        std::fs::write(dir.path().join("identity.key"), legacy).expect("write legacy");
        std::fs::write(
            dir.path().join("pin_attempts.json"),
            serde_json::to_vec(&PinAttemptState {
                failed_attempts: 2,
                last_failed_at: now_secs() - 10,
                wipe_threshold: None,
            })
            .expect("json"),
        )
        .expect("write legacy counter");
        rt.reset_identity();

        // A wrong PIN is counted on top of the carried-over history.
        assert_eq!(
            rt.unlock_identity(Some("0000".into())).unwrap_err(),
            "Wrong PIN"
        );
        assert!(
            !dir.path().join("pin_attempts.json").exists(),
            "plaintext counter removed"
        );
        assert_eq!(read_sealed_counter(&dir).failed_attempts, 3);

        rt.unlock_identity(Some("4321".into()))
            .expect("legacy PIN unlocks");
        let bytes = std::fs::read(dir.path().join("identity.key")).expect("key");
        match parse_master_key_record(&bytes).expect("parse") {
            MasterKeyRecord::Wrapped(w) => {
                assert!(!w.legacy, "must be re-wrapped as 0x02");
                assert_eq!(w.params, pin::KdfParams::SPEC);
            }
            MasterKeyRecord::Plain(_) => panic!("migration must keep the PIN wrap"),
        }
        assert_eq!(read_sealed_counter(&dir).failed_attempts, 0);
        let reloaded = SelfIdentity::load_from_disk(dir.path(), Some("4321")).expect("0x02 load");
        assert_eq!(reloaded.ed25519_pub, original_pub);
    }

    /// Changing the unlock PIN keeps the duress blob valid (shared salt),
    /// refuses a new PIN equal to the duress PIN, and the duress PIN still
    /// triggers rotation afterwards.
    #[test]
    fn change_pin_preserves_duress_and_rejects_collision() {
        let (dir, mut rt, original_pub) = locked_pin_runtime("1234", Some("9999"));
        rt.unlock_identity(Some("1234".into())).expect("unlock");
        rt.change_pin("1234".into(), "5555".into())
            .expect("change pin");
        assert_eq!(
            rt.change_pin("5555".into(), "9999".into()).unwrap_err(),
            "New PIN must differ from the duress PIN"
        );
        assert!(
            dir.path().join("pin.dat").exists(),
            "duress blob kept across PIN change"
        );
        rt.reset_identity();

        rt.unlock_identity(Some("9999".into()))
            .expect("duress still works");
        let fresh = wait_for_duress_rotation(&dir, "9999");
        assert_ne!(fresh.ed25519_pub, original_pub);
    }

    /// Removing the PIN removes the counter and the duress blob, and a
    /// no-PIN unlock then needs neither.
    #[test]
    fn remove_pin_clears_counter_and_duress() {
        let (dir, mut rt, _) = locked_pin_runtime("1234", Some("9999"));
        rt.unlock_identity(Some("1234".into())).expect("unlock");
        rt.remove_pin("1234".into()).expect("remove pin");
        assert!(!dir.path().join("pin_attempts.sealed").exists());
        assert!(!dir.path().join("pin_counter.key").exists());
        assert!(!dir.path().join("pin.dat").exists());
        rt.reset_identity();
        rt.unlock_identity(None).expect("no-PIN unlock");
        assert!(rt.identity_unlocked);
    }

    /// Settings flows that verify a PIN outside the counter are refused on
    /// a locked device, so they cannot serve as a backoff-free oracle.
    #[test]
    fn pin_verification_flows_require_unlock() {
        let (_dir, mut rt, _) = locked_pin_runtime("1234", Some("9999"));
        assert!(rt
            .change_pin("1234".into(), "5555".into())
            .unwrap_err()
            .contains("unlocked"));
        assert!(rt
            .remove_pin("1234".into())
            .unwrap_err()
            .contains("unlocked"));
        assert!(rt
            .change_duress_pin("9999".into(), "8888".into())
            .unwrap_err()
            .contains("unlocked"));
        assert!(rt
            .remove_duress_pin("9999".into())
            .unwrap_err()
            .contains("unlocked"));
    }
}
