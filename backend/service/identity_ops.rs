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

use crate::service::runtime::{MeshRuntime, try_random_fill, build_settings_json};
use crate::identity::self_identity::{SelfIdentity, IdentityError};
use crate::crypto::backup::EncryptedBackup;
use crate::storage::VaultManager;
use crate::trust::levels::TrustLevel;
use ed25519_dalek::Signer as _;

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

impl MeshRuntime {
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
        // Generate fresh key material.
        let identity = SelfIdentity::generate(display_name);
        let peer_id  = identity.peer_id();
        let ed25519_pub  = identity.ed25519_pub;
        let master_key   = *identity.master_key;

        // Derive (and discard) the public mask to validate the derivation path.
        // Storing is not necessary — it is re-derived on demand.
        let public_mask_id = crate::identity::mask::MaskId([0u8; 16]);
        let _public_mask = crate::identity::mask::Mask::derive_from_self(
            &identity.ed25519_signing,
            &identity.x25519_secret,
            public_mask_id,
            "Public".to_string(),
            0,
            true,
        );

        // Persist identity to disk (no PIN — PIN set separately via mi_set_pin).
        let data_dir = std::path::Path::new(&self.data_dir);
        identity.save_to_disk(data_dir, None)
            .map_err(|e| format!("Failed to persist identity: {e}"))?;

        // Initialise vault with the identity master key.
        self.vault = Some(VaultManager::new(
            std::path::PathBuf::from(&self.data_dir),
            master_key,
        ));
        self.identity_unlocked = true;
        *self.identity.lock().unwrap_or_else(|e| e.into_inner()) = Some(identity);

        // Load any existing vault data (first-run = silent no-op).
        self.load_from_vault();

        // Emit SettingsUpdated so Flutter knows identity is now live.
        let flags       = self.transport_flags.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let node_mode   = *self.node_mode.lock().unwrap_or_else(|e| e.into_inner());
        let clearnet_port = *self.clearnet_port.lock().unwrap_or_else(|e| e.into_inner());
        self.push_event("SettingsUpdated", build_settings_json(
            &flags, node_mode, &self.threat_context,
            &peer_id.to_hex(), &hex::encode(ed25519_pub), clearnet_port,
        ));

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
        let data_dir = std::path::Path::new(&self.data_dir);

        let identity = SelfIdentity::load_from_disk(data_dir, pin.as_deref())
            .map_err(|e| match e {
                IdentityError::WrongPin        => "Wrong PIN".to_string(),
                IdentityError::NotFound(_)     => "No identity found — call mi_create_identity first".to_string(),
                other                          => format!("Identity unlock failed: {other}"),
            })?;

        let master_key    = *identity.master_key;
        let peer_id       = identity.peer_id().to_hex();
        let ed25519_pub   = hex::encode(identity.ed25519_pub);

        // Initialise vault.
        self.vault = Some(VaultManager::new(
            std::path::PathBuf::from(&self.data_dir),
            master_key,
        ));
        self.identity_unlocked = true;
        *self.identity.lock().unwrap_or_else(|e| e.into_inner()) = Some(identity);

        // Restore rooms, contacts, messages, settings from vault.
        self.load_from_vault();

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
                    .map(|d| d.as_secs()).unwrap_or(0);

                let public_profile = id.display_name.as_ref().map(|name| {
                    crate::network::map::PublicProfileSummary {
                        display_name: Some(name.clone()),
                        bio:          None,
                        avatar_hash:  None,
                    }
                });

                let kem_ek = if id.kem_encapsulation_key.is_empty() { None }
                    else { Some(id.kem_encapsulation_key.clone()) };

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
                        ed25519_public:        id.ed25519_pub,
                        x25519_public:         *id.x25519_pub.as_bytes(),
                        preauth_x25519_public: Some(*id.preauth_x25519_pub.as_bytes()),
                        kem_encapsulation_key: kem_ek,
                        preauth_sig,
                    }],
                    last_seen:        now,
                    transport_hints:  vec![],
                    public_profile,
                    services:         vec![],
                    sequence:         1,
                    signature:        vec![],
                    local_trust:      TrustLevel::InnerCircle,
                };
                self_entry.sign(&signing_key);
                drop(guard);

                let mut gossip = self.gossip.lock().unwrap_or_else(|e| e.into_inner());
                let _ = gossip.map.insert(self_entry, now);
            }
        }

        // Emit settings event so Flutter receives the unlocked identity details.
        let flags         = self.transport_flags.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let node_mode     = *self.node_mode.lock().unwrap_or_else(|e| e.into_inner());
        let clearnet_port = *self.clearnet_port.lock().unwrap_or_else(|e| e.into_inner());
        self.push_event("SettingsUpdated", build_settings_json(
            &flags, node_mode, &self.threat_context,
            &peer_id, &ed25519_pub, clearnet_port,
        ));

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
        let json_bytes = base64::engine::general_purpose::STANDARD.decode(&b64_str)
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
        self.contacts.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.rooms.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.messages.lock().unwrap_or_else(|e| e.into_inner()).clear();

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
        self.identity_unlocked = false;
        *self.identity.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.rooms.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.contacts.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.messages.lock().unwrap_or_else(|e| e.into_inner()).clear();
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
        let profile: serde_json::Value = serde_json::from_str(profile_json)
            .map_err(|_| "Invalid JSON".to_string())?;

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

        self.push_event("ProfileUpdated", serde_json::json!({
            "kind":    "public",
            "profile": profile,
        }));
        Ok(())
    }

    /// Persist the private profile shared only with trusted contacts (§9.2).
    ///
    /// Persists to vault under `"private_profile"` and emits `ProfileUpdated`.
    ///
    /// Returns `Ok(())` on success, `Err(reason)` on persist failure.
    pub fn set_private_profile(&self, profile_json: &str) -> Result<(), String> {
        let profile: serde_json::Value = serde_json::from_str(profile_json)
            .map_err(|_| "Invalid JSON".to_string())?;

        // Persist to vault (encrypted at rest by the vault layer).
        if let Some(vm) = self.vault.as_ref() {
            if let Ok(coll) = vm.collection("private_profile") {
                coll.save(&profile)
                    .map_err(|e| format!("vault write failed: {e}"))?;
            }
        }

        self.push_event("ProfileUpdated", serde_json::json!({
            "kind":    "private",
            "profile": profile,
        }));
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
        let id = guard.as_ref()
            .ok_or_else(|| "identity not unlocked".to_string())?;

        let peer_id_hex        = id.peer_id().to_hex();
        let ed25519_hex        = hex::encode(id.ed25519_pub);
        let x25519_hex         = hex::encode(id.x25519_pub.as_bytes());
        let preauth_x25519_hex = hex::encode(id.preauth_x25519_pub.as_bytes());

        // One-time pairing token (prevents replay attacks).
        let mut token = [0u8; 32];
        if !try_random_fill(&mut token) {
            return Err("random number generation failed".to_string());
        }

        // Transport hints: include clearnet if the listener is running.
        let port = *self.clearnet_port.lock().unwrap_or_else(|e| e.into_inner());
        let mut hints: Vec<serde_json::Value> = Vec::new();
        if self.clearnet_listener.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
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
            .map(|d| d.as_secs()).unwrap_or(0);

        let payload = serde_json::json!({
            "version":              1,
            "peer_id":              peer_id_hex,
            "ed25519_public":       ed25519_hex,
            "x25519_public":        x25519_hex,
            // Preauth X25519 public key (our current SPK — changes weekly).
            "preauth_x25519_public": preauth_x25519_hex,
            "pairing_token":        hex::encode(token),
            "display_name":         display_name,
            "display_name_sig":     display_name_sig,
            "transport_hints":      hints,
            "expiry":               now + crate::pairing::methods::QR_EXPIRY_LIVE,
            // ML-KEM-768 encapsulation key (hex) — enables PQXDH (§3.4.1).
            "kem_pub":              hex::encode(&id.kem_encapsulation_key),
        });

        Ok(payload.to_string())
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
