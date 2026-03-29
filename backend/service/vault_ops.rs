//! Vault persistence operations for `MeshRuntime`.
//!
//! Every `save_*` method serialises a single data collection to the vault.
//! `load_from_vault` reads all collections at once after identity unlock.
//! `rebuild_routing_table_from_contacts` reseeds the routing table from the
//! contact store and is called by `load_from_vault` and after any pairing.
//!
//! ## Error policy
//! All save operations are best-effort: failure is logged to `stderr` but
//! does not abort the operation.  A vault write failure should never crash
//! the backend or leave in-memory state inconsistent.

use crate::messaging::room::Room;
use crate::network::threat_context::ThreatContext;
use crate::pairing::contact::{ContactRecord, ContactStore};
use crate::routing::announcement::AnnouncementProcessor;
use crate::routing::table::{DeviceAddress, RoutingEntry};
use crate::service::runtime::{MeshRuntime, SettingsVault};

impl MeshRuntime {
    // -----------------------------------------------------------------------
    // Load
    // -----------------------------------------------------------------------

    /// Load all persisted state from the vault into in-memory fields.
    ///
    /// Must be called after the vault is opened (i.e. after identity unlock).
    /// Reads rooms, contacts, messages, groups, settings, and ratchet sessions
    /// in sequence.  Missing collections are silently skipped (first-run case).
    ///
    /// Also rebuilds the routing table from contacts and updates the
    /// announcement processor with our real peer address.
    pub fn load_from_vault(&mut self) {
        // Nothing to do if no vault has been opened yet.
        let vm = match self.vault.as_ref() {
            Some(v) => v,
            None => return,
        };

        // ---- Rooms ----
        // Restore the conversation list from the vault.
        if let Ok(coll) = vm.collection("rooms") {
            if let Ok(Some(rooms)) = coll.load::<Vec<Room>>() {
                *self.rooms.lock().unwrap_or_else(|e| e.into_inner()) = rooms;
            }
        }

        // ---- Contacts ----
        // Rebuild the ContactStore from the persisted list of ContactRecords.
        if let Ok(coll) = vm.collection("peers") {
            if let Ok(Some(contacts)) = coll.load::<Vec<ContactRecord>>() {
                let mut store = ContactStore::new();
                for c in contacts {
                    store.upsert(c);
                }
                *self.contacts.lock().unwrap_or_else(|e| e.into_inner()) = store;
            }
        }

        // ---- Messages ----
        // Per-room message history: key = room_id hex, value = JSON array.
        if let Ok(coll) = vm.collection("messages") {
            if let Ok(Some(msgs)) =
                coll.load::<std::collections::HashMap<String, Vec<serde_json::Value>>>()
            {
                *self.messages.lock().unwrap_or_else(|e| e.into_inner()) = msgs;
            }
        }

        // ---- Groups ----
        // Group membership records including Sender Key state.
        if let Ok(coll) = vm.collection("groups") {
            if let Ok(Some(groups)) = coll.load::<Vec<crate::groups::group::Group>>() {
                *self.groups.lock().unwrap_or_else(|e| e.into_inner()) = groups;
            }
        }

        // ---- Settings ----
        // Transport flags, node mode, threat context, notification config, modules.
        if let Ok(coll) = vm.collection("settings") {
            if let Ok(Some(s)) = coll.load::<SettingsVault>() {
                self.apply_settings_vault(s);
            }
        }

        // ---- Ratchet sessions ----
        // Load persisted ratchet sessions (optional; missing collection is fine).
        self.load_ratchet_sessions();

        // ---- Derived state ----
        // Reseed the routing table with direct entries for all known contacts.
        self.rebuild_routing_table_from_contacts();

        // Replace the placeholder announcement processor address with our real
        // peer ID now that the identity has been unlocked.
        if let Some(our_peer_id) = self
            .identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|id| id.peer_id().0)
        {
            *self
                .announcement_processor
                .lock()
                .unwrap_or_else(|e| e.into_inner()) =
                AnnouncementProcessor::new(DeviceAddress(our_peer_id), 10);
        }
    }

    /// Apply a deserialized `SettingsVault` to all relevant fields.
    ///
    /// Factored out of `load_from_vault` so it can also be used by restore
    /// operations that load a `SettingsVault` from a backup payload.
    pub fn apply_settings_vault(&mut self, s: SettingsVault) {
        // Node mode and threat context are plain values (no mutex needed).
        *self.node_mode.lock().unwrap_or_else(|e| e.into_inner()) = s.node_mode;
        if let Some(tc) = ThreatContext::from_u8(s.threat_context) {
            self.threat_context = tc;
        }

        // Transport flags.
        let mut flags = self.transport_flags.lock().unwrap_or_else(|e| e.into_inner());
        flags.tor              = s.tor;
        flags.clearnet         = s.clearnet;
        flags.clearnet_fallback = s.clearnet_fallback;
        flags.i2p              = s.i2p;
        flags.bluetooth        = s.bluetooth;
        flags.rf               = s.rf;
        flags.mesh_discovery   = s.mesh_discovery;
        flags.allow_relays     = s.allow_relays;
        drop(flags);

        // Clearnet port: 0 in vault means "use default 7234".
        let port = if s.clearnet_port == 0 { 7_234 } else { s.clearnet_port };
        *self.clearnet_port.lock().unwrap_or_else(|e| e.into_inner()) = port;

        // Notification config.
        {
            let mut notif = self.notifications.lock().unwrap_or_else(|e| e.into_inner());
            notif.config.enabled = s.notification_enabled;
            if s.notification_tier >= 1 && s.notification_tier <= 4 {
                notif.config.tier = match s.notification_tier {
                    2 => crate::notifications::NotificationTier::UnifiedPush,
                    3 => crate::notifications::NotificationTier::SilentPush,
                    4 => crate::notifications::NotificationTier::RichPush,
                    _ => crate::notifications::NotificationTier::MeshTunnel,
                };
            }
            if !s.notification_push_url.is_empty() {
                notif.config.push_relay = Some(crate::notifications::PushRelayConfig {
                    relay_address: crate::notifications::RelayAddress::UnifiedPush {
                        endpoint: s.notification_push_url,
                    },
                    device_token: Vec::new(),
                    platform: crate::notifications::PushPlatform::UnifiedPush,
                });
            }
            notif.config.rich_content_level = if s.notification_show_previews {
                crate::notifications::RichPushContentLevel::Standard
            } else {
                crate::notifications::RichPushContentLevel::Minimal
            };
        }

        // Module config.
        if let Some(mc_val) = s.module_config {
            if let Ok(mc) = serde_json::from_value::<
                crate::services::module_system::ModuleConfig,
            >(mc_val)
            {
                *self.module_config.lock().unwrap_or_else(|e| e.into_inner()) = mc;
            }
        }
    }

    /// Rebuild the routing table with direct entries for all known contacts.
    ///
    /// Called after vault load and after any contact mutation (pairing, remove).
    /// Each paired contact that has cleared the challenge-response receives a
    /// local-plane routing entry with `hop_count = 1` (direct neighbour).
    pub fn rebuild_routing_table_from_contacts(&self) {
        let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
        let mut table = self.routing_table.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        for contact in contacts.all() {
            // Each paired peer is a direct neighbour — destination = next hop.
            let dest = DeviceAddress(contact.peer_id.0);
            let entry = RoutingEntry {
                destination:     dest,
                next_hop:        dest,
                hop_count:       1,
                latency_ms:      10,
                next_hop_trust:  contact.trust_level,
                last_updated:    now,
                announcement_id: [0u8; 32], // direct entry — no gossip announcement
            };
            table.update_local(entry);
        }
    }

    // -----------------------------------------------------------------------
    // Save
    // -----------------------------------------------------------------------

    /// Persist rooms to vault.  Called after any room mutation.
    pub fn save_rooms(&self) {
        let Some(vm) = self.vault.as_ref() else { return };
        let Ok(coll) = vm.collection("rooms") else { return };
        let rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = coll.save(&*rooms) {
            eprintln!("[vault] ERROR: failed to persist rooms: {e}");
        }
    }

    /// Persist contacts to vault.  Called after any contact mutation.
    pub fn save_contacts(&self) {
        let Some(vm) = self.vault.as_ref() else { return };
        let Ok(coll) = vm.collection("peers") else { return };
        let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
        let all: Vec<ContactRecord> = contacts.all().into_iter().cloned().collect();
        if let Err(e) = coll.save(&all) {
            eprintln!("[vault] ERROR: failed to persist contacts: {e}");
        }
    }

    /// Persist messages to vault.  Called after any message mutation.
    pub fn save_messages(&self) {
        let Some(vm) = self.vault.as_ref() else { return };
        let Ok(coll) = vm.collection("messages") else { return };
        let msgs = self.messages.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = coll.save(&*msgs) {
            eprintln!("[vault] ERROR: failed to persist messages: {e}");
        }
    }

    /// Persist groups to vault.  Called after any group mutation.
    pub fn save_groups(&self) {
        let Some(vm) = self.vault.as_ref() else { return };
        let Ok(coll) = vm.collection("groups") else { return };
        let groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = coll.save(&*groups) {
            eprintln!("[vault] ERROR: failed to persist groups: {e}");
        }
    }

    /// Persist settings to vault.  Called after any transport flag, node mode,
    /// threat context, notification config, or module config change.
    pub fn save_settings(&self) {
        let Some(vm) = self.vault.as_ref() else { return };
        let Ok(coll) = vm.collection("settings") else { return };

        // Build the vault record from current in-memory state.
        let flags = self.transport_flags.lock().unwrap_or_else(|e| e.into_inner());
        let notif = self.notifications.lock().unwrap_or_else(|e| e.into_inner());
        let ncfg  = &notif.config;

        // Resolve push URL from the relay config variant.
        let push_url = ncfg.push_relay.as_ref().map(|r| match &r.relay_address {
            crate::notifications::RelayAddress::ClearnetUrl  { url }     => url.clone(),
            crate::notifications::RelayAddress::UnifiedPush { endpoint } => endpoint.clone(),
            crate::notifications::RelayAddress::MeshService { .. }       => String::new(),
        }).unwrap_or_default();

        let mc_val = serde_json::to_value(
            &*self.module_config.lock().unwrap_or_else(|e| e.into_inner()),
        ).ok();

        let s = SettingsVault {
            node_mode:                  *self.node_mode.lock().unwrap_or_else(|e| e.into_inner()),
            threat_context:             self.threat_context as u8,
            tor:                        flags.tor,
            clearnet:                   flags.clearnet,
            clearnet_fallback:          flags.clearnet_fallback,
            i2p:                        flags.i2p,
            bluetooth:                  flags.bluetooth,
            rf:                         flags.rf,
            mesh_discovery:             flags.mesh_discovery,
            allow_relays:               flags.allow_relays,
            clearnet_port:              *self.clearnet_port.lock().unwrap_or_else(|e| e.into_inner()),
            notification_tier:          ncfg.tier as u8,
            notification_enabled:       ncfg.enabled,
            notification_push_url:      push_url,
            notification_show_previews: ncfg.rich_content_level as u8 >= 1,
            module_config:              mc_val,
        };

        if let Err(e) = coll.save(&s) {
            eprintln!("[vault] ERROR: failed to persist settings: {e}");
        }
    }

    /// Persist Double Ratchet sessions to vault.
    ///
    /// Sessions are serialised as `Vec<(peer_id_hex, SessionSnapshot)>`.
    /// Called after each ratchet advancement to preserve forward secrecy
    /// across restarts.
    pub fn save_ratchet_sessions(&self) {
        let Some(vm) = self.vault.as_ref() else { return };
        let Ok(coll) = vm.collection("ratchet_sessions") else { return };
        let sessions = self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner());

        let snapshots: Vec<(String, crate::crypto::double_ratchet::SessionSnapshot)> = sessions
            .iter()
            .map(|(peer_id, session)| (hex::encode(peer_id.0), session.to_snapshot()))
            .collect();

        if let Err(e) = coll.save(&snapshots) {
            eprintln!("[vault] ERROR: failed to persist ratchet sessions: {e}");
        }
    }

    /// Load Double Ratchet sessions from vault.  Called from `load_from_vault`.
    ///
    /// Missing collection or individual corrupt entries are silently skipped;
    /// a missing session will be bootstrapped on demand from static DH keys.
    pub fn load_ratchet_sessions(&self) {
        let Some(vm) = self.vault.as_ref() else { return };
        let Ok(coll) = vm.collection("ratchet_sessions") else { return };
        let Ok(Some(snapshots)) = coll
            .load::<Vec<(String, crate::crypto::double_ratchet::SessionSnapshot)>>()
        else {
            return;
        };

        let mut sessions = self.ratchet_sessions.lock().unwrap_or_else(|e| e.into_inner());
        for (peer_hex, snap) in snapshots {
            let Ok(peer_bytes) = hex::decode(&peer_hex) else { continue };
            if peer_bytes.len() != 32 {
                continue;
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&peer_bytes);
            let peer_id = crate::identity::peer_id::PeerId(arr);
            // Restore the snapshot; `from_snapshot` is infallible.
            let session =
                crate::crypto::double_ratchet::DoubleRatchetSession::from_snapshot(snap);
            sessions.insert(peer_id, session);
        }
    }
}
