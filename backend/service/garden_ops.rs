//! Garden feed and discovery helpers.
//!
//! Discoverable Gardens are carried over the backend service-advertisement
//! path, not synthesized solely from joined rooms. This keeps the Garden
//! Explore surface aligned with the spec's passive discovery model.

use crate::identity::peer_id::PeerId;
use crate::messaging::message::ConversationType;
use crate::service::runtime::{GardenDirectoryEntry, MeshRuntime};
use crate::services::registry::{
    ServicePublication, ServiceRecord, ServiceScope, ServiceTransportHint,
};
use sha2::{Digest, Sha256};

const GARDEN_DISCOVERY_APPLICATION_ID: [u8; 16] = *b"garden_discovery";
const GARDEN_DISCOVERY_DOMAIN: &[u8] = b"meshinfinity-garden-discovery-v1\x00";

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct GardenDiscoveryPayload {
    garden_id: String,
    display_name: String,
    description: Option<String>,
    member_count: u32,
    tags: Vec<String>,
    language: Option<String>,
    network_type: String,
    join_endpoint: String,
    updated_at: u64,
    signature: String,
}

impl MeshRuntime {
    /// Return discoverable gardens in the UI discovery shape.
    pub fn discover_gardens(&self) -> String {
        self.publish_local_garden_discovery_records();
        self.rebuild_garden_directory_from_service_registry();

        let rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
        let joined_room_ids: std::collections::HashSet<String> = rooms
            .iter()
            .filter(|room| room.conversation_type == ConversationType::Group)
            .map(|room| hex::encode(room.id))
            .collect();
        let directory = self
            .discoverable_gardens
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        let mut gardens: Vec<serde_json::Value> = directory
            .into_iter()
            .map(|entry| {
                serde_json::json!({
                    "id": entry.id,
                    "name": entry.name,
                    "description": entry.description,
                    "memberCount": entry.member_count,
                    "networkType": entry.network_type,
                    "joined": joined_room_ids.contains(&entry.id),
                })
            })
            .collect();

        gardens.sort_by(|a, b| {
            let a_name = a.get("name").and_then(|v| v.as_str()).unwrap_or_default();
            let b_name = b.get("name").and_then(|v| v.as_str()).unwrap_or_default();
            a_name.cmp(b_name)
        });

        serde_json::Value::Array(gardens).to_string()
    }

    /// Return Garden feed posts either for one Garden or across all joined ones.
    pub fn get_garden_posts(&self, garden_id: &str) -> String {
        let rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
        let messages = self.messages.lock().unwrap_or_else(|e| e.into_inner());

        let mut joined_gardens = std::collections::HashMap::new();
        for room in rooms
            .iter()
            .filter(|room| room.conversation_type == ConversationType::Group)
        {
            let room_id = hex::encode(room.id);
            if garden_id.is_empty() || room_id == garden_id {
                joined_gardens.insert(room_id, room.name.clone());
            }
        }

        let mut posts = Vec::new();
        for (room_id, room_name) in joined_gardens {
            if let Some(room_messages) = messages.get(&room_id) {
                for message in room_messages {
                    let content = message
                        .get("text")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    if content.is_empty() {
                        continue;
                    }

                    let sender = message
                        .get("sender")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    let timestamp = message
                        .get("timestamp")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);

                    posts.push(serde_json::json!({
                        "id": message.get("id").and_then(|v| v.as_str()).unwrap_or_default(),
                        "authorId": sender,
                        "authorName": self.resolve_garden_author_name(sender),
                        "gardenId": room_id,
                        "gardenName": room_name,
                        "content": content,
                        "timestamp": timestamp,
                        "reactionCount": message
                            .get("reactions")
                            .and_then(|v| v.as_array())
                            .map(|r| r.len())
                            .unwrap_or(0),
                    }));
                }
            }
        }

        posts.sort_by(|a, b| {
            let a_ts = a.get("timestamp").and_then(|v| v.as_u64()).unwrap_or(0);
            let b_ts = b.get("timestamp").and_then(|v| v.as_u64()).unwrap_or(0);
            b_ts.cmp(&a_ts)
        });
        serde_json::Value::Array(posts).to_string()
    }

    /// Publish a Garden post through the existing room messaging pipeline.
    pub fn post_to_garden(&self, garden_id: &str, content: &str) -> Result<(), String> {
        let room_exists = {
            let rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
            rooms.iter().any(|room| {
                room.conversation_type == ConversationType::Group
                    && hex::encode(room.id) == garden_id
            })
        };
        if !room_exists {
            return Err("garden not found".into());
        }
        if !self.send_text_message(garden_id, content) {
            return Err("failed to publish garden post".into());
        }
        Ok(())
    }

    /// Join a Garden from the backend-owned directory.
    pub fn join_garden(&self, garden_id: &str) -> Result<(), String> {
        self.rebuild_garden_directory_from_service_registry();

        let directory_entry = self
            .discoverable_gardens
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|entry| entry.id == garden_id)
            .cloned()
            .ok_or_else(|| "garden not found".to_string())?;

        let mut rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner());
        if rooms.iter().any(|room| {
            room.conversation_type == ConversationType::Group && hex::encode(room.id) == garden_id
        }) {
            return Ok(());
        }

        let mut room = crate::messaging::room::Room::new_group(
            &directory_entry.name,
            self.identity
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(|identity| vec![identity.peer_id()])
                .unwrap_or_default(),
        );

        let room_id = hex::decode(garden_id).map_err(|_| "invalid garden id".to_string())?;
        let room_id: [u8; 16] = room_id
            .try_into()
            .map_err(|_| "invalid garden id length".to_string())?;
        room.id = room_id;
        room.last_message_preview = if directory_entry.description.is_empty() {
            None
        } else {
            Some(directory_entry.description)
        };
        rooms.push(room);
        drop(rooms);
        self.save_rooms();
        self.push_event(
            "RoomsChanged",
            serde_json::json!({ "gardenId": garden_id, "action": "join" }),
        );
        Ok(())
    }

    /// Build local Garden discovery records and publish them through the
    /// service registry so peers learn about them over the same discovery path.
    pub fn publish_local_garden_discovery_records(&self) {
        let now = current_time_secs();
        let records = match self.local_garden_service_records(now) {
            Ok(records) => records,
            Err(_) => return,
        };
        let mut changed = false;
        {
            let mut registry = self
                .service_registry
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            for record in records {
                if registry.upsert(record.clone()) {
                    changed = true;
                    self.broadcast_service_record(record, None);
                }
            }
        }
        if changed {
            self.save_service_registry();
            self.rebuild_garden_directory_from_service_registry();
        }
    }

    /// Merge an inbound service record and rebuild the Garden directory if it
    /// carried Garden discovery metadata.
    pub fn receive_service_record(&self, record: ServiceRecord, sender: Option<&str>) -> bool {
        let accepted = {
            let mut registry = self
                .service_registry
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            registry.upsert(record.clone())
        };
        if !accepted {
            return false;
        }

        self.save_service_registry();
        self.rebuild_garden_directory_from_service_registry();
        self.broadcast_service_record(record, sender);
        true
    }

    /// Return all locally stored Garden discovery service records.
    pub fn local_garden_service_records(
        &self,
        updated_at: u64,
    ) -> Result<Vec<ServiceRecord>, String> {
        let identity = self.identity.lock().unwrap_or_else(|e| e.into_inner());
        let Some(identity) = identity.as_ref() else {
            return Ok(Vec::new());
        };
        let secret = identity.ed25519_signing.to_bytes();
        let owner_peer_id = identity.ed25519_pub;
        let join_endpoint = identity.peer_id().to_hex();

        let rooms = self.rooms.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let mut records = Vec::new();

        for room in rooms
            .iter()
            .filter(|room| room.conversation_type == ConversationType::Group)
        {
            let garden_id = hex::encode(room.id);
            let payload = GardenDiscoveryPayload {
                garden_id: garden_id.clone(),
                display_name: room.name.clone(),
                description: room
                    .last_message_preview
                    .clone()
                    .filter(|value| !value.is_empty()),
                member_count: room.participants.len() as u32,
                tags: Vec::new(),
                language: None,
                network_type: "public".to_string(),
                join_endpoint: join_endpoint.clone(),
                updated_at,
                signature: String::new(),
            };
            let payload = sign_garden_discovery_payload(&secret, payload)?;
            records.push(ServiceRecord {
                service_id: derive_garden_service_id(&room.id),
                owner_peer_id,
                version: updated_at,
                publications: vec![ServicePublication {
                    scope: ServiceScope::Public,
                    address: owner_peer_id,
                    port: None,
                    protocols: Vec::new(),
                    name: Some(room.name.clone()),
                    description: room
                        .last_message_preview
                        .clone()
                        .filter(|value| !value.is_empty()),
                    transport_hint: ServiceTransportHint::PreferMesh,
                    acl: None,
                    application_id: Some(GARDEN_DISCOVERY_APPLICATION_ID),
                    application_data: Some(
                        serde_json::to_value(&payload).map_err(|e| {
                            format!("failed to encode garden discovery payload: {e}")
                        })?,
                    ),
                    losec_config: crate::routing::losec::ServiceLoSecConfig::default(),
                }],
                sig: Vec::new(),
            });

            if let Some(record) = records.last_mut() {
                record.sig = sign_service_record(
                    &secret,
                    record.service_id,
                    record.owner_peer_id,
                    record.version,
                    &record.publications,
                )?;
            }
        }

        Ok(records)
    }

    fn verify_garden_discovery_payload(
        &self,
        owner_peer_id: &[u8; 32],
        payload: &GardenDiscoveryPayload,
    ) -> bool {
        let signature = match hex::decode(&payload.signature) {
            Ok(signature) => signature,
            Err(_) => return false,
        };
        let message = match garden_discovery_payload_message(payload) {
            Ok(message) => message,
            Err(_) => return false,
        };
        crate::crypto::signing::verify(owner_peer_id, GARDEN_DISCOVERY_DOMAIN, &message, &signature)
    }

    fn rebuild_garden_directory_from_service_registry(&self) {
        let joined_room_ids: std::collections::HashSet<String> = self
            .rooms
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|room| room.conversation_type == ConversationType::Group)
            .map(|room| hex::encode(room.id))
            .collect();

        let registry = self
            .service_registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .all();

        let mut entries = std::collections::HashMap::<String, GardenDirectoryEntry>::new();
        for record in registry {
            for publication in record.publications {
                let Some(application_id) = publication.application_id else {
                    continue;
                };
                if application_id != GARDEN_DISCOVERY_APPLICATION_ID {
                    continue;
                }
                let Some(application_data) = publication.application_data else {
                    continue;
                };
                let payload: GardenDiscoveryPayload = match serde_json::from_value(application_data)
                {
                    Ok(payload) => payload,
                    Err(_) => continue,
                };
                if !self.verify_garden_discovery_payload(&record.owner_peer_id, &payload) {
                    continue;
                }
                if payload.garden_id.is_empty() {
                    continue;
                }
                entries.insert(
                    payload.garden_id.clone(),
                    GardenDirectoryEntry {
                        id: payload.garden_id,
                        name: payload.display_name,
                        description: payload.description.unwrap_or_default(),
                        network_type: payload.network_type,
                        member_count: payload.member_count,
                    },
                );
            }
        }

        for room in self
            .rooms
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|room| room.conversation_type == ConversationType::Group)
        {
            let room_id = hex::encode(room.id);
            entries
                .entry(room_id.clone())
                .or_insert_with(|| GardenDirectoryEntry {
                    id: room_id,
                    name: room.name.clone(),
                    description: room.last_message_preview.clone().unwrap_or_default(),
                    network_type: "public".to_string(),
                    member_count: room.participants.len() as u32,
                });
        }

        let mut values: Vec<GardenDirectoryEntry> = entries.into_values().collect();
        values.sort_by(|a, b| {
            let a_joined = joined_room_ids.contains(&a.id);
            let b_joined = joined_room_ids.contains(&b.id);
            b_joined
                .cmp(&a_joined)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });

        *self
            .discoverable_gardens
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = values;
        self.save_garden_directory();
    }

    pub fn broadcast_service_record(
        &self,
        record: ServiceRecord,
        exclude_peer_id_hex: Option<&str>,
    ) {
        let peer_ids: Vec<String> = self
            .clearnet_connections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .filter(|peer_id| Some(peer_id.as_str()) != exclude_peer_id_hex)
            .cloned()
            .collect();
        let frame = serde_json::json!({
            "type": "service_record",
            "sender": self
                .identity
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(|identity| identity.peer_id().to_hex())
                .unwrap_or_default(),
            "record": record,
        });
        for peer_id in peer_ids {
            self.send_raw_frame(&peer_id, &frame);
        }
    }

    fn resolve_garden_author_name(&self, sender_hex: &str) -> String {
        let our_peer_id = self
            .identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|identity| identity.peer_id().to_hex());
        if our_peer_id.as_deref() == Some(sender_hex) {
            return "You".into();
        }

        let sender_bytes: [u8; 32] = match hex::decode(sender_hex)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
        {
            Some(bytes) => bytes,
            None => return short_label(sender_hex),
        };
        let sender_peer_id = PeerId(sender_bytes);
        let contacts = self.contacts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(contact) = contacts.get(&sender_peer_id) {
            if let Some(name) = contact
                .local_nickname
                .as_ref()
                .filter(|name| !name.is_empty())
            {
                return name.clone();
            }
            if let Some(name) = contact
                .display_name
                .as_ref()
                .filter(|name| !name.is_empty())
            {
                return name.clone();
            }
        }
        short_label(sender_hex)
    }
}

fn derive_garden_service_id(garden_id: &[u8; 16]) -> [u8; 16] {
    let mut message = Vec::with_capacity(17 + garden_id.len());
    message.extend_from_slice(b"garden-service-v1");
    message.extend_from_slice(garden_id);
    let digest = Sha256::digest(message);
    let mut service_id = [0u8; 16];
    service_id.copy_from_slice(&digest[..16]);
    service_id
}

fn sign_service_record(
    secret: &[u8; 32],
    service_id: [u8; 16],
    owner_peer_id: [u8; 32],
    version: u64,
    publications: &[ServicePublication],
) -> Result<Vec<u8>, String> {
    let pubs_json = serde_json::to_vec(publications)
        .map_err(|e| format!("failed to encode service publications: {e}"))?;
    let mut message = Vec::with_capacity(16 + 32 + 8 + pubs_json.len());
    message.extend_from_slice(&service_id);
    message.extend_from_slice(&owner_peer_id);
    message.extend_from_slice(&version.to_be_bytes());
    message.extend_from_slice(&pubs_json);
    Ok(crate::crypto::signing::sign(
        secret,
        crate::crypto::signing::DOMAIN_SERVICE_RECORD,
        &message,
    ))
}

fn sign_garden_discovery_payload(
    secret: &[u8; 32],
    mut payload: GardenDiscoveryPayload,
) -> Result<GardenDiscoveryPayload, String> {
    let message = garden_discovery_payload_message(&payload)?;
    let signature = crate::crypto::signing::sign(secret, GARDEN_DISCOVERY_DOMAIN, &message);
    payload.signature = hex::encode(signature);
    Ok(payload)
}

fn garden_discovery_payload_message(payload: &GardenDiscoveryPayload) -> Result<Vec<u8>, String> {
    let mut unsigned = payload.clone();
    unsigned.signature.clear();
    serde_json::to_vec(&unsigned)
        .map_err(|e| format!("failed to encode garden discovery payload: {e}"))
}

fn current_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn short_label(value: &str) -> String {
    value.chars().take(8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messaging::room::Room;
    use tempfile::TempDir;

    #[test]
    fn test_garden_discovery_records_round_trip_between_runtimes() {
        let source_dir = TempDir::new().unwrap();
        let sink_dir = TempDir::new().unwrap();

        let mut source = MeshRuntime::new(source_dir.path().to_string_lossy().into_owned());
        source.transport_flags.lock().unwrap().clearnet = false;
        *source.clearnet_port.lock().unwrap() = 0;
        source.create_identity(Some("Source".to_string())).unwrap();

        let mut sink = MeshRuntime::new(sink_dir.path().to_string_lossy().into_owned());
        sink.transport_flags.lock().unwrap().clearnet = false;
        *sink.clearnet_port.lock().unwrap() = 0;
        sink.create_identity(Some("Sink".to_string())).unwrap();

        let mut room = Room::new_group("Field Notes", Vec::new());
        room.last_message_preview = Some("Observed through passive gossip".to_string());
        source.rooms.lock().unwrap().push(room);

        let records = source
            .local_garden_service_records(current_time_secs())
            .unwrap();
        assert_eq!(records.len(), 1);
        assert!(sink.receive_service_record(records[0].clone(), Some("peer_a")));

        let discovered: Vec<serde_json::Value> =
            serde_json::from_str(&sink.discover_gardens()).unwrap();
        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0]["name"], "Field Notes");
        assert_eq!(discovered[0]["networkType"], "public");
    }
}
