use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use getrandom::getrandom;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};
use time::format_description;

use crate::{AppConfig, MainWindow, MessageRow, NodeMode, PeerRow, RoomRow};

pub struct AppController {
    ui: MainWindow,
    state: Rc<RefCell<AppState>>,
}

impl AppController {
    pub fn new(ui: MainWindow, config: AppConfig) -> Self {
        let state = Rc::new(RefCell::new(AppState::new(config)));
        let controller = Self { ui, state };
        controller.sync_all();
        controller
    }

    pub fn bind(&self) {
        let ui_handle = self.ui.as_weak();
        self.ui.on_toggle_settings(move || {
            if let Some(ui) = ui_handle.upgrade() {
                let open = ui.get_settings_open();
                ui.set_settings_open(!open);
            }
        });

        let ui_handle = self.ui.as_weak();
        let state = self.state.clone();
        self.ui.on_create_room(move |name: SharedString| {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                return;
            }

            let Some(ui) = ui_handle.upgrade() else {
                return;
            };

            {
                let mut state = state.borrow_mut();
                if state.settings.node_mode == NodeMode::Server {
                    return;
                }
                let room_id = state.create_room(trimmed);
                state.select_room(&room_id);
            }

            sync_rooms(&ui, &state.borrow());
            sync_active_room(&ui, &state.borrow());
            sync_messages(&ui, &state.borrow());
        });

        let ui_handle = self.ui.as_weak();
        let state = self.state.clone();
        self.ui.on_select_room(move |room_id: SharedString| {
            let Some(ui) = ui_handle.upgrade() else {
                return;
            };

            {
                let mut state = state.borrow_mut();
                if state.settings.node_mode == NodeMode::Server {
                    return;
                }
                state.select_room(room_id.as_str());
            }
            sync_rooms(&ui, &state.borrow());
            sync_active_room(&ui, &state.borrow());
            sync_messages(&ui, &state.borrow());
        });

        let ui_handle = self.ui.as_weak();
        let state = self.state.clone();
        self.ui.on_send_message(move |text: SharedString| {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                return;
            }

            let Some(ui) = ui_handle.upgrade() else {
                return;
            };

            {
                let mut state = state.borrow_mut();
                if state.settings.node_mode == NodeMode::Server {
                    return;
                }
                state.send_message(trimmed);
            }

            sync_rooms(&ui, &state.borrow());
            sync_messages(&ui, &state.borrow());
        });

        let ui_handle = self.ui.as_weak();
        let state = self.state.clone();
        self.ui.on_pair_peer(move |code: SharedString| {
            let trimmed = code.trim();
            if trimmed.is_empty() {
                return;
            }

            let Some(ui) = ui_handle.upgrade() else {
                return;
            };

            {
                let mut state = state.borrow_mut();
                state.pair_peer(trimmed);
            }

            sync_peers(&ui, &state.borrow());
        });

        let ui_handle = self.ui.as_weak();
        let state = self.state.clone();
        self.ui.on_set_node_mode(move |mode| {
            state.borrow_mut().settings.node_mode = mode;
            if let Some(ui) = ui_handle.upgrade() {
                ui.set_node_mode(mode);
            }
        });

        let ui_handle = self.ui.as_weak();
        let state = self.state.clone();
        self.ui.on_set_enable_tor(move |value| {
            state.borrow_mut().settings.enable_tor = value;
            if let Some(ui) = ui_handle.upgrade() {
                ui.set_enable_tor(value);
            }
        });

        let ui_handle = self.ui.as_weak();
        let state = self.state.clone();
        self.ui.on_set_enable_clearnet(move |value| {
            state.borrow_mut().settings.enable_clearnet = value;
            if let Some(ui) = ui_handle.upgrade() {
                ui.set_enable_clearnet(value);
            }
        });

        let ui_handle = self.ui.as_weak();
        let state = self.state.clone();
        self.ui.on_set_mesh_discovery(move |value| {
            state.borrow_mut().settings.mesh_discovery = value;
            if let Some(ui) = ui_handle.upgrade() {
                ui.set_mesh_discovery(value);
            }
        });

        let ui_handle = self.ui.as_weak();
        let state = self.state.clone();
        self.ui.on_set_allow_relays(move |value| {
            state.borrow_mut().settings.allow_relays = value;
            if let Some(ui) = ui_handle.upgrade() {
                ui.set_allow_relays(value);
            }
        });
    }

    fn sync_all(&self) {
        let state = self.state.borrow();
        self.ui.set_settings_open(false);
        sync_rooms(&self.ui, &state);
        sync_messages(&self.ui, &state);
        sync_peers(&self.ui, &state);
        sync_active_room(&self.ui, &state);
        sync_settings(&self.ui, &state);
    }
}

struct AppState {
    rooms: Vec<RoomState>,
    messages: HashMap<String, Vec<MessageState>>,
    peers: Vec<PeerState>,
    active_room_id: Option<String>,
    settings: SettingsState,
}

impl AppState {
    fn new(config: AppConfig) -> Self {
        Self {
            rooms: Vec::new(),
            messages: HashMap::new(),
            peers: Vec::new(),
            active_room_id: None,
            settings: SettingsState::new(config.initial_mode),
        }
    }

    fn create_room(&mut self, name: &str) -> String {
        let room_id = random_id("room");
        let room = RoomState {
            id: room_id.clone(),
            name: name.to_string(),
            last_message: String::new(),
            unread: 0,
            timestamp: String::new(),
        };
        self.rooms.insert(0, room);
        self.messages.insert(room_id.clone(), Vec::new());
        room_id
    }

    fn select_room(&mut self, room_id: &str) {
        self.active_room_id = Some(room_id.to_string());
        if let Some(room) = self.rooms.iter_mut().find(|room| room.id == room_id) {
            room.unread = 0;
        }
    }

    fn send_message(&mut self, text: &str) {
        let Some(room_id) = self.active_room_id.clone() else {
            return;
        };

        let message = MessageState {
            id: random_id("msg"),
            sender: "You".to_string(),
            text: text.to_string(),
            timestamp: now_label(),
            is_outgoing: true,
        };

        let entry = self.messages.entry(room_id.clone()).or_default();
        entry.push(message.clone());

        if let Some(room) = self.rooms.iter_mut().find(|room| room.id == room_id) {
            room.last_message = message.text;
            room.timestamp = message.timestamp;
        }
    }

    fn pair_peer(&mut self, code: &str) {
        let short_code: String = code.chars().take(6).collect();
        let peer = PeerState {
            id: random_id("peer"),
            name: format!("Peer {}", short_code),
            trust_level: 0,
            status: "Paired".to_string(),
        };
        self.peers.insert(0, peer);
    }
}

struct RoomState {
    id: String,
    name: String,
    last_message: String,
    unread: i32,
    timestamp: String,
}

#[derive(Clone)]
struct MessageState {
    id: String,
    sender: String,
    text: String,
    timestamp: String,
    is_outgoing: bool,
}

struct PeerState {
    id: String,
    name: String,
    trust_level: i32,
    status: String,
}

struct SettingsState {
    node_mode: NodeMode,
    enable_tor: bool,
    enable_clearnet: bool,
    mesh_discovery: bool,
    allow_relays: bool,
    pairing_code: String,
}

impl SettingsState {
    fn new(initial_mode: NodeMode) -> Self {
        Self {
            node_mode: initial_mode,
            enable_tor: true,
            enable_clearnet: true,
            mesh_discovery: true,
            allow_relays: true,
            pairing_code: random_pairing_code(),
        }
    }
}

fn sync_rooms(ui: &MainWindow, state: &AppState) {
    let model = VecModel::from(
        state
            .rooms
            .iter()
            .map(|room| RoomRow {
                id: SharedString::from(room.id.as_str()),
                name: SharedString::from(room.name.as_str()),
                last_message: SharedString::from(room.last_message.as_str()),
                unread_count: room.unread,
                unread_label: SharedString::from(room.unread.to_string()),
                timestamp: SharedString::from(room.timestamp.as_str()),
            })
            .collect::<Vec<_>>(),
    );
    ui.set_rooms(ModelRc::new(model));
}

fn sync_messages(ui: &MainWindow, state: &AppState) {
    let messages = state
        .active_room_id
        .as_ref()
        .and_then(|room_id| state.messages.get(room_id))
        .cloned()
        .unwrap_or_default();

    let model = VecModel::from(messages.into_iter().map(|message| MessageRow {
        id: SharedString::from(message.id),
        sender: SharedString::from(message.sender),
        text: SharedString::from(message.text),
        timestamp: SharedString::from(message.timestamp),
        is_outgoing: message.is_outgoing,
    }).collect::<Vec<_>>());

    ui.set_messages(ModelRc::new(model));
}

fn sync_peers(ui: &MainWindow, state: &AppState) {
    let model = VecModel::from(state.peers.iter().map(|peer| PeerRow {
        id: SharedString::from(peer.id.as_str()),
        name: SharedString::from(peer.name.as_str()),
        trust_level: peer.trust_level,
        status: SharedString::from(peer.status.as_str()),
    }).collect::<Vec<_>>());
    ui.set_peers(ModelRc::new(model));
}

fn sync_active_room(ui: &MainWindow, state: &AppState) {
    let active_id = state.active_room_id.clone().unwrap_or_default();
    let active_title = state
        .rooms
        .iter()
        .find(|room| room.id == active_id)
        .map(|room| room.name.clone())
        .unwrap_or_default();

    ui.set_active_room_id(SharedString::from(active_id));
    ui.set_active_room_title(SharedString::from(active_title));
}

fn sync_settings(ui: &MainWindow, state: &AppState) {
    ui.set_node_mode(state.settings.node_mode);
    ui.set_enable_tor(state.settings.enable_tor);
    ui.set_enable_clearnet(state.settings.enable_clearnet);
    ui.set_mesh_discovery(state.settings.mesh_discovery);
    ui.set_allow_relays(state.settings.allow_relays);
    ui.set_pairing_code(SharedString::from(state.settings.pairing_code.as_str()));
}

fn random_id(prefix: &str) -> String {
    let mut bytes = [0u8; 8];
    getrandom(&mut bytes).expect("system RNG unavailable");
    format!("{}-{}", prefix, hex_encode(&bytes))
}

fn random_pairing_code() -> String {
    let mut bytes = [0u8; 8];
    getrandom(&mut bytes).expect("system RNG unavailable");
    let hex = hex_encode(&bytes);
    format!(
        "{}-{}-{}-{}",
        &hex[0..4],
        &hex[4..8],
        &hex[8..12],
        &hex[12..16]
    )
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

fn now_label() -> String {
    let format = format_description::parse("[hour]:[minute]").ok();
    let now = time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    match format {
        Some(format) => now.format(&format).unwrap_or_default(),
        None => String::new(),
    }
}
