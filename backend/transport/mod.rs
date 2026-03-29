//! Transport Layer (§5)
//!
//! # What is the Transport Layer?
//!
//! The transport layer is responsible for moving encrypted bytes between
//! two nodes. It sits BELOW the routing layer (which decides WHERE to send)
//! and ABOVE the physical network (internet, Bluetooth, etc.).
//!
//! # Architecture
//!
//! ```text
//! Application message
//!     ↓
//! Four-layer encryption (§7.2)
//!     ↓
//! KCP reliability sublayer (§5.30) — retransmission, ordering
//!     ↓
//! WireGuard encryption (§5.2) — per-hop authenticated encryption
//!     ↓
//! Traffic shaping (§15.4) — padding, jitter, cover traffic
//!     ↓
//! Obfuscation (§5.26) — optional DPI evasion (QUIC wrapper, etc.)
//!     ↓
//! Physical transport (internet, Bluetooth, Tor, etc.)
//! ```
//!
//! # Key Principle: Transport Agnostic
//!
//! Mesh Infinity is NOT bound by IP, TCP, or any internet infrastructure.
//! WireGuard is the encrypted link layer; what carries WireGuard packets
//! is entirely pluggable. A transport is anything that can move bytes:
//! the internet, a Bluetooth connection, a phone call, a serial cable,
//! or inaudible sound.
//!
//! # Transport Selection
//!
//! The Transport Solver (§5.10) decides which transport to use for each
//! connection based on:
//! - Hardware availability (does this device have Bluetooth?)
//! - Peer capabilities (does the peer support Tor?)
//! - Threat context (Critical mode disables clearnet)
//! - Latency/bandwidth requirements (voice calls need low latency)
//! - Transport diversity (spread traffic across multiple transports)

pub mod bluetooth;
pub mod can_bus;
pub mod cjdns;
pub mod i2p;
pub mod kcp;
pub mod layer2;
pub mod libp2p_transport;
pub mod manager;
pub mod mixnet;
pub mod nfc;
pub mod nl80211;
pub mod obfuscation;
pub mod offline;
pub mod overlay_client;
pub mod rf_sdr;
pub mod solver;
pub mod health;
pub mod tailscale;
pub mod telephone;
pub mod tor;
pub mod ultrasonic;
pub mod usb_serial;
pub mod wifi_direct;
pub mod wireguard;
pub mod yggdrasil;
pub mod zerotier;
