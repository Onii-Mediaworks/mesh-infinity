//! Messaging Service (§10.1)
//!
//! Chat messaging: rooms, messages, delivery status, message requests.
//! Integrates Double Ratchet sessions with four-layer encryption.

pub mod room;
pub mod message;
pub mod delivery;
