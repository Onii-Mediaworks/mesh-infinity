//! Messaging Service (§10.1)
//!
//! Chat messaging: rooms, messages, delivery status, message requests.
//! Integrates Double Ratchet sessions with four-layer encryption.

// Room management — conversation containers for 1:1 and group chats.
pub mod room;
// Message types, metadata, and content model for discrete messages.
pub mod message;
// Delivery status tracking, receipts, and store-and-forward integration.
pub mod delivery;
