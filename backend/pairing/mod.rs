//! Pairing Flows (§8.3)
//!
//! # What is Pairing?
//!
//! Pairing is **identity verification** — not trust assignment. The
//! cryptographic core is the Sigma protocol handshake (§3.5), which
//! proves key possession. Trust assignment is a separate, optional
//! step that may happen during pairing, after pairing, or never.
//!
//! # Pairing Methods
//!
//! All methods achieve the same cryptographic result: mutual exchange
//! of public keys and a Sigma protocol proof of key possession. They
//! differ in the out-of-band channel used to convey initial key material.
//!
//! - **methods** — QR code, pairing code, link share, key export,
//!   BLE proximity, NFC, telephone subchannel, and service identity
//! - **handshake** — the Sigma protocol handshake that proves key
//!   possession after key exchange
//! - **contact** — the contact record created after a successful pairing

pub mod contact;
pub mod handshake;
pub mod methods;
