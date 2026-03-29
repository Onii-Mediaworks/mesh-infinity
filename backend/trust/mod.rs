//! Trust Model (§8.1, §8.2)
//!
//! 8-level trust model divided into two tiers:
//! - Levels 0-5: Untrusted tier (no private channel, no identity disclosure)
//! - Levels 6-8: Trusted tier (private channel, private profile shared)
//!
//! The trust state machine handles negative trust:
//! - Self-Disavowed: identity owner declares device compromised
//! - Friend-Disavowed: InnerCircle peers flag device as seized
//! - Compromised: permanent — both Self-Disavowed AND Friend-Disavowed threshold met

pub mod levels;
pub mod state_machine;
pub mod capabilities;
pub mod endorsement;
pub mod promotion;
pub mod acl;
pub mod governance;
