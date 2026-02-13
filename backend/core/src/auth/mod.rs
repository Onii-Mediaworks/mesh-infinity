// Authentication module
pub mod web_of_trust;
pub mod identity;
pub mod storage;

pub use web_of_trust::*;
pub use identity::{Identity as LocalIdentity, IdentityManager};
pub use storage::*;
