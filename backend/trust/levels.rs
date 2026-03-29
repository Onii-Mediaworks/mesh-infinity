//! Trust Levels (§8.1)
//!
//! 8-level model with two tiers. The effective access level between two peers
//! is always min(alice_trusts_bob, bob_trusts_alice).

use serde::{Deserialize, Serialize};

/// Trust level (0-8).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TrustLevel {
    #[default]
    /// Level 0: Complete stranger. No endorsement, no prior contact.
    Unknown = 0,
    /// Level 1: Self-introduced via public profile, or initiated contact.
    Public = 1,
    /// Level 2: Endorsed by a Trusted-tier (Level 6+) peer.
    Vouched = 2,
    /// Level 3: Endorsed by a HighlyTrusted (Level 7) peer.
    Referenced = 3,
    /// Level 4: Endorsed by an InnerCircle (Level 8) peer.
    Ally = 4,
    /// Level 5: Directly paired. Chat-accessible. No private channel.
    Acquaintance = 5,
    /// Level 6: Entry trusted. Private channel established.
    Trusted = 6,
    /// Level 7: Top trusted below InnerCircle. Exit node eligible.
    HighlyTrusted = 7,
    /// Level 8: Maximum trust. Required for Friend-Disavowed votes.
    InnerCircle = 8,
}

impl TrustLevel {
    /// Numeric value.
    pub fn value(self) -> u8 {
        self as u8
    }

    /// From numeric value.
    pub fn from_value(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Unknown),
            1 => Some(Self::Public),
            2 => Some(Self::Vouched),
            3 => Some(Self::Referenced),
            4 => Some(Self::Ally),
            5 => Some(Self::Acquaintance),
            6 => Some(Self::Trusted),
            7 => Some(Self::HighlyTrusted),
            8 => Some(Self::InnerCircle),
            _ => None,
        }
    }

    /// Human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Public => "Public",
            Self::Vouched => "Vouched",
            Self::Referenced => "Referenced",
            Self::Ally => "Ally",
            Self::Acquaintance => "Acquaintance",
            Self::Trusted => "Trusted",
            Self::HighlyTrusted => "Highly Trusted",
            Self::InnerCircle => "Inner Circle",
        }
    }

    /// Short label for compact display.
    pub fn short_label(self) -> &'static str {
        match self {
            Self::Unknown => "?",
            Self::Public => "P",
            Self::Vouched => "V",
            Self::Referenced => "R",
            Self::Ally => "A",
            Self::Acquaintance => "Aq",
            Self::Trusted => "T",
            Self::HighlyTrusted => "HT",
            Self::InnerCircle => "IC",
        }
    }

    /// Whether this level is in the trusted tier (Level 6+).
    pub fn is_trusted_tier(self) -> bool {
        self.value() >= 6
    }

    /// Whether this level is in the untrusted tier (Level 0-5).
    pub fn is_untrusted_tier(self) -> bool {
        self.value() < 6
    }

    /// Compute the effective mutual trust level between two peers.
    /// Always the minimum of both directions.
    pub fn effective(a_trusts_b: TrustLevel, b_trusts_a: TrustLevel) -> TrustLevel {
        if a_trusts_b.value() <= b_trusts_a.value() {
            a_trusts_b
        } else {
            b_trusts_a
        }
    }

    /// Trust weight for routing path selection (§6.3).
    pub fn routing_weight(self) -> f32 {
        match self {
            Self::Unknown => 0.05,
            Self::Public => 0.10,
            Self::Vouched => 0.20,
            Self::Referenced => 0.35,
            Self::Ally => 0.55,
            Self::Acquaintance => 0.65,
            Self::Trusted => 0.75,
            Self::HighlyTrusted => 1.00,
            Self::InnerCircle => 1.30,
        }
    }

    /// Default endorsement starting point based on endorser level (§8.5.3).
    pub fn endorsement_default(endorser_level: TrustLevel) -> Option<TrustLevel> {
        match endorser_level {
            Self::Trusted => Some(Self::Vouched),
            Self::HighlyTrusted => Some(Self::Referenced),
            Self::InnerCircle => Some(Self::Ally),
            _ => None, // Endorsements from below Level 6 are ignored (§8.5.2)
        }
    }
}

impl std::fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.label(), self.value())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_level_ordering() {
        assert!(TrustLevel::Unknown < TrustLevel::InnerCircle);
        assert!(TrustLevel::Acquaintance < TrustLevel::Trusted);
        assert!(TrustLevel::Trusted < TrustLevel::HighlyTrusted);
    }

    #[test]
    fn test_effective_trust() {
        assert_eq!(
            TrustLevel::effective(TrustLevel::Trusted, TrustLevel::InnerCircle),
            TrustLevel::Trusted
        );
        assert_eq!(
            TrustLevel::effective(TrustLevel::Unknown, TrustLevel::InnerCircle),
            TrustLevel::Unknown
        );
    }

    #[test]
    fn test_trusted_tier() {
        assert!(!TrustLevel::Acquaintance.is_trusted_tier());
        assert!(TrustLevel::Trusted.is_trusted_tier());
        assert!(TrustLevel::InnerCircle.is_trusted_tier());
    }

    #[test]
    fn test_from_value_roundtrip() {
        for v in 0..=8 {
            let level = TrustLevel::from_value(v).unwrap();
            assert_eq!(level.value(), v);
        }
        assert!(TrustLevel::from_value(9).is_none());
    }

    #[test]
    fn test_routing_weights_monotonic() {
        let weights: Vec<f32> = (0..=8)
            .map(|v| TrustLevel::from_value(v).unwrap().routing_weight())
            .collect();
        for i in 1..weights.len() {
            assert!(weights[i] > weights[i - 1], "Weight at level {} should be > level {}", i, i-1);
        }
    }

    #[test]
    fn test_endorsement_defaults() {
        assert_eq!(TrustLevel::endorsement_default(TrustLevel::Trusted), Some(TrustLevel::Vouched));
        assert_eq!(TrustLevel::endorsement_default(TrustLevel::HighlyTrusted), Some(TrustLevel::Referenced));
        assert_eq!(TrustLevel::endorsement_default(TrustLevel::InnerCircle), Some(TrustLevel::Ally));
        assert_eq!(TrustLevel::endorsement_default(TrustLevel::Acquaintance), None);
    }

    #[test]
    fn test_serde_roundtrip() {
        let level = TrustLevel::Trusted;
        let json = serde_json::to_string(&level).unwrap();
        let recovered: TrustLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(level, recovered);
    }
}
