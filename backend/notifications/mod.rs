//! Notifications (§14)
//!
//! # Four-Tier Notification Architecture
//!
//! | Tier | Mechanism | Third-Party Exposure |
//! |------|-----------|---------------------|
//! | 1 | Persistent mesh tunnel | None |
//! | 2 | UnifiedPush (ntfy/Gotify) | Push server sees timing |
//! | 3 | APNs/FCM silent push | Apple/Google see timing only |
//! | 4 | APNs/FCM rich push | Apple/Google see timing + content |
//!
//! Notifications are delivery HINTS only. Message content always
//! travels via four-layer mesh encryption, never via notification
//! infrastructure.
//!
//! # Priority Levels
//!
//! - Urgent: calls, pairing (no jitter)
//! - High: DMs from trusted peers (0-10s jitter)
//! - Normal: group messages, files (0-60s jitter, coalesced)
//! - Low: presence, map updates (always batched)
//!
//! # ThreatContext Suppression
//!
//! Elevated or Critical → Tiers 3 and 4 automatically suppressed.
//! Cannot be re-enabled while threat context is active.

use serde::{Deserialize, Serialize};
use crate::network::threat_context::ThreatContext;

// ---------------------------------------------------------------------------
// Notification Tier
// ---------------------------------------------------------------------------

/// Notification delivery tier (§14).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum NotificationTier {
    /// Persistent mesh tunnel. No third-party exposure.
    MeshTunnel = 1,
    /// UnifiedPush (ntfy/Gotify). Push server sees timing.
    UnifiedPush = 2,
    /// APNs/FCM silent push. Platform vendor sees timing.
    SilentPush = 3,
    /// APNs/FCM rich push. Platform vendor sees timing + content.
    RichPush = 4,
}

// ---------------------------------------------------------------------------
// Notification Priority
// ---------------------------------------------------------------------------

/// Notification priority level (§14).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum NotificationPriority {
    /// Background sync, presence updates. Always batched.
    Low = 0,
    /// Group messages, file offers. 0-60s jitter, coalesced.
    Normal = 1,
    /// DMs from trusted peers. 0-10s jitter.
    High = 2,
    /// Calls, pairing requests. Sent immediately.
    Urgent = 3,
}

impl NotificationPriority {
    /// Maximum jitter in seconds for this priority.
    pub fn max_jitter_secs(&self) -> u64 {
        match self {
            Self::Urgent => 0,
            Self::High => 10,
            Self::Normal => 60,
            Self::Low => 300, // Batched.
        }
    }
}

// ---------------------------------------------------------------------------
// Push Platform
// ---------------------------------------------------------------------------

/// Push notification platform.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PushPlatform {
    /// Apple Push Notification Service.
    APNs,
    /// Firebase Cloud Messaging.
    FCM,
    /// UnifiedPush (ntfy, Gotify, etc.).
    UnifiedPush,
}

// ---------------------------------------------------------------------------
// Push Relay Configuration
// ---------------------------------------------------------------------------

/// How to reach the push relay for Tier 3/4 notifications.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RelayAddress {
    /// Relay running as a mesh service (preferred).
    MeshService { service_id: [u8; 16] },
    /// Clearnet URL (fallback).
    ClearnetUrl { url: String },
    /// UnifiedPush endpoint.
    UnifiedPush { endpoint: String },
}

/// Configuration for push relay registration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PushRelayConfig {
    /// How to reach the relay.
    pub relay_address: RelayAddress,
    /// Device token (APNs token or FCM registration ID).
    pub device_token: Vec<u8>,
    /// Which platform this device uses.
    pub platform: PushPlatform,
}

// ---------------------------------------------------------------------------
// Tier 4 Content Level
// ---------------------------------------------------------------------------

/// How much content to include in rich push notifications (§14).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RichPushContentLevel {
    /// "New message" (no sender info).
    Minimal,
    /// Sender name + "New message".
    Standard,
    /// Sender name + message preview.
    Full,
}

// ---------------------------------------------------------------------------
// Notification Configuration
// ---------------------------------------------------------------------------

/// Per-device notification settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationConfig {
    /// Current notification tier.
    pub tier: NotificationTier,
    /// Push relay config (for Tier 2-4).
    pub push_relay: Option<PushRelayConfig>,
    /// Rich push content level (Tier 4 only).
    pub rich_content_level: RichPushContentLevel,
    /// Whether notifications are enabled at all.
    pub enabled: bool,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            tier: NotificationTier::MeshTunnel,
            push_relay: None,
            rich_content_level: RichPushContentLevel::Minimal,
            enabled: true,
        }
    }
}

impl NotificationConfig {
    /// Whether the current tier is suppressed by threat context.
    ///
    /// Elevated or Critical → Tiers 3 and 4 suppressed (§14.7, §14.8).
    pub fn is_suppressed_by_threat(&self, tc: ThreatContext) -> bool {
        !tc.allows_push_notifications() && self.tier >= NotificationTier::SilentPush
    }

    /// Get the effective tier considering threat context suppression.
    pub fn effective_tier(&self, tc: ThreatContext) -> NotificationTier {
        if self.is_suppressed_by_threat(tc) {
            // Fall back to Tier 2 (UnifiedPush) ONLY if the configured relay is
            // actually UnifiedPush.  MeshService and ClearnetUrl relays are
            // Tier 3/4 themselves and are also suppressed under elevated threat
            // context, so they must fall all the way back to Tier 1 (MeshTunnel).
            let relay_is_unified_push = matches!(
                self.push_relay.as_ref().map(|r| &r.relay_address),
                Some(RelayAddress::UnifiedPush { .. })
            );
            if relay_is_unified_push {
                NotificationTier::UnifiedPush
            } else {
                NotificationTier::MeshTunnel
            }
        } else {
            self.tier
        }
    }
}

// ---------------------------------------------------------------------------
// Notification Event
// ---------------------------------------------------------------------------

/// A notification event to be dispatched.
///
/// Created by the messaging/call/file layers when something
/// needs to notify the user. The dispatcher applies jitter,
/// coalescing, and tier selection.
#[derive(Clone, Debug)]
pub struct NotificationEvent {
    /// What kind of notification this is.
    pub priority: NotificationPriority,
    /// A short title (e.g., "New message from Alice").
    pub title: String,
    /// The body/preview text (used in Tier 4 rich push).
    pub body: Option<String>,
    /// Sender peer ID (for sender name resolution).
    pub sender_id: Option<[u8; 32]>,
    /// Conversation/room ID (for navigation).
    pub conversation_id: Option<[u8; 32]>,
    /// When the event was created.
    pub created_at: u64,
}

// ---------------------------------------------------------------------------
// Notification Dispatcher
// ---------------------------------------------------------------------------

/// Dispatches notifications through the appropriate tier.
///
/// Applies jitter, coalescing, and threat context suppression.
/// Multiple events within the jitter window are coalesced into
/// a single push notification.
pub struct NotificationDispatcher {
    /// Current notification configuration.
    pub config: NotificationConfig,

    /// Pending events waiting for jitter window to close.
    /// Key: conversation_id (or [0;32] for non-conversation events).
    /// Value: (events, earliest_dispatch_time).
    pending: std::collections::HashMap<[u8; 32], (Vec<NotificationEvent>, u64)>,

    /// Current threat context — governs Tier 3/4 suppression.
    pub threat_context: ThreatContext,
}

impl NotificationDispatcher {
    /// Create a new dispatcher.
    pub fn new(config: NotificationConfig) -> Self {
        Self {
            config,
            pending: std::collections::HashMap::new(),
            threat_context: ThreatContext::Normal,
        }
    }

    /// Update the threat context. Suppresses Tier 3/4 at Elevated or Critical.
    pub fn set_threat_context(&mut self, tc: ThreatContext) {
        self.threat_context = tc;
    }

    /// Submit a notification event.
    ///
    /// The event is buffered until its jitter window closes.
    /// Returns the time when `dispatch_ready()` should be called.
    pub fn submit(&mut self, event: NotificationEvent) -> u64 {
        if !self.config.enabled {
            return u64::MAX;
        }

        let jitter = event.priority.max_jitter_secs();
        let dispatch_at = event.created_at + jitter;

        let conv_id = event.conversation_id.unwrap_or([0u8; 32]);

        let entry = self.pending.entry(conv_id).or_insert_with(|| {
            (Vec::new(), dispatch_at)
        });

        // Use the earliest dispatch time among events in this group.
        if dispatch_at < entry.1 {
            entry.1 = dispatch_at;
        }

        entry.0.push(event);
        entry.1
    }

    /// Collect events that are ready to dispatch.
    ///
    /// Returns coalesced notification events grouped by conversation.
    /// Each group becomes a single push notification.
    pub fn dispatch_ready(&mut self, now: u64) -> Vec<CoalescedNotification> {
        let mut ready = Vec::new();

        let ready_keys: Vec<[u8; 32]> = self
            .pending
            .iter()
            .filter(|(_, (_, dispatch_at))| now >= *dispatch_at)
            .map(|(k, _)| *k)
            .collect();

        for key in ready_keys {
            if let Some((events, _)) = self.pending.remove(&key) {
                let effective_tier = self.config.effective_tier(self.threat_context);

                // Determine the highest priority among coalesced events.
                let max_priority = events
                    .iter()
                    .map(|e| e.priority)
                    .max()
                    .unwrap_or(NotificationPriority::Low);

                // Build the coalesced notification.
                let title = if events.len() == 1 {
                    events[0].title.clone()
                } else {
                    format!("{} new messages", events.len())
                };

                let body = match self.config.rich_content_level {
                    RichPushContentLevel::Minimal => None,
                    RichPushContentLevel::Standard => {
                        events.last().map(|e| e.title.clone())
                    }
                    RichPushContentLevel::Full => {
                        events.last().and_then(|e| e.body.clone())
                    }
                };

                ready.push(CoalescedNotification {
                    tier: effective_tier,
                    priority: max_priority,
                    title,
                    body,
                    conversation_id: if key == [0u8; 32] { None } else { Some(key) },
                    event_count: events.len(),
                });
            }
        }

        ready
    }

    /// Number of pending events across all conversations.
    pub fn pending_count(&self) -> usize {
        self.pending.values().map(|(events, _)| events.len()).sum()
    }
}

/// A coalesced notification ready for delivery.
#[derive(Clone, Debug)]
pub struct CoalescedNotification {
    /// Which tier to deliver through.
    pub tier: NotificationTier,
    /// Highest priority among coalesced events.
    pub priority: NotificationPriority,
    /// Notification title.
    pub title: String,
    /// Notification body (Tier 4 only, depending on content level).
    pub body: Option<String>,
    /// Which conversation this notification is about.
    pub conversation_id: Option<[u8; 32]>,
    /// Number of events coalesced into this notification.
    pub event_count: usize,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = NotificationConfig::default();
        assert_eq!(config.tier, NotificationTier::MeshTunnel);
        assert!(config.enabled);
    }

    #[test]
    fn test_priority_jitter() {
        assert_eq!(NotificationPriority::Urgent.max_jitter_secs(), 0);
        assert_eq!(NotificationPriority::High.max_jitter_secs(), 10);
        assert_eq!(NotificationPriority::Normal.max_jitter_secs(), 60);
    }

    #[test]
    fn test_threat_suppression() {
        let mut config = NotificationConfig::default();
        config.tier = NotificationTier::RichPush;

        // Not suppressed in Normal context.
        assert!(!config.is_suppressed_by_threat(ThreatContext::Normal));

        // Suppressed in Elevated context (§14.7).
        assert!(config.is_suppressed_by_threat(ThreatContext::Elevated));
        assert_eq!(
            config.effective_tier(ThreatContext::Elevated),
            NotificationTier::MeshTunnel
        );

        // Also suppressed in Critical.
        assert!(config.is_suppressed_by_threat(ThreatContext::Critical));
        assert_eq!(
            config.effective_tier(ThreatContext::Critical),
            NotificationTier::MeshTunnel
        );
    }

    #[test]
    fn test_threat_suppression_with_unified_push() {
        let mut config = NotificationConfig::default();
        config.tier = NotificationTier::SilentPush;
        config.push_relay = Some(PushRelayConfig {
            relay_address: RelayAddress::UnifiedPush {
                endpoint: "https://ntfy.example.com/topic".to_string(),
            },
            device_token: vec![0x01; 32],
            platform: PushPlatform::UnifiedPush,
        });

        // Falls back to UnifiedPush (Tier 2) when Elevated.
        assert_eq!(
            config.effective_tier(ThreatContext::Elevated),
            NotificationTier::UnifiedPush
        );
        // Also falls back when Critical.
        assert_eq!(
            config.effective_tier(ThreatContext::Critical),
            NotificationTier::UnifiedPush
        );
    }

    #[test]
    fn test_tier_ordering() {
        assert!(NotificationTier::MeshTunnel < NotificationTier::RichPush);
        assert!(NotificationTier::SilentPush < NotificationTier::RichPush);
    }

    #[test]
    fn test_dispatcher_submit_and_dispatch() {
        let config = NotificationConfig::default();
        let mut dispatcher = NotificationDispatcher::new(config);

        let event = NotificationEvent {
            priority: NotificationPriority::Urgent,
            title: "Incoming call".to_string(),
            body: None,
            sender_id: Some([0x01; 32]),
            conversation_id: Some([0xAA; 32]),
            created_at: 1000,
        };

        // Submit an urgent event (0 jitter).
        let dispatch_at = dispatcher.submit(event);
        assert_eq!(dispatch_at, 1000); // Immediate.

        // Dispatch now.
        let ready = dispatcher.dispatch_ready(1000);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].priority, NotificationPriority::Urgent);
        assert_eq!(ready[0].event_count, 1);
    }

    #[test]
    fn test_dispatcher_coalescing() {
        let config = NotificationConfig::default();
        let mut dispatcher = NotificationDispatcher::new(config);
        let conv = [0xBB; 32];

        // Submit two Normal-priority events in the same conversation.
        for i in 0..2 {
            dispatcher.submit(NotificationEvent {
                priority: NotificationPriority::Normal,
                title: format!("Message {}", i),
                body: Some(format!("Body {}", i)),
                sender_id: None,
                conversation_id: Some(conv),
                created_at: 1000,
            });
        }

        // After jitter window (60s for Normal).
        let ready = dispatcher.dispatch_ready(1060);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].event_count, 2);
        assert!(ready[0].title.contains("2 new messages"));
    }

    #[test]
    fn test_dispatcher_jitter_not_ready() {
        let config = NotificationConfig::default();
        let mut dispatcher = NotificationDispatcher::new(config);

        dispatcher.submit(NotificationEvent {
            priority: NotificationPriority::Normal, // 60s jitter.
            title: "msg".to_string(),
            body: None,
            sender_id: None,
            conversation_id: Some([0xCC; 32]),
            created_at: 1000,
        });

        // Too early — jitter window hasn't closed.
        let ready = dispatcher.dispatch_ready(1030);
        assert!(ready.is_empty());
        assert_eq!(dispatcher.pending_count(), 1);
    }

    #[test]
    fn test_dispatcher_threat_suppression() {
        let mut config = NotificationConfig::default();
        config.tier = NotificationTier::RichPush;
        let mut dispatcher = NotificationDispatcher::new(config);
        dispatcher.set_threat_context(ThreatContext::Critical);

        dispatcher.submit(NotificationEvent {
            priority: NotificationPriority::Urgent,
            title: "test".to_string(),
            body: None,
            sender_id: None,
            conversation_id: None,
            created_at: 1000,
        });

        let ready = dispatcher.dispatch_ready(1000);
        // Should be suppressed from RichPush down to MeshTunnel.
        assert_eq!(ready[0].tier, NotificationTier::MeshTunnel);
    }

    /// A MeshService relay is Tier 3/4 and must NOT trigger UnifiedPush fallback
    /// under threat suppression — it should fall all the way back to MeshTunnel.
    #[test]
    fn test_threat_suppression_mesh_service_relay_falls_to_tier1() {
        let mut config = NotificationConfig::default();
        config.tier = NotificationTier::SilentPush;
        config.push_relay = Some(PushRelayConfig {
            relay_address: RelayAddress::MeshService { service_id: [0x42; 16] },
            device_token: vec![0xAB; 32],
            platform: PushPlatform::FCM,
        });

        // MeshService is not UnifiedPush — must fall back to MeshTunnel, not UnifiedPush.
        assert_eq!(
            config.effective_tier(ThreatContext::Elevated),
            NotificationTier::MeshTunnel,
            "MeshService relay must fall back to Tier 1, not Tier 2"
        );
        assert_eq!(
            config.effective_tier(ThreatContext::Critical),
            NotificationTier::MeshTunnel,
        );
    }

    /// A ClearnetUrl relay must also fall back to MeshTunnel under threat suppression.
    #[test]
    fn test_threat_suppression_clearnet_url_relay_falls_to_tier1() {
        let mut config = NotificationConfig::default();
        config.tier = NotificationTier::SilentPush;
        config.push_relay = Some(PushRelayConfig {
            relay_address: RelayAddress::ClearnetUrl { url: "https://relay.example.com".into() },
            device_token: vec![],
            platform: PushPlatform::APNs,
        });

        assert_eq!(
            config.effective_tier(ThreatContext::Elevated),
            NotificationTier::MeshTunnel,
            "ClearnetUrl relay must fall back to Tier 1, not Tier 2"
        );
    }
}
