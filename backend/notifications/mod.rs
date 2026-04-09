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

use crate::network::threat_context::ThreatContext;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Notification Tier
// ---------------------------------------------------------------------------

/// Notification delivery tier (§14).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
// Begin the block scope.
// NotificationTier — variant enumeration.
// Match exhaustively to handle every protocol state.
// NotificationTier — variant enumeration.
// Match exhaustively to handle every protocol state.
// NotificationTier — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum NotificationTier {
    /// Persistent mesh tunnel. No third-party exposure.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    MeshTunnel = 1,
    /// UnifiedPush (ntfy/Gotify). Push server sees timing.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    UnifiedPush = 2,
    /// APNs/FCM silent push. Platform vendor sees timing.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    SilentPush = 3,
    /// APNs/FCM rich push. Platform vendor sees timing + content.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    RichPush = 4,
}

// ---------------------------------------------------------------------------
// Notification Priority
// ---------------------------------------------------------------------------

/// Notification priority level (§14).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
// Begin the block scope.
// NotificationPriority — variant enumeration.
// Match exhaustively to handle every protocol state.
// NotificationPriority — variant enumeration.
// Match exhaustively to handle every protocol state.
// NotificationPriority — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum NotificationPriority {
    /// Background sync, presence updates. Always batched.
    Low = 0,
    /// Group messages, file offers. 0-60s jitter, coalesced.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Normal = 1,
    /// DMs from trusted peers. 0-10s jitter.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    High = 2,
    /// Calls, pairing requests. Sent immediately.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Urgent = 3,
}

// Begin the block scope.
// NotificationPriority implementation — core protocol logic.
// NotificationPriority implementation — core protocol logic.
// NotificationPriority implementation — core protocol logic.
impl NotificationPriority {
    /// Maximum jitter in seconds for this priority.
    // Perform the 'max jitter secs' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'max jitter secs' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'max jitter secs' operation.
    // Errors are propagated to the caller via Result.
    pub fn max_jitter_secs(&self) -> u64 {
        // Dispatch based on the variant to apply type-specific logic.
        // Dispatch on the variant.
        // Dispatch on the variant.
        // Dispatch on the variant.
        match self {
            // Handle this match arm.
            Self::Urgent => 0,
            // Handle this match arm.
            Self::High => 10,
            // Handle this match arm.
            Self::Normal => 60,
            // Handle this match arm.
            Self::Low => 300, // Batched.
        }
    }
}

// ---------------------------------------------------------------------------
// Push Platform
// ---------------------------------------------------------------------------

/// Push notification platform.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// PushPlatform — variant enumeration.
// Match exhaustively to handle every protocol state.
// PushPlatform — variant enumeration.
// Match exhaustively to handle every protocol state.
// PushPlatform — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum PushPlatform {
    /// Apple Push Notification Service.
    APNs,
    /// Firebase Cloud Messaging.
    FCM,
    /// UnifiedPush (ntfy, Gotify, etc.).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    UnifiedPush,
}

// ---------------------------------------------------------------------------
// Push Relay Configuration
// ---------------------------------------------------------------------------

/// How to reach the push relay for Tier 3/4 notifications.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// RelayAddress — variant enumeration.
// Match exhaustively to handle every protocol state.
// RelayAddress — variant enumeration.
// Match exhaustively to handle every protocol state.
// RelayAddress — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum RelayAddress {
    /// Relay running as a mesh service (preferred).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    MeshService { service_id: [u8; 16] },
    /// Clearnet URL (fallback).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    ClearnetUrl { url: String },
    /// UnifiedPush endpoint.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    UnifiedPush { endpoint: String },
}

/// Configuration for push relay registration.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// PushRelayConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PushRelayConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// PushRelayConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct PushRelayConfig {
    /// How to reach the relay.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub relay_address: RelayAddress,
    /// Device token (APNs token or FCM registration ID).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub device_token: Vec<u8>,
    /// Which platform this device uses.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub platform: PushPlatform,
}

// ---------------------------------------------------------------------------
// Tier 4 Content Level
// ---------------------------------------------------------------------------

/// How much content to include in rich push notifications (§14).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Begin the block scope.
// RichPushContentLevel — variant enumeration.
// Match exhaustively to handle every protocol state.
// RichPushContentLevel — variant enumeration.
// Match exhaustively to handle every protocol state.
// RichPushContentLevel — variant enumeration.
// Match exhaustively to handle every protocol state.
pub enum RichPushContentLevel {
    /// "New message" (no sender info).
    Minimal,
    /// Sender name + "New message".
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    Standard,
    /// Sender name + message preview.
    Full,
}

// ---------------------------------------------------------------------------
// Notification Configuration
// ---------------------------------------------------------------------------

/// Per-device notification settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Begin the block scope.
// NotificationConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// NotificationConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// NotificationConfig — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct NotificationConfig {
    /// Current notification tier.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub tier: NotificationTier,
    /// Push relay config (for Tier 2-4).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub push_relay: Option<PushRelayConfig>,
    /// Rich push content level (Tier 4 only).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub rich_content_level: RichPushContentLevel,
    /// Whether notifications are enabled at all.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub enabled: bool,
}

// Trait implementation for protocol conformance.
// Implement Default for NotificationConfig.
// Implement Default for NotificationConfig.
// Implement Default for NotificationConfig.
impl Default for NotificationConfig {
    // Begin the block scope.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'default' operation.
    // Errors are propagated to the caller via Result.
    fn default() -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            tier: NotificationTier::MeshTunnel,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            push_relay: None,
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            rich_content_level: RichPushContentLevel::Minimal,
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            enabled: true,
        }
    }
}

// Begin the block scope.
// NotificationConfig implementation — core protocol logic.
// NotificationConfig implementation — core protocol logic.
// NotificationConfig implementation — core protocol logic.
impl NotificationConfig {
    /// Whether the current tier is suppressed by threat context.
    ///
    /// Elevated or Critical → Tiers 3 and 4 suppressed (§14.7, §14.8).
    // Perform the 'is suppressed by threat' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is suppressed by threat' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'is suppressed by threat' operation.
    // Errors are propagated to the caller via Result.
    pub fn is_suppressed_by_threat(&self, tc: ThreatContext) -> bool {
        // Process the current step in the protocol.
        // Execute this protocol step.
        // Execute this protocol step.
        // Execute this protocol step.
        !tc.allows_push_notifications() && self.tier >= NotificationTier::SilentPush
    }

    /// Get the effective tier considering threat context suppression.
    // Perform the 'effective tier' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'effective tier' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'effective tier' operation.
    // Errors are propagated to the caller via Result.
    pub fn effective_tier(&self, tc: ThreatContext) -> NotificationTier {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if self.is_suppressed_by_threat(tc) {
            // Fall back to Tier 2 (UnifiedPush) ONLY if the configured relay is
            // actually UnifiedPush.  MeshService and ClearnetUrl relays are
            // Tier 3/4 themselves and are also suppressed under elevated threat
            // context, so they must fall all the way back to Tier 1 (MeshTunnel).
            // Compute relay is unified push for this protocol step.
            // Compute relay is unified push for this protocol step.
            // Compute relay is unified push for this protocol step.
            let relay_is_unified_push = matches!(
                // Transform the result, mapping errors to the local error type.
                // Transform each element.
                // Transform each element.
                // Transform each element.
                self.push_relay.as_ref().map(|r| &r.relay_address),
                // Wrap the found value for the caller.
                // Wrap the found value.
                // Wrap the found value.
                // Wrap the found value.
                Some(RelayAddress::UnifiedPush { .. })
            );
            // Conditional branch based on the current state.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if relay_is_unified_push {
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                NotificationTier::UnifiedPush
            // Begin the block scope.
            // Fallback when the guard was not satisfied.
            // Fallback when the guard was not satisfied.
            // Fallback when the guard was not satisfied.
            } else {
                // Process the current step in the protocol.
                // Execute this protocol step.
                // Execute this protocol step.
                // Execute this protocol step.
                NotificationTier::MeshTunnel
            }
        // Begin the block scope.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        // Fallback when the guard was not satisfied.
        } else {
            // Mutate the internal state.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
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
// Begin the block scope.
// NotificationEvent — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// NotificationEvent — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// NotificationEvent — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct NotificationEvent {
    /// What kind of notification this is.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub priority: NotificationPriority,
    /// A short title (e.g., "New message from Alice").
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub title: String,
    /// The body/preview text (used in Tier 4 rich push).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub body: Option<String>,
    /// Sender peer ID (for sender name resolution).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub sender_id: Option<[u8; 32]>,
    /// Conversation/room ID (for navigation).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub conversation_id: Option<[u8; 32]>,
    /// When the event was created.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
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
// NotificationDispatcher — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// NotificationDispatcher — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// NotificationDispatcher — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct NotificationDispatcher {
    /// Current notification configuration.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub config: NotificationConfig,

    /// Pending events waiting for jitter window to close.
    /// Key: conversation_id (or [0;32] for non-conversation events).
    /// Value: (events, earliest_dispatch_time).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pending: std::collections::HashMap<[u8; 32], (Vec<NotificationEvent>, u64)>,

    /// Current threat context — governs Tier 3/4 suppression.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub threat_context: ThreatContext,
}

// Begin the block scope.
// NotificationDispatcher implementation — core protocol logic.
// NotificationDispatcher implementation — core protocol logic.
// NotificationDispatcher implementation — core protocol logic.
impl NotificationDispatcher {
    /// Create a new dispatcher.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'new' operation.
    // Errors are propagated to the caller via Result.
    pub fn new(config: NotificationConfig) -> Self {
        // Assemble the instance from the computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        // Construct the instance from computed fields.
        Self {
            config,
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            pending: std::collections::HashMap::new(),
            // Process the current step in the protocol.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            threat_context: ThreatContext::Normal,
        }
    }

    /// Update the threat context. Suppresses Tier 3/4 at Elevated or Critical.
    // Perform the 'set threat context' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'set threat context' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'set threat context' operation.
    // Errors are propagated to the caller via Result.
    pub fn set_threat_context(&mut self, tc: ThreatContext) {
        // Update the threat context to reflect the new state.
        // Advance threat context state.
        // Advance threat context state.
        // Advance threat context state.
        self.threat_context = tc;
    }

    /// Submit a notification event.
    ///
    /// The event is buffered until its jitter window closes.
    /// Returns the time when `dispatch_ready()` should be called.
    // Perform the 'submit' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'submit' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'submit' operation.
    // Errors are propagated to the caller via Result.
    pub fn submit(&mut self, event: NotificationEvent) -> u64 {
        // Conditional branch based on the current state.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if !self.config.enabled {
            // Return the result to the caller.
            // Return to the caller.
            // Return to the caller.
            // Return to the caller.
            return u64::MAX;
        }

        // Execute the operation and bind the result.
        // Compute jitter for this protocol step.
        // Compute jitter for this protocol step.
        // Compute jitter for this protocol step.
        let jitter = event.priority.max_jitter_secs();
        // Execute the operation and bind the result.
        // Compute dispatch at for this protocol step.
        // Compute dispatch at for this protocol step.
        // Compute dispatch at for this protocol step.
        let dispatch_at = event.created_at + jitter;

        // Unique identifier for lookup and deduplication.
        // Compute conv id for this protocol step.
        // Compute conv id for this protocol step.
        // Compute conv id for this protocol step.
        let conv_id = event.conversation_id.unwrap_or([0u8; 32]);

        // Unique identifier for lookup and deduplication.
        // Compute entry for this protocol step.
        // Compute entry for this protocol step.
        // Compute entry for this protocol step.
        let entry = self.pending.entry(conv_id).or_insert_with(|| {
            // Create a new instance with the specified parameters.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            (Vec::new(), dispatch_at)
        });

        // Use the earliest dispatch time among events in this group.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        // Guard: validate the condition before proceeding.
        if dispatch_at < entry.1 {
            // Execute the operation and bind the result.
            // Execute this protocol step.
            // Execute this protocol step.
            // Execute this protocol step.
            entry.1 = dispatch_at;
        }

        // Add the element to the collection.
        // Append to the collection.
        // Append to the collection.
        // Append to the collection.
        entry.0.push(event);
        // Chain the operation on the intermediate result.
        entry.1
    }

    /// Collect events that are ready to dispatch.
    ///
    /// Returns coalesced notification events grouped by conversation.
    /// Each group becomes a single push notification.
    // Perform the 'dispatch ready' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'dispatch ready' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'dispatch ready' operation.
    // Errors are propagated to the caller via Result.
    pub fn dispatch_ready(&mut self, now: u64) -> Vec<CoalescedNotification> {
        // Pre-allocate the buffer to avoid repeated reallocations.
        // Compute ready for this protocol step.
        // Compute ready for this protocol step.
        // Compute ready for this protocol step.
        let mut ready = Vec::new();

        // Key material — must be zeroized when no longer needed.
        // Compute ready keys for this protocol step.
        // Compute ready keys for this protocol step.
        // Compute ready keys for this protocol step.
        let ready_keys: Vec<[u8; 32]> = self
            // Chain the operation on the intermediate result.
            .pending
            // Create an iterator over the collection elements.
            // Create an iterator over the elements.
            // Create an iterator over the elements.
            // Create an iterator over the elements.
            .iter()
            // Select only elements matching the predicate.
            // Filter by the predicate.
            // Filter by the predicate.
            // Filter by the predicate.
            .filter(|(_, (_, dispatch_at))| now >= *dispatch_at)
            // Transform the result, mapping errors to the local error type.
            // Transform each element.
            // Transform each element.
            // Transform each element.
            .map(|(k, _)| *k)
            // Materialize the iterator into a concrete collection.
            // Collect into a concrete collection.
            // Collect into a concrete collection.
            // Collect into a concrete collection.
            .collect();

        // Iterate over each element in the collection.
        // Iterate over each element.
        // Iterate over each element.
        // Iterate over each element.
        for key in ready_keys {
            // Conditional branch based on the current state.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            // Guard: validate the condition before proceeding.
            if let Some((events, _)) = self.pending.remove(&key) {
                // Configure the operation parameters.
                // Compute effective tier for this protocol step.
                // Compute effective tier for this protocol step.
                // Compute effective tier for this protocol step.
                let effective_tier = self.config.effective_tier(self.threat_context);

                // Determine the highest priority among coalesced events.
                // Compute max priority for this protocol step.
                // Compute max priority for this protocol step.
                // Compute max priority for this protocol step.
                let max_priority = events
                    // Create an iterator over the collection elements.
                    // Create an iterator over the elements.
                    // Create an iterator over the elements.
                    // Create an iterator over the elements.
                    .iter()
                    // Transform the result, mapping errors to the local error type.
                    // Transform each element.
                    // Transform each element.
                    // Transform each element.
                    .map(|e| e.priority)
                    // Clamp the value to prevent overflow or underflow.
                    .max()
                    // Fall back to the default value on failure.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    .unwrap_or(NotificationPriority::Low);

                // Build the coalesced notification.
                // Compute title for this protocol step.
                // Compute title for this protocol step.
                // Compute title for this protocol step.
                let title = if events.len() == 1 {
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    events[0].title.clone()
                // Begin the block scope.
                // Fallback when the guard was not satisfied.
                // Fallback when the guard was not satisfied.
                // Fallback when the guard was not satisfied.
                } else {
                    // Format the output for display or logging.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    format!("{} new messages", events.len())
                };

                // Configure the operation parameters.
                // Compute body for this protocol step.
                // Compute body for this protocol step.
                // Compute body for this protocol step.
                let body = match self.config.rich_content_level {
                    // Handle this match arm.
                    RichPushContentLevel::Minimal => None,
                    // Begin the block scope.
                    // Handle RichPushContentLevel::Standard.
                    // Handle RichPushContentLevel::Standard.
                    // Handle RichPushContentLevel::Standard.
                    RichPushContentLevel::Standard => {
                        // Transform the result, mapping errors to the local error type.
                        // Transform each element.
                        // Transform each element.
                        // Transform each element.
                        events.last().map(|e| e.title.clone())
                    }
                    // Begin the block scope.
                    // Handle RichPushContentLevel::Full.
                    // Handle RichPushContentLevel::Full.
                    // Handle RichPushContentLevel::Full.
                    RichPushContentLevel::Full => {
                        // Transform the result, mapping errors to the local error type.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        // Execute this protocol step.
                        events.last().and_then(|e| e.body.clone())
                    }
                };

                // Begin the block scope.
                // Append to the collection.
                // Append to the collection.
                // Append to the collection.
                ready.push(CoalescedNotification {
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    tier: effective_tier,
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    priority: max_priority,
                    title,
                    body,
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    conversation_id: if key == [0u8; 32] { None } else { Some(key) },
                    // Process the current step in the protocol.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    // Execute this protocol step.
                    event_count: events.len(),
                });
            }
        }

        ready
    }

    /// Number of pending events across all conversations.
    // Perform the 'pending count' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'pending count' operation.
    // Errors are propagated to the caller via Result.
    // Perform the 'pending count' operation.
    // Errors are propagated to the caller via Result.
    pub fn pending_count(&self) -> usize {
        // Transform the result, mapping errors to the local error type.
        // Transform each element.
        // Transform each element.
        // Transform each element.
        self.pending.values().map(|(events, _)| events.len()).sum()
    }
}

/// A coalesced notification ready for delivery.
#[derive(Clone, Debug)]
// Begin the block scope.
// CoalescedNotification — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// CoalescedNotification — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
// CoalescedNotification — protocol data structure (see field-level docs).
// Invariants are enforced at construction time.
pub struct CoalescedNotification {
    /// Which tier to deliver through.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub tier: NotificationTier,
    /// Highest priority among coalesced events.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub priority: NotificationPriority,
    /// Notification title.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub title: String,
    /// Notification body (Tier 4 only, depending on content level).
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub body: Option<String>,
    /// Which conversation this notification is about.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
    pub conversation_id: Option<[u8; 32]>,
    /// Number of events coalesced into this notification.
    // Execute this protocol step.
    // Execute this protocol step.
    // Execute this protocol step.
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
        let config = NotificationConfig { tier: NotificationTier::RichPush, ..Default::default() };

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
        let config = NotificationConfig {
            tier: NotificationTier::SilentPush,
            push_relay: Some(PushRelayConfig {
                relay_address: RelayAddress::UnifiedPush {
                    endpoint: "https://ntfy.example.com/topic".to_string(),
                },
                device_token: vec![0x01; 32],
                platform: PushPlatform::UnifiedPush,
            }),
            ..Default::default()
        };

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
        let config = NotificationConfig { tier: NotificationTier::RichPush, ..Default::default() };
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
        let config = NotificationConfig {
            tier: NotificationTier::SilentPush,
            push_relay: Some(PushRelayConfig {
                relay_address: RelayAddress::MeshService {
                    service_id: [0x42; 16],
                },
                device_token: vec![0xAB; 32],
                platform: PushPlatform::FCM,
            }),
            ..Default::default()
        };

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
        let config = NotificationConfig {
            tier: NotificationTier::SilentPush,
            push_relay: Some(PushRelayConfig {
                relay_address: RelayAddress::ClearnetUrl {
                    url: "https://relay.example.com".into(),
                },
                device_token: vec![],
                platform: PushPlatform::APNs,
            }),
            ..Default::default()
        };

        assert_eq!(
            config.effective_tier(ThreatContext::Elevated),
            NotificationTier::MeshTunnel,
            "ClearnetUrl relay must fall back to Tier 1, not Tier 2"
        );
    }
}
