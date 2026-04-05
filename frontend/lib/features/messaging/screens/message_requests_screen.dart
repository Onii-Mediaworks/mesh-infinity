// message_requests_screen.dart
//
// This file implements the MessageRequestsScreen — the inbox for inbound
// conversations from low-trust peers (§22.5.4).
//
// WHAT IS A MESSAGE REQUEST?
// --------------------------
// When a peer whose trust level is below Level 6 (i.e. they are in the
// "untrusted" range — Levels 0–5) sends the first message to us, that
// conversation does NOT appear directly in the main chat list.  Instead
// it lands here, in the "message requests" inbox.
//
// This design keeps the main chat list a trusted space.  You only see
// conversations there from people you have explicitly allowed.
//
// The user can:
//   - Accept → moves the conversation to the main chat list immediately.
//   - Decline → removes the request; the sender is NOT notified.
//   - Tap the tile → opens the sender's contact detail for more context.
//
// RATE LIMITS (enforced in Rust, not here):
//   - Max 5 pending requests per unique sender.
//   - Max 200 total pending requests in the queue.
//   - Requests older than 30 days are automatically expired.
//
// WHY StatefulWidget?
// -------------------
// We need to call loadRequests() after the first frame so the widget tree
// is fully mounted before we access Provider state.  StatefulWidget gives
// us initState() for that post-frame callback.

import 'package:flutter/material.dart';
// HapticFeedback.mediumImpact() fires the device's vibration motor for a
// tactile confirmation on Accept/Decline.  Requires this import.
import 'package:flutter/services.dart';
// Provider gives us context.watch / context.read to access shared state
// without passing it manually down the widget tree.
import 'package:provider/provider.dart';

// MessageRequest — the data model for a single pending inbound request.
// Defined in message_models.dart alongside MessageModel and ReactionModel.
import '../../../backend/models/message_models.dart';
// TrustLevel enum — maps the integer trust score (0–8) to a named level.
// We call TrustLevel.fromInt() to convert the raw integer stored in the
// MessageRequest into a typed enum value for display.
import '../../../backend/models/peer_models.dart';
// EmptyState — shared widget for zero-data screens.
// Shows a centred icon + title + body when a list has no items.
import '../../../core/widgets/empty_state.dart';
// TrustBadge — the compact coloured pill/circle that renders trust level.
// compact: true renders as a small 20×20 circle with the level number.
import '../../../features/contacts/widgets/trust_badge.dart';
// MessagingState — the ChangeNotifier that owns all messaging data.
// We use it for: requests list, loadRequests(), acceptRequest(), declineRequest().
import '../messaging_state.dart';
// ContactDetailScreen — shows full contact info for a given peer ID.
// Tapping a request tile opens this so the user can evaluate who is asking.
import '../../contacts/screens/contact_detail_screen.dart';

// ---------------------------------------------------------------------------
// MessageRequestsScreen — top-level screen widget (§22.5.4)
// ---------------------------------------------------------------------------

/// Screen that lists all pending inbound message requests.
///
/// Pushed onto the navigation stack from ConversationListScreen's requests
/// icon button in the AppBar (§22.5.1).
///
/// Layout (top to bottom):
///   1. AppBar with title "Message requests"
///   2. [_ExplanationBanner] — muted text describing what requests are
///   3. Either [EmptyState] (no requests) or a scrollable ListView of tiles
class MessageRequestsScreen extends StatefulWidget {
  const MessageRequestsScreen({super.key});

  @override
  State<MessageRequestsScreen> createState() => _MessageRequestsScreenState();
}

class _MessageRequestsScreenState extends State<MessageRequestsScreen> {
  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  @override
  void initState() {
    super.initState();

    // addPostFrameCallback ensures the widget tree is fully built before we
    // try to access Provider.  Calling context.read inside initState directly
    // can fail on some platforms because the InheritedWidget tree may not be
    // ready.  The callback fires after the first frame completes — safe to use.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      // context.read (not .watch) — we only want to trigger the load once,
      // not subscribe to rebuilds here.  The Expanded child uses .watch and
      // will rebuild automatically when loadRequests() calls notifyListeners().
      context.read<MessagingState>().loadRequests();
    });
  }

  // ---------------------------------------------------------------------------
  // Build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    // context.watch subscribes this build method to MessagingState changes.
    // Any time loadRequests / acceptRequest / declineRequest calls
    // notifyListeners(), Flutter will call build() again and the list
    // will reflect the updated requests.
    final messaging = context.watch<MessagingState>();

    return Scaffold(
      appBar: AppBar(title: const Text('Message requests')),
      body: Column(
        children: [
          // Static explanation banner at the top — always visible.
          _ExplanationBanner(),

          // Flexible content area — grows to fill remaining screen height.
          Expanded(
            child: RefreshIndicator(
              // Pull-to-refresh re-fetches from the backend.
              onRefresh: messaging.loadRequests,
              child: messaging.requests.isEmpty
                  // Zero-state: centred placeholder with icon and copy.
                  ? const EmptyState(
                      icon: Icons.mark_unread_chat_alt_outlined,
                      title: 'No pending requests',
                      body:
                          'Message requests from new contacts will appear here.',
                    )
                  // Non-empty: a separated list, one tile per request.
                  // ListView.separated draws a thin Divider between items
                  // without needing a separate widget for each gap.
                  : ListView.separated(
                      padding: const EdgeInsets.symmetric(vertical: 8),
                      // The `_` wildcard discards both parameters (index,
                      // BuildContext) since the divider is always the same.
                      separatorBuilder: (_, _) =>
                          const Divider(height: 1, indent: 72),
                      itemCount: messaging.requests.length,
                      itemBuilder: (ctx, i) {
                        // Capture the request at index i into a local so the
                        // closures below always reference the correct item
                        // even if the list changes between builds.
                        final req = messaging.requests[i];
                        return _MessageRequestTile(
                          request: req,
                          // _accept and _decline are instance methods on State
                          // so they can safely use `this.context` and `mounted`
                          // after the await completes.
                          onAccept: () => _accept(messaging, req),
                          onDecline: () => _decline(messaging, req),
                          // Open the sender's contact detail for evaluation.
                          // Uses ctx (from itemBuilder) rather than the State
                          // context because this is a synchronous push — no
                          // async gap, so using ctx is safe here.
                          onViewContact: () => Navigator.push(
                            ctx,
                            MaterialPageRoute(
                              builder: (_) =>
                                  ContactDetailScreen(peerId: req.peerId),
                            ),
                          ),
                        );
                      },
                    ),
            ),
          ),
        ],
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Accept / Decline actions
  // ---------------------------------------------------------------------------

  /// Accept the message request — moves the conversation to the main chat list.
  ///
  /// Uses `mounted` (the State's built-in flag) to guard the SnackBar show call
  /// after the await.  If the user navigates away while the request is in
  /// flight, the widget will have been disposed and `mounted` will be false —
  /// calling setState or ScaffoldMessenger on a disposed widget throws.
  Future<void> _accept(MessagingState messaging, MessageRequest req) async {
    final ok = await messaging.acceptRequest(req.id);

    // Guard: stop if the screen was disposed during the async wait.
    if (!mounted) return;

    if (ok) {
      // Haptic success confirmation — reassures the user the tap registered.
      HapticFeedback.mediumImpact();
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Conversation added to your chat list.')),
      );
    }
  }

  /// Decline the message request — removes it silently (sender not notified).
  ///
  /// Haptic feedback fires immediately (before the async call) so the UI
  /// feels responsive even if the backend takes a moment to confirm.
  ///
  /// A 5-second Undo SnackBar gives the user a safety net in case of
  /// accidental taps.  Undo re-fetches requests from the backend rather
  /// than trying to reconstruct local state — the backend is the source of
  /// truth for what is pending.
  Future<void> _decline(MessagingState messaging, MessageRequest req) async {
    // Immediate haptic — before awaiting the backend — so the decline
    // feels instant from the user's perspective.
    HapticFeedback.mediumImpact();

    final ok = await messaging.declineRequest(req.id);

    // Guard against disposed widget after the async gap.
    if (!mounted) return;

    if (ok) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: const Text('Request declined.'),
          action: SnackBarAction(
            label: 'Undo',
            // Undo re-fetches from the backend rather than reconstructing
            // a request client-side.
            onPressed: () => messaging.loadRequests(),
          ),
          // 5-second window gives the user time to see and act on the undo.
          duration: const Duration(seconds: 5),
        ),
      );
    }
  }
}

// ---------------------------------------------------------------------------
// _ExplanationBanner — static description above the request list (§22.5.4)
// ---------------------------------------------------------------------------

/// A muted full-width banner that explains what message requests are.
///
/// Rendered on [colorScheme.surfaceContainerHighest] to distinguish it
/// visually from the list below without using an obtrusive card or border.
///
/// This text is deliberately non-alarmist — new contacts are described
/// neutrally, not as threats (§22.2.1 framing guidelines).
class _ExplanationBanner extends StatelessWidget {
  // No constructor parameters — content is hardcoded spec text.
  @override
  Widget build(BuildContext context) {
    // Pull theme tokens rather than hardcoding colours so the banner adapts
    // to both light and dark mode automatically.
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;

    return Container(
      // surfaceContainerHighest is one step more prominent than the scaffold
      // background — creates a subtle visual group for the explanation text.
      color: colorScheme.surfaceContainerHighest,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
      child: Text(
        'These are messages from people you\'ve paired with but haven\'t '
        'added to your chat list yet. Accepting moves them to your main '
        'conversations. Declining doesn\'t notify the sender.',
        style: textTheme.bodySmall?.copyWith(
          // onSurfaceVariant is the M3 token for secondary text on surfaces.
          color: colorScheme.onSurfaceVariant,
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _MessageRequestTile — one row in the requests list (§22.5.4)
// ---------------------------------------------------------------------------

/// A ListTile that displays a single message request.
///
/// Layout:
///   Leading:   Circular avatar with the sender's initial letter.
///   Title:     Sender's display name.
///   Subtitle:  (3-line mode)
///                - First: message preview text, up to 2 lines.
///                - Second: compact TrustBadge + timestamp row.
///   Trailing:  Decline (outlined) + Accept (filled) button pair.
///   onTap:     Opens the sender's ContactDetailScreen for fuller context.
///
/// All callbacks ([onAccept], [onDecline], [onViewContact]) are provided
/// by the parent so this widget stays stateless and easy to test.
class _MessageRequestTile extends StatelessWidget {
  const _MessageRequestTile({
    required this.request,
    required this.onAccept,
    required this.onDecline,
    required this.onViewContact,
  });

  /// The pending request data to display.
  final MessageRequest request;

  /// Called when the user taps the Accept button.
  final VoidCallback onAccept;

  /// Called when the user taps the Decline button.
  final VoidCallback onDecline;

  /// Called when the user taps the tile body (opens contact detail).
  final VoidCallback onViewContact;

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;

    // Convert the raw integer trust score (0–8) stored in the model into the
    // typed TrustLevel enum.  fromInt clamps to the valid range so an
    // out-of-range backend value cannot crash the UI.
    final trustLevel = TrustLevel.fromInt(request.trustLevel);

    return ListTile(
      // Extra vertical padding gives the three-line subtitle breathing room.
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),

      // Sender avatar — single initial letter on a brand-tinted circle.
      // Falls back to '?' if the name is empty (e.g. anonymous peer).
      leading: CircleAvatar(
        radius: 24,
        backgroundColor: colorScheme.primaryContainer,
        child: Text(
          request.senderName.isNotEmpty
              ? request.senderName[0].toUpperCase()
              : '?',
          style: TextStyle(
            color: colorScheme.onPrimaryContainer,
            fontWeight: FontWeight.w600,
          ),
        ),
      ),

      // Sender's display name (may be a hex peer ID prefix if unnamed).
      title: Text(request.senderName, style: textTheme.titleSmall),

      // Three-line subtitle: message preview + trust context row.
      subtitle: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // First few words of the first incoming message — helps the user
          // decide whether to accept without opening the full thread.
          Text(
            request.messagePreview,
            style: textTheme.bodySmall?.copyWith(
              color: colorScheme.onSurfaceVariant,
            ),
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
          ),
          const SizedBox(height: 4),

          // Trust context row: compact badge + timestamp.
          Row(
            children: [
              // Compact TrustBadge shows the numeric trust level in a small
              // 20×20 circle so the user can quickly gauge relationship depth.
              TrustBadge(level: trustLevel, compact: true),
              const SizedBox(width: 6),
              // Timestamp from the backend (ISO string or relative time).
              Text(
                request.timestamp,
                style: textTheme.bodySmall?.copyWith(
                  color: colorScheme.onSurfaceVariant,
                  // Slightly smaller than bodySmall default to keep the row
                  // from crowding the trust badge.
                  fontSize: 11,
                ),
              ),
            ],
          ),
        ],
      ),

      // isThreeLine tells ListTile to reserve height for a multi-line subtitle.
      // Without this the third line would be clipped on some screen sizes.
      isThreeLine: true,

      // Trailing action buttons — Decline (outlined/secondary) on the left,
      // Accept (filled/primary) on the right.  This ordering follows M3
      // guidelines: destructive/dismissive action appears before confirmatory.
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          OutlinedButton(
            onPressed: onDecline,
            // Compact horizontal padding + fixed minimum height keeps the
            // buttons small enough to fit in the trailing area on all devices.
            style: OutlinedButton.styleFrom(
              padding: const EdgeInsets.symmetric(horizontal: 12),
              minimumSize: const Size(0, 36),
            ),
            child: const Text('Decline'),
          ),
          const SizedBox(width: 8),
          FilledButton(
            onPressed: onAccept,
            style: FilledButton.styleFrom(
              padding: const EdgeInsets.symmetric(horizontal: 12),
              minimumSize: const Size(0, 36),
            ),
            child: const Text('Accept'),
          ),
        ],
      ),

      // Tapping the tile body (not the buttons) opens the sender's full
      // contact profile so the user can make a more informed decision.
      onTap: onViewContact,
    );
  }
}
