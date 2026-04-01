// contact_detail_screen.dart
//
// This file implements ContactDetailScreen — the full-detail view for a
// single contact (§22.8.2).
//
// WHAT DOES THIS SCREEN SHOW?
// ---------------------------
// When the user taps a contact in the contacts list, or navigates from a
// message thread, they land here.  It shows:
//   - A hero card: large avatar, display name, trust badge, online status.
//   - A quick-action row: Chat, Files, Call buttons.
//   - An info card: the contact's peer ID (copyable monospace text).
//   - A trust card: current trust level with a Set Trust Level button.
//   - A more-actions card: Voice call, Video call, Open chat, Send file,
//     and a destructive "Remove Contact" option.
//
// NAVIGATION
// ----------
// This screen is reached from:
//   - AllContactsScreen / OnlineScreen (tapping a contact tile)
//   - PeerListScreen (tapping a peer)
//   - MessageRequestsScreen ("View contact" action)
//   - ConversationSearchScreen result tiles (future)
//   - ProfilePreviewScreen ("View contact" action)
//   - AppShell desktop detail pane (shell.selectedPeerId != null)
//
// SPEC REFERENCE: §22.8.2

import 'package:flutter/material.dart';
// Clipboard.setData() — lets the user copy the contact's peer ID with one tap.
import 'package:flutter/services.dart';
// Provider — context.watch / context.read to subscribe to and read state.
import 'package:provider/provider.dart';

// PeerModel — the typed Dart representation of a contact/peer.
// Fields we use: id, name, status, isOnline, trustLevel.
import '../../../backend/models/peer_models.dart';
// ShellState — we update selectedRoom and section when opening a chat.
import '../../../shell/shell_state.dart';
// MeshTheme — for kSecGreen (online indicator colour).
import '../../../app/app_theme.dart';
// CallsState — startCall() / startVideoCall() when the user taps call buttons.
import '../../calls/calls_state.dart';
// MessagingState — createRoom() + selectRoom() to open a conversation.
import '../../messaging/messaging_state.dart';
// ThreadScreen — the chat view pushed on narrow screens when chat is opened.
import '../../messaging/screens/thread_screen.dart';
// SettingsState — to get localPeerId when calling attestTrust().
import '../../settings/settings_state.dart';
// PeersState — attestTrust() to update the trust level stored in Rust.
import '../../peers/peers_state.dart';
// TrustBadge — renders the trust level as a coloured pill (§22.4.2).
// Imported from contacts/widgets (canonical location) via peers/widgets re-export.
import '../widgets/trust_badge.dart';
import '../../tidbits/tidbits.dart'; // Peer ID Haiku §22.12.5 #9, Copy Confetti

// ---------------------------------------------------------------------------
// Module-level helper: _openConversation
// ---------------------------------------------------------------------------
//
// Opens a direct chat room with [peer].
//
// WHY is this a module-level function rather than a method on the widget?
// -----------------------------------------------------------------------
// Multiple widgets inside this file need to trigger the same "open chat"
// flow: _QuickActions, the "Open Chat" ListTile in the more-actions card,
// etc.  Making it a module-level function avoids duplicating the logic and
// avoids tying it to a specific widget's BuildContext lifecycle.
//
// The function is `async` because createRoom() is async — it waits for the
// backend to confirm the room was created before proceeding.
//
// THREAD-SAFETY NOTE:
// After any `await`, a BuildContext might be invalid (the widget may have
// been disposed while the async call was in flight).  We capture
// ScaffoldMessenger and Navigator BEFORE the await so we can safely use
// them afterward.  The `navigator.mounted` check provides an additional
// guard.

Future<void> _openConversation(BuildContext context, PeerModel peer) async {
  // Capture state objects before the async gap — they hold references to the
  // underlying Messenger/Navigator even after the widget tree changes.
  final messaging = context.read<MessagingState>();
  final shell = context.read<ShellState>();
  final messenger = ScaffoldMessenger.of(context);
  final navigator = Navigator.of(context);

  // Determine layout BEFORE awaiting — screen may resize during the async call.
  final isWide = MediaQuery.sizeOf(context).width >= 1200;

  // Use the peer's display name as the room name; fall back to peer ID prefix.
  final roomName = peer.name.isNotEmpty ? peer.name : peer.id.substring(0, 12);

  // createRoom() calls Rust via FFI to create a new room in the backend.
  // Returns the new room's ID on success, or null on failure.
  final roomId = await messaging.createRoom(roomName);

  // Guard: widget may be gone by the time the await resolves.
  if (roomId == null || !navigator.mounted) {
    messenger.showSnackBar(
      const SnackBar(content: Text('Failed to open conversation')),
    );
    return;
  }

  // Tell MessagingState which room is now active so ThreadScreen can load
  // the correct messages and mark the right room as selected in the list.
  await messaging.selectRoom(roomId);
  if (!navigator.mounted) return;

  // Update shell so the Chat section is active (relevant on desktop
  // where the shell persists and section switching is always visible).
  shell.selectSection(AppSection.chat);
  shell.selectRoom(roomId);

  if (isWide) {
    // On wide layouts the detail pane shows the thread automatically when
    // selectedRoomId is set in ShellState — no push needed.
    messenger.showSnackBar(
      SnackBar(content: Text('Opened chat with $roomName')),
    );
    return;
  }

  // On narrow layouts, push ThreadScreen so the user can see the messages.
  navigator.push(
    MaterialPageRoute(builder: (_) => ThreadScreen(roomId: roomId)),
  );
}

// ---------------------------------------------------------------------------
// ContactDetailScreen (§22.8.2)
// ---------------------------------------------------------------------------

/// Full-detail view for a single contact.
///
/// Takes [peerId] and looks up the live [PeerModel] from [PeersState].
/// If the peer is not found (e.g. just removed), shows a "Contact not found"
/// placeholder rather than crashing.
class ContactDetailScreen extends StatelessWidget {
  const ContactDetailScreen({super.key, required this.peerId});

  /// The peer ID to look up and display.
  final String peerId;

  @override
  Widget build(BuildContext context) {
    // context.watch subscribes to PeersState — if the peer's data changes
    // (e.g. they come online, their trust changes) this widget rebuilds.
    final peer = context.watch<PeersState>().findPeer(peerId);

    // Guard: peer may have been removed while this screen is open.
    if (peer == null) {
      return const Scaffold(body: Center(child: Text('Contact not found')));
    }

    return Scaffold(
      appBar: AppBar(
        // Show the contact's name in the AppBar; fall back to generic label.
        title: Text(peer.name.isNotEmpty ? peer.name : 'Contact'),
        actions: [
          // More-vert menu for less-frequent actions (block, remove).
          // Currently delegated to the more-actions card in the body.
          // Keeping this for future use per §22.8.2.
          IconButton(
            icon: const Icon(Icons.more_vert),
            tooltip: 'More options',
            onPressed: () => _showMoreMenu(context, peer),
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // Hero card: large avatar, name, trust badge, online status.
          _HeaderCard(peer: peer),
          const SizedBox(height: 12),
          // Quick action buttons: Chat, Files, Call.
          _QuickActions(peer: peer),
          const SizedBox(height: 12),
          // Peer ID card — copyable monospace hex string.
          _InfoCard(peer: peer),
          const SizedBox(height: 12),
          // Trust level card with button to change it.
          _TrustCard(peer: peer),
          const SizedBox(height: 12),
          // Extended actions: calls, chat, files, remove.
          _MoreActionsCard(peer: peer),
        ],
      ),
    );
  }

  /// Shows a modal menu for infrequent actions (block, remove).
  void _showMoreMenu(BuildContext context, PeerModel peer) {
    // showModalBottomSheet is the M3 way for action sheets.
    // It gets showDragHandle: true from BottomSheetThemeData in MeshTheme.
    showModalBottomSheet<void>(
      context: context,
      builder: (ctx) => _MoreMenuSheet(peer: peer),
    );
  }
}

// ---------------------------------------------------------------------------
// _HeaderCard — avatar, name, trust badge, online status (§22.8.2 hero card)
// ---------------------------------------------------------------------------

/// Displays the contact's avatar, display name, full trust badge, and
/// online/offline status at the top of the detail screen.
class _HeaderCard extends StatelessWidget {
  const _HeaderCard({required this.peer});

  final PeerModel peer;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final textTheme = Theme.of(context).textTheme;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          children: [
            // Avatar stack: circle + online indicator dot (§22.8.2).
            Stack(
              children: [
                // Contact avatar — initial letter on secondary container.
                // TODO: replace with MaskAvatar once MaskAvatarData is wired
                // to the contact's stored avatar colour (§22.4.3).
                CircleAvatar(
                  radius: 36,
                  backgroundColor: cs.secondaryContainer,
                  child: Text(
                    peer.name.isNotEmpty ? peer.name[0].toUpperCase() : '?',
                    style: TextStyle(
                      fontSize: 32,
                      fontWeight: FontWeight.bold,
                      color: cs.onSecondaryContainer,
                    ),
                  ),
                ),
                // Online indicator dot — positioned bottom-right of avatar.
                // Uses kSecGreen for online, transparent when offline.
                if (peer.isOnline)
                  Positioned(
                    bottom: 2,
                    right: 2,
                    child: Container(
                      width: 14,
                      height: 14,
                      decoration: BoxDecoration(
                        // kSecGreen matches the OnlineIndicator widget colour.
                        color: MeshTheme.secGreen,
                        shape: BoxShape.circle,
                        // White border separates dot from avatar background.
                        border: Border.all(color: cs.surface, width: 2),
                      ),
                    ),
                  ),
              ],
            ),
            const SizedBox(height: 12),

            // Display name — large enough to be the visual anchor.
            Text(
              peer.name.isNotEmpty ? peer.name : 'Unknown',
              style: textTheme.titleLarge,
            ),
            const SizedBox(height: 6),

            // Full trust badge: icon + label pill (§22.4.2).
            TrustBadge(
              level: peer.trustLevel,
              showLabel: true,
            ),
            const SizedBox(height: 4),

            // Online/offline status text below the trust badge.
            Text(
              peer.isOnline ? 'Online' : peer.status,
              style: textTheme.bodySmall?.copyWith(
                color: peer.isOnline
                    ? MeshTheme.secGreen
                    : cs.onSurfaceVariant,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _QuickActions — horizontal Chat / Files / Call buttons
// ---------------------------------------------------------------------------

/// Three quick-action buttons rendered as a horizontal row of outlined pills.
///
/// Each button has an icon + label, matching the M3 action-button pattern
/// used in contact detail screens (§22.8.2).
class _QuickActions extends StatelessWidget {
  const _QuickActions({required this.peer});

  final PeerModel peer;

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Expanded(
          child: _ActionButton(
            icon: Icons.chat_bubble_outline,
            label: 'Chat',
            onTap: () => _openConversation(context, peer),
          ),
        ),
        const SizedBox(width: 8),
        Expanded(
          child: _ActionButton(
            icon: Icons.folder_outlined,
            label: 'Files',
            // File transfer launches from the Files section; this is a shortcut
            // that nudges the user in the right direction.
            onTap: () => ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(content: Text('Open Files to send something')),
            ),
          ),
        ),
        const SizedBox(width: 8),
        Expanded(
          child: _ActionButton(
            icon: Icons.call_outlined,
            label: 'Call',
            // CallsState.startCall() initiates a VoIP call via the call overlay.
            onTap: () => context.read<CallsState>().startCall(peer.id),
          ),
        ),
      ],
    );
  }
}

/// Single icon+label button used inside [_QuickActions].
class _ActionButton extends StatelessWidget {
  const _ActionButton({
    required this.icon,
    required this.label,
    required this.onTap,
  });

  final IconData icon;
  final String label;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return OutlinedButton(
      onPressed: onTap,
      style: OutlinedButton.styleFrom(
        padding: const EdgeInsets.symmetric(vertical: 12),
        minimumSize: const Size(double.infinity, 48),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 22),
          const SizedBox(height: 4),
          Text(label, style: Theme.of(context).textTheme.labelSmall),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _InfoCard — peer ID with copy button
// ---------------------------------------------------------------------------

/// Shows the contact's cryptographic peer ID as copyable monospace text.
///
/// The peer ID is their unique identifier on the mesh — useful for out-of-band
/// verification, for example comparing IDs over a voice call to confirm
/// identity before promoting trust level.
class _InfoCard extends StatelessWidget {
  const _InfoCard({required this.peer});

  final PeerModel peer;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Peer ID', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            Row(
              children: [
                // Triple-tap on the peer ID triggers a haiku (§22.12.5 #9).
                // TapTrigger is transparent — the SelectableText looks unchanged.
                Expanded(
                  child: TapTrigger(
                    count: 3,
                    onTriggered: () {
                      // Register the haiku on demand so it's available for show().
                      registerHaikuForPeer(TidbitRegistry.instance, peer.id);
                      TidbitRegistry.instance.show('peer_id_haiku_${peer.id}', context);
                    },
                    child: SelectableText(
                      peer.id,
                      style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                    ),
                  ),
                ),
                // One-tap copy icon — also fires Copy Confetti §22.12.5 #7.
                IconButton(
                  icon: const Icon(Icons.copy_outlined, size: 18),
                  tooltip: 'Copy peer ID',
                  onPressed: () {
                    Clipboard.setData(ClipboardData(text: peer.id));
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(content: Text('Peer ID copied')),
                    );
                    TidbitRegistry.instance.show('copy_confetti', context);
                  },
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _TrustCard — trust level display + set trust button
// ---------------------------------------------------------------------------

/// Shows the current trust level and a button to open the trust sheet.
///
/// Trust level affects: which features are available (calls, files), whether
/// messages go through LoSec mode, and queue routing decisions in the mesh.
/// See §9 for the full trust model specification.
class _TrustCard extends StatelessWidget {
  const _TrustCard({required this.peer});

  final PeerModel peer;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Trust', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 12),
            // Full-label TrustBadge shows icon + name (e.g. "Trusted ●●●●●").
            TrustBadge(level: peer.trustLevel, showLabel: true),
            const SizedBox(height: 16),
            // Opens the trust level picker bottom sheet.
            FilledButton.tonal(
              onPressed: () => _showTrustSheet(context, peer),
              child: const Text('Set Trust Level'),
            ),
          ],
        ),
      ),
    );
  }

  /// Shows a bottom sheet listing all nine trust levels for selection.
  void _showTrustSheet(BuildContext context, PeerModel peer) {
    showModalBottomSheet<void>(
      context: context,
      builder: (ctx) => _TrustSheet(peer: peer),
    );
  }
}

// ---------------------------------------------------------------------------
// _MoreActionsCard — extended actions (calls, chat, files, remove)
// ---------------------------------------------------------------------------

/// Card containing less-frequent but important actions: voice/video call,
/// open chat, send file, and the destructive "Remove Contact" option.
///
/// "Remove Contact" is placed last in the list and uses error colours to
/// make it visually distinct and harder to tap accidentally.
class _MoreActionsCard extends StatelessWidget {
  const _MoreActionsCard({required this.peer});

  final PeerModel peer;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'More Actions',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            ListTile(
              leading: const Icon(Icons.call_outlined),
              title: const Text('Voice Call'),
              onTap: () {
                // Start a VoIP call via CallsState — the call overlay will
                // appear over the current screen automatically.
                context.read<CallsState>().startCall(peer.id);
                Navigator.of(context).pop();
              },
            ),
            ListTile(
              leading: const Icon(Icons.videocam_outlined),
              title: const Text('Video Call'),
              onTap: () {
                context.read<CallsState>().startCall(peer.id, video: true);
                Navigator.of(context).pop();
              },
            ),
            ListTile(
              leading: const Icon(Icons.chat_outlined),
              title: const Text('Open Chat'),
              onTap: () => _openConversation(context, peer),
            ),
            ListTile(
              leading: const Icon(Icons.send_outlined),
              title: const Text('Send File'),
              onTap: () {
                Navigator.of(context).pop();
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('File transfer: select a file to send'),
                  ),
                );
              },
            ),
            // Destructive action — uses error colour to signal risk.
            ListTile(
              leading: Icon(
                Icons.block_outlined,
                color: Theme.of(context).colorScheme.error,
              ),
              title: Text(
                'Remove Contact',
                style: TextStyle(color: Theme.of(context).colorScheme.error),
              ),
              onTap: () => _confirmRemove(context, peer),
            ),
          ],
        ),
      ),
    );
  }

  /// Shows a confirmation dialog before removing the contact.
  ///
  /// Removing a contact sets their trust level to 0 (unknown) which
  /// effectively revokes access without deleting message history.
  void _confirmRemove(BuildContext context, PeerModel peer) {
    showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Remove Contact?'),
        content: Text(
          'This will revoke trust and remove '
          '${peer.name.isNotEmpty ? peer.name : "this contact"} '
          'from your contact list.',
        ),
        actions: [
          // Cancel — dismiss without action.
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Cancel'),
          ),
          // Confirm remove — set trust to 0 (unknown) via PeersState.
          FilledButton(
            style: FilledButton.styleFrom(
              backgroundColor: Theme.of(ctx).colorScheme.error,
            ),
            onPressed: () {
              // Get the local peer ID needed to sign the trust attestation.
              final localId =
                  context.read<SettingsState>().settings?.localPeerId ?? '';
              // attestTrust() sends a signed trust record to Rust which
              // updates the trust database and notifies the backend.
              context.read<PeersState>().attestTrust(
                localPeerId: localId,
                targetPeerId: peer.id,
                // Trust level 0 = unknown — effectively removes the contact.
                trustLevel: 0,
              );
              // Close the dialog, then pop this screen since the contact
              // no longer exists in the list.
              Navigator.of(ctx).pop();
              Navigator.of(context).pop();
            },
            child: const Text('Remove'),
          ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _MoreMenuSheet — bottom sheet for block / remove (from AppBar more-vert)
// ---------------------------------------------------------------------------

/// A simple action sheet for block and remove, accessible from the
/// AppBar more-vert button (§22.8.2).
class _MoreMenuSheet extends StatelessWidget {
  const _MoreMenuSheet({required this.peer});

  final PeerModel peer;

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 8),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const Icon(Icons.qr_code),
              title: const Text('View QR code'),
              onTap: () {
                Navigator.of(context).pop();
                // TODO: show this contact's QR for re-sharing (§22.8.2).
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('QR code: coming soon')),
                );
              },
            ),
            ListTile(
              leading: const Icon(Icons.block_outlined),
              title: const Text('Block contact'),
              onTap: () {
                Navigator.of(context).pop();
                // TODO: block confirmation dialog (§22.8.2).
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Block: coming soon')),
                );
              },
            ),
            ListTile(
              leading: Icon(
                Icons.delete_outline,
                color: Theme.of(context).colorScheme.error,
              ),
              title: Text(
                'Remove contact',
                style: TextStyle(color: Theme.of(context).colorScheme.error),
              ),
              onTap: () {
                Navigator.of(context).pop();
                // TODO: remove confirmation dialog (§22.8.2).
              },
            ),
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _TrustSheet — bottom sheet for setting trust level
// ---------------------------------------------------------------------------

/// Lists all nine trust levels as selectable tiles.  The currently active
/// level is highlighted.  Selecting a level calls attestTrust() in Rust
/// which updates the signed trust record for this contact.
class _TrustSheet extends StatelessWidget {
  const _TrustSheet({required this.peer});

  final PeerModel peer;

  @override
  Widget build(BuildContext context) {
    // Read local peer ID once before building the list tiles.
    final localPeerId =
        context.read<SettingsState>().settings?.localPeerId ?? '';

    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 8),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Padding(
              padding: const EdgeInsets.all(16),
              child: Text(
                'Set Trust Level',
                style: Theme.of(context).textTheme.titleMedium,
              ),
            ),
            const Divider(),
            // One ListTile per TrustLevel value (9 values: 0–8).
            // TrustLevel.values returns them in definition order (lowest first).
            for (final level in TrustLevel.values)
              ListTile(
                // Compact badge shows the numeric level in a small circle.
                leading: TrustBadge(level: level, compact: true),
                // Full label: e.g. "Unknown", "Public", "Vouched", etc.
                title: Text(level.label),
                // Highlight the row matching the peer's current trust level.
                selected: peer.trustLevel == level,
                onTap: () {
                  // Dismiss the sheet before performing the async operation
                  // to avoid a stale context after the navigation.
                  Navigator.pop(context);

                  if (localPeerId.isEmpty) {
                    // Guard: cannot attest without a local identity.
                    // This should not happen during normal use — identity is
                    // created during onboarding.
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(
                        content: Text(
                          'Cannot set trust: local identity not available. '
                          'Complete onboarding first.',
                        ),
                      ),
                    );
                    return;
                  }

                  // attestTrust() sends a Rust FFI call that signs and stores
                  // the new trust level in the local trust database.
                  context.read<PeersState>().attestTrust(
                    localPeerId: localPeerId,
                    targetPeerId: peer.id,
                    // level.value is the integer 0–8 stored in Rust.
                    trustLevel: level.value,
                  );
                },
              ),
          ],
        ),
      ),
    );
  }
}
