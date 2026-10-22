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
import 'package:qr_flutter/qr_flutter.dart';

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
  final roomId = await messaging.createRoom(roomName, peerId: peer.id);

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

  /// Shows a modal menu for infrequent actions (block, remove) and runs the
  /// chosen one with this screen's context once the sheet has closed.
  ///
  /// The sheet only reports a choice; the confirmation dialogs are opened
  /// from here because the sheet's own context is gone once it pops, and
  /// §22.8.2 wants each of these actions behind a confirmation.
  Future<void> _showMoreMenu(BuildContext context, PeerModel peer) async {
    // showModalBottomSheet is the M3 way for action sheets.
    // It gets showDragHandle: true from BottomSheetThemeData in MeshTheme.
    final action = await showModalBottomSheet<_MoreAction>(
      context: context,
      builder: (ctx) => _MoreMenuSheet(peer: peer),
    );
    // Dismissed without a choice, or the screen went away meanwhile.
    if (action == null || !context.mounted) return;
    switch (action) {
      case _MoreAction.block:
        _confirm_block(context, peer);
      case _MoreAction.unblock:
        _unblock(context, peer);
      case _MoreAction.remove:
        _confirm_remove(context, peer);
    }
  }
}

// ---------------------------------------------------------------------------
// Module-level trust and block actions
// ---------------------------------------------------------------------------
//
// These take the *screen's* BuildContext, never a sheet's or dialog's, so
// the Provider lookups and the final Navigator.pop() land on a live route.

/// The contact's name for dialog copy; §22.31 wants "[name]", and a contact
/// without a display name still needs a readable noun.
String _display_name(PeerModel peer) =>
    peer.name.isNotEmpty ? peer.name : 'this contact';

/// Which §22.31 side of the Acquaintance/Trusted boundary a level is on.
/// Level 6 and above share the private profile; below does not.
bool _is_trusted_tier(TrustLevel level) =>
    level.value >= TrustLevel.trusted.value;

/// Send the signed trust attestation for [level] to the backend.
///
/// The local peer ID signs the record; without one (identity not loaded)
/// nothing is sent and the user is told why.
void _attest_trust(BuildContext context, PeerModel peer, TrustLevel level) {
  final local_id = context.read<SettingsState>().settings?.localPeerId ?? '';
  if (local_id.isEmpty) {
    // Should not happen in normal use — identity is created during
    // onboarding — but a missing signer must never attest silently.
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
  // attestTrust() sends a Rust FFI call that signs and stores the new
  // trust level in the local trust database.
  context.read<PeersState>().attestTrust(
    localPeerId: local_id,
    targetPeerId: peer.id,
    trustLevel: level.value,
  );
}

/// Apply a trust change chosen in the trust sheet (§22.8.2, §22.31).
///
/// Changes that stay on one side of the Acquaintance/Trusted boundary are
/// applied at once.  Any change that crosses it — in either direction — goes
/// through the §22.31 confirmation first, because crossing upward commits to
/// sharing the private profile once reciprocated, and crossing downward
/// cannot take back what was already shared.  Re-selecting the current
/// level is a no-op.
void _apply_trust(BuildContext context, PeerModel peer, TrustLevel level) {
  if (level == peer.trustLevel) return;
  final crosses = _is_trusted_tier(peer.trustLevel) != _is_trusted_tier(level);
  if (!crosses) {
    _attest_trust(context, peer, level);
    return;
  }
  if (_is_trusted_tier(level)) {
    _confirm_promote(context, peer, level);
  } else {
    _confirm_demote(context, peer, level);
  }
}

/// §22.31 promote confirmation — the only promote text in the spec.
///
/// The body states what crosses over and when: the private profile goes out
/// on reciprocation, not on this tap, and cannot be recalled afterwards.
void _confirm_promote(BuildContext context, PeerModel peer, TrustLevel level) {
  final name = _display_name(peer);
  showDialog<void>(
    context: context,
    builder: (ctx) => AlertDialog(
      // Brand blue as an icon foreground goes through the per-theme token
      // (§22.1.1 "Brand as foreground", CMR-019), never the raw seed.
      icon: Icon(Icons.lock_outlined, color: MeshColors.of(ctx).brand_fg),
      title: Text('Share your identity with $name?'),
      content: Text(
        'Trusting $name opens a private channel between you. Your private '
        'profile — your real name and any contact info you\'ve added — is '
        'sent only once $name trusts you back. After that it can\'t be '
        'recalled: you can remove trust later, but they keep what was '
        'already shared.',
      ),
      actions: [
        // Cancel — nothing is sent.
        TextButton(
          onPressed: () => Navigator.of(ctx).pop(),
          child: const Text('Cancel'),
        ),
        // Confirm — close the dialog, then attest with the screen context.
        FilledButton(
          onPressed: () {
            Navigator.of(ctx).pop();
            _attest_trust(context, peer, level);
          },
          child: Text('Trust $name'),
        ),
      ],
    ),
  );
}

/// §22.31 demote confirmation — the only demote text in the spec.
///
/// Cancel is the default-focused action and the destructive button uses the
/// amber security token, as §22.31 specifies.
void _confirm_demote(BuildContext context, PeerModel peer, TrustLevel level) {
  final name = _display_name(peer);
  showDialog<void>(
    context: context,
    builder: (ctx) => AlertDialog(
      title: Text('Remove trust from $name?'),
      content: Text(
        'This closes the private channel. $name keeps any profile info '
        'already shared — that can\'t be undone — but won\'t receive future '
        'private updates.',
      ),
      actions: [
        // Cancel — default focus so Enter/Return keeps trust (§22.31).
        TextButton(
          autofocus: true,
          onPressed: () => Navigator.of(ctx).pop(),
          child: const Text('Cancel'),
        ),
        // Confirm — amber, not red: a demotion is reversible in part.
        FilledButton(
          style: FilledButton.styleFrom(
            backgroundColor: MeshColors.of(ctx).sec_amber,
          ),
          onPressed: () {
            Navigator.of(ctx).pop();
            _attest_trust(context, peer, level);
          },
          child: const Text('Remove trust'),
        ),
      ],
    ),
  );
}

/// Shows a confirmation dialog before removing the contact (§22.8.2).
///
/// Removing a contact sets their trust level to 0 (unknown) which
/// effectively revokes access without deleting message history.  Shared by
/// the more-actions card and the AppBar more-vert menu.
void _confirm_remove(BuildContext context, PeerModel peer) {
  showDialog<void>(
    context: context,
    builder: (ctx) => AlertDialog(
      title: const Text('Remove Contact?'),
      content: Text(
        'This will revoke trust and remove ${_display_name(peer)} '
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
            // Trust level 0 = unknown — effectively removes the contact.
            _attest_trust(context, peer, TrustLevel.unknown);
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

/// Shows a confirmation dialog before blocking the contact (§22.8.2).
///
/// Blocking keeps the contact record (so it can be undone from the same
/// menu) but the backend drops every message and message request from them.
void _confirm_block(BuildContext context, PeerModel peer) {
  final name = _display_name(peer);
  showDialog<void>(
    context: context,
    builder: (ctx) => AlertDialog(
      title: Text('Block $name?'),
      content: Text(
        '$name won\'t be able to message you. They aren\'t told, and you '
        'can unblock them from this screen at any time.',
      ),
      actions: [
        // Cancel — dismiss without action.
        TextButton(
          onPressed: () => Navigator.of(ctx).pop(),
          child: const Text('Cancel'),
        ),
        // Confirm — error colour: the contact loses the ability to reach us.
        FilledButton(
          style: FilledButton.styleFrom(
            backgroundColor: Theme.of(ctx).colorScheme.error,
          ),
          onPressed: () {
            Navigator.of(ctx).pop();
            _set_blocked(context, peer, blocked: true);
          },
          child: const Text('Block'),
        ),
      ],
    ),
  );
}

/// Unblock without a confirmation: it restores the contact's ability to
/// reach us and is itself undoable through "Block contact".
void _unblock(BuildContext context, PeerModel peer) =>
    _set_blocked(context, peer, blocked: false);

/// Write the block state through PeersState and report a backend refusal.
Future<void> _set_blocked(
  BuildContext context,
  PeerModel peer, {
  required bool blocked,
}) async {
  // Capture before the await — the screen may be gone afterwards.
  final messenger = ScaffoldMessenger.of(context);
  final ok = await context.read<PeersState>().setPeerBlocked(
    peer.id,
    blocked: blocked,
  );
  if (!ok) {
    messenger.showSnackBar(
      SnackBar(
        content: Text(
          blocked
              ? 'Couldn\'t block this contact.'
              : 'Couldn\'t unblock this contact.',
        ),
      ),
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
                // Uses MeshColors.sec_green for online, transparent when offline.
                if (peer.isOnline)
                  Positioned(
                    bottom: 2,
                    right: 2,
                    child: Container(
                      width: 14,
                      height: 14,
                      decoration: BoxDecoration(
                        // sec_green matches the OnlineIndicator widget colour.
                        color: MeshColors.of(context).sec_green,
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
            // Blocked state (§22.8.2) — the one place the user can see that
            // this contact's messages are being dropped.
            if (peer.blocked) ...[
              const SizedBox(height: 4),
              Text(
                'Blocked',
                style: textTheme.labelMedium?.copyWith(color: cs.error),
              ),
            ],
            const SizedBox(height: 6),

            // Full trust badge: icon + label pill (§22.4.2).
            TrustBadge(level: peer.trustLevel, showLabel: true),
            const SizedBox(height: 4),

            // Online/offline status text below the trust badge.
            Text(
              peer.isOnline ? 'Online' : peer.status,
              style: textTheme.bodySmall?.copyWith(
                color: peer.isOnline
                    ? MeshColors.of(context).sec_green
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
                      TidbitRegistry.instance.show(
                        'peer_id_haiku_${peer.id}',
                        context,
                      );
                    },
                    child: SelectableText(
                      peer.id,
                      style: const TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 12,
                      ),
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

  /// Shows a bottom sheet listing all nine trust levels for selection, then
  /// applies the choice (with the §22.31 confirmation when the change
  /// crosses the trusted boundary) using this card's live context.
  Future<void> _showTrustSheet(BuildContext context, PeerModel peer) async {
    final level = await showModalBottomSheet<TrustLevel>(
      context: context,
      builder: (ctx) => _TrustSheet(peer: peer),
    );
    // Dismissed without a choice, or the screen went away meanwhile.
    if (level == null || !context.mounted) return;
    _apply_trust(context, peer, level);
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
              onTap: () => _confirm_remove(context, peer),
            ),
          ],
        ),
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
                showDialog<void>(
                  context: context,
                  builder: (ctx) => AlertDialog(
                    title: const Text('Contact QR code'),
                    content: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        QrImageView(
                          data: peer.id,
                          size: 220,
                          backgroundColor: Colors.white,
                        ),
                        const SizedBox(height: 12),
                        SelectableText(
                          peer.id,
                          style: Theme.of(ctx).textTheme.bodySmall?.copyWith(
                            fontFamily: 'monospace',
                          ),
                        ),
                      ],
                    ),
                    actions: [
                      TextButton(
                        onPressed: () {
                          Clipboard.setData(ClipboardData(text: peer.id));
                          Navigator.of(ctx).pop();
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(content: Text('Peer ID copied')),
                          );
                        },
                        child: const Text('Copy peer ID'),
                      ),
                      FilledButton(
                        onPressed: () => Navigator.of(ctx).pop(),
                        child: const Text('Close'),
                      ),
                    ],
                  ),
                );
              },
            ),
            // Block / Unblock — the label follows the current state so the
            // same row undoes what it did (§22.8.2 "Block contact").
            ListTile(
              leading: Icon(
                peer.blocked
                    ? Icons.check_circle_outline
                    : Icons.block_outlined,
                color: peer.blocked
                    ? null
                    : Theme.of(context).colorScheme.error,
              ),
              title: Text(
                peer.blocked ? 'Unblock contact' : 'Block contact',
                style: peer.blocked
                    ? null
                    : TextStyle(color: Theme.of(context).colorScheme.error),
              ),
              // The sheet only reports the choice; the screen confirms it.
              onTap: () => Navigator.of(
                context,
              ).pop(peer.blocked ? _MoreAction.unblock : _MoreAction.block),
            ),
            // Remove — confirmed by the screen (§22.8.2, error colour).
            ListTile(
              leading: Icon(
                Icons.delete_outline,
                color: Theme.of(context).colorScheme.error,
              ),
              title: Text(
                'Remove contact',
                style: TextStyle(color: Theme.of(context).colorScheme.error),
              ),
              onTap: () => Navigator.of(context).pop(_MoreAction.remove),
            ),
          ],
        ),
      ),
    );
  }
}

/// What the more-vert sheet reports back to the screen.
enum _MoreAction { block, unblock, remove }

// ---------------------------------------------------------------------------
// _TrustSheet — bottom sheet for setting trust level
// ---------------------------------------------------------------------------

/// Lists all nine trust levels as selectable tiles.  The currently active
/// level is highlighted.  Selecting a level closes the sheet with that level
/// as its result; _TrustCard then applies it, asking for the §22.31
/// confirmation when the change crosses the trusted boundary.
class _TrustSheet extends StatelessWidget {
  const _TrustSheet({required this.peer});

  final PeerModel peer;

  @override
  Widget build(BuildContext context) {
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
                // Close the sheet with the chosen level; nothing is sent
                // from here.  _TrustCard decides whether a confirmation is
                // needed (§22.31) and performs the attestation.
                onTap: () => Navigator.pop(context, level),
              ),
          ],
        ),
      ),
    );
  }
}
