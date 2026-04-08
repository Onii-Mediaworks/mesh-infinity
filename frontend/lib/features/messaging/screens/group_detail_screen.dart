// group_detail_screen.dart
//
// GroupDetailScreen shows the metadata and membership of a group room, and
// lets admins invite peers and lets any member leave.
//
// HOW IS GROUP DATA FETCHED?
// --------------------------
// The backend does not expose a single "get group by room ID" call.
// Instead, listGroups() returns ALL groups the local node knows about, and
// we filter that list by widget.groupId.  This is intentional: the same
// listGroups() call is used elsewhere (e.g. garden discovery) and avoids
// adding a bespoke per-group endpoint.
//
// ADMIN FLAG
// ----------
// The 'isAdmin' flag in the groupInfo map is set by the backend based on
// whether the local node's public key matches the group's admin list.
// When isAdmin == true, an "Invite" button and the admin-status card are
// shown.  Regular members see only the member list and the Leave button.
//
// LEAVE FLOW
// ----------
// Leaving requires explicit confirmation (AlertDialog) because it is
// destructive — the user loses access to all group messages permanently.
// After a confirmed leave, both the detail screen AND the thread screen
// are popped from the stack so the user is returned to the room list.
//
// INVITE FLOW
// -----------
// Admins can invite any paired peer who is not already a member.
// The invite picker is a modal bottom-sheet list built from fetchPeers()
// filtered to exclude current group members.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
// Clipboard.setData — used to copy the group ID to the clipboard.
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';
// BackendBridge — all backend calls used here:
//   listGroups(), getGroupMembers(), leaveGroup(), inviteToGroup(), fetchPeers().
import '../../../backend/models/peer_models.dart';
// PeerModel — typed peer data used in the invite-picker bottom sheet.
import '../messaging_state.dart';
// MessagingState — loadRooms() is called after leaving so the room list
// is refreshed.

/// Detail screen for a group room — shows members, admin controls, group settings.
///
/// [groupId] is the backend's group identifier (not the same as the room ID,
/// though they are related).  Pushed from [ThreadScreen] when the room is a
/// group and the user taps the group-info icon.
class GroupDetailScreen extends StatefulWidget {
  const GroupDetailScreen({super.key, required this.groupId});

  /// The opaque group identifier from [RoomSummary.groupId].
  final String groupId;

  @override
  State<GroupDetailScreen> createState() => _GroupDetailScreenState();
}

class _GroupDetailScreenState extends State<GroupDetailScreen> {
  // ---------------------------------------------------------------------------
  // State fields
  // ---------------------------------------------------------------------------

  /// Raw group metadata map from listGroups().
  /// Null while loading or if the group was not found.
  Map<String, dynamic>? _groupInfo;

  /// List of raw member maps from getGroupMembers().
  List<Map<String, dynamic>> _members = [];

  /// True while _load() is running — shows a full-screen spinner.
  bool _loading = true;

  /// Non-null if the group could not be found — shows an error placeholder.
  String? _error;

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  @override
  void initState() {
    super.initState();
    _load();
  }

  // ---------------------------------------------------------------------------
  // Data loading
  // ---------------------------------------------------------------------------

  /// Fetches group metadata and member list from the backend.
  ///
  /// listGroups() is called rather than a direct "get group" endpoint because
  /// the backend exposes a list-and-filter pattern (see file header).
  /// getGroupMembers() returns a separate richer member list.
  Future<void> _load() async {
    // Show spinner and clear any previous error before reloading.
    setState(() { _loading = true; _error = null; });
    final bridge = context.read<BackendBridge>();

    // Fetch all groups and find the one matching our groupId.
    final groups = bridge.listGroups();
    final matching = groups.where(
      (g) => (g['groupId'] as String?) == widget.groupId,
    );
    // isNotEmpty before .first prevents a RangeError if the group was deleted
    // between the time ThreadScreen pushed this screen and now.
    final group = matching.isNotEmpty ? matching.first : null;

    // Separate call for member list — richer data than what listGroups() returns.
    final members = bridge.getGroupMembers(widget.groupId);

    setState(() {
      _groupInfo = group;
      _members = members;
      _loading = false;
      // If the group wasn't found, set an error message for the UI to display.
      if (group == null) _error = 'Group not found';
    });
  }

  // ---------------------------------------------------------------------------
  // Leave action
  // ---------------------------------------------------------------------------

  /// Shows a confirmation dialog and, if confirmed, leaves the group.
  ///
  /// After a successful leave:
  ///   1. loadRooms() updates the room list so the deleted room disappears.
  ///   2. Both this screen AND the thread screen are popped so the user
  ///      is returned to the room list rather than a dead thread.
  Future<void> _leaveGroup() async {
    // Confirmation dialog — leaving is destructive and irreversible.
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Leave Group?'),
        content: const Text(
          'You will lose access to all group messages. '
          'This cannot be undone.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel'),
          ),
          // Use error colour for the destructive action button.
          FilledButton(
            style: FilledButton.styleFrom(
              backgroundColor: Theme.of(ctx).colorScheme.error,
            ),
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Leave'),
          ),
        ],
      ),
    );

    // confirmed == false (Cancel) or null (dialog dismissed).
    if (confirmed != true || !mounted) return;

    final bridge = context.read<BackendBridge>();
    final ok = bridge.leaveGroup(widget.groupId);

    if (!mounted) return;

    if (ok) {
      // Refresh the room list so the departed group no longer appears.
      await context.read<MessagingState>().loadRooms();
      if (mounted) {
        // Double pop: first closes GroupDetailScreen, second closes ThreadScreen.
        Navigator.of(context)
          ..pop()   // group detail screen
          ..pop();  // thread screen
      }
    } else {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Failed to leave group')),
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    // Full-screen spinners during load and error states — no appBar needed
    // in the error path because the Scaffold's back button handles exit.
    if (_loading) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }
    if (_error != null) {
      return Scaffold(body: Center(child: Text(_error!)));
    }

    final cs = Theme.of(context).colorScheme;

    // Parse group metadata with null-safe casts.
    final name        = _groupInfo?['name']        as String? ?? 'Group';
    final description = _groupInfo?['description'] as String? ?? '';
    final networkType = _groupInfo?['networkType'] as String? ?? 'private';
    final isAdmin     = _groupInfo?['isAdmin']     as bool?   ?? false;
    final groupId     = widget.groupId;

    return Scaffold(
      appBar: AppBar(
        title: Text(name),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            tooltip: 'Refresh',
            onPressed: _load,
          ),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: _load,
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            // Group hero section — large avatar + name + description + badge.
            Center(
              child: Column(
                children: [
                  CircleAvatar(
                    radius: 40,
                    backgroundColor: cs.primaryContainer,
                    child: Icon(
                      Icons.group_outlined,
                      size: 40,
                      color: cs.onPrimaryContainer,
                    ),
                  ),
                  const SizedBox(height: 12),
                  Text(name, style: Theme.of(context).textTheme.titleLarge),
                  if (description.isNotEmpty) ...[
                    const SizedBox(height: 4),
                    Text(
                      description,
                      style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                        color: cs.onSurfaceVariant,
                      ),
                      textAlign: TextAlign.center,
                    ),
                  ],
                  const SizedBox(height: 8),
                  // networkType badge (private/closed/open/public) shows the
                  // group's join policy at a glance.
                  _NetworkTypeBadge(networkType: networkType),
                ],
              ),
            ),

            const SizedBox(height: 24),

            // Group ID card — shows the raw group ID in monospace with a
            // copy-to-clipboard button.  Useful for sharing invitations
            // or verifying identity with another member.
            Card(
              child: ListTile(
                leading: const Icon(Icons.fingerprint_outlined),
                title: const Text('Group ID'),
                subtitle: Text(
                  groupId,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
                ),
                trailing: IconButton(
                  icon: const Icon(Icons.copy_outlined, size: 18),
                  tooltip: 'Copy group ID',
                  onPressed: () {
                    Clipboard.setData(ClipboardData(text: groupId));
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(content: Text('Group ID copied')),
                    );
                  },
                ),
              ),
            ),

            const SizedBox(height: 12),

            // Members card — lists all current members with admin status icons.
            // Admins also see an "Invite" button to add more members.
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Text(
                          'Members (${_members.length})',
                          style: Theme.of(context).textTheme.titleMedium,
                        ),
                        const Spacer(),
                        // Invite button is only available to group admins.
                        if (isAdmin)
                          TextButton.icon(
                            icon: const Icon(Icons.person_add_outlined, size: 18),
                            label: const Text('Invite'),
                            onPressed: _invitePeer,
                          ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    if (_members.isEmpty)
                      Text(
                        'No members',
                        style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                          color: cs.onSurfaceVariant,
                        ),
                      )
                    else
                      // Spread the member tiles directly into the column children.
                      ..._members.map((m) => _MemberTile(member: m, isAdmin: isAdmin)),
                  ],
                ),
              ),
            ),

            const SizedBox(height: 12),

            // Admin-status card — only visible to the current admin.
            // Explains admin privileges in plain language.
            if (isAdmin)
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Row(
                    children: [
                      Icon(Icons.admin_panel_settings_outlined, color: cs.primary),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text('Admin', style: Theme.of(context).textTheme.titleSmall),
                            Text(
                              'You are an admin of this group. '
                              'You can invite peers and manage members.',
                              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                                color: cs.onSurfaceVariant,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
              ),

            const SizedBox(height: 24),

            // Leave group — styled as a destructive outlined button.
            // Error colour signals the action is irreversible.
            OutlinedButton.icon(
              style: OutlinedButton.styleFrom(
                foregroundColor: cs.error,
                side: BorderSide(color: cs.error),
              ),
              icon: const Icon(Icons.exit_to_app_outlined),
              label: const Text('Leave Group'),
              onPressed: _leaveGroup,
            ),
          ],
        ),
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Invite peer
  // ---------------------------------------------------------------------------

  /// Opens a bottom-sheet peer picker and invites the selected peer to the group.
  ///
  /// Fetches all known peers from the backend, then excludes those already in
  /// this group so the admin cannot accidentally re-invite an existing member.
  ///
  /// If the invite succeeds, _load() is called to refresh the member list.
  Future<void> _invitePeer() async {
    final bridge = context.read<BackendBridge>();
    final allPeers = bridge.fetchPeers();

    // Build a set of already-member peer IDs for fast O(1) exclusion.
    final memberIds = _members.map((m) => m['peerId'] as String? ?? '').toSet();
    final candidates = allPeers.where((p) => !memberIds.contains(p.id)).toList();

    // If all known peers are already members, there is nobody to invite.
    if (candidates.isEmpty) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('All known peers are already in this group')),
        );
      }
      return;
    }

    if (!mounted) return;

    // Show a scrollable bottom-sheet list of invite candidates.
    final selected = await showModalBottomSheet<PeerModel>(
      context: context,
      builder: (ctx) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
              child: Text(
                'Invite a peer',
                style: Theme.of(ctx).textTheme.titleSmall,
              ),
            ),
            // Constrain height to 40% of the screen so the sheet doesn't
            // cover the whole screen on phones with many contacts.
            ConstrainedBox(
              constraints: BoxConstraints(
                maxHeight: MediaQuery.sizeOf(ctx).height * 0.4,
              ),
              child: ListView.builder(
                shrinkWrap: true,
                itemCount: candidates.length,
                itemBuilder: (_, i) {
                  final peer = candidates[i];
                  return ListTile(
                    leading: const Icon(Icons.person_outline),
                    title: Text(peer.name),
                    // Show a truncated peer ID in monospace as a subtitle —
                    // helps disambiguate peers with the same display name.
                    subtitle: Text(
                      peer.id.length > 16 ? '${peer.id.substring(0, 16)}…' : peer.id,
                      style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
                    ),
                    // Pop the sheet with the selected PeerModel.
                    onTap: () => Navigator.pop(ctx, peer),
                  );
                },
              ),
            ),
          ],
        ),
      ),
    );

    // selected is null if the user dismissed the sheet without picking.
    if (selected == null || !mounted) return;

    final ok = bridge.inviteToGroup(widget.groupId, selected.id);

    if (!mounted) return;

    if (ok) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('${selected.name} invited to group')),
      );
      // Reload so the new member appears in the member list.
      await _load();
    } else {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Failed to invite ${selected.name}')),
      );
    }
  }
}

// ---------------------------------------------------------------------------
// _NetworkTypeBadge — join-policy pill badge
// ---------------------------------------------------------------------------

/// Displays the group's networkType as a colour-coded pill.
///
/// Uses error/tertiary/primary/green colours to convey openness at a glance:
///   private → error red   (most restrictive)
///   closed  → tertiary    (restricted, but discoverable)
///   open    → primary     (open with approval)
///   public  → green       (fully open)
class _NetworkTypeBadge extends StatelessWidget {
  const _NetworkTypeBadge({required this.networkType});

  final String networkType;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    // Map networkType string to a (label, colour) pair using Dart 3 records.
    final (label, color) = switch (networkType.toLowerCase()) {
      'private' => ('Private', cs.error),
      'closed'  => ('Closed',  cs.tertiary),
      'open'    => ('Open',    cs.primary),
      'public'  => ('Public',  Colors.green),
      _         => ('Unknown', cs.outline), // Graceful fallback for future types.
    };

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      decoration: BoxDecoration(
        // Very light fill (alpha 30 ≈ 12%) so the badge is readable on
        // both light and dark backgrounds.
        color: color.withAlpha(30),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withAlpha(80)),
      ),
      child: Text(
        label,
        style: TextStyle(
          fontSize: 12,
          fontWeight: FontWeight.w600,
          color: color,
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _MemberTile — one row per group member
// ---------------------------------------------------------------------------

/// Displays a single group member with admin status icon and "you" badge.
///
/// [isAdmin] refers to whether the *viewing user* is an admin, not whether
/// this particular member is an admin (that comes from member['isAdmin']).
/// The field is included so future admin-only actions (e.g. remove member)
/// can be gated here.
class _MemberTile extends StatelessWidget {
  const _MemberTile({required this.member, required this.isAdmin});

  /// Raw member map from getGroupMembers().
  /// Expected keys: peerId (String), isAdmin (bool), isSelf (bool).
  final Map<String, dynamic> member;

  /// True if the local user is an admin of this group.
  final bool isAdmin;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    final peerId       = member['peerId']  as String? ?? '';
    final isGroupAdmin = member['isAdmin'] as bool?   ?? false;
    // isSelf is set by the backend when this member entry represents the
    // local node — used to show a "you" chip for self-identification.
    final isSelf       = member['isSelf']  as bool?   ?? false;

    return ListTile(
      dense: true,
      contentPadding: EdgeInsets.zero,
      // Admin members get a highlighted avatar icon; regular members get a plain person icon.
      leading: CircleAvatar(
        radius: 16,
        backgroundColor: isGroupAdmin ? cs.primaryContainer : cs.surfaceContainerHighest,
        child: Icon(
          isGroupAdmin ? Icons.admin_panel_settings_outlined : Icons.person_outline,
          size: 16,
          color: isGroupAdmin ? cs.onPrimaryContainer : cs.onSurfaceVariant,
        ),
      ),
      title: Row(
        children: [
          // Show a truncated peer ID (monospace) as the primary identity.
          // Display names for group members are not yet fetched — this is
          // the raw cryptographic ID that uniquely identifies the member.
          Expanded(
            child: Text(
              peerId.length > 16 ? '${peerId.substring(0, 16)}…' : peerId,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
            ),
          ),
          // "you" chip — only shown for the local node's own member entry so
          // the user can immediately spot themselves in the member list.
          if (isSelf)
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
              decoration: BoxDecoration(
                color: cs.secondaryContainer,
                borderRadius: BorderRadius.circular(8),
              ),
              child: Text(
                'you',
                style: TextStyle(fontSize: 10, color: cs.onSecondaryContainer),
              ),
            ),
        ],
      ),
      // "Admin" label as subtitle for admin members — visible to all viewers.
      subtitle: isGroupAdmin ? const Text('Admin') : null,
    );
  }
}
