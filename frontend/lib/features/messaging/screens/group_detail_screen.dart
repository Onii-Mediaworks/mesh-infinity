import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../../../backend/backend_bridge.dart';
import '../../../backend/models/peer_models.dart';
import '../messaging_state.dart';

/// Group detail screen — shows members, admin controls, and group settings.
///
/// Navigated to from ThreadScreen when the room is a group room.
class GroupDetailScreen extends StatefulWidget {
  const GroupDetailScreen({super.key, required this.groupId});

  final String groupId;

  @override
  State<GroupDetailScreen> createState() => _GroupDetailScreenState();
}

class _GroupDetailScreenState extends State<GroupDetailScreen> {
  Map<String, dynamic>? _groupInfo;
  List<Map<String, dynamic>> _members = [];
  bool _loading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() { _loading = true; _error = null; });
    final bridge = context.read<BackendBridge>();

    final groups = bridge.listGroups();
    final matching = groups.where(
      (g) => (g['groupId'] as String?) == widget.groupId,
    );
    final group = matching.isNotEmpty ? matching.first : null;

    final members = bridge.getGroupMembers(widget.groupId);

    setState(() {
      _groupInfo = group;
      _members = members;
      _loading = false;
      if (group == null) _error = 'Group not found';
    });
  }

  Future<void> _leaveGroup() async {
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
    if (confirmed != true || !mounted) return;

    final bridge = context.read<BackendBridge>();
    final ok = bridge.leaveGroup(widget.groupId);
    if (!mounted) return;

    if (ok) {
      await context.read<MessagingState>().loadRooms();
      if (mounted) {
        // Pop back to conversation list.
        Navigator.of(context)
          ..pop()   // group detail
          ..pop();  // thread
      }
    } else {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Failed to leave group')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }
    if (_error != null) {
      return Scaffold(body: Center(child: Text(_error!)));
    }

    final cs = Theme.of(context).colorScheme;
    final name = _groupInfo?['name'] as String? ?? 'Group';
    final description = _groupInfo?['description'] as String? ?? '';
    final networkType = _groupInfo?['networkType'] as String? ?? 'private';
    final isAdmin = _groupInfo?['isAdmin'] as bool? ?? false;
    final groupId = widget.groupId;

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
            // Group avatar + name
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
                  _NetworkTypeBadge(networkType: networkType),
                ],
              ),
            ),

            const SizedBox(height: 24),

            // Group ID
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

            // Members
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
                      ..._members.map((m) => _MemberTile(member: m, isAdmin: isAdmin)),
                  ],
                ),
              ),
            ),

            const SizedBox(height: 12),

            // Admin status
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

            // Leave group
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

  Future<void> _invitePeer() async {
    final bridge = context.read<BackendBridge>();
    final allPeers = bridge.fetchPeers();

    // Exclude peers already in this group.
    final memberIds = _members.map((m) => m['peerId'] as String? ?? '').toSet();
    final candidates = allPeers.where((p) => !memberIds.contains(p.id)).toList();

    if (candidates.isEmpty) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('All known peers are already in this group')),
        );
      }
      return;
    }

    if (!mounted) return;
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
                    subtitle: Text(
                      peer.id.length > 16 ? '${peer.id.substring(0, 16)}…' : peer.id,
                      style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
                    ),
                    onTap: () => Navigator.pop(ctx, peer),
                  );
                },
              ),
            ),
          ],
        ),
      ),
    );

    if (selected == null || !mounted) return;

    final ok = bridge.inviteToGroup(widget.groupId, selected.id);
    if (!mounted) return;

    if (ok) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('${selected.name} invited to group')),
      );
      await _load();
    } else {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Failed to invite ${selected.name}')),
      );
    }
  }
}

class _NetworkTypeBadge extends StatelessWidget {
  const _NetworkTypeBadge({required this.networkType});

  final String networkType;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final (label, color) = switch (networkType.toLowerCase()) {
      'private' => ('Private', cs.error),
      'closed'  => ('Closed',  cs.tertiary),
      'open'    => ('Open',    cs.primary),
      'public'  => ('Public',  Colors.green),
      _         => ('Unknown', cs.outline),
    };
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      decoration: BoxDecoration(
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

class _MemberTile extends StatelessWidget {
  const _MemberTile({required this.member, required this.isAdmin});

  final Map<String, dynamic> member;
  final bool isAdmin;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final peerId = member['peerId'] as String? ?? '';
    final isGroupAdmin = member['isAdmin'] as bool? ?? false;
    final isSelf = member['isSelf'] as bool? ?? false;

    return ListTile(
      dense: true,
      contentPadding: EdgeInsets.zero,
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
          Expanded(
            child: Text(
              peerId.length > 16 ? '${peerId.substring(0, 16)}…' : peerId,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
            ),
          ),
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
      subtitle: isGroupAdmin ? const Text('Admin') : null,
    );
  }
}
