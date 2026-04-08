// zeronet_list_tile.dart
//
// ZeroNetListTile — a single list tile representing one ZeroNet instance in
// the ZeroTier hub screen.
//
// VISUAL STRUCTURE
// -----------------
//   [Status dot]  Label (title)                    [Priority badge?] [Menu ▾]
//                 Status · Node ID (subtitle)
//
// Leading: a colored circle indicating connection status.  The color follows
// the Mesh Infinity semantic palette: green = connected, amber = connecting,
// grey = disconnected, red = error.
//
// Trailing: an optional PriorityBadge (if this is the priority instance)
// followed by a PopupMenuButton offering per-instance actions (Set Priority,
// Delete).
//
// Tap behaviour: navigates to ZeroNetDetailScreen for the tapped instance,
// giving access to Overview, Networks, and Members tabs.
//
// Spec ref: §5.23 ZeroTier overlay — instance management hub.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../features/tailscale/widgets/priority_badge.dart';
// PriorityBadge lives in the Tailscale directory as the canonical shared
// widget — ZeroTier imports it from there rather than duplicating it.

import '../../network/network_state.dart';
// OverlayClientStatus — the shared connection-state enum.

import '../models/zeronet_instance.dart';
// ZeroNetInstance — the data model rendered by this tile.

import '../zerotier_state.dart';
// ZeroTierState — needed to call setPriority / removeInstance from the menu.

import '../zeronet_detail_screen.dart';
// ZeroNetDetailScreen — pushed when the tile is tapped.

// ---------------------------------------------------------------------------
// ZeroNetListTile
// ---------------------------------------------------------------------------

/// [ListTile] for one ZeroNet instance in the hub screen list.
///
/// Tapping navigates to [ZeroNetDetailScreen].  The trailing popup menu
/// provides Set Priority and Delete actions.
class ZeroNetListTile extends StatelessWidget {
  /// The instance to display.
  final ZeroNetInstance instance;

  /// Whether this instance is the currently designated priority instance.
  final bool isPriority;

  /// Creates a [ZeroNetListTile].
  const ZeroNetListTile({
    super.key,
    required this.instance,
    required this.isPriority,
  });

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    // Status color — follows the Mesh Infinity semantic palette.
    final statusColor = _statusColor(instance.status);

    return ListTile(
      // ---- Leading: status indicator dot ------------------------------------
      // A colored circle is faster to parse than a status icon — the human
      // eye reads color before shape, so the connection state is visible
      // at a glance even in a long list.
      leading: Container(
        width: 36,
        height: 36,
        decoration: BoxDecoration(
          // 15% opacity fill creates a soft halo around the dot.
          color: statusColor.withValues(alpha: 0.15),
          shape: BoxShape.circle,
        ),
        child: Center(
          child: Container(
            width: 10,
            height: 10,
            decoration: BoxDecoration(
              color: statusColor,
              shape: BoxShape.circle,
            ),
          ),
        ),
      ),

      // ---- Title: instance label -------------------------------------------
      title: Text(
        instance.label,
        style: tt.bodyLarge?.copyWith(fontWeight: FontWeight.w500),
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
      ),

      // ---- Subtitle: status + node ID -------------------------------------
      // Combines the human-readable status string and the node ID (if known)
      // separated by a center dot — compact but information-rich.
      subtitle: Text(
        _buildSubtitle(),
        style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
      ),

      // ---- Trailing: priority badge + menu --------------------------------
      trailing: Row(
        // Row must be constrained: trailing area has a limited width and
        // Row is unbounded by default.  mainAxisSize.min collapses to content.
        mainAxisSize: MainAxisSize.min,
        children: [
          // Show PriorityBadge only for the priority instance.
          if (isPriority) ...[
            const PriorityBadge(),
            const SizedBox(width: 4),
          ],

          // Per-instance action menu.
          _InstanceMenu(instance: instance, isPriority: isPriority),
        ],
      ),

      // ---- Tap: open detail screen ----------------------------------------
      onTap: () {
        Navigator.of(context).push(
          MaterialPageRoute<void>(
            builder: (_) => ZeroNetDetailScreen(instanceId: instance.id),
          ),
        );
      },
    );
  }

  // ---------------------------------------------------------------------------
  // _buildSubtitle
  // ---------------------------------------------------------------------------

  /// Builds the subtitle string from status label and node ID.
  String _buildSubtitle() {
    final parts = <String>[_statusLabel(instance.status)];

    // Append node ID if known — gives experts a quick reference without
    // needing to open the detail screen.
    final nodeId = instance.nodeId;
    if (nodeId != null && nodeId.isNotEmpty) {
      // Truncate to first 6 chars so it fits in the subtitle line on narrow
      // screens (full 10-char node IDs overflow on small phones).
      parts.add('${nodeId.substring(0, nodeId.length.clamp(0, 6))}…');
    }

    return parts.join(' · ');
  }

  // ---------------------------------------------------------------------------
  // Static helpers
  // ---------------------------------------------------------------------------

  /// Human-readable status label.
  static String _statusLabel(OverlayClientStatus s) => switch (s) {
    OverlayClientStatus.notConfigured => 'Not configured',
    OverlayClientStatus.connecting    => 'Connecting',
    OverlayClientStatus.connected     => 'Connected',
    OverlayClientStatus.disconnected  => 'Disconnected',
    OverlayClientStatus.error         => 'Error',
  };

  /// Semantic color from the Mesh Infinity palette for the given status.
  static Color _statusColor(OverlayClientStatus s) => switch (s) {
    OverlayClientStatus.connected     => const Color(0xFF22C55E), // secGreen
    OverlayClientStatus.connecting    => const Color(0xFFF59E0B), // secAmber
    OverlayClientStatus.disconnected  => const Color(0xFF9CA3AF), // neutral
    OverlayClientStatus.error         => const Color(0xFFEF4444), // secRed
    OverlayClientStatus.notConfigured => const Color(0xFF9CA3AF), // neutral
  };
}

// ---------------------------------------------------------------------------
// _InstanceMenu (private)
// ---------------------------------------------------------------------------

/// PopupMenuButton providing per-instance actions: Set Priority and Delete.
///
/// Extracted from [ZeroNetListTile] to keep the tile's build method readable.
class _InstanceMenu extends StatelessWidget {
  final ZeroNetInstance instance;
  final bool isPriority;

  const _InstanceMenu({required this.instance, required this.isPriority});

  @override
  Widget build(BuildContext context) {
    return PopupMenuButton<_Action>(
      // Small icon keeps the trailing area compact.
      icon: const Icon(Icons.more_vert),
      onSelected: (action) => _handle(context, action),
      itemBuilder: (_) => [
        // "Set as priority" — only shown when this instance is NOT already
        // the priority.  Showing it when already priority would be a no-op
        // and confusing.
        if (!isPriority)
          const PopupMenuItem(
            value: _Action.setPriority,
            child: ListTile(
              leading: Icon(Icons.star_outline),
              title: Text('Set as priority'),
              contentPadding: EdgeInsets.zero,
            ),
          ),

        // "Delete" — always available.  Shows a confirmation dialog before
        // calling removeInstance to guard against accidental taps.
        const PopupMenuItem(
          value: _Action.delete,
          child: ListTile(
            leading: Icon(Icons.delete_outline),
            title: Text('Delete'),
            contentPadding: EdgeInsets.zero,
          ),
        ),
      ],
    );
  }

  // ---------------------------------------------------------------------------
  // _handle
  // ---------------------------------------------------------------------------

  /// Dispatches the selected menu action.
  Future<void> _handle(BuildContext context, _Action action) async {
    switch (action) {
      case _Action.setPriority:
        // Set this instance as the overlay routing priority.
        // The state calls the bridge then reloads.
        await context.read<ZeroTierState>().setPriority(instance.id);

      case _Action.delete:
        // Confirm before deletion — data loss is not reversible.
        final confirmed = await _confirmDelete(context);
        if (confirmed && context.mounted) {
          await context.read<ZeroTierState>().removeInstance(instance.id);
        }
    }
  }

  // ---------------------------------------------------------------------------
  // _confirmDelete
  // ---------------------------------------------------------------------------

  /// Shows a confirmation AlertDialog before deleting the instance.
  ///
  /// Returns true if the user confirmed, false if they cancelled.
  Future<bool> _confirmDelete(BuildContext context) async {
    final result = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Delete ZeroNet?'),
        content: Text(
          'This will disconnect "${instance.label}" and remove its stored '
          'credentials. You will need to re-enter your API key to reconnect.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            // Red fill signals a destructive action.
            style: FilledButton.styleFrom(
              backgroundColor: const Color(0xFFEF4444), // secRed
              foregroundColor: Colors.white,
            ),
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Delete'),
          ),
        ],
      ),
    );
    return result ?? false;
  }
}

// ---------------------------------------------------------------------------
// _Action (private enum)
// ---------------------------------------------------------------------------

/// Menu actions for [_InstanceMenu].
enum _Action {
  /// Mark this instance as the priority for overlay routing.
  setPriority,

  /// Remove this instance and clear its credentials.
  delete,
}
