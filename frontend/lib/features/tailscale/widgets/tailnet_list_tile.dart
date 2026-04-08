// tailnet_list_tile.dart
//
// TailnetListTile — a ListTile-based widget representing one tailnet instance
// in the TailscaleHubScreen list.
//
// WHAT THIS WIDGET SHOWS
// ----------------------
// Each row in the hub screen's list shows:
//   - Leading: coloured circle icon reflecting the instance's connection status.
//   - Title:   the user-chosen label ("Work", "Home", etc.).
//   - Subtitle: status string + tailnet name or controller URL.
//   - Trailing: PriorityBadge (if this is the priority instance) +
//              PopupMenuButton with instance actions.
//
// TAP BEHAVIOUR
// -------------
// Tapping the tile navigates to TailnetDetailScreen for that instance.  The
// navigation uses Navigator.push so the detail screen appears on top of the
// hub and the back button returns to the hub.
//
// POPUP MENU ACTIONS
// ------------------
//   Set Priority — only shown when there is more than one instance AND this
//     is not already the priority instance.
//   Disconnect  — only shown when the instance is currently connected.
//   Remove      — always shown; confirmation is handled in TailscaleHubScreen.
//
// WHY SEPARATE FROM THE HUB SCREEN?
// ----------------------------------
// TailscaleHubScreen builds a list of these tiles; extracting the tile into
// its own file keeps the hub screen focused on layout/orchestration rather
// than the per-item rendering detail.  It also makes it easy to reuse the
// tile in a future "quick overview" widget without duplicating code.

import 'package:flutter/material.dart';
// ListTile, PopupMenuButton, Icon, Text, etc.

import 'package:provider/provider.dart';
// context.read<TailscaleState>() — fire-and-forget calls to state.

import '../../../features/network/network_state.dart';
// OverlayClientStatus — the five-state connection enum used by TailnetInstance.
// Imported here so _statusLabel() and the switch expressions compile.

import '../tailscale_state.dart';
// TailscaleState — the ChangeNotifier that handles all bridge calls.

import '../models/tailnet_instance.dart';
// TailnetInstance — the data model for one tailnet.

import 'priority_badge.dart';
// PriorityBadge — the compact star badge shown on the priority instance.

import '../tailnet_detail_screen.dart';
// TailnetDetailScreen — the full management screen for one instance.
// This file is created alongside tailnet_list_tile.dart in the same session;
// the "target doesn't exist" diagnostic clears as soon as that file is written.

// ---------------------------------------------------------------------------
// TailnetListTile
// ---------------------------------------------------------------------------

/// A list tile representing one [TailnetInstance] in [TailscaleHubScreen].
///
/// Tapping the tile navigates to [TailnetDetailScreen].  The trailing popup
/// menu provides quick-access actions (set priority, disconnect, remove).
///
/// [isPriority]      — true when this instance is the priority tailnet.
///   Renders a [PriorityBadge] in the trailing area when true.
///
/// [totalInstances]  — the total number of instances currently managed.
///   Used to conditionally show the "Set Priority" menu item (only relevant
///   when there is more than one instance).
///
/// [onRemoveRequest] — called when the user selects "Remove" from the popup
///   menu.  The parent (TailscaleHubScreen) shows a confirmation dialog and
///   then calls TailscaleState.removeInstance().  This keeps the confirmation
///   UI in one place and the tile widget stateless.
class TailnetListTile extends StatelessWidget {
  /// Creates a [TailnetListTile] for the given [instance].
  const TailnetListTile({
    super.key,
    required this.instance,
    required this.isPriority,
    required this.totalInstances,
    required this.onRemoveRequest,
  });

  /// The tailnet instance this tile represents.
  final TailnetInstance instance;

  /// True when this instance is the currently designated priority instance.
  ///
  /// Renders a [PriorityBadge] in compact mode in the trailing section when
  /// true.
  final bool isPriority;

  /// Total number of tailnet instances currently managed.
  ///
  /// The "Set Priority" action is only meaningful when there are two or more
  /// instances, so it is hidden when [totalInstances] <= 1.
  final int totalInstances;

  /// Called when the user selects "Remove" from the popup menu.
  ///
  /// The parent widget is responsible for showing a confirmation dialog.
  final VoidCallback onRemoveRequest;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    // Leading icon — a filled circle whose colour reflects the connection status.
    //
    // The circle-fill / outline split gives at-a-glance connectivity info:
    //   connected   → solid green primary
    //   connecting  → solid amber (tertiary)
    //   disconnected → outlined grey
    //   error       → solid red
    //   not configured → outlined grey
    final (IconData leadingIcon, Color leadingColor) = switch (instance.status) {
      OverlayClientStatus.connected     => (Icons.circle,          cs.primary),
      OverlayClientStatus.connecting    => (Icons.circle,          cs.tertiary),
      OverlayClientStatus.disconnected  => (Icons.circle_outlined, cs.outline),
      OverlayClientStatus.error         => (Icons.circle,          cs.error),
      OverlayClientStatus.notConfigured => (Icons.circle_outlined, cs.outline),
    };

    // Subtitle line: status string + tailnet name (or controller) when known.
    final String statusLabel = _statusLabel(instance.status);
    final String? secondaryInfo = instance.tailnetName?.isNotEmpty == true
        ? instance.tailnetName
        : (instance.controller?.isNotEmpty == true ? instance.controller : null);
    final String subtitleText = secondaryInfo != null
        ? '$statusLabel · $secondaryInfo'
        : statusLabel;

    return ListTile(
      // Left icon: connection status circle.
      leading: Icon(leadingIcon, size: 16, color: leadingColor),

      // Main label: the user-assigned tailnet name.
      title: Row(
        children: [
          // Label text wraps if very long, but the Row keeps it and the badge
          // on the same line where space allows.
          Flexible(
            child: Text(
              instance.label,
              overflow: TextOverflow.ellipsis,
              style: tt.bodyLarge,
            ),
          ),
          if (isPriority) ...[
            const SizedBox(width: 6),
            // Compact badge — no text, just the star — to keep the row tight.
            const PriorityBadge(compact: true),
          ],
        ],
      ),

      // Status + tailnet name as subtitle.
      subtitle: Text(
        subtitleText,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
      ),

      // Trailing: popup menu with instance-scoped actions.
      trailing: _ActionMenu(
        instance: instance,
        isPriority: isPriority,
        totalInstances: totalInstances,
        onRemoveRequest: onRemoveRequest,
      ),

      // Tap → push TailnetDetailScreen for this instance.
      onTap: () => Navigator.of(context).push(
        MaterialPageRoute<void>(
          builder: (_) => TailnetDetailScreen(instanceId: instance.id),
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _ActionMenu — private popup menu widget
// ---------------------------------------------------------------------------

/// The trailing popup menu for one tailnet list tile.
///
/// Provides quick-access actions without requiring the user to navigate into
/// the detail screen.  The available actions adapt based on current state
/// (e.g. "Set Priority" is only offered when relevant).
class _ActionMenu extends StatelessWidget {
  const _ActionMenu({
    required this.instance,
    required this.isPriority,
    required this.totalInstances,
    required this.onRemoveRequest,
  });

  final TailnetInstance instance;
  final bool isPriority;
  final int totalInstances;
  final VoidCallback onRemoveRequest;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    return PopupMenuButton<_MenuAction>(
      // Icon used for the "more options" button — standard three-dot menu.
      icon: Icon(Icons.more_vert, color: cs.onSurfaceVariant),
      // Tooltip for accessibility.
      tooltip: 'Instance actions',
      onSelected: (action) => _handleAction(context, action),
      itemBuilder: (ctx) => [
        // "Set Priority" — only shown when:
        //   - there is more than one instance (priority only matters then), AND
        //   - this instance is not already the priority.
        if (totalInstances > 1 && !isPriority)
          const PopupMenuItem<_MenuAction>(
            value: _MenuAction.setPriority,
            child: ListTile(
              leading: Icon(Icons.star_outline),
              title: Text('Set as priority'),
              dense: true,
              contentPadding: EdgeInsets.zero,
            ),
          ),

        // "Disconnect" — only when the instance is currently connected.
        if (instance.status == OverlayClientStatus.connected)
          const PopupMenuItem<_MenuAction>(
            value: _MenuAction.disconnect,
            child: ListTile(
              leading: Icon(Icons.link_off_outlined),
              title: Text('Disconnect'),
              dense: true,
              contentPadding: EdgeInsets.zero,
            ),
          ),

        // "Remove" — always available.  Shown last and styled with the error
        // colour to communicate that this is a destructive action.
        PopupMenuItem<_MenuAction>(
          value: _MenuAction.remove,
          child: ListTile(
            leading: Icon(Icons.delete_outline, color: cs.error),
            title: Text('Remove', style: TextStyle(color: cs.error)),
            dense: true,
            contentPadding: EdgeInsets.zero,
          ),
        ),
      ],
    );
  }

  /// Dispatch a selected popup menu action to TailscaleState.
  void _handleAction(BuildContext context, _MenuAction action) {
    // We use context.read (not watch) because this is a one-shot write
    // operation, not a subscription.
    final state = context.read<TailscaleState>();

    switch (action) {
      case _MenuAction.setPriority:
        // Delegate to TailscaleState — it handles the bridge call and reload.
        state.setPriority(instance.id);

      case _MenuAction.disconnect:
        state.disconnect(instance.id);

      case _MenuAction.remove:
        // The tile delegates confirmation to the parent so the tile stays
        // stateless.  The parent calls state.removeInstance() after confirm.
        onRemoveRequest();
    }
  }
}

// ---------------------------------------------------------------------------
// Private enums and helpers
// ---------------------------------------------------------------------------

/// The set of actions available in the instance popup menu.
enum _MenuAction {
  /// Designate this instance as the routing-priority tailnet.
  setPriority,
  /// Disconnect without removing credentials.
  disconnect,
  /// Permanently remove this instance (with confirmation from parent).
  remove,
}

/// Convert [OverlayClientStatus] to a concise human-readable label.
///
/// Used in the tile subtitle.  Kept short (one word) so it fits alongside
/// the tailnet name without overflowing into the trailing area.
String _statusLabel(OverlayClientStatus s) => switch (s) {
  OverlayClientStatus.notConfigured => 'Not configured',
  OverlayClientStatus.connecting    => 'Connecting',
  OverlayClientStatus.connected     => 'Connected',
  OverlayClientStatus.disconnected  => 'Disconnected',
  OverlayClientStatus.error         => 'Error',
};
