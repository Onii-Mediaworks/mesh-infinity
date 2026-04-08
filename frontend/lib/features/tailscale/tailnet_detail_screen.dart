// tailnet_detail_screen.dart
//
// TailnetDetailScreen — the full per-instance management screen for one
// Tailscale tailnet.
//
// NAVIGATION
// ----------
// Pushed onto the navigator stack from TailnetListTile.onTap() and from the
// TailscaleHubScreen empty-state call-to-action.  The back button in the
// AppBar pops back to TailscaleHubScreen.
//
// STRUCTURE
// ---------
// The screen uses a TabBar with three tabs:
//
//   Overview    — status card, relay preference toggle, refresh / disconnect
//                 buttons, and a key-expiry warning when appropriate.
//
//   Peers       — delegates to TailnetPeersPage (a stateless widget, not a
//                 full screen) which lists all peers visible in this tailnet.
//
//   Exit Nodes  — delegates to TailnetExitNodePage which provides a dropdown
//                 for selecting or clearing the active exit node.
//
// WHY TABS INSTEAD OF NESTED NAVIGATION?
// ----------------------------------------
// The three content areas (overview, peers, exit nodes) for a single tailnet
// are closely related — they all operate on the same instance.  A tab layout
// keeps them at the same navigation depth and avoids deep push/pop stacks.
// This is consistent with how TailscaleSetupScreen handled all content in a
// single scrollable list, but splits the concerns into distinct tabs so the
// Overview tab isn't overwhelmed by long peer and exit-node lists.
//
// LOADING THE INSTANCE
// --------------------
// The screen receives [instanceId] as a constructor argument and resolves the
// live TailnetInstance from TailscaleState on every build() call via
// context.watch<TailscaleState>().instanceById(instanceId).  This means the
// screen automatically reflects any status changes pushed by the backend
// (e.g. "connecting" → "connected") without any manual refresh.
//
// If instanceById() returns null (the instance was deleted while the detail
// screen was open), the screen shows a "not found" placeholder instead of
// crashing.
//
// Spec reference: §5.22 (multi-instance Tailscale overlay management)

import 'package:flutter/material.dart';
// Scaffold, AppBar, TabBar, TabBarView, DefaultTabController, IconButton.

import 'package:provider/provider.dart';
// context.watch<TailscaleState>(), context.read<TailscaleState>().

import '../../../features/network/network_state.dart';
// OverlayClientStatus — the five-state connection enum used in the disconnect
// button guard and the status card.

import 'tailscale_state.dart';
// TailscaleState — all mutating operations (disconnect, refresh, etc.).

import 'models/tailnet_instance.dart';
// TailnetInstance — the read-only snapshot displayed by this screen.

import 'widgets/tailnet_status_card.dart';
// TailnetStatusCard — the bordered overview card at the top of the Overview tab.

import 'widgets/key_expiry_banner.dart';
// KeyExpiryBanner — amber warning strip shown when the key expires within 7 days.

import 'tailnet_peers_page.dart';
// TailnetPeersPage — the peer list sub-page (used in the Peers tab).

import 'tailnet_exit_node_page.dart';
// TailnetExitNodePage — the exit-node picker sub-page (used in Exit Nodes tab).

// ---------------------------------------------------------------------------
// TailnetDetailScreen
// ---------------------------------------------------------------------------

/// Full management screen for one Tailscale tailnet instance.
///
/// [instanceId] — the opaque UUID of the instance to display.  Resolved to a
///   [TailnetInstance] via TailscaleState on every rebuild.
///
/// Spec reference: §5.22
class TailnetDetailScreen extends StatelessWidget {
  /// Creates a [TailnetDetailScreen] for the instance identified by [instanceId].
  const TailnetDetailScreen({super.key, required this.instanceId});

  /// The opaque backend UUID of the tailnet instance to manage.
  ///
  /// Passed by TailnetListTile.onTap() when it pushes this screen.
  final String instanceId;

  @override
  Widget build(BuildContext context) {
    // Watch TailscaleState so the screen rebuilds when status changes arrive
    // from the event bus (e.g. "connecting" → "connected" after OAuth).
    final state = context.watch<TailscaleState>();
    final instance = state.instanceById(instanceId);

    // Guard: the instance may have been removed while this screen was open
    // (e.g. the user removed it from another screen, or a sync wiped it).
    // Show a placeholder rather than crashing on a null dereference.
    if (instance == null) {
      return Scaffold(
        appBar: AppBar(title: const Text('Tailnet')),
        body: const Center(
          child: Text('This tailnet no longer exists.'),
        ),
      );
    }

    // DefaultTabController manages the tab index state.  Three tabs.
    return DefaultTabController(
      length: 3,
      child: Scaffold(
        appBar: AppBar(
          // The AppBar title is the user-chosen label so the user always knows
          // which tailnet they are managing — especially useful when they have
          // multiple instances with similar names.
          title: Text(instance.label),

          // Delete/disconnect button in the trailing action area.
          // Shows a delete icon that opens a confirmation dialog.
          // We offer delete rather than disconnect here because the detail
          // screen is the "deep" view — quick disconnect is available in the
          // hub list tile's popup menu.
          actions: [
            IconButton(
              icon: const Icon(Icons.delete_outline),
              tooltip: 'Remove this tailnet',
              onPressed: () => _confirmRemove(context, state, instance),
            ),
          ],

          // The TabBar sits at the bottom of the AppBar, beneath the title.
          // This is the standard Material 3 pattern for tabbed content screens.
          bottom: const TabBar(
            tabs: [
              Tab(icon: Icon(Icons.info_outline),      text: 'Overview'),
              Tab(icon: Icon(Icons.people_outline),    text: 'Peers'),
              Tab(icon: Icon(Icons.route_outlined),    text: 'Exit Nodes'),
            ],
          ),
        ),

        body: TabBarView(
          children: [
            // Tab 0: Overview — status, relay toggle, action buttons.
            _OverviewTab(instance: instance, state: state),

            // Tab 1: Peers — list of all peers in this tailnet.
            TailnetPeersPage(instance: instance),

            // Tab 2: Exit Nodes — dropdown picker for the active exit node.
            TailnetExitNodePage(instance: instance),
          ],
        ),
      ),
    );
  }

  // -------------------------------------------------------------------------
  // _confirmRemove
  // -------------------------------------------------------------------------

  /// Show a confirmation dialog and remove the instance if confirmed.
  ///
  /// Removing an instance is irreversible — credentials are deleted from the
  /// backend's keystore.  We require explicit confirmation rather than acting
  /// immediately on a single tap.
  Future<void> _confirmRemove(
    BuildContext context,
    TailscaleState state,
    TailnetInstance instance,
  ) async {
    // Show an AlertDialog to confirm the destructive action.
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Remove tailnet?'),
        content: Text(
          'This will permanently remove "${instance.label}" from Mesh Infinity '
          'and delete its stored credentials. You will need to re-enrol to '
          'reconnect to this tailnet.',
        ),
        actions: [
          // Cancel — close dialog without doing anything.
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('Cancel'),
          ),
          // Confirm — remove and pop this screen.
          FilledButton(
            style: FilledButton.styleFrom(
              backgroundColor: Theme.of(ctx).colorScheme.error,
              foregroundColor: Theme.of(ctx).colorScheme.onError,
            ),
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('Remove'),
          ),
        ],
      ),
    );

    if (confirmed == true && context.mounted) {
      // Delegate to TailscaleState which calls the bridge and reloads.
      final ok = await state.removeInstance(instance.id);
      if (ok && context.mounted) {
        // Pop the detail screen back to the hub — the instance no longer exists.
        Navigator.of(context).pop();
      }
    }
  }
}

// ---------------------------------------------------------------------------
// _OverviewTab
// ---------------------------------------------------------------------------

/// The Overview tab content — status card, relay toggle, action buttons, and
/// the key-expiry warning banner when applicable.
///
/// Extracted into a private widget to keep [TailnetDetailScreen.build()] clean
/// and to give this tab its own rebuild boundary (it watches no additional
/// state beyond what the parent already provides via the [instance] argument).
class _OverviewTab extends StatelessWidget {
  const _OverviewTab({required this.instance, required this.state});

  /// The snapshot of the instance to display.  Passed from the parent build so
  /// this widget does not need to call context.watch again.
  final TailnetInstance instance;

  /// The TailscaleState used to fire bridge calls from the action buttons.
  final TailscaleState state;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    return ListView(
      // Standard screen padding on all sides.
      padding: const EdgeInsets.all(16),
      children: [
        // Key expiry warning — shown at the very top so it is immediately
        // visible when the user opens the overview tab.
        if (instance.isKeyExpiringSoon) ...[
          KeyExpiryBanner(
            daysRemaining: instance.daysUntilKeyExpiry,
            // onReauth calls TailscaleState.reauth() which opens the browser
            // flow for the appropriate controller type.
            onReauth: () => state.reauth(instance.id),
          ),
          const SizedBox(height: 16),
        ],

        // Status card — shows connection state, device IP, controller, etc.
        TailnetStatusCard(instance: instance),
        const SizedBox(height: 20),

        // Relay preference toggle.
        //
        // WHY HERE AND NOT IN SETTINGS?
        // The relay preference is per-tailnet-instance (each instance has its
        // own preferMeshRelay flag).  Putting it here keeps it in context with
        // the instance it affects.
        SwitchListTile(
          contentPadding: EdgeInsets.zero,
          title: const Text('Prefer mesh relay over Tailscale relay'),
          subtitle: const Text(
            'Use Mesh Infinity relay nodes instead of Tailscale DERP servers '
            'when a direct peer path is not available. Avoids Tailscale relay '
            'infrastructure, which can observe connection metadata.',
          ),
          value: instance.preferMeshRelay,
          // Disable while a bridge call is in flight to prevent double-submit.
          onChanged: state.loading
              ? null
              : (value) => state.setPreferMeshRelay(instance.id, value),
        ),
        const SizedBox(height: 16),

        // Action buttons row: Refresh and Disconnect.
        Row(
          children: [
            // Refresh — re-syncs with the control plane.  Useful after peer
            // list changes or ACL updates by the tailnet admin.
            Expanded(
              child: FilledButton.tonalIcon(
                onPressed: state.loading
                    ? null
                    : () => state.refresh(instance.id),
                icon: const Icon(Icons.refresh),
                label: const Text('Refresh'),
              ),
            ),
            const SizedBox(width: 12),
            // Disconnect — severs the WireGuard tunnel without deleting
            // credentials.  The user can reconnect later.
            Expanded(
              child: FilledButton.tonalIcon(
                // Disconnect is only meaningful when connected or connecting.
                onPressed: (state.loading ||
                        instance.status == OverlayClientStatus.disconnected ||
                        instance.status == OverlayClientStatus.notConfigured)
                    ? null
                    : () => state.disconnect(instance.id),
                icon: const Icon(Icons.link_off),
                label: const Text('Disconnect'),
              ),
            ),
          ],
        ),

        // Error message — shown when the last bridge call returned an error.
        if (state.lastError != null) ...[
          const SizedBox(height: 14),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: cs.errorContainer,
              borderRadius: BorderRadius.circular(8),
            ),
            child: Row(
              children: [
                Icon(Icons.error_outline,
                    size: 16, color: cs.onErrorContainer),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    state.lastError!,
                    style: TextStyle(
                      fontSize: 13,
                      color: cs.onErrorContainer,
                    ),
                  ),
                ),
                // Allow the user to dismiss the error.
                IconButton(
                  icon: Icon(Icons.close,
                      size: 16, color: cs.onErrorContainer),
                  padding: EdgeInsets.zero,
                  constraints: const BoxConstraints(),
                  onPressed: state.clearError,
                ),
              ],
            ),
          ),
        ],

        const SizedBox(height: 24),

        // Privacy footnote — consistent with the copy in the old single-
        // instance setup screen.
        Text(
          'Tailscale anonymization score: 0.3 (vendor coordination server) '
          '· Headscale: 0.5 (self-hosted). '
          'Clearnet traffic routed via exit nodes is visible to the exit node '
          'operator. Mesh traffic remains end-to-end encrypted.',
          style: Theme.of(context).textTheme.bodySmall?.copyWith(
                color: cs.onSurfaceVariant,
              ),
          textAlign: TextAlign.center,
        ),
      ],
    );
  }
}
