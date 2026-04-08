// zeronet_detail_screen.dart
//
// ZeroNetDetailScreen — full management screen for one ZeroNet instance.
//
// STRUCTURE
// ----------
// The screen is organised as a TabBar with three tabs:
//
//   Overview
//     Status card (connection state, node ID, controller, relay mode, counts).
//     Prefer-mesh-relay toggle.
//     Refresh and Disconnect action buttons.
//     Join-network input (text field + Join button).
//
//   Networks
//     Delegates to ZeroNetNetworksPage — the list of joined networks with
//     their authorization state.
//
//   Members
//     Delegates to ZeroNetMembersPage — the controller member roster (only
//     meaningful when this device is the network controller).
//
// NAVIGATION
// -----------
// ZeroNetDetailScreen is pushed from ZeroNetListTile.onTap, receiving the
// instance ID as a constructor argument.  The instance is looked up from
// ZeroTierState inside build() so the screen automatically reflects backend
// mutations (e.g. relay preference changed, new network joined) without
// needing to pass a mutable object across the push.
//
// WHY LOOK UP BY ID RATHER THAN PASSING THE INSTANCE?
// -----------------------------------------------------
// Dart's Navigator.push creates a new widget subtree.  If we passed a
// ZeroNetInstance snapshot, that snapshot would be stale the moment the
// backend mutates.  Looking up the instance from ZeroTierState on every
// build() means the screen is always showing the live state.
//
// Spec ref: §5.23 ZeroTier overlay — instance management.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../backend/backend_bridge.dart';
// BackendBridge — needed for bridge calls (refresh, disconnect, join, relay).

import '../network/network_state.dart';
// OverlayClientStatus — used to decide which actions are available.

import 'models/zeronet_instance.dart';
// ZeroNetInstance — the data model for the displayed instance.

import 'zerotier_state.dart';
// ZeroTierState — source of truth for the instance list.

import 'zeronet_networks_page.dart';
// Networks tab content.

import 'zeronet_members_page.dart';
// Members tab content.

import 'widgets/zeronet_status_card.dart';
// Status summary card shown in the Overview tab.

// ---------------------------------------------------------------------------
// ZeroNetDetailScreen
// ---------------------------------------------------------------------------

/// Full management screen for one ZeroNet instance, with three tabs:
/// Overview, Networks, and Members.
///
/// [instanceId] is the opaque backend ID of the instance to display.
/// If the instance has been deleted while this screen is open, the screen
/// shows a "not found" message rather than crashing.
class ZeroNetDetailScreen extends StatefulWidget {
  /// Opaque backend ID of the ZeroNet instance to display.
  final String instanceId;

  /// Creates a [ZeroNetDetailScreen] for [instanceId].
  const ZeroNetDetailScreen({super.key, required this.instanceId});

  @override
  State<ZeroNetDetailScreen> createState() => _ZeroNetDetailScreenState();
}

class _ZeroNetDetailScreenState extends State<ZeroNetDetailScreen>
    with SingleTickerProviderStateMixin {
  // ---------------------------------------------------------------------------
  // Tab controller
  // ---------------------------------------------------------------------------

  /// Controls the three-tab layout (Overview / Networks / Members).
  ///
  /// Requires [SingleTickerProviderStateMixin] so the controller has an
  /// animation vsync source — without it Flutter throws an assertion.
  late final TabController _tabs;

  // ---------------------------------------------------------------------------
  // Local UI state
  // ---------------------------------------------------------------------------

  /// Controller for the "join network" text input in the Overview tab.
  final _joinCtrl = TextEditingController();

  /// True while a bridge call is in flight (refresh / disconnect / join).
  ///
  /// Disables action buttons to prevent double-submission.
  bool _busy = false;

  /// Error string from the most recent failed action, or null.
  String? _error;

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  @override
  void initState() {
    super.initState();
    // Initialise a TabController for three tabs.
    _tabs = TabController(length: 3, vsync: this);
  }

  @override
  void dispose() {
    // Always dispose controllers to release resources (animation ticker,
    // text editing resources).
    _tabs.dispose();
    _joinCtrl.dispose();
    super.dispose();
  }

  // ---------------------------------------------------------------------------
  // Bridge actions
  // ---------------------------------------------------------------------------

  /// Asks the backend to re-sync this instance from its controller.
  ///
  /// Useful after the network admin changes topology or authorises new members,
  /// or after the device regains connectivity following an offline period.
  Future<void> _refresh(BackendBridge bridge, ZeroTierState state) async {
    _setBusy(true);
    final ok = bridge.zerotierRefreshInstance(widget.instanceId);
    await state.loadAll();
    if (!ok && mounted) {
      _setError(bridge.getLastError() ?? 'Could not refresh');
    }
    _setBusy(false);
  }

  /// Disconnects this instance from the overlay.
  ///
  /// Credentials are retained — the user can reconnect without re-entering
  /// their API key.  Use Delete (from the hub) to fully remove credentials.
  Future<void> _disconnect(BackendBridge bridge, ZeroTierState state) async {
    _setBusy(true);
    final ok = bridge.zerotierDisconnectInstance(widget.instanceId);
    await state.loadAll();
    if (!ok && mounted) {
      _setError(bridge.getLastError() ?? 'Could not disconnect');
    }
    _setBusy(false);
  }

  /// Joins an additional ZeroTier network on this instance.
  ///
  /// Validates the 16-hex-char network ID format before passing to the bridge.
  /// Private networks will show "Pending" authorization until the admin approves.
  Future<void> _joinNetwork(BackendBridge bridge, ZeroTierState state) async {
    final id = _joinCtrl.text.trim();

    // ZeroTier network IDs are exactly 16 hexadecimal characters.
    // The first 10 chars are the controller's node ID; the last 6 identify
    // the network within that controller.  Reject obviously wrong values here
    // rather than surfacing an opaque backend error.
    if (!RegExp(r'^[0-9a-fA-F]{16}$').hasMatch(id)) {
      _setError('Network ID must be exactly 16 hex characters (e.g. 8056c2e21c000001)');
      return;
    }

    _setBusy(true);
    final ok = bridge.zerotierJoinNetworkInstance(widget.instanceId, id);
    await state.loadAll();
    if (!ok && mounted) {
      _setError(bridge.getLastError() ?? 'Could not join network');
    } else if (mounted) {
      // Clear the field on success so the user can type the next network ID.
      _joinCtrl.clear();
      _clearError();
    }
    _setBusy(false);
  }

  /// Toggles the prefer-mesh-relay setting for this instance.
  ///
  /// When enabled the backend routes relayed traffic through Mesh Infinity
  /// relay nodes instead of ZeroTier's PLANET/MOON nodes.
  Future<void> _setRelay(
    BackendBridge bridge,
    ZeroTierState state,
    bool enabled,
  ) async {
    _setBusy(true);
    final ok =
        bridge.zerotierSetPreferMeshRelayInstance(widget.instanceId, enabled);
    await state.loadAll();
    if (!ok && mounted) {
      _setError(bridge.getLastError() ?? 'Could not update relay preference');
    }
    _setBusy(false);
  }

  // ---------------------------------------------------------------------------
  // State helpers
  // ---------------------------------------------------------------------------

  void _setBusy(bool value) {
    if (mounted) setState(() => _busy = value);
  }

  void _setError(String msg) {
    if (mounted) setState(() => _error = msg);
  }

  void _clearError() {
    if (mounted) setState(() => _error = null);
  }

  // ---------------------------------------------------------------------------
  // build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    // Watch ZeroTierState so this screen rebuilds after any mutation.
    final state = context.watch<ZeroTierState>();
    final bridge = context.read<BackendBridge>();

    // Look up the instance by ID — may be null if deleted while screen is open.
    final instance = state.instanceById(widget.instanceId);

    // Guard: instance was deleted while viewing this screen.
    if (instance == null) {
      return Scaffold(
        appBar: AppBar(title: const Text('ZeroNet')),
        body: const Center(
          child: Text('This ZeroNet instance has been removed.'),
        ),
      );
    }

    return Scaffold(
      appBar: AppBar(
        // Use the instance label as the screen title — tells the user which
        // instance they are managing without needing secondary context.
        title: Text(instance.label),

        // Bottom: TabBar anchored to the AppBar.
        bottom: TabBar(
          controller: _tabs,
          tabs: const [
            Tab(text: 'Overview'),
            Tab(text: 'Networks'),
            Tab(text: 'Members'),
          ],
        ),
      ),

      // TabBarView: each child fills the remaining screen height.
      body: TabBarView(
        controller: _tabs,
        children: [
          // ---- Overview tab -----------------------------------------------
          _OverviewTab(
            instance: instance,
            busy: _busy,
            error: _error,
            joinCtrl: _joinCtrl,
            onRefresh: () => _refresh(bridge, state),
            onDisconnect: () => _disconnect(bridge, state),
            onJoin: () => _joinNetwork(bridge, state),
            onSetRelay: (v) => _setRelay(bridge, state, v),
          ),

          // ---- Networks tab -----------------------------------------------
          // Delegates all state and bridge calls to ZeroNetNetworksPage.
          ZeroNetNetworksPage(instanceId: widget.instanceId),

          // ---- Members tab ------------------------------------------------
          // Delegates all state and bridge calls to ZeroNetMembersPage.
          ZeroNetMembersPage(instanceId: widget.instanceId),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _OverviewTab (private)
// ---------------------------------------------------------------------------

/// Overview tab content for [ZeroNetDetailScreen].
///
/// Shows the status card, relay toggle, action buttons (Refresh/Disconnect),
/// and the join-network input.  Extracted from the main State class to keep
/// the build method readable.
class _OverviewTab extends StatelessWidget {
  final ZeroNetInstance instance;
  final bool busy;
  final String? error;
  final TextEditingController joinCtrl;
  final VoidCallback onRefresh;
  final VoidCallback onDisconnect;
  final VoidCallback onJoin;
  final ValueChanged<bool> onSetRelay;

  const _OverviewTab({
    required this.instance,
    required this.busy,
    required this.error,
    required this.joinCtrl,
    required this.onRefresh,
    required this.onDisconnect,
    required this.onJoin,
    required this.onSetRelay,
  });

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    // The instance is "configured" if it has been through the setup flow
    // (status is anything other than notConfigured).
    final isConfigured =
        instance.status != OverlayClientStatus.notConfigured;

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // ---- Status card --------------------------------------------------
        ZeroNetStatusCard(instance: instance),
        const SizedBox(height: 16),

        if (isConfigured) ...[
          // ---- Relay preference toggle -----------------------------------
          // Prefer mesh relay: routes relayed traffic through Mesh Infinity
          // infrastructure instead of ZeroTier's PLANET/MOON nodes.
          // Only useful when using a self-hosted controller — with ZeroTier
          // Central, the control plane already involves ZeroTier's servers.
          SwitchListTile(
            contentPadding: EdgeInsets.zero,
            title: const Text('Prefer mesh relay'),
            subtitle: const Text(
              'Route relayed traffic through Mesh Infinity instead of '
              'ZeroTier PLANET/MOON relay nodes.',
            ),
            value: instance.preferMeshRelay,
            onChanged: busy ? null : onSetRelay,
          ),
          const SizedBox(height: 12),

          // ---- Refresh / Disconnect buttons --------------------------------
          Row(
            children: [
              Expanded(
                child: FilledButton.tonalIcon(
                  onPressed: busy ? null : onRefresh,
                  icon: const Icon(Icons.refresh),
                  label: const Text('Refresh'),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: FilledButton.tonalIcon(
                  onPressed: busy ? null : onDisconnect,
                  icon: const Icon(Icons.link_off),
                  label: const Text('Disconnect'),
                ),
              ),
            ],
          ),
          const SizedBox(height: 24),

          // ---- Join network input -----------------------------------------
          Text('Join Network', style: tt.labelLarge),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(
                child: TextField(
                  controller: joinCtrl,
                  decoration: const InputDecoration(
                    labelText: 'Network ID',
                    hintText: '8056c2e21c000001',
                    border: OutlineInputBorder(),
                    prefixIcon: Icon(Icons.lan_outlined),
                  ),
                  // 16 = exact length of a ZeroTier network ID.
                  maxLength: 16,
                  autocorrect: false,
                  // Allow submission via keyboard "Done" action.
                  onSubmitted: (_) => onJoin(),
                ),
              ),
              const SizedBox(width: 8),
              FilledButton.tonal(
                onPressed: busy ? null : onJoin,
                child: const Text('Join'),
              ),
            ],
          ),
        ],

        // ---- Error banner -------------------------------------------------
        if (error != null) ...[
          const SizedBox(height: 12),
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
                    error!,
                    style:
                        tt.bodySmall?.copyWith(color: cs.onErrorContainer),
                  ),
                ),
              ],
            ),
          ),
        ],
      ],
    );
  }
}
