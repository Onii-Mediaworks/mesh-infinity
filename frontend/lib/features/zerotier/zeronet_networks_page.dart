// zeronet_networks_page.dart
//
// ZeroNetNetworksPage — the Networks tab content for ZeroNetDetailScreen.
//
// PURPOSE
// --------
// Shows all ZeroTier networks that the given instance has joined.  For each
// network the user can see:
//   • Network name (or ID as fallback)
//   • Network ID (16 hex chars, monospace for readability)
//   • Assigned virtual IP address
//   • Authorization status chip (authorized / pending / unauthorized)
//   • Member count
//
// JOIN NETWORK
// -------------
// A "Join Network" row at the bottom of the list lets the user add more
// networks without returning to the Overview tab.  The input is a standalone
// text field + "Join" button validated against the 16-hex-char format.
//
// EMPTY STATE
// ------------
// When no networks are joined yet, a centered call-to-action tells the user
// to use the join input below — rather than just showing a blank list.
//
// DATA SOURCE
// ------------
// Networks are extracted from the ZeroNetInstance returned by ZeroTierState.
// The instance is re-fetched on every build() so the list reflects mutations
// (e.g. a successful join) without needing extra streams.
//
// Spec ref: §5.23 ZeroTier overlay — network membership.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../backend/backend_bridge.dart';
// BackendBridge — for the join-network bridge call.

import 'models/zeronet_instance.dart';
import 'models/zeronet_network.dart';
// ZeroNetNetwork + ZeroNetAuthStatus — data model for one network.

import 'zerotier_state.dart';
// ZeroTierState — provides the instance and handles state refresh.

import 'widgets/network_auth_chip.dart';
// NetworkAuthChip — compact authorization status indicator.

// ---------------------------------------------------------------------------
// ZeroNetNetworksPage
// ---------------------------------------------------------------------------

/// Networks tab for [ZeroNetDetailScreen].
///
/// Lists all networks joined by the specified ZeroNet instance and provides
/// a bottom join-network input row.
class ZeroNetNetworksPage extends StatefulWidget {
  /// Opaque backend ID of the ZeroNet instance whose networks are shown.
  final String instanceId;

  /// Creates a [ZeroNetNetworksPage] for [instanceId].
  const ZeroNetNetworksPage({super.key, required this.instanceId});

  @override
  State<ZeroNetNetworksPage> createState() => _ZeroNetNetworksPageState();
}

class _ZeroNetNetworksPageState extends State<ZeroNetNetworksPage> {
  // ---------------------------------------------------------------------------
  // Local UI state
  // ---------------------------------------------------------------------------

  /// Text controller for the join-network ID input field.
  final _networkIdCtrl = TextEditingController();

  /// True while a join bridge call is in flight.
  bool _joining = false;

  /// Error from the most recent failed join attempt, or null.
  String? _error;

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  @override
  void dispose() {
    _networkIdCtrl.dispose();
    super.dispose();
  }

  // ---------------------------------------------------------------------------
  // _joinNetwork
  // ---------------------------------------------------------------------------

  /// Validates the network ID and calls the bridge to join.
  ///
  /// ZeroTier network IDs are exactly 16 hexadecimal characters.  Private
  /// networks will show "Pending" authorization until the controller admin
  /// approves the membership request.
  Future<void> _joinNetwork() async {
    final id = _networkIdCtrl.text.trim();

    // Client-side validation — catches obvious mistakes before hitting the
    // backend.  The backend will also reject invalid IDs, but this gives
    // faster and friendlier feedback.
    if (!RegExp(r'^[0-9a-fA-F]{16}$').hasMatch(id)) {
      setState(() {
        _error =
            'Network ID must be exactly 16 hex characters (e.g. 8056c2e21c000001)';
      });
      return;
    }

    setState(() {
      _joining = true;
      _error = null;
    });

    final bridge = context.read<BackendBridge>();
    final state = context.read<ZeroTierState>();

    final ok = bridge.zerotierJoinNetworkInstance(widget.instanceId, id);
    await state.loadAll();

    if (!mounted) return;

    if (!ok) {
      setState(() {
        _error = bridge.getLastError() ?? 'Could not join network';
        _joining = false;
      });
    } else {
      setState(() {
        _networkIdCtrl.clear();
        _joining = false;
      });
    }
  }

  // ---------------------------------------------------------------------------
  // build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    // Watch ZeroTierState to rebuild when the instance reloads after a join.
    final state = context.watch<ZeroTierState>();
    final instance = state.instanceById(widget.instanceId);

    // Extract the networks list from the instance's raw overlay map.
    // The backend embeds a 'networks' array in the JSON response for this
    // instance.  We fall back to an empty list if absent.
    final networks = _parseNetworks(instance);

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // ---- Header -------------------------------------------------------
        Text('Joined Networks', style: tt.labelLarge),
        const SizedBox(height: 12),

        // ---- Empty state --------------------------------------------------
        if (networks.isEmpty)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 24),
            child: Column(
              children: [
                Icon(
                  Icons.lan_outlined,
                  size: 48,
                  color: cs.onSurfaceVariant.withValues(alpha: 0.4),
                ),
                const SizedBox(height: 12),
                Text(
                  'No networks joined yet.',
                  style: tt.bodyMedium?.copyWith(color: cs.onSurfaceVariant),
                ),
                const SizedBox(height: 4),
                Text(
                  'Use the form below to join a ZeroTier network by ID.',
                  style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
                  textAlign: TextAlign.center,
                ),
              ],
            ),
          ),

        // ---- Network list -------------------------------------------------
        for (final network in networks) _NetworkRow(network: network),

        const SizedBox(height: 24),
        const Divider(),
        const SizedBox(height: 16),

        // ---- Join network input -------------------------------------------
        Text('Join Another Network', style: tt.labelLarge),
        const SizedBox(height: 8),
        Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(
              child: TextField(
                controller: _networkIdCtrl,
                decoration: const InputDecoration(
                  labelText: 'Network ID',
                  hintText: '8056c2e21c000001',
                  border: OutlineInputBorder(),
                  prefixIcon: Icon(Icons.lan_outlined),
                ),
                // Exact length of a ZeroTier network ID.
                maxLength: 16,
                autocorrect: false,
                onSubmitted: (_) => _joinNetwork(),
              ),
            ),
            const SizedBox(width: 8),
            Padding(
              // Align button with text field (offset for the label height).
              padding: const EdgeInsets.only(top: 4),
              child: FilledButton.tonal(
                onPressed: _joining ? null : _joinNetwork,
                child: _joining
                    ? const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Text('Join'),
              ),
            ),
          ],
        ),

        // ---- Error banner ------------------------------------------------
        if (_error != null) ...[
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
                    _error!,
                    style:
                        tt.bodySmall?.copyWith(color: cs.onErrorContainer),
                  ),
                ),
              ],
            ),
          ),
        ],

        // ---- Footer note -------------------------------------------------
        const SizedBox(height: 16),
        Text(
          'Private networks require admin approval before traffic flows. '
          'Your Node ID will be visible to the network admin.',
          style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
        ),
      ],
    );
  }

  // ---------------------------------------------------------------------------
  // _parseNetworks
  // ---------------------------------------------------------------------------

  /// Extracts the network list from the backend state for this instance.
  ///
  /// The ZeroTierState / ZeroNetInstance model carries a summary count but
  /// not the full network list (keeping the model light).  The backend embeds
  /// the full list in a `networks` JSON field accessible via the raw overlay
  /// map.  We decode it here so the page is self-contained.
  ///
  /// Falls back to an empty list if the data is missing or malformed.
  List<ZeroNetNetwork> _parseNetworks(dynamic instance) {
    // ZeroNetInstance now carries the full networks list directly — populated
    // from the `networks` array in zerotierListInstances (§5.23).  We accept
    // `dynamic` to keep the call-site flexible, but cast safely here.
    if (instance is ZeroNetInstance) return instance.networks;
    return const [];
  }
}

// ---------------------------------------------------------------------------
// _NetworkRow (private)
// ---------------------------------------------------------------------------

/// A single row in the networks list showing name, ID, IP, auth chip, and
/// member count.
class _NetworkRow extends StatelessWidget {
  /// The network to display.
  final ZeroNetNetwork network;

  const _NetworkRow({required this.network});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Leading icon: represents a LAN segment.
          Padding(
            padding: const EdgeInsets.only(top: 2, right: 12),
            child: Icon(
              Icons.lan_outlined,
              size: 20,
              color: cs.onSurfaceVariant,
            ),
          ),

          // Content column: name, ID, IP.
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Primary: display name (or ID if unnamed).
                Text(
                  network.displayName,
                  style: tt.bodyMedium
                      ?.copyWith(fontWeight: FontWeight.w500),
                ),

                // Secondary: network ID in monospace for readability.
                if (network.name != null && network.name!.isNotEmpty)
                  Text(
                    network.networkId,
                    style: tt.bodySmall?.copyWith(
                      color: cs.onSurfaceVariant,
                      fontFamily: 'monospace',
                    ),
                  ),

                // Tertiary: assigned IP if one has been allocated.
                if (network.assignedIp != null &&
                    network.assignedIp!.isNotEmpty)
                  Text(
                    network.assignedIp!,
                    style: tt.bodySmall?.copyWith(
                      color: cs.onSurfaceVariant,
                      fontFamily: 'monospace',
                    ),
                  ),
              ],
            ),
          ),

          // Trailing: auth status chip + member count.
          Column(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              NetworkAuthChip(status: network.authStatus),
              const SizedBox(height: 4),
              Text(
                '${network.memberCount} members',
                style: tt.labelSmall
                    ?.copyWith(color: cs.onSurfaceVariant),
              ),
            ],
          ),
        ],
      ),
    );
  }
}
