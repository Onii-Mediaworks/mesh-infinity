// tailnet_exit_node_page.dart
//
// TailnetExitNodePage — the Exit Nodes tab content for one tailnet instance.
//
// WHAT IS A TAILSCALE EXIT NODE?
// --------------------------------
// An exit node is a peer in the tailnet that advertises a default route
// (0.0.0.0/0) — meaning all internet-destined traffic from this device is
// tunnelled through the exit node's outgoing connection.  From the perspective
// of websites and remote services, the traffic appears to originate from the
// exit node's IP address rather than this device's real IP.
//
// WHY USE AN EXIT NODE?
// ----------------------
// Common use cases:
//   - Route corporate traffic through an office node to satisfy a firewall
//     policy or access intranet resources.
//   - Use a home server as an exit node while travelling to appear to be
//     at home (useful for geo-restricted services).
//   - Route traffic through a trusted peer instead of a commercial VPN,
//     keeping the exit point under the user's own control.
//
// PRIVACY CAVEAT
// --------------
// The exit node operator CAN see which internet destinations are being
// accessed (clearnet destinations after traffic leaves the tunnel).
// This is disclosed in the privacy notice at the bottom of this page.
// End-to-end encrypted Mesh Infinity traffic is NOT visible to the exit node.
//
// WHY A PAGE WIDGET AND NOT A SCREEN?
// ------------------------------------
// Same reason as TailnetPeersPage — this content lives inside a TabBarView
// in TailnetDetailScreen and is not pushed onto the navigator stack.  Data
// flows in via the TailnetInstance constructor argument; mutations go through
// TailscaleState read from context.

import 'package:flutter/material.dart';
// Material widgets: ListView, DropdownButtonFormField, TextButton, Column, etc.

import 'package:provider/provider.dart';
// context.read<TailscaleState>() — for firing exit-node set/clear calls.

import 'tailscale_state.dart';
// TailscaleState — mediates all bridge calls.

import 'models/tailnet_instance.dart';
// TailnetInstance — carries the peer list and active exit node.
// TailnetPeer — individual peer model (we filter for isExitNode == true).

// ---------------------------------------------------------------------------
// TailnetExitNodePage
// ---------------------------------------------------------------------------

/// The Exit Nodes tab content shown inside [TailnetDetailScreen].
///
/// Provides a [DropdownButtonFormField] listing peers that advertise exit-node
/// capability, a privacy notice, and a "Clear exit node" button.
///
/// State changes (selecting a new exit node, clearing it) are dispatched
/// through [TailscaleState] which calls the appropriate bridge method and
/// reloads the instance list.
///
/// Spec reference: §5.22 (multi-instance overlay exit node selection)
class TailnetExitNodePage extends StatelessWidget {
  /// Creates a [TailnetExitNodePage] for the given [instance].
  const TailnetExitNodePage({super.key, required this.instance});

  /// The tailnet instance whose exit-node configuration to manage.
  final TailnetInstance instance;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    // Filter the peer list to only those that advertise exit-node capability.
    // Only these peers should appear in the dropdown.
    final exitNodes = instance.exitNodePeers;

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // Section header.
        Text('Exit Node', style: tt.labelLarge),
        const SizedBox(height: 8),

        // Explanatory note — helps users who are unfamiliar with exit nodes
        // understand what they are about to configure.
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: cs.primaryContainer.withValues(alpha: 0.35),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Text(
            'An exit node routes your internet-bound traffic through another '
            'device in this tailnet. Websites see the exit node\'s IP address '
            'instead of yours.',
            style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
          ),
        ),
        const SizedBox(height: 20),

        // No-exit-nodes state — shown when no peers advertise exit capability.
        if (exitNodes.isEmpty) ...[
          _NoExitNodesPlaceholder(cs: cs, tt: tt),
        ] else ...[
          // Dropdown for selecting the active exit node.
          //
          // DropdownButtonFormField is used (rather than plain DropdownButton)
          // because it provides the InputDecoration border and label, matching
          // the style of TextFields in TailnetSetupSheet.
          //
          // The value is the peer name string (or empty string = no exit node).
          // An empty-string sentinel item ("None") is always the first entry.
          DropdownButtonFormField<String>(
            // Show the currently active exit node as the selected value.
            // Fall back to empty string (None) when no exit node is set.
            initialValue: instance.activeExitNode ?? '',
            decoration: const InputDecoration(
              labelText: 'Active exit node',
              border: OutlineInputBorder(),
              prefixIcon: Icon(Icons.route_outlined),
            ),
            items: [
              // "None" sentinel — selecting this clears the exit node.
              const DropdownMenuItem<String>(
                value: '',
                child: Text('None'),
              ),
              // One item per exit-node-capable peer.
              ...exitNodes.map(
                (peer) => DropdownMenuItem<String>(
                  value: peer.name,
                  child: Row(
                    children: [
                      // Online indicator dot — lets the user prefer an online
                      // exit node over an offline one.
                      Icon(
                        peer.online ? Icons.circle : Icons.circle_outlined,
                        size: 10,
                        color: peer.online
                            ? cs.primary
                            : cs.outline,
                      ),
                      const SizedBox(width: 8),
                      Text(peer.name),
                      if (!peer.online) ...[
                        const SizedBox(width: 6),
                        Text(
                          '(offline)',
                          style: TextStyle(
                            fontSize: 11,
                            color: cs.onSurfaceVariant,
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
              ),
            ],
            onChanged: context.read<TailscaleState>().loading
                ? null
                : (value) {
                    // An empty value means "clear the exit node".
                    // A non-empty value sets the named peer as exit node.
                    context.read<TailscaleState>().setExitNode(
                          instance.id,
                          value ?? '',
                        );
                  },
          ),
          const SizedBox(height: 12),

          // "Clear exit node" button — explicit shortcut so the user does not
          // have to scroll the dropdown back to "None".  Only shown when an
          // exit node is currently active.
          if (instance.activeExitNode != null &&
              instance.activeExitNode!.isNotEmpty)
            Align(
              // Left-align to match the dropdown rather than centering.
              alignment: Alignment.centerLeft,
              child: TextButton.icon(
                onPressed: context.read<TailscaleState>().loading
                    ? null
                    : () => context.read<TailscaleState>().setExitNode(
                          instance.id,
                          '', // empty = clear
                        ),
                icon: const Icon(Icons.close, size: 16),
                label: const Text('Clear exit node'),
              ),
            ),

          const SizedBox(height: 24),

          // Currently selected exit node summary card.
          if (instance.activeExitNode != null &&
              instance.activeExitNode!.isNotEmpty)
            _ActiveExitNodeCard(
              peerName: instance.activeExitNode!,
              cs: cs,
              tt: tt,
            ),
        ],

        const SizedBox(height: 24),

        // Privacy notice — mandatory disclosure about exit node visibility.
        //
        // Exit node operators CAN observe which internet destinations are
        // accessed after traffic leaves the WireGuard tunnel.  This is
        // fundamentally different from Mesh Infinity's end-to-end encrypted
        // mesh traffic, which the exit node cannot inspect.
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: cs.surfaceContainerHighest,
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: cs.outlineVariant),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Icon(Icons.privacy_tip_outlined,
                      size: 16, color: cs.onSurfaceVariant),
                  const SizedBox(width: 6),
                  Text(
                    'Privacy notice',
                    style: tt.labelMedium?.copyWith(
                        color: cs.onSurfaceVariant),
                  ),
                ],
              ),
              const SizedBox(height: 6),
              Text(
                'The exit node operator can see which internet destinations '
                'your device accesses after traffic leaves the tailnet tunnel. '
                'Websites see the exit node\'s IP address instead of yours. '
                'Mesh Infinity peer-to-peer traffic remains end-to-end '
                'encrypted and is not visible to the exit node.',
                style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
              ),
            ],
          ),
        ),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// _NoExitNodesPlaceholder — private empty-state widget
// ---------------------------------------------------------------------------

/// Empty state shown in [TailnetExitNodePage] when no peers in this tailnet
/// advertise exit-node capability.
///
/// Explains how to enable exit-node capability on a peer, since the user may
/// not be familiar with the Tailscale admin panel workflow.
class _NoExitNodesPlaceholder extends StatelessWidget {
  const _NoExitNodesPlaceholder({required this.cs, required this.tt});

  final ColorScheme cs;
  final TextTheme tt;

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Icon(
          Icons.route_outlined,
          size: 48,
          color: cs.onSurfaceVariant.withValues(alpha: 0.4),
        ),
        const SizedBox(height: 12),
        Text(
          'No exit nodes available',
          style: tt.titleSmall?.copyWith(color: cs.onSurfaceVariant),
        ),
        const SizedBox(height: 8),
        Text(
          'Exit nodes must be enabled on a peer in the Tailscale admin panel '
          '(or Headscale equivalent) before they appear here. '
          'Use Refresh on the Overview tab after enabling an exit node on a peer.',
          style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
          textAlign: TextAlign.center,
        ),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// _ActiveExitNodeCard — private summary card widget
// ---------------------------------------------------------------------------

/// A small summary card showing which exit node is currently active.
///
/// Shown below the dropdown when an exit node is selected, providing a clear
/// confirmation of the active configuration without requiring the user to read
/// the dropdown label.
class _ActiveExitNodeCard extends StatelessWidget {
  const _ActiveExitNodeCard({
    required this.peerName,
    required this.cs,
    required this.tt,
  });

  /// The name of the currently active exit node peer.
  final String peerName;

  final ColorScheme cs;
  final TextTheme tt;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        // Use the secondary container colour to distinguish this confirmation
        // card from the error/warning containers used elsewhere on the screen.
        color: cs.secondaryContainer,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        children: [
          Icon(Icons.check_circle_outline,
              size: 18, color: cs.onSecondaryContainer),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              'Exit node active: $peerName',
              style: tt.bodySmall?.copyWith(
                color: cs.onSecondaryContainer,
                fontWeight: FontWeight.w500,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
