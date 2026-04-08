// tailnet_peers_page.dart
//
// TailnetPeersPage — the Peers tab content for one tailnet instance.
//
// WHAT ARE TAILSCALE PEERS?
// -------------------------
// Peers are all other devices enrolled in the same tailnet.  Each peer has:
//   - A stable Tailscale-assigned IP address (100.x.x.x or fd7a:... IPv6).
//   - An optional exit-node capability flag.
//   - An online/offline status based on recent WireGuard keepalives.
//
// The peer list here is the same set of peers returned by the backend's
// tailscaleListInstances() call — the TailnetInstance model already carries
// them.  We do not make a separate bridge call from this page; the parent
// TailscaleState.loadAll() keeps the list fresh.
//
// WHY A PAGE WIDGET AND NOT A SCREEN?
// ------------------------------------
// "Page" in this codebase means a widget that is embedded inside a TabBarView
// rather than pushed onto the navigator stack.  It receives its data via
// constructor arguments (the parent TailnetDetailScreen resolves the
// TailnetInstance and passes it in) rather than reading TailscaleState itself.
// This keeps the widget stateless and easy to unit-test.
//
// EMPTY STATE
// -----------
// A newly enrolled device that has not yet synced its peer map shows zero
// peers.  We show an informative empty state with an icon and a message
// rather than a blank white screen, which could be mistaken for a loading
// failure.

import 'package:flutter/material.dart';
// Material widgets: ListView, ListTile, Icon, Text, Center, Column.

import 'models/tailnet_instance.dart';
// TailnetInstance — carries the peer list this page renders.
// TailnetPeer — the individual peer model.

// ---------------------------------------------------------------------------
// TailnetPeersPage
// ---------------------------------------------------------------------------

/// The Peers tab content shown inside [TailnetDetailScreen].
///
/// Renders a scrollable list of all peers visible in [instance].  Each row
/// shows the peer's online status, name, IP address, and an exit-node icon
/// when applicable.
///
/// This widget is stateless — it receives a pre-resolved [TailnetInstance]
/// from its parent and renders it.  State mutation (e.g. "refresh peers")
/// is handled by the Overview tab's Refresh button, which calls
/// TailscaleState.refresh() and triggers a rebuild of the whole detail screen.
///
/// Spec reference: §5.22 (multi-instance overlay peer visibility)
class TailnetPeersPage extends StatelessWidget {
  /// Creates a [TailnetPeersPage] for the given [instance].
  const TailnetPeersPage({super.key, required this.instance});

  /// The tailnet instance whose peer list to display.
  ///
  /// Passed by [TailnetDetailScreen] so this widget does not need to resolve
  /// the instance itself via TailscaleState.
  final TailnetInstance instance;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;
    final peers = instance.peers;

    // Empty state — shown when the backend has not yet delivered a peer map
    // or the tailnet genuinely has no other enrolled devices.
    if (peers.isEmpty) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(
            // shrink-wrap so the column sits in the vertical centre of the tab.
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(
                Icons.people_outline,
                size: 56,
                // Dim the icon slightly — it is decoration, not actionable.
                color: cs.onSurfaceVariant.withValues(alpha: 0.5),
              ),
              const SizedBox(height: 16),
              Text(
                'No peers yet',
                style: tt.titleMedium?.copyWith(color: cs.onSurfaceVariant),
              ),
              const SizedBox(height: 8),
              Text(
                'Peers appear here once other devices are enrolled in this '
                'tailnet and the device map has been synced. '
                'Use Refresh on the Overview tab to force a sync.',
                style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
                textAlign: TextAlign.center,
              ),
            ],
          ),
        ),
      );
    }

    // Non-empty: render a scrollable list of peer rows.
    return ListView.separated(
      // Consistent padding with the Overview and Exit Nodes tabs.
      padding: const EdgeInsets.symmetric(vertical: 8),
      itemCount: peers.length,
      // A subtle divider between rows improves scannability in long peer lists.
      separatorBuilder: (_, _) => const Divider(height: 1, indent: 56),
      itemBuilder: (context, index) {
        final peer = peers[index];
        return _PeerRow(peer: peer);
      },
    );
  }
}

// ---------------------------------------------------------------------------
// _PeerRow — private widget for one peer entry
// ---------------------------------------------------------------------------

/// A single row in the peer list showing one [TailnetPeer].
///
/// Kept private because it is only used within [TailnetPeersPage].
/// Extracting it to a named widget (even a private one) gives Flutter a
/// useful element identity for incremental rebuilds when the peer list
/// changes length.
class _PeerRow extends StatelessWidget {
  const _PeerRow({required this.peer});

  /// The peer data to display.
  final TailnetPeer peer;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    // Online indicator: filled circle (green) when online, outlined (grey)
    // when offline.  The same icon pair is used in TailscaleSetupScreen's
    // peer list for visual consistency.
    final onlineIcon = peer.online
        ? Icon(Icons.circle, size: 14, color: cs.primary)
        : Icon(Icons.circle_outlined, size: 14, color: cs.outline);

    return ListTile(
      // Leading: online status indicator.
      leading: onlineIcon,

      // Title: peer hostname.  Falls back to the IP address if the name is
      // empty (can happen for newly enrolled peers whose MagicDNS record has
      // not yet propagated).
      title: Text(
        peer.name.isNotEmpty ? peer.name : peer.ip,
        style: const TextStyle(fontWeight: FontWeight.w500),
      ),

      // Subtitle: IP address (always shown) — allows copy-paste for
      // direct-connect use cases.
      subtitle: Text(
        peer.ip,
        style: TextStyle(
          fontSize: 12,
          color: cs.onSurfaceVariant,
          fontFamily: 'monospace',
          // Monospace font makes IP addresses easier to read and compare.
        ),
      ),

      // Trailing: exit-node capability icon, if applicable.
      // Routes the UI by icon rather than text to keep the row compact.
      trailing: peer.isExitNode
          ? Tooltip(
              message: 'Exit node — can route internet traffic',
              child: Icon(Icons.route_outlined, color: cs.secondary),
            )
          : null,
    );
  }
}
