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
//   - An OS identifier (linux, windows, macOS, iOS, android).
//   - A last-seen timestamp used to display recency for offline peers.
//
// SEARCH / FILTER
// ---------------
// A search bar at the top of the list lets users filter by name, IP, or OS.
// The filter is purely local (no bridge call) — it operates on the peer list
// already held in TailnetInstance.  Typing is instant.
//
// COPY IP
// -------
// Long-pressing or tapping the trailing copy button on any row copies the
// peer's Tailscale IP to the clipboard.  This is the primary use-case for
// looking up a peer's IP when SSH-ing or curl-ing directly.
//
// DATA SOURCE
// -----------
// The peer list is embedded in the TailnetInstance passed by TailnetDetailScreen.
// No separate bridge call is needed.  TailscaleState.loadAll() keeps the list
// fresh; the parent TailnetDetailScreen rebuilds this page on each loadAll().
//
// Spec reference: §5.22 (multi-instance Tailscale overlay peer visibility)

import 'package:flutter/material.dart';
// Material widgets: ListView, ListTile, TextField, Icon, Text.

import 'package:flutter/services.dart';
// Clipboard.setData() — for copy IP to clipboard.

import 'models/tailnet_instance.dart';
// TailnetInstance — carries the peer list this page renders.
// TailnetPeer — the individual peer model (now includes os + lastSeen).

// ---------------------------------------------------------------------------
// TailnetPeersPage
// ---------------------------------------------------------------------------

/// The Peers tab content shown inside [TailnetDetailScreen].
///
/// Renders a filterable, scrollable list of all peers visible in [instance].
/// Each row shows the peer's online status, name, IP address, OS icon, last-
/// seen label (for offline peers), and an exit-node icon when applicable.
/// The copy button on each row copies the IP to the clipboard.
///
/// This widget is stateful only for the search query — all peer data arrives
/// via the immutable [instance] argument.
///
/// Spec reference: §5.22 (multi-instance Tailscale overlay peer visibility)
class TailnetPeersPage extends StatefulWidget {
  /// Creates a [TailnetPeersPage] for the given [instance].
  const TailnetPeersPage({super.key, required this.instance});

  /// The tailnet instance whose peer list to display.
  final TailnetInstance instance;

  @override
  State<TailnetPeersPage> createState() => _TailnetPeersPageState();
}

class _TailnetPeersPageState extends State<TailnetPeersPage> {
  // ---------------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------------

  /// Current search query.  Empty string means "show all".
  String _query = '';

  /// Controller for the search text field so we can clear it programmatically.
  final _searchCtrl = TextEditingController();

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  @override
  void dispose() {
    _searchCtrl.dispose();
    super.dispose();
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  /// Returns the subset of [peers] that match [_query].
  ///
  /// Matching is case-insensitive and spans the name, IP, and OS fields.
  /// An empty query always returns all peers.
  List<TailnetPeer> _filtered(List<TailnetPeer> peers) {
    final q = _query.trim().toLowerCase();
    if (q.isEmpty) return peers;
    return peers.where((p) {
      return p.name.toLowerCase().contains(q) ||
          p.ip.toLowerCase().contains(q) ||
          (p.os?.toLowerCase().contains(q) ?? false);
    }).toList();
  }

  // ---------------------------------------------------------------------------
  // build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;
    final allPeers  = widget.instance.peers;
    final peers     = _filtered(allPeers);

    return Column(
      children: [
        // ---- Search bar ---------------------------------------------------
        // Always shown — even for an empty list — because the user may not
        // yet know whether peers are absent or merely filtered.
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 10, 12, 4),
          child: TextField(
            controller: _searchCtrl,
            decoration: InputDecoration(
              hintText: 'Filter by name, IP, or OS',
              prefixIcon: const Icon(Icons.search, size: 20),
              isDense: true,
              border: const OutlineInputBorder(),
              // Clear button — only visible when there is text to clear.
              suffixIcon: _query.isNotEmpty
                  ? IconButton(
                      icon: const Icon(Icons.clear, size: 18),
                      tooltip: 'Clear filter',
                      onPressed: () {
                        _searchCtrl.clear();
                        setState(() => _query = '');
                      },
                    )
                  : null,
            ),
            onChanged: (v) => setState(() => _query = v),
          ),
        ),

        // ---- Online / total count ----------------------------------------
        if (allPeers.isNotEmpty)
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
            child: Row(
              children: [
                Icon(Icons.circle,
                    size: 10,
                    color: cs.primary.withValues(alpha: 0.8)),
                const SizedBox(width: 6),
                Text(
                  // Show how many are online and how many are visible after
                  // filtering.
                  '${allPeers.where((p) => p.online).length} online'
                  '${_query.isNotEmpty ? ' · ${peers.length} of ${allPeers.length} shown' : ' · ${allPeers.length} total'}',
                  style: tt.labelSmall
                      ?.copyWith(color: cs.onSurfaceVariant),
                ),
              ],
            ),
          ),

        // ---- List or empty state ------------------------------------------
        Expanded(
          child: allPeers.isEmpty
              ? _EmptyState(cs: cs, tt: tt, hasFilter: false)
              : peers.isEmpty
                  ? _EmptyState(cs: cs, tt: tt, hasFilter: true)
                  : ListView.separated(
                      padding: const EdgeInsets.symmetric(vertical: 8),
                      itemCount: peers.length,
                      separatorBuilder: (_, _) =>
                          const Divider(height: 1, indent: 56),
                      itemBuilder: (context, index) {
                        return _PeerRow(peer: peers[index]);
                      },
                    ),
        ),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// _EmptyState — private helper
// ---------------------------------------------------------------------------

/// Centered message shown when there are no peers (or no filter matches).
class _EmptyState extends StatelessWidget {
  const _EmptyState({
    required this.cs,
    required this.tt,
    required this.hasFilter,
  });

  /// True when the empty state is due to a filter returning no matches.
  /// False when the peer list itself is empty.
  final bool hasFilter;

  final ColorScheme cs;
  final TextTheme tt;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              hasFilter ? Icons.search_off : Icons.people_outline,
              size: 56,
              color: cs.onSurfaceVariant.withValues(alpha: 0.5),
            ),
            const SizedBox(height: 16),
            Text(
              hasFilter ? 'No peers match' : 'No peers yet',
              style: tt.titleMedium?.copyWith(color: cs.onSurfaceVariant),
            ),
            const SizedBox(height: 8),
            Text(
              hasFilter
                  ? 'Try a different name, IP, or OS.'
                  : 'Peers appear here once other devices are enrolled in this '
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
}

// ---------------------------------------------------------------------------
// _PeerRow — private widget for one peer entry
// ---------------------------------------------------------------------------

/// A single row in the peer list showing one [TailnetPeer].
///
/// Shows:
///   • Online/offline status indicator (filled vs outlined circle)
///   • Peer name (or IP when name is empty)
///   • IP address in monospace + copy button
///   • Last-seen label when the peer is offline and a timestamp is available
///   • OS icon (phone/laptop/desktop based on OS string)
///   • Exit-node route icon when applicable
class _PeerRow extends StatelessWidget {
  const _PeerRow({required this.peer});

  final TailnetPeer peer;

  // ---------------------------------------------------------------------------
  // OS icon helper
  // ---------------------------------------------------------------------------

  /// Returns a small icon that represents the peer's reported OS.
  ///
  /// Falls back to a generic laptop icon for unknown OS strings.
  IconData _osIcon() {
    final os = peer.os?.toLowerCase() ?? '';
    if (os == 'ios' || os == 'android') return Icons.smartphone;
    if (os == 'macos' || os == 'windows' || os == 'linux') {
      return Icons.laptop;
    }
    return Icons.devices_other;
  }

  // ---------------------------------------------------------------------------
  // _copyIp
  // ---------------------------------------------------------------------------

  /// Copies the peer's IP to the clipboard and shows a brief snackbar.
  void _copyIp(BuildContext context) {
    Clipboard.setData(ClipboardData(text: peer.ip));
    // Show a brief snackbar so the user gets feedback.
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('Copied ${peer.ip}'),
        duration: const Duration(seconds: 2),
        behavior: SnackBarBehavior.floating,
        width: 220,
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // build
  // ---------------------------------------------------------------------------

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    // Online indicator: filled circle (primary colour) = online,
    //                   outlined circle (grey)          = offline.
    final onlineIcon = peer.online
        ? Icon(Icons.circle, size: 14, color: cs.primary)
        : Icon(Icons.circle_outlined, size: 14, color: cs.outline);

    // Build subtitle: IP address + optional "last seen" for offline peers.
    final lastSeenStr = peer.lastSeenLabel; // null when online or ts=0
    final subtitleText = lastSeenStr != null
        ? '${peer.ip}  ·  $lastSeenStr'
        : peer.ip;

    return ListTile(
      // Leading: online status indicator.
      leading: onlineIcon,

      // Title: peer hostname or IP fallback.
      title: Row(
        children: [
          // OS icon — subtle visual cue about the device type.
          Icon(_osIcon(),
              size: 14,
              color: cs.onSurfaceVariant.withValues(alpha: 0.7)),
          const SizedBox(width: 6),
          Expanded(
            child: Text(
              peer.name.isNotEmpty ? peer.name : peer.ip,
              style: const TextStyle(fontWeight: FontWeight.w500),
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),

      // Subtitle: IP (monospace) + optional last-seen.
      subtitle: Text(
        subtitleText,
        style: tt.bodySmall?.copyWith(
          color: cs.onSurfaceVariant,
          fontFamily: 'monospace',
          fontSize: 12,
        ),
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
      ),

      // Trailing: exit-node icon and/or copy-IP button.
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          // Exit-node badge — only when the peer advertises that capability.
          if (peer.isExitNode)
            Tooltip(
              message: 'Exit node — can route internet traffic',
              child: Padding(
                padding: const EdgeInsets.only(right: 4),
                child: Icon(Icons.route_outlined,
                    size: 18, color: cs.secondary),
              ),
            ),
          // Copy-IP button — always shown so the user can quickly grab the IP.
          IconButton(
            icon: Icon(Icons.copy, size: 16, color: cs.onSurfaceVariant),
            tooltip: 'Copy IP address',
            visualDensity: VisualDensity.compact,
            onPressed: () => _copyIp(context),
          ),
        ],
      ),
    );
  }
}
