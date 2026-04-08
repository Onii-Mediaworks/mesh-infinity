// peer_tile.dart
//
// PeerTile — a single row in the Contacts list representing one known peer.
//
// VISUAL STRUCTURE:
// -----------------
// Leading avatar: first initial on a coloured circle, with a small status dot
//   overlaid at the bottom-right.  The dot colour encodes online state:
//     green  = online (actively reachable)
//     orange = idle (reachable but inactive)
//     grey   = offline / unknown
// Title: display name, falling back to the first 12 chars of the peer ID when
//   the name is blank (backend hasn't fetched the profile yet).
// Subtitle: peer.status string — e.g. "Online", "Offline 2h ago".
// Trailing: TrustBadge in compact mode showing the numeric trust tier.
//
// SELECTION HIGHLIGHT:
// --------------------
// The `selected` parameter applies a primaryContainer tint — used on wide
// screens where this tile corresponds to the currently open detail panel.
// On narrow screens, selection is never active.

import 'package:flutter/material.dart';

import '../../../backend/models/peer_models.dart';
import 'trust_badge.dart';

/// A single list row representing [peer] in the contacts list.
///
/// [selected] applies a highlight tint — only meaningful on wide-screen
/// master-detail layouts where the detail panel is simultaneously visible.
///
/// [onTap] is called when the user taps the tile; the caller decides whether
/// to push a new route or update a side-panel selection.
class PeerTile extends StatelessWidget {
  const PeerTile({
    super.key,
    required this.peer,
    required this.selected,
    required this.onTap,
  });

  /// The peer to display. Must not be null.
  final PeerModel peer;

  /// Whether this tile is the currently selected peer in a wide-screen layout.
  final bool selected;

  /// Callback invoked when the tile is tapped.
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    // Map the peer's online/idle state to a status dot colour.
    // online → green, idle → orange, anything else (offline/unknown) → grey.
    final statusColor = peer.isOnline
        ? Colors.green
        : peer.isIdle
            ? Colors.orange
            : Colors.grey;

    return ListTile(
      selected: selected,
      // Subtle tint so the selected tile is visually distinct without being
      // distracting (0.3 alpha keeps the text readable on any background).
      selectedTileColor: cs.primaryContainer.withValues(alpha: 0.3),

      // ── Avatar with status dot overlay ──────────────────────────────────
      leading: Stack(
        children: [
          // Main avatar circle: first letter of the display name, uppercased
          // for legibility. Falls back to '?' when the name is empty (e.g.
          // before the backend delivers the peer's public profile).
          CircleAvatar(
            backgroundColor: cs.secondaryContainer,
            child: Text(
              peer.name.isNotEmpty ? peer.name[0].toUpperCase() : '?',
              style: TextStyle(
                color: cs.onSecondaryContainer,
                fontWeight: FontWeight.bold,
              ),
            ),
          ),

          // Status dot: 10×10 circle at bottom-right of the avatar.
          // The white border visually separates it from the avatar background
          // so it remains readable against any avatar colour.
          // Semantics label exposes the status to screen readers since the
          // colour alone would be inaccessible.
          Positioned(
            right: 0,
            bottom: 0,
            child: Semantics(
              label: peer.status,
              child: Container(
                width: 10,
                height: 10,
                decoration: BoxDecoration(
                  color: statusColor,
                  shape: BoxShape.circle,
                  border: Border.all(color: cs.surface, width: 1.5),
                ),
              ),
            ),
          ),
        ],
      ),

      // Display name with fallback to a 12-char prefix of the peer ID.
      // Showing a partial ID is better than "Unknown" because power users
      // can cross-reference it with the full ID in the detail screen.
      title: Text(peer.name.isNotEmpty ? peer.name : peer.id.substring(0, 12)),

      // Localised status string from the backend, e.g. "Online", "Offline 3m ago".
      subtitle: Text(
        peer.status,
        style: Theme.of(context).textTheme.bodySmall,
      ),

      // Compact trust badge shows the tier number without the full label.
      trailing: TrustBadge(level: peer.trustLevel, compact: true),

      onTap: onTap,
    );
  }
}
