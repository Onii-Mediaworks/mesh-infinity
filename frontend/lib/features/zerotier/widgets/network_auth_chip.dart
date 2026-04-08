// network_auth_chip.dart
//
// NetworkAuthChip — a small status chip showing the authorization state of a
// ZeroTier network membership.
//
// ZEROTIER AUTHORIZATION FLOW
// ----------------------------
// When you join a private ZeroTier network, your node is not immediately
// permitted to route traffic.  The network admin must review the join request
// and explicitly mark your node as "authorized" in the controller.  Until then
// your membership is "awaiting authorization".
//
// Public networks skip this step — all joiners are auto-authorized.
//
// VISUAL DESIGN
// --------------
// The chip uses the Mesh Infinity semantic color palette:
//   Green  (#22C55E) — Authorized.  Traffic is flowing.
//   Amber  (#F59E0B) — Awaiting authorization.  Admin has not yet approved.
//   Red    (#EF4444) — Unauthorized.  Admin denied membership (or revoked it).
//   Grey             — Unknown state.  Backend hasn't fetched status yet.
//
// These match the global MeshTheme semantic colors (secGreen, secAmber,
// secRed) to maintain visual consistency with status indicators elsewhere in
// the app (peer status, transport health, etc.).
//
// Spec ref: §5.23 ZeroTier — network membership states.

import 'package:flutter/material.dart';

import '../models/zeronet_network.dart';
// ZeroNetAuthStatus is the enum we're visually representing.

// ---------------------------------------------------------------------------
// NetworkAuthChip
// ---------------------------------------------------------------------------

/// Compact chip displaying the authorization status of a ZeroTier network
/// membership.
///
/// Uses the Mesh Infinity semantic color palette so the meaning is immediately
/// clear without reading the label text:
///   Green  → authorized
///   Amber  → awaiting authorization
///   Red    → unauthorized
///   Grey   → unknown
///
/// Spec ref: §5.23 ZeroTier network membership.
class NetworkAuthChip extends StatelessWidget {
  /// The authorization status to display.
  final ZeroNetAuthStatus status;

  /// Creates a [NetworkAuthChip] for the given [status].
  const NetworkAuthChip({super.key, required this.status});

  @override
  Widget build(BuildContext context) {
    // Resolve color and label based on the status value.
    // These are the Mesh Infinity semantic colors — matching the palette
    // defined in MeshTheme (app_theme.dart) for consistency.
    final (color, label, icon) = _resolve(status);

    return Container(
      // Small padding keeps the chip compact inside a list tile.
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        // 15% opacity fill — visible but doesn't overpower the tile content.
        color: color.withValues(alpha: 0.15),
        borderRadius: BorderRadius.circular(12),
        // Subtle border at 40% opacity gives the chip a defined edge without
        // looking heavy.
        border: Border.all(color: color.withValues(alpha: 0.4)),
      ),
      child: Row(
        // Row rather than Chip widget because Chip adds unwanted minimum height
        // constraints that look too tall inside dense ListTile subtitles.
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 10, color: color),
          const SizedBox(width: 4),
          Text(
            label,
            style: TextStyle(
              fontSize: 10,
              fontWeight: FontWeight.w600,
              color: color,
              // Uppercase letter-spaced label reads as a status badge
              // rather than inline prose, matching common design patterns
              // for status indicators (e.g. GitHub PR status badges).
              letterSpacing: 0.4,
            ),
          ),
        ],
      ),
    );
  }

  /// Maps [ZeroNetAuthStatus] to a (color, label, icon) triple.
  ///
  /// Returns a record — Dart 3 destructuring keeps the call site clean.
  static (Color, String, IconData) _resolve(ZeroNetAuthStatus status) {
    return switch (status) {
      // Authorized: green circle-check — clear "all good" signal.
      ZeroNetAuthStatus.authorized => (
        const Color(0xFF22C55E), // MeshTheme.secGreen
        'Authorized',
        Icons.check_circle_outline,
      ),

      // Awaiting: amber clock — "waiting for human action".
      ZeroNetAuthStatus.awaitingAuthorization => (
        const Color(0xFFF59E0B), // MeshTheme.secAmber
        'Pending',
        Icons.hourglass_empty_outlined,
      ),

      // Unauthorized: red block — explicit denial by admin.
      ZeroNetAuthStatus.unauthorized => (
        const Color(0xFFEF4444), // MeshTheme.secRed
        'Unauthorized',
        Icons.block_outlined,
      ),

      // Unknown: grey question mark — status not yet fetched.
      ZeroNetAuthStatus.unknown => (
        const Color(0xFF9CA3AF), // neutral grey
        'Unknown',
        Icons.help_outline,
      ),
    };
  }
}
