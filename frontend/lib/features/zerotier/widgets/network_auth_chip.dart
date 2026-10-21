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
//   Green  (sec_green) — Authorized.  Traffic is flowing.
//   Amber  (sec_amber) — Awaiting authorization.  Admin has not yet approved.
//   Red    (sec_red) — Unauthorized.  Admin denied membership (or revoked it).
//   Grey   (trust 0)  — Unknown state.  Backend hasn't fetched status yet.
//
// These are the per-theme MeshColors semantic tokens (sec_green, sec_amber,
// sec_red) so the chip meets contrast in both themes and stays consistent with
// status indicators elsewhere in
// the app (peer status, transport health, etc.).
//
// Spec ref: §5.23 ZeroTier — network membership states.

import 'package:flutter/material.dart';

import '../../../app/app_theme.dart';
// MeshColors supplies the per-theme semantic status colours.
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
    // The colours come from the MeshColors theme extension (app_theme.dart),
    // so they follow the active light/dark theme.
    final (color, label, icon) = _resolve(MeshColors.of(context), status);

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
  /// [colors] is the ambient theme's [MeshColors] so the result is theme-aware.
  static (Color, String, IconData) _resolve(
    MeshColors colors,
    ZeroNetAuthStatus status,
  ) {
    return switch (status) {
      // Authorized: green circle-check — clear "all good" signal.
      ZeroNetAuthStatus.authorized => (
        colors.sec_green,
        'Authorized',
        Icons.check_circle_outline,
      ),

      // Awaiting: amber clock — "waiting for human action".
      ZeroNetAuthStatus.awaitingAuthorization => (
        colors.sec_amber,
        'Pending',
        Icons.hourglass_empty_outlined,
      ),

      // Unauthorized: red block — explicit denial by admin.
      ZeroNetAuthStatus.unauthorized => (
        colors.sec_red,
        'Unauthorized',
        Icons.block_outlined,
      ),

      // Unknown: grey question mark — status not yet fetched.
      ZeroNetAuthStatus.unknown => (
        colors.trust_color(0), // neutral grey (Unknown trust)
        'Unknown',
        Icons.help_outline,
      ),
    };
  }
}
