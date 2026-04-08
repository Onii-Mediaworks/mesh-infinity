// profile_card.dart
//
// ProfileCard — reusable contact identity display widget (§22.4.9).
//
// WHAT THIS WIDGET DOES:
// ----------------------
// ProfileCard shows a contact's identity in a consistent way wherever it
// appears in the app: contact detail screens, search results, pairing flows,
// and any other place a peer's profile needs to be surfaced.
//
// It handles two layout modes:
//
//   Full layout (compact == false): A Card with avatar, display name, trust
//   badge, profile-tier badge, online/idle status, and the full peer ID in
//   monospace.  Used in ContactDetailScreen and similar full-page contexts.
//
//   Compact layout (compact == true): A Row with avatar, name, and optional
//   trust badge only.  Used in list tiles and search results where vertical
//   space is limited.
//
// PROFILE RESOLUTION (§9.2):
// --------------------------
// When a peer is known at different levels of trust, the app has access to
// progressively more personal profile data:
//
//   Trust level ≥ 6 (Close/Intimate) → private profile (user-set for this
//                                       contact specifically; may differ from
//                                       their public profile).
//   Trust level ≥ 1 (any paired)     → paired profile (what the peer showed
//                                       during pairing; may be pseudonymous).
//   No trust / anonymous             → public profile (what the peer has
//                                       published to the mesh network).
//   Absolute fallback                → first 8 characters of the peer ID.
//
// The full tier-walk is not yet implemented — the [_resolvedDisplayName] getter
// notes this and falls back to PeerModel.name until the profile stack is wired.
//
// PROFILE-TIER BADGE:
// -------------------
// The profile-tier badge (rendered by [_ProfileTierBadge]) indicates which
// resolution tier is currently displayed:
//   'Private' (green)  — the user has a private profile for this contact.
//   'Direct'  (blue)   — a paired/direct profile is available.
//   (absent)           — only a public or anonymous profile is available.
//
// AVATAR COLOR:
// -------------
// When no custom avatar image is available, [_avatarColor] derives a stable
// colour from the peer ID using a simple XOR fold.  This means the same peer
// always gets the same background colour across sessions and devices — a
// useful consistency property when users recognise contacts visually.

import 'package:flutter/material.dart';

import '../app/app_theme.dart';
import '../backend/models/peer_models.dart';
import 'mask_avatar.dart';

/// Displays a contact's profile in either full-card or compact-row layout.
///
/// [contact] is the [PeerModel] to render.  [compact] switches between the
/// two layouts.  [showTrustBadge] controls whether the trust level chip is
/// shown (useful to hide it in contexts where trust is implied).
class ProfileCard extends StatelessWidget {
  const ProfileCard({
    super.key,
    required this.contact,
    this.showTrustBadge = true,
    this.compact = false,
  });

  /// The peer whose profile this card displays.
  final PeerModel contact;

  /// When false (default), renders the full Card layout with bio, status, and
  /// peer ID.  When true, renders a compact Row for list tile usage.
  final bool compact;

  /// Whether to show the [_TrustBadge] chip next to the display name.
  ///
  /// Some call sites (e.g. a context where trust is shown elsewhere) set this
  /// to false to reduce visual clutter.
  final bool showTrustBadge;

  // --------------------------------------------------------------------------
  // Profile resolution helpers
  // --------------------------------------------------------------------------

  /// Resolves the display name following the §9.2 profile tier order.
  ///
  /// Currently simplified: uses [PeerModel.name] as the primary field and
  /// falls back to the first 8 characters of the peer ID if the name is
  /// empty.  The full tier-walk (private → paired → public) will be wired
  /// here once the profile-tier stack is available from the backend.
  String get _resolvedDisplayName =>
      contact.name.isNotEmpty ? contact.name : contact.id.substring(0, 8);

  /// Returns the tier badge label if a specific profile tier can be identified.
  ///
  /// Returns 'Private' when the contact is at trust level ≥ 6 (the user has
  /// set a private name/bio specifically for this person).
  /// Returns 'Direct' when the contact is at trust level ≥ 1 (paired).
  /// Returns null for anonymous contacts (no badge shown).
  String? get _profileTierLabel {
    if (contact.trustLevel.value >= 6) return 'Private';
    if (contact.trustLevel.value >= 1) return 'Direct';
    return null;
  }

  /// Background colour for the profile-tier badge pill.
  ///
  /// Green for private (highest trust, most personal profile).
  /// Brand blue for direct (paired but not yet intimate trust level).
  Color get _profileTierColor {
    if (contact.trustLevel.value >= 6) return MeshTheme.secGreen;
    return MeshTheme.brand;
  }

  /// Derives a stable avatar background colour from the peer ID.
  ///
  /// Uses a simple XOR fold over the UTF-16 code units of the peer ID string.
  /// The result is used as an index into [kMaskAvatarColors].
  ///
  /// XOR fold is chosen because:
  ///   1. It produces the same output for the same input on every call —
  ///      the contact always gets the same colour.
  ///   2. It is fast (one allocation-free loop).
  ///   3. It distributes reasonably across the 8-colour palette.
  ///
  /// This is not cryptographically meaningful — it is purely aesthetic.
  Color _avatarColor() {
    final hash = contact.id.codeUnits.fold(0, (h, c) => h ^ c);
    // abs() handles the case where XOR folding produces a negative integer
    // (which can occur because Dart integers are not unsigned on all platforms).
    return kMaskAvatarColors[hash.abs() % kMaskAvatarColors.length];
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;
    // Build the avatar data once and reuse in both layouts.
    final avatar = MaskAvatarData(
      name: _resolvedDisplayName,
      avatarColor: _avatarColor(),
    );

    // ---- Compact layout ---------------------------------------------------
    // Used in list tiles: avatar + name + optional trust badge, single row.
    if (compact) {
      return Row(
        children: [
          MaskAvatar(mask: avatar, size: MaskAvatarSize.medium),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  _resolvedDisplayName,
                  style: theme.textTheme.titleSmall,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
                // Trust badge sits below the name in compact mode.
                // When showTrustBadge is false, this row is omitted entirely
                // so the name is vertically centred in the row.
                if (showTrustBadge)
                  _TrustBadge(level: contact.trustLevel),
              ],
            ),
          ),
        ],
      );
    }

    // ---- Full card layout ------------------------------------------------
    // Used in detail screens: full Card with all available information.
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Large avatar — 64 px gives enough surface for the initial
                // to be readable at arm's length.
                MaskAvatar(mask: avatar, size: MaskAvatarSize.large),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      // Primary display name in large style.
                      Text(
                        _resolvedDisplayName,
                        style: theme.textTheme.titleLarge,
                      ),
                      const SizedBox(height: 4),
                      // Badge row: trust badge and profile-tier badge side by side.
                      Row(
                        children: [
                          if (showTrustBadge) ...[
                            _TrustBadge(level: contact.trustLevel),
                            // Space between trust badge and tier badge when both show.
                            const SizedBox(width: 6),
                          ],
                          // Profile-tier badge only shown when a specific tier
                          // can be identified (private or direct — not anonymous).
                          if (_profileTierLabel != null)
                            _ProfileTierBadge(
                              label: _profileTierLabel!,
                              color: _profileTierColor,
                            ),
                        ],
                      ),
                      // Online / idle status — only shown when a live status
                      // is available.  Offline contacts show neither line to
                      // avoid surfacing "last seen" timing metadata.
                      if (contact.isOnline) ...[
                        const SizedBox(height: 4),
                        Text(
                          'Online',
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: MeshTheme.secGreen,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ] else if (contact.isIdle) ...[
                        const SizedBox(height: 4),
                        Text(
                          'Idle',
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: MeshTheme.secAmber,
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
              ],
            ),
            // Full peer ID — always shown in the full card so the user can
            // verify the contact's cryptographic identity by comparing this
            // ID with what the contact shows on their device.
            // Monospace font makes character-by-character comparison easier.
            const SizedBox(height: 12),
            Text(
              contact.id,
              style: theme.textTheme.bodySmall?.copyWith(
                color: cs.onSurfaceVariant,
                fontFamily: 'monospace',
                fontSize: 11,
              ),
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
            ),
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _TrustBadge — small inline chip showing the trust level
// ---------------------------------------------------------------------------

/// Small trust-level indicator showing an icon and the level label.
///
/// Trust levels and their icons/colours are defined on the [TrustLevel] model.
/// This widget just renders them in a compact row.
///
/// Used in both compact and full [ProfileCard] layouts.
class _TrustBadge extends StatelessWidget {
  const _TrustBadge({required this.level});

  /// The trust level to display.
  final TrustLevel level;

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        // Icon defined on the trust level model — allows the model to control
        // which icon represents each level without duplicating the mapping here.
        Icon(level.icon, size: 13, color: level.color),
        const SizedBox(width: 3),
        Text(
          level.label,
          style: TextStyle(
            fontSize: 12,
            color: level.color,
            fontWeight: FontWeight.w600,
          ),
        ),
      ],
    );
  }
}

// ---------------------------------------------------------------------------
// _ProfileTierBadge — pill showing which profile tier is displayed
// ---------------------------------------------------------------------------

/// Small bordered pill badge showing the profile resolution tier.
///
/// Appears next to the trust badge in the full card layout when the profile
/// tier is known ('Private' or 'Direct').  Hidden for anonymous contacts.
class _ProfileTierBadge extends StatelessWidget {
  const _ProfileTierBadge({required this.label, required this.color});

  /// The tier label to display (e.g. 'Private', 'Direct').
  final String label;

  /// Colour used for the text, border, and tinted background.
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        // 12% opacity fill + 30% opacity border gives a "chip" look that is
        // clearly associated with [color] without dominating the card visually.
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: color.withValues(alpha: 0.3)),
      ),
      child: Text(
        label,
        style: TextStyle(
          fontSize: 10,
          color: color,
          fontWeight: FontWeight.w600,
        ),
      ),
    );
  }
}
