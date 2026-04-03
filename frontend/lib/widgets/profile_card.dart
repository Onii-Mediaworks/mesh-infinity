// §22.4.9 ProfileCard
//
// Reusable profile display used in ContactDetailScreen, search results,
// and anywhere a contact's identity needs to be shown consistently.
// Reads from the contact's resolved profile tier (§9.2 resolution order):
//   Level 6+ with private profile → private profile fields
//   paired profile present        → paired profile fields
//   public profile present        → public profile fields
//   fallback                      → peerId[:8]

import 'package:flutter/material.dart';

import '../app/app_theme.dart';
import '../backend/models/peer_models.dart';
import 'mask_avatar.dart';

class ProfileCard extends StatelessWidget {
  const ProfileCard({
    super.key,
    required this.contact,
    this.showTrustBadge = true,
    this.compact = false,
  });

  final PeerModel contact;

  /// When true shows the full card layout with bio and contact hint rows.
  /// When false (compact) shows avatar + name + trust badge only — for list contexts.
  final bool compact;

  /// Whether to render the TrustBadge chip.
  final bool showTrustBadge;

  // §9.2 resolution: for now the peer's own name is the resolved display name.
  // When the full profile-tier stack is available (private → paired → public),
  // this getter will walk the tiers; until then PeerModel.name is the primary field.
  String get _resolvedDisplayName =>
      contact.name.isNotEmpty ? contact.name : contact.id.substring(0, 8);

  // Profile-tier badge label (shown alongside the trust badge).
  // Returns null if no tier can be determined.
  String? get _profileTierLabel {
    if (contact.trustLevel.value >= 6) return 'Private';
    if (contact.trustLevel.value >= 1) return 'Direct';
    return null;
  }

  Color get _profileTierColor {
    if (contact.trustLevel.value >= 6) return MeshTheme.secGreen;
    return MeshTheme.brand;
  }

  // Derives a stable avatar color from the peer ID so the same peer always
  // gets the same color even before they set a custom avatar.
  Color _avatarColor() {
    final hash = contact.id.codeUnits.fold(0, (h, c) => h ^ c);
    return kMaskAvatarColors[hash.abs() % kMaskAvatarColors.length];
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final cs = theme.colorScheme;
    final avatar = MaskAvatarData(
      name: _resolvedDisplayName,
      avatarColor: _avatarColor(),
    );

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
                if (showTrustBadge)
                  _TrustBadge(level: contact.trustLevel),
              ],
            ),
          ),
        ],
      );
    }

    // Full layout
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
                MaskAvatar(mask: avatar, size: MaskAvatarSize.large),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        _resolvedDisplayName,
                        style: theme.textTheme.titleLarge,
                      ),
                      const SizedBox(height: 4),
                      Row(
                        children: [
                          if (showTrustBadge) ...[
                            _TrustBadge(level: contact.trustLevel),
                            const SizedBox(width: 6),
                          ],
                          if (_profileTierLabel != null)
                            _ProfileTierBadge(
                              label: _profileTierLabel!,
                              color: _profileTierColor,
                            ),
                        ],
                      ),
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
            // Peer ID — always shown in full card for identification.
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
// TrustBadge
// ---------------------------------------------------------------------------

/// Small chip showing the trust level label and icon.
class _TrustBadge extends StatelessWidget {
  const _TrustBadge({required this.level});
  final TrustLevel level;

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
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
// ProfileTierBadge
// ---------------------------------------------------------------------------

class _ProfileTierBadge extends StatelessWidget {
  const _ProfileTierBadge({required this.label, required this.color});
  final String label;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
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
