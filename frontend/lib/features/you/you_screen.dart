// you_screen.dart
//
// YouScreen — the user's own identity card and masks list.
//
// WHAT THIS SCREEN SHOWS:
// -----------------------
// This is the "self" screen — it displays the current user's own identity
// rather than another peer's identity.  It contains two sections:
//
//   _SelfCard    — the Layer 1/Layer 2 identity card: avatar, display name,
//                  peer ID (tappable to copy), QR code for pairing, and an
//                  "Edit profile" button.
//
//   _MasksSection — Layer 3 contextual identities (masks).  Currently shows
//                   a "not yet implemented" placeholder; mask backend support
//                   is pending.
//
// PEER ID:
// --------
// The peer ID is the public key derived short-form identifier for this node.
// It is what other devices use to address this node in the mesh network.
// Sharing your peer ID is the primary way to be added as a contact.
//
// IDENTITY LAYERS:
//   Layer 1 — cryptographic root: private key (never leaves device)
//   Layer 2 — public mesh identity: peer ID, display name, profile
//   Layer 3 — contextual masks: separate per-context identities (future)
//
// BACKEND:
//   Self identity sourced from LocalIdentitySummary via SettingsState.
//   Masks: not yet implemented in backend — section shows placeholder.
//
// REACHED FROM: NavDrawer → "You" section.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../../app/app_theme.dart';
import '../../backend/backend_bridge.dart';
import '../../backend/models/settings_models.dart';
import '../../widgets/mask_avatar.dart';
import '../settings/settings_state.dart';
import 'mask_intro_card.dart';
import '../settings/screens/profile_edit_screen.dart';
import '../tidbits/tidbits.dart'; // Copy Confetti §22.12.5 #7, TapTrigger

// ---------------------------------------------------------------------------
// YouScreen
// ---------------------------------------------------------------------------

/// Top-level You section screen — shows the local user's identity.
///
/// Uses [RefreshIndicator] so the user can pull-to-refresh after editing
/// their profile in [ProfileEditScreen] to see the updated values.
class YouScreen extends StatefulWidget {
  const YouScreen({super.key});

  @override
  State<YouScreen> createState() => _YouScreenState();
}

class _YouScreenState extends State<YouScreen> {
  List<_MaskRecord> _masks = const [];
  bool _masks_loading = true;

  @override
  void initState() {
    super.initState();
    _load_masks();
  }

  Future<void> _load_masks() async {
    final raw_masks = context.read<BackendBridge>().fetchMasks();
    final masks =
        raw_masks
            .map(_MaskRecord.from_json)
            // The You screen manages contextual masks only. Primary/public masks
            // remain surfaced through the self card and profile flows (§17.2,
            // §22.11).
            .where((mask) => !mask.is_public)
            .toList()
          ..sort((left, right) {
            if (left.is_anonymous != right.is_anonymous) {
              return left.is_anonymous ? 1 : -1;
            }
            return left.name.toLowerCase().compareTo(right.name.toLowerCase());
          });

    if (!mounted) {
      return;
    }

    setState(() {
      _masks = masks;
      _masks_loading = false;
    });
  }

  Future<void> _refresh_all(SettingsState settings) async {
    await settings.loadAll();
    await _load_masks();
  }

  Future<void> _create_mask() async {
    final name_controller = TextEditingController();
    bool is_anonymous = false;

    final created = await showDialog<bool>(
      context: context,
      builder: (dialog_context) {
        return StatefulBuilder(
          builder: (dialog_context, set_dialog_state) {
            return AlertDialog(
              title: const Text('New mask'),
              content: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  TextField(
                    controller: name_controller,
                    autofocus: true,
                    decoration: const InputDecoration(
                      labelText: 'Mask name',
                      hintText: 'Work, Garden, Travel...',
                    ),
                  ),
                  const SizedBox(height: 12),
                  SwitchListTile(
                    contentPadding: EdgeInsets.zero,
                    title: const Text('Anonymous mask'),
                    subtitle: const Text(
                      'Generate an isolated identity instead of deriving from your self.',
                    ),
                    value: is_anonymous,
                    onChanged: (value) =>
                        set_dialog_state(() => is_anonymous = value),
                  ),
                ],
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.of(dialog_context).pop(false),
                  child: const Text('Cancel'),
                ),
                FilledButton(
                  onPressed: () {
                    final ok = context.read<BackendBridge>().createMask(
                      name: name_controller.text.trim(),
                      isAnonymous: is_anonymous,
                    );
                    Navigator.of(dialog_context).pop(ok);
                  },
                  child: const Text('Create'),
                ),
              ],
            );
          },
        );
      },
    );

    name_controller.dispose();

    if (!mounted || created == null) {
      return;
    }

    await _load_masks();
    if (!mounted) {
      return;
    }

    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(created ? 'Mask created' : 'Failed to create mask'),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    // context.watch rebuilds YouScreen whenever SettingsState notifies —
    // which happens after loadAll() (called by ProfileEditScreen on save).
    final settings = context.watch<SettingsState>();
    final identity = settings.identity;

    return Scaffold(
      body: identity == null
          // Identity is null only during initial loading (before loadAll()
          // completes on app start).  Show a spinner rather than an empty card.
          ? const _LoadingIdentity()
          : RefreshIndicator(
              onRefresh: () => _refresh_all(settings),
              child: ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  _SelfCard(identity: identity),
                  const SizedBox(height: 24),
                  // First-use definition of "mask" (CMR-024), shown until dismissed.
                  const MaskIntroGate(),
                  _MasksSection(
                    masks: _masks,
                    loading: _masks_loading,
                    onCreateMask: _create_mask,
                  ),
                ],
              ),
            ),
    );
  }
}

// ---------------------------------------------------------------------------
// _SelfCard — the user's Layer 1/Layer 2 identity card
// ---------------------------------------------------------------------------

/// Full-width card showing the local user's avatar, name, peer ID, and QR code.
///
/// The peer ID is tappable — tapping copies it to the clipboard and fires the
/// Copy Confetti tidbit (§22.12.5 #7).  The QR code encodes the full peer ID
/// and is used for in-person contact pairing by scanning.
class _SelfCard extends StatelessWidget {
  const _SelfCard({required this.identity});

  /// The current local identity summary from SettingsState.
  final LocalIdentitySummary identity;

  @override
  Widget build(BuildContext context) {
    // Fall back to 'Unnamed' if the user has not set a display name yet.
    // This can happen if the user skipped the optional name step during
    // onboarding.
    final displayName = identity.name ?? 'Unnamed';

    // Truncate the peer ID to 16 hex characters for display — the full ID
    // is encoded in the QR code for scanning.  Showing the full ID as text
    // would overflow most screens and is not user-readable anyway.
    final shortId = identity.peerId.length > 16
        ? '${identity.peerId.substring(0, 16)}…'
        : identity.peerId;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          children: [
            // Avatar — first letter of display name on a brand-tinted circle.
            // This is the same style as the NavDrawer header for consistency.
            CircleAvatar(
              radius: 40,
              backgroundColor: MeshTheme.brand.withValues(alpha: 0.15),
              child: Text(
                displayName[0].toUpperCase(),
                // Text on a light tint: contrast-safe brand foreground
                // (§22.1.1 "Brand as foreground", CMR-019).
                style: TextStyle(
                  fontSize: 36,
                  fontWeight: FontWeight.w700,
                  color: MeshColors.of(context).brand_fg,
                ),
              ),
            ),
            const SizedBox(height: 16),

            // Display name
            Text(
              displayName,
              style: Theme.of(
                context,
              ).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 4),

            // Peer ID — monospace, truncated, tappable to copy the full ID.
            // GestureDetector here rather than InkWell because the peer ID
            // is a Text widget with no natural tap target size — GestureDetector
            // is lighter and doesn't require a Material ancestor.
            GestureDetector(
              onTap: () {
                // Copy the FULL peer ID (not the truncated shortId) to the
                // clipboard so the user can share or use it elsewhere.
                Clipboard.setData(ClipboardData(text: identity.peerId));
                ScaffoldMessenger.of(
                  context,
                ).showSnackBar(const SnackBar(content: Text('Peer ID copied')));
                // §22.12.5 #7 — tiny confetti burst on peer ID copy.
                // Keeps the action feel celebratory and confirms to the user
                // that the tap was recognised.
                TidbitRegistry.instance.show('copy_confetti', context);
              },
              child: Text(
                shortId,
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  fontFamily: 'monospace',
                  color: Theme.of(context).colorScheme.outline,
                ),
              ),
            ),
            const SizedBox(height: 20),

            // QR code — encodes the full peer ID for in-person pairing.
            // White background is necessary because QR codes require high
            // contrast; relying on the card background (which can be any colour
            // in dark mode) would make the code unscannable.
            QrImageView(
              data: identity.peerId,
              version: QrVersions
                  .auto, // auto-selects the smallest QR version that fits
              size: 160,
              backgroundColor: Colors.white,
            ),
            const SizedBox(height: 20),

            // Edit profile — opens ProfileEditScreen as a full route so the
            // user can change their public and private profile fields.
            OutlinedButton.icon(
              onPressed: () => Navigator.push(
                context,
                MaterialPageRoute(builder: (_) => const ProfileEditScreen()),
              ),
              icon: const Icon(Icons.edit_outlined, size: 18),
              label: const Text('Edit profile'),
            ),
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _MasksSection — Layer 3 contextual identities
// ---------------------------------------------------------------------------

/// Section showing the user's contextual masks (contextual identities).
///
class _MasksSection extends StatelessWidget {
  const _MasksSection({
    required this.masks,
    required this.loading,
    required this.onCreateMask,
  });

  final List<_MaskRecord> masks;
  final bool loading;
  final Future<void> Function() onCreateMask;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Text(
              'Masks',
              style: Theme.of(
                context,
              ).textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w600),
            ),
            const Spacer(),
            TextButton.icon(
              onPressed: onCreateMask,
              icon: const Icon(Icons.add, size: 18),
              label: const Text('New mask'),
            ),
          ],
        ),
        const SizedBox(height: 8),
        if (loading)
          const Padding(
            padding: EdgeInsets.symmetric(vertical: 24),
            child: Center(child: CircularProgressIndicator()),
          )
        else if (masks.isEmpty)
          _MasksEmptyState(onCreateMask: onCreateMask)
        else
          for (final mask in masks) ...[
            _MaskTile(mask: mask),
            const SizedBox(height: 8),
          ],
      ],
    );
  }
}

class _MasksEmptyState extends StatelessWidget {
  const _MasksEmptyState({required this.onCreateMask});

  final Future<void> Function() onCreateMask;

  @override
  Widget build(BuildContext context) {
    final color_scheme = Theme.of(context).colorScheme;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Center(
          child: Column(
            children: [
              Icon(Icons.masks_outlined, size: 40, color: color_scheme.outline),
              const SizedBox(height: 12),
              Text(
                'No contextual masks yet',
                style: Theme.of(context).textTheme.titleSmall,
              ),
              const SizedBox(height: 6),
              Text(
                'Masks let you present different identities in different contexts without exposing your root identity directly.',
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  color: color_scheme.onSurfaceVariant,
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 16),
              FilledButton.tonal(
                onPressed: onCreateMask,
                child: const Text('Create first mask'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _MaskTile extends StatelessWidget {
  const _MaskTile({required this.mask});

  final _MaskRecord mask;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final badge = mask.is_anonymous ? 'Anonymous' : 'Contextual';

    return Card(
      child: ListTile(
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        leading: MaskAvatar(
          mask: MaskAvatarData(name: mask.name, avatarColor: mask.avatar_color),
          size: MaskAvatarSize.medium,
        ),
        title: Text(mask.name, style: theme.textTheme.titleSmall),
        subtitle: Text(
          '$badge · ${mask.short_peer_id}',
          style: theme.textTheme.bodySmall?.copyWith(
            color: theme.colorScheme.onSurfaceVariant,
            fontFamily: 'monospace',
          ),
        ),
      ),
    );
  }
}

class _MaskRecord {
  const _MaskRecord({
    required this.name,
    required this.peer_id,
    required this.avatar_color,
    required this.is_public,
    required this.is_anonymous,
  });

  factory _MaskRecord.from_json(Map<String, dynamic> json) {
    final color_index = (json['avatarColor'] as num?)?.toInt() ?? 0;
    return _MaskRecord(
      name: (json['name'] as String?)?.trim().isNotEmpty == true
          ? (json['name'] as String).trim()
          : 'Unnamed mask',
      peer_id: json['peerId'] as String? ?? '',
      avatar_color:
          kMaskAvatarColors[color_index.clamp(0, kMaskAvatarColors.length - 1)],
      is_public: json['isPublic'] == true,
      is_anonymous: json['isAnonymous'] == true,
    );
  }

  final String name;
  final String peer_id;
  final Color avatar_color;
  final bool is_public;
  final bool is_anonymous;

  String get short_peer_id =>
      peer_id.length > 16 ? '${peer_id.substring(0, 16)}…' : peer_id;
}

// ---------------------------------------------------------------------------
// _LoadingIdentity — shown while identity is being loaded from the backend
// ---------------------------------------------------------------------------

/// Simple full-screen spinner shown while [SettingsState.identity] is null.
///
/// This is typically only visible for one or two frames on app start.
class _LoadingIdentity extends StatelessWidget {
  const _LoadingIdentity();

  @override
  Widget build(BuildContext context) {
    return const Center(child: CircularProgressIndicator());
  }
}
