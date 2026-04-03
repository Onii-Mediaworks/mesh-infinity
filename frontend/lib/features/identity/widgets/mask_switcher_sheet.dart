// §22.4.10 MaskSwitcherSheet
//
// Bottom sheet presented when the user taps the active mask avatar in the
// AppBar.  Allows switching between identity masks without navigating to
// Settings.  Until the full multi-mask API is wired, this shows the single
// primary identity derived from LocalIdentitySummary.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../../../app/app_theme.dart';
import '../../../backend/backend_bridge.dart';
import '../../../backend/models/settings_models.dart';
import '../../../widgets/mask_avatar.dart';

/// Shows the MaskSwitcherSheet as a modal bottom sheet.
///
/// Call this from any AppBar leading-widget `onTap` handler:
/// ```dart
/// GestureDetector(
///   onTap: () => showMaskSwitcherSheet(context),
///   child: MaskAvatar(mask: activeMask, size: MaskAvatarSize.small),
/// )
/// ```
void showMaskSwitcherSheet(BuildContext context) {
  showModalBottomSheet<void>(
    context: context,
    useRootNavigator: true,
    builder: (_) => const MaskSwitcherSheet(),
  );
}

/// Content widget for the mask-switcher bottom sheet.
class MaskSwitcherSheet extends StatefulWidget {
  const MaskSwitcherSheet({super.key});

  @override
  State<MaskSwitcherSheet> createState() => _MaskSwitcherSheetState();
}

class _MaskSwitcherSheetState extends State<MaskSwitcherSheet> {
  LocalIdentitySummary? _identity;

  @override
  void initState() {
    super.initState();
    final bridge = context.read<BackendBridge>();
    _identity = bridge.fetchLocalIdentity();
  }

  // Derives a stable color from the peer ID.
  Color _avatarColor(String id) {
    final hash = id.codeUnits.fold(0, (h, c) => h ^ c);
    return kMaskAvatarColors[hash.abs() % kMaskAvatarColors.length];
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final identity = _identity;

    // Build a single-entry mask list from the local identity.
    // When multi-mask support is added, this will iterate identity.masks.
    final String maskName =
        identity?.name ?? identity?.peerId.substring(0, 8) ?? 'You';
    final Color maskColor = identity != null
        ? _avatarColor(identity.peerId)
        : MeshTheme.brand;

    final primaryMask = MaskAvatarData(name: maskName, avatarColor: maskColor);

    return SafeArea(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          // Header row: "Active identity" title + "Manage" link
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 4, 8, 8),
            child: Row(
              children: [
                Expanded(
                  child: Text(
                    'Active identity',
                    style: theme.textTheme.titleMedium,
                  ),
                ),
                TextButton(
                  onPressed: () {
                    Navigator.pop(context);
                    // Navigate to identity management in Settings.
                    // Full IdentityMasksScreen will be wired here.
                  },
                  child: const Text('Manage'),
                ),
              ],
            ),
          ),

          // Primary identity tile — always active (single mask for now).
          ListTile(
            leading: MaskAvatar(mask: primaryMask, size: MaskAvatarSize.medium),
            title: Text(maskName),
            subtitle: identity != null
                ? Text(
                    identity.peerId.length > 16
                        ? '${identity.peerId.substring(0, 16)}…'
                        : identity.peerId,
                    style: theme.textTheme.bodySmall?.copyWith(
                      fontFamily: 'monospace',
                    ),
                  )
                : null,
            trailing: const Icon(Icons.check_rounded, color: MeshTheme.brand),
            selected: true,
          ),

          const SizedBox(height: 8),
        ],
      ),
    );
  }
}
