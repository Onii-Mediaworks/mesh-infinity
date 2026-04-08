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
import '../../backend/models/settings_models.dart';
import '../settings/settings_state.dart';
import '../settings/screens/profile_edit_screen.dart';
import '../tidbits/tidbits.dart'; // Copy Confetti §22.12.5 #7, TapTrigger

// ---------------------------------------------------------------------------
// YouScreen
// ---------------------------------------------------------------------------

/// Top-level You section screen — shows the local user's identity.
///
/// Uses [RefreshIndicator] so the user can pull-to-refresh after editing
/// their profile in [ProfileEditScreen] to see the updated values.
class YouScreen extends StatelessWidget {
  const YouScreen({super.key});

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
              onRefresh: settings.loadAll,
              child: ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  _SelfCard(identity: identity),
                  const SizedBox(height: 24),
                  // _MasksSection has no constructor arguments because it
                  // shows a static placeholder until backend mask support lands.
                  _MasksSection(),
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
                style: const TextStyle(
                  fontSize: 36,
                  fontWeight: FontWeight.w700,
                  color: MeshTheme.brand,
                ),
              ),
            ),
            const SizedBox(height: 16),

            // Display name
            Text(
              displayName,
              style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                    fontWeight: FontWeight.w700,
                  ),
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
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Peer ID copied')),
                );
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
              version: QrVersions.auto, // auto-selects the smallest QR version that fits
              size: 160,
              backgroundColor: Colors.white,
            ),
            const SizedBox(height: 20),

            // Edit profile — opens ProfileEditScreen as a full route so the
            // user can change their public and private profile fields.
            OutlinedButton.icon(
              onPressed: () => Navigator.push(
                context,
                MaterialPageRoute(
                    builder: (_) => const ProfileEditScreen()),
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
/// Masks are planned for a future update — this section currently shows a
/// placeholder explaining what masks are and when they will arrive.
///
/// The "New mask" button is disabled (onPressed: null) rather than hidden so
/// the user can see the feature exists without being able to activate it yet.
class _MasksSection extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Text(
              'Masks',
              style: Theme.of(context).textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.w600,
                  ),
            ),
            const Spacer(),
            // Disabled until the backend mask API is implemented.
            // Showing the button communicates the feature is coming without
            // making it appear broken.
            TextButton.icon(
              onPressed: null, // Masks not yet implemented in backend
              icon: const Icon(Icons.add, size: 18),
              label: const Text('New mask'),
            ),
          ],
        ),
        const SizedBox(height: 8),
        // Empty-state card — explains what masks are so users understand
        // the placeholder rather than thinking something is broken.
        Card(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Center(
              child: Column(
                children: [
                  Icon(
                    Icons.masks_outlined,
                    size: 40,
                    color: Theme.of(context).colorScheme.outline,
                  ),
                  const SizedBox(height: 12),
                  Text(
                    'No masks',
                    style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                          color: Theme.of(context).colorScheme.outline,
                        ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    'Masks are contextual identities coming in a future update.',
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                          color: Theme.of(context).colorScheme.outline,
                        ),
                    textAlign: TextAlign.center,
                  ),
                ],
              ),
            ),
          ),
        ),
      ],
    );
  }
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
