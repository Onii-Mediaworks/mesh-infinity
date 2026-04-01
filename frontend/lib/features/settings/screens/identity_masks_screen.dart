// identity_masks_screen.dart
//
// IdentityMasksScreen — manage Layer-1 identity and Layer-3 contextual masks (§22.10.2).
//
// WHAT IS A MASK?
// ---------------
// A mask is a contextual identity — a different name, avatar, and set of
// permissions you use in a specific context.  For example:
//   - "Alex" for work colleagues (trust them but keep home life private)
//   - "A" for anonymous public Garden participation
//   - Your real name for close friends
//
// Masks all derive from your one root identity (Layer 1 — the cryptographic
// key pair).  Switching masks doesn't create a new identity or break existing
// sessions — it changes what name/profile people see in new interactions.
//
// The root identity is NEVER directly exposed on the mesh.  Only masks are.
//
// BACKEND STATUS:
// ---------------
// Masks are not yet implemented in the backend.  The screen shows:
//   - The root identity peer ID (read from SettingsState.identity)
//   - An empty masks list with a "New mask" button (stub)
// When the backend wires up (§8.3, §9.1), replace the empty list with
// real mask data from `bridge.fetchMasks()`.
//
// Reached from: Settings → Identity & Masks.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../settings_state.dart';

// ---------------------------------------------------------------------------
// IdentityMasksScreen
// ---------------------------------------------------------------------------

/// Shows the root identity summary and the list of configured masks.
class IdentityMasksScreen extends StatelessWidget {
  const IdentityMasksScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final settings = context.watch<SettingsState>();
    final identity = settings.identity;
    final tt = Theme.of(context).textTheme;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Identity & Masks'),
        actions: [
          // Global "New mask" button in the AppBar for easy access.
          TextButton.icon(
            onPressed: () => _createMask(context),
            icon: const Icon(Icons.add, size: 18),
            label: const Text('New mask'),
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // ---------------------------------------------------------------------------
          // Root identity card
          // ---------------------------------------------------------------------------
          // Shows the root cryptographic peer ID.  This ID is the anchor of all masks
          // and is the identifier other users paired with you through.
          _IdentityCard(
            peerId: identity?.peerId ?? '',
            displayName: identity?.name ?? 'Unnamed',
          ),

          const SizedBox(height: 20),

          // ---------------------------------------------------------------------------
          // Masks section header with count
          // ---------------------------------------------------------------------------
          Row(
            children: [
              Text('Masks', style: tt.titleSmall),
              const Spacer(),
              // Secondary "New mask" link — matches spec layout exactly.
              TextButton.icon(
                onPressed: () => _createMask(context),
                icon: const Icon(Icons.add, size: 16),
                label: const Text('New mask'),
              ),
            ],
          ),

          const SizedBox(height: 8),

          // ---------------------------------------------------------------------------
          // Masks list — empty state while backend is pending
          // ---------------------------------------------------------------------------
          // When the backend implements masks, replace this with:
          //   for (final mask in identity.masks) _MaskTile(mask: mask)
          _MasksEmptyState(onAddMask: () => _createMask(context)),

          const SizedBox(height: 24),
        ],
      ),
    );
  }

  // Opens the new-mask creation flow (stub until backend implements masks).
  void _createMask(BuildContext context) {
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Mask creation coming in a future update.'),
        duration: Duration(seconds: 3),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _IdentityCard — root identity peer ID display
// ---------------------------------------------------------------------------

/// Shows the root peer ID as selectable monospace text with copy and QR buttons.
///
/// The peer ID is the user's Layer-1 cryptographic fingerprint.  Users may
/// need to share it for out-of-band verification or for adding this identity
/// to another Mesh Infinity installation.
class _IdentityCard extends StatelessWidget {
  const _IdentityCard({required this.peerId, required this.displayName});

  final String peerId;
  final String displayName;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    // Truncated peer ID: first 24 chars + ellipsis to keep the card compact.
    // The full ID is shown on SelectableText so the user can still read all of it.
    final shortId = peerId.length > 24 ? '${peerId.substring(0, 24)}…' : peerId;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Card header row: icon + label.
            Row(
              children: [
                Icon(Icons.hub_outlined, size: 20, color: cs.primary),
                const SizedBox(width: 8),
                Text('Your identity', style: tt.titleSmall),
              ],
            ),
            const SizedBox(height: 8),

            // Clarification: the root ID is never directly on-mesh.
            Text(
              'The root of all your masks. Never exposed on the mesh directly.',
              style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
            ),
            const SizedBox(height: 12),

            // Peer ID row: selectable text + copy button + QR button.
            Row(
              children: [
                // SelectableText lets power users manually highlight and copy
                // partial segments for comparison (e.g. over a voice call).
                Expanded(
                  child: SelectableText(
                    shortId,
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                  ),
                ),
                // One-tap copy.
                IconButton(
                  icon: const Icon(Icons.copy_outlined, size: 18),
                  tooltip: 'Copy peer ID',
                  onPressed: peerId.isNotEmpty
                      ? () {
                          Clipboard.setData(ClipboardData(text: peerId));
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(content: Text('Peer ID copied')),
                          );
                        }
                      : null,
                ),
                // QR code button — shows the peer ID as a scannable code.
                IconButton(
                  icon: const Icon(Icons.qr_code_outlined, size: 18),
                  tooltip: 'Show QR code',
                  onPressed: peerId.isNotEmpty
                      ? () => _showQr(context)
                      : null,
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  // Show the peer ID as a QR code in a bottom sheet.
  void _showQr(BuildContext context) {
    showModalBottomSheet<void>(
      context: context,
      showDragHandle: true,
      builder: (_) => Padding(
        padding: const EdgeInsets.fromLTRB(24, 8, 24, 40),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              displayName,
              style: Theme.of(context).textTheme.titleLarge?.copyWith(
                    fontWeight: FontWeight.w700,
                  ),
            ),
            const SizedBox(height: 16),
            Container(
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(12),
              ),
              padding: const EdgeInsets.all(12),
              child: QrImageView(
                data: peerId,
                version: QrVersions.auto,
                size: 200,
                backgroundColor: Colors.white,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// _MasksEmptyState — shown when no masks are configured
// ---------------------------------------------------------------------------

/// Empty state for the masks list.  Shown until backend masks are implemented.
class _MasksEmptyState extends StatelessWidget {
  const _MasksEmptyState({required this.onAddMask});

  final VoidCallback onAddMask;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final tt = Theme.of(context).textTheme;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          children: [
            Icon(
              Icons.masks_outlined,
              size: 40,
              color: cs.outline,
            ),
            const SizedBox(height: 12),
            Text('No masks', style: tt.titleSmall),
            const SizedBox(height: 6),
            Text(
              'Masks let you present different identities in different contexts. '
              'Your root identity is never exposed directly.',
              style: tt.bodySmall?.copyWith(color: cs.onSurfaceVariant),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 16),
            // Action button inside the card — mirrors the AppBar button.
            FilledButton.tonal(
              onPressed: onAddMask,
              child: const Text('Create first mask'),
            ),
          ],
        ),
      ),
    );
  }
}
